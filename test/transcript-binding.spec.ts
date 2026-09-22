import { defaultLogger } from '@libp2p/logger'
import { multiaddrConnectionPair } from '@libp2p/utils'
import { expect } from 'aegir/chai'
import { stubInterface } from 'sinon-ts'
import { equals as uint8ArrayEquals } from 'uint8arrays/equals'
import { Noise } from '../src/noise.js'
import {
  canonicalProtocols,
  DowngradeDetectedError,
  expectedProtocol,
  toTranscriptBindingConfig,
  transcriptSignaturePayload
} from '../src/transcript-binding.js'
import { createHandshakePayload, decodeHandshakePayload } from '../src/utils.js'
import { createPeerIdsFromFixtures } from './fixtures/peer.js'
import type { TranscriptBindingInit } from '../src/noise.js'
import type { TranscriptBindingVariant } from '../src/transcript-binding.js'
import type { PeerId, PrivateKey, Upgrader } from '@libp2p/interface'

const HFS = '/noise-mlkem768-hfs/0.2.0'
const CLASSICAL = '/noise'

describe('transcript binding', () => {
  let remotePeer: { peerId: PeerId, privateKey: PrivateKey }
  let localPeer: { peerId: PeerId, privateKey: PrivateKey }

  before(async () => {
    [localPeer, remotePeer] = await createPeerIdsFromFixtures(2)
  })

  function makeNoise (peer: { peerId: PeerId, privateKey: PrivateKey }, transcriptBinding?: TranscriptBindingInit): Noise {
    return new Noise({
      ...peer,
      logger: defaultLogger(),
      upgrader: stubInterface<Upgrader>({
        getStreamMuxers: () => new Map()
      })
    }, { transcriptBinding })
  }

  /**
   * Run a full handshake between two peers with the given binding options.
   *
   * Both instances are `/noise`, so `actualProtocol` is `/noise` on both
   * sides. A peer listing HFS ahead of `/noise` while the session runs
   * `/noise` is exactly the state an on-path downgrade leaves behind.
   */
  async function handshake (initOpts?: TranscriptBindingInit, respOpts?: TranscriptBindingInit): Promise<void> {
    const [inboundConnection, outboundConnection] = multiaddrConnectionPair()

    await Promise.all([
      makeNoise(localPeer, initOpts).secureOutbound(outboundConnection, { remotePeer: remotePeer.peerId }),
      makeNoise(remotePeer, respOpts).secureInbound(inboundConnection, { remotePeer: localPeer.peerId })
    ])
  }

  describe('canonical encoding', () => {
    it('distinguishes lists that plain concatenation would collide', () => {
      // Without length prefixes both encode to the bytes 'abc', so a single
      // signature would be valid for two different protocol lists.
      expect(uint8ArrayEquals(canonicalProtocols(['ab', 'c']), canonicalProtocols(['a', 'bc']))).to.equal(false)
    })

    it('is order sensitive', () => {
      expect(uint8ArrayEquals(canonicalProtocols([HFS, CLASSICAL]), canonicalProtocols([CLASSICAL, HFS]))).to.equal(false)
    })

    it('encodes each entry as a uint16 length followed by its utf-8 bytes', () => {
      expect(canonicalProtocols(['ab'])).to.deep.equal(Uint8Array.from([0, 2, 0x61, 0x62]))
      expect(canonicalProtocols([])).to.deep.equal(new Uint8Array(0))
    })

    it('refuses an implausible number of protocols', () => {
      expect(() => canonicalProtocols(new Array(33).fill('/noise'))).to.throw(/too many security protocols/)
    })
  })

  describe('expected protocol', () => {
    it('is the dialer\'s first choice that the listener supports', () => {
      expect(expectedProtocol([HFS, CLASSICAL], [CLASSICAL, HFS])).to.equal(HFS)
    })

    it('follows the dialer\'s order, not the listener\'s', () => {
      expect(expectedProtocol([CLASSICAL, HFS], [HFS, CLASSICAL])).to.equal(CLASSICAL)
    })

    it('is undefined when the two offers do not intersect', () => {
      expect(expectedProtocol([HFS], [CLASSICAL])).to.equal(undefined)
    })
  })

  describe('configuration', () => {
    it('rejects a protocol list that omits the encrypter\'s own protocol', () => {
      expect(() => toTranscriptBindingConfig({ securityProtocols: [HFS] }, CLASSICAL))
        .to.throw(/must include this encrypter's own protocol/)
    })

    it('defaults to enforcing the extension variant', () => {
      const config = toTranscriptBindingConfig({ securityProtocols: [CLASSICAL] }, CLASSICAL)

      expect(config).to.include({ mode: 'enforce', variant: 'extension', actualProtocol: CLASSICAL })
    })

    it('is disabled when the option is absent', () => {
      expect(toTranscriptBindingConfig(undefined, CLASSICAL)).to.equal(undefined)
    })
  })

  const variants: TranscriptBindingVariant[] = ['extension', 'identity']

  for (const variant of variants) {
    describe(`${variant} variant`, () => {
      it('completes an honest handshake', async () => {
        await handshake(
          { variant, securityProtocols: [CLASSICAL] },
          { variant, securityProtocols: [CLASSICAL] }
        )
      })

      it('allows a session on the weaker protocol when the listener genuinely lacks the stronger one', async () => {
        // The dialer prefers HFS, the listener does not implement it, so
        // /noise is the honest outcome and must not be flagged.
        await handshake(
          { variant, securityProtocols: [HFS, CLASSICAL] },
          { variant, securityProtocols: [CLASSICAL] }
        )
      })

      it('refuses a session both peers should have run over the stronger protocol', async () => {
        // Both support HFS and both prefer it, yet the session is /noise.
        // Only a tampered negotiation produces that.
        await expect(handshake(
          { variant, securityProtocols: [HFS, CLASSICAL] },
          { variant, securityProtocols: [HFS, CLASSICAL] }
        )).to.eventually.be.rejected
          .with.property('message')
          .that.matches(/downgrade/)
      })

      it('continues but reports in warn mode', async () => {
        await handshake(
          { variant, mode: 'warn', securityProtocols: [HFS, CLASSICAL] },
          { variant, mode: 'warn', securityProtocols: [HFS, CLASSICAL] }
        )
      })

      it('does not check anything in off mode', async () => {
        await handshake(
          { variant, mode: 'off', securityProtocols: [HFS, CLASSICAL] },
          { variant, mode: 'off', securityProtocols: [HFS, CLASSICAL] }
        )
      })
    })
  }

  describe('interoperability with peers that do not implement it', () => {
    it('accepts a peer that sends no binding, rather than treating it as an attack', async () => {
      // The responder is an older peer. The initiator cannot conclude anything
      // from the absent field, so the handshake must succeed.
      await handshake({ securityProtocols: [HFS, CLASSICAL] }, undefined)
    })

    it('is accepted by a peer that does not implement it', async () => {
      await handshake(undefined, { securityProtocols: [HFS, CLASSICAL] })
    })

    // The identity variant behaves completely differently here, and the
    // difference is the reason it cannot be deployed on the existing /noise
    // protocol id. The protocol list is inside identity_sig, so a peer that
    // does not send a list is verifying a different message and the handshake
    // hard-fails. That is not a downgrade check firing, it is signature
    // verification failing, so `mode` never gets a say: warn does not soften
    // it. These tests pin that behaviour so it cannot be mistaken later for a
    // regression.
    it('cannot talk to a peer that does not implement it at all', async () => {
      await expect(handshake({ variant: 'identity', securityProtocols: [HFS, CLASSICAL] }, undefined))
        .to.eventually.be.rejected
        .with.property('message')
        .that.matches(/Invalid payload signature/)
    })

    it('cannot be reached by a peer that does not implement it', async () => {
      await expect(handshake(undefined, { variant: 'identity', securityProtocols: [HFS, CLASSICAL] }))
        .to.eventually.be.rejected
        .with.property('message')
        .that.matches(/Invalid payload signature/)
    })

    it('fails against an older peer even in warn mode', async () => {
      await expect(handshake({ variant: 'identity', mode: 'warn', securityProtocols: [CLASSICAL] }, undefined))
        .to.eventually.be.rejected
        .with.property('message')
        .that.matches(/Invalid payload signature/)
    })

    it('cannot talk to a peer using the other variant', async () => {
      await expect(handshake(
        { variant: 'identity', securityProtocols: [CLASSICAL] },
        { variant: 'extension', securityProtocols: [CLASSICAL] }
      )).to.eventually.be.rejected
        .with.property('message')
        .that.matches(/Invalid payload signature/)
    })
  })

  describe('signature verification', () => {
    const payloadHash = Uint8Array.from({ length: 32 }, (_, i) => i)

    it('rejects a payload whose protocol list was altered in flight', async () => {
      const staticKey = Uint8Array.from({ length: 32 }, (_, i) => 255 - i)
      const bytes = await createHandshakePayload(
        localPeer.privateKey,
        staticKey,
        undefined,
        { payloadHash, protocols: [HFS, CLASSICAL], variant: 'extension' }
      )

      // An attacker strips HFS from the list so the victim believes only
      // /noise was ever on offer. The signature no longer covers the list.
      const { NoiseHandshakePayload } = await import('../src/proto/payload.js')
      const decoded = NoiseHandshakePayload.decode(bytes)
      const tampered = NoiseHandshakePayload.encode({
        ...decoded,
        extensions: {
          ...decoded.extensions,
          webtransportCerthashes: decoded.extensions?.webtransportCerthashes ?? [],
          streamMuxers: decoded.extensions?.streamMuxers ?? [],
          transcriptSig: decoded.extensions?.transcriptSig ?? new Uint8Array(0),
          securityProtocols: [CLASSICAL]
        }
      })

      await expect(decodeHandshakePayload(tampered, staticKey, localPeer.privateKey.publicKey, { payloadHash, variant: 'extension' }))
        .to.eventually.be.rejected
        .with.property('message')
        .that.matches(/transcript binding signature/)
    })

    it('rejects a binding signed against a different transcript', async () => {
      const staticKey = Uint8Array.from({ length: 32 }, (_, i) => 255 - i)
      const bytes = await createHandshakePayload(
        localPeer.privateKey,
        staticKey,
        undefined,
        { payloadHash, protocols: [CLASSICAL], variant: 'extension' }
      )

      // Same signed list, replayed into a different session.
      const otherHash = Uint8Array.from({ length: 32 }, () => 7)

      await expect(decodeHandshakePayload(bytes, staticKey, localPeer.privateKey.publicKey, { payloadHash: otherHash, variant: 'extension' }))
        .to.eventually.be.rejected
        .with.property('message')
        .that.matches(/transcript binding signature/)
    })

    it('binds the list and the transcript together, not separately', () => {
      // Moving a byte across the hash/list boundary must change the signed
      // message, otherwise the two fields could be traded off against
      // each other.
      const a = transcriptSignaturePayload(payloadHash, ['ab'])
      const b = transcriptSignaturePayload(payloadHash, ['a', 'b'])

      expect(uint8ArrayEquals(a, b)).to.equal(false)
    })
  })

  describe('error type', () => {
    it('is distinguishable from an ordinary handshake failure', async () => {
      const error = await handshake(
        { securityProtocols: [HFS, CLASSICAL] },
        { securityProtocols: [HFS, CLASSICAL] }
      ).then(() => undefined, (err: Error) => err)

      expect(error?.message).to.match(/downgrade/)
      expect(DowngradeDetectedError.code).to.equal('ERR_SECURITY_PROTOCOL_DOWNGRADE')
    })
  })
})
