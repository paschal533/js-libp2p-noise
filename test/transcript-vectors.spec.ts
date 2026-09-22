/**
 * Guards the committed cross-implementation vectors.
 *
 * test/fixtures/transcript-binding-vectors.json is consumed by other
 * implementations (py-libp2p reads the same file) to check that they encode
 * and sign identical bytes. This spec asserts that this implementation still
 * reproduces the committed file, so an accidental change to the canonical
 * encoding, a signature prefix or a protobuf field number fails here rather
 * than silently breaking interop.
 *
 * If a wire-format change is deliberate, regenerate with
 * `node scripts/generate-transcript-vectors.js`, update the other
 * implementations' copies in the same change, and say so.
 */

import { readFileSync } from 'fs'
import { dirname, resolve } from 'path'
import { fileURLToPath } from 'url'
import { generateKeyPairFromSeed } from '@libp2p/crypto/keys'
import { expect } from 'aegir/chai'
import { fromString as uint8ArrayFromString } from 'uint8arrays/from-string'
import { toString as uint8ArrayToString } from 'uint8arrays/to-string'
import { NoiseHandshakePayload } from '../src/proto/payload.js'
import { canonicalProtocols, transcriptSignaturePayload, TRANSCRIPT_SIG_PREFIX } from '../src/transcript-binding.js'
import { createHandshakePayload, getSignaturePayload } from '../src/utils.js'
import type { PrivateKey } from '@libp2p/interface'

interface Vector {
  protocols: string[]
  canonical_protocols: string
  transcript_sig_payload: string
  identity_sig_payload_bound: string
  extension_variant: { handshake_payload: string, transcript_sig: string }
  identity_variant: { handshake_payload: string, identity_sig: string }
}

interface VectorFile {
  identity_key_seed: string
  identity_public_key: string
  noise_static_public_key: string
  payload_hash: string
  transcript_sig_prefix: string
  protobuf_field_numbers: Record<string, number>
  vectors: Vector[]
}

const here = dirname(fileURLToPath(import.meta.url))
const FIXTURE_PATH = resolve(here, '../../test/fixtures/transcript-binding-vectors.json')

const file: VectorFile = JSON.parse(readFileSync(FIXTURE_PATH, 'utf-8'))

const hex = (value: Uint8Array | { subarray(): Uint8Array }): string =>
  uint8ArrayToString(value instanceof Uint8Array ? value : value.subarray(), 'base16')
const unhex = (value: string): Uint8Array => uint8ArrayFromString(value, 'base16')

const staticKey = unhex(file.noise_static_public_key)
const payloadHash = unhex(file.payload_hash)

// Derived on demand and cached. A `let` assigned in `before()` and read
// from closures created in the vector loop below is exactly what
// no-loop-func warns about.
let cached: PrivateKey | undefined

async function identityKey (): Promise<PrivateKey> {
  cached ??= await generateKeyPairFromSeed('Ed25519', unhex(file.identity_key_seed))

  return cached
}

describe('transcript binding vectors', () => {
  it('has vectors', () => {
    expect(file.vectors.length).to.be.greaterThanOrEqual(5)
  })

  it('derives the recorded identity key from the recorded seed', async () => {
    expect(hex((await identityKey()).publicKey.raw)).to.equal(file.identity_public_key)
  })

  it('records the signature prefix actually in use', () => {
    expect(TRANSCRIPT_SIG_PREFIX).to.equal(file.transcript_sig_prefix)
  })

  it('records the protobuf field numbers actually in use', () => {
    // Encode a payload carrying only the two new fields and read the tags off
    // the wire, rather than trusting a constant that could drift from the
    // generated code.
    const encoded = NoiseHandshakePayload.encode({
      identityKey: new Uint8Array(0),
      identitySig: new Uint8Array(0),
      extensions: {
        webtransportCerthashes: [],
        streamMuxers: [],
        securityProtocols: ['x'],
        transcriptSig: Uint8Array.from([1])
      }
    }).subarray()

    const decoded = NoiseHandshakePayload.decode(encoded)
    expect(decoded.extensions?.securityProtocols).to.deep.equal(['x'])

    // Field 4 of NoiseExtensions is tag 0x22, field 5 is 0x2a.
    expect(file.protobuf_field_numbers['NoiseExtensions.security_protocols']).to.equal(4)
    expect(file.protobuf_field_numbers['NoiseExtensions.transcript_sig']).to.equal(5)
  })

  for (const vector of file.vectors) {
    describe(`[${vector.protocols.join(', ')}]`, () => {
      it('reproduces the canonical encoding', () => {
        expect(hex(canonicalProtocols(vector.protocols))).to.equal(vector.canonical_protocols)
      })

      it('reproduces the transcript signature payload', () => {
        expect(hex(transcriptSignaturePayload(payloadHash, vector.protocols)))
          .to.equal(vector.transcript_sig_payload)
      })

      it('reproduces the bound identity signature payload', () => {
        expect(hex(getSignaturePayload(staticKey, { payloadHash, protocols: vector.protocols })))
          .to.equal(vector.identity_sig_payload_bound)
      })

      it('reproduces the extension variant handshake payload', async () => {
        const payload = await createHandshakePayload(
          await identityKey(), staticKey, undefined, { payloadHash, protocols: vector.protocols, variant: 'extension' }
        )

        expect(hex(payload)).to.equal(vector.extension_variant.handshake_payload)
      })

      it('reproduces the identity variant handshake payload', async () => {
        const payload = await createHandshakePayload(
          await identityKey(), staticKey, undefined, { payloadHash, protocols: vector.protocols, variant: 'identity' }
        )

        expect(hex(payload)).to.equal(vector.identity_variant.handshake_payload)
      })
    })
  }
})
