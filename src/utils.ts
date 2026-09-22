import { publicKeyFromProtobuf, publicKeyToProtobuf } from '@libp2p/crypto/keys'
import { StreamMessageEvent, UnexpectedPeerError } from '@libp2p/interface'
import { AbstractMessageStream, LengthPrefixedDecoder } from '@libp2p/utils'
import { Uint8ArrayList } from 'uint8arraylist'
import { concat as uint8ArrayConcat } from 'uint8arrays/concat'
import { fromString as uint8ArrayFromString } from 'uint8arrays/from-string'
import { CHACHA_TAG_LENGTH, NOISE_MSG_MAX_LENGTH_BYTES, NOISE_MSG_MAX_LENGTH_BYTES_WITHOUT_TAG } from './constants.ts'
import { uint16BEEncode, uint16BEDecode } from './encoder.ts'
import { NoiseHandshakePayload } from './proto/payload.js'
import { canonicalProtocols, createTranscriptBinding, hasTranscriptBinding, transcriptSignaturePayload } from './transcript-binding.js'
import type { MetricsRegistry } from './metrics.ts'
import type { NoiseExtensions } from './proto/payload.js'
import type { TranscriptBindingVariant } from './transcript-binding.js'
import type { HandshakeResult } from './types.ts'
import type { AbortOptions, MessageStream, PrivateKey, PublicKey, StreamCloseEvent } from '@libp2p/interface'
import type { SendResult } from '@libp2p/utils'

/**
 * Binds a handshake payload to this session. Supplied only when transcript
 * binding is enabled; see TRANSCRIPT_BINDING_SPEC.md.
 */
export interface TranscriptBindingInit {
  /**
   * The Noise transcript hash this payload is encrypted under.
   */
  payloadHash: Uint8Array
  /**
   * The security protocols this peer has configured, in preference order.
   */
  protocols: string[]
  /**
   * `extension` signs the list separately and leaves identity_sig untouched,
   * so unmodified peers still interoperate. `identity` folds the binding into
   * identity_sig instead, which is smaller but changes what every libp2p peer
   * verifies.
   */
  variant: TranscriptBindingVariant
}

export async function createHandshakePayload (
  privateKey: PrivateKey,
  staticPublicKey: Uint8Array | Uint8ArrayList,
  extensions?: NoiseExtensions,
  binding?: TranscriptBindingInit
): Promise<Uint8Array | Uint8ArrayList> {
  const identitySig = await privateKey.sign(
    getSignaturePayload(staticPublicKey, binding?.variant === 'identity' ? binding : undefined)
  )

  let payloadExtensions = extensions

  if (binding?.variant === 'extension') {
    payloadExtensions = {
      webtransportCerthashes: extensions?.webtransportCerthashes ?? [],
      streamMuxers: extensions?.streamMuxers ?? [],
      ...await createTranscriptBinding(privateKey, binding.payloadHash, binding.protocols)
    }
  } else if (binding?.variant === 'identity') {
    payloadExtensions = {
      webtransportCerthashes: extensions?.webtransportCerthashes ?? [],
      streamMuxers: extensions?.streamMuxers ?? [],
      securityProtocols: binding.protocols,
      transcriptSig: new Uint8Array(0)
    }
  }

  return NoiseHandshakePayload.encode({
    identityKey: publicKeyToProtobuf(privateKey.publicKey),
    identitySig,
    extensions: payloadExtensions
  })
}

export async function decodeHandshakePayload (
  payloadBytes: Uint8Array | Uint8ArrayList,
  remoteStaticKey?: Uint8Array | Uint8ArrayList,
  remoteIdentityKey?: PublicKey,
  binding?: Pick<TranscriptBindingInit, 'payloadHash' | 'variant'>
): Promise<NoiseHandshakePayload> {
  try {
    const payload = NoiseHandshakePayload.decode(payloadBytes)
    const publicKey = publicKeyFromProtobuf(payload.identityKey)

    if (remoteIdentityKey?.equals(publicKey) === false) {
      throw new Error(`Payload identity key ${publicKey} does not match expected remote identity key ${remoteIdentityKey}`)
    }

    if (!remoteStaticKey) {
      throw new Error('Remote static does not exist')
    }

    // Under the identity variant the protocol list is covered by identity_sig
    // itself, so it has to be folded in here, using the list as received. A
    // tampered list simply fails the signature check below.
    const identityBinding = binding?.variant === 'identity'
      ? { payloadHash: binding.payloadHash, protocols: payload.extensions?.securityProtocols ?? [] }
      : undefined

    const signaturePayload = getSignaturePayload(remoteStaticKey, identityBinding)

    if (!(await publicKey.verify(signaturePayload, payload.identitySig))) {
      throw new Error('Invalid payload signature')
    }

    if (binding?.variant === 'extension' && hasTranscriptBinding(payload.extensions, 'extension')) {
      const transcriptPayload = transcriptSignaturePayload(
        binding.payloadHash,
        payload.extensions?.securityProtocols ?? []
      )

      if (!(await publicKey.verify(transcriptPayload, payload.extensions?.transcriptSig ?? new Uint8Array(0)))) {
        throw new Error('Invalid transcript binding signature')
      }
    }

    return payload
  } catch (e) {
    throw new UnexpectedPeerError((e as Error).message)
  }
}

export function getSignaturePayload (
  publicKey: Uint8Array | Uint8ArrayList,
  binding?: Pick<TranscriptBindingInit, 'payloadHash' | 'protocols'>
): Uint8Array | Uint8ArrayList {
  const prefix = uint8ArrayFromString('noise-libp2p-static-key:')

  if (binding != null) {
    // Variant B: one signature covering the static key and the session-bound
    // protocol list.
    const canonical = canonicalProtocols(binding.protocols)
    const list = new Uint8ArrayList(prefix, publicKey, binding.payloadHash, canonical)

    return list
  }

  if (publicKey instanceof Uint8Array) {
    return uint8ArrayConcat([prefix, publicKey], prefix.length + publicKey.length)
  }

  publicKey.prepend(prefix)

  return publicKey
}

class EncryptedMessageStream extends AbstractMessageStream {
  private stream: MessageStream
  private handshake: HandshakeResult
  private metrics?: MetricsRegistry
  private decoder: LengthPrefixedDecoder

  constructor (stream: MessageStream, handshake: HandshakeResult, metrics?: MetricsRegistry) {
    super({
      log: stream.log,
      inactivityTimeout: stream.inactivityTimeout,
      maxReadBufferLength: stream.maxReadBufferLength,
      direction: stream.direction
    })

    this.stream = stream
    this.handshake = handshake
    this.metrics = metrics
    this.decoder = new LengthPrefixedDecoder({
      lengthDecoder: uint16BEDecode,
      maxBufferSize: 16 * 1024 * 1024,
      encodingLength: () => 2
    })

    const noiseOnMessageDecrypt = (evt: StreamMessageEvent): void => {
      try {
        for (const buf of this.decoder.decode(evt.data)) {
          this.onData(this.decrypt(buf))
        }
      } catch (err: any) {
        this.abort(err)
      }
    }
    this.stream.addEventListener('message', noiseOnMessageDecrypt)

    const noiseOnClose = (evt: StreamCloseEvent): void => {
      if (evt.error != null) {
        if (evt.local === true) {
          this.abort(evt.error)
        } else {
          this.onRemoteReset()
        }
      } else {
        this.onTransportClosed()
      }
    }
    this.stream.addEventListener('close', noiseOnClose)

    const noiseOnDrain = (): void => {
      this.safeDispatchEvent('drain')
    }
    this.stream.addEventListener('drain', noiseOnDrain)

    const noiseOnRemoteCloseWrite = (): void => {
      this.onRemoteCloseWrite()
    }
    this.stream.addEventListener('remoteCloseWrite', noiseOnRemoteCloseWrite)
  }

  encrypt (chunk: Uint8Array | Uint8ArrayList): Uint8ArrayList {
    const output = new Uint8ArrayList()

    for (let i = 0; i < chunk.byteLength; i += NOISE_MSG_MAX_LENGTH_BYTES_WITHOUT_TAG) {
      let end = i + NOISE_MSG_MAX_LENGTH_BYTES_WITHOUT_TAG
      if (end > chunk.byteLength) {
        end = chunk.byteLength
      }

      let data: Uint8Array | Uint8ArrayList

      if (chunk instanceof Uint8Array) {
        data = this.handshake.encrypt(chunk.subarray(i, end))
      } else {
        data = this.handshake.encrypt(chunk.sublist(i, end))
      }

      this.metrics?.encryptedPackets.increment()

      output.append(uint16BEEncode(data.byteLength))
      output.append(data)
    }

    return output
  }

  decrypt (chunk: Uint8Array | Uint8ArrayList): Uint8ArrayList {
    const output = new Uint8ArrayList()

    for (let i = 0; i < chunk.byteLength; i += NOISE_MSG_MAX_LENGTH_BYTES) {
      let end = i + NOISE_MSG_MAX_LENGTH_BYTES
      if (end > chunk.byteLength) {
        end = chunk.byteLength
      }

      if (end - CHACHA_TAG_LENGTH < i) {
        throw new Error('Invalid chunk')
      }

      let encrypted: Uint8Array | Uint8ArrayList

      if (chunk instanceof Uint8Array) {
        encrypted = chunk.subarray(i, end)
      } else {
        encrypted = chunk.sublist(i, end)
      }

      // memory allocation is not cheap so reuse the encrypted Uint8Array
      // see https://github.com/ChainSafe/js-libp2p-noise/pull/242#issue-1422126164
      // this is ok because chacha20 reads bytes one by one and don't reread after that
      // it's also tested in https://github.com/ChainSafe/as-chacha20poly1305/pull/1/files#diff-25252846b58979dcaf4e41d47b3eadd7e4f335e7fb98da6c049b1f9cd011f381R48
      const dst = chunk.subarray(i, end - CHACHA_TAG_LENGTH)
      try {
        const plaintext = this.handshake.decrypt(encrypted, dst)
        this.metrics?.decryptedPackets.increment()

        output.append(plaintext)
      } catch (e) {
        this.metrics?.decryptErrors.increment()
        throw e
      }
    }

    return output
  }

  close (options?: AbortOptions): Promise<void> {
    return this.stream.close(options)
  }

  sendPause (): void {
    this.stream.pause()
  }

  sendResume (): void {
    this.stream.resume()
  }

  sendReset (err: Error): void {
    this.stream.abort(err)
  }

  sendData (data: Uint8ArrayList): SendResult {
    return {
      sentBytes: data.byteLength,
      canSendMore: this.stream.send(this.encrypt(data))
    }
  }
}

export function toMessageStream (connection: MessageStream, handshake: HandshakeResult, metrics?: MetricsRegistry): MessageStream {
  return new EncryptedMessageStream(connection, handshake, metrics)
}
