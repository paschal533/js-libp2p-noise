/**
 * Transcript-bound security protocol negotiation.
 *
 * multistream-select picks the connection encrypter in plaintext, before any
 * handshake, so an on-path attacker can strip a proposal or forge an `na` and
 * silently push both peers onto a weaker protocol. This module lets each peer
 * state, inside the encrypted handshake payload, which security protocols it
 * has configured, bound to the Noise transcript so the statement cannot be
 * replayed from another session. Both peers then recompute what the
 * negotiation should have produced and compare it against the protocol they
 * are actually running.
 *
 * See TRANSCRIPT_BINDING_SPEC.md for the design and the two binding variants.
 */

import { concat as uint8ArrayConcat } from 'uint8arrays/concat'
import { fromString as uint8ArrayFromString } from 'uint8arrays/from-string'
import { uint16BEEncode } from './encoder.js'
import type { NoiseExtensions } from './proto/payload.js'
import type { Logger, PrivateKey } from '@libp2p/interface'

export const TRANSCRIPT_SIG_PREFIX = 'noise-libp2p-transcript:'

/**
 * Upper bound on a single protocol identifier, so that the uint16 length
 * prefix in the canonical encoding cannot overflow.
 */
const MAX_PROTOCOL_LENGTH = 0xffff

/**
 * Upper bound on how many protocols a peer may claim. Verification cost is
 * linear in the encoded length, and a peer has no legitimate reason to
 * configure hundreds of connection encrypters.
 */
const MAX_PROTOCOLS = 32

/**
 * How strictly a peer treats the binding. `off` neither sends the field nor
 * checks it, `warn` sends it and logs a mismatch, `enforce` sends it and
 * aborts the handshake on a mismatch.
 *
 * A peer that does not send the field at all is never treated as an attack in
 * any mode, because that is indistinguishable from an older implementation.
 */
export type TranscriptBindingMode = 'off' | 'warn' | 'enforce'

/**
 * Which of the two bindings in TRANSCRIPT_BINDING_SPEC.md is in use.
 *
 * `extension` carries a separate signature in NoiseExtensions and stays wire
 * compatible with peers that do not implement it. `identity` folds the
 * binding into identity_sig, which is one signature instead of two but is not
 * incrementally deployable.
 */
export type TranscriptBindingVariant = 'extension' | 'identity'

export class DowngradeDetectedError extends Error {
  public code: string

  constructor (message: string) {
    super(message)
    this.code = DowngradeDetectedError.code
  }

  static readonly code = 'ERR_SECURITY_PROTOCOL_DOWNGRADE'
}

/**
 * Encode a protocol list unambiguously: each identifier as a big-endian uint16
 * length followed by its UTF-8 bytes.
 *
 * The length prefixes matter. Plain concatenation would let ['ab', 'c'] and
 * ['a', 'bc'] produce the same bytes, so an attacker could substitute one list
 * for another under a signature that is valid for both.
 */
export function canonicalProtocols (protocols: string[]): Uint8Array {
  if (protocols.length > MAX_PROTOCOLS) {
    throw new Error(`too many security protocols: ${protocols.length} > ${MAX_PROTOCOLS}`)
  }

  const parts: Uint8Array[] = []
  let length = 0

  for (const protocol of protocols) {
    const bytes = uint8ArrayFromString(protocol, 'utf-8')

    if (bytes.byteLength > MAX_PROTOCOL_LENGTH) {
      throw new Error(`security protocol identifier is too long: ${bytes.byteLength} bytes`)
    }

    parts.push(uint16BEEncode(bytes.byteLength), bytes)
    length += 2 + bytes.byteLength
  }

  return uint8ArrayConcat(parts, length)
}

/**
 * The bytes a peer signs to bind its protocol list to this handshake.
 *
 * `payloadHash` is the Noise transcript hash the handshake payload is
 * encrypted under. Both peers hold the same value for a given payload, so no
 * extra round trip is needed to agree on what was signed.
 */
export function transcriptSignaturePayload (payloadHash: Uint8Array, protocols: string[]): Uint8Array {
  const prefix = uint8ArrayFromString(TRANSCRIPT_SIG_PREFIX)
  const canonical = canonicalProtocols(protocols)

  return uint8ArrayConcat(
    [prefix, payloadHash, canonical],
    prefix.byteLength + payloadHash.byteLength + canonical.byteLength
  )
}

/**
 * Produce the two extension fields a peer contributes under variant A.
 */
export async function createTranscriptBinding (
  privateKey: PrivateKey,
  payloadHash: Uint8Array,
  protocols: string[]
): Promise<Pick<NoiseExtensions, 'securityProtocols' | 'transcriptSig'>> {
  return {
    securityProtocols: protocols,
    transcriptSig: await privateKey.sign(transcriptSignaturePayload(payloadHash, protocols))
  }
}

/**
 * Whether a received payload carries a usable binding. A peer that omits the
 * fields is an older peer, not an attacker.
 *
 * The two variants look different on the wire. Under `extension` the list is
 * only trustworthy alongside its own signature, so both fields must be
 * present. Under `identity` the list is covered by identity_sig, which has
 * already been verified by the time this is called, and transcript_sig is
 * deliberately empty.
 */
export function hasTranscriptBinding (extensions: NoiseExtensions | undefined, variant: TranscriptBindingVariant): boolean {
  if (extensions == null || extensions.securityProtocols.length === 0) {
    return false
  }

  return variant === 'identity' || extensions.transcriptSig.byteLength > 0
}

/**
 * What multistream-select should have selected, given the dialer's ordered
 * offer and the listener's supported set: the dialer's most preferred protocol
 * that the listener also supports.
 *
 * Both peers evaluate this over the same two lists once the payloads have been
 * exchanged, so both reach the same answer without exchanging the answer.
 */
export function expectedProtocol (dialerOffered: string[], listenerSupported: string[]): string | undefined {
  return dialerOffered.find(protocol => listenerSupported.includes(protocol))
}

/**
 * Everything a handshake needs to know to apply transcript binding. Assembled
 * once by the connection encrypter and threaded through to the handshake.
 */
export interface TranscriptBindingConfig {
  mode: TranscriptBindingMode
  variant: TranscriptBindingVariant
  /**
   * The security protocols this peer has configured, in preference order.
   */
  protocols: string[]
  /**
   * The protocol identifier this handshake is running under.
   */
  actualProtocol: string
  /**
   * Called whenever a mismatch is detected, in both warn and enforce mode.
   * Warn mode is where a deployment collects rollout data, so the signal has
   * to be observable there too, not only when the handshake aborts.
   */
  onDetected?(): void
}

/**
 * Resolve the user-facing option into the config the handshake uses.
 *
 * `actualProtocol` is the protocol identifier of the encrypter doing the
 * resolving, which is by definition the one this handshake runs under.
 */
export function toTranscriptBindingConfig (
  init: { mode?: TranscriptBindingMode, variant?: TranscriptBindingVariant, securityProtocols: string[] } | undefined,
  actualProtocol: string,
  onDetected?: () => void
): TranscriptBindingConfig | undefined {
  if (init == null) {
    return undefined
  }

  if (!init.securityProtocols.includes(actualProtocol)) {
    throw new Error(
      `transcriptBinding.securityProtocols must include this encrypter's own protocol ${actualProtocol}, got [${init.securityProtocols.join(', ')}]`
    )
  }

  return {
    mode: init.mode ?? 'enforce',
    variant: init.variant ?? 'extension',
    protocols: init.securityProtocols,
    actualProtocol,
    onDetected
  }
}

/**
 * The per-payload binding, or undefined when binding is disabled or the
 * transcript hash is not available yet.
 */
export function bindingFor (config?: TranscriptBindingConfig, payloadHash?: Uint8Array): TranscriptBindingArgs | undefined {
  if (config == null || config.mode === 'off' || payloadHash == null) {
    return undefined
  }

  return { payloadHash, protocols: config.protocols, variant: config.variant }
}

export interface TranscriptBindingArgs {
  payloadHash: Uint8Array
  protocols: string[]
  variant: TranscriptBindingVariant
}

/**
 * The half of a negotiation check that does not depend on the remote payload.
 */
export function negotiationCheckFor (config: TranscriptBindingConfig | undefined, log: Logger): Pick<NegotiationCheck, 'mode' | 'variant' | 'localProtocols' | 'actualProtocol' | 'onDetected' | 'log'> {
  return {
    mode: config?.mode ?? 'off',
    variant: config?.variant ?? 'extension',
    localProtocols: config?.protocols ?? [],
    actualProtocol: config?.actualProtocol ?? '',
    onDetected: config?.onDetected,
    log
  }
}

export interface NegotiationCheck {
  mode: TranscriptBindingMode
  variant: TranscriptBindingVariant
  /**
   * True if this peer dialled, i.e. it is the one whose offer order decides
   * the outcome.
   */
  initiator: boolean
  /**
   * The security protocols this peer has configured, in preference order.
   */
  localProtocols: string[]
  /**
   * The protocol identifier this handshake is actually running under.
   */
  actualProtocol: string
  /**
   * The verified payload received from the remote peer.
   */
  remoteExtensions?: NoiseExtensions
  onDetected?(): void
  log: Logger
}

/**
 * Compare the negotiated protocol against what the two signed offers imply.
 *
 * The signature over `remoteExtensions` must already have been verified
 * against the remote identity key before this is called: an unverified list is
 * attacker-controlled and checking it proves nothing.
 */
export function checkNegotiation (check: NegotiationCheck): void {
  const { mode, variant, initiator, localProtocols, actualProtocol, remoteExtensions, onDetected, log } = check

  if (mode === 'off') {
    return
  }

  if (!hasTranscriptBinding(remoteExtensions, variant)) {
    log.trace('remote peer sent no transcript binding, skipping downgrade check')
    return
  }

  const remoteProtocols = remoteExtensions?.securityProtocols ?? []
  const [dialerOffered, listenerSupported] = initiator
    ? [localProtocols, remoteProtocols]
    : [remoteProtocols, localProtocols]

  const expected = expectedProtocol(dialerOffered, listenerSupported)

  if (expected === actualProtocol) {
    return
  }

  const detail = expected == null
    ? `the two offers have no protocol in common, yet ${actualProtocol} was negotiated`
    : `${expected} should have been negotiated, but this session is running ${actualProtocol}`

  const message = `security protocol downgrade detected: ${detail} ` +
    `(dialer offered [${dialerOffered.join(', ')}], listener supports [${listenerSupported.join(', ')}])`

  onDetected?.()

  if (mode === 'warn') {
    log.error(message)
    return
  }

  throw new DowngradeDetectedError(message)
}
