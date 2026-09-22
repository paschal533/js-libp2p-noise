/* eslint-disable no-console */
/**
 * Deterministic cross-implementation vectors for transcript-bound security
 * protocol negotiation.
 *
 * The point of these is wire compatibility. Two implementations that agree on
 * the design but disagree by one byte on the canonical encoding, the signature
 * prefix or the protobuf field numbers will each pass their own tests and fail
 * to interoperate. These vectors are the shared reference: any implementation
 * can check itself against the committed file without running a handshake.
 *
 * Writes test/fixtures/transcript-binding-vectors.json.
 *
 * Run after build:
 *   node scripts/generate-transcript-vectors.js
 *
 * Security note: the identity key is seeded so the vectors are reproducible.
 * Production code always uses cryptographically random keys.
 */

import { writeFileSync } from 'fs'
import { dirname, resolve } from 'path'
import { fileURLToPath } from 'url'
import { generateKeyPairFromSeed } from '@libp2p/crypto/keys'
import { toString as uint8ArrayToString } from 'uint8arrays/to-string'
import { NoiseHandshakePayload } from '../dist/src/proto/payload.js'
import { canonicalProtocols, transcriptSignaturePayload, TRANSCRIPT_SIG_PREFIX } from '../dist/src/transcript-binding.js'
import { createHandshakePayload, getSignaturePayload } from '../dist/src/utils.js'

const here = dirname(fileURLToPath(import.meta.url))

function hex (value) {
  return uint8ArrayToString(value instanceof Uint8Array ? value : value.subarray(), 'base16')
}

// Fixed inputs. A second implementation feeds these in and must reproduce
// every output byte for byte.
const IDENTITY_SEED = new Uint8Array(32).fill(7)
const STATIC_KEY = new Uint8Array(32).fill(3)
const PAYLOAD_HASH = Uint8Array.from({ length: 32 }, (_, i) => i)

const PROTOCOL_LISTS = [
  ['/noise'],
  ['/noise', '/noise-mlkem768-hfs/0.2.0'],
  ['/noise-mlkem768-hfs/0.2.0', '/noise', '/tls/1.0.0'],
  // Deliberately adversarial: without length prefixes these two collide with
  // each other, so an implementation that concatenates naively will produce
  // the same canonical encoding for both and fail this file.
  ['ab', 'c'],
  ['a', 'bc']
]

const privateKey = await generateKeyPairFromSeed('Ed25519', IDENTITY_SEED)

const vectors = []

for (const protocols of PROTOCOL_LISTS) {
  const extensionPayload = await createHandshakePayload(
    privateKey, STATIC_KEY, undefined, { payloadHash: PAYLOAD_HASH, protocols, variant: 'extension' }
  )
  const identityPayload = await createHandshakePayload(
    privateKey, STATIC_KEY, undefined, { payloadHash: PAYLOAD_HASH, protocols, variant: 'identity' }
  )

  vectors.push({
    protocols,
    canonical_protocols: hex(canonicalProtocols(protocols)),
    transcript_sig_payload: hex(transcriptSignaturePayload(PAYLOAD_HASH, protocols)),
    identity_sig_payload_bound: hex(getSignaturePayload(STATIC_KEY, { payloadHash: PAYLOAD_HASH, protocols })),
    extension_variant: {
      handshake_payload: hex(extensionPayload),
      transcript_sig: hex(NoiseHandshakePayload.decode(extensionPayload).extensions.transcriptSig)
    },
    identity_variant: {
      handshake_payload: hex(identityPayload),
      identity_sig: hex(NoiseHandshakePayload.decode(identityPayload).identitySig)
    }
  })
}

const out = {
  description:
    'Cross-implementation vectors for transcript-bound security protocol negotiation. ' +
    'Fixed inputs, so any implementation can verify its encoding and signatures without a handshake. ' +
    'Seeded keys: do NOT use in production.',
  generated_by: '@chainsafe/libp2p-noise (js-libp2p-noise)',
  spec: 'TRANSCRIPT_BINDING_SPEC.md',
  identity_key_type: 'Ed25519',
  identity_key_seed: hex(IDENTITY_SEED),
  identity_public_key: hex(privateKey.publicKey.raw),
  noise_static_public_key: hex(STATIC_KEY),
  payload_hash: hex(PAYLOAD_HASH),
  transcript_sig_prefix: TRANSCRIPT_SIG_PREFIX,
  identity_sig_prefix: 'noise-libp2p-static-key:',
  protobuf_field_numbers: {
    'NoiseExtensions.security_protocols': 4,
    'NoiseExtensions.transcript_sig': 5
  },
  vectors
}

const path = resolve(here, '../test/fixtures/transcript-binding-vectors.json')
writeFileSync(path, `${JSON.stringify(out, null, 2)}\n`)
console.log(`wrote ${vectors.length} vectors to ${path}`)
