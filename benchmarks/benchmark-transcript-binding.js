/* eslint-disable no-console */
// Measures what transcript-bound security protocol negotiation costs, for
// both binding variants, against the same handshake with the binding off.
//
// Reports two things that the design note should not be asserting without
// numbers:
//   1. wire cost, as the encoded handshake payload size
//   2. CPU cost, as full handshake wall time over an in-memory connection pair
//
// Run after `npm run build`:
//   node benchmarks/benchmark-transcript-binding.js

import { generateKeyPairFromSeed } from '@libp2p/crypto/keys'
import { defaultLogger } from '@libp2p/logger'
import { peerIdFromPrivateKey } from '@libp2p/peer-id'
import { multiaddrConnectionPair } from '@libp2p/utils'
import { Noise } from '../dist/src/noise.js'
import { createHandshakePayload } from '../dist/src/utils.js'

const HFS = '/noise-mlkem768-hfs/0.2.0'
const CLASSICAL = '/noise'
// Two realistic protocol identifiers, ordered so that /noise is the honest
// outcome: these peers are classical-first, so a /noise session is exactly
// what the two offers imply and the check passes. That isolates the cost of
// the mechanism from the cost of the abort path.
const OFFERED = [CLASSICAL, HFS]

const ITERATIONS = Number(process.env.ITERATIONS ?? 200)
const WARMUP = Number(process.env.WARMUP ?? 30)

function seed (byte) {
  const s = new Uint8Array(32)
  s.fill(byte)
  return s
}

const upgrader = { getStreamMuxers: () => new Map() }

async function makePeer (byte) {
  const privateKey = await generateKeyPairFromSeed('Ed25519', seed(byte))
  return { privateKey, peerId: peerIdFromPrivateKey(privateKey) }
}

const local = await makePeer(1)
const remote = await makePeer(2)

// ---- wire cost -------------------------------------------------------------

const payloadHash = new Uint8Array(32).fill(9)
const staticKey = new Uint8Array(32).fill(3)

async function payloadSize (binding) {
  const bytes = await createHandshakePayload(local.privateKey, staticKey, undefined, binding)
  return bytes.byteLength
}

const sizes = {
  off: await payloadSize(undefined),
  extension: await payloadSize({ payloadHash, protocols: OFFERED, variant: 'extension' }),
  identity: await payloadSize({ payloadHash, protocols: OFFERED, variant: 'identity' })
}

// ---- handshake cost --------------------------------------------------------

function makeNoise (peer, transcriptBinding) {
  return new Noise({ ...peer, logger: defaultLogger(), upgrader }, { transcriptBinding })
}

async function oneHandshake (transcriptBinding) {
  const [inbound, outbound] = multiaddrConnectionPair()
  await Promise.all([
    makeNoise(local, transcriptBinding).secureOutbound(outbound, { remotePeer: remote.peerId }),
    makeNoise(remote, transcriptBinding).secureInbound(inbound, { remotePeer: local.peerId })
  ])
}

function summarise (label, raw) {
  const samples = [...raw].sort((a, b) => a - b)

  return {
    label,
    mean: samples.reduce((a, b) => a + b, 0) / samples.length,
    median: samples[Math.floor(samples.length / 2)],
    p95: samples[Math.floor(samples.length * 0.95)],
    min: samples[0]
  }
}

/**
 * Time every configuration interleaved, in a shuffled order within each round.
 *
 * Running each configuration to completion in turn does not work here: this
 * machine drifts by more than the effect being measured, so whichever
 * configuration runs first is penalised. An earlier version of this benchmark
 * reported the bound handshakes as faster than the unbound one, which is not
 * possible and is a property of the harness, not the code. Interleaving makes
 * drift hit all configurations equally.
 *
 * @param {Array<[string, object|undefined]>} configs - label and binding option pairs
 * @returns {Promise<object[]>} one summary per configuration, in the given order
 */
async function timeInterleaved (configs) {
  const samples = new Map(configs.map(([label]) => [label, []]))

  for (let i = 0; i < WARMUP; i++) {
    for (const [, binding] of configs) {
      await oneHandshake(binding)
    }
  }

  for (let i = 0; i < ITERATIONS; i++) {
    const round = [...configs].sort(() => Math.random() - 0.5)

    for (const [label, binding] of round) {
      const start = process.hrtime.bigint()
      await oneHandshake(binding)
      samples.get(label).push(Number(process.hrtime.bigint() - start) / 1e6)
    }
  }

  return configs.map(([label]) => summarise(label, samples.get(label)))
}

const configs = [
  ['off', undefined],
  ['extension', { variant: 'extension', securityProtocols: OFFERED }],
  ['identity', { variant: 'identity', securityProtocols: OFFERED }]
]

const timings = await timeInterleaved(configs)

// ---- report ----------------------------------------------------------------

const baselineSize = sizes.off
const baselineTime = timings.find(t => t.label === 'off').median

console.log(`node ${process.version}, ${ITERATIONS} handshakes per configuration after ${WARMUP} warmup`)
console.log(`identity key: Ed25519, offered protocols: [${OFFERED.join(', ')}]`)
console.log('')
console.log('handshake payload size (bytes)')
for (const [label, size] of Object.entries(sizes)) {
  const delta = size - baselineSize
  console.log(`  ${label.padEnd(10)} ${String(size).padStart(5)}  ${delta === 0 ? '' : `(+${delta})`}`)
}
console.log('')
console.log('full /noise handshake, milliseconds')
console.log(`  ${'config'.padEnd(10)} ${'median'.padStart(8)} ${'mean'.padStart(8)} ${'p95'.padStart(8)}   vs off`)
for (const t of timings) {
  const ratio = t.median / baselineTime
  console.log(
    `  ${t.label.padEnd(10)} ${t.median.toFixed(3).padStart(8)} ${t.mean.toFixed(3).padStart(8)} ` +
    `${t.p95.toFixed(3).padStart(8)}   ${t.label === 'off' ? '' : `${ratio.toFixed(2)}x`}`
  )
}
