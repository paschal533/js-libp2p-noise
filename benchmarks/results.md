# Benchmark results

`Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` against classical `Noise_XX_25519_ChaChaPoly_SHA256`.

Node.js v22.17.1, Windows 11 x64. Medians over 5 paired passes of 30 iterations
(`benchmarks/paired-passes.mjs`), sampling the classical and hybrid handshakes interleaved so
machine drift is common-mode rather than landing in the ratio. Last refreshed 2026-09-17, one
session alongside paired Python, Nim and Rust runs on the same machine (see cross-language table
below).

**The comparison has to hold the backend constant.** `noise()` defaults to `defaultCrypto` (Node
native plus AssemblyScript WASM) while `noiseHFS()` defaults to `pureJsCrypto` (`@noble/*`, all
JavaScript), so timing the two default configurations against each other varies the backend as
well as the KEM.

| comparison | overhead |
|---|---:|
| default configurations, backend varies with the KEM | 3.24x (per-pass range 3.19 to 3.52) |
| **like for like, backend held constant** | **1.56x** (per-pass range 1.51 to 1.60) |

Of the 32.9 ms separating the two default configurations, about four fifths (82%, ~27.0 ms) is the
backend substitution and about 8.6 ms is the KEM, which is roughly 36% of the hybrid (native)
handshake.

(2026-09-10 figures, for reference: 3.54x default, range 3.40-3.64; 1.51x like-for-like, range
1.51-1.58. Both ratios shifted mildly upward on 2026-09-17; see the artefacts SUMMARY linked below
for the cross-run comparison and the reasoning about a possible shared cause.)

The pure-JavaScript backend can also be held constant on both sides, which gives a lower ratio
again, but the native figure is the one reported: it is the configuration a deployment would
actually use, and it is what makes the number comparable with the Rust, Nim and Python
measurements, each of which uses its own optimised stack.

## Cross-language comparison

Absolute milliseconds are not comparable across implementations — each harness measures a
different transport. Only the within-language classical-vs-hybrid ratio is a sound comparison
across languages, and the full breakdown (KEM library, sampling method, raw files) lives in the
`pq-noise-artifacts` repository, not duplicated here:

| language | overhead (2026-09-10) | overhead (2026-09-17) |
|---|---:|---:|
| Python (`kyber-py`) | 10.7x | 12.0x (range 11.3-12.4) |
| **JavaScript** (`@noble/post-quantum`) | 1.51x | **1.56x** (range 1.51-1.60) |
| Rust (RustCrypto `ml-kem`) | 1.24x | 1.32x (range 1.23-1.61) |
| Nim (BoringSSL) | 1.13x | 1.19x (range 1.16-1.21) |

See `pq-noise-artifacts/benchmarks/RESULTS.md` and
`pq-noise-artifacts/benchmarks/2026-09-17/SUMMARY.md` for KEM-share breakdowns, sampling method per
language, and the anomalies observed in the 2026-09-17 run (notably Python's KEM share of the
hybrid handshake falling from ~91% to ~68% even as its overhead ratio rose).

## Wire sizes

Read directly from the interoperability test vectors in `../test/fixtures/pqc-test-vectors.json`, consistent across all five:

| message | classical XX | XXhfs | delta |
|---|---:|---:|---:|
| A, initiator to responder | 32 B | **1,216 B** | +1,184 B |
| B, responder to initiator | 96 B | **1,200 B** | +1,104 B |
| C, initiator to responder | 64 B | **64 B** | 0 |
| **total** | **192 B** | **2,480 B** | **+2,288 B** |

Every message fits inside a standard 1,500-byte MTU: Message A at 1,216 bytes plus libp2p's
two-byte length prefix sits below the 1,460-byte maximum segment size, so the hybrid handshake
adds no IP fragmentation and no additional round trip.

Msg A carries the 1,184-byte ML-KEM-768 encapsulation key (`e1`); msg B carries the 1,088-byte
ciphertext plus its 16-byte AEAD tag (`ekem1`). Msg C is unchanged from classical XX.

## Limitations

- **One machine, one OS, one Node version.** Absolute milliseconds are indicative; the ratios are
  the claim.
- **Medians of 5 passes x 30 iterations.** The spread across passes is small (the like-for-like
  native ratio moves only between 1.51x and 1.60x, 2026-09-17 run), but this is a shared desktop,
  not an isolated benchmarking rig.
- **Handshake latency only.** This does not measure throughput after the handshake, memory, or
  behaviour under connection churn.
- **`@noble/post-quantum` does not claim constant-time execution.** Its own documentation notes
  that JIT compilation, garbage collection and bigint arithmetic do not provide the guarantees a
  formal constant-time claim needs. These numbers are performance measurements and say nothing
  about side-channel resistance.

## Re-running

```bash
pnpm build
node benchmarks/paired-passes.mjs
```

The raw output of the run reported here is in
`pq-noise-artifacts/benchmarks/2026-09-17/js-paired-passes.json`. An older copy lives in
`paired-passes-results.json`. The previous version of this file reported a +4.9x figure from an
X-Wing build measured across mismatched backends; it is superseded by the table above.
