# Benchmark results

`Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` against classical `Noise_XX_25519_ChaChaPoly_SHA256`.

Node.js v22.17.1, Windows 11 x64. Medians over 5 paired passes of 30 iterations
(`benchmarks/paired-passes.mjs`), sampling the classical and hybrid handshakes interleaved so
machine drift is largely common-mode, and its effect on the ratio is largely (not fully)
cancelled rather than left to land directly in it. Last refreshed 2026-09-17, one session
alongside paired Python, Nim and Rust runs on the same machine (see cross-language table below).

**The whole machine measured slower on 2026-09-17 than on 2026-09-10, before any ratio is
computed:** classical (native) 6.82 -> 15.40 ms (2.26x), hybrid (native) 10.30 -> 24.10 ms
(2.34x). AC power was confirmed on and the power plan (Balanced) is unchanged from the prior
session; the cause is not established. Because KEM and non-KEM cost need not scale together
under whatever changed, the overhead ratio below may not be directly comparable to the
2026-09-10 one even though it is internally sound. See
`pq-noise-artifacts/benchmarks/2026-09-17/SUMMARY.md` for the same caveat applied to all four
languages.

**The comparison has to hold the backend constant.** `noise()` defaults to `defaultCrypto` (Node
native plus AssemblyScript WASM) while `noiseHFS()` defaults to `pureJsCrypto` (`@noble/*`, all
JavaScript), so timing the two default configurations against each other varies the backend as
well as the KEM.

| comparison | overhead |
|---|---:|
| default configurations, backend varies with the KEM | 3.24x (per-pass range 3.19 to 3.52) |
| **like for like, backend held constant** | **1.56x** (per-pass range 1.51 to 1.60) |

The 32.9 ms gap between the two default configurations (hybrid pure-JS 48.25 ms vs classical
native 15.40 ms) decomposes, per pass then medianed, into about 6.7 ms of KEM cost within the
pure-JS backend and about 26.9 ms of backend substitution (pure-JS classical minus native
classical) — together about 33.6 ms, close to the 32.9 ms gap; the small residual is because a
median of per-pass differences is not the same number as the difference of two medians. Holding
the *native* backend constant on both sides instead gives a different quantity, the
native-backend KEM cost: about 8.6 ms, roughly 36% of the 24.10 ms native hybrid handshake. These
two KEM-cost figures (6.7 ms pure-JS, 8.6 ms native) are not the same measurement.

(2026-09-10 figures, for reference: 3.54x default, range 3.40-3.64; 1.51x like-for-like, range
1.51-1.58. The like-for-like ratio moved from 1.51x to 1.56x, about +3%; see the artefacts
SUMMARY linked below for the whole-machine-slowdown caveat that applies to this comparison.)

The pure-JavaScript backend can also be held constant on both sides, which gives a lower ratio
again, but the native figure is the one reported: it is the configuration a deployment would
actually use, and it is what makes the number comparable with the Rust, Nim and Python
measurements, each of which uses its own optimised stack.

## Cross-language comparison

Absolute milliseconds are not comparable across implementations — each harness measures a
different transport. Only the within-language classical-vs-hybrid ratio is a sound comparison
across languages, and the full breakdown (KEM library, sampling method, raw files) lives in the
`pq-noise-artifacts` repository, not duplicated here:

| language | overhead (2026-09-10) | overhead (2026-09-17) | shift |
|---|---:|---:|---|
| Python (`kyber-py`) | 10.7x | 12.0x (range 11.3-12.4) | +1.3x, ~+12% — the largest overhead shift |
| **JavaScript** (`@noble/post-quantum`) | 1.51x | **1.56x** (range 1.51-1.60) | +0.05x, ~+3% |
| Rust (RustCrypto `ml-kem`) | 1.24x | 1.32x (range 1.23-1.61) | +0.08x, ~+6.5% |
| Nim (BoringSSL) | 1.13x | 1.19x (range 1.16-1.21) | +0.06x, ~+5% |

All four overhead ratios moved up; the whole machine measured slower on every language before any
ratio was taken (see the artefacts SUMMARY), so it is an open question how much of this reflects
the protocol versus the same unexplained slowdown. See `pq-noise-artifacts/benchmarks/RESULTS.md`
and `pq-noise-artifacts/benchmarks/2026-09-17/SUMMARY.md` for KEM-share breakdowns (computed by
one consistent method, the delta method `(hybrid-classical)/hybrid` — an earlier draft of this
page compared two different formulas across dates and wrongly reported a large Python KEM-share
"shift" that a single consistent method does not show), sampling method per language, and the
other anomalies observed in the 2026-09-17 run.

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
