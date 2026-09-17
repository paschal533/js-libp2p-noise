# Benchmark results

`Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` against classical `Noise_XX_25519_ChaChaPoly_SHA256`.

Node.js v22.17.1, Windows 11 x64. Medians over 5 paired passes of 30 iterations
(`benchmarks/paired-passes.mjs`), sampling the classical and hybrid handshakes interleaved so
machine drift is largely common-mode, and its effect on the ratio is largely (not fully)
cancelled rather than left to land directly in it. Last refreshed 2026-09-17, one session
alongside paired Python, Nim and Rust runs on the same machine.

This file reports this run's own figures. Comparison against any earlier session is confined to
one section near the end ("Previous session, for reference"), which gives each earlier value's
own source and statistic with no delta computed against it. AC power was checked after this run
(not during) and found on (`Win32_Battery.BatteryStatus=2`); no AC-power or power-plan record
exists from any earlier session to compare against.

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
classical) -- together about 33.6 ms, close to the 32.9 ms gap; the residual exists because a
median of per-pass differences is not the same number as the difference of two medians. Holding
the *native* backend constant on both sides instead gives a different quantity, the
native-backend KEM cost: about 8.6 ms (`kemCostNative`, the median of the 5 per-pass differences),
roughly 36% of the 24.10 ms native hybrid handshake. The cross-language KEM-share table in
`pq-noise-artifacts` instead reports 8.70 ms for this same quantity -- the *difference of the two
pass-median figures* (24.10 - 15.40) rather than the median of per-pass differences; the two
statistics do not agree to the decimal for the same reason the 32.9 ms gap here is not exactly
6.7 + 26.9. These KEM-cost figures are not interchangeable and should not be added together.

The pure-JavaScript backend can also be held constant on both sides, which gives a lower ratio
again, but the native figure is the one reported: it is the configuration a deployment would
actually use, and it is what makes the number comparable with the Rust, Nim and Python
measurements, each of which uses its own optimised stack.

## Cross-language comparison, this run only

Absolute milliseconds are not comparable across implementations -- each harness measures a
different transport. Only the within-language classical-vs-hybrid ratio is a sound comparison
across languages, and the full breakdown (KEM library, sampling method, raw files) lives in the
`pq-noise-artifacts` repository, not duplicated here. All figures in this table are from this
run; none is compared to any earlier session in this table:

| language | overhead, this run | KEM share, this run |
|---|---:|---:|
| Python (`kyber-py`) | 12.0x (range 11.3-12.4) | ~92% |
| **JavaScript** (`@noble/post-quantum`) | **1.56x** (range 1.51-1.60) | ~36% |
| Rust (RustCrypto `ml-kem`) | 1.32x (range 1.23-1.61) | ~20%, upper bound |
| Nim (BoringSSL) | 1.19x (range 1.16-1.21) | median 15.9% across 5 passes (17.5%, 17.3%, 14.1%, 15.0%, 15.9%) |

See `pq-noise-artifacts/benchmarks/RESULTS.md` and
`pq-noise-artifacts/benchmarks/2026-09-17/SUMMARY.md` for the KEM-share method, the sampling
method per language, and the anomalies observed in this run.

## Previous session, for reference (not directly comparable)

| Language | Date | Metric | Value | Statistic | Source |
|---|---|---|---:|---|---|
| JavaScript | 2026-09-10 | Classical, native | 6.82 ms | median, 5 passes | research-paper.md:692-696 |
| JavaScript | 2026-09-10 | Hybrid, native | 10.30 ms | median, 5 passes | research-paper.md:710 |
| JavaScript | 2026-09-10 | Overhead, like-for-like native | 1.51x, range 1.51-1.58 | median-based ratio | research-paper.md:890-891 |
| Python | 2026-09-10 | Overhead | 10.7x | ratio of medians, single unpaired run | research-paper.md:843, 890 |
| Rust | 2026-09-10 | Overhead | 1.24x | as published (Sec 7.8 table) | research-paper.md:874, 890 |
| Nim | 2026-09-08 | Overhead | 1.13x, range 1.12-1.14 | median-based ratio | research-paper.md:890-891 |

No delta is computed between this table and the "this run" table above. Reasons: this run's
absolute latencies differ from the 2026-09-10 session's by roughly a factor of two for JS, Python
and Rust; the paper separately documents day-to-day drift of a similar size on this same machine
(research-paper.md:651); and the Python figures span a sampling-method change (2026-09-10 ran
classical and hybrid handshakes in separate phases, this run's harness -- built in this task's
Step 1 -- interleaves them per iteration). Nim's prior figure is from 2026-09-08, a different
session from the other three languages' 2026-09-10. The full timing comparison, with each pair
using the same statistic on both sides, is in `pq-noise-artifacts/benchmarks/2026-09-17/SUMMARY.md`.

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
ciphertext plus its 16-byte AEAD tag (`ekem1`). Msg C is identical to classical XX.

## Limitations

- **One machine, one OS, one Node version.** Absolute milliseconds are indicative; the ratios are
  the claim.
- **Medians of 5 passes x 30 iterations.** The like-for-like native ratio spans 1.51x to 1.60x
  across this run's 5 passes, but this is a shared desktop, not an isolated benchmarking rig.
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
X-Wing build measured across mismatched backends; the table earlier in this document supersedes
it.
