# Benchmark results

`Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` against classical `Noise_XX_25519_ChaChaPoly_SHA256`.

Node.js v22.17.1, Windows 11 x64. Medians over 5 paired passes of 30 iterations
(`benchmarks/paired-passes.mjs`), sampling the classical and hybrid handshakes interleaved so
machine drift is largely common-mode, and its effect on the ratio is largely (not fully)
cancelled rather than left to land directly in it. Last refreshed 2026-09-17, one session
alongside paired Python, Nim and Rust runs on the same machine.

This file reports this run's own figures. Previously published figures appear only in one
reference table near the end ("Previously published figures (not directly comparable)"), each with
its date, its line in `research-paper.md` and the paper's own wording for its statistic; no delta,
ratio or factor is computed against them. AC power was checked after this run (not during) and
found on (`Win32_Battery.BatteryStatus=2`); no AC-power or power-plan record exists from any
earlier session.

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
`pq-noise-artifacts` instead reports 8.70 ms for a related quantity -- the *difference of the two
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

| language | overhead, this run | overhead statistic | KEM share, this run (delta method) | KEM-share inputs |
|---|---:|---|---:|---|
| Python (`kyber-py`) | 12.0x (range 11.3-12.4) | median and range of the 5 per-pass values, each the median of 50 paired per-iteration ratios | ~92% | 40.08 and 3.35 ms: medians of the 5 per-pass handshake medians |
| **JavaScript** (`@noble/post-quantum`) | **1.56x** (range 1.51-1.60) | median and range of the 5 per-pass values, each the median of 30 per-iteration ratios, native backend on both sides | ~36% | 24.10 and 15.40 ms: medians of the 5 pass-level medians, native backend |
| Rust (RustCrypto `ml-kem`) | 1.32x (range 1.23-1.61) | median and range of the 5 per-pass ratios of `estimates.json` medians (via `rust-passes.tsv`) | ~20%, upper bound | 1.96 and 1.57 ms: medians of the 5 per-pass `estimates.json` medians (via `rust-passes.tsv`) |
| Nim (BoringSSL) | 1.19x (range 1.16-1.21) | median and range of the 5 per-pass ratios of the hybrid median to the classical median | median 15.9% across 5 passes (17.5%, 17.3%, 14.1%, 15.0%, 15.9%) | each pass's own classical and hybrid harness medians, one share per pass |

KEM share is `(hybrid_ms - classical_ms) / hybrid_ms` on the inputs named in the last column.

See `pq-noise-artifacts/benchmarks/RESULTS.md` and
`pq-noise-artifacts/benchmarks/2026-09-17/SUMMARY.md` for the KEM-share method, the sampling
method per language, and the anomalies observed in this run.

## Previously published figures (not directly comparable)

Published values, their statistics and their line numbers are from `research-paper.md`. Each
statistic is quoted in the paper's own words, or given as "as published" where the paper does not
name one. The "This run" columns are filled only for absolute handshake latencies; this run's
overhead and KEM-share figures are in the table above and are not repeated beside the published
ones.

| Language | Metric | Published date | Published value | Statistic, as the paper words it | Paper line | This run, 2026-09-17 | This run's statistic |
|---|---|---|---:|---|---|---:|---|
| JavaScript | Classical handshake, native backend | 2026-09-10 | 6.82 ms | "Medians across five serial passes" (:692); the same value also appears in the table introduced as "Medians of thirty iterations, four repetitions" (:703) | :696, :707 | 15.40 ms | median of the 5 pass-level medians (`summary.medians.xxNative`, `js-paired-passes.json`) |
| JavaScript | Hybrid handshake, native backend | 2026-09-10 | 10.30 ms | "Medians of thirty iterations, four repetitions" (:703) | :710 | 24.10 ms | median of the 5 pass-level medians (`summary.medians.hfsNative`, `js-paired-passes.json`) |
| JavaScript | Like-for-like overhead | 2026-09-10 | 1.51x | as published; "Precision" row reads "1.51–1.58 (5 passes)" (:891) | :890, :891 | -- | -- |
| Python | Overhead | 2026-09-10 | 10.7x | "XXhfs overhead vs classical" (:843); "the quotient of two medians from a single invocation" (:849); "Precision" row reads "single run" (:891) | :843, :849, :890, :891 | -- | -- |
| Rust | Overhead | 2026-09-10 | 1.24x | as published | :874, :890 | -- | -- |
| Nim | Overhead | 2026-09-08 | 1.127x (range 1.117–1.141) | "Paired overhead" (:864); also given as 1.13x with "Precision" "1.12–1.14 (5 passes)" (:890, :891) | :864, :890, :891 | -- | -- |

Every value in the "This run" column is higher than the published value in the same row. No
delta, ratio or factor between a published value and a figure from this run is computed anywhere in
this file, and it is not claimed that any published value was computed with the same statistic as
the corresponding figure from this run. The paper itself states that "absolute latencies are not
comparable between the two sessions" and that "this machine ran roughly twice as fast on 10
September as on 8 September, which is well within the drift documented below"
(research-paper.md:651). The paper's "Paired sampling" row reads "no" for Python (:892); this
run's Python harness, as revised in this task's Step 1, interleaves the classical and hybrid
handshakes per iteration.

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
`paired-passes-results.json`. An earlier version of this file reported a +4.9x figure; that figure is
retracted (it was measured on an X-Wing build across mismatched backends) and is not a result.
