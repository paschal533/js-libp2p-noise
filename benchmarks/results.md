# Benchmark results

`Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` against classical `Noise_XX_25519_ChaChaPoly_SHA256`.

Node.js v22.17.1, Windows 11 x64. Medians over 5 paired passes of 30 iterations
(`benchmarks/paired-passes.mjs`), sampling the classical and hybrid handshakes interleaved so
machine drift is common-mode rather than landing in the ratio.

**The comparison has to hold the backend constant.** `noise()` defaults to `defaultCrypto` (Node
native plus AssemblyScript WASM) while `noiseHFS()` defaults to `pureJsCrypto` (`@noble/*`, all
JavaScript), so timing the two default configurations against each other varies the backend as
well as the KEM.

| comparison | overhead |
|---|---:|
| default configurations, backend varies with the KEM | 3.54x (per-pass range 3.40 to 3.64) |
| **like for like, backend held constant** | **1.51x** (per-pass range 1.51 to 1.58) |

Of the 17.3 ms separating the two default configurations, over four fifths is the backend
substitution and only about 3.5 ms is the KEM, which is roughly 34% of the hybrid handshake.

The pure-JavaScript backend can also be held constant on both sides, which gives a lower ratio
again, but the native figure is the one reported: it is the configuration a deployment would
actually use, and it is what makes the number comparable with the Rust, Nim and Python
measurements, each of which uses its own optimised stack.

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
  native ratio moves only between 1.51x and 1.61x), but this is a shared desktop, not an isolated
  benchmarking rig.
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

The raw output of the run reported here is in `paired-passes-results.json`. The previous version
of this file reported a +4.9x figure from an X-Wing build measured across mismatched backends;
it is superseded by the table above.
