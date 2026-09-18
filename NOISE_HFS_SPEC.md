# Noise HFS Implementation Spec

**Protocol:** `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`  
**libp2p protocol ID:** `/noise-mlkem768-hfs/0.2.0` (what this implementation ships; see §3.1)  
**Status:** Prototype / research implementation  
**Based on:** [Noise HFS spec](https://github.com/noiseprotocol/noise_hfs_spec), PQNoise (ePrint 2022/539), Noise rev 34 §8.2 + FIPS 203

---

## 1. Overview

This document describes the `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` handshake as implemented in `@chainsafe/libp2p-noise`. The handshake is a post-quantum hybrid of the classical Noise XX pattern that adds an ephemeral KEM step (the "HFS" tokens `e1` and `ekem1`) alongside the existing ECDH operations.

The result is a protocol where forward secrecy is secure if **either** X25519 **or** ML-KEM-768 is unbroken. Classical security is preserved; quantum-safe forward secrecy is added on top.

---

## 2. Algorithm Identifiers

| Role | Algorithm | Library |
|------|-----------|---------|
| KEM | ML-KEM-768 (FIPS 203) | `@noble/post-quantum` (`ml_kem768`) |
| DH | X25519 | `@noble/curves` (via pureJsCrypto) |
| AEAD | ChaCha20-Poly1305 | `@noble/ciphers` |
| Hash / HKDF | SHA-256 | Web Crypto / noble |

ML-KEM-768 is specified in FIPS 203. The 32-byte shared secret it outputs is fed into `MixKey()`.

An earlier revision of this implementation used X-Wing (ML-KEM-768 combined with X25519 under a SHA3-256 combiner). It was replaced by raw ML-KEM-768 so that the handshake matches the pattern implemented in `libp2p/rust-libp2p#6481` and specified in `libp2p/specs#727`. (The change was originally made to match `libp2p/specs#716`, this author's own draft; #716 was closed on 2026-09-18 in favour of #727, which specifies the same raw ML-KEM-768 pattern.) The hybrid property is unchanged: X25519 is already present in the XX pattern, so forward secrecy still holds if either primitive survives.

---

## 3. Handshake Pattern

The XXhfs pattern adds two tokens to the classical XX pattern:

```
Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256:
  <- s
  ...
  -> e, e1
  <- e, ee, ekem1, s, es
  -> s, se
```

The `e1` token carries the initiator's KEM ephemeral public key. The `ekem1` token carries the responder's KEM encapsulation (ciphertext encrypted under the `ee`-derived key), and mixes the resulting KEM shared secret into the chaining key.

### 3.1 Protocol identifier

Earlier drafts used `ML-KEM-768`, which Noise §8.2 does not permit (algorithm names are alphanumeric plus `/`). Because the name is hashed into `h`, the rename is wire-incompatible, and the protocol id moved to 0.2.0 so mismatched peers fail at negotiation.

`/noise-mlkem768-hfs/0.2.0` is the identifier this implementation ships, not a spec-endorsed one. `libp2p/specs#727`, the Working Draft for this suite, writes `/noise-mlkem768-hfs/0.1.0` and lists the identifier string as the first of its open issues. This implementation will follow whatever #727 settles on.

---

## 4. IKem Interface

The KEM is abstracted behind `IKem` in `src/kem.ts`:

```ts
interface IKem {
  PUBKEY_LEN: number   // ML-KEM-768: 1184
  CT_LEN:     number   // ML-KEM-768: 1088
  SS_LEN:     number   // ML-KEM-768: 32
  SK_LEN:     number   // ML-KEM-768: 2400

  generateKemKeyPair(): KemKeyPair
  encapsulate(remotePublicKey: Uint8Array): KemEncapsulateResult
  decapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array
}
```

The default implementation is `pqcKem` from `src/crypto/pqc.ts`, which uses `ml_kem768` from `@noble/post-quantum/ml-kem.js`. Any object conforming to `IKem` can be passed as `kemBackend` in `NoiseHFSInit`.

---

## 5. Wire Format

All sizes assume an empty libp2p handshake payload (no `NoiseHandshakePayload`).

### 5.1 Message A: initiator to responder

```
+-------------------+-----------------------+---------+
| e.publicKey       | e1.publicKey          | payload |
| 32 bytes          | 1184 bytes            | 0 bytes |
+-------------------+-----------------------+---------+
                    Total: 1216 bytes
```

- `e.publicKey`: X25519 ephemeral public key, sent in plaintext (no cipher key exists yet).
- `e1.publicKey`: ML-KEM-768 ephemeral encapsulation key, 1184 bytes. Sent via `encryptAndHash()`, which is a plain `MixHash()` at this stage because there is no cipher key.

### 5.2 Message B: responder to initiator

```
+-------------------+-----------------------+--------------------+---------+
| e.publicKey       | enc(KEM ciphertext)   | enc(s.publicKey)   | payload |
| 32 bytes          | 1104 bytes            | 48 bytes           | 16 bytes|
+-------------------+-----------------------+--------------------+---------+
                    Total: 1200 bytes (16-byte payload AEAD tag)
```

- `e.publicKey`: Responder's X25519 ephemeral, plaintext.
- After `ee`: `MixKey(DH(e_R, e_I))` establishes the first cipher key.
- `enc(KEM ciphertext)`: Responder encapsulates to `e1.publicKey`, producing a 1088-byte ML-KEM-768 ciphertext. The ciphertext is AEAD-encrypted under the `ee`-derived key (adds 16-byte tag). Total: 1104 bytes.
- After `ekem1`: `MixKey(kemSharedSecret)` strengthens the chaining key.
- `enc(s.publicKey)`: Responder static public key (32 bytes + 16-byte AEAD tag = 48 bytes), encrypted under the KEM-strengthened key.
- After `es`: `MixKey(DH(e_I, s_R))` mixes classical auth.
- `payload`: `encryptAndHash(NoiseHandshakePayload)` -- 16-byte AEAD tag on empty payload.

### 5.3 Message C: initiator to responder

```
+--------------------+---------+
| enc(s.publicKey)   | payload |
| 48 bytes           | 16 bytes|
+--------------------+---------+
                    Total: 64 bytes (empty payload)
```

This message is identical to the classical Noise XX pattern. The initiator sends its static key (`se` completes the mutual authentication).

### 5.4 Compared to classical XX

| Message | Classical XX | XXhfs (PQ) | Delta |
|---------|------------:|----------:|------:|
| Msg A (initiator to responder) | 32 B | 1,216 B | +1,184 B |
| Msg B (responder to initiator) | 96 B | 1,200 B | +1,104 B |
| Msg C (initiator to responder) | 64 B | 64 B | 0 B |
| Total | 192 B | 2,480 B | +2,288 B |

Real libp2p handshakes include a `NoiseHandshakePayload` (signed identity key + extensions) in messages B and C. The payload is identical in both patterns, so it adds the same bytes to each column and the delta stays +2,288 B.

---

## 6. Token Ordering

The ordering of `ekem1` operations is critical and must match exactly on both sides:

```
writeEkem1():
  1. encapsulate(re1)  -> { cipherText, sharedSecret }
  2. encryptAndHash(cipherText)       // encrypted under ee-derived key
  3. mixKey(sharedSecret)             // AFTER encrypt, strengthens subsequent tokens

readEkem1():
  1. decryptAndHash(raw)              // decrypt ciphertext (throws on AEAD failure)
  2. decapsulate(cipherText, e1.secretKey) -> sharedSecret
  3. mixKey(sharedSecret)             // must match write ordering
```

Swapping steps 2 and 3 would produce divergent chaining keys and is incorrect.

---

## 7. State Machine

```
Initiator                               Responder
---------                               ---------
generate e (X25519)
generate e1 (ML-KEM-768)
writeMessageA(payload=empty)
  -> e, e1
                                        readMessageA()
                                          read e (32 bytes)
                                          read e1 (1184 bytes, store as re1)

                                        generate e (X25519)
                                        writeMessageB(payload)
                                          -> e
                                          ee = DH(e_R, e_I)  MixKey(ee)
                                          -> ekem1 = encapsulate(re1)
                                               encryptAndHash(cipherText)
                                               mixKey(sharedSecret)
                                          -> s (encrypted)
                                          es = DH(e_I, s_R)  MixKey(es)
                                          -> payload (signed identity)
readMessageB()
  read e (32 bytes)
  MixKey(DH(ee))
  readEkem1 (1104 bytes)
    decryptAndHash(cipherText)
    decapsulate(cipherText, e1.secretKey)
    mixKey(sharedSecret)
  readS (48 bytes)
  MixKey(DH(es))
  decode and verify payload

writeMessageC(payload)
  -> s (encrypted, 48 bytes)
  se = DH(s_I, e_R)  MixKey(se)
  -> payload (signed identity)
                                        readMessageC()
                                          readS (48 bytes)
                                          MixKey(DH(se))
                                          decode and verify payload

[cs1, cs2] = split()                    [cs1, cs2] = split()
encrypt = cs1                           encrypt = cs2
decrypt = cs2                           decrypt = cs1
```

Both sides must derive the same `cs1` and `cs2`. Any deviation (AEAD failure, KEM implicit rejection, tampered DH key) causes the handshake to abort with `InvalidCryptoExchangeError`.

---

## 8. Cipher State Split

After `split()`, two cipher states `cs1` and `cs2` are produced from the final chaining key via HKDF. They are directional:

| Direction | Initiator uses | Responder uses |
|-----------|---------------|---------------|
| Initiator to responder | `cs1.encryptWithAd(ZEROLEN, plaintext)` | `cs1.decryptWithAd(ZEROLEN, ciphertext)` |
| Responder to initiator | `cs2.decryptWithAd(ZEROLEN, ciphertext)` | `cs2.encryptWithAd(ZEROLEN, plaintext)` |

---

## 9. ML-KEM Implicit Rejection

ML-KEM-768 (FIPS 203 Section 6.4) uses implicit rejection: `Decaps()` never throws even when given a ciphertext encrypted for a different key. Instead it returns a pseudorandom shared secret derived from a secret implicit rejection value. This means:

- A tampered or wrong-key ciphertext produces a divergent shared secret rather than an error.
- The divergence causes all subsequent AEAD operations (`s`, `es`, payload) to fail authentication.
- This is correct and intentional behavior. The handshake still aborts on AEAD failure.

The AEAD protection on the ciphertext (`encryptAndHash` before `mixKey`) means that a tampering attack is caught by the AEAD tag before decapsulation is even attempted.

---

## 10. Security Properties

| Property | Source |
|----------|--------|
| Forward secrecy (classical) | DH(ee): ephemeral X25519 on both sides |
| Forward secrecy (quantum-safe) | ML-KEM-768 KEM alongside the pattern's existing X25519 |
| Mutual authentication | DH(es) + DH(se) via signed static keys |
| Identity hiding | Static keys encrypted after ephemeral exchange |
| Hybrid robustness | Secure if either X25519 or ML-KEM-768 is unbroken |
| Payload confidentiality | ChaCha20-Poly1305 AEAD under the final chaining key |

The protocol does NOT provide quantum-safe authentication. The identity layer uses Ed25519 signatures (classical). For full post-quantum authentication, ML-DSA (FIPS 204) identity keys are needed. PR #3432 in js-libp2p tracks that work. When it lands, this implementation will support ML-DSA identity automatically because `privateKey.sign()` is key-type aware and no changes are needed in this layer.

---

## 11. Test Vectors

Deterministic test vectors are in `test/fixtures/pqc-test-vectors.json`. They were generated by `scripts/generate-pqc-vectors.js` using seeded keys. The JSON schema is:

```json
{
  "protocol": "Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256",
  "vectors": [
    {
      "vector_index": 1,
      "static_i_public": "<hex>",
      "static_i_private": "<hex>",
      "static_r_public": "<hex>",
      "static_r_private": "<hex>",
      "ephemeral_dh_i_public": "<hex>",
      "ephemeral_dh_i_private": "<hex>",
      "ephemeral_dh_r_public": "<hex>",
      "ephemeral_dh_r_private": "<hex>",
      "ephemeral_kem_i_public": "<hex>",
      "ephemeral_kem_i_secret": "<hex>",
      "encap_seed_hex": "<hex 64-byte seed>",
      "msg_a": "<hex>",
      "msg_b": "<hex>",
      "msg_c": "<hex>",
      "msg_a_bytes": 1216,
      "msg_b_bytes": 1200,
      "msg_c_bytes": 64,
      "handshake_hash": "<hex>",
      "cs1_k": "<hex 32-byte key>",
      "cs2_k": "<hex 32-byte key>"
    }
  ]
}
```

To regenerate vectors after a code change:

```bash
pnpm build
node scripts/generate-pqc-vectors.js
```

To verify vectors against the current implementation:

```bash
pnpm test:node -- --grep "Noise_XXhfs test vectors"
```

---

## 12. Usage

```ts
import { createLibp2p } from 'libp2p'
import { noiseHFS } from '@chainsafe/libp2p-noise'

const node = await createLibp2p({
  connectionEncrypters: [noiseHFS()],
  // ... other options
})
```

For testing or custom KEM backends:

```ts
import { noiseHFS } from '@chainsafe/libp2p-noise'
import type { IKem } from '@chainsafe/libp2p-noise'

const myKem: IKem = {
  PUBKEY_LEN: 1184,
  CT_LEN: 1088,
  SS_LEN: 32,
  SK_LEN: 2400,
  generateKemKeyPair: () => { /* ... */ },
  encapsulate: (pubkey) => { /* ... */ },
  decapsulate: (ct, sk) => { /* ... */ }
}

const node = await createLibp2p({
  connectionEncrypters: [noiseHFS({ kemBackend: myKem })],
})
```

---

## 13. Interoperability

A compatible implementation in another language must:

1. Use the same protocol name exactly: `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`
2. Use raw ML-KEM-768 (FIPS 203) as the KEM
3. Apply `encryptAndHash(cipherText)` BEFORE `mixKey(sharedSecret)` in the ekem1 token
4. Read e1 as 1184 bytes in Message A (no AEAD tag at that stage)
5. Read ekem1 as 1088 + 16 = 1104 bytes in Message B (ciphertext + AEAD tag)
6. Use the test vectors in `test/fixtures/pqc-test-vectors.json` to verify correctness

---

## 14. Performance Reference

Node.js v22.17.1, Windows 11 x64. Medians over 5 paired passes of 30 iterations
(`benchmarks/paired-passes.mjs`), classical and hybrid sampled interleaved so machine drift is
common-mode rather than landing in the ratio.

**Hold the backend constant.** `noise()` defaults to `defaultCrypto` (Node native plus
AssemblyScript WASM) while `noiseHFS()` defaults to `pureJsCrypto`, so comparing the two default
configurations varies the backend as well as the KEM.

| comparison | overhead |
|------------|---------:|
| default configurations | 3.54x (range 3.40 to 3.64) |
| **like for like, backend held constant** | **1.51x** (range 1.51 to 1.58) |

Of the 17.3 ms separating the two defaults, over four fifths is the backend substitution and
about 3.5 ms is the KEM, roughly 34% of the hybrid handshake.

See `benchmarks/results.md` for the full table and `paschal533/pq-noise-artifacts` for the raw data.

---

## 15. Files

| File | Purpose |
|------|---------|
| `src/kem.ts` | `IKem` interface, `KemKeyPair`, `KemEncapsulateResult` types |
| `src/crypto/pqc.ts` | Default KEM backend (`pqcKem`) using `@noble/post-quantum` |
| `src/crypto/pqc.node.ts` | Node.js backend slot (currently falls back to noble; native TODO) |
| `src/protocol-pqc.ts` | `XXhfsHandshakeState` state machine, `NOISE_HFS_PROTOCOL_NAME` |
| `src/performHandshake-hfs.ts` | Initiator and responder orchestration |
| `src/noise-hfs.ts` | `NoiseHFS` connection encrypter, `noiseHFS()` factory |
| `test/pqc-kem.spec.ts` | IKem unit tests (17 tests) |
| `test/pqc-protocol.spec.ts` | XXhfsHandshakeState unit tests (18 tests) |
| `test/pqc-noise.spec.ts` | Integration tests against libp2p (12 tests) |
| `test/pqc-vectors.spec.ts` | Test vector verification (52 tests) |
| `test/fixtures/pqc-test-vectors.json` | Committed deterministic test vectors (5 vectors) |
| `scripts/generate-pqc-vectors.js` | Vector generator (run after build) |
| `benchmarks/benchmark-pqc.js` | Benchmark runner |
| `benchmarks/results.md` | Benchmark results and analysis |
