# Transcript-Bound Security Protocol Negotiation

Status: prototype / work in progress (milestone B)

## Problem

libp2p selects a connection encrypter with multistream-select, which runs
unauthenticated and in plaintext before any handshake. An active attacker on the
path can:

1. Strip a dialer's proposal for a preferred protocol, so the listener never
   sees that it was offered, or
2. Forge an `na` response, so the dialer believes the listener does not support
   the preferred protocol.

Either way both peers complete a perfectly valid handshake over the weaker of
the two protocols and neither can tell. `experiments/downgrade-demo` in the
pq-noise-artifacts repository demonstrates this end to end against
`/noise-mlkem768-hfs/0.2.0` and `/noise`.

Nothing in the current Noise handshake detects it. `identity_sig` covers the
string `noise-libp2p-static-key:` followed by the static public key, and nothing
else. It is a statement about a key, not about a session, so it is equally valid
in a downgraded session as in an honest one.

## Mechanism

Each peer states, inside the encrypted and authenticated handshake payload, the
ordered list of security protocols it has configured. Each peer then recomputes
what the negotiation should have produced and compares that against the protocol
it is actually running.

```
expected(dialerOffered, listenerSupported) =
    the first p in dialerOffered such that p is in listenerSupported
```

Both sides can evaluate this once the payloads have been exchanged:

| Role     | Has locally        | Learns from payload | Detects                       |
|----------|--------------------|---------------------|-------------------------------|
| Dialer   | its offered list   | listener's list     | a forged `na`                 |
| Listener | its supported list | dialer's list       | a stripped proposal           |

The selected protocol is never sent, because each peer already knows which
protocol it is running. If `expected` differs from that protocol, the
negotiation was tampered with.

This is the same shape as the TLS 1.3 downgrade sentinel in RFC 8446 section
4.1.3, with one difference: TLS signals a detected downgrade through a value the
server places in `ServerHello.random`, whereas here both peers independently
recompute the expected outcome from two signed lists.

## Binding

The list is only meaningful if it is bound to this session. A bare signed list
is a static claim about a peer's configuration, so an attacker could replay a
list signed at a time when the peer supported fewer protocols. Binding the
signature to the Noise handshake hash `h` makes the statement session-specific.

`h` at the moment a peer encrypts its handshake payload covers the protocol
name, the prologue, both ephemeral public keys and the static key material
exchanged so far. The peer that decrypts that payload holds the identical `h`
value at the corresponding point, which is the standard Noise transcript
property, so no extra round trip and no extra wire field are needed to agree on
what was signed.

## Two variants under evaluation

The prototype implements both so the cost and the complexity can be compared
rather than asserted.

### Variant A: separate signature in the extension registry

`NoiseExtensions` gains two fields:

```proto
message NoiseExtensions {
    repeated bytes webtransport_certhashes = 1;
    repeated string stream_muxers = 2;
    // Field 3 is skipped: py-libp2p already ships it as its own early_data
    // extension. See Cross-implementation vectors below.
    repeated string security_protocols = 4;
    bytes transcript_sig = 5;
}
```

`transcript_sig` is a signature by the identity key over:

```
"noise-libp2p-transcript:" || h || canonical(security_protocols)
```

`canonical` encodes the list unambiguously (see Encoding below). `identity_sig`
is untouched.

Properties: an unmodified peer ignores unknown extension fields, so this is
wire-compatible in both directions and can be deployed incrementally on the
existing `/noise` protocol. Cost is one extra signature and one extra
verification per handshake, plus the encoded list and signature on the wire.

### Variant B: fold the binding into the identity signature

`getSignaturePayload` becomes a signature over:

```
"noise-libp2p-static-key:" || s_pub || h || canonical(security_protocols)
```

Properties: one signature instead of two and a smaller payload, but every libp2p
peer verifies `identity_sig`, so this cannot ship incrementally. It would
require a coordinated change to `/noise` itself, or a new protocol identifier.

## Is the extra signature redundant?

Worth asking, because the answer nearly changed the design. The handshake
payload is AEAD-encrypted with `h` as associated data under keys derived from
`ee`, `es` and `se`, and `identity_sig` binds the peer's static key to its
identity key. So a list carried inside that payload is already unforgeable by
an on-path attacker who holds neither static key: it cannot be altered,
reordered, replayed across sessions, or spliced between the classical and
hybrid suites, since the protocol name seeds `h` and therefore the whole key
schedule. Against the multistream-select attacker this document targets,
`transcript_sig` adds nothing, and the mechanism would work with the list
alone, at +37 bytes and no new cryptography.

The reason to keep it is that `identity_sig` is session-independent. It covers
`"noise-libp2p-static-key:" || s_pub` and nothing else: no transcript, no
nonce. It is a replayable bearer token over a long-lived key. So the
authentication of everything in the payload actually rests on possession of
the X25519 static key, not on possession of the identity key. Anyone who
learns `sk_s` can harvest a peer's `(identity_key, identity_sig)` pair by
dialling it once, then impersonate it indefinitely and assert any protocol
list they like.

A transcript-bound signature is the only element in the handshake that proves
the identity key is live in this session. That matters most exactly where this
project is aimed: `XXhfs` gives post-quantum confidentiality, but `es` and
`se` are X25519 and `identity_sig` is a static token, so an adversary who can
compute discrete logarithms recovers `sk_s` once and impersonates the peer
forever. With an ML-DSA identity key, the transcript-bound signature is the
only post-quantum-authenticated element in the handshake. This is the same gap
the header comment in `src/noise-hfs.ts` already describes: PQ authentication
needs "an identity signature covering the handshake hash rather than only the
static key". That is what this is.

One consequence for the current code: because a peer that omits the fields is
always accepted, `transcript_sig`'s extra unforgeability buys no operational
downgrade detection today. It is a primitive that becomes load-bearing the
moment there is a mode that requires the binding, or a post-quantum identity
profile.

An alternative neither variant implements: put each peer's view of the
multistream-select exchange into the Noise prologue, which is mixed into `h`
and is currently empty. Honest peers derive identical prologues, a tampered
negotiation makes them differ, and the handshake dies at the first AEAD in
message B. No new field, no signature, no payload growth. It is not
incrementally deployable, but neither is the identity variant, and it does not
provide the session-fresh identity proof above.

## Encoding

`canonical(list)` is the concatenation, in the order the peer offers them, of
each protocol identifier encoded as a big-endian `uint16` length followed by its
UTF-8 bytes. Length prefixes prevent a peer from splitting or merging
identifiers to produce a different list with the same encoding.

The order is significant and is the peer's own preference order. It is not
sorted, because the dialer's order is what determines the negotiation outcome.

## Behaviour

Controlled by a single option, `transcriptBinding`, with `mode` and `variant`.
Under the extension variant:

| Value      | Sends the field | On a missing field | On a mismatch |
|------------|-----------------|--------------------|---------------|
| `off`      | no              | ignore             | not checked   |
| `warn`     | yes             | ignore             | log only      |
| `enforce`  | yes             | ignore             | abort         |

A missing field is always ignored, in every mode, because a peer that does not
implement this extension is not evidence of an attack.

**The identity variant does not behave this way, and `mode` does not change
it.** The protocol list is inside `identity_sig`, so a peer that sends no list
is verifying a different message: the handshake fails during signature
verification, before any mode is consulted. A node configured with
`variant: 'identity'` therefore cannot connect to a stock libp2p peer on
`/noise` at all, and cannot connect to a peer using the extension variant
either. This is fail-closed rather than a security hole, but it is a total
partition, not graceful degradation, and it is not negotiated on the wire, so a
configuration skew between two of your own nodes presents as an unexplained
connectivity outage. `test/transcript-binding.spec.ts` pins all four of these
cases. Deploying the identity variant requires a distinct protocol identifier.

A mismatch aborts with `DowngradeDetectedError`
(`ERR_SECURITY_PROTOCOL_DOWNGRADE`), exported from the package entry point, and
increments `libp2p_noise_security_protocol_downgrades_total`. Detection is
counted separately from generic handshake errors, and it is counted in warn
mode too, since warn mode is where a deployment would collect rollout data.

## What this does not do

Three limits, stated rather than discovered later.

**It cannot see a downgrade out of Noise entirely.** A real node's
`securityProtocols` may include `/tls/1.0.0`. An attacker who strips every
Noise proposal forces TLS, no Noise handshake runs, and nothing checks
anything. That is the attacker's best move. Covering it needs the check in the
shared upgrader, where the full offered set lives, not inside one connection
encrypter. This prototype is the mechanism, not the final placement.

**It cannot see an attacker who strips the extension itself.** Stripping the
field is indistinguishable from talking to an older peer. This is the inherent
cost of incremental deployability, and it is why the fields only help once both
peers are known to implement them.

**It protects a session only when both peers implement it.**

## Measured cost

`benchmarks/benchmark-transcript-binding.js`, Node v22.17.1, Ed25519 identity
keys, two offered protocols (`/noise` and `/noise-mlkem768-hfs/0.2.0`), 300
handshakes per configuration, configurations interleaved in a shuffled order
within each round.

Handshake payload, encoded bytes:

| Configuration | Payload | Added |
|---------------|---------|-------|
| binding off   | 104     |       |
| extension     | 207     | +103  |
| identity      | 141     | +37   |

The extension variant adds the protocol list (37 bytes here) plus a second
Ed25519 signature and its field framing. The identity variant adds only the
list, because it reuses the signature that is already there.

Full `/noise` handshake time, median over three runs, relative to the binding
being off:

| Configuration | Run 1 | Run 2 | Run 3 |
|---------------|-------|-------|-------|
| extension     | 1.10x | 1.08x | 1.05x |
| identity      | 1.03x | 0.98x | 0.99x |

The identity variant is not distinguishable from the baseline, which is what
one would expect: it signs a slightly longer message with the same single
signature. The extension variant costs a consistent few percent, from the
extra signature and verification.

A caveat this benchmark cannot settle: with Ed25519 the second signature is a
few percent. With an ML-DSA-65 identity key it would be a second ML-DSA
signature and verification, and a second 3,309-byte signature on the wire.
That is not measured here, and it is the strongest cost argument for the
identity variant in a post-quantum-identity deployment. Note also that under
the extension variant a responder performs two identity signatures in response
to message A, which is unauthenticated, so the pre-authentication work an
attacker can compel per TCP connection doubles.

Two earlier versions of this benchmark are worth recording as a method note.
The first ran each configuration to completion in turn and reported the bound
handshakes as faster than the unbound one, which is impossible: the machine
drifts by more than the effect. Interleaving the configurations fixed it. The
numbers above are from the interleaved harness.

## Cross-implementation vectors

Two implementations can agree on every word of this document and still fail to
interoperate over one byte: a different canonical encoding, a different
signature prefix, or different protobuf field numbers. Each side's own tests
pass and the handshake fails in the field.

`test/fixtures/transcript-binding-vectors.json` pins the shared format from
fixed inputs, so agreement can be checked without running a handshake.
Generated by `scripts/generate-transcript-vectors.js`, guarded on this side by
`test/transcript-vectors.spec.ts`, and consumed by py-libp2p at
`tests/security/noise/test_transcript_vectors.py`, which verifies signatures
produced by this implementation rather than round-tripping its own.

Two of the five vectors are `['ab', 'c']` and `['a', 'bc']`, which collide
under naive concatenation. An implementation that omits the length prefixes
passes its own round-trip tests and fails this file.

The field numbers are 4 and 5, not 3 and 4, because py-libp2p already ships
field 3 as its own `early_data` extension. Renumbering a field another
implementation already uses would break its wire format for no gain.

## Gates for this milestone

| Gate | Status |
|------|--------|
| TypeScript and Python agree on the wire format | Met, by shared vectors: Python verifies TS-produced signatures and parses TS-produced payloads |
| Both refuse a session whose offered sets are inconsistent | Met within each implementation |
| `experiments/downgrade-demo` refuses the attack it used to complete | Met |
| Honest connections unaffected by the defence | Met, `baseline-tap-defended` still negotiates hybrid |
| The existing suites still pass with the flag off | Met, 195 TypeScript and 412 Python |
| The added cost is measured, not estimated | Met, see above |
| A live TypeScript-to-Python handshake with the flag on | **Not met.** The interop scripts have no flag for it yet |
| The 48-run interop matrix re-run | **Not met**, pending the above |

The wire-format agreement is the stronger of the two interop facts, since it
pins the bytes rather than one successful connection, but it is not a
substitute for a live cross-language handshake.
