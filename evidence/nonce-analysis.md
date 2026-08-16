# Nonce management analysis

Supporting material for TR-7 and SR-3. Quantifies the two design
decisions documented in `srp/nonce.py`.

## The construction in use

```
nonce (96 bits) = nonce_prefix (32 bits, random per session)
                || seq         (64 bits, big-endian counter)
```

NIST SP 800-38D s8.2.1 deterministic construction: a fixed field
identifying the device/session, and an invocation field that must not
repeat. Both fields travel in the authenticated record header, so the
receiver reconstructs the nonce without it being sent separately.

## Decision 1: counter, not random nonces

With uniformly random 96-bit nonces, the probability that some pair
among `q` records collides follows the birthday bound:

```
p(q) ~ 1 - exp( -q(q-1) / 2^97 )
```

A collision is not a near miss. Both AES-GCM and ChaCha20-Poly1305
derive their keystream *and* their one-time authentication key from
(key, nonce). Repeat the pair and an attacker recovers the XOR of the
two plaintexts and, worse, enough structure to forge tags at will. So
the column below is not a quality metric; it is the probability of
total failure.

| Records under one key | Random 96-bit nonce | ~log2 | Counter | Why this volume |
|---|---|---|---|---|
| 10,000 | 6.310e-22 | 2^-70.4 | 0 | the volume TR-7 suggests demonstrating |
| 1,000,000 | 6.311e-18 | 2^-57.1 | 0 | a busy day of telemetry |
| 2^24 | 1.776e-15 | 2^-49.0 | 0 | this subsystem's deployed per-key record budget |
| 2^32 | 1.164e-10 | 2^-33.0 | 0 | the NIST SP 800-38D s8.3 cap on random-nonce construction |
| 2^40 | 7.629e-06 | 2^-17.0 | 0 | a long-lived key that was never rotated |
| 2^48 | 0.3935 | 2^-1.3 | 0 | roughly where a 96-bit random nonce collision becomes likely |
| 2^49 | 0.8647 | 2^-0.2 | 0 | past the point of no return |

The counter column is exactly zero, not merely small, and it is zero
for a structural reason rather than a probabilistic one: a strictly
increasing 64-bit integer cannot produce the same value twice before it
wraps, and the subsystem refuses to send long before it could wrap.
This is also why the property is *testable* -- `test_tr7_nonce_
management.py` asserts uniqueness over 10,000 real nonces directly,
which is not something one can do with a probabilistic argument.

## Decision 2: per-session random prefix, not a bare counter

A counter alone is safe within one run and catastrophic across runs.
Restart a sender that persists nothing and it re-emits seq 0, 1, 2, ...
against different plaintexts under the same long-term key -- the exact
collision the counter was chosen to avoid, delivered on a plate. This
failure has a long history in deployed systems: it is the mechanism
behind the WPA2 key-reinstallation attack, and behind repeated IoT
firmware bugs that reset the counter on reboot.

The 32-bit random prefix means each session occupies a disjoint region
of the nonce space, so the counter only has to be unique *within* a
session -- which an in-memory integer guarantees with no persistent
state and no coordination.

The residual risk is two sessions drawing the same prefix under the
same key, again a birthday bound but over 32 bits:

| Sessions sharing one key | P(prefix collision) |
|---|---|
| 10 | 1.048e-08 |
| 100 | 1.153e-06 |
| 1,000 | 0.0001 |
| 10,000 | 0.0116 |
| 65,536 | 0.3935 |
| 200,000 | 0.9905 |

Two sessions sharing a prefix is not automatically a nonce collision --
their counters would also have to overlap, which they do, from seq 0.
So this table should be read as a genuine bound on how many sessions
one key may serve. It is comfortable for the volumes in scope and
uncomfortable past a few thousand sessions per key.

The clean fix is not a wider prefix but per-session key derivation:
derive `K_session = KDF(K, session_id)` and each session gets its own
key, making cross-session nonce reuse impossible by construction rather
than by probability. That is a key-management change, and key
establishment and management are out of scope for this assignment
(Section 3.2), so it is recorded here as the documented next step
rather than implemented.

## Decision 3: the per-key record budget

Nonce uniqueness is necessary but not sufficient: both constructions
also degrade with the total volume protected under one key.

| Configuration | Algorithm-inherent limit | Reason |
|---|---|---|
| AES-256-GCM | 2^24 records | GHASH collision term grows as sigma^2 / 2^128; TLS 1.3 (RFC 8446 s5.5) caps AES-GCM at 2^24.5 records |
| ChaCha20-Poly1305 | 2^48 records | 512-bit state, no birthday bound of that form; RFC 8446 sets no comparable cap |

The subsystem deploys the stricter of the two, 2^24, for **both**
configurations. That is a deliberate FR-9 decision: switching AEAD
configuration must not change what the subsystem does, only which
primitive it calls, so the observable record budget is held identical.

The sender enforces it by failing closed -- `NonceExhaustedError` is
raised *instead of* returning a nonce, so there is no code path by
which a caller obtains a reused one. Retrying yields the same error;
the correct response is to rekey.

