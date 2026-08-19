# CS6530 — Applied Cryptography, Assignment 1

## Member 2: Implementation and Ownership Guide

**Receiver, Replay Protection, Adversary, and TR-2 to TR-6**

---

## 1. Scope

Member 2 owns the receiver side of the subsystem and the security testing that
goes with it. The purpose is not to redesign the cryptographic core: the
project already contains a common AEAD layer, record format, nonce construction
and sender, and those are fixed. Member 2 builds against them.

| Responsibility | Primary file |
|---|---|
| Receiver processing and rejection handling | `srp/receiver.py` |
| Replay protection | `srp/replay.py` |
| On-path malicious actor | `srp/adversary.py` |
| Ciphertext integrity | `tests/test_tr2_ciphertext_integrity.py` |
| Authentication tag | `tests/test_tr3_authentication_tag.py` |
| Associated data / header | `tests/test_tr4_associated_data.py` |
| Replay handling | `tests/test_tr5_replay.py` |
| Wrong-key handling | `tests/test_tr6_wrong_key.py` |

---

## 2. Current state of the code

**These eight files are not implemented.** Each source module is a
specification stub whose methods raise `NotImplementedError`; each test module
is a coverage specification with no tests written. That is deliberate — they
are Member 2's deliverable.

| File | Current state | Member 2 responsibility |
|---|---|---|
| `srp/receiver.py` | Class and method signatures only. `Receiver.__init__` stores its configuration so the rest of the project still runs; every method that makes a decision raises. | Design and implement the verification pipeline. |
| `srp/replay.py` | `ReplayVerdict`, `WindowSnapshot`, `ReplayWindow`, `ReplayGuard` signatures and default constants only. | Choose a replay strategy, implement it, justify it. |
| `srp/adversary.py` | ~20 attack method signatures, all raising. | Implement the attacks against wire bytes. |
| `tests/test_tr2…tr6` | Module docstring listing required coverage; no tests. | Write the tests and produce the evidence. |

Each stub's docstring states the requirements it must satisfy and the design
questions its author has to answer. **Read the docstring before writing the
module** — several of the questions have a wrong answer that is not obviously
wrong.

Each stub also carries a `MEMBER2_STUB = True` sentinel. **Delete it when the
module is real.** The test suite and `run_all.py` change behaviour based on it
and both return to normal on their own once all three are gone.

Current baseline: `python -m pytest -q` reports **38 passed, 41 skipped**. The
skips are the tests blocked on these modules plus the five unwritten files.

---

## 3. Files and interfaces that must not be redesigned

These remain outside the ownership boundary. Use their current interfaces;
raise an interface problem for discussion rather than changing it.

| File | What Member 2 uses |
|---|---|
| `srp/header.py` | `RecordHeader`, `ProtectedRecord`, `parse_record()`, `HEADER_LEN`, `TAG_LEN`, `header.aad()`, `header.evolve()` |
| `srp/suites.py` | `AeadSuite.open()` and the suite identity the AEAD abstraction exposes |
| `srp/nonce.py` | `derive_nonce(header.nonce_prefix, header.seq)` |
| `srp/sender.py` | `Sender.protect()`, for generating genuine records in tests |
| `srp/session.py` | `create_channel()` and `SessionPolicy` for paired sender/receiver tests |
| `srp/errors.py` | `RecordStatus`, `RejectReason`, `AuthenticationFailure`, `ConfigurationError`, `MalformedRecordError` |

---

## 4. Receiver: what has to be built

`Receiver.receive(wire)` takes one protected record and returns a `Verdict`.
It must **never raise** on attacker-supplied input — malformed frames, wrong
suite, wrong session, replays and failed tags are all verdicts, not exceptions.
Exceptions are reserved for local programming and configuration errors.

The checks it has to perform, in no particular order:

- framing / parse the wire record
- AEAD configuration binding (does the record's suite match this receiver?)
- session binding, when the receiver is pinned to one session
- the replay check
- nonce reconstruction — the receiver is never sent the nonce
- the AEAD open
- the replay state update

**Deciding the order is the work.** For each check that runs before the AEAD
open, be able to say whether it could ever cause a record to be *accepted*.
And settle where the replay check and the replay state update belong relative
to the open — they do not go in the same place, and putting the update in the
wrong one enables a specific one-packet attack. Work out what it is.

`RejectReason` already defines the taxonomy: `MALFORMED`, `SUITE_MISMATCH`,
`SESSION_MISMATCH`, `REPLAY_DETECTED`, `STALE_RECORD`, `AUTH_FAILED`. Map each
failure onto one of them.

One further decision: TR-2, TR-3, TR-4 and TR-6 all end in a failed tag check.
Decide whether the rejection reason should distinguish them, and justify the
answer in terms of what an attacker learns from the reply.

### 4.1 Fail-closed invariant

`Verdict` is a frozen dataclass with `status`, `reason`, `plaintext`, `header`
and `detail`. There is one invariant relating `status` to `plaintext` that must
hold on **every** path through `receive()`. Work out what it is and enforce it
in `Verdict.__post_init__()`, not in a comment — a failure path that forgets to
clear an output buffer is the classic way a subsystem like this leaks.

This is what FR-7 and SR-6 are asking for.

---

## 5. Replay protection: what has to be built

FR-8 requires replayed records to be detected; SR-5 requires that they are not
accepted as fresh. The strategy is Member 2's to choose, and Section 6 of the
assignment requires it to be **documented**, so the reasoning is part of the
deliverable.

Decisions to make:

1. **What counts as "already seen"?** Strict successor checking (`seq == last + 1`)
   is the simplest exact test, but Section 3.2 puts reliable delivery, ordering
   and retransmission out of scope, so records may legitimately arrive late or
   out of order. Decide how much reordering to tolerate and say why.
2. **Records too old to classify.** Any bounded structure eventually forgets.
   Decide whether those records are accepted or rejected, and argue that the
   direction chosen is the conservative one.
3. **Why the sequence number can be trusted at all.** Look at what
   `RecordHeader.aad()` covers.
4. **Scoping.** Streams are keyed by `(session_id, stream_id)`. Explain what
   would go wrong if they were not.
5. **Bounded state.** `max_streams` caps tracked streams. Decide what happens
   at the cap, and what stops an attacker from driving the receiver there.

`ReplayGuard` deliberately splits `check()` from `commit()`. `check()` runs on
unauthenticated, attacker-controlled input, so it must not mutate state and
must not allocate. Keep that true.

### 5.1 Critical replay rule

The replay state must never be advanced by an unauthenticated record. A forged
large sequence number must not move the receiver's high-water mark, must not
create stream state, and must not lock out later genuine records. If it can,
one packet is a permanent denial of service.

---

## 6. Malicious actor: what has to be built

`MaliciousActor` operates on wire bytes and does **not** hold the key. That is
exactly the capability of an on-path network attacker.

Every method must start from a **real, valid record produced by the real
sender** and make the smallest change that achieves the attacker's goal. This
matters: handing the receiver a random blob "demonstrates" nothing, because any
parser rejects garbage. The interesting claim is that an attacker who sees
genuine traffic and can rewrite it still cannot get one forged byte accepted.

| Method | Purpose | Requirement |
|---|---|---|
| `flip_ciphertext_bit()` | Flip one ciphertext bit, header and tag intact | TR-2 |
| `truncate_ciphertext()` | Remove ciphertext bytes | TR-2 / framing |
| `flip_tag_bit()` | Flip one authentication-tag bit | TR-3 |
| `replace_tag()` | Replace the tag with random or supplied bytes | TR-3 |
| `zero_tag()` | All-zero tag | TR-3 |
| `truncate_tag()` | Shorten the tag | TR-3 / framing |
| `tamper_header()` | Rewrite authenticated header fields | TR-4 |
| `flip_header_bit()` | Flip any header bit, for exhaustive sweeps | TR-4 |
| `relabel_record_type()` | Change the record's semantic type | TR-4 |
| `set_flags()` | Forge or strip flags | TR-4 |
| `redirect_stream()` | Change the stream identifier | TR-4 |
| `declare_wrong_length()` | Forge `payload_len` | TR-4 / framing |
| `switch_suite_label()` | Change the declared suite | TR-4 / suite binding |
| `replay()` | Return the identical wire bytes | TR-5 |
| `renumber()` | Change `seq`, leaving ciphertext and tag alone | TR-5 |
| `forge_with_wrong_key()` | Build a structurally valid record under another key | TR-6 |
| `splice()` / `swap_bodies()` | Mix header and body from different records | TR-2 / TR-4 |

The `rng` parameter exists so a demo run is reproducible and the report's
evidence can be regenerated exactly. Use it for every random choice.

### 6.1 Test-design hazard

For authentication-specific tests, modify a **fresh** record and deliver only
the modified copy. If the original was already accepted and the modified copy
is sent afterwards, the receiver may correctly reject it for replay before the
AEAD ever runs. That still proves rejection, but it does not isolate
authentication failure, which is what TR-2, TR-3, TR-4 and TR-6 are about.

This will cost hours if it is discovered by accident. It is also the more
realistic attacker model — someone who can rewrite a record can equally well
suppress the original — so it belongs in the report.

---

## 7. Test ownership

**Every Testing Requirement must be demonstrated separately under both AEAD
configurations.** The assignment awards only partial credit otherwise. The
`suite_name` fixture in `tests/conftest.py` is parametrised over both, so any
test taking `channel` or `suite_name` is collected twice automatically. Never
hard-code a suite.

Fixtures available: `suite_name`, `channel`, `actor`, `small_policy`, `payloads`.

---

## 8. TR-2: Ciphertext integrity

*"Modify the ciphertext of a protected record and demonstrate that the receiver
detects the modification and rejects the record."*

Required coverage:

- single-bit modification of the ciphertext body
- an exhaustive sweep over every bit of a small payload — turns "we tried one"
  into "no single-bit edit is accepted"
- modification at several positions of a large record
- ciphertext truncation and extension
- body swapped between two records
- random garbage (the trivial baseline)
- a genuine record still accepted after the attacks

Completion criteria: every modified ciphertext rejected; authentication-specific
modifications give `AUTH_FAILED`; framing defects give `MALFORMED`; no rejected
verdict carries plaintext; both configurations.

---

## 9. TR-3: Authentication tag

*"Modify the authentication tag of a protected record and demonstrate that the
receiver rejects the record."*

Required coverage:

- single-bit tag modification
- an exhaustive sweep of all 128 tag bits
- all-zero tag
- repeated random tag guessing — state the per-attempt success probability
- tag truncation
- a valid tag lifted from a different record

Completion criteria: modified tags give `AUTH_FAILED` while framing stays valid;
truncated tags give `MALFORMED`; no plaintext released; the genuine record still
succeeds; both configurations.

---

## 10. TR-4: Associated data

*"Modify the associated data of a protected record and demonstrate that the
receiver rejects the record."*

**Read `RecordHeader.aad()` first.** The subsystem authenticates the entire
40-byte header as AAD. Every field it covers is a field the attacker cannot
silently rewrite.

Attack each field individually — each is a different *semantic* attack, and the
report should say what the attacker would gain if it succeeded: `version`,
`suite_id`, `record_type`, `flags`, `session_id`, `stream_id`, `nonce_prefix`,
`seq`, `payload_len`. Then sweep every bit of the header so the claim covers the
whole AAD and not only the fields you thought to name.

Note that these do not all fail the same way. Some are caught by framing or by a
configuration check *before* the AEAD runs; the rest fail authentication.
Preserve and document that distinction — build the expected-reason table from
your own observations, and be able to explain each one.

Also required: the parse-then-reserialise round trip must be the identity (if it
were not, two encodings of one header would exist and the AAD would stop being
canonical), and a demonstration that the AAD is authenticated but **not**
encrypted, with an explanation of why the header has to be readable.

---

## 11. TR-5: Replay

*"Capture a valid protected record and re-deliver it to the receiver.
Demonstrate that the replayed record is detected and handled according to the
replay handling strategy."*

A replayed record is byte-identical, so its tag verifies perfectly. **The AEAD
cannot help here at all** — that is exactly why FR-8 asks for a separate
mechanism. Demonstrate this explicitly: show the replayed bytes really would
authenticate, so the rejection provably comes from the replay logic.

Required coverage:

- exact replay of an accepted record
- many repeated replays — the state must not decay
- legitimate out-of-order delivery within tolerance is **accepted**
- a duplicate of an out-of-order record is still caught
- records too old to classify are rejected at the documented boundary — use
  `small_policy` so the boundary is reachable
- renumbering a captured record to slip past the check
- **sequence-number poisoning**: a forged high sequence number must not move the
  replay state; show a genuine record still accepted afterwards
- replay onto a different stream, and across sessions
- independent state per stream
- ~10,000 genuine records with **zero** false replay positives
- render the state via `WindowSnapshot.describe()` in at least one test, so the
  report can show the mechanism working rather than only its verdict

---

## 12. TR-6: Wrong key

*"Attempt to recover a protected record using an incorrect key and demonstrate
that recovery fails safely."*

"Fails safely" is the part under test — not merely "fails". The receiver must
reject cleanly, release no plaintext, raise nothing out of `receive()`, and stay
usable afterwards. A wrong key is an everyday key-management error as much as it
is an attack.

Required coverage:

- genuine record rejected by a receiver holding a different key
- **the control**: the same record accepted under the correct key (without this
  the test proves nothing about the key)
- a batch of records, all failing — not one unlucky record
- a key differing in a **single bit**, swept across the key
- all-zero and all-ones keys are not special
- an attacker-forged record built under the attacker's own key, reproducing
  everything observable so the key is the only difference
- key length validated at construction — a `ConfigurationError`, **not** a
  verdict. Be ready to explain why those two failure kinds are reported
  differently.
- recovery works again once the correct key is used

---

## 13. Commands

Run from the project root.

```bash
python -m pytest -q                        # full suite
python -m pytest -v -k tr5                 # one requirement
python -m pytest -v -k "tr2 and chacha"    # one requirement, one configuration

python -m demo.run_demo                    # TR-1..TR-7 transcripts
python -m demo.run_demo --suite aes-gcm --records 10000
python -m demo.run_network_demo            # over real TCP sockets
python run_all.py                          # everything, into evidence/
```

`demo/run_demo.py` and `demo/run_network_demo.py` already call the API being
built. They fail until the modules exist, and passing them is a good acceptance
check — but they are not a substitute for the unit tests, which have to
demonstrate each requirement individually.

---

## 14. Evidence to save

| Requirement | What to capture |
|---|---|
| TR-2 | Test name, configuration, modification performed, observed reason, `plaintext is None`, result |
| TR-3 | Tag attack type, observed `AUTH_FAILED`/`MALFORMED`, `plaintext is None`, result |
| TR-4 | Field modified, expected reason, observed reason, result |
| TR-5 | First acceptance, replay rejection, state snapshot, stale and out-of-order cases |
| TR-6 | Correct-key control, wrong-key rejection, attacker-forged rejection |
| Integration | Full `pytest` output showing both configurations |

The report requires, for each requirement: objective, procedure, test input,
expected behaviour, observed behaviour, outcome, supporting evidence. The
observed behaviour must come from a run actually performed.

---

## 15. Integration rules

| Keep | Do not change without agreement |
|---|---|
| `parse_record()`, `RecordHeader` | Wire format and header layout |
| `header.aad()` | AAD definition |
| `derive_nonce()` | Nonce derivation |
| `AeadSuite.open()` | Cryptographic backend contract |
| `RejectReason`, `Verdict` fields | Rejection taxonomy |
| `Sender.protect()` | Sender record-generation contract |
| `SessionPolicy` | Session and replay policy semantics |

The names and signatures in the stubs are called from `srp/session.py`,
`demo/`, `bench/` and `tests/conftest.py`. Keep them; everything inside the
modules is free.

---

## 16. Handoff back to Member 1

- Implemented `srp/receiver.py`, `srp/replay.py`, `srp/adversary.py`, with the
  `MEMBER2_STUB` sentinels removed.
- Written TR-2 to TR-6 test files.
- A short note on design decisions taken and anything that surprised you.
- Full test output: `python -m pytest -q` with no skips remaining.
- Evidence files for TR-2 through TR-6.
- The TR-2 to TR-6 report sections.

---

## 17. Viva topics

| Topic | Should be able to explain |
|---|---|
| Receiver | Why parsing, configuration checks, replay check, AEAD verification and replay commit happen in that order |
| Fail-closed | Why a rejected `Verdict` cannot carry plaintext |
| Replay | Why `check()` and `commit()` are separate, and why authentication must precede the commit |
| Replay state | How the high-water mark, offsets, duplicates and stale records are classified |
| AAD | Why the whole 40-byte header is authenticated, and which fields are used before a plaintext exists |
| Adversary | How the attacker changes wire data without the key |
| TR-2/3/4 | Why each mutation causes authentication or framing failure |
| TR-5 | Why the AEAD alone cannot detect an exact replay |
| TR-6 | Why a structurally valid record under another key still fails |

---

## 18. Final checklist

- [ ] `python -m pytest -q` — no skips remaining, both configurations green
- [ ] `MEMBER2_STUB` sentinels deleted from all three modules
- [ ] TR-2 passes without releasing plaintext
- [ ] TR-3 passes without releasing plaintext
- [ ] TR-4 passes with a documented rejection reason for each header field
- [ ] TR-5 passes duplicate, stale, out-of-order and sequence-poisoning cases
- [ ] TR-6 passes wrong-key and attacker-forged cases
- [ ] Replay state is unchanged by unauthenticated records
- [ ] No shared cryptographic or wire-format contract redesigned independently
- [ ] `python -m demo.run_demo` passes for both configurations
- [ ] `python -m demo.run_network_demo` passes for both configurations
- [ ] `python run_all.py` completes with every stage PASS
- [ ] Evidence saved for TR-2 through TR-6
- [ ] Report sections written for TR-2 through TR-6
- [ ] Can explain the complete receiver and security flow for the viva

---

## Out of scope

From Section 3.2 of the assignment — do not build these:

- AES, ChaCha20, GCM or Poly1305 primitives. Use `srp/suites.py`, which wraps a
  reviewed library.
- Key establishment, key exchange, PKI, certificate handling.
- Transport protocol design, reliable delivery, ordering, retransmission. This
  last one matters for `srp/replay.py`: records may legitimately arrive out of
  order, so a design that treats all reordering as an attack is wrong, not
  strict.
