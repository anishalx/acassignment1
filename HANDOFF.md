# Member 2 — work package

CS6530 Applied Cryptography, Assignment 1 (Jul–Nov 2026).

This repository contains a secure data protection subsystem for chunked
application records, built on AEAD in two configurations (AES-256-GCM and
ChaCha20-Poly1305). Member 1 has built the sending side and the record format.
**The receiving side does not exist yet — that is your work package.**

Three source modules and five test modules are specification stubs. Each one
states what the assignment requires of it, which design decisions are yours,
and which names the rest of the codebase already depends on. Nothing else in
the repository needs to change.

---

## 1. What you own

### Source (`srp/`)

| File | What it must do | Requirements |
|---|---|---|
| `srp/replay.py` | Detect replayed records; per-stream state over authenticated sequence numbers | FR-8, SR-5 |
| `srp/receiver.py` | Verify and recover records; reject and report failures without releasing data | FR-6, FR-7, SR-6 |
| `srp/adversary.py` | The Malicious Actor entity: modify or forge records on the wire | Section 6 |

### Tests (`tests/`)

| File | Testing Requirement |
|---|---|
| `tests/test_tr2_ciphertext_integrity.py` | TR-2 — modified ciphertext is rejected |
| `tests/test_tr3_authentication_tag.py` | TR-3 — modified tag is rejected |
| `tests/test_tr4_associated_data.py` | TR-4 — modified AAD is rejected |
| `tests/test_tr5_replay.py` | TR-5 — replayed record is detected and handled |
| `tests/test_tr6_wrong_key.py` | TR-6 — wrong key fails safely |

### Report (`report/REPORT.md`)

The sections covering TR-2 to TR-6, and the replay-handling and
failure-handling parts of the Design Summary. Section 6 of the assignment
requires seven fields for every Testing Requirement: Objective, Procedure, Test
Input, Expected Behaviour, Observed Behaviour, Outcome, Supporting Evidence.
The observed behaviour has to come from a run you actually did.

**Every Testing Requirement must be demonstrated separately under *both* AEAD
configurations.** The assignment awards only partial credit otherwise. The
`suite_name` fixture in `tests/conftest.py` is parametrised over both, so any
test that takes `channel` or `suite_name` is collected twice automatically.
Do not hard-code a suite anywhere.

---

## 2. What is already built (do not change)

| File | Provides |
|---|---|
| `srp/suites.py` | `AeadSuite`, `AesGcmSuite`, `ChaCha20Poly1305Suite` — the only module that touches a crypto library |
| `srp/header.py` | Record header, wire format, and `RecordHeader.aad()` — **read this first** |
| `srp/nonce.py` | Deterministic nonce construction and the per-key record budget |
| `srp/sender.py` | `Sender.protect()` — application record to wire record |
| `srp/session.py` | `SessionPolicy`, `Channel`, `create_channel()` |
| `srp/errors.py` | Exception hierarchy, `RecordStatus`, `RejectReason` |
| `srp/util.py` | Formatting helpers for evidence output |

If you find you need to change one of these, that is a conversation to have
rather than a commit to make — the interfaces are what let both halves be
written in parallel.

### The integration contract

These names and signatures are called from code outside your files
(`srp/session.py`, `demo/`, `bench/`, `tests/conftest.py`). Keep them:

```python
# srp/replay.py
DEFAULT_WINDOW_SIZE, DEFAULT_MAX_STREAMS      # imported by srp/session.py
ReplayVerdict.{FRESH, DUPLICATE, TOO_OLD, INVALID}
ReplayGuard(window_size, *, max_streams)
    .check(key, seq) -> ReplayVerdict          # must not mutate or allocate
    .commit(key, seq) -> bool
    .window_for(key) -> ReplayWindow | None
ReplayWindow(size).{check, commit, seen, snapshot, highest_seq, size, accepted}
WindowSnapshot.describe() -> str

# srp/receiver.py
Verdict(status, reason=None, plaintext=None, header=None, detail="")
    .accepted, .rejected, .describe()
Receiver(suite, *, expected_session_id=None, replay_window=..., max_streams=...)
    .receive(wire) -> Verdict                  # must never raise on wire input
    .receive_all(wires) -> list[Verdict]
    .stats, .suite, .replay_guard, .window_for_stream(session_id, stream_id)

# srp/adversary.py
MaliciousActor(rng=None)   # ~20 attack methods, all listed in the stub
```

Each stub carries a `MEMBER2_STUB = True` sentinel. **Delete it when the module
is real.** The test suite and `run_all.py` key their "pending" behaviour off it,
and both go back to normal on their own once all three are gone.

---

## 3. Where to start

1. Read `srp/header.py`, especially `RecordHeader.aad()`. Which fields are
   authenticated, and which are not, determines what every one of your tests
   can prove.
2. Read the module docstring in each stub you are about to write. The design
   questions in them are the ones the report has to answer, and several have a
   wrong answer that is not obviously wrong.
3. `srp/adversary.py` first. It has no dependencies on your other two modules,
   and you cannot write an honest negative test without it.
4. Then `srp/replay.py`, then `srp/receiver.py`, which ties them together.
5. Then the five test files.

There is one ordering question worth settling before you write `Receiver.receive`,
because it decides how the TR-2/3/4/6 tests must be built: if the attacker
modifies a record the receiver has **already accepted** and re-sends it, which
check rejects it — the replay check, or the tag? Whichever it is, that is not
the failure TR-2 is asking you to demonstrate. Work out what the malicious
actor has to do instead.

### Running things

```
python -m pytest -q                 # currently: 38 passed, 41 skipped
python -m pytest -q -k tr5          # one requirement at a time
python -m demo.run_demo             # evidence transcripts (needs your modules)
python -m demo.run_network_demo     # the same subsystem over real TCP sockets
python run_all.py                   # everything, into evidence/
```

The 41 skips are tests blocked on your modules, plus the five test files you
have not written. `pytest` reclassifies the `NotImplementedError`s from the
stubs as skips so that a real failure elsewhere stays visible; that behaviour
disappears with the sentinels.

### Definition of done

- `python -m pytest -q` — no skips left, both configurations green.
- `python -m demo.run_demo` — passes for `aes-gcm` and `chacha20-poly1305`, and
  writes `evidence/demo-<suite>.log`.
- `python -m demo.run_network_demo` — passes for both. This drives your
  `MaliciousActor` over a real socket and is a good final check that the API
  matches what the rest of the code expects.
- `python run_all.py` — completes with every stage `PASS`.
- `report/REPORT.md` — TR-2 to TR-6 written up from *your* run, with all seven
  fields, both configurations, and the evidence files cited by name.

`demo/run_demo.py` and `demo/run_network_demo.py` already call your API. They
will fail until the modules exist, and passing them is a reasonable acceptance
test — but they are not a substitute for the unit tests, which have to
demonstrate each requirement individually.

---

## 4. Out of scope

Straight from the assignment (Section 3.2). Do not build these:

- AES, ChaCha20, GCM or Poly1305 primitives — use `srp/suites.py`, which wraps
  a reviewed library.
- Key establishment, key exchange, PKI, certificate handling.
- Transport protocol design, reliable delivery, ordering, retransmission.
  This last one matters for `srp/replay.py`: records may legitimately arrive
  out of order, so a design that treats all reordering as an attack is wrong,
  not strict.
