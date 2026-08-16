# Secure Data Protection Subsystem — AES-GCM and ChaCha20-Poly1305

CS6530 Applied Cryptography, Assignment 1 · IIT Madras · Jul–Nov 2026

A subsystem that protects generic chunked/packetized application data
(application records) exchanged between a sender and a receiver, using
Authenticated Encryption with Associated Data in either of two configurations:

| Configuration | Key | Nonce | Tag | Reference |
|---|---|---|---|---|
| AES-256-GCM | 256-bit | 96-bit | 128-bit | NIST SP 800-38D, RFC 5116 |
| ChaCha20-Poly1305 | 256-bit | 96-bit | 128-bit | RFC 8439, RFC 5116 |

Both configurations share the same wire format, nonce construction, replay
window and code path. Only the primitive invoked differs, which is what makes
FR-9 (configuration equivalence) a property of the design rather than something
that had to be engineered separately.

---

## 1. Software requirements

| Requirement | Version used | Notes |
|---|---|---|
| Python | 3.13.3 | 3.10 or newer (the code uses `X \| Y` type syntax and `slots=True` dataclasses) |
| OS | Windows 11 | No platform-specific code; runs unchanged on Linux and macOS |
| CPU | x86-64 with AES-NI | Not required, but see the note in §6 about what it means for TR-8 |

No compiler or build toolchain is needed — the project is pure Python and the
cryptographic primitives come from a pre-built wheel.

## 2. External libraries used

| Library | Version used | Purpose | Required? |
|---|---|---|---|
| [`cryptography`](https://cryptography.io) | 43.0.3 | Supplies `AESGCM` and `ChaCha20Poly1305` (pyca/cryptography, backed by OpenSSL 3.3.2) | **Yes** |
| `pytest` | 9.0.3 | Runs the TR-1…TR-7 test suite | Dev only |
| `matplotlib` | 3.10.5 | Renders the TR-8 charts | Dev only — the benchmark falls back to tables if absent |

Everything else is Python standard library (`struct`, `os`, `socket`,
`statistics`, `dataclasses`, `enum`).

Per Section 3.2 of the assignment, **no cryptographic primitive is implemented
here**. AES, ChaCha20, GCM and Poly1305 are used through the library above. The
entire cryptographic surface of this project is confined to one module,
`srp/suites.py` — nothing else imports `cryptography`.

## 3. Build instructions

There is nothing to compile. Install the dependencies:

```bash
cd <project root>
python -m pip install -r requirements.txt
```

Or, minimally, just the runtime dependency:

```bash
python -m pip install "cryptography>=42.0"
```

The package is importable directly from the repository root — no `pip install -e .`
is needed. `pyproject.toml` sets `pythonpath = ["."]` for pytest, and every
script inserts the repository root into `sys.path` itself, so both
`python -m demo.run_demo` and `python demo/run_demo.py` work.

Verify the installation:

```bash
python -c "from srp import create_channel; c = create_channel('aes-gcm'); print(c.roundtrip(b'hello').describe())"
# ACCEPTED (5 B recovered)
```

## 4. Execution instructions

### Everything at once

```bash
python run_all.py            # tests + demonstrations + analysis + benchmarks
python run_all.py --quick    # faster pass, required TR-8 sizes only
python run_all.py --skip-bench
```

Regenerates every file under `evidence/` and exits non-zero if any stage fails.
Full run takes roughly 4–5 minutes; `--quick` about 1 minute.

### Individual stages

```bash
# Automated test suite: every TR runs against BOTH configurations
python -m pytest -q
python -m pytest -v -k tr5              # just the replay tests
python -m pytest -v -k "tr2 and chacha" # one requirement, one configuration

# TR-1..TR-7 demonstration transcripts -> evidence/demo-<configuration>.log
python -m demo.run_demo
python -m demo.run_demo --suite aes-gcm --records 10000
python -m demo.run_demo --quiet         # write logs without echoing

# The same subsystem over real TCP sockets, with an on-path attacker
python -m demo.run_network_demo
python -m demo.run_network_demo --suite chacha20-poly1305 --records 20

# TR-8 performance evaluation -> evidence/perf-*.{json,md,png}
python -m bench.perf
python -m bench.perf --quick            # 64 B, 1 KiB, 64 KiB only
python -m bench.perf --no-charts

# TR-7 supporting analysis -> evidence/nonce-analysis.md
python -m bench.nonce_analysis
```

### Using the subsystem in your own code

```python
from srp import create_channel

channel = create_channel("chacha20-poly1305")   # or "aes-gcm"

wire = channel.send(b"application record payload")
verdict = channel.deliver(wire)

if verdict.accepted:
    process(verdict.plaintext)
else:
    log_rejection(verdict.reason, verdict.detail)   # plaintext is None here
```

For separate sender and receiver entities over a pre-shared key:

```python
from srp import Sender, Receiver, new_session_id, suite_class

cls = suite_class("aes-gcm")
key = cls.generate_key()          # key establishment is out of scope (§3.2)
session_id = new_session_id()

sender   = Sender(cls(key), session_id, stream_id=1)
receiver = Receiver(cls(key), expected_session_id=session_id)

verdict = receiver.receive(sender.protect(b"record"))
```

## 5. Project layout

```
srp/                    the subsystem
  suites.py             AEAD configuration abstraction — the ONLY module that
                        touches a cryptographic library
  header.py             record header, wire format, and the AAD selection
  nonce.py              deterministic prefix||counter nonce management
  replay.py             sliding-window replay detection
  sender.py             application record -> protected record
  receiver.py           protected record -> verified record, or a typed verdict
  session.py            pairing sender and receiver over a pre-shared key
  adversary.py          the malicious actor used by the negative tests
  errors.py             exception hierarchy and rejection reasons
  util.py               hex dumps and diffs for evidence output

tests/                  pytest suite; every test is parametrised over BOTH
                        configurations, so no test can cover only one
  test_tr1_baseline.py … test_tr7_nonce_management.py
  test_fr_requirements.py   FR-9 equivalence, fail-closed invariant, framing

demo/
  run_demo.py           TR-1..TR-7 with full console evidence
  run_network_demo.py   sender / on-path attacker / receiver over TCP
  evidence.py           the transcript formatter

bench/
  perf.py               TR-8 measurements, tables and charts
  nonce_analysis.py     birthday-bound analysis behind the nonce design

evidence/               generated — transcripts, measurements, charts
report/REPORT.md        the Assignment 1 Report (D2)
run_all.py              regenerates everything
```

## 6. Design summary

Full rationale is in `report/REPORT.md` §2 and in the module docstrings, which
carry the reasoning rather than restating the code. In brief:

**Wire format.** `header (40 B) || ciphertext (n B) || tag (16 B)`. Constant
56-byte overhead, identical under both configurations.

**Associated Data.** The entire 40-byte header, used verbatim as AAD. It carries
`version`, `suite_id`, `record_type`, `flags`, `session_id`, `stream_id`,
`nonce_prefix`, `seq` and `payload_len`. The selection rule was: everything the
receiver must read *before* it holds a verified plaintext is unencryptable by
necessity and therefore must be authenticated; anything else belongs in the
payload where it also gets confidentiality.

**Nonce management.** 96-bit nonce = 32-bit per-session random prefix ‖ 64-bit
monotonic counter (NIST SP 800-38D §8.2.1 deterministic construction). A counter
rather than random nonces, because random 96-bit nonces carry a birthday bound
and a counter carries none; a per-session prefix rather than a bare counter,
because a bare counter repeats across restarts under the same long-term key.
The sender enforces a 2²⁴-record per-key budget and **fails closed** —
`NonceExhaustedError` is raised instead of a nonce being returned.

**Replay handling.** A 64-record sliding bitmap window per
`(session_id, stream_id)`, in the style of IPsec ESP (RFC 4303 §3.4.3 / RFC 6479).
Window over a *window*, not strict successor checking, because reordering and
loss are out of scope (§3.2) and must be tolerated rather than treated as
attacks. The window is consulted before decryption but **committed only after
the tag verifies**, so a forged sequence number cannot advance it — otherwise one
packet claiming `seq = 2⁶³` would be a denial of service.

**Fail-closed.** The receiver returns a `Verdict` whose invariant is asserted in
code: a plaintext is present *if and only if* the record authenticated. All
authentication failures report the same reason and the same detail text, so no
decryption oracle is exposed.

### A note on the TR-8 result

On this host AES-GCM outperforms ChaCha20-Poly1305 at large record sizes, which
is a fact about the CPU, not about the algorithms. `bench/perf.py` therefore
also re-measures with AES-NI and PCLMULQDQ disabled
(`OPENSSL_ia32cap=~0x200000200000000:~0x0`), which reverses the ordering
decisively. See `report/REPORT.md` §4 — reporting only the first number would
have been the misleading half of the comparison.

## 7. Mapping requirements to code and evidence

| Requirement | Implementation | Evidence |
|---|---|---|
| FR-1, FR-3 | `srp/sender.py` | `tests/test_tr1_baseline.py` |
| FR-2, FR-9 | `srp/suites.py`, `srp/session.py` | `tests/test_fr_requirements.py` |
| FR-4, SR-4 | `srp/header.py` | `tests/test_tr4_associated_data.py` |
| FR-5, SR-3 | `srp/nonce.py` | `tests/test_tr7_nonce_management.py`, `evidence/nonce-analysis.md` |
| FR-6 | `srp/receiver.py` | `tests/test_tr1_baseline.py` |
| FR-7, SR-6 | `srp/receiver.py` (`Verdict.__post_init__`) | `tests/test_fr_requirements.py` |
| FR-8, SR-5 | `srp/replay.py` | `tests/test_tr5_replay.py` |
| SR-1 | AEAD confidentiality | `tests/test_tr1_baseline.py` |
| SR-2 | AEAD integrity | `tests/test_tr2_ciphertext_integrity.py`, `test_tr3_authentication_tag.py` |
| TR-1…TR-7 | — | `evidence/demo-*.log`, `python -m pytest` |
| TR-8 | `bench/perf.py` | `evidence/perf-summary.md`, `evidence/perf-*.png` |

## 8. Assumptions

Recorded here and in `report/REPORT.md` §2.7:

1. The sender and receiver already share a 256-bit secret key. Key
   establishment, distribution and rotation are out of scope (§3.2).
2. A session identifier is agreed alongside the key. In this implementation the
   sender generates it and it travels in the authenticated header.
3. Each `Sender` instance owns one `(key, session, stream)` and its nonce
   counter. Two senders must not be constructed with the same key, session and
   nonce prefix; the random prefix makes that collision improbable rather than
   impossible, and per-session key derivation is the documented next step.
4. The transport may reorder, duplicate or drop records. It is assumed not to
   deliver a record more than 64 positions out of order, which is the window
   width; records beyond that are refused as stale rather than accepted.
5. Endpoints are trusted; this subsystem defends the data in transit, not a
   compromised endpoint.
6. Single-threaded use per `Sender`. The nonce manager is deliberately not
   thread-safe — see the rationale in `srp/nonce.py`.
