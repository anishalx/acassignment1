"""Supporting analysis for the nonce management design decision (TR-7, SR-3).

Run from the repository root::

    python -m bench.nonce_analysis

Produces ``evidence/nonce-analysis.md``, which quantifies the choice documented
in :mod:`srp.nonce`: a deterministic counter rather than random nonces, and a
per-session random prefix rather than a bare counter.

The point of putting numbers on this is that "use a counter" is folklore unless
you can say what the alternative costs.  Both alternatives fail for reasons that
are arithmetic, not stylistic, and the arithmetic is short enough to show.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from srp import random_nonce_collision_probability  # noqa: E402
from srp.suites import AesGcmSuite, ChaCha20Poly1305Suite  # noqa: E402

EVIDENCE_DIR = ROOT / "evidence"

#: Record volumes worth tabulating, with why each one matters.
VOLUMES = [
    (10 ** 4, "the volume TR-7 suggests demonstrating"),
    (10 ** 6, "a busy day of telemetry"),
    (2 ** 24, "this subsystem's deployed per-key record budget"),
    (2 ** 32, "the NIST SP 800-38D s8.3 cap on random-nonce construction"),
    (2 ** 40, "a long-lived key that was never rotated"),
    (2 ** 48, "roughly where a 96-bit random nonce collision becomes likely"),
    (2 ** 49, "past the point of no return"),
]


def format_probability(p: float) -> str:
    if p == 0:
        return "0"
    if p >= 1e-4:
        return f"{p:.4f}"
    return f"{p:.3e}"


def approx_log2(p: float) -> str:
    import math

    if p <= 0:
        return "-inf (exactly zero)"
    return f"2^{math.log2(p):.1f}"


def build_report() -> str:
    lines: list[str] = []
    add = lines.append

    add("# Nonce management analysis")
    add("")
    add("Supporting material for TR-7 and SR-3. Quantifies the two design")
    add("decisions documented in `srp/nonce.py`.")
    add("")

    add("## The construction in use")
    add("")
    add("```")
    add("nonce (96 bits) = nonce_prefix (32 bits, random per session)")
    add("                || seq         (64 bits, big-endian counter)")
    add("```")
    add("")
    add("NIST SP 800-38D s8.2.1 deterministic construction: a fixed field")
    add("identifying the device/session, and an invocation field that must not")
    add("repeat. Both fields travel in the authenticated record header, so the")
    add("receiver reconstructs the nonce without it being sent separately.")
    add("")

    add("## Decision 1: counter, not random nonces")
    add("")
    add("With uniformly random 96-bit nonces, the probability that some pair")
    add("among `q` records collides follows the birthday bound:")
    add("")
    add("```")
    add("p(q) ~ 1 - exp( -q(q-1) / 2^97 )")
    add("```")
    add("")
    add("A collision is not a near miss. Both AES-GCM and ChaCha20-Poly1305")
    add("derive their keystream *and* their one-time authentication key from")
    add("(key, nonce). Repeat the pair and an attacker recovers the XOR of the")
    add("two plaintexts and, worse, enough structure to forge tags at will. So")
    add("the column below is not a quality metric; it is the probability of")
    add("total failure.")
    add("")
    add("| Records under one key | Random 96-bit nonce | ~log2 | Counter | Why this volume |")
    add("|---|---|---|---|---|")
    for q, why in VOLUMES:
        p = random_nonce_collision_probability(q)
        label = f"2^{q.bit_length() - 1}" if (q & (q - 1)) == 0 else f"{q:,}"
        add(f"| {label} | {format_probability(p)} | {approx_log2(p)} | 0 | {why} |")
    add("")
    add("The counter column is exactly zero, not merely small, and it is zero")
    add("for a structural reason rather than a probabilistic one: a strictly")
    add("increasing 64-bit integer cannot produce the same value twice before it")
    add("wraps, and the subsystem refuses to send long before it could wrap.")
    add("This is also why the property is *testable* -- `test_tr7_nonce_")
    add("management.py` asserts uniqueness over 10,000 real nonces directly,")
    add("which is not something one can do with a probabilistic argument.")
    add("")

    add("## Decision 2: per-session random prefix, not a bare counter")
    add("")
    add("A counter alone is safe within one run and catastrophic across runs.")
    add("Restart a sender that persists nothing and it re-emits seq 0, 1, 2, ...")
    add("against different plaintexts under the same long-term key -- the exact")
    add("collision the counter was chosen to avoid, delivered on a plate. This")
    add("failure has a long history in deployed systems: it is the mechanism")
    add("behind the WPA2 key-reinstallation attack, and behind repeated IoT")
    add("firmware bugs that reset the counter on reboot.")
    add("")
    add("The 32-bit random prefix means each session occupies a disjoint region")
    add("of the nonce space, so the counter only has to be unique *within* a")
    add("session -- which an in-memory integer guarantees with no persistent")
    add("state and no coordination.")
    add("")
    add("The residual risk is two sessions drawing the same prefix under the")
    add("same key, again a birthday bound but over 32 bits:")
    add("")
    add("| Sessions sharing one key | P(prefix collision) |")
    add("|---|---|")
    for sessions in (10, 100, 1_000, 10_000, 65_536, 200_000):
        p = random_nonce_collision_probability(sessions, nonce_bits=32)
        add(f"| {sessions:,} | {format_probability(p)} |")
    add("")
    add("Two sessions sharing a prefix is not automatically a nonce collision --")
    add("their counters would also have to overlap, which they do, from seq 0.")
    add("So this table should be read as a genuine bound on how many sessions")
    add("one key may serve. It is comfortable for the volumes in scope and")
    add("uncomfortable past a few thousand sessions per key.")
    add("")
    add("The clean fix is not a wider prefix but per-session key derivation:")
    add("derive `K_session = KDF(K, session_id)` and each session gets its own")
    add("key, making cross-session nonce reuse impossible by construction rather")
    add("than by probability. That is a key-management change, and key")
    add("establishment and management are out of scope for this assignment")
    add("(Section 3.2), so it is recorded here as the documented next step")
    add("rather than implemented.")
    add("")

    add("## Decision 3: the per-key record budget")
    add("")
    add("Nonce uniqueness is necessary but not sufficient: both constructions")
    add("also degrade with the total volume protected under one key.")
    add("")
    add("| Configuration | Algorithm-inherent limit | Reason |")
    add("|---|---|---|")
    add(f"| AES-256-GCM | 2^{AesGcmSuite.max_records_per_key.bit_length() - 1} records | "
        "GHASH collision term grows as sigma^2 / 2^128; TLS 1.3 (RFC 8446 s5.5) "
        "caps AES-GCM at 2^24.5 records |")
    add(f"| ChaCha20-Poly1305 | 2^{ChaCha20Poly1305Suite.max_records_per_key.bit_length() - 1} records | "
        "512-bit state, no birthday bound of that form; RFC 8446 sets no "
        "comparable cap |")
    add("")
    add("The subsystem deploys the stricter of the two, 2^24, for **both**")
    add("configurations. That is a deliberate FR-9 decision: switching AEAD")
    add("configuration must not change what the subsystem does, only which")
    add("primitive it calls, so the observable record budget is held identical.")
    add("")
    add("The sender enforces it by failing closed -- `NonceExhaustedError` is")
    add("raised *instead of* returning a nonce, so there is no code path by")
    add("which a caller obtains a reused one. Retrying yields the same error;")
    add("the correct response is to rekey.")
    add("")

    return "\n".join(lines) + "\n"


def main() -> int:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE_DIR / "nonce-analysis.md"
    report = build_report()
    path.write_text(report, encoding="utf-8")

    print("=" * 78)
    print(" Nonce management analysis")
    print("=" * 78)
    print(f"  {'records under one key':<28} {'random 96-bit nonce':>22}   counter")
    print("-" * 78)
    for q, _ in VOLUMES:
        p = random_nonce_collision_probability(q)
        label = f"2^{q.bit_length() - 1}" if (q & (q - 1)) == 0 else f"{q:,}"
        print(f"  {label:<28} {format_probability(p):>22}   0")
    print("-" * 78)
    print(f"  written to {path.relative_to(ROOT)}")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
