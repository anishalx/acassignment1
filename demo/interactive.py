"""Interactive demonstration of the Secure Record Protection subsystem.

Run from the repository root::

    py -3.11 -m demo.interactive

Lets the user choose an AEAD configuration, type custom payloads, and
manually trigger individual testing-requirement demonstrations (TR-1 to TR-6).
All results are printed to the console with colour-coded verdicts.
"""

from __future__ import annotations

import os
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from srp import (  # noqa: E402
    HEADER_LEN,
    SUITE_NAMES,
    TAG_LEN,
    ConfigurationError,
    MaliciousActor,
    Receiver,
    RecordFlags,
    RecordHeader,
    RecordType,
    RejectReason,
    Sender,
    SessionPolicy,
    create_channel,
    suite_class,
)

# ── Colours ────────────────────────────────────────────────────────────────

GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

SEED = 0xC5_65_30


def _ok(msg: str) -> str:
    return f"  {GREEN}✓ PASS{RESET}  {msg}"


def _fail(msg: str) -> str:
    return f"  {RED}✗ FAIL{RESET}  {msg}"


def _info(msg: str) -> str:
    return f"  {CYAN}ℹ{RESET}  {msg}"


def _warn(msg: str) -> str:
    return f"  {YELLOW}⚠{RESET}  {msg}"


def _header(title: str) -> None:
    print(f"\n{BOLD}{'═' * 70}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'═' * 70}{RESET}")


def _subheader(title: str) -> None:
    print(f"\n{CYAN}  ── {title} ──{RESET}")


def _verdict_line(verdict) -> str:
    if verdict.accepted:
        pt = verdict.plaintext
        preview = pt[:40].decode("utf-8", errors="replace") if pt else ""
        if len(pt) > 40:
            preview += "…"
        return f"{GREEN}ACCEPTED{RESET}  plaintext={preview!r} ({len(pt)} bytes)"
    return (
        f"{RED}REJECTED{RESET}  reason={verdict.reason.value}  "
        f"plaintext={'None' if verdict.plaintext is None else 'LEAKED!'}"
        f"  detail={verdict.detail}"
    )


# ── Suite selection ───────────────────────────────────────────────────────

def choose_suite() -> str:
    names = list(SUITE_NAMES)
    print(f"\n{BOLD}Available AEAD configurations:{RESET}")
    for i, name in enumerate(names, 1):
        print(f"  {i}. {name}")
    while True:
        choice = input(f"\nSelect configuration [1-{len(names)}]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(names):
            return names[int(choice) - 1]
        print(f"{RED}Invalid choice.{RESET}")


# ── Individual demos ─────────────────────────────────────────────────────

def demo_tr1(channel):
    """TR-1: Positive Baseline — user-supplied payload."""
    _subheader("TR-1: Positive Baseline Test")
    payload = input("  Enter your plaintext message: ").encode("utf-8")
    if not payload:
        payload = b"Hello, Applied Cryptography!"
        print(_info(f"Using default: {payload.decode()!r}"))

    wire = channel.send(payload)
    print(_info(f"Protected record: {len(wire)} bytes on the wire"))
    print(_info(f"Header (40B, cleartext): {wire[:HEADER_LEN].hex()}"))
    print(_info(f"Ciphertext ({len(wire)-HEADER_LEN-TAG_LEN}B): {wire[HEADER_LEN:-TAG_LEN].hex()[:80]}…"))
    print(_info(f"Auth tag (16B): {wire[-TAG_LEN:].hex()}"))

    verdict = channel.deliver(wire)
    print(f"\n  Verdict: {_verdict_line(verdict)}")
    if verdict.accepted and verdict.plaintext == payload:
        print(_ok("Record recovered successfully — plaintext matches."))
    else:
        print(_fail("Recovery failed!"))


def demo_tr2(channel, actor):
    """TR-2: Ciphertext Integrity — flip a user-chosen bit."""
    _subheader("TR-2: Ciphertext Integrity Test")
    payload = input("  Enter plaintext to protect: ").encode("utf-8") or b"TR-2 test record"
    wire = channel.send(payload)
    ct_len = len(wire) - HEADER_LEN - TAG_LEN
    print(_info(f"Ciphertext is {ct_len} bytes ({ct_len * 8} bits)"))

    offset_str = input(f"  Byte offset to flip [0-{ct_len - 1}] (Enter = random): ").strip()
    offset = int(offset_str) if offset_str.isdigit() else None
    bit_str = input("  Bit position to flip [0-7] (Enter = random): ").strip()
    bit = int(bit_str) if bit_str.isdigit() else None

    tampered = actor.flip_ciphertext_bit(wire, offset=offset, bit=bit)
    print(_info("Attacker flipped one ciphertext bit."))
    verdict = channel.deliver(tampered)
    print(f"  Verdict: {_verdict_line(verdict)}")

    if verdict.rejected and verdict.reason is RejectReason.AUTH_FAILED:
        print(_ok("Ciphertext modification detected — AUTH_FAILED."))
    else:
        print(_fail("Unexpected result!"))


def demo_tr3(channel, actor):
    """TR-3: Authentication Tag — zero/random/flip the tag."""
    _subheader("TR-3: Authentication Tag Test")
    payload = input("  Enter plaintext: ").encode("utf-8") or b"TR-3 test record"
    wire = channel.send(payload)

    print(f"  Tag attacks:")
    attacks = {
        "1": ("Zero tag", lambda: actor.zero_tag(wire)),
        "2": ("Random tag", lambda: actor.replace_tag(wire)),
        "3": ("Flip first tag bit", lambda: actor.flip_tag_bit(wire, offset=0, bit=0)),
        "4": ("Truncate 1 tag byte", lambda: actor.truncate_tag(wire, count=1)),
    }
    for k, (name, _) in attacks.items():
        print(f"    {k}. {name}")
    print(f"    5. Run all")

    choice = input("  Select attack [1-5]: ").strip() or "5"

    if choice == "5":
        selected = list(attacks.items())
    elif choice in attacks:
        selected = [(choice, attacks[choice])]
    else:
        selected = list(attacks.items())

    for _, (name, fn) in selected:
        tampered = fn()
        verdict = channel.deliver(tampered)
        status = _ok(name) if verdict.rejected else _fail(name)
        print(f"  {status}  → {verdict.reason.value if verdict.reason else '?'}, plaintext={'None' if verdict.plaintext is None else 'LEAKED!'}")


def demo_tr4(channel, actor):
    """TR-4: Associated Data — modify individual header fields."""
    _subheader("TR-4: Associated Data (AAD) Test")
    payload = input("  Enter plaintext: ").encode("utf-8") or b"TR-4 test record"
    wire = channel.send(payload)

    header = RecordHeader.from_bytes(wire[:HEADER_LEN])
    print(_info(f"Original header: {header.summary()}"))
    print(_info("The entire 40-byte header is authenticated as AAD."))

    attacks = [
        ("record_type → CLOSE", lambda: actor.relabel_record_type(wire, RecordType.CLOSE)),
        ("flags → END_OF_STREAM", lambda: actor.set_flags(wire, RecordFlags.END_OF_STREAM)),
        ("stream_id → 999", lambda: actor.redirect_stream(wire, stream_id=999)),
        ("session_id → random", lambda: actor.reassign_session(wire, os.urandom(16))),
        ("suite_id → other", lambda: actor.switch_suite_label(wire, 0x02 if header.suite_id == 0x01 else 0x01)),
        ("payload_len → 9999", lambda: actor.declare_wrong_length(wire, payload_len=9999)),
        ("nonce_prefix → 0xff×4", lambda: actor.tamper_header(wire, nonce_prefix=b"\xff\xff\xff\xff")),
        ("seq → 99999", lambda: actor.renumber(wire, seq=99999)),
    ]

    for name, fn in attacks:
        tampered = fn()
        verdict = channel.deliver(tampered)
        reason = verdict.reason.value if verdict.reason else "?"
        ok = verdict.rejected and verdict.plaintext is None
        line = _ok(f"{name:30s}") if ok else _fail(f"{name:30s}")
        print(f"  {line} → {reason}")


def demo_tr5(channel, actor):
    """TR-5: Replay Test — replay an accepted record."""
    _subheader("TR-5: Replay Test")
    payload = input("  Enter plaintext: ").encode("utf-8") or b"TR-5 replay target"
    wire = channel.send(payload)

    print(_info("Delivering original record…"))
    v1 = channel.deliver(wire)
    print(f"  Original: {_verdict_line(v1)}")

    print(_info("Replaying the exact same bytes…"))
    replayed = actor.replay(wire)
    v2 = channel.deliver(replayed)
    print(f"  Replay:   {_verdict_line(v2)}")

    if v2.rejected and v2.reason is RejectReason.REPLAY_DETECTED:
        print(_ok("Replay detected and rejected!"))
    else:
        print(_fail("Replay was NOT detected!"))

    # Show replay state
    stream_key = (channel.session_id, channel.sender.stream_id)
    window = channel.receiver.replay_guard.window_for(stream_key)
    if window:
        print(_info(f"Replay window state: {window.snapshot().describe()}"))

    # Sequence-number poisoning demo
    print()
    _subheader("Sequence-Number Poisoning Attack")
    forged = actor.renumber(wire, seq=999999)
    print(_info("Attacker forges a record with seq=999999…"))
    v3 = channel.deliver(forged)
    print(f"  Forged:   {_verdict_line(v3)}")

    genuine = channel.send(b"post-poison genuine")
    v4 = channel.deliver(genuine)
    print(f"  Genuine after attack: {_verdict_line(v4)}")

    if v4.accepted:
        print(_ok("Replay state was NOT poisoned — genuine record accepted."))
        print(_info(f"Window highest_seq: {window.highest_seq} (not 999999)"))
    else:
        print(_fail("Replay state was poisoned!"))


def demo_tr6(channel, actor, suite_name):
    """TR-6: Wrong Key — attempt recovery with a different key."""
    _subheader("TR-6: Wrong-Key Test")
    payload = input("  Enter plaintext: ").encode("utf-8") or b"TR-6 secret data"

    cls = suite_class(suite_name)
    correct_key = channel.key
    wrong_key = cls.generate_key()

    print(_info(f"Correct key: {correct_key.hex()[:32]}…"))
    print(_info(f"Wrong key:   {wrong_key.hex()[:32]}…"))

    wire = channel.send(payload)

    # Wrong key
    rx_wrong = Receiver(cls(wrong_key), expected_session_id=channel.session_id)
    v_wrong = rx_wrong.receive(wire)
    print(f"\n  Wrong key:   {_verdict_line(v_wrong)}")

    # Correct key
    v_correct = channel.deliver(wire)
    print(f"  Correct key: {_verdict_line(v_correct)}")

    if v_wrong.rejected and v_correct.accepted:
        print(_ok("Wrong key rejected, correct key accepted."))
    else:
        print(_fail("Unexpected result!"))

    # Attacker-forged record
    print()
    _subheader("Attacker-Forged Record (structurally perfect, wrong key)")
    forged = actor.forge_with_wrong_key(
        suite_name,
        session_id=channel.session_id,
        stream_id=channel.sender.stream_id,
        seq=100,
        nonce_prefix=channel.sender.nonce_prefix,
        payload=b"forged by the attacker",
    )
    v_forged = channel.deliver(forged)
    print(f"  Forged record: {_verdict_line(v_forged)}")
    if v_forged.rejected:
        print(_ok("Attacker-forged record rejected."))


# ── Main menu ────────────────────────────────────────────────────────────

def main():
    _header("CS6530 — Secure Data Protection: Interactive Demo")
    print(f"  Three logical entities: {CYAN}Sender{RESET}, {RED}Malicious Actor{RESET}, {GREEN}Receiver{RESET}")

    suite_name = choose_suite()
    print(_info(f"Using {BOLD}{suite_name}{RESET}"))

    channel = create_channel(suite_name)
    actor = MaliciousActor(random.Random(SEED))

    print(_info(f"Session ID: {channel.session_id.hex()[:16]}…"))
    print(_info(f"Nonce prefix: {channel.sender.nonce_prefix.hex()}"))

    menu = {
        "1": ("TR-1: Positive Baseline (send your own message)", lambda: demo_tr1(channel)),
        "2": ("TR-2: Ciphertext Integrity (flip a ciphertext bit)", lambda: demo_tr2(channel, actor)),
        "3": ("TR-3: Authentication Tag (modify the tag)", lambda: demo_tr3(channel, actor)),
        "4": ("TR-4: Associated Data (tamper header fields)", lambda: demo_tr4(channel, actor)),
        "5": ("TR-5: Replay (re-deliver an accepted record)", lambda: demo_tr5(channel, actor)),
        "6": ("TR-6: Wrong Key (attempt recovery with wrong key)", lambda: demo_tr6(channel, actor, suite_name)),
        "a": ("Run ALL demos sequentially", None),
        "r": ("Reset channel (new key + session)", None),
        "s": ("Switch AEAD configuration", None),
        "q": ("Quit", None),
    }

    while True:
        print(f"\n{BOLD}  ┌──────────────────────────────────────────┐{RESET}")
        print(f"{BOLD}  │  Testing Requirements Demo Menu          │{RESET}")
        print(f"{BOLD}  └──────────────────────────────────────────┘{RESET}")
        for key, (label, _) in menu.items():
            print(f"    {CYAN}{key}{RESET}. {label}")

        choice = input(f"\n  {BOLD}>{RESET} ").strip().lower()

        if choice == "q":
            print(f"\n{DIM}  Goodbye!{RESET}\n")
            break
        elif choice == "r":
            channel = create_channel(suite_name)
            actor = MaliciousActor(random.Random(SEED))
            print(_info(f"New session: {channel.session_id.hex()[:16]}…"))
        elif choice == "s":
            suite_name = choose_suite()
            channel = create_channel(suite_name)
            actor = MaliciousActor(random.Random(SEED))
            print(_info(f"Switched to {suite_name}"))
        elif choice == "a":
            demo_tr1(channel)
            # Fresh channel for each to avoid replay conflicts
            channel = create_channel(suite_name)
            demo_tr2(channel, actor)
            channel = create_channel(suite_name)
            demo_tr3(channel, actor)
            channel = create_channel(suite_name)
            demo_tr4(channel, actor)
            channel = create_channel(suite_name)
            demo_tr5(channel, actor)
            channel = create_channel(suite_name)
            demo_tr6(channel, actor, suite_name)
        elif choice in menu and menu[choice][1] is not None:
            try:
                menu[choice][1]()
            except Exception as e:
                print(f"  {RED}Error: {e}{RESET}")
        else:
            print(f"  {RED}Unknown option.{RESET}")


if __name__ == "__main__":
    main()
