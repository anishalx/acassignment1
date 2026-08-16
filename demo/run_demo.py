"""Demonstrates TR-1 through TR-7 and writes the report's supporting evidence.

Run from the repository root::

    python -m demo.run_demo                     # both AEAD configurations
    python -m demo.run_demo --suite aes-gcm     # one configuration
    python -m demo.run_demo --quiet             # write logs without echoing

Each Testing Requirement is exercised against both configurations and the
transcript is written to ``evidence/demo-<configuration>.log``.  The process
exits non-zero if any demonstration fails, so it doubles as a smoke test.

The three logical entities of Section 6 -- Sender, Malicious Actor and Receiver
-- appear here as ``channel.sender``, a :class:`~srp.adversary.MaliciousActor`,
and ``channel.receiver``.  The actor never touches the key; it only rewrites
bytes in flight, which is the capability a real on-path attacker has.
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from demo.evidence import Evidence  # noqa: E402
from srp import (  # noqa: E402
    HEADER_LEN,
    SUITE_NAMES,
    TAG_LEN,
    MaliciousActor,
    NonceExhaustedError,
    Receiver,
    RecordFlags,
    RecordType,
    RejectReason,
    Sender,
    SessionPolicy,
    create_channel,
    derive_nonce,
    new_session_id,
    parse_record,
    random_nonce_collision_probability,
    suite_class,
)

SEED = 0xC5_65_30
EVIDENCE_DIR = ROOT / "evidence"


# ---------------------------------------------------------------------------
# TR-1  Positive Baseline Test
# ---------------------------------------------------------------------------

def tr1_positive_baseline(ev: Evidence, suite_name: str) -> None:
    ev.begin(
        "TR-1",
        "Positive Baseline Test",
        suite_name,
        objective=(
            "Demonstrate successful protection, transmission, verification and "
            "recovery of valid application records."
        ),
        procedure=[
            "Establish a session over a pre-shared key.",
            "Protect a series of application records of differing sizes.",
            "Deliver each protected record to the receiver.",
            "Confirm each recovered record equals the original, byte for byte.",
        ],
        test_input="Application records of 0, 17, 64, 1024 and 65536 bytes.",
        expected="All records are accepted and recovered exactly.",
    )

    channel = create_channel(suite_name)
    ev.step("Session established")
    ev.field("AEAD configuration", suite_name)
    ev.field("key (pre-shared)", channel.key.hex())
    ev.field("session id", channel.session_id.hex())
    ev.field("nonce prefix", channel.sender.nonce_prefix.hex())

    rng = random.Random(SEED)
    records = [
        b"",
        b"telemetry frame 1",
        rng.randbytes(64),
        rng.randbytes(1024),
        rng.randbytes(65536),
    ]

    ev.step("Protecting and delivering records")
    recovered_all = True
    for payload in records:
        wire = channel.send(payload)
        verdict = channel.deliver(wire)
        ok = verdict.accepted and verdict.plaintext == payload
        recovered_all &= ok
        ev.field(
            f"{len(payload):>6} B record",
            f"wire={len(wire):>6} B  seq={parse_record(wire).header.seq}  "
            f"-> {verdict.describe()}",
        )

    ev.step("Detail of one protected record")
    payload = b"telemetry frame: sensor=temp value=21.5C ts=1755300000"
    wire = channel.send(payload)
    ev.hexdump("application record (plaintext)", payload)
    ev.show_record("protected application record", wire)
    verdict = channel.deliver(wire)
    ev.hexdump("recovered application record", verdict.plaintext)

    ev.step("Confidentiality spot check (SR-1)")
    marker = b"CONFIDENTIAL-MARKER"
    marked = channel.send(marker + b" payload body")
    marked_verdict = channel.deliver(marked)
    ev.field("plaintext marker", marker.decode())
    ev.field("marker present on wire", marker in marked)
    ev.field("record still recovers", marked_verdict.accepted)

    delivered = len(records) + 2  # the size batch, the detailed record, the marker
    ev.observe(
        f"All {delivered} records delivered were accepted; recovered plaintext "
        f"identical to the input in every case."
    )
    ev.observe(
        f"Wire overhead is a constant {HEADER_LEN + TAG_LEN} bytes "
        f"({HEADER_LEN} B header + {TAG_LEN} B tag) regardless of record size."
    )
    ev.observe("The plaintext marker does not appear anywhere in the protected record.")

    ev.check(recovered_all, "every record recovered byte-for-byte")
    ev.check(verdict.accepted and verdict.plaintext == payload, "detailed record recovered")
    ev.check(marker not in marked, "plaintext does not appear on the wire")
    ev.check(channel.receiver.stats.rejected_total == 0, "no valid record was rejected")
    ev.check(channel.receiver.stats.accepted == delivered,
             f"all {delivered} delivered records accepted")
    ev.end()


# ---------------------------------------------------------------------------
# TR-2  Ciphertext Integrity Test
# ---------------------------------------------------------------------------

def tr2_ciphertext_integrity(ev: Evidence, suite_name: str) -> None:
    ev.begin(
        "TR-2",
        "Ciphertext Integrity Test",
        suite_name,
        objective=(
            "Demonstrate that modification of the protected application record "
            "by the malicious actor causes authentication verification to fail "
            "and the record to be rejected."
        ),
        procedure=[
            "Sender protects an application record.",
            "Malicious actor intercepts it in flight and flips one ciphertext bit.",
            "Only the modified record is delivered to the receiver.",
            "Repeat for every bit of an 8-byte record (exhaustive sweep).",
        ],
        test_input="A valid protected record with exactly one ciphertext bit inverted.",
        expected="AUTH_FAILED; no application record is released.",
    )

    channel = create_channel(suite_name)
    actor = MaliciousActor(random.Random(SEED))

    ev.step("Single-bit modification of the ciphertext")
    payload = b"application record that must not be modifiable"
    wire = channel.send(payload)
    tampered = actor.flip_ciphertext_bit(wire, offset=0, bit=0)
    ev.show_record("original protected record", wire)
    ev.show_diff(wire, tampered)
    ev.show_record("modified protected record", tampered)
    verdict = channel.deliver(tampered)
    ev.show_verdict("receiver verdict", verdict)
    ev.field("plaintext released", verdict.plaintext)

    ev.step("Exhaustive single-bit sweep over an 8-byte record")
    sweep_payload = b"8 octets"
    reasons: dict[str, int] = {}
    accepted = 0
    for offset in range(len(sweep_payload)):
        for bit in range(8):
            probe = channel.send(sweep_payload)
            result = channel.deliver(actor.flip_ciphertext_bit(probe, offset=offset, bit=bit))
            if result.accepted:
                accepted += 1
            else:
                reasons[result.reason.value] = reasons.get(result.reason.value, 0) + 1
    ev.field("modifications attempted", 8 * len(sweep_payload))
    ev.field("accepted", accepted)
    ev.field("rejections by reason", reasons)

    ev.step("Truncation of the ciphertext body")
    truncated = actor.truncate_ciphertext(channel.send(b"a record of known length"), count=4)
    trunc_verdict = channel.deliver(truncated)
    ev.show_verdict("receiver verdict", trunc_verdict)

    ev.observe(
        f"A single inverted ciphertext bit is rejected with "
        f"{verdict.reason.value}; no plaintext is returned."
    )
    ev.observe(
        f"All {8 * len(sweep_payload)} single-bit ciphertext modifications were "
        f"rejected ({reasons}); none was accepted."
    )
    ev.observe(
        f"Truncating the body is caught earlier still, by framing validation "
        f"({trunc_verdict.reason.value}), because payload_len is authenticated."
    )

    ev.check(verdict.rejected and verdict.reason is RejectReason.AUTH_FAILED,
             "single-bit ciphertext modification rejected as AUTH_FAILED")
    ev.check(verdict.plaintext is None, "no plaintext released")
    ev.check(accepted == 0, "no modification in the exhaustive sweep was accepted")
    ev.check(set(reasons) == {"AUTH_FAILED"}, "every sweep rejection was AUTH_FAILED")
    ev.check(trunc_verdict.reason is RejectReason.MALFORMED, "truncation rejected")
    ev.end()


# ---------------------------------------------------------------------------
# TR-3  Authentication Tag Test
# ---------------------------------------------------------------------------

def tr3_authentication_tag(ev: Evidence, suite_name: str) -> None:
    ev.begin(
        "TR-3",
        "Authentication Tag Test",
        suite_name,
        objective=(
            "Demonstrate that modification of the authentication tag causes "
            "authentication verification to fail and the record to be rejected."
        ),
        procedure=[
            "Sender protects an application record.",
            "Malicious actor modifies only the 16-byte tag, leaving header and "
            "ciphertext untouched.",
            "Deliver to the receiver.",
            "Sweep all 128 tag bits, then attempt 256 random tag forgeries.",
        ],
        test_input="A valid protected record with a modified authentication tag.",
        expected="AUTH_FAILED; no application record is released.",
    )

    channel = create_channel(suite_name)
    actor = MaliciousActor(random.Random(SEED))

    ev.step("Single-bit modification of the tag")
    wire = channel.send(b"application record with an intact body")
    tampered = actor.flip_tag_bit(wire, offset=0, bit=0)
    ev.field("original tag", wire[-TAG_LEN:].hex())
    ev.field("modified tag", tampered[-TAG_LEN:].hex())
    ev.field("header+ciphertext unchanged", tampered[:-TAG_LEN] == wire[:-TAG_LEN])
    verdict = channel.deliver(tampered)
    ev.show_verdict("receiver verdict", verdict)

    ev.step("Exhaustive sweep over all 128 tag bits")
    tag_accepted = 0
    tag_reasons: dict[str, int] = {}
    for offset in range(TAG_LEN):
        for bit in range(8):
            probe = channel.send(b"body held constant")
            result = channel.deliver(actor.flip_tag_bit(probe, offset=offset, bit=bit))
            if result.accepted:
                tag_accepted += 1
            else:
                tag_reasons[result.reason.value] = tag_reasons.get(result.reason.value, 0) + 1
    ev.field("tag bits flipped", 8 * TAG_LEN)
    ev.field("accepted", tag_accepted)
    ev.field("rejections by reason", tag_reasons)

    ev.step("Random tag forgery attempts")
    forgeries = 256
    forged_accepted = 0
    for _ in range(forgeries):
        probe = channel.send(b"forge me")
        if channel.deliver(actor.replace_tag(probe)).accepted:
            forged_accepted += 1
    ev.field("forgery attempts", forgeries)
    ev.field("accepted", forged_accepted)
    ev.field("per-attempt success probability", "2^-128")

    ev.step("All-zero and truncated tags")
    zero_verdict = channel.deliver(actor.zero_tag(channel.send(b"zero tag")))
    trunc_verdict = channel.deliver(actor.truncate_tag(channel.send(b"short tag"), count=4))
    ev.show_verdict("all-zero tag", zero_verdict)
    ev.show_verdict("truncated tag", trunc_verdict)

    ev.observe(
        f"Inverting one tag bit is rejected with {verdict.reason.value}, with the "
        f"header and ciphertext left byte-identical."
    )
    ev.observe(f"All {8 * TAG_LEN} single-bit tag modifications were rejected.")
    ev.observe(f"All {forgeries} random 128-bit tag forgeries were rejected.")
    ev.observe(
        f"A truncated tag is rejected as {trunc_verdict.reason.value}: the tag "
        f"length is fixed at {TAG_LEN} bytes, so short tags never reach the AEAD."
    )

    ev.check(verdict.reason is RejectReason.AUTH_FAILED, "tag bit flip rejected")
    ev.check(tag_accepted == 0, "no tag-bit modification accepted")
    ev.check(set(tag_reasons) == {"AUTH_FAILED"}, "all tag sweeps AUTH_FAILED")
    ev.check(forged_accepted == 0, "no random tag forgery accepted")
    ev.check(zero_verdict.reason is RejectReason.AUTH_FAILED, "zero tag rejected")
    ev.check(trunc_verdict.reason is RejectReason.MALFORMED, "truncated tag rejected")
    ev.end()


# ---------------------------------------------------------------------------
# TR-4  Associated Data (AAD) Test
# ---------------------------------------------------------------------------

def tr4_associated_data(ev: Evidence, suite_name: str) -> None:
    ev.begin(
        "TR-4",
        "Associated Data (AAD) Test",
        suite_name,
        objective=(
            "Demonstrate that modification of the Associated Data causes "
            "authentication verification to fail and the record to be rejected."
        ),
        procedure=[
            "Sender protects a DATA record on stream 1.",
            "Malicious actor rewrites authenticated header fields: record type, "
            "flags, stream id, session id, suite id, declared length.",
            "Deliver each variant to the receiver.",
            "Sweep all 320 header bits and attribute each rejection to a field.",
        ],
        test_input="A valid protected record with modified header (AAD) fields.",
        expected=(
            "Every variant is rejected; semantic fields fail authentication, "
            "framing and binding fields are caught by earlier checks."
        ),
    )

    channel = create_channel(suite_name)
    actor = MaliciousActor(random.Random(SEED))

    ev.step("The AAD is the 40-byte record header")
    wire = channel.send(b"ordinary data record on stream 1")
    header = parse_record(wire).header
    ev.field("header / AAD", header.aad().hex())
    ev.field("decoded", header.summary())

    ev.step("Semantic modifications of individual AAD fields")
    other_suite_id = 0x02 if channel.sender.suite.suite_id == 0x01 else 0x01
    cases = [
        ("record_type DATA -> CLOSE", lambda w: actor.relabel_record_type(w, RecordType.CLOSE)),
        ("flags -> END_OF_STREAM", lambda w: actor.set_flags(w, RecordFlags.END_OF_STREAM)),
        ("stream_id 1 -> 7", lambda w: actor.redirect_stream(w, 7)),
        ("nonce_prefix -> deadbeef", lambda w: actor.tamper_header(w, nonce_prefix=b"\xde\xad\xbe\xef")),
        ("seq -> 5000", lambda w: actor.renumber(w, 5000)),
        ("session_id -> random", lambda w: actor.reassign_session(w, new_session_id())),
        (f"suite_id -> 0x{other_suite_id:02x}", lambda w: actor.switch_suite_label(w, other_suite_id)),
        ("payload_len -> 1", lambda w: actor.declare_wrong_length(w, 1)),
    ]
    case_results = {}
    for label, attack in cases:
        probe = channel.send(b"ordinary data record on stream 1")
        result = channel.deliver(attack(probe))
        case_results[label] = result
        ev.field(label, f"{result.describe()}")

    ev.step("Exhaustive sweep over all 320 header bits")
    field_ranges = {
        "version": range(0, 1), "suite_id": range(1, 2), "record_type": range(2, 3),
        "flags": range(3, 4), "session_id": range(4, 20), "stream_id": range(20, 24),
        "nonce_prefix": range(24, 28), "seq": range(28, 36), "payload_len": range(36, 40),
    }
    attribution: dict[str, dict[str, int]] = {name: {} for name in field_ranges}
    header_accepted = 0
    for offset in range(HEADER_LEN):
        name = next(n for n, r in field_ranges.items() if offset in r)
        for bit in range(8):
            probe = channel.send(b"header integrity probe")
            result = channel.deliver(actor.flip_header_bit(probe, offset=offset, bit=bit))
            if result.accepted:
                header_accepted += 1
            else:
                bucket = attribution[name]
                bucket[result.reason.value] = bucket.get(result.reason.value, 0) + 1
    ev.field("header bits flipped", 8 * HEADER_LEN)
    ev.field("accepted", header_accepted)
    for name, bucket in attribution.items():
        ev.field(f"  {name}", bucket)

    ev.observe(
        "The AAD is the complete 40-byte header, transmitted in the clear and "
        "authenticated in full."
    )
    ev.observe(
        "Modifying record_type, flags, stream_id, nonce_prefix or seq is "
        "rejected as AUTH_FAILED -- the cryptographic binding."
    )
    ev.observe(
        "Modifying suite_id, session_id or payload_len is rejected earlier, by "
        "the configuration binding, the session pin and framing validation "
        "respectively -- defence in depth over the same authenticated bytes."
    )
    ev.observe(f"All {8 * HEADER_LEN} single-bit AAD modifications were rejected.")

    ev.check(header_accepted == 0, "no header modification accepted")
    ev.check(
        all(r.rejected for r in case_results.values()),
        "every semantic AAD modification rejected",
    )
    for name in ("record_type", "flags", "stream_id", "nonce_prefix", "seq"):
        ev.check(
            set(attribution[name]) == {"AUTH_FAILED"},
            f"{name} modifications fail authentication",
        )
    ev.check(set(attribution["suite_id"]) == {"SUITE_MISMATCH"},
             "suite_id modifications hit the configuration binding")
    ev.check(set(attribution["session_id"]) == {"SESSION_MISMATCH"},
             "session_id modifications hit the session pin")
    ev.check(set(attribution["payload_len"]) == {"MALFORMED"},
             "payload_len modifications hit framing validation")
    ev.end()


# ---------------------------------------------------------------------------
# TR-5  Replay Test
# ---------------------------------------------------------------------------

def tr5_replay(ev: Evidence, suite_name: str) -> None:
    ev.begin(
        "TR-5",
        "Replay Test",
        suite_name,
        objective=(
            "Demonstrate that replay of a previously accepted protected "
            "application record is detected and handled per the documented "
            "replay handling strategy."
        ),
        procedure=[
            "Deliver a record and confirm acceptance.",
            "Malicious actor re-sends the identical record.",
            "Confirm the AEAD alone would accept it, but the subsystem does not.",
            "Exercise out-of-order delivery, stale records and window poisoning.",
        ],
        test_input="A byte-identical copy of an already-accepted protected record.",
        expected="REPLAY_DETECTED; no application record is released.",
    )

    channel = create_channel(suite_name)
    actor = MaliciousActor(random.Random(SEED))

    ev.step("Strategy in force")
    ev.field("mechanism", "sliding bitmap window over authenticated seq")
    ev.field("window size", f"{channel.policy.replay_window} records")
    ev.field("scope", "per (session_id, stream_id)")
    ev.field("window update", "only after successful authentication")

    ev.step("Accept a record, then replay it")
    payload = b"application record to be replayed"
    wire = channel.send(payload)
    first = channel.deliver(wire)
    ev.show_verdict("first delivery", first)
    replayed = actor.replay(wire)
    ev.field("replay is byte-identical", replayed == wire)
    second = channel.deliver(replayed)
    ev.show_verdict("replayed delivery", second)
    ev.field("plaintext released", second.plaintext)

    ev.step("Why the AEAD alone cannot detect this")
    record = parse_record(wire)
    nonce = derive_nonce(record.header.nonce_prefix, record.header.seq)
    direct = channel.receiver.suite.open(nonce, record.ciphertext_and_tag, record.header.aad())
    ev.field("raw AEAD decryption of replay", f"succeeds, recovers {len(direct)} bytes")
    ev.field("subsystem verdict", second.reason.value)

    ev.step("Replay flood")
    flood = 100
    flood_accepted = sum(1 for _ in range(flood) if channel.deliver(actor.replay(wire)).accepted)
    ev.field("replays attempted", flood)
    ev.field("accepted", flood_accepted)

    ev.step("Out-of-order delivery is tolerated, duplicates are not")
    ooo = create_channel(suite_name, policy=SessionPolicy(replay_window=8))
    wires = [ooo.send(f"record {i}".encode()) for i in range(32)]
    order = [3, 0, 7, 1, 5, 2, 6, 4]
    ooo_ok = all(ooo.deliver(wires[i]).accepted for i in order)
    ev.field("delivery order", order)
    ev.field("all accepted", ooo_ok)
    dup = ooo.deliver(wires[3])
    ev.show_verdict("duplicate of seq 3", dup)

    ev.step("Records below the window are refused as stale")
    ooo.deliver(wires[19])
    window = ooo.receiver.window_for_stream(ooo.session_id, 1)
    ev.field("window state", window.snapshot().describe())
    in_window = ooo.deliver(wires[12])
    below = ooo.deliver(wires[11])
    ev.show_verdict("seq 12 (oldest in window)", in_window)
    ev.show_verdict("seq 11 (one below window)", below)

    ev.step("A forged sequence number cannot poison the window")
    poison_channel = create_channel(suite_name)
    poison_channel.deliver(poison_channel.send(b"legitimate"))
    victim_window = poison_channel.receiver.window_for_stream(poison_channel.session_id, 1)
    before = victim_window.highest_seq
    poison = actor.renumber(poison_channel.send(b"poison"), seq=2 ** 63)
    poison_verdict = poison_channel.deliver(poison)
    after = victim_window.highest_seq
    ev.field("forged seq", 2 ** 63)
    ev.show_verdict("verdict", poison_verdict)
    ev.field("window highest before", before)
    ev.field("window highest after", after)
    still_works = poison_channel.deliver(poison_channel.send(b"still working")).accepted
    ev.field("channel still functional", still_works)

    ev.step("Renumbering a replay to evade the window")
    renumbered = channel.deliver(actor.renumber(wire, seq=999_999))
    ev.show_verdict("renumbered replay", renumbered)

    ev.observe(
        f"A byte-identical replay is rejected as {second.reason.value}, even "
        f"though its authentication tag verifies correctly."
    )
    ev.observe(f"All {flood} replays in a flood were rejected.")
    ev.observe(
        "Out-of-order delivery within the window is accepted; a duplicate of an "
        "out-of-order record is still detected."
    )
    ev.observe(
        f"A record below the window is rejected as {below.reason.value}, the "
        f"conservative choice where history is no longer retained."
    )
    ev.observe(
        "A forged high sequence number leaves the window untouched, because the "
        "window is committed only after authentication succeeds."
    )
    ev.observe(
        f"Renumbering a replayed record to evade the window fails with "
        f"{renumbered.reason.value}: seq is authenticated and feeds the nonce."
    )

    ev.check(first.accepted, "original record accepted")
    ev.check(second.reason is RejectReason.REPLAY_DETECTED, "replay detected")
    ev.check(second.plaintext is None, "no plaintext released on replay")
    ev.check(direct == payload, "raw AEAD would have accepted the replay")
    ev.check(flood_accepted == 0, "no replay in the flood was accepted")
    ev.check(ooo_ok, "out-of-order delivery accepted")
    ev.check(dup.reason is RejectReason.REPLAY_DETECTED, "out-of-order duplicate detected")
    ev.check(in_window.accepted, "oldest in-window record accepted")
    ev.check(below.reason is RejectReason.STALE_RECORD, "below-window record refused")
    ev.check(before == after, "forged sequence number did not move the window")
    ev.check(still_works, "channel functional after poisoning attempt")
    ev.check(renumbered.reason is RejectReason.AUTH_FAILED, "renumbered replay rejected")
    ev.end()


# ---------------------------------------------------------------------------
# TR-6  Wrong-Key Test
# ---------------------------------------------------------------------------

def tr6_wrong_key(ev: Evidence, suite_name: str) -> None:
    ev.begin(
        "TR-6",
        "Wrong-Key Test",
        suite_name,
        objective=(
            "Demonstrate that use of an incorrect cryptographic key results in "
            "authentication verification failure and rejection of the record."
        ),
        procedure=[
            "Sender protects records under key K.",
            "A receiver holding key K' != K attempts verification.",
            "Repeat with a key differing from K in a single bit.",
            "Malicious actor forges a structurally perfect record under its own key.",
        ],
        test_input="Valid protected records verified under an incorrect key.",
        expected="AUTH_FAILED in every case; no application record is released.",
    )

    cls = suite_class(suite_name)
    correct_key = cls.generate_key()
    wrong_key = cls.generate_key()
    session_id = new_session_id()

    sender = Sender(cls(correct_key), session_id)
    good_receiver = Receiver(cls(correct_key), expected_session_id=session_id)
    bad_receiver = Receiver(cls(wrong_key), expected_session_id=session_id)

    ev.step("Keys in play")
    ev.field("correct key K", correct_key.hex())
    ev.field("incorrect key K'", wrong_key.hex())
    ev.field("hamming distance", sum(bin(a ^ b).count("1") for a, b in zip(correct_key, wrong_key)))

    ev.step("Same record, two receivers")
    payload = b"a perfectly genuine application record"
    wire = sender.protect(payload)
    good = good_receiver.receive(wire)
    bad = bad_receiver.receive(wire)
    ev.show_verdict("receiver with key K", good)
    ev.show_verdict("receiver with key K'", bad)
    ev.field("plaintext released by K'", bad.plaintext)

    ev.step("Batch under the wrong key")
    batch = 100
    batch_accepted = sum(
        1 for i in range(batch)
        if bad_receiver.receive(sender.protect(f"record {i}".encode())).accepted
    )
    ev.field("records delivered", batch)
    ev.field("accepted", batch_accepted)

    ev.step("Keys differing in a single bit (all 256 positions)")
    near_miss_accepted = 0
    for byte_index in range(cls.key_len):
        for bit in range(8):
            near = bytearray(correct_key)
            near[byte_index] ^= 1 << bit
            receiver = Receiver(cls(bytes(near)), expected_session_id=session_id)
            if receiver.receive(sender.protect(b"near miss probe")).accepted:
                near_miss_accepted += 1
    ev.field("single-bit key variants", 8 * cls.key_len)
    ev.field("accepted", near_miss_accepted)

    ev.step("Attacker forges a record under a key of its own")
    actor = MaliciousActor(random.Random(SEED))
    genuine = sender.protect(b"genuine record")
    good_receiver.receive(genuine)
    genuine_header = parse_record(genuine).header
    forged = actor.forge_with_wrong_key(
        suite_name,
        session_id=genuine_header.session_id,
        stream_id=genuine_header.stream_id,
        seq=genuine_header.seq + 1,
        nonce_prefix=genuine_header.nonce_prefix,
        payload=b"injected application record",
    )
    forged_header = parse_record(forged).header
    ev.field("forged session id matches", forged_header.session_id == genuine_header.session_id)
    ev.field("forged stream id matches", forged_header.stream_id == genuine_header.stream_id)
    ev.field("forged nonce prefix matches", forged_header.nonce_prefix == genuine_header.nonce_prefix)
    ev.field("forged seq (fresh, not a replay)", forged_header.seq)
    ev.show_record("forged record", forged)
    forged_verdict = good_receiver.receive(forged)
    ev.show_verdict("receiver verdict", forged_verdict)

    ev.observe(
        f"A genuine record verified under key K' is rejected with "
        f"{bad.reason.value}; the same record under K is accepted."
    )
    ev.observe(f"All {batch} records under the wrong key were rejected.")
    ev.observe(
        f"All {8 * cls.key_len} keys differing from K in a single bit rejected "
        f"every record: there is no partial-match behaviour."
    )
    ev.observe(
        f"A forged record matching the genuine session, stream, nonce prefix and "
        f"framing is still rejected with {forged_verdict.reason.value}."
    )

    ev.check(good.accepted, "correct key recovers the record")
    ev.check(bad.reason is RejectReason.AUTH_FAILED, "wrong key rejected as AUTH_FAILED")
    ev.check(bad.plaintext is None, "no plaintext released under the wrong key")
    ev.check(batch_accepted == 0, "no record accepted under the wrong key")
    ev.check(near_miss_accepted == 0, "no single-bit key variant accepted")
    ev.check(forged_verdict.reason is RejectReason.AUTH_FAILED, "attacker forgery rejected")
    ev.end()


# ---------------------------------------------------------------------------
# TR-7  Nonce Management Verification
# ---------------------------------------------------------------------------

def tr7_nonce_management(ev: Evidence, suite_name: str, *, count: int = 10_000) -> None:
    ev.begin(
        "TR-7",
        "Nonce Management Verification",
        suite_name,
        objective=(
            "Demonstrate that the nonce management approach satisfies the "
            "requirements of the AEAD configuration, with evidence that nonce "
            "reuse does not occur during normal operation."
        ),
        procedure=[
            f"Protect {count:,} application records under a single key.",
            "Reconstruct each nonce from the record's own header and collect it.",
            "Check uniqueness, monotonicity and structure directly.",
            "Simulate restarts under the same key, then exhaust the budget.",
        ],
        test_input=f"{count:,} application records under one key and session.",
        expected="All nonces distinct; sender fails closed at the record budget.",
    )

    ev.step("Construction under test")
    ev.field("nonce length", "96 bits (12 bytes)")
    ev.field("layout", "32-bit random session prefix || 64-bit BE counter")
    ev.field("reference", "NIST SP 800-38D s8.2.1 deterministic construction")

    channel = create_channel(suite_name)
    ev.field("session prefix", channel.sender.nonce_prefix.hex())
    ev.field("record budget", f"{channel.policy.record_limit:,} records")

    ev.step(f"Protecting and verifying {count:,} records under one key")
    started = time.perf_counter()
    nonces = []
    seqs = []
    accepted = 0
    for i in range(count):
        wire = channel.send(i.to_bytes(4, "big"))
        header = parse_record(wire).header
        nonces.append(derive_nonce(header.nonce_prefix, header.seq))
        seqs.append(header.seq)
        if channel.deliver(wire).accepted:
            accepted += 1
    elapsed = time.perf_counter() - started

    unique = len(set(nonces))
    prefixes = {n[:4] for n in nonces}
    monotonic = seqs == list(range(count))

    ev.field("records protected", f"{count:,}")
    ev.field("records accepted", f"{accepted:,}")
    ev.field("nonces collected", f"{len(nonces):,}")
    ev.field("distinct nonces", f"{unique:,}")
    ev.field("duplicate nonces", f"{len(nonces) - unique:,}")
    ev.field("distinct prefixes", len(prefixes))
    ev.field("seq strictly increasing", monotonic)
    ev.field("seq range", f"{seqs[0]} .. {seqs[-1]}")
    ev.field("elapsed", f"{elapsed:.3f} s")
    ev.field("first nonce", nonces[0].hex())
    ev.field("last nonce", nonces[-1].hex())

    ev.step("Restarting under the same key does not restart the nonce space")
    cls = suite_class(suite_name)
    shared_key = cls.generate_key()
    restart_prefixes = set()
    restart_first_nonces = set()
    for _ in range(200):
        s = Sender(cls(shared_key), new_session_id())
        h = parse_record(s.protect(b"first record of a session")).header
        restart_prefixes.add(h.nonce_prefix)
        restart_first_nonces.add(derive_nonce(h.nonce_prefix, h.seq))
    ev.field("simulated restarts", 200)
    ev.field("counter restarts at 0 each time", True)
    ev.field("distinct session prefixes", len(restart_prefixes))
    ev.field("distinct first nonces", len(restart_first_nonces))

    ev.step("Sender fails closed when the record budget is exhausted")
    limited = create_channel(suite_name, policy=SessionPolicy(record_limit=64))
    for _ in range(64):
        limited.send(b"record")
    seq_at_limit = limited.sender.next_seq
    exhausted_error = None
    try:
        limited.send(b"one record too many")
    except NonceExhaustedError as exc:
        exhausted_error = exc
    for _ in range(5):
        try:
            limited.send(b"retry")
        except NonceExhaustedError:
            pass
    ev.field("budget", 64)
    ev.field("records emitted", limited.sender.stats.records_protected)
    ev.field("error raised", type(exhausted_error).__name__ if exhausted_error else None)
    ev.field("message", str(exhausted_error))
    ev.field("counter after 5 retries", limited.sender.next_seq)
    ev.field("counter did not advance", limited.sender.next_seq == seq_at_limit)

    ev.step("Why a counter rather than random nonces")
    for q_label, q in (("10,000", 10_000), ("2^24 (budget)", 2 ** 24),
                       ("2^32 (NIST cap)", 2 ** 32), ("2^49", 2 ** 49)):
        p = random_nonce_collision_probability(q)
        ev.field(f"random-nonce collision p at {q_label}", f"{p:.3e}")
    ev.field("counter collision p (any q < 2^64)", "0")

    ev.observe(
        f"{count:,} records were protected under one key; all {unique:,} nonces "
        f"were distinct, with zero duplicates."
    )
    ev.observe(
        "Sequence numbers were strictly increasing with no gaps or repeats, so "
        "uniqueness is structural rather than probabilistic."
    )
    ev.observe(
        f"All {accepted:,} records verified at the receiver, confirming sender "
        f"and receiver derive the same nonce."
    )
    ev.observe(
        f"Across 200 simulated restarts under one key the counter restarted at 0 "
        f"each time, yet all {len(restart_first_nonces)} first-record nonces were "
        f"distinct, because the 32-bit session prefix is redrawn."
    )
    ev.observe(
        "At the record budget the sender raised NonceExhaustedError and emitted "
        "nothing further; the counter did not advance on retry."
    )

    ev.check(unique == count, f"all {count:,} nonces distinct")
    ev.check(monotonic, "sequence numbers strictly increasing with no gaps")
    ev.check(len(prefixes) == 1, "one session prefix throughout the session")
    ev.check(accepted == count, "every record verified at the receiver")
    ev.check(len(restart_prefixes) == 200, "each restart drew a fresh prefix")
    ev.check(len(restart_first_nonces) == 200, "no nonce repeated across restarts")
    ev.check(exhausted_error is not None, "budget exhaustion raised NonceExhaustedError")
    ev.check(limited.sender.stats.records_protected == 64, "no record emitted past the budget")
    ev.check(limited.sender.next_seq == seq_at_limit, "counter did not advance after exhaustion")
    ev.end()


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------

DEMOS = (
    tr1_positive_baseline,
    tr2_ciphertext_integrity,
    tr3_authentication_tag,
    tr4_associated_data,
    tr5_replay,
    tr6_wrong_key,
    tr7_nonce_management,
)


def run_for_suite(suite_name: str, *, echo: bool, records: int) -> Evidence:
    log_path = EVIDENCE_DIR / f"demo-{suite_name}.log"
    ev = Evidence(log_path, echo=echo)

    ev.banner(
        f" CS6530 Assignment 1 -- Secure Data Protection Subsystem\n"
        f" Testing Requirements TR-1 to TR-7\n"
        f" AEAD configuration: {suite_name}"
    )
    ev.write(f"  generated  : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    ev.write(f"  python     : {sys.version.split()[0]}")
    ev.write(f"  seed       : 0x{SEED:06x} (malicious actor is deterministic)")

    for demo in DEMOS:
        if demo is tr7_nonce_management:
            demo(ev, suite_name, count=records)
        else:
            demo(ev, suite_name)

    ev.summary_table()
    saved = ev.save()
    if saved:
        ev.write(f"\n  transcript written to {saved.relative_to(ROOT)}")
        if echo:
            print(f"\n  transcript written to {saved.relative_to(ROOT)}")
    return ev


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--suite", choices=SUITE_NAMES, action="append",
        help="AEAD configuration to demonstrate (repeatable; default: both)",
    )
    parser.add_argument(
        "--records", type=int, default=10_000,
        help="records to process in the TR-7 nonce volume test (default: 10000)",
    )
    parser.add_argument("--quiet", action="store_true", help="write logs without echoing")
    args = parser.parse_args(argv)

    suites = args.suite or list(SUITE_NAMES)
    all_passed = True
    summaries = []

    for suite_name in suites:
        ev = run_for_suite(suite_name, echo=not args.quiet, records=args.records)
        all_passed &= ev.all_passed
        summaries.append((suite_name, ev))

    print()
    print("=" * 78)
    print(" OVERALL RESULT")
    print("=" * 78)
    for suite_name, ev in summaries:
        passed = sum(1 for o in ev.outcomes if o.passed)
        print(f"  {suite_name:<22} {passed}/{len(ev.outcomes)} testing requirements PASS")
    print("=" * 78)

    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
