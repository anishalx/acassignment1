"""TR-4 -- Associated Data (AAD) Test.

Objective
    Demonstrate that modification of the Associated Data results in
    authentication verification failure and rejection of the protected
    application record, under both AEAD configurations.

The AAD here is the entire 40-byte record header (see :mod:`srp.header`).  These
tests attack it from two directions:

1. **Semantically**, by rewriting individual fields to something an attacker
   would actually want -- relabel a DATA record as CLOSE, forge END_OF_STREAM,
   redirect a record onto another stream.  These are the attacks that would
   succeed against a subsystem that encrypted the payload but left the metadata
   unauthenticated, which is the mistake this requirement exists to prevent.

2. **Exhaustively**, by flipping every one of the 320 header bits and confirming
   that not one of them yields an accepted record.
"""

from __future__ import annotations

import pytest

from srp import (
    HEADER_LEN,
    Receiver,
    RecordFlags,
    RecordType,
    RejectReason,
    new_session_id,
    parse_record,
    suite_class,
)

# Byte ranges within the 40-byte header, matching the layout in srp/header.py.
FIELD_RANGES = {
    "version": range(0, 1),
    "suite_id": range(1, 2),
    "record_type": range(2, 3),
    "flags": range(3, 4),
    "session_id": range(4, 20),
    "stream_id": range(20, 24),
    "nonce_prefix": range(24, 28),
    "seq": range(28, 36),
    "payload_len": range(36, 40),
}


def test_relabelling_the_record_type_is_rejected(channel, actor):
    """A DATA record cannot be re-presented as a CLOSE record."""
    wire = channel.send(b"ordinary data record")

    tampered = actor.relabel_record_type(wire, RecordType.CLOSE)

    assert parse_record(tampered).header.record_type is RecordType.CLOSE
    verdict = channel.deliver(tampered)
    assert verdict.rejected
    assert verdict.reason is RejectReason.AUTH_FAILED
    assert verdict.plaintext is None


def test_forging_end_of_stream_is_rejected(channel, actor):
    """Flags are authenticated: END_OF_STREAM can be neither forged nor stripped."""
    wire = channel.send(b"mid-stream record")
    verdict = channel.deliver(actor.set_flags(wire, RecordFlags.END_OF_STREAM))
    assert verdict.rejected
    assert verdict.reason is RejectReason.AUTH_FAILED

    # ... and stripping a genuine flag fails the same way.
    wire = channel.send(b"final record", flags=RecordFlags.END_OF_STREAM)
    verdict = channel.deliver(actor.set_flags(wire, RecordFlags.NONE))
    assert verdict.rejected
    assert verdict.reason is RejectReason.AUTH_FAILED


def test_redirecting_a_record_to_another_stream_is_rejected(channel, actor):
    """A record valid on stream 1 cannot be re-injected onto stream 7."""
    wire = channel.send(b"stream 1 record")

    verdict = channel.deliver(actor.redirect_stream(wire, stream_id=7))

    assert verdict.rejected
    assert verdict.reason is RejectReason.AUTH_FAILED


def test_reassigning_the_session_is_rejected(channel, actor):
    """Cross-session splicing fails, caught by the session pin."""
    wire = channel.send(b"session-bound record")

    verdict = channel.deliver(actor.reassign_session(wire, new_session_id()))

    assert verdict.rejected
    assert verdict.reason is RejectReason.SESSION_MISMATCH


def test_reassigning_the_session_fails_authentication_when_unpinned(suite_name):
    """With no session pin, the same attack is caught by the AAD instead.

    This separates the two defences: the pin is an early filter, but the
    cryptographic binding is what actually makes session_id unforgeable.
    """
    from srp import Sender

    cls = suite_class(suite_name)
    key = cls.generate_key()
    session_id = new_session_id()

    sender = Sender(cls(key), session_id)
    receiver = Receiver(cls(key), expected_session_id=None)  # accepts any session

    from srp import MaliciousActor

    actor = MaliciousActor()
    wire = sender.protect(b"session-bound record")
    tampered = actor.reassign_session(wire, new_session_id())

    verdict = receiver.receive(tampered)
    assert verdict.rejected
    assert verdict.reason is RejectReason.AUTH_FAILED


def test_switching_the_suite_label_is_rejected(channel, actor):
    """Cross-suite confusion: claim an AES-GCM record is ChaCha20, or vice versa."""
    wire = channel.send(b"suite-bound record")
    other_suite_id = 0x02 if channel.sender.suite.suite_id == 0x01 else 0x01

    verdict = channel.deliver(actor.switch_suite_label(wire, other_suite_id))

    assert verdict.rejected
    assert verdict.reason is RejectReason.SUITE_MISMATCH


def test_lying_about_the_payload_length_is_rejected(channel, actor):
    """A payload_len that does not describe the frame is caught by framing."""
    wire = channel.send(b"a record of known length")
    true_len = parse_record(wire).header.payload_len

    for forged_len in (0, true_len - 1, true_len + 1, 4096):
        verdict = channel.deliver(actor.declare_wrong_length(wire, forged_len))
        assert verdict.rejected
        assert verdict.reason is RejectReason.MALFORMED


def test_altering_the_nonce_prefix_is_rejected(channel, actor):
    """The nonce material is authenticated, so it cannot be steered."""
    wire = channel.send(b"nonce-bound record")

    verdict = channel.deliver(actor.tamper_header(wire, nonce_prefix=b"\xde\xad\xbe\xef"))

    assert verdict.rejected
    assert verdict.reason is RejectReason.AUTH_FAILED


def test_every_single_bit_flip_in_the_header_is_rejected(channel, actor):
    """Exhaustive sweep over all 320 AAD bits.

    Every flip is rejected.  Which check catches it depends on the field: bits
    in ``version`` and ``payload_len`` break framing, ``suite_id`` and
    ``session_id`` hit the configuration and session bindings, and everything
    else reaches the AEAD and fails tag verification.  The test asserts both the
    universal property (nothing is accepted) and the per-field attribution, so a
    check silently moving between layers would be caught.
    """
    payload = b"header integrity probe"
    by_field: dict[str, set] = {name: set() for name in FIELD_RANGES}

    for offset in range(HEADER_LEN):
        field = next(n for n, r in FIELD_RANGES.items() if offset in r)
        for bit in range(8):
            wire = channel.send(payload)
            tampered = actor.flip_header_bit(wire, offset=offset, bit=bit)
            assert tampered[HEADER_LEN:] == wire[HEADER_LEN:]  # body untouched

            verdict = channel.deliver(tampered)

            assert verdict.rejected, f"header byte {offset} bit {bit} was accepted"
            assert verdict.plaintext is None
            by_field[field].add(verdict.reason)

    assert channel.receiver.stats.accepted == 0

    assert by_field["version"] == {RejectReason.MALFORMED}
    assert by_field["suite_id"] == {RejectReason.SUITE_MISMATCH}
    assert by_field["session_id"] == {RejectReason.SESSION_MISMATCH}
    assert by_field["payload_len"] == {RejectReason.MALFORMED}
    for field in ("record_type", "flags", "stream_id", "nonce_prefix", "seq"):
        assert by_field[field] == {RejectReason.AUTH_FAILED}, field


def test_header_parse_reserialise_is_the_identity(channel, actor):
    """No encoder freedom: one header maps to exactly one byte string.

    The receiver recomputes the AAD from the parsed header, so if any header
    byte failed to survive parse-then-reserialise, the bytes it authenticates
    against would differ from the bytes on the wire.  Checked across every
    single-bit perturbation, including values that are not valid enum members.
    """
    wire = channel.send(b"round trip probe")

    for offset in range(HEADER_LEN):
        for bit in range(8):
            tampered = actor.flip_header_bit(wire, offset=offset, bit=bit)
            raw_header = tampered[:HEADER_LEN]
            try:
                parsed = parse_record(tampered).header
            except Exception:
                continue  # unparseable frames have no round trip to check
            assert parsed.to_bytes() == raw_header, f"byte {offset} bit {bit}"


def test_aad_is_visible_but_authenticated(channel):
    """AAD is authenticated, not encrypted -- and that is the intended property.

    The header must be readable by the receiver before it holds a verified
    plaintext, so it is deliberately in the clear.  Confidentiality for it was
    never claimed; integrity is, and the tests above establish that.
    """
    wire = channel.send(b"payload")
    header = parse_record(wire).header

    assert wire[:HEADER_LEN] == header.to_bytes() == header.aad()
    assert header.seq == 0  # plainly readable, as intended
