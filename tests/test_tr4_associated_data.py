"""TR-4 -- Associated Data (AAD) Test.

Demonstrates that modification of any authenticated header field is detected
and the record is rejected.

The AAD in this subsystem is the entire 40-byte header, serialised verbatim
by ``RecordHeader.aad()``.  Every field it covers is a field the attacker
cannot silently rewrite.  The header is authenticated but **not** encrypted —
it must be readable on the wire because the receiver needs ``payload_len`` to
frame the record, ``suite_id`` to know which primitive to use, ``seq`` to
reconstruct the nonce and run the replay check — all before it holds a
verified plaintext.

Header field layout (40 bytes)::

    Byte 0:      version        (1B)
    Byte 1:      suite_id       (1B)
    Byte 2:      record_type    (1B)
    Byte 3:      flags          (1B)
    Bytes 4-19:  session_id     (16B)
    Bytes 20-23: stream_id      (4B)
    Bytes 24-27: nonce_prefix   (4B)
    Bytes 28-35: seq            (8B)
    Bytes 36-39: payload_len    (4B)

Not all modifications fail the same way:
- ``version``: MALFORMED (parse rejects unknown versions before AEAD)
- ``suite_id``: SUITE_MISMATCH (configuration check before AEAD)
- ``session_id``: SESSION_MISMATCH (if receiver is pinned, before AEAD)
- ``payload_len``: MALFORMED (framing mismatch before AEAD)
- ``record_type``, ``flags``, ``stream_id``, ``nonce_prefix``, ``seq``:
  AUTH_FAILED (caught by the AEAD tag verification)
"""

from __future__ import annotations

import os
import struct

import pytest

from srp import (
    HEADER_LEN,
    TAG_LEN,
    RecordFlags,
    RecordHeader,
    RecordType,
    RejectReason,
    SessionPolicy,
    create_channel,
)


# ---- Per-field semantic attacks ------------------------------------------
# Each field is a different semantic attack.  The report should say what the
# attacker would gain if the modification succeeded.


class TestRecordTypeModification:
    """Changing record_type: an attacker could make a DATA record look like
    CLOSE, prematurely terminating a stream."""

    def test_relabel_data_as_close(self, channel, actor):
        wire = channel.send(b"data payload")
        tampered = actor.relabel_record_type(wire, RecordType.CLOSE)
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED
        assert verdict.plaintext is None

    def test_relabel_data_as_control(self, channel, actor):
        wire = channel.send(b"data payload")
        tampered = actor.relabel_record_type(wire, RecordType.CONTROL)
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED
        assert verdict.plaintext is None


class TestFlagsModification:
    """Forging or stripping flags: an attacker could inject a false
    END_OF_STREAM or strip a real one, disrupting stream lifecycle."""

    def test_forge_end_of_stream(self, channel, actor):
        wire = channel.send(b"not the last record")
        tampered = actor.set_flags(wire, RecordFlags.END_OF_STREAM)
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED
        assert verdict.plaintext is None

    def test_strip_end_of_stream(self, channel, actor):
        wire = channel.send(
            b"last record",
            record_type=RecordType.DATA,
            flags=RecordFlags.END_OF_STREAM,
        )
        tampered = actor.set_flags(wire, RecordFlags.NONE)
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED
        assert verdict.plaintext is None


class TestStreamIdModification:
    """Re-routing a record to a different stream: an attacker could inject
    data into a stream the sender never intended."""

    def test_redirect_stream(self, channel, actor):
        wire = channel.send(b"stream 1 data")
        tampered = actor.redirect_stream(wire, stream_id=99)
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED
        assert verdict.plaintext is None


class TestSessionIdModification:
    """Moving a record into a different session: an attacker could splice
    records across key epochs.  Caught by SESSION_MISMATCH when the receiver
    is pinned, and by AUTH_FAILED regardless (since session_id is in the AAD).
    """

    def test_pinned_session_mismatch(self, channel, actor):
        wire = channel.send(b"session test")
        fake_session = os.urandom(16)
        tampered = actor.reassign_session(wire, fake_session)
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        # Pinned receiver catches this before the AEAD.
        assert verdict.reason is RejectReason.SESSION_MISMATCH
        assert verdict.plaintext is None

    def test_unpinned_session_auth_failed(self, suite_name, actor):
        """With an unpinned receiver, session_id modification is caught by
        the AEAD (since session_id is in the AAD), not by a session check."""
        policy = SessionPolicy(pin_session=False)
        ch = create_channel(suite_name, policy=policy)
        wire = ch.send(b"unpinned session test")
        fake_session = os.urandom(16)
        tampered = actor.reassign_session(wire, fake_session)
        verdict = ch.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED
        assert verdict.plaintext is None


class TestSuiteIdModification:
    """Claiming the record was protected by the other AEAD configuration.
    Caught by SUITE_MISMATCH before the AEAD runs."""

    def test_switch_suite_label(self, channel, actor):
        wire = channel.send(b"suite test")
        # Flip to the other suite (0x01 ↔ 0x02).
        original_suite_id = channel.sender.suite.suite_id
        other_suite_id = 0x02 if original_suite_id == 0x01 else 0x01
        tampered = actor.switch_suite_label(wire, other_suite_id)
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.SUITE_MISMATCH
        assert verdict.plaintext is None


class TestPayloadLenModification:
    """Lying about payload_len without changing the frame creates a framing
    mismatch.  Caught as MALFORMED by parse_record before the AEAD runs."""

    def test_declare_wrong_length_larger(self, channel, actor):
        wire = channel.send(b"payload length test")
        tampered = actor.declare_wrong_length(wire, payload_len=9999)
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.MALFORMED
        assert verdict.plaintext is None

    def test_declare_wrong_length_smaller(self, channel, actor):
        wire = channel.send(b"payload length test")
        tampered = actor.declare_wrong_length(wire, payload_len=1)
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.MALFORMED
        assert verdict.plaintext is None


class TestNoncePrefixModification:
    """Changing the nonce_prefix alters the nonce the receiver reconstructs,
    so the AEAD decrypts with the wrong nonce and the tag fails.  This is
    a second effect beyond AAD modification: the nonce_prefix is both
    authenticated (in the AAD) and used to derive the nonce."""

    def test_change_nonce_prefix(self, channel, actor):
        wire = channel.send(b"nonce prefix test")
        tampered = actor.tamper_header(wire, nonce_prefix=b"\xff\xff\xff\xff")
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED
        assert verdict.plaintext is None


class TestSeqModification:
    """Changing seq alters both the AAD and the reconstructed nonce.
    Caught by AUTH_FAILED (the AEAD tag no longer verifies)."""

    def test_change_seq(self, channel, actor):
        wire = channel.send(b"seq test")
        tampered = actor.renumber(wire, seq=99999)
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED
        assert verdict.plaintext is None


# ---- Full header bit sweep ----------------------------------------------


class TestHeaderBitSweep:
    """Sweep every bit of the 40-byte header.

    This makes the claim cover the *whole* AAD, not just the fields we
    thought to name.  Different bits trigger different rejection reasons
    (MALFORMED, SUITE_MISMATCH, SESSION_MISMATCH, AUTH_FAILED) depending
    on which field they fall in.
    """

    def test_every_header_bit_rejected(self, channel, actor):
        wire = channel.send(b"header sweep payload")
        for byte_offset in range(HEADER_LEN):
            for bit in range(8):
                tampered = actor.flip_header_bit(
                    wire, offset=byte_offset, bit=bit
                )
                verdict = channel.deliver(tampered)
                assert verdict.rejected, (
                    f"header byte {byte_offset} bit {bit} unexpectedly accepted"
                )
                assert verdict.plaintext is None


# ---- Round-trip property -------------------------------------------------


class TestHeaderRoundTrip:
    """Parsing a header and re-serialising it must be the identity.

    If it were not, an attacker could find two encodings of one header,
    and the AAD would stop being canonical.
    """

    def test_parse_reserialise_identity(self, channel):
        wire = channel.send(b"round trip test")
        original_header_bytes = wire[:HEADER_LEN]
        header = RecordHeader.from_bytes(original_header_bytes)
        reserialised = header.to_bytes()
        assert reserialised == original_header_bytes

    def test_arbitrary_bytes_round_trip(self):
        """Even with unusual field values, parse → serialise is an identity."""
        # Construct a header with non-standard but valid values.
        header = RecordHeader(
            session_id=b"\xaa" * 16,
            stream_id=0xDEAD,
            nonce_prefix=b"\xbb" * 4,
            seq=0x1234567890ABCDEF,
            payload_len=42,
            record_type=0xFF,  # unknown type — preserved as int
            flags=0x03,
            suite_id=0x01,
        )
        raw = header.to_bytes()
        parsed = RecordHeader.from_bytes(raw)
        assert parsed.to_bytes() == raw


# ---- AAD is authenticated but not encrypted ------------------------------


class TestAADReadableButAuthenticated:
    """The header is readable on the wire (not encrypted) but authenticated.

    Readable: the receiver must read payload_len, suite_id, seq, etc. before
    decryption to frame and route the record.
    Authenticated: any modification is caught by the AEAD tag.
    """

    def test_header_readable_in_cleartext(self, channel):
        payload = b"cleartext header test"
        wire = channel.send(payload)
        # The header fields are readable from the wire without decryption.
        header = RecordHeader.from_bytes(wire[:HEADER_LEN])
        assert header.payload_len == len(payload)
        assert header.stream_id == channel.sender.stream_id
        assert header.session_id == channel.session_id
        assert header.suite_id == channel.sender.suite.suite_id

    def test_header_authenticated(self, channel, actor):
        wire = channel.send(b"authenticated header test")
        # Modify a field — the tag catches it.
        tampered = actor.redirect_stream(wire, stream_id=999)
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED
