"""TR-2 -- Ciphertext Integrity Test.

Demonstrates that any modification to the ciphertext body of a protected
application record is detected by the receiver and the record is rejected.

Every test uses a **fresh** record that has not been delivered to the receiver,
so that rejection is provably caused by authentication failure and not by the
replay check.  This is the more realistic attacker model: an on-path adversary
who can rewrite a record can equally well suppress the original.
"""

from __future__ import annotations

import pytest

from srp import HEADER_LEN, TAG_LEN, RejectReason


class TestSingleBitFlip:
    """A single-bit modification in the ciphertext is detected."""

    def test_flip_first_byte(self, channel, actor):
        wire = channel.send(b"telemetry frame 0001")
        tampered = actor.flip_ciphertext_bit(wire, offset=0, bit=0)
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED
        assert verdict.plaintext is None

    def test_flip_last_byte(self, channel, actor):
        payload = b"telemetry frame 0002"
        wire = channel.send(payload)
        ct_len = len(wire) - HEADER_LEN - TAG_LEN
        tampered = actor.flip_ciphertext_bit(wire, offset=ct_len - 1, bit=7)
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED
        assert verdict.plaintext is None

    def test_flip_middle_byte(self, channel, actor):
        payload = b"telemetry frame 0003"
        wire = channel.send(payload)
        ct_len = len(wire) - HEADER_LEN - TAG_LEN
        tampered = actor.flip_ciphertext_bit(wire, offset=ct_len // 2, bit=4)
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED
        assert verdict.plaintext is None


class TestExhaustiveBitSweep:
    """Every single-bit edit of a small ciphertext is rejected.

    This turns "we tried one and it failed" into "no single-bit edit is
    accepted", which is a much stronger claim for the report.
    """

    def test_sweep_all_bits(self, channel, actor):
        payload = b"tiny"
        wire = channel.send(payload)
        ct_len = len(wire) - HEADER_LEN - TAG_LEN
        assert ct_len == len(payload)  # ciphertext = same length as plaintext

        for byte_offset in range(ct_len):
            for bit in range(8):
                tampered = actor.flip_ciphertext_bit(
                    wire, offset=byte_offset, bit=bit
                )
                verdict = channel.deliver(tampered)
                assert verdict.rejected, (
                    f"byte {byte_offset} bit {bit} was unexpectedly accepted"
                )
                assert verdict.reason is RejectReason.AUTH_FAILED
                assert verdict.plaintext is None


class TestLargeRecordPositions:
    """Modifications at several positions of a large record are all rejected."""

    def test_multiple_positions(self, channel, actor):
        payload = bytes(range(256)) * 4  # 1024 bytes
        wire = channel.send(payload)
        ct_len = len(wire) - HEADER_LEN - TAG_LEN

        positions = [0, ct_len // 4, ct_len // 2, 3 * ct_len // 4, ct_len - 1]
        for offset in positions:
            tampered = actor.flip_ciphertext_bit(wire, offset=offset, bit=3)
            verdict = channel.deliver(tampered)
            assert verdict.rejected, f"offset {offset} accepted"
            assert verdict.reason is RejectReason.AUTH_FAILED
            assert verdict.plaintext is None


class TestCiphertextTruncation:
    """Removing ciphertext bytes creates a framing mismatch (MALFORMED)."""

    def test_truncate_one_byte(self, channel, actor):
        wire = channel.send(b"telemetry frame 0004")
        tampered = actor.truncate_ciphertext(wire, count=1)
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.MALFORMED
        assert verdict.plaintext is None

    def test_truncate_half(self, channel, actor):
        payload = b"A" * 100
        wire = channel.send(payload)
        tampered = actor.truncate_ciphertext(wire, count=50)
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.MALFORMED
        assert verdict.plaintext is None


class TestCiphertextExtension:
    """Adding bytes to the ciphertext creates a framing mismatch."""

    def test_append_byte_before_tag(self, channel, actor):
        wire = channel.send(b"telemetry frame")
        # Insert a byte between ciphertext and tag.
        tag = wire[-TAG_LEN:]
        extended = wire[:-TAG_LEN] + b"\x42" + tag
        verdict = channel.deliver(extended)
        assert verdict.rejected
        assert verdict.plaintext is None


class TestBodySwap:
    """Swapping ciphertext+tag between two records is rejected.

    The splice combines one record's header (and therefore its AAD and nonce)
    with another record's ciphertext+tag.  The AEAD catches the mismatch.
    """

    def test_splice_rejects(self, channel, actor):
        wire_a = channel.send(b"record A")
        wire_b = channel.send(b"record B")
        spliced = actor.splice(wire_a, wire_b)
        verdict = channel.deliver(spliced)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED
        assert verdict.plaintext is None

    def test_swap_bodies_both_rejected(self, channel, actor):
        # Same-length payloads so the swap doesn't cause a framing mismatch.
        wire_a = channel.send(b"aaaa")
        wire_b = channel.send(b"bbbb")
        swapped_a, swapped_b = actor.swap_bodies(wire_a, wire_b)
        v_a = channel.deliver(swapped_a)
        v_b = channel.deliver(swapped_b)
        assert v_a.rejected and v_a.reason is RejectReason.AUTH_FAILED
        assert v_b.rejected and v_b.reason is RejectReason.AUTH_FAILED
        assert v_a.plaintext is None and v_b.plaintext is None


class TestRandomGarbage:
    """Random noise is rejected — the trivial baseline case."""

    def test_random_bytes(self, channel, actor):
        garbage = actor.random_bytes(128)
        verdict = channel.deliver(garbage)
        assert verdict.rejected
        assert verdict.plaintext is None

    def test_short_garbage(self, channel, actor):
        verdict = channel.deliver(b"\x01" * 10)
        assert verdict.rejected
        assert verdict.reason is RejectReason.MALFORMED
        assert verdict.plaintext is None


class TestRecoveryAfterAttacks:
    """The receiver remains functional after processing forged records."""

    def test_genuine_after_tampered(self, channel, actor):
        wire = channel.send(b"first record")
        tampered = actor.flip_ciphertext_bit(wire, offset=0, bit=0)
        v1 = channel.deliver(tampered)
        assert v1.rejected

        genuine = channel.send(b"genuine after attack")
        v2 = channel.deliver(genuine)
        assert v2.accepted
        assert v2.plaintext == b"genuine after attack"

    def test_multiple_attacks_then_genuine(self, channel, actor):
        # Fire several different attacks.
        for i in range(5):
            wire = channel.send(f"record {i}".encode())
            tampered = actor.flip_ciphertext_bit(wire, offset=0, bit=i % 8)
            v = channel.deliver(tampered)
            assert v.rejected

        # Genuine record still works.
        genuine = channel.send(b"still working")
        v = channel.deliver(genuine)
        assert v.accepted
        assert v.plaintext == b"still working"
