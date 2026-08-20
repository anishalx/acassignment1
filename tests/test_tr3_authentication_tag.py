"""TR-3 -- Authentication Tag Test.

Demonstrates that any modification to the authentication tag of a protected
application record is detected and the record is rejected, with no plaintext
released.

The 128-bit (16-byte) tag is the output of GHASH (AES-GCM) or Poly1305
(ChaCha20-Poly1305).  Both are keyed MACs with 2^-128 forgery probability per
attempt, so randomly guessing a valid tag succeeds with probability 2^-128 ≈
2.9 × 10^-39 — computationally infeasible.
"""

from __future__ import annotations

import pytest

from srp import HEADER_LEN, TAG_LEN, RejectReason


class TestSingleBitTagFlip:
    """A single-bit modification of the tag causes AUTH_FAILED."""

    def test_flip_first_tag_bit(self, channel, actor):
        wire = channel.send(b"tag integrity test")
        tampered = actor.flip_tag_bit(wire, offset=0, bit=0)
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED
        assert verdict.plaintext is None

    def test_flip_last_tag_bit(self, channel, actor):
        wire = channel.send(b"tag integrity test 2")
        tampered = actor.flip_tag_bit(wire, offset=TAG_LEN - 1, bit=7)
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED
        assert verdict.plaintext is None


class TestExhaustiveTagBitSweep:
    """Every single-bit edit of all 128 tag bits is rejected.

    This makes the claim exhaustive: not one of the 128 bit positions produces
    a tag that verifies.
    """

    def test_sweep_all_128_bits(self, channel, actor):
        wire = channel.send(b"sweep target payload")
        for byte_offset in range(TAG_LEN):
            for bit in range(8):
                tampered = actor.flip_tag_bit(
                    wire, offset=byte_offset, bit=bit
                )
                verdict = channel.deliver(tampered)
                assert verdict.rejected, (
                    f"tag byte {byte_offset} bit {bit} unexpectedly accepted"
                )
                assert verdict.reason is RejectReason.AUTH_FAILED
                assert verdict.plaintext is None


class TestZeroTag:
    """An all-zero tag is not special-cased anywhere."""

    def test_zero_tag_rejected(self, channel, actor):
        wire = channel.send(b"zero tag test")
        tampered = actor.zero_tag(wire)
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED
        assert verdict.plaintext is None


class TestRandomTagGuessing:
    """Random tag guessing has a per-attempt success probability of 2^-128.

    For a 128-bit tag, the probability of a random tag verifying is:
        P(success) = 1 / 2^128 ≈ 2.94 × 10^-39

    Even 1000 attempts are astronomically unlikely to succeed.
    """

    def test_random_tags_all_rejected(self, channel, actor):
        wire = channel.send(b"random tag target")
        for _ in range(100):
            tampered = actor.replace_tag(wire)  # random tag each time
            verdict = channel.deliver(tampered)
            assert verdict.rejected
            assert verdict.reason is RejectReason.AUTH_FAILED
            assert verdict.plaintext is None


class TestTagTruncation:
    """A truncated tag creates a framing mismatch.

    Short tags are a real historical weakness in GCM.  In this subsystem,
    truncated frames are caught by ``parse_record`` as MALFORMED because the
    body length no longer matches ``payload_len + TAG_LEN``.  This happens
    *before* the AEAD runs.
    """

    def test_truncate_one_byte(self, channel, actor):
        wire = channel.send(b"truncation test")
        tampered = actor.truncate_tag(wire, count=1)
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.MALFORMED
        assert verdict.plaintext is None

    def test_truncate_half_tag(self, channel, actor):
        wire = channel.send(b"truncation test half")
        tampered = actor.truncate_tag(wire, count=TAG_LEN // 2)
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.MALFORMED
        assert verdict.plaintext is None

    def test_truncate_entire_tag(self, channel, actor):
        wire = channel.send(b"truncation test full")
        tampered = actor.truncate_tag(wire, count=TAG_LEN)
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.MALFORMED
        assert verdict.plaintext is None


class TestTagFromDifferentRecord:
    """A valid tag from a different record does not authenticate this one.

    The tag is computed over (nonce, ciphertext, AAD), all of which differ
    between records.  The nonce binds the tag to a specific sequence number,
    and the AAD binds it to a specific header, so no tag can be transplanted.
    """

    def test_cross_record_tag(self, channel, actor):
        wire_a = channel.send(b"record alpha")
        wire_b = channel.send(b"record beta")
        # Put wire_b's tag on wire_a's header+ciphertext.
        tag_b = wire_b[-TAG_LEN:]
        tampered = wire_a[:-TAG_LEN] + tag_b
        verdict = channel.deliver(tampered)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED
        assert verdict.plaintext is None


class TestRecoveryAfterTagAttacks:
    """A genuine record is accepted after tag-modification attacks."""

    def test_genuine_after_attacks(self, channel, actor):
        # Several attacks first.
        wire = channel.send(b"attack target")
        channel.deliver(actor.zero_tag(wire))
        channel.deliver(actor.replace_tag(wire))
        channel.deliver(actor.flip_tag_bit(wire, offset=0, bit=0))

        # Genuine record still works.
        genuine = channel.send(b"post-attack genuine")
        verdict = channel.deliver(genuine)
        assert verdict.accepted
        assert verdict.plaintext == b"post-attack genuine"
