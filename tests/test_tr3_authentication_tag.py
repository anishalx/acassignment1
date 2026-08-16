"""TR-3 -- Authentication Tag Test.

Objective
    Demonstrate that modification of the authentication tag results in
    authentication verification failure and rejection of the protected
    application record, under both AEAD configurations.

The tag is the only part of the record whose sole purpose is verification, so
these tests attack it directly: flip every bit of it, zero it, randomise it, and
truncate it.  Between them, the exhaustive sweep and the random-tag trials cover
both "the attacker perturbs a real tag" and "the attacker guesses a tag".
"""

from __future__ import annotations

import pytest

from srp import HEADER_LEN, TAG_LEN, RejectReason, parse_record


def test_single_bit_flip_in_the_tag_is_rejected(channel, actor):
    """The canonical TR-3 case."""
    wire = channel.send(b"application record with an intact body")

    tampered = actor.flip_tag_bit(wire, offset=0, bit=0)

    verdict = channel.deliver(tampered)
    assert verdict.rejected
    assert verdict.reason is RejectReason.AUTH_FAILED
    assert verdict.plaintext is None


def test_every_single_bit_flip_in_the_tag_is_rejected(channel, actor):
    """Exhaustive sweep over all 128 tag bits.

    Note that the header and ciphertext are untouched here, so the record is
    valid in every respect except the tag: this isolates tag verification from
    every other check in the receiver.
    """
    payload = b"body held constant"
    reasons = set()

    for offset in range(TAG_LEN):
        for bit in range(8):
            wire = channel.send(payload)
            tampered = actor.flip_tag_bit(wire, offset=offset, bit=bit)

            # Only the tag changed.
            assert tampered[:-TAG_LEN] == wire[:-TAG_LEN]
            assert tampered[-TAG_LEN:] != wire[-TAG_LEN:]

            verdict = channel.deliver(tampered)

            assert verdict.rejected, f"tag byte {offset} bit {bit} was accepted"
            assert verdict.plaintext is None
            reasons.add(verdict.reason)

    assert reasons == {RejectReason.AUTH_FAILED}
    assert channel.receiver.stats.rejected["AUTH_FAILED"] == 8 * TAG_LEN
    assert channel.receiver.stats.accepted == 0


def test_all_zero_tag_is_rejected(channel, actor):
    """A common forgery attempt: submit an obviously fixed tag."""
    wire = channel.send(b"zero tag attempt")

    verdict = channel.deliver(actor.zero_tag(wire))

    assert verdict.rejected
    assert verdict.reason is RejectReason.AUTH_FAILED


def test_random_tag_guessing_always_fails(channel, actor):
    """256 independent forgery attempts, all rejected.

    Each attempt succeeds with probability 2**-128, so observing 256 failures is
    the expected outcome; the test documents that no structural shortcut exists.
    """
    attempts = 256

    for _ in range(attempts):
        wire = channel.send(b"forge me")
        verdict = channel.deliver(actor.replace_tag(wire))
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED

    assert channel.receiver.stats.accepted == 0
    assert channel.receiver.stats.rejected["AUTH_FAILED"] == attempts


def test_truncated_tag_is_rejected(channel, actor):
    """Short tags are refused by framing validation, not silently accepted.

    GCM permits tags shorter than 128 bits, and a short tag materially weakens
    forgery resistance.  This subsystem fixes the tag length, so a truncated
    frame never reaches the AEAD.
    """
    for dropped in (1, 4, 8, TAG_LEN):
        wire = channel.send(b"truncation test")
        verdict = channel.deliver(actor.truncate_tag(wire, count=dropped))

        assert verdict.rejected
        assert verdict.reason is RejectReason.MALFORMED
        assert verdict.plaintext is None


def test_tag_from_another_record_is_rejected(channel):
    """A genuine tag is only genuine for the record it was computed over."""
    wire_a = channel.send(b"record A")
    wire_b = channel.send(b"record B")

    frankenstein = wire_a[:-TAG_LEN] + wire_b[-TAG_LEN:]

    verdict = channel.deliver(frankenstein)
    assert verdict.rejected
    assert verdict.reason is RejectReason.AUTH_FAILED


def test_tag_is_not_derivable_from_visible_record_material(channel):
    """Sanity check that the tag is not, say, a checksum of the ciphertext."""
    payload = b"\x00" * 64
    wire = channel.send(payload)
    record = parse_record(wire)

    assert record.tag != bytes(TAG_LEN)
    assert record.tag not in record.ciphertext
    assert record.tag != record.ciphertext[:TAG_LEN]
    # Two records with identical plaintext get different tags, because the
    # nonce and hence the keystream and the tag key differ per record.
    other = parse_record(channel.send(payload))
    assert other.tag != record.tag
    assert other.ciphertext != record.ciphertext
