"""TR-2 -- Ciphertext Integrity Test.

Objective
    Demonstrate that modification of the protected application record by the
    malicious actor results in authentication verification failure and
    rejection of the modified record by the receiver, under both AEAD
    configurations.

Attack model
    The actor is on-path: it observes a genuine record in flight, modifies it,
    and delivers only the modified copy.  The original is suppressed, so the
    record's sequence number is still fresh when the receiver checks the tag --
    this isolates *authentication* failure from replay detection.

Why single-bit modifications
    Both configurations are stream-cipher based, so ciphertext bit ``i`` and
    plaintext bit ``i`` are related by a XOR with keystream.  Flipping one
    ciphertext bit flips exactly one plaintext bit and nothing else.  Without
    authentication that is a precise, silent edit primitive over data the
    attacker cannot even read -- e.g. flipping a sign bit or a status flag.
    Showing that *every* such flip is caught is the substantive claim.
"""

from __future__ import annotations

import pytest

from srp import RejectReason, TAG_LEN, HEADER_LEN


def test_single_bit_flip_in_ciphertext_is_rejected(channel, actor):
    """The canonical TR-2 case."""
    payload = b"application record that must not be modifiable"

    wire = channel.send(payload)
    tampered = actor.flip_ciphertext_bit(wire, offset=0, bit=0)

    verdict = channel.deliver(tampered)

    assert verdict.rejected
    assert verdict.reason is RejectReason.AUTH_FAILED
    assert verdict.plaintext is None  # FR-7 / SR-6: nothing is released


def test_every_single_bit_flip_in_the_ciphertext_is_rejected(channel, actor):
    """Exhaustive sweep: all 8 x N single-bit modifications fail, none slip through.

    A fresh record is sent for each variant so that every tampered record
    carries an unused sequence number and therefore reaches the AEAD check.
    """
    payload = b"8 octets"  # 64 distinct single-bit modifications
    reasons = set()

    for offset in range(len(payload)):
        for bit in range(8):
            wire = channel.send(payload)
            tampered = actor.flip_ciphertext_bit(wire, offset=offset, bit=bit)
            assert tampered != wire

            verdict = channel.deliver(tampered)

            assert verdict.rejected, f"offset {offset} bit {bit} was accepted"
            assert verdict.plaintext is None
            reasons.add(verdict.reason)

    assert reasons == {RejectReason.AUTH_FAILED}
    assert channel.receiver.stats.accepted == 0
    assert channel.receiver.stats.rejected["AUTH_FAILED"] == 8 * len(payload)


def test_modification_anywhere_in_a_large_record_is_rejected(channel, actor):
    """Position within the record does not matter: first byte, middle or last."""
    payload = bytes(4096)

    for offset in (0, 1, 2047, 4094, 4095):
        wire = channel.send(payload)
        verdict = channel.deliver(actor.flip_ciphertext_bit(wire, offset=offset, bit=3))

        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED


def test_ciphertext_truncation_is_rejected(channel, actor):
    """Cutting bytes out of the body is detected by framing validation.

    ``payload_len`` in the authenticated header no longer describes the frame,
    so the record is rejected before the AEAD is invoked -- defence in depth
    over the tag, which would also have caught it.
    """
    wire = channel.send(b"a record of a known and authenticated length")

    verdict = channel.deliver(actor.truncate_ciphertext(wire, count=4))

    assert verdict.rejected
    assert verdict.reason is RejectReason.MALFORMED
    assert verdict.plaintext is None


def test_ciphertext_extension_is_rejected(channel):
    """Appending bytes is equally detected."""
    wire = channel.send(b"append test")

    verdict = channel.deliver(wire + b"\x00\x00\x00\x00")

    assert verdict.rejected
    assert verdict.reason is RejectReason.MALFORMED


def test_swapping_bodies_between_two_records_is_rejected(channel, actor):
    """Cut-and-paste across records fails: the body is bound to its own header."""
    wire_a = channel.send(b"record A payload")
    wire_b = channel.send(b"record B payload")

    spliced_a, spliced_b = actor.swap_bodies(wire_a, wire_b)

    for spliced in (spliced_a, spliced_b):
        verdict = channel.deliver(spliced)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED


def test_random_garbage_is_rejected(channel, actor):
    """The trivial baseline: unstructured noise never authenticates."""
    for length in (0, 10, 55, 56, 128, 1024):
        verdict = channel.deliver(actor.random_bytes(length))
        assert verdict.rejected
        assert verdict.plaintext is None


def test_valid_records_still_accepted_after_the_attacks(channel, actor):
    """The receiver is not left in a broken state by rejected records."""
    wire = channel.send(b"probe")
    assert channel.deliver(actor.flip_ciphertext_bit(wire, offset=0, bit=0)).rejected

    follow_up = channel.send(b"legitimate record after attack")
    verdict = channel.deliver(follow_up)

    assert verdict.accepted
    assert verdict.plaintext == b"legitimate record after attack"
