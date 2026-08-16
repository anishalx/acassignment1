"""TR-6 -- Wrong-Key Test.

Objective
    Demonstrate that use of an incorrect cryptographic key results in
    authentication verification failure and rejection of the protected
    application record, under both AEAD configurations.

Two directions are covered, because they are different claims:

* the **receiver** holds the wrong key, so a genuine record fails to verify --
  this is what happens when key distribution goes wrong;
* the **attacker** holds a key of their own and produces a structurally perfect
  record -- this is what happens when someone tries to inject traffic.

A third case is included: keys differing in a single bit.  It guards against a
subsystem that "checks the key" by comparing something derived and truncated,
rather than by actually verifying the tag.
"""

from __future__ import annotations

import pytest

from srp import (
    MaliciousActor,
    Receiver,
    RejectReason,
    Sender,
    new_session_id,
    parse_record,
    suite_class,
)


@pytest.fixture
def wrong_key_setup(suite_name):
    """A sender and a receiver holding *different* keys for the same session."""
    cls = suite_class(suite_name)
    correct_key = cls.generate_key()
    wrong_key = cls.generate_key()
    assert correct_key != wrong_key

    session_id = new_session_id()
    sender = Sender(cls(correct_key), session_id)
    receiver = Receiver(cls(wrong_key), expected_session_id=session_id)
    return sender, receiver, correct_key, wrong_key, cls, session_id


def test_receiver_with_the_wrong_key_rejects_a_genuine_record(wrong_key_setup):
    """The canonical TR-6 case."""
    sender, receiver, *_ = wrong_key_setup

    wire = sender.protect(b"a perfectly genuine application record")
    verdict = receiver.receive(wire)

    assert verdict.rejected
    assert verdict.reason is RejectReason.AUTH_FAILED
    assert verdict.plaintext is None


def test_the_record_is_valid_under_the_correct_key(wrong_key_setup):
    """Control: the rejection above is about the key, not a broken record."""
    sender, _, correct_key, _, cls, session_id = wrong_key_setup

    wire = sender.protect(b"a perfectly genuine application record")
    good_receiver = Receiver(cls(correct_key), expected_session_id=session_id)

    verdict = good_receiver.receive(wire)
    assert verdict.accepted
    assert verdict.plaintext == b"a perfectly genuine application record"


def test_every_record_fails_under_the_wrong_key(wrong_key_setup):
    """Not a fluke of one record: a whole batch is rejected."""
    sender, receiver, *_ = wrong_key_setup

    for i in range(100):
        verdict = receiver.receive(sender.protect(f"record {i}".encode()))
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED

    assert receiver.stats.accepted == 0
    assert receiver.stats.rejected["AUTH_FAILED"] == 100


def test_a_key_differing_in_one_bit_is_still_the_wrong_key(suite_name):
    """No partial credit: a single flipped key bit rejects everything.

    Swept over all 256 bit positions of the 32-byte key, so the property is
    established for every bit rather than a sampled few.
    """
    cls = suite_class(suite_name)
    correct_key = cls.generate_key()
    session_id = new_session_id()
    sender = Sender(cls(correct_key), session_id)

    for byte_index in range(cls.key_len):
        for bit in range(8):
            near_miss = bytearray(correct_key)
            near_miss[byte_index] ^= 1 << bit
            receiver = Receiver(cls(bytes(near_miss)), expected_session_id=session_id)

            verdict = receiver.receive(sender.protect(b"near miss probe"))

            assert verdict.rejected, f"key byte {byte_index} bit {bit} was accepted"
            assert verdict.reason is RejectReason.AUTH_FAILED
            assert verdict.plaintext is None


def test_attacker_forged_record_under_its_own_key_is_rejected(channel):
    """An injected record that is perfect in every respect except the key.

    The forgery reproduces the real session id, stream, sequence number and
    nonce prefix, so it is indistinguishable from genuine traffic on the wire
    until the tag is checked.
    """
    actor = MaliciousActor()

    genuine = channel.send(b"genuine record")
    assert channel.deliver(genuine).accepted
    header = parse_record(genuine).header

    forged = actor.forge_with_wrong_key(
        channel.suite_name,
        session_id=header.session_id,
        stream_id=header.stream_id,
        seq=header.seq + 1,          # fresh sequence number: not a replay
        nonce_prefix=header.nonce_prefix,
        payload=b"injected application record",
    )

    # Structurally identical to a genuine record ...
    forged_header = parse_record(forged).header
    assert forged_header.session_id == header.session_id
    assert forged_header.stream_id == header.stream_id
    assert forged_header.nonce_prefix == header.nonce_prefix
    assert forged_header.suite_id == header.suite_id
    assert len(forged) == len(b"injected application record") + 56

    # ... and rejected anyway.
    verdict = channel.deliver(forged)
    assert verdict.rejected
    assert verdict.reason is RejectReason.AUTH_FAILED
    assert verdict.plaintext is None


def test_all_zero_and_all_ones_keys_are_not_special(suite_name):
    """Degenerate keys confer no advantage on an attacker."""
    cls = suite_class(suite_name)
    correct_key = cls.generate_key()
    session_id = new_session_id()
    sender = Sender(cls(correct_key), session_id)
    wire = sender.protect(b"degenerate key probe")

    for key in (bytes(cls.key_len), b"\xff" * cls.key_len):
        receiver = Receiver(cls(key), expected_session_id=session_id)
        verdict = receiver.receive(wire)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED


def test_key_length_is_validated_at_construction(suite_name):
    """A wrong-sized key is a configuration error, not a silent truncation."""
    from srp import ConfigurationError

    cls = suite_class(suite_name)

    for bad_length in (0, 15, 16, 31, 33, 64):
        with pytest.raises(ConfigurationError, match="requires a 32-byte key"):
            cls(bytes(bad_length))


def test_recovery_works_again_once_the_correct_key_is_used(wrong_key_setup):
    """Rejections under the wrong key do not corrupt receiver state."""
    sender, receiver, correct_key, _, cls, session_id = wrong_key_setup

    for _ in range(10):
        assert receiver.receive(sender.protect(b"rejected")).rejected

    good_receiver = Receiver(cls(correct_key), expected_session_id=session_id)
    verdict = good_receiver.receive(sender.protect(b"accepted at last"))

    assert verdict.accepted
    assert verdict.plaintext == b"accepted at last"
