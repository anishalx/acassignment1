"""TR-6 -- Wrong-Key Test.

Demonstrates that attempting to recover a protected record using an incorrect
cryptographic key fails *safely*: the receiver rejects the record cleanly,
releases no plaintext, raises no exception, and remains usable afterwards.

A wrong key is an everyday key-management error as much as it is an attack,
so the failure must be orderly.

Key length validation is a ``ConfigurationError`` (a local programming error),
**not** a verdict.  Configuration errors are raised at construction time and
cannot be triggered by attacker-supplied input; record verification failures
are returned as verdicts because they are routine on a hostile network.
"""

from __future__ import annotations

import os

import pytest

from srp import (
    ConfigurationError,
    RejectReason,
    Receiver,
    Sender,
    SessionPolicy,
    create_channel,
)
from srp.suites import suite_class


# ---- Helpers -------------------------------------------------------------


def _make_mismatched(suite_name):
    """Create a sender with key_A and a receiver with key_B."""
    cls = suite_class(suite_name)
    key_a = cls.generate_key()
    key_b = cls.generate_key()
    session_id = os.urandom(16)

    sender = Sender(cls(key_a), session_id)
    receiver_wrong = Receiver(cls(key_b), expected_session_id=session_id)
    receiver_correct = Receiver(cls(key_a), expected_session_id=session_id)
    return sender, receiver_wrong, receiver_correct, key_a, key_b, session_id


def _flip_key_bit(key: bytes, bit_position: int) -> bytes:
    """Return a copy of *key* with one bit flipped."""
    byte_idx = bit_position // 8
    bit_idx = bit_position % 8
    k = bytearray(key)
    k[byte_idx] ^= 1 << bit_idx
    return bytes(k)


# ---- Wrong-key rejection -------------------------------------------------


class TestWrongKeyRejection:
    """A genuine record is rejected by a receiver holding a different key."""

    def test_wrong_key_rejected(self, suite_name):
        sender, rx_wrong, rx_correct, *_ = _make_mismatched(suite_name)
        wire = sender.protect(b"secret data")

        verdict = rx_wrong.receive(wire)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED
        assert verdict.plaintext is None

    def test_correct_key_control(self, suite_name):
        """The same record IS accepted by the correct receiver.
        Without this control, the test proves nothing about the key."""
        sender, rx_wrong, rx_correct, *_ = _make_mismatched(suite_name)
        wire = sender.protect(b"secret data")

        verdict = rx_correct.receive(wire)
        assert verdict.accepted
        assert verdict.plaintext == b"secret data"


class TestBatchWrongKey:
    """Every record in a batch fails under the wrong key — not one unlucky record."""

    def test_batch_all_rejected(self, suite_name):
        sender, rx_wrong, *_ = _make_mismatched(suite_name)
        for i in range(20):
            wire = sender.protect(f"record {i}".encode())
            verdict = rx_wrong.receive(wire)
            assert verdict.rejected, f"record {i} unexpectedly accepted"
            assert verdict.reason is RejectReason.AUTH_FAILED
            assert verdict.plaintext is None


# ---- Single-bit key difference -------------------------------------------


class TestSingleBitKeyDifference:
    """A key differing in a single bit is still the wrong key.

    This says something about the primitive rather than the plumbing: the
    AEAD is sensitive to every bit of the key.
    """

    def test_sweep_key_bits(self, suite_name):
        cls = suite_class(suite_name)
        key = cls.generate_key()
        session_id = os.urandom(16)

        sender = Sender(cls(key), session_id)
        wire = sender.protect(b"key bit sweep")

        # Sweep a representative set of bit positions (every 8th bit).
        for bit_pos in range(0, len(key) * 8, 8):
            wrong_key = _flip_key_bit(key, bit_pos)
            rx = Receiver(cls(wrong_key), expected_session_id=session_id)
            verdict = rx.receive(wire)
            assert verdict.rejected, f"bit {bit_pos} flip unexpectedly accepted"
            assert verdict.reason is RejectReason.AUTH_FAILED
            assert verdict.plaintext is None


# ---- Special keys --------------------------------------------------------


class TestSpecialKeys:
    """All-zero and all-ones keys are not special-cased anywhere."""

    def test_all_zero_key(self, suite_name):
        cls = suite_class(suite_name)
        zero_key = b"\x00" * cls.key_len
        real_key = cls.generate_key()
        session_id = os.urandom(16)

        sender = Sender(cls(real_key), session_id)
        rx_zero = Receiver(cls(zero_key), expected_session_id=session_id)

        wire = sender.protect(b"zero key test")
        verdict = rx_zero.receive(wire)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED
        assert verdict.plaintext is None

    def test_all_ones_key(self, suite_name):
        cls = suite_class(suite_name)
        ones_key = b"\xff" * cls.key_len
        real_key = cls.generate_key()
        session_id = os.urandom(16)

        sender = Sender(cls(real_key), session_id)
        rx_ones = Receiver(cls(ones_key), expected_session_id=session_id)

        wire = sender.protect(b"ones key test")
        verdict = rx_ones.receive(wire)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED
        assert verdict.plaintext is None


# ---- Attacker-forged record under a chosen key ---------------------------


class TestAttackerForgedRecord:
    """An attacker forges a structurally perfect record under their own key.

    Everything observable is reproduced — session_id, stream_id, seq,
    nonce_prefix — so the only difference is the key.  This is the strongest
    TR-6 demonstration.
    """

    def test_forge_rejected(self, channel, actor):
        # Create a forged record that mimics the channel's metadata.
        forged = actor.forge_with_wrong_key(
            channel.suite_name,
            session_id=channel.session_id,
            stream_id=channel.sender.stream_id,
            seq=0,
            nonce_prefix=channel.sender.nonce_prefix,
            payload=b"attacker-forged record",
        )
        verdict = channel.deliver(forged)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED
        assert verdict.plaintext is None


# ---- Key length validation -----------------------------------------------


class TestKeyLengthValidation:
    """Key length is validated at construction — a ConfigurationError, not a
    verdict.

    Configuration errors are raised at construction time because they are local
    programming errors, not the result of attacker-supplied input.  A verdict is
    the result of processing a record on a hostile network; a ConfigurationError
    says the developer made a mistake.
    """

    def test_short_key(self, suite_name):
        cls = suite_class(suite_name)
        with pytest.raises(ConfigurationError):
            cls(b"tooshort")

    def test_long_key(self, suite_name):
        cls = suite_class(suite_name)
        with pytest.raises(ConfigurationError):
            cls(b"\x00" * (cls.key_len + 1))

    def test_empty_key(self, suite_name):
        cls = suite_class(suite_name)
        with pytest.raises(ConfigurationError):
            cls(b"")


# ---- Recovery after wrong-key usage --------------------------------------


class TestRecoveryAfterWrongKey:
    """The receiver remains usable after wrong-key failures."""

    def test_correct_key_after_wrong_key(self, suite_name):
        cls = suite_class(suite_name)
        key_correct = cls.generate_key()
        key_wrong = cls.generate_key()
        session_id = os.urandom(16)

        sender = Sender(cls(key_correct), session_id)
        rx = Receiver(cls(key_correct), expected_session_id=session_id)

        # First: a forged record under the wrong key.
        bad_sender = Sender(cls(key_wrong), session_id)
        bad_wire = bad_sender.protect(b"bad record")
        v_bad = rx.receive(bad_wire)
        assert v_bad.rejected
        assert v_bad.reason is RejectReason.AUTH_FAILED

        # Second: a genuine record under the correct key — accepted.
        good_wire = sender.protect(b"good record")
        v_good = rx.receive(good_wire)
        assert v_good.accepted
        assert v_good.plaintext == b"good record"
