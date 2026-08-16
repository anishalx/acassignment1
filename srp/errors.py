"""Exception and status types for the secure record protection subsystem.

Design note (SR-6, FR-7): the subsystem distinguishes between *programming /
configuration* errors, which are raised as exceptions, and *record verification*
failures, which are reported as a :class:`RejectReason` inside a verdict object.

Verification failures are an expected, routine part of operating on a hostile
network: an attacker can trigger them at will.  Turning every forged packet into
an exception would invite the caller to write ``try/except`` around the receive
loop and, sooner or later, to swallow the exception and carry on with a partly
initialised result.  Returning an explicit verdict makes the failure path the
*normal* path and keeps the "no plaintext is released" invariant checkable in
one place.
"""

from __future__ import annotations

from enum import Enum


class SrpError(Exception):
    """Base class for every error raised by this subsystem."""


class ConfigurationError(SrpError):
    """Invalid configuration: bad key length, unknown suite, bad parameters.

    Raised at construction time, never as a result of attacker-supplied input.
    """


class NonceExhaustedError(SrpError):
    """The sender has reached its usage limit for the current key (SR-3).

    Raised *instead of* producing a record.  This is deliberately fatal: the
    only safe response to running out of unique nonces is to stop encrypting
    and rekey.  Continuing would force a nonce (and therefore keystream) reuse,
    which is catastrophic for both AES-GCM and ChaCha20-Poly1305.
    """


class AuthenticationFailure(SrpError):
    """Raised by the low-level AEAD wrapper when tag verification fails.

    Callers above :mod:`srp.suites` should not let this escape; the receiver
    converts it into :attr:`RejectReason.AUTH_FAILED`.
    """


class MalformedRecordError(SrpError):
    """A wire record could not be parsed at all (truncated, bad version, ...).

    Only raised by the parser; the receiver converts it into
    :attr:`RejectReason.MALFORMED`.
    """


class RecordStatus(str, Enum):
    """Outcome of processing one protected application record."""

    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"


class RejectReason(str, Enum):
    """Why a protected application record was rejected.

    The receiver reports exactly one of these.  They are ordered here in the
    order the checks are applied in :meth:`srp.receiver.Receiver.receive`.
    """

    #: Record could not be parsed: too short, bad version byte, declared
    #: payload length inconsistent with the actual frame length.
    MALFORMED = "MALFORMED"

    #: Header names an AEAD configuration other than the one this receiver is
    #: configured for (cross-suite confusion attempt).
    SUITE_MISMATCH = "SUITE_MISMATCH"

    #: Header names a session other than the one this receiver is pinned to
    #: (cross-session splicing attempt).
    SESSION_MISMATCH = "SESSION_MISMATCH"

    #: Sequence number already accepted on this stream: a replay (TR-5, SR-5).
    REPLAY_DETECTED = "REPLAY_DETECTED"

    #: Sequence number is so far behind the window that replay cannot be ruled
    #: out; rejected conservatively (TR-5, SR-5).
    STALE_RECORD = "STALE_RECORD"

    #: AEAD tag verification failed: ciphertext, tag, AAD or key is wrong
    #: (TR-2, TR-3, TR-4, TR-6; SR-2, SR-4, SR-6).
    AUTH_FAILED = "AUTH_FAILED"


__all__ = [
    "SrpError",
    "ConfigurationError",
    "NonceExhaustedError",
    "AuthenticationFailure",
    "MalformedRecordError",
    "RecordStatus",
    "RejectReason",
]
