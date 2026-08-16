"""Nonce management (FR-5, SR-3, TR-7).

The rule both configurations depend on
--------------------------------------

AES-GCM and ChaCha20-Poly1305 are both *nonce-respecting* AEADs built on a
stream-cipher core.  A (key, nonce) pair defines a keystream.  Encrypting two
different plaintexts under the same pair XORs them together in the ciphertext,
so their difference leaks immediately.  Worse, for both constructions nonce
reuse also leaks the *authentication* key -- the GHASH subkey for GCM, the
Poly1305 one-time key for ChaCha20-Poly1305 -- which lets an attacker forge
arbitrary records from then on.  Nonce reuse is therefore not a degradation, it
is a total break of both confidentiality and integrity.

That makes "a nonce is never reused with a given key" the single invariant this
module exists to enforce, structurally rather than by convention.

Construction
------------

96-bit nonce, split as::

    nonce = nonce_prefix (32 bits, random per session) || seq (64 bits, big-endian counter)
            +--------------------------------+  +------------------------------------+
                    4 bytes                              8 bytes

This is the deterministic construction of NIST SP 800-38D s8.2.1 (a fixed field
plus an invocation field) and the same shape TLS 1.3 and IPsec ESP use.

Why a counter rather than random nonces
---------------------------------------

Drawing all 96 bits at random is the tempting alternative, and it is wrong here.
With random 96-bit nonces the birthday bound gives a collision probability of
roughly ``q^2 / 2^97`` after ``q`` records.  That is why NIST SP 800-38D s8.3
caps *random* nonce construction at 2^32 invocations per key: past that, a
repeat is likelier than not.  A counter has no birthday bound at all -- it
cannot repeat until it wraps, which for 64 bits it never will.

The counter also gives us three things for free:

1. **Replay detection.** The sequence number the replay window needs is the same
   counter, so no separate anti-replay field is required (see :mod:`srp.replay`).
2. **Reconstructable nonces.** The receiver derives the nonce from authenticated
   header fields, so the nonce need not be transmitted as a separate element.
3. **A checkable invariant.** "Strictly increasing" is trivially testable, which
   is what TR-7 asks for; "probably no collisions" is not.

Why the random 32-bit prefix
----------------------------

A bare counter starting at zero repeats across *sessions*: restart the sender
with the same long-term key and it re-emits nonce 0, 1, 2, ... against
plaintexts that differ.  This is the classic way deployed systems have destroyed
themselves (it is the same failure mode as the WPA2 key-reinstallation attack,
and as several IoT stacks that reset their counter on reboot).

The prefix is fresh per session, so two sessions under the same key occupy
disjoint nonce subspaces with overwhelming probability, and the counter only has
to be unique *within* a session -- which a monotonic in-memory integer
guarantees without any persistent state.

The residual risk is a prefix collision between two sessions sharing a key:
about ``s^2 / 2^33`` for ``s`` sessions.  For the record volumes in scope that
is negligible, and it is bounded further by the per-key record budget below.
A deployment needing a hard guarantee should derive per-session keys instead --
which is a key-management change, and key management is out of scope here
(Section 3.2).

Exhaustion
----------

The manager refuses to emit beyond a configured record budget.  It fails closed:
:class:`~srp.errors.NonceExhaustedError` is raised *instead of* returning a
nonce, so there is no path by which the caller obtains a reused one.  The
correct response is to rekey, not to retry.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .errors import ConfigurationError, NonceExhaustedError
from .header import NONCE_PREFIX_LEN

#: Width of the invocation counter, in bits.
SEQ_BITS = 64

#: One past the largest representable sequence number.
SEQ_SPACE = 1 << SEQ_BITS

#: Total nonce length for both AEAD configurations, in bytes.
NONCE_LEN = NONCE_PREFIX_LEN + SEQ_BITS // 8  # 4 + 8 = 12


def derive_nonce(nonce_prefix: bytes, seq: int) -> bytes:
    """Build the 96-bit nonce from its two authenticated header fields.

    Pure function, used identically by sender and receiver.  Having exactly one
    definition of the nonce construction is deliberate: a sender and receiver
    that disagree about it would fail every authentication, and a subsystem with
    two copies of the rule is a subsystem where they can drift apart.
    """
    if len(nonce_prefix) != NONCE_PREFIX_LEN:
        raise ConfigurationError(
            f"nonce_prefix must be {NONCE_PREFIX_LEN} bytes, got {len(nonce_prefix)}"
        )
    if not 0 <= seq < SEQ_SPACE:
        raise ConfigurationError(f"seq {seq} outside 64-bit range")
    return nonce_prefix + seq.to_bytes(SEQ_BITS // 8, "big")


@dataclass(frozen=True, slots=True)
class NonceAllocation:
    """One issued (seq, nonce) pair."""

    seq: int
    nonce: bytes


class NonceManager:
    """Sender-side allocator of unique nonces for one (key, session).

    Not thread-safe by design.  Adding a lock would make concurrent senders
    *appear* safe while leaving the real hazard -- two independently constructed
    managers sharing a key and a prefix -- untouched.  The intended pattern is
    one manager per sending context; see :class:`srp.session.SenderSession`.
    """

    __slots__ = ("_prefix", "_next", "_start", "_limit", "_issued")

    def __init__(
        self,
        nonce_prefix: bytes | None = None,
        *,
        start: int = 0,
        record_limit: int = 2 ** 24,
    ) -> None:
        if nonce_prefix is None:
            nonce_prefix = os.urandom(NONCE_PREFIX_LEN)
        if len(nonce_prefix) != NONCE_PREFIX_LEN:
            raise ConfigurationError(
                f"nonce_prefix must be {NONCE_PREFIX_LEN} bytes, got {len(nonce_prefix)}"
            )
        if not 0 <= start < SEQ_SPACE:
            raise ConfigurationError(f"start {start} outside 64-bit range")
        if record_limit <= 0:
            raise ConfigurationError("record_limit must be positive")
        if start + record_limit > SEQ_SPACE:
            raise ConfigurationError(
                "start + record_limit would overflow the 64-bit sequence space"
            )

        self._prefix = bytes(nonce_prefix)
        self._start = start
        self._next = start
        self._limit = record_limit
        self._issued = 0

    # -- allocation --------------------------------------------------------

    def allocate(self) -> NonceAllocation:
        """Issue the next unique (seq, nonce) pair.

        Raises :class:`NonceExhaustedError` once the record budget is spent.
        The counter is advanced only after the budget check passes, so a caller
        that catches the error and retries gets the same error, not a duplicate.
        """
        if self._issued >= self._limit:
            raise NonceExhaustedError(
                f"record budget of {self._limit} exhausted for this key/session "
                f"(prefix={self._prefix.hex()}); rekey before sending further records"
            )
        seq = self._next
        nonce = derive_nonce(self._prefix, seq)
        self._next = seq + 1
        self._issued += 1
        return NonceAllocation(seq=seq, nonce=nonce)

    # -- introspection (used by TR-7 evidence and by the sender's stats) ----

    @property
    def nonce_prefix(self) -> bytes:
        return self._prefix

    @property
    def next_seq(self) -> int:
        """The sequence number the next :meth:`allocate` will return."""
        return self._next

    @property
    def issued(self) -> int:
        """How many nonces have been issued by this manager."""
        return self._issued

    @property
    def record_limit(self) -> int:
        return self._limit

    @property
    def remaining(self) -> int:
        """Records still permitted under the current budget."""
        return max(0, self._limit - self._issued)

    @property
    def exhausted(self) -> bool:
        return self._issued >= self._limit

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"<NonceManager prefix={self._prefix.hex()} next_seq={self._next} "
            f"issued={self._issued}/{self._limit}>"
        )


def random_nonce_collision_probability(records: int, nonce_bits: int = 96) -> float:
    """Birthday-bound estimate for the *rejected* random-nonce design.

    Returns ``1 - exp(-q(q-1) / 2^(bits+1))``, the standard approximation for at
    least one collision among ``q`` uniform draws from a ``2**bits`` space.
    Used by ``bench/nonce_analysis.py`` to quantify, in the report, what the
    counter construction buys.

    Computed as ``-expm1(x)`` rather than ``1 - exp(x)``: at the probabilities
    that matter here the exponent is around ``-1e-22``, where ``exp(x)`` rounds
    to exactly 1.0 in double precision and the naive form returns a flat zero.
    """
    import math

    if records < 2:
        return 0.0
    exponent = -(records * (records - 1)) / float(1 << (nonce_bits + 1))
    return -math.expm1(exponent)


__all__ = [
    "SEQ_BITS",
    "SEQ_SPACE",
    "NONCE_LEN",
    "derive_nonce",
    "NonceAllocation",
    "NonceManager",
    "random_nonce_collision_probability",
]
