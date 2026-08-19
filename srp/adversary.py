"""The malicious actor (Section 6): a third logical entity between the endpoints.

    OWNER: MEMBER 2 -- NOT YET IMPLEMENTED

This module is a specification stub.  It fixes the *interface* the negative
tests and the demonstrations are already written against; the attacks
themselves are Member 2's to implement.

Why this module exists
----------------------

Section 6 names three logical entities -- Sender, Malicious Actor, Receiver --
and every negative Testing Requirement is stated as something the actor *does*.
The point is to make the negative tests honest.  It would be easy to
"demonstrate" TR-2 by handing the receiver a random blob, but that proves
nothing: any parser rejects garbage.  The interesting claim is that an attacker
who sees genuine traffic and can modify it arbitrarily still cannot get a single
forged byte accepted.

So every method below must start from a **real, valid record produced by the
real sender** and make the smallest change that would achieve the attacker's
goal -- usually a single bit.  The actor has no access to the key; it
manipulates wire bytes only, which is exactly the capability an on-path network
attacker has.

Things worth working out before you write it
--------------------------------------------

*   Where the ciphertext ends and the tag begins in a wire record.  See
    ``HEADER_LEN``, ``TAG_LEN`` and ``parse_record`` in ``srp/header.py``.
*   For the header attacks, whether it is better to flip raw bytes or to parse,
    change a field and re-serialise.  Both are useful; they demonstrate
    different things.
*   For ``forge_with_wrong_key``, how much of an observed record an on-path
    attacker can faithfully reproduce.  Everything except the key, ideally --
    that is what makes TR-6 convincing rather than trivial.
*   The ``rng`` parameter exists so a demo run is reproducible and the report's
    evidence can be regenerated exactly.  Use it for every random choice.

Integration contract -- do not change these names or signatures
---------------------------------------------------------------

``demo/run_demo.py``, ``demo/run_network_demo.py`` and ``tests/conftest.py``
already call these methods; they are the acceptance test for this module.
Delete ``MEMBER2_STUB`` when the module is real -- the test suite keys its
"pending" skips off it.
"""

from __future__ import annotations

import random

from .header import RecordFlags, RecordType

#: Sentinel: this module is still a stub.  Remove it once implemented.
MEMBER2_STUB = True

_TODO = (
    "srp.adversary is MEMBER 2's deliverable and is not implemented yet. "
    "See HANDOFF.md."
)


class MaliciousActor:
    """Generates or modifies protected records to simulate hostile conditions.

    Parameters
    ----------
    rng:
        Optional seeded :class:`random.Random` for reproducible runs.
    """

    def __init__(self, rng: random.Random | None = None) -> None:
        raise NotImplementedError(_TODO)

    # -- TR-2: ciphertext modification -------------------------------------

    def flip_ciphertext_bit(
        self, wire: bytes, *, offset: int | None = None, bit: int | None = None
    ) -> bytes:
        """Invert one bit of the ciphertext body, leaving header and tag intact."""
        raise NotImplementedError(_TODO)

    def truncate_ciphertext(self, wire: bytes, count: int = 1) -> bytes:
        """Drop ``count`` bytes from the end of the ciphertext body."""
        raise NotImplementedError(_TODO)

    # -- TR-3: authentication tag modification -----------------------------

    def flip_tag_bit(
        self, wire: bytes, *, offset: int | None = None, bit: int | None = None
    ) -> bytes:
        """Invert one bit of the authentication tag."""
        raise NotImplementedError(_TODO)

    def replace_tag(self, wire: bytes, tag: bytes | None = None) -> bytes:
        """Substitute the whole tag, by default with random bytes."""
        raise NotImplementedError(_TODO)

    def zero_tag(self, wire: bytes) -> bytes:
        """Replace the tag with all zero bytes."""
        raise NotImplementedError(_TODO)

    def truncate_tag(self, wire: bytes, count: int = 1) -> bytes:
        """Shorten the tag, testing that truncated tags are not accepted."""
        raise NotImplementedError(_TODO)

    # -- TR-4: associated data modification --------------------------------

    def tamper_header(self, wire: bytes, **changes) -> bytes:
        """Rewrite authenticated header fields, keeping ciphertext and tag.

        Should accept any :class:`~srp.header.RecordHeader` field by keyword,
        e.g. ``stream_id=9``, ``record_type=RecordType.CONTROL``, ``seq=...``.
        """
        raise NotImplementedError(_TODO)

    def flip_header_bit(
        self, wire: bytes, *, offset: int | None = None, bit: int | None = None
    ) -> bytes:
        """Invert one bit anywhere in the header / AAD."""
        raise NotImplementedError(_TODO)

    def relabel_record_type(
        self, wire: bytes, record_type: RecordType = RecordType.CLOSE
    ) -> bytes:
        """Present a DATA record as some other type -- an AAD-only semantic attack."""
        raise NotImplementedError(_TODO)

    def set_flags(self, wire: bytes, flags: RecordFlags) -> bytes:
        """Forge or strip per-record flags such as END_OF_STREAM."""
        raise NotImplementedError(_TODO)

    def redirect_stream(self, wire: bytes, stream_id: int) -> bytes:
        """Re-inject a record as if it belonged to a different stream."""
        raise NotImplementedError(_TODO)

    def declare_wrong_length(self, wire: bytes, payload_len: int) -> bytes:
        """Lie about ``payload_len`` without changing the frame."""
        raise NotImplementedError(_TODO)

    def switch_suite_label(self, wire: bytes, suite_id: int) -> bytes:
        """Claim the record was protected with the other AEAD configuration."""
        raise NotImplementedError(_TODO)

    # -- TR-5: replay -------------------------------------------------------

    def replay(self, wire: bytes) -> bytes:
        """Capture and re-send an unmodified record.

        Byte-identical by construction.  Think about why that means the AEAD
        alone cannot detect it.
        """
        raise NotImplementedError(_TODO)

    def renumber(self, wire: bytes, seq: int) -> bytes:
        """Replay a record under a fresh sequence number."""
        raise NotImplementedError(_TODO)

    # -- TR-6: wrong key ----------------------------------------------------

    def forge_with_wrong_key(
        self,
        suite_name: str,
        *,
        session_id: bytes,
        stream_id: int = 1,
        seq: int = 0,
        nonce_prefix: bytes | None = None,
        payload: bytes = b"forged application record",
        key: bytes | None = None,
    ) -> bytes:
        """Build a structurally perfect record under a key the attacker chose."""
        raise NotImplementedError(_TODO)

    # -- cross-record and cross-session attacks -----------------------------

    def splice(self, header_source: bytes, body_source: bytes) -> bytes:
        """Cut-and-paste: one record's header with another's ciphertext and tag."""
        raise NotImplementedError(_TODO)

    def swap_bodies(self, wire_a: bytes, wire_b: bytes) -> tuple[bytes, bytes]:
        """Exchange the ciphertext+tag of two records, keeping their headers."""
        raise NotImplementedError(_TODO)

    def reassign_session(self, wire: bytes, session_id: bytes) -> bytes:
        """Present a record as belonging to a different session/key epoch."""
        raise NotImplementedError(_TODO)

    # -- misc ---------------------------------------------------------------

    def random_bytes(self, length: int = 128) -> bytes:
        """Pure noise, for the trivial baseline case."""
        raise NotImplementedError(_TODO)


__all__ = ["MaliciousActor"]
