"""The malicious actor (Section 6): a third logical entity between the endpoints.

Every method starts from a **real, valid record produced by the real sender**
and makes the smallest change that would achieve the attacker's goal.  The actor
has no access to the key; it manipulates wire bytes only, which is exactly the
capability of an on-path network attacker.

Wire layout reference (from ``srp/header.py``)::

    wire[:HEADER_LEN]        = 40-byte header (the AAD)
    wire[HEADER_LEN:-TAG_LEN] = ciphertext (payload_len bytes)
    wire[-TAG_LEN:]          = 16-byte authentication tag

The ``rng`` parameter exists so a demo run is reproducible and the report's
evidence can be regenerated exactly.  It is used for every random choice.
"""

from __future__ import annotations

import os
import random

from .header import (
    HEADER_LEN,
    TAG_LEN,
    RecordFlags,
    RecordHeader,
    RecordType,
)


class MaliciousActor:
    """Generates or modifies protected records to simulate hostile conditions.

    Parameters
    ----------
    rng:
        Optional seeded :class:`random.Random` for reproducible runs.
    """

    def __init__(self, rng: random.Random | None = None) -> None:
        self._rng = rng if rng is not None else random.Random()

    # -- helpers -----------------------------------------------------------

    def _ct_range(self, wire: bytes) -> tuple[int, int]:
        """Return (start, end) byte offsets of the ciphertext in *wire*."""
        return HEADER_LEN, len(wire) - TAG_LEN

    # -- TR-2: ciphertext modification -------------------------------------

    def flip_ciphertext_bit(
        self, wire: bytes, *, offset: int | None = None, bit: int | None = None
    ) -> bytes:
        """Invert one bit of the ciphertext body, leaving header and tag intact."""
        ct_start, ct_end = self._ct_range(wire)
        ct_len = ct_end - ct_start
        if ct_len <= 0:
            raise ValueError("no ciphertext to modify (empty payload)")
        if offset is None:
            offset = self._rng.randrange(ct_len)
        if bit is None:
            bit = self._rng.randrange(8)
        w = bytearray(wire)
        w[ct_start + offset] ^= 1 << bit
        return bytes(w)

    def truncate_ciphertext(self, wire: bytes, count: int = 1) -> bytes:
        """Drop ``count`` bytes from the end of the ciphertext body.

        The header (including its ``payload_len``) and the tag are preserved,
        so the resulting frame has a framing mismatch that ``parse_record``
        detects as ``MALFORMED``.
        """
        ct_start, ct_end = self._ct_range(wire)
        ct_len = ct_end - ct_start
        if count > ct_len:
            count = ct_len
        header = wire[:HEADER_LEN]
        ciphertext = wire[ct_start : ct_end - count]
        tag = wire[ct_end:]
        return header + ciphertext + tag

    # -- TR-3: authentication tag modification -----------------------------

    def flip_tag_bit(
        self, wire: bytes, *, offset: int | None = None, bit: int | None = None
    ) -> bytes:
        """Invert one bit of the authentication tag."""
        if offset is None:
            offset = self._rng.randrange(TAG_LEN)
        if bit is None:
            bit = self._rng.randrange(8)
        tag_start = len(wire) - TAG_LEN
        w = bytearray(wire)
        w[tag_start + offset] ^= 1 << bit
        return bytes(w)

    def replace_tag(self, wire: bytes, tag: bytes | None = None) -> bytes:
        """Substitute the whole tag, by default with random bytes."""
        if tag is None:
            tag = self._rng.randbytes(TAG_LEN)
        return wire[:-TAG_LEN] + tag

    def zero_tag(self, wire: bytes) -> bytes:
        """Replace the tag with all zero bytes."""
        return wire[:-TAG_LEN] + b"\x00" * TAG_LEN

    def truncate_tag(self, wire: bytes, count: int = 1) -> bytes:
        """Shorten the tag, testing that truncated tags are not accepted."""
        return wire[:-count]

    # -- TR-4: associated data modification --------------------------------

    def tamper_header(self, wire: bytes, **changes) -> bytes:
        """Rewrite authenticated header fields, keeping ciphertext and tag.

        Accepts any :class:`~srp.header.RecordHeader` field by keyword,
        e.g. ``stream_id=9``, ``record_type=RecordType.CONTROL``, ``seq=...``.
        """
        header = RecordHeader.from_bytes(wire[:HEADER_LEN])
        new_header = header.evolve(**changes)
        return new_header.to_bytes() + wire[HEADER_LEN:]

    def flip_header_bit(
        self, wire: bytes, *, offset: int | None = None, bit: int | None = None
    ) -> bytes:
        """Invert one bit anywhere in the header / AAD."""
        if offset is None:
            offset = self._rng.randrange(HEADER_LEN)
        if bit is None:
            bit = self._rng.randrange(8)
        w = bytearray(wire)
        w[offset] ^= 1 << bit
        return bytes(w)

    def relabel_record_type(
        self, wire: bytes, record_type: RecordType = RecordType.CLOSE
    ) -> bytes:
        """Present a DATA record as some other type -- an AAD-only semantic attack."""
        return self.tamper_header(wire, record_type=record_type)

    def set_flags(self, wire: bytes, flags: RecordFlags) -> bytes:
        """Forge or strip per-record flags such as END_OF_STREAM."""
        return self.tamper_header(wire, flags=flags)

    def redirect_stream(self, wire: bytes, stream_id: int) -> bytes:
        """Re-inject a record as if it belonged to a different stream."""
        return self.tamper_header(wire, stream_id=stream_id)

    def declare_wrong_length(self, wire: bytes, payload_len: int) -> bytes:
        """Lie about ``payload_len`` without changing the frame."""
        return self.tamper_header(wire, payload_len=payload_len)

    def switch_suite_label(self, wire: bytes, suite_id: int) -> bytes:
        """Claim the record was protected with the other AEAD configuration."""
        return self.tamper_header(wire, suite_id=suite_id)

    # -- TR-5: replay -------------------------------------------------------

    def replay(self, wire: bytes) -> bytes:
        """Capture and re-send an unmodified record.

        Byte-identical by construction.  The AEAD alone cannot detect this,
        which is why FR-8 requires a separate replay mechanism.
        """
        return bytes(wire)

    def renumber(self, wire: bytes, seq: int) -> bytes:
        """Replay a record under a fresh sequence number.

        Changes ``seq`` in the header while keeping the ciphertext and tag
        from the original.  This changes the AAD, so the tag no longer verifies
        — the AEAD catches this as AUTH_FAILED, independent of the replay check.
        """
        return self.tamper_header(wire, seq=seq)

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
        """Build a structurally perfect record under a key the attacker chose.

        Reproduces everything observable from a genuine record — session id,
        stream, sequence number, nonce prefix — so the only difference is the
        key.  This is the strongest TR-6 demonstration: even a record that is
        structurally indistinguishable from a genuine one is rejected because
        the key is wrong.
        """
        from .sender import Sender
        from .suites import suite_class

        cls = suite_class(suite_name)
        if key is None:
            key = cls.generate_key()
        suite = cls(key)

        if nonce_prefix is None:
            nonce_prefix = os.urandom(4)

        sender = Sender(
            suite,
            session_id,
            stream_id=stream_id,
            nonce_prefix=nonce_prefix,
            start_seq=seq,
        )
        return sender.protect(payload)

    # -- cross-record and cross-session attacks -----------------------------

    def splice(self, header_source: bytes, body_source: bytes) -> bytes:
        """Cut-and-paste: one record's header with another's ciphertext and tag."""
        return header_source[:HEADER_LEN] + body_source[HEADER_LEN:]

    def swap_bodies(self, wire_a: bytes, wire_b: bytes) -> tuple[bytes, bytes]:
        """Exchange the ciphertext+tag of two records, keeping their headers."""
        header_a = wire_a[:HEADER_LEN]
        header_b = wire_b[:HEADER_LEN]
        body_a = wire_a[HEADER_LEN:]
        body_b = wire_b[HEADER_LEN:]
        return header_a + body_b, header_b + body_a

    def reassign_session(self, wire: bytes, session_id: bytes) -> bytes:
        """Present a record as belonging to a different session/key epoch."""
        return self.tamper_header(wire, session_id=session_id)

    # -- misc ---------------------------------------------------------------

    def random_bytes(self, length: int = 128) -> bytes:
        """Pure noise, for the trivial baseline case."""
        return self._rng.randbytes(length)


__all__ = ["MaliciousActor"]
