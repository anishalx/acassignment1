"""The malicious actor (Section 6): a third logical entity between the endpoints.

This module exists to make the negative tests *honest*.  It would be easy to
"demonstrate" TR-2 by handing the receiver a random blob, but that proves
nothing: any parser rejects garbage.  The interesting claim is that an attacker
who sees genuine traffic and can modify it arbitrarily still cannot get a single
forged byte accepted.  So every method here starts from a **real, valid record
produced by the real sender** and makes the smallest possible change to it --
usually a single bit.

The actor deliberately has no access to the key.  It manipulates wire bytes and
nothing else, which is exactly the capability an on-path network attacker has.
"""

from __future__ import annotations

import os
import random

from .errors import ConfigurationError
from .header import (
    HEADER_LEN,
    TAG_LEN,
    RecordFlags,
    RecordHeader,
    RecordType,
    parse_record,
)
from .sender import Sender
from .suites import suite_class


def _flip_bit(data: bytes, byte_index: int, bit_index: int) -> bytes:
    """Return ``data`` with one bit inverted."""
    if not 0 <= byte_index < len(data):
        raise ConfigurationError(
            f"byte offset {byte_index} outside record of {len(data)} bytes"
        )
    if not 0 <= bit_index < 8:
        raise ConfigurationError(f"bit index {bit_index} outside 0..7")
    mutable = bytearray(data)
    mutable[byte_index] ^= 1 << bit_index
    return bytes(mutable)


class MaliciousActor:
    """Generates or modifies protected records to simulate hostile conditions.

    Parameters
    ----------
    rng:
        Optional seeded :class:`random.Random` so that a demo run is
        reproducible and the report's evidence can be regenerated exactly.
    """

    def __init__(self, rng: random.Random | None = None) -> None:
        self._rng = rng or random.Random()

    # -- TR-2: ciphertext modification -------------------------------------

    def flip_ciphertext_bit(
        self, wire: bytes, *, offset: int | None = None, bit: int | None = None
    ) -> bytes:
        """Invert one bit of the ciphertext body, leaving header and tag intact.

        The single-bit choice is the point.  In a stream-cipher-based AEAD this
        flips exactly the corresponding plaintext bit, so *without* the tag the
        attacker would have a precise, silent edit primitive over the plaintext.
        The test shows that the tag removes it entirely.
        """
        ct_len = len(wire) - HEADER_LEN - TAG_LEN
        if ct_len <= 0:
            raise ConfigurationError(
                "record carries no ciphertext to modify; use a non-empty payload"
            )
        if offset is None:
            offset = self._rng.randrange(ct_len)
        if bit is None:
            bit = self._rng.randrange(8)
        return _flip_bit(wire, HEADER_LEN + offset, bit)

    def truncate_ciphertext(self, wire: bytes, count: int = 1) -> bytes:
        """Drop ``count`` bytes from the end of the ciphertext body."""
        ct_len = len(wire) - HEADER_LEN - TAG_LEN
        if not 0 < count <= ct_len:
            raise ConfigurationError(f"cannot drop {count} of {ct_len} ciphertext bytes")
        cut = HEADER_LEN + ct_len - count
        return wire[:cut] + wire[HEADER_LEN + ct_len :]

    # -- TR-3: authentication tag modification -----------------------------

    def flip_tag_bit(
        self, wire: bytes, *, offset: int | None = None, bit: int | None = None
    ) -> bytes:
        """Invert one bit of the 16-byte authentication tag."""
        if len(wire) < HEADER_LEN + TAG_LEN:
            raise ConfigurationError("record too short to contain a tag")
        if offset is None:
            offset = self._rng.randrange(TAG_LEN)
        if bit is None:
            bit = self._rng.randrange(8)
        return _flip_bit(wire, len(wire) - TAG_LEN + offset, bit)

    def replace_tag(self, wire: bytes, tag: bytes | None = None) -> bytes:
        """Substitute the whole tag, by default with 16 random bytes.

        This is the naive forgery: guessing a 128-bit tag succeeds with
        probability 2**-128 per attempt.
        """
        if tag is None:
            tag = bytes(self._rng.randrange(256) for _ in range(TAG_LEN))
        if len(tag) != TAG_LEN:
            raise ConfigurationError(f"tag must be {TAG_LEN} bytes, got {len(tag)}")
        return wire[:-TAG_LEN] + tag

    def zero_tag(self, wire: bytes) -> bytes:
        """Replace the tag with all zero bytes."""
        return self.replace_tag(wire, bytes(TAG_LEN))

    def truncate_tag(self, wire: bytes, count: int = 1) -> bytes:
        """Shorten the tag, testing that truncated tags are not accepted.

        Tag truncation is a real historical weakness (GCM permits shorter tags,
        and short tags materially weaken forgery resistance).  This subsystem
        fixes the tag at 16 bytes, so a truncated frame fails framing validation
        before it reaches the AEAD.
        """
        if not 0 < count <= TAG_LEN:
            raise ConfigurationError(f"cannot drop {count} of {TAG_LEN} tag bytes")
        return wire[:-count]

    # -- TR-4: associated data modification --------------------------------

    def tamper_header(self, wire: bytes, **changes) -> bytes:
        """Rewrite authenticated header fields, keeping ciphertext and tag.

        Accepts any :class:`~srp.header.RecordHeader` field, e.g.
        ``stream_id=9``, ``record_type=RecordType.CONTROL``, ``seq=...``,
        ``session_id=...``.  Each is metadata the receiver acts on before it
        holds a verified plaintext, which is precisely why it is in the AAD.
        """
        record = parse_record(wire)
        forged = record.header.evolve(**changes)
        return forged.to_bytes() + record.ciphertext_and_tag

    def flip_header_bit(
        self, wire: bytes, *, offset: int | None = None, bit: int | None = None
    ) -> bytes:
        """Invert one bit anywhere in the 40-byte header / AAD."""
        if offset is None:
            offset = self._rng.randrange(HEADER_LEN)
        if bit is None:
            bit = self._rng.randrange(8)
        if not 0 <= offset < HEADER_LEN:
            raise ConfigurationError(f"header offset {offset} outside 0..{HEADER_LEN-1}")
        return _flip_bit(wire, offset, bit)

    def relabel_record_type(
        self, wire: bytes, record_type: RecordType = RecordType.CLOSE
    ) -> bytes:
        """Present a DATA record as some other type -- an AAD-only semantic attack.

        Nothing about the ciphertext changes; only the meaning the receiver
        would attach to it.  An unauthenticated header would make this free.
        """
        return self.tamper_header(wire, record_type=record_type)

    def set_flags(self, wire: bytes, flags: RecordFlags) -> bytes:
        """Forge or strip per-record flags such as END_OF_STREAM."""
        return self.tamper_header(wire, flags=flags)

    def redirect_stream(self, wire: bytes, stream_id: int) -> bytes:
        """Re-inject a record as if it belonged to a different stream."""
        return self.tamper_header(wire, stream_id=stream_id)

    def declare_wrong_length(self, wire: bytes, payload_len: int) -> bytes:
        """Lie about ``payload_len`` without changing the frame.

        Caught by framing validation before the AEAD runs -- the belt to the
        AAD's braces.
        """
        return self.tamper_header(wire, payload_len=payload_len)

    def switch_suite_label(self, wire: bytes, suite_id: int) -> bytes:
        """Claim the record was protected with the other AEAD configuration."""
        return self.tamper_header(wire, suite_id=suite_id)

    # -- TR-5: replay -------------------------------------------------------

    def replay(self, wire: bytes) -> bytes:
        """Capture and re-send an unmodified record.

        Byte-identical by construction: a replay is not a modification, which is
        exactly why the AEAD alone cannot detect it and a separate replay
        mechanism is required (FR-8).
        """
        return bytes(wire)

    def renumber(self, wire: bytes, seq: int) -> bytes:
        """Replay a record under a fresh sequence number.

        The natural next move once plain replay is blocked: slip past the replay
        window by relabelling the record.  It fails authentication instead,
        because ``seq`` is both authenticated as AAD *and* an input to the
        nonce, so changing it invalidates the tag two different ways.
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

        Everything an on-path attacker can observe is reproduced faithfully --
        session id, stream, sequence number, nonce prefix, framing -- so the
        record is indistinguishable from a genuine one until the tag is checked.
        Only the key differs.
        """
        cls = suite_class(suite_name)
        attacker_key = key if key is not None else cls.generate_key()
        sender = Sender(
            cls(attacker_key),
            session_id,
            stream_id=stream_id,
            nonce_prefix=nonce_prefix or os.urandom(4),
            start_seq=seq,
        )
        return sender.protect(payload)

    # -- cross-record and cross-session attacks -----------------------------

    def splice(self, header_source: bytes, body_source: bytes) -> bytes:
        """Cut-and-paste: one record's header with another's ciphertext and tag.

        Defeated because the header is the AAD, so a body only ever
        authenticates under the exact header it was sealed with.
        """
        return header_source[:HEADER_LEN] + body_source[HEADER_LEN:]

    def swap_bodies(self, wire_a: bytes, wire_b: bytes) -> tuple[bytes, bytes]:
        """Exchange the ciphertext+tag of two records, keeping their headers."""
        return self.splice(wire_a, wire_b), self.splice(wire_b, wire_a)

    def reassign_session(self, wire: bytes, session_id: bytes) -> bytes:
        """Present a record as belonging to a different session/key epoch."""
        return self.tamper_header(wire, session_id=session_id)

    # -- misc ---------------------------------------------------------------

    def random_bytes(self, length: int = 128) -> bytes:
        """Pure noise, for the trivial baseline case."""
        return bytes(self._rng.randrange(256) for _ in range(length))


__all__ = ["MaliciousActor"]
