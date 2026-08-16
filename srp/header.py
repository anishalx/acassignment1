"""Record header, wire format, and Associated Data selection (FR-4, SR-4).

Wire format of a protected application record
---------------------------------------------

::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   version     |   suite_id    |  record_type  |     flags     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                         session_id (16)                       +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          stream_id                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        nonce_prefix                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                        seq (64-bit BE)                        +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        payload_len                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                     ciphertext (payload_len)                  +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                    authentication tag (16)                    +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The 40-byte header is transmitted **in the clear** and used **verbatim as the
Associated Data**.  That is the whole AAD selection decision, and it is worth
stating why it is the right one.

Why the entire header, and nothing but the header?
--------------------------------------------------

AAD exists for data that must be *authentic* but cannot be *encrypted*, because
some intermediary has to read it to route or reassemble the record.  Every field
above is exactly that: the receiver must read ``payload_len`` to frame the
record, ``suite_id`` to know which primitive to invoke, ``seq`` to reconstruct
the nonce and run the replay check -- all *before* it holds a verified plaintext.
So all of it is unencrypted by necessity, and therefore all of it needs
authenticating.

The converse also holds: nothing that *could* be encrypted is put in the AAD.
Application metadata that the receiver does not need before decryption belongs
in the plaintext payload, where it gets confidentiality as well as integrity.
Putting it in the AAD would leak it for no benefit.

What each field buys, concretely:

``version``
    Binds the frame format.  Prevents a downgrade to a hypothetical future
    version with weaker framing.
``suite_id``
    Binds the AEAD configuration to the record.  Without it, an attacker who
    somehow obtained an AES-GCM and a ChaCha20-Poly1305 record could try to
    present one as the other; with it, such a swap fails authentication.
``record_type``, ``flags``
    Binds application-level semantics.  A DATA record cannot be re-presented as
    a CLOSE record, and END_OF_STREAM cannot be forged or stripped.
``session_id``
    Binds the record to one key epoch, defeating cross-session splicing.
``stream_id``
    Binds the record to one logical stream, so a record legitimately sent on
    stream 1 cannot be re-injected as if it belonged to stream 2.
``nonce_prefix``, ``seq``
    Together these *are* the nonce (see :mod:`srp.nonce`).  Authenticating them
    means the position of a record in the stream is cryptographically fixed:
    reordering, deletion and duplication all become detectable rather than
    silent.  This is what makes the replay defence in :mod:`srp.replay`
    meaningful -- a sliding window over an *unauthenticated* counter would be
    trivially defeated.
``payload_len``
    Binds the framing, so a record cannot be truncated or extended undetected.

Note that authenticating the nonce material also means the nonce need not be
transmitted separately: it is derived from two header fields that are already
covered by the tag.  Nonces are public inputs in both AEAD constructions, so
sending them in the clear costs nothing.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, replace
from enum import IntEnum, IntFlag

from .errors import ConfigurationError, MalformedRecordError

#: Frame format version.  Bump only on an incompatible layout change.
PROTOCOL_VERSION = 0x01

#: ``!`` = big-endian, no padding.  Field order matches the diagram above.
_HEADER = struct.Struct("!BBBB16sI4sQI")

#: Size of the authenticated header / AAD, in bytes.
HEADER_LEN = _HEADER.size  # 40

#: Length of the authentication tag appended by both configurations.
TAG_LEN = 16

#: Minimum size of a well-formed protected record (empty payload).
MIN_RECORD_LEN = HEADER_LEN + TAG_LEN

#: Policy limit on a single application record's payload, 16 MiB.  Both AEAD
#: configurations permit far larger inputs (see ``max_plaintext_len``), but a
#: subsystem that will allocate whatever an unauthenticated ``payload_len``
#: field asks for is a memory-exhaustion target.  Bounding it here means the
#: parser can reject absurd frames before touching the crypto.
MAX_PAYLOAD_LEN = 2 ** 24

SESSION_ID_LEN = 16
NONCE_PREFIX_LEN = 4


class RecordType(IntEnum):
    """Application-level record classification, authenticated via AAD."""

    DATA = 0x01
    CONTROL = 0x02
    CLOSE = 0x03


class RecordFlags(IntFlag):
    """Per-record flags, authenticated via AAD."""

    NONE = 0x00
    END_OF_STREAM = 0x01


@dataclass(frozen=True, slots=True)
class RecordHeader:
    """The cleartext, authenticated metadata of one protected record.

    Frozen because the header is the AAD: once a record is sealed, mutating its
    header in place would silently invalidate the tag.  The adversary module
    creates *modified copies* instead, which is exactly the attack TR-4 checks.
    """

    session_id: bytes
    stream_id: int
    nonce_prefix: bytes
    seq: int
    payload_len: int
    # ``int`` is admitted alongside the enums so that an unrecognised type or
    # flag byte survives parse-then-reserialise unchanged; see _coerce_type.
    record_type: RecordType | int = RecordType.DATA
    flags: RecordFlags | int = RecordFlags.NONE
    version: int = PROTOCOL_VERSION
    suite_id: int = 0x01

    def __post_init__(self) -> None:
        if len(self.session_id) != SESSION_ID_LEN:
            raise ConfigurationError(
                f"session_id must be {SESSION_ID_LEN} bytes, got {len(self.session_id)}"
            )
        if len(self.nonce_prefix) != NONCE_PREFIX_LEN:
            raise ConfigurationError(
                f"nonce_prefix must be {NONCE_PREFIX_LEN} bytes, "
                f"got {len(self.nonce_prefix)}"
            )
        if not 0 <= self.seq <= 0xFFFF_FFFF_FFFF_FFFF:
            raise ConfigurationError(f"seq {self.seq} out of 64-bit range")
        if not 0 <= self.stream_id <= 0xFFFF_FFFF:
            raise ConfigurationError(f"stream_id {self.stream_id} out of 32-bit range")
        if not 0 <= self.payload_len <= 0xFFFF_FFFF:
            raise ConfigurationError(f"payload_len {self.payload_len} out of range")

    # -- serialisation -----------------------------------------------------

    def to_bytes(self) -> bytes:
        """Serialise to the canonical 40-byte on-wire / AAD encoding.

        Canonical means: exactly one byte string represents a given header.
        Fixed-width big-endian fields with no optional parts and no padding, so
        there is no encoder freedom an attacker could exploit to produce two
        distinct encodings that a receiver would treat as equivalent.
        """
        return _HEADER.pack(
            self.version,
            self.suite_id,
            int(self.record_type),
            int(self.flags),
            self.session_id,
            self.stream_id,
            self.nonce_prefix,
            self.seq,
            self.payload_len,
        )

    #: The header *is* the Associated Data.  Named separately so call sites read
    #: as the requirement does (FR-4) rather than as an implementation detail.
    def aad(self) -> bytes:
        return self.to_bytes()

    @classmethod
    def from_bytes(cls, raw: bytes) -> RecordHeader:
        """Parse a 40-byte header.

        Accepts unknown ``record_type`` / ``flags`` / ``suite_id`` values: those
        are policy decisions for the receiver, not framing errors, and rejecting
        them here would give a parse-error-vs-auth-error distinction to an
        attacker.  Only genuinely unparseable input raises.
        """
        if len(raw) != HEADER_LEN:
            raise MalformedRecordError(
                f"header must be {HEADER_LEN} bytes, got {len(raw)}"
            )
        (
            version,
            suite_id,
            record_type,
            flags,
            session_id,
            stream_id,
            nonce_prefix,
            seq,
            payload_len,
        ) = _HEADER.unpack(raw)

        if version != PROTOCOL_VERSION:
            raise MalformedRecordError(
                f"unsupported protocol version 0x{version:02x}"
            )
        return cls(
            session_id=session_id,
            stream_id=stream_id,
            nonce_prefix=nonce_prefix,
            seq=seq,
            payload_len=payload_len,
            record_type=_coerce_type(record_type),
            flags=RecordFlags(flags & 0xFF),
            version=version,
            suite_id=suite_id,
        )

    def evolve(self, **changes) -> RecordHeader:
        """Return a copy with fields replaced (used by the adversary module)."""
        return replace(self, **changes)

    def summary(self) -> str:
        """Compact one-line description for logs and test evidence."""
        type_name = getattr(self.record_type, "name", None) or f"0x{int(self.record_type):02x}"
        return (
            f"session={self.session_id.hex()[:8]}.. stream={self.stream_id} "
            f"seq={self.seq} type={type_name} "
            f"flags=0x{int(self.flags):02x} len={self.payload_len} "
            f"suite=0x{self.suite_id:02x}"
        )


def _coerce_type(value: int) -> RecordType | int:
    """Map a type byte to :class:`RecordType`, preserving unknown values.

    Unknown values are kept as plain integers rather than rejected.  This is
    what makes parse-then-reserialise an exact identity on *every* 40-byte
    input, which the receiver depends on: it recomputes the AAD from the parsed
    header, so if any byte failed to survive the round trip the AAD it
    authenticates against would differ from the bytes actually on the wire.
    An unknown type simply never matches a legitimate sender's tag.
    """
    try:
        return RecordType(value)
    except ValueError:
        return value


@dataclass(frozen=True, slots=True)
class ProtectedRecord:
    """A parsed protected application record: header + ciphertext + tag.

    ``ciphertext_and_tag`` is kept as one buffer because that is how RFC 5116
    AEADs treat it, and splitting it would invite a caller to verify the tag
    separately from the ciphertext.
    """

    header: RecordHeader
    ciphertext_and_tag: bytes

    @property
    def ciphertext(self) -> bytes:
        return self.ciphertext_and_tag[:-TAG_LEN]

    @property
    def tag(self) -> bytes:
        return self.ciphertext_and_tag[-TAG_LEN:]

    def to_bytes(self) -> bytes:
        return self.header.to_bytes() + self.ciphertext_and_tag

    def __len__(self) -> int:
        return HEADER_LEN + len(self.ciphertext_and_tag)


def parse_record(wire: bytes) -> ProtectedRecord:
    """Parse a wire record, validating framing only -- never authenticity.

    Raises :class:`MalformedRecordError` if the frame cannot be interpreted.
    A successful parse says nothing whatsoever about the record being genuine;
    every field it returns is still attacker-controlled at this point.
    """
    if len(wire) < MIN_RECORD_LEN:
        raise MalformedRecordError(
            f"record must be at least {MIN_RECORD_LEN} bytes, got {len(wire)}"
        )

    header = RecordHeader.from_bytes(bytes(wire[:HEADER_LEN]))

    if header.payload_len > MAX_PAYLOAD_LEN:
        raise MalformedRecordError(
            f"declared payload_len {header.payload_len} exceeds policy limit "
            f"{MAX_PAYLOAD_LEN}"
        )

    body = bytes(wire[HEADER_LEN:])
    expected = header.payload_len + TAG_LEN
    if len(body) != expected:
        # Catches truncation, trailing garbage, and a payload_len that does not
        # describe the frame actually delivered.
        raise MalformedRecordError(
            f"frame carries {len(body)} bytes after the header but payload_len "
            f"{header.payload_len} implies {expected}"
        )

    return ProtectedRecord(header=header, ciphertext_and_tag=body)


__all__ = [
    "PROTOCOL_VERSION",
    "HEADER_LEN",
    "TAG_LEN",
    "MIN_RECORD_LEN",
    "MAX_PAYLOAD_LEN",
    "SESSION_ID_LEN",
    "NONCE_PREFIX_LEN",
    "RecordType",
    "RecordFlags",
    "RecordHeader",
    "ProtectedRecord",
    "parse_record",
]
