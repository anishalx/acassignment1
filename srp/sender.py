"""Sending side: turn application records into protected records (FR-1, FR-3).

One :class:`Sender` owns one (key, session, stream) triple and the nonce
counter that goes with it.  That coupling is the point: the only way to reuse a
nonce is to have two things allocating from the same counter space, so the
counter is not a free-floating parameter the caller can get wrong -- it lives
inside the object that also holds the key.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .errors import ConfigurationError
from .header import (
    MAX_PAYLOAD_LEN,
    SESSION_ID_LEN,
    ProtectedRecord,
    RecordFlags,
    RecordHeader,
    RecordType,
)
from .nonce import NonceManager
from .suites import AeadSuite


@dataclass
class SenderStats:
    """Counters exposed for test evidence and the performance report."""

    records_protected: int = 0
    plaintext_bytes: int = 0
    wire_bytes: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "records_protected": self.records_protected,
            "plaintext_bytes": self.plaintext_bytes,
            "wire_bytes": self.wire_bytes,
        }


class Sender:
    """Protects application records under one AEAD configuration.

    Parameters
    ----------
    suite:
        The AEAD configuration, already bound to the pre-shared key.
    session_id:
        16-byte identifier for this key epoch, authenticated in every record.
    stream_id:
        Logical stream this sender writes to.  Distinct streams under the same
        session get independent replay windows at the receiver, but share the
        nonce space -- so use a separate :class:`Sender` per stream and let each
        have its own nonce prefix.
    nonce_prefix:
        Optional fixed prefix; a fresh random one is drawn if omitted.  Supply
        it only to reproduce a specific run, never to pin it across sessions.
    record_limit:
        Per-key record budget; the sender refuses to emit beyond it.
    start_seq:
        First sequence number.  Non-zero values are for tests that need to
        exercise window behaviour near a specific point in the sequence space.
    """

    def __init__(
        self,
        suite: AeadSuite,
        session_id: bytes,
        *,
        stream_id: int = 1,
        nonce_prefix: bytes | None = None,
        record_limit: int = 2 ** 24,
        start_seq: int = 0,
    ) -> None:
        if len(session_id) != SESSION_ID_LEN:
            raise ConfigurationError(
                f"session_id must be {SESSION_ID_LEN} bytes, got {len(session_id)}"
            )
        self._suite = suite
        self._session_id = bytes(session_id)
        self._stream_id = stream_id
        self._nonces = NonceManager(
            nonce_prefix, start=start_seq, record_limit=record_limit
        )
        self._stats = SenderStats()

    # -- protection --------------------------------------------------------

    def seal(
        self,
        payload: bytes,
        *,
        record_type: RecordType = RecordType.DATA,
        flags: RecordFlags = RecordFlags.NONE,
    ) -> ProtectedRecord:
        """Protect one application record.

        The order here is load-bearing.  The nonce is allocated first, then the
        header is built around it, then the header is used as the AAD for the
        seal.  Because the header is frozen and is serialised exactly once, the
        bytes that are authenticated are necessarily the bytes that go on the
        wire -- there is no window in which the two could diverge.
        """
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise ConfigurationError("payload must be a bytes-like object")
        payload = bytes(payload)
        if len(payload) > MAX_PAYLOAD_LEN:
            raise ConfigurationError(
                f"payload of {len(payload)} bytes exceeds policy limit "
                f"{MAX_PAYLOAD_LEN}"
            )

        # Raises NonceExhaustedError rather than returning a reused nonce.
        allocation = self._nonces.allocate()

        header = RecordHeader(
            session_id=self._session_id,
            stream_id=self._stream_id,
            nonce_prefix=self._nonces.nonce_prefix,
            seq=allocation.seq,
            payload_len=len(payload),
            record_type=record_type,
            flags=flags,
            suite_id=self._suite.suite_id,
        )

        ciphertext_and_tag = self._suite.seal(
            allocation.nonce, payload, header.aad()
        )

        record = ProtectedRecord(header=header, ciphertext_and_tag=ciphertext_and_tag)

        self._stats.records_protected += 1
        self._stats.plaintext_bytes += len(payload)
        self._stats.wire_bytes += len(record)
        return record

    def protect(
        self,
        payload: bytes,
        *,
        record_type: RecordType = RecordType.DATA,
        flags: RecordFlags = RecordFlags.NONE,
    ) -> bytes:
        """Protect one application record and return the wire encoding."""
        return self.seal(payload, record_type=record_type, flags=flags).to_bytes()

    def protect_many(self, payloads) -> list[bytes]:
        """Protect a sequence of application records (FR-1: each independently)."""
        return [self.protect(p) for p in payloads]

    # -- introspection -----------------------------------------------------

    @property
    def suite(self) -> AeadSuite:
        return self._suite

    @property
    def session_id(self) -> bytes:
        return self._session_id

    @property
    def stream_id(self) -> int:
        return self._stream_id

    @property
    def nonce_prefix(self) -> bytes:
        return self._nonces.nonce_prefix

    @property
    def next_seq(self) -> int:
        return self._nonces.next_seq

    @property
    def nonces(self) -> NonceManager:
        """The nonce manager, exposed so TR-7 can inspect its state."""
        return self._nonces

    @property
    def stats(self) -> SenderStats:
        return self._stats

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"<Sender suite={self._suite.name} "
            f"session={self._session_id.hex()[:8]}.. stream={self._stream_id} "
            f"next_seq={self.next_seq}>"
        )


def new_session_id() -> bytes:
    """Fresh 16-byte session identifier from the OS CSPRNG."""
    return os.urandom(SESSION_ID_LEN)


__all__ = ["Sender", "SenderStats", "new_session_id"]
