"""Receiving side: verify and recover application records (FR-6, FR-7, SR-6).

The receiver is the part of the subsystem an attacker actually gets to talk to,
so its contract is deliberately narrow: one method, one immutable verdict, and
one invariant that holds on every path.

    **A plaintext is present if and only if the record authenticated.**

That invariant is asserted in code (:meth:`Verdict.__post_init__`) rather than
left as a comment, because "the failure path forgot to clear the output buffer"
is the classic way this kind of subsystem leaks.  Returning a verdict object
instead of raising also means the caller cannot accidentally use a
partly-populated result: there is nothing to use unless ``accepted`` is true.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .errors import (
    AuthenticationFailure,
    ConfigurationError,
    MalformedRecordError,
    RecordStatus,
    RejectReason,
)
from .header import HEADER_LEN, RecordHeader, parse_record
from .nonce import derive_nonce
from .replay import (
    DEFAULT_MAX_STREAMS,
    DEFAULT_WINDOW_SIZE,
    ReplayGuard,
    ReplayVerdict,
)
from .suites import AeadSuite


@dataclass(frozen=True, slots=True)
class Verdict:
    """Outcome of processing one protected application record."""

    status: RecordStatus
    reason: RejectReason | None = None
    plaintext: bytes | None = None
    header: RecordHeader | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        accepted = self.status is RecordStatus.ACCEPTED
        if accepted and self.plaintext is None:
            raise ConfigurationError("ACCEPTED verdict without plaintext")
        if not accepted and self.plaintext is not None:
            # The invariant that matters (FR-7, SR-6): a rejected record must
            # never carry recovered application data out of the receiver.
            raise ConfigurationError("rejected verdict must not carry plaintext")
        if accepted and self.reason is not None:
            raise ConfigurationError("ACCEPTED verdict must not carry a reject reason")
        if not accepted and self.reason is None:
            raise ConfigurationError("rejected verdict must state a reason")

    @property
    def accepted(self) -> bool:
        return self.status is RecordStatus.ACCEPTED

    @property
    def rejected(self) -> bool:
        return not self.accepted

    def describe(self) -> str:
        """One-line description for logs and test evidence."""
        if self.accepted:
            assert self.plaintext is not None
            return f"ACCEPTED ({len(self.plaintext)} B recovered)"
        assert self.reason is not None
        return f"REJECTED [{self.reason.value}] {self.detail}".rstrip()


def _accept(plaintext: bytes, header: RecordHeader) -> Verdict:
    return Verdict(
        status=RecordStatus.ACCEPTED, plaintext=plaintext, header=header
    )


def _reject(
    reason: RejectReason, detail: str = "", header: RecordHeader | None = None
) -> Verdict:
    return Verdict(
        status=RecordStatus.REJECTED, reason=reason, detail=detail, header=header
    )


@dataclass
class ReceiverStats:
    """Counters exposed for test evidence and the report."""

    accepted: int = 0
    plaintext_bytes: int = 0
    rejected: dict[str, int] = field(default_factory=dict)

    @property
    def rejected_total(self) -> int:
        return sum(self.rejected.values())

    def note_rejection(self, reason: RejectReason) -> None:
        self.rejected[reason.value] = self.rejected.get(reason.value, 0) + 1

    def as_dict(self) -> dict:
        return {
            "accepted": self.accepted,
            "plaintext_bytes": self.plaintext_bytes,
            "rejected_total": self.rejected_total,
            "rejected": dict(self.rejected),
        }


class Receiver:
    """Verifies protected records and recovers application records.

    Parameters
    ----------
    suite:
        AEAD configuration bound to the pre-shared key.  A record whose header
        names a different configuration is rejected before any crypto runs.
    expected_session_id:
        If given, the receiver is pinned to one key epoch and rejects records
        from any other session.  Leave as ``None`` to accept any session under
        this key (each still gets its own replay window).
    replay_window:
        Width of the anti-replay window, in records.
    max_streams:
        Cap on concurrently tracked streams.
    """

    def __init__(
        self,
        suite: AeadSuite,
        *,
        expected_session_id: bytes | None = None,
        replay_window: int = DEFAULT_WINDOW_SIZE,
        max_streams: int = DEFAULT_MAX_STREAMS,
    ) -> None:
        self._suite = suite
        self._expected_session_id = (
            bytes(expected_session_id) if expected_session_id is not None else None
        )
        self._replay = ReplayGuard(replay_window, max_streams=max_streams)
        self._stats = ReceiverStats()

    # -- the one entry point ----------------------------------------------

    def receive(self, wire: bytes) -> Verdict:
        """Process one protected application record.

        Checks run cheapest-first, but note that the ordering is a performance
        decision only: every check before the AEAD is a *rejection* filter that
        can throw a record away, and none of them can cause one to be accepted.
        Acceptance requires the tag to verify, always.

        One consequence of that ordering is worth stating, because it shapes how
        the negative tests must be written.  If an attacker modifies a record the
        receiver has *already accepted* and sends it back, the replay window
        rejects it as ``REPLAY_DETECTED`` before the tag is ever checked -- the
        modification is real but never reached.  The record is rejected either
        way, and the invariant this subsystem guarantees is rejection, not any
        particular reason for it.  But to demonstrate *authentication* failure
        specifically (TR-2, TR-3, TR-4, TR-6), the malicious actor has to
        intercept a record **in flight**: modify it and deliver only the modified
        copy, so its sequence number is still fresh when the tag is checked.
        That is also the more realistic on-path attacker model, since a real
        attacker who can rewrite a record can equally well suppress the original.
        """
        # 1. Framing.  Nothing here is trusted; this only establishes that the
        #    bytes can be interpreted at all.
        try:
            record = parse_record(wire)
        except MalformedRecordError as exc:
            return self._record_rejection(RejectReason.MALFORMED, str(exc))

        header = record.header

        # 2. Configuration binding.  Rejecting a cross-suite record here saves a
        #    pointless decryption; the AAD would catch it regardless, since
        #    suite_id is authenticated.
        if header.suite_id != self._suite.suite_id:
            return self._record_rejection(
                RejectReason.SUITE_MISMATCH,
                f"record declares suite 0x{header.suite_id:02x}, receiver is "
                f"configured for {self._suite.name} (0x{self._suite.suite_id:02x})",
                header,
            )

        # 3. Session binding, when pinned.  Same reasoning: defence in depth
        #    over an already-authenticated field.
        if (
            self._expected_session_id is not None
            and header.session_id != self._expected_session_id
        ):
            return self._record_rejection(
                RejectReason.SESSION_MISMATCH,
                f"record belongs to session {header.session_id.hex()[:8]}.., "
                f"receiver is pinned to {self._expected_session_id.hex()[:8]}..",
                header,
            )

        # 4. Replay pre-check.  Read-only: an attacker-supplied sequence number
        #    can cause a rejection here but can never alter window state.
        stream_key = (header.session_id, header.stream_id)
        verdict = self._replay.check(stream_key, header.seq)
        if verdict is ReplayVerdict.DUPLICATE:
            return self._record_rejection(
                RejectReason.REPLAY_DETECTED,
                f"seq {header.seq} already accepted on stream {header.stream_id}",
                header,
            )
        if verdict is ReplayVerdict.TOO_OLD:
            window = self._replay.window_for(stream_key)
            highest = window.highest_seq if window else -1
            return self._record_rejection(
                RejectReason.STALE_RECORD,
                f"seq {header.seq} falls outside the {self._replay.window_size}-record "
                f"window below highest accepted seq {highest}",
                header,
            )
        if verdict is ReplayVerdict.INVALID:  # pragma: no cover - parser bounds seq
            return self._record_rejection(
                RejectReason.MALFORMED, f"seq {header.seq} out of range", header
            )

        # 5. Authentication and decryption.  This is the only step that can
        #    produce a plaintext, and it covers the ciphertext, the tag, the
        #    entire header (as AAD) and, through the derived nonce, the record's
        #    position in the stream.
        nonce = derive_nonce(header.nonce_prefix, header.seq)
        try:
            plaintext = self._suite.open(nonce, record.ciphertext_and_tag, header.aad())
        except AuthenticationFailure as exc:
            # Covers TR-2 (ciphertext edited), TR-3 (tag edited), TR-4 (AAD
            # edited) and TR-6 (wrong key).  They are deliberately
            # indistinguishable to the caller: reporting which one failed would
            # hand an attacker a decryption oracle.
            return self._record_rejection(RejectReason.AUTH_FAILED, str(exc), header)

        # Length-preserving AEADs, so this should be unreachable; assert rather
        # than trust, since a mismatch would mean the framing and the plaintext
        # disagree about the record.
        if len(plaintext) != header.payload_len:  # pragma: no cover - defensive
            return self._record_rejection(
                RejectReason.MALFORMED,
                f"recovered {len(plaintext)} bytes but header declared "
                f"{header.payload_len}",
                header,
            )

        # 6. Commit to the replay window.  Only now, with the record proven
        #    genuine, is attacker-influenced state allowed to move.
        self._replay.commit(stream_key, header.seq)

        self._stats.accepted += 1
        self._stats.plaintext_bytes += len(plaintext)
        return _accept(plaintext, header)

    def receive_all(self, wires) -> list[Verdict]:
        """Process a sequence of records, returning a verdict for each."""
        return [self.receive(w) for w in wires]

    # -- helpers -----------------------------------------------------------

    def _record_rejection(
        self,
        reason: RejectReason,
        detail: str = "",
        header: RecordHeader | None = None,
    ) -> Verdict:
        self._stats.note_rejection(reason)
        return _reject(reason, detail, header)

    # -- introspection -----------------------------------------------------

    @property
    def suite(self) -> AeadSuite:
        return self._suite

    @property
    def stats(self) -> ReceiverStats:
        return self._stats

    @property
    def replay_guard(self) -> ReplayGuard:
        """The replay guard, exposed so TR-5 can inspect window state."""
        return self._replay

    def window_for_stream(self, session_id: bytes, stream_id: int):
        return self._replay.window_for((bytes(session_id), stream_id))

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        pinned = (
            self._expected_session_id.hex()[:8] + ".."
            if self._expected_session_id
            else "any"
        )
        return f"<Receiver suite={self._suite.name} session={pinned}>"


__all__ = ["Receiver", "ReceiverStats", "Verdict"]
