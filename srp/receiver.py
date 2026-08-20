"""Receiving side: verify and recover application records (FR-6, FR-7, SR-6).

Verification pipeline
---------------------

The pipeline applies checks in an order where each pre-AEAD check can only
**reject** a record, never accept one.  This is what makes them safe to run on
unauthenticated, attacker-controlled input:

1. **Parse** — framing validation.  Rejects malformed frames before any
   cryptographic or state operations.
2. **Suite binding** — does the header name this receiver's AEAD configuration?
   Rejects cross-suite confusion attempts.
3. **Session binding** — if the receiver is pinned, does the header name the
   expected session?  Rejects cross-session splicing.
4. **Replay check** — ``ReplayGuard.check()``, a pure query with no state
   mutation.  Rejects duplicates and stale records.
5. **Nonce reconstruction** — ``derive_nonce(header.nonce_prefix, header.seq)``.
6. **AEAD open** — the only step that can *accept* a record.  Catches ciphertext
   modification (TR-2), tag modification (TR-3), AAD modification (TR-4), and
   wrong-key (TR-6).
7. **Replay commit** — ``ReplayGuard.commit()``, only after authentication
   succeeds.  This is what prevents a forged high sequence number from
   poisoning the replay state.

Fail-closed invariant (FR-7, SR-6)
-----------------------------------

The ``Verdict`` dataclass enforces in ``__post_init__``:

- ``ACCEPTED`` ⟹ ``plaintext is not None`` and ``reason is None``
- ``REJECTED`` ⟹ ``plaintext is None`` and ``reason is not None``

A failure path that forgets to clear an output buffer is the classic way a
subsystem like this leaks.  Enforcing the invariant in executable code rather
than a comment makes that impossible.

Rejection reasons
-----------------

TR-2, TR-3, TR-4 and TR-6 all end in a failed tag check.  The receiver reports
them uniformly as ``AUTH_FAILED`` — distinguishing "bad ciphertext" from "bad
tag" from "bad AAD" from "wrong key" would tell the attacker *which* part of
the record to change next.  That is the standard rationale for not being
specific about AEAD failures, and it matches what the underlying library does
(``InvalidTag`` carries no detail by design).
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
from .header import RecordHeader, parse_record
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
    """Outcome of processing one protected application record.

    Immutable and self-validating by design: the caller must not be able to use
    a partly-populated result.
    """

    status: RecordStatus
    reason: RejectReason | None = None
    plaintext: bytes | None = None
    header: RecordHeader | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        # Fail-closed invariant: the relationship between status and plaintext
        # is enforced here in code, not left to convention.
        if self.status is RecordStatus.ACCEPTED:
            if self.plaintext is None:
                raise ConfigurationError(
                    "accepted verdict without plaintext"
                )
            if self.reason is not None:
                raise ConfigurationError(
                    "accepted verdict must not carry a reject reason"
                )
        else:
            if self.plaintext is not None:
                raise ConfigurationError(
                    "rejected verdict must not carry plaintext — "
                    "this is the leak FR-7 and SR-6 exist to prevent"
                )
            if self.reason is None:
                raise ConfigurationError(
                    "rejected verdict must state a reason"
                )

    @property
    def accepted(self) -> bool:
        return self.status is RecordStatus.ACCEPTED

    @property
    def rejected(self) -> bool:
        return not self.accepted

    def describe(self) -> str:
        """One-line description for logs and test evidence."""
        if self.accepted:
            seq = self.header.seq if self.header else "?"
            n = len(self.plaintext) if self.plaintext else 0
            return f"ACCEPTED seq={seq} plaintext_len={n}"
        reason = self.reason.value if self.reason else "?"
        return f"REJECTED reason={reason} detail={self.detail}"


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
        key = reason.value
        self.rejected[key] = self.rejected.get(key, 0) + 1

    def as_dict(self) -> dict:
        return {
            "accepted": self.accepted,
            "plaintext_bytes": self.plaintext_bytes,
            "rejected": dict(self.rejected),
            "rejected_total": self.rejected_total,
        }


class Receiver:
    """Verifies protected records and recovers application records.

    Parameters
    ----------
    suite:
        AEAD configuration bound to the pre-shared key.
    expected_session_id:
        If given, pins the receiver to one key epoch.  ``None`` accepts any
        session under this key.
    replay_window:
        Width of the anti-replay history, in records.
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
        self._replay_window = replay_window
        self._max_streams = max_streams
        self._stats = ReceiverStats()
        self._replay_guard = ReplayGuard(
            replay_window, max_streams=max_streams
        )

    # -- the one entry point ----------------------------------------------

    def receive(self, wire: bytes) -> Verdict:
        """Process one protected application record.

        Must never raise on attacker-supplied input: malformed frames, wrong
        suite, wrong session, replays and failed tags are all *verdicts*, not
        exceptions.  Exceptions are reserved for programming and configuration
        errors on the local side.
        """
        # Step 1: Parse — framing validation.
        try:
            record = parse_record(wire)
        except MalformedRecordError as exc:
            return self._reject(RejectReason.MALFORMED, detail=str(exc))

        header = record.header

        # Step 2: Suite binding — does the record name this configuration?
        if header.suite_id != self._suite.suite_id:
            return self._reject(
                RejectReason.SUITE_MISMATCH,
                header=header,
                detail=(
                    f"receiver bound to suite 0x{self._suite.suite_id:02x}, "
                    f"record declares 0x{header.suite_id:02x}"
                ),
            )

        # Step 3: Session binding — if pinned, does the record match?
        if (
            self._expected_session_id is not None
            and header.session_id != self._expected_session_id
        ):
            return self._reject(
                RejectReason.SESSION_MISMATCH,
                header=header,
                detail=(
                    f"receiver pinned to session "
                    f"{self._expected_session_id.hex()[:8]}.., "
                    f"record declares {header.session_id.hex()[:8]}.."
                ),
            )

        # Step 4: Replay check — pure query, no state mutation.
        stream_key = (header.session_id, header.stream_id)
        replay_verdict = self._replay_guard.check(stream_key, header.seq)

        if replay_verdict is ReplayVerdict.DUPLICATE:
            return self._reject(
                RejectReason.REPLAY_DETECTED,
                header=header,
                detail=f"seq {header.seq} already accepted on stream {header.stream_id}",
            )
        if replay_verdict is ReplayVerdict.TOO_OLD:
            return self._reject(
                RejectReason.STALE_RECORD,
                header=header,
                detail=(
                    f"seq {header.seq} is behind the replay window "
                    f"on stream {header.stream_id}"
                ),
            )
        if replay_verdict is ReplayVerdict.INVALID:
            return self._reject(
                RejectReason.STALE_RECORD,
                header=header,
                detail=(
                    f"seq {header.seq} could not be classified "
                    f"(stream capacity or range exceeded)"
                ),
            )

        # Step 5: Nonce reconstruction.
        nonce = derive_nonce(header.nonce_prefix, header.seq)

        # Step 6: AEAD open — the only step that can accept a record.
        try:
            plaintext = self._suite.open(
                nonce, record.ciphertext_and_tag, header.aad()
            )
        except AuthenticationFailure as exc:
            return self._reject(
                RejectReason.AUTH_FAILED, header=header, detail=str(exc)
            )

        # Step 7: Replay commit — only after authentication succeeds.
        self._replay_guard.commit(stream_key, header.seq)

        # Step 8: Success.
        self._stats.accepted += 1
        self._stats.plaintext_bytes += len(plaintext)
        return Verdict(
            status=RecordStatus.ACCEPTED,
            plaintext=plaintext,
            header=header,
        )

    def receive_all(self, wires) -> list[Verdict]:
        """Process a sequence of records, returning a verdict for each."""
        return [self.receive(w) for w in wires]

    # -- internal ----------------------------------------------------------

    def _reject(
        self,
        reason: RejectReason,
        *,
        header: RecordHeader | None = None,
        detail: str = "",
    ) -> Verdict:
        """Build a rejection verdict and update stats."""
        self._stats.note_rejection(reason)
        return Verdict(
            status=RecordStatus.REJECTED,
            reason=reason,
            header=header,
            detail=detail,
        )

    # -- introspection -----------------------------------------------------

    @property
    def suite(self) -> AeadSuite:
        return self._suite

    @property
    def stats(self) -> ReceiverStats:
        return self._stats

    @property
    def replay_guard(self):
        """The replay guard, exposed so TR-5 can inspect state."""
        return self._replay_guard

    def window_for_stream(self, session_id: bytes, stream_id: int):
        key = (bytes(session_id), stream_id)
        return self._replay_guard.window_for(key)


__all__ = ["Receiver", "ReceiverStats", "Verdict"]
