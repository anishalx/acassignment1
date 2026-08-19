"""Receiving side: verify and recover application records (FR-6, FR-7, SR-6).

    OWNER: MEMBER 2 -- NOT YET IMPLEMENTED

This module is a specification stub.  It fixes the *interface* the rest of the
subsystem is already written against; the verification pipeline and its
security properties are Member 2's to design, build and justify.

What the assignment requires of this module
-------------------------------------------

FR-6  Recover the original application record from a protected record, using
      the same AEAD configuration and the correct key.
FR-7  Handle authentication failure: a record that fails verification shall be
      rejected and reported, and no unverified data shall be released.
SR-6  Authentication failures shall be detected and handled safely.

The receiver is the only part of the subsystem an attacker gets to talk to, so
every negative Testing Requirement lands here:

    TR-2  ciphertext modified in flight   -> rejected
    TR-3  authentication tag modified     -> rejected
    TR-4  associated data modified        -> rejected
    TR-5  record replayed                 -> rejected
    TR-6  wrong key                       -> rejected

Design decisions that are yours to make and to defend in the report
-------------------------------------------------------------------

1.  The output contract.  ``Verdict`` returns a result rather than raising.
    Work out the one invariant that must hold on *every* path through
    ``receive`` relating ``status`` to ``plaintext``, then enforce it in code
    rather than leaving it as a comment -- a failure path that forgets to clear
    an output buffer is the classic way a subsystem like this leaks.
2.  Check ordering.  Framing, configuration binding, session binding, replay
    and the AEAD open all have to happen somewhere.  Decide the order and be
    able to say, for each check before the AEAD, whether it could ever cause a
    record to be *accepted*.
3.  Replay check versus replay commit.  ``ReplayGuard`` deliberately splits
    these.  Decide where each belongs relative to the AEAD open, and work out
    the concrete attack that the wrong choice enables.  (Hint: what happens if
    an unauthenticated header can move the receiver's state?)
4.  How much to tell the caller.  TR-2, TR-3, TR-4 and TR-6 all end in a failed
    tag check.  Decide whether the rejection reason should distinguish them,
    and justify the answer in terms of what an attacker learns.
5.  The nonce.  The receiver is never sent the nonce; it has to reconstruct it.
    See ``srp/nonce.py`` for how, and note what that means for TR-4.

Integration contract -- do not change these names or signatures
---------------------------------------------------------------

``srp/session.py`` constructs ``Receiver(suite, expected_session_id=...,
replay_window=..., max_streams=...)`` and calls ``.receive(wire) -> Verdict``.
``demo/``, ``bench/`` and the TR-1/TR-7 tests read ``.stats``, ``.suite``,
``.replay_guard`` and ``.window_for_stream``.  Delete ``MEMBER2_STUB`` when the
module is real -- the test suite keys its "pending" skips off it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .errors import RecordStatus, RejectReason
from .header import RecordHeader
from .replay import DEFAULT_MAX_STREAMS, DEFAULT_WINDOW_SIZE
from .suites import AeadSuite

#: Sentinel: this module is still a stub.  Remove it once implemented.
MEMBER2_STUB = True

_TODO = (
    "srp.receiver is MEMBER 2's deliverable and is not implemented yet. "
    "See HANDOFF.md."
)


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
        # TODO(Member 2): enforce the accepted/rejected invariant here, raising
        # ConfigurationError on any inconsistent combination of fields.  This is
        # the fail-closed guarantee FR-7 and SR-6 ask for, so it belongs in
        # executable code rather than in a docstring.
        raise NotImplementedError(_TODO)

    @property
    def accepted(self) -> bool:
        return self.status is RecordStatus.ACCEPTED

    @property
    def rejected(self) -> bool:
        return not self.accepted

    def describe(self) -> str:
        """One-line description for logs and test evidence."""
        raise NotImplementedError(_TODO)


@dataclass
class ReceiverStats:
    """Counters exposed for test evidence and the report."""

    accepted: int = 0
    plaintext_bytes: int = 0
    rejected: dict[str, int] = field(default_factory=dict)

    @property
    def rejected_total(self) -> int:
        raise NotImplementedError(_TODO)

    def note_rejection(self, reason: RejectReason) -> None:
        raise NotImplementedError(_TODO)

    def as_dict(self) -> dict:
        raise NotImplementedError(_TODO)


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
        # The stub stores its configuration and nothing else, so that
        # ``create_channel`` still works and the sender-side tests (TR-1, TR-7)
        # can run while this module is being written.  You will want to set up
        # the replay guard here too -- and think about whether the window size
        # should be validated now or on the first record.
        self._suite = suite
        self._expected_session_id = (
            bytes(expected_session_id) if expected_session_id is not None else None
        )
        self._replay_window = replay_window
        self._max_streams = max_streams
        self._stats = ReceiverStats()

    # -- the one entry point ----------------------------------------------

    def receive(self, wire: bytes) -> Verdict:
        """Process one protected application record.

        Must never raise on attacker-supplied input: malformed frames, wrong
        suite, wrong session, replays and failed tags are all *verdicts*, not
        exceptions.  Exceptions are reserved for programming and configuration
        errors on the local side.
        """
        raise NotImplementedError(_TODO)

    def receive_all(self, wires) -> list[Verdict]:
        """Process a sequence of records, returning a verdict for each."""
        raise NotImplementedError(_TODO)

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
        raise NotImplementedError(_TODO)

    def window_for_stream(self, session_id: bytes, stream_id: int):
        raise NotImplementedError(_TODO)


__all__ = ["Receiver", "ReceiverStats", "Verdict"]
