"""Replay handling (FR-8, SR-5, TR-5).

    OWNER: MEMBER 2 -- NOT YET IMPLEMENTED

This module is a specification stub.  It fixes the *interface* the rest of the
subsystem is already written against; the strategy, the data structure and the
implementation are Member 2's to design, build and justify.

What the assignment requires of this module
-------------------------------------------

FR-8  The receiver shall detect and handle replayed protected records.
SR-5  Replayed records shall not be accepted as fresh application records.
TR-5  Capture a valid protected record, re-deliver it, and show it is rejected
      -- separately under both AEAD configurations.

Design decisions that are yours to make and to defend in the report
-------------------------------------------------------------------

1.  What counts as "already seen"?  Strict successor checking (``seq ==
    last + 1``) is the simplest exact test, but Section 3.2 puts reliable
    delivery, ordering and retransmission out of scope, so records may legally
    arrive late or out of order.  Decide how much reordering to tolerate and
    say why.
2.  Records too old to classify.  Whatever structure you choose has bounded
    memory, so some records will fall off the end of your history.  Decide
    whether those are accepted or rejected, and argue that the direction you
    picked is the conservative one.
3.  Where in the receive pipeline the check and the state update belong,
    relative to the AEAD open.  This ordering has a direct security
    consequence -- work out what it is before you write the code, because
    ``Receiver.receive`` has to call the two halves in the right places.
4.  Why the sequence number can be trusted for any of this at all.  (Look at
    what ``RecordHeader.aad()`` covers in ``srp/header.py``.)
5.  Scoping.  Streams are keyed by ``(session_id, stream_id)``; explain what
    would go wrong if they were not.

Section 6 requires the chosen strategy to be *documented*, so the reasoning is
part of the deliverable, not an optional extra.

Integration contract -- do not change these names or signatures
---------------------------------------------------------------

``srp/session.py`` imports ``DEFAULT_WINDOW_SIZE`` and ``DEFAULT_MAX_STREAMS``;
``srp/receiver.py`` calls ``ReplayGuard.check`` / ``.commit`` / ``.window_for``
and compares against ``ReplayVerdict`` members.  Everything else inside the
module is yours.  Delete ``MEMBER2_STUB`` when the module is real -- the test
suite keys its "pending" skips off it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

#: Sentinel: this module is still a stub.  Remove it once implemented.
MEMBER2_STUB = True

_TODO = (
    "srp.replay is MEMBER 2's deliverable and is not implemented yet. "
    "See HANDOFF.md."
)

#: Default width of the replay history, in records.  Referenced by
#: :class:`srp.session.SessionPolicy`; tune it if your design calls for a
#: different default, but keep the name.
DEFAULT_WINDOW_SIZE = 64

#: Default cap on the number of concurrently tracked streams, so that receiver
#: state stays bounded.
DEFAULT_MAX_STREAMS = 1024

#: A stream is identified by the session it belongs to and its stream id, both
#: of which are authenticated header fields.
StreamKey = tuple[bytes, int]


class ReplayVerdict(str, Enum):
    """Result of consulting the replay state.

    These four outcomes are part of the interface: ``srp/receiver.py`` maps
    them onto :class:`~srp.errors.RejectReason` values that already exist.
    """

    #: Not seen before; may proceed to authentication.
    FRESH = "FRESH"
    #: Already accepted on this stream -- a replay.
    DUPLICATE = "DUPLICATE"
    #: Too old to classify with confidence.
    TOO_OLD = "TOO_OLD"
    #: Sequence number outside the representable range.
    INVALID = "INVALID"


@dataclass(frozen=True, slots=True)
class WindowSnapshot:
    """Immutable view of replay state, for logging and test evidence.

    TR-5 has to *show* the state, not just assert on it, so the demo and the
    report both render this.  Adjust the fields to match whatever structure you
    implement.
    """

    highest_seq: int
    window_size: int
    accepted: int
    bitmap: int

    def describe(self) -> str:
        """One-line human-readable rendering for evidence transcripts."""
        raise NotImplementedError(_TODO)


class ReplayWindow:
    """Replay history for a single logical stream.

    Parameters
    ----------
    size:
        How much history to keep, in records.
    """

    def __init__(self, size: int = DEFAULT_WINDOW_SIZE) -> None:
        raise NotImplementedError(_TODO)

    # -- query: must not modify any state ---------------------------------
    #
    # This is called on attacker-controlled input before anything has been
    # authenticated.  Work out what that implies and keep it true.

    def check(self, seq: int) -> ReplayVerdict:
        """Classify ``seq`` without modifying any state."""
        raise NotImplementedError(_TODO)

    def seen(self, seq: int) -> bool:
        """Whether ``seq`` is recorded as accepted (test/evidence helper)."""
        raise NotImplementedError(_TODO)

    # -- commit: state change, authenticated input only --------------------

    def commit(self, seq: int) -> bool:
        """Record ``seq`` as accepted.  Returns True if state changed.

        Should be total and idempotent: committing a duplicate or an
        out-of-history value must be a no-op, not an error.
        """
        raise NotImplementedError(_TODO)

    # -- introspection -----------------------------------------------------

    @property
    def highest_seq(self) -> int:
        """Highest accepted sequence number, or ``-1`` if none yet."""
        raise NotImplementedError(_TODO)

    @property
    def size(self) -> int:
        raise NotImplementedError(_TODO)

    @property
    def accepted(self) -> int:
        raise NotImplementedError(_TODO)

    def snapshot(self) -> WindowSnapshot:
        raise NotImplementedError(_TODO)


class ReplayGuard:
    """Manages one :class:`ReplayWindow` per stream.

    Parameters
    ----------
    window_size:
        Passed through to each per-stream window.
    max_streams:
        Upper bound on tracked streams.  Decide what happens when it is hit,
        and what stops an attacker from driving the receiver into that state.
    """

    def __init__(
        self,
        window_size: int = DEFAULT_WINDOW_SIZE,
        *,
        max_streams: int = DEFAULT_MAX_STREAMS,
    ) -> None:
        raise NotImplementedError(_TODO)

    def check(self, key: StreamKey, seq: int) -> ReplayVerdict:
        """Pre-authentication query.  Must not allocate and must not mutate."""
        raise NotImplementedError(_TODO)

    def commit(self, key: StreamKey, seq: int) -> bool:
        """Post-authentication update."""
        raise NotImplementedError(_TODO)

    # -- introspection -----------------------------------------------------

    def window_for(self, key: StreamKey) -> ReplayWindow | None:
        raise NotImplementedError(_TODO)

    @property
    def tracked_streams(self) -> int:
        raise NotImplementedError(_TODO)

    @property
    def evictions(self) -> int:
        raise NotImplementedError(_TODO)

    @property
    def window_size(self) -> int:
        raise NotImplementedError(_TODO)

    def reset(self) -> None:
        """Drop all replay state (used when starting a fresh key epoch)."""
        raise NotImplementedError(_TODO)


__all__ = [
    "DEFAULT_WINDOW_SIZE",
    "DEFAULT_MAX_STREAMS",
    "ReplayVerdict",
    "WindowSnapshot",
    "ReplayWindow",
    "ReplayGuard",
    "StreamKey",
]
