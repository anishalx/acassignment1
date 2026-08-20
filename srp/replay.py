"""Replay handling (FR-8, SR-5, TR-5).

Strategy: sliding-window bitmap
-------------------------------

The replay window tracks the highest accepted sequence number and a fixed-width
bitmap recording which of the preceding ``window_size`` sequence numbers have
been accepted.  This is the same approach used by IPsec ESP (RFC 6479) and
DTLS 1.3, chosen because it tolerates out-of-order delivery while keeping
bounded, constant-size state per stream.

Design decisions
----------------

1. **What counts as "already seen"?**  A record is a duplicate if its
   ``(session_id, stream_id, seq)`` triple has already been committed.  The
   window tolerates out-of-order delivery up to ``window_size`` positions behind
   the highest accepted sequence number.  Section 3.2 puts ordering out of
   scope, so strict successor checking would be wrong.

2. **Records too old to classify** (``seq < highest_seq - window_size + 1``)
   are rejected as ``TOO_OLD``.  This is the conservative direction: accepting
   them would mean accepting records for which replay status is unknown.

3. **check() vs commit() ordering.**  ``check()`` runs before the AEAD open and
   must not mutate state.  ``commit()`` runs after the AEAD succeeds.  This
   prevents a forged record with a high sequence number from advancing the
   window and locking out subsequent genuine records.

4. **Why the sequence number can be trusted.**  The sequence number is part of
   the header, which is authenticated verbatim as the AAD.  A forged seq fails
   the AEAD check, so the replay state is never advanced by unauthenticated
   input.

5. **Scoping.**  Streams are keyed by ``(session_id, stream_id)`` so that a
   record legitimately sent on stream 1 cannot be replayed as stream 2, and
   different sessions have independent state.

6. **Bounded state.**  ``max_streams`` caps tracked streams.  Since streams are
   only created in ``commit()`` (post-authentication), an attacker without the
   key cannot drive the receiver to the cap.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

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
    report both render this.
    """

    highest_seq: int
    window_size: int
    accepted: int
    bitmap: int

    def describe(self) -> str:
        """One-line human-readable rendering for evidence transcripts."""
        if self.highest_seq < 0:
            return f"[empty window] size={self.window_size} accepted=0"
        low = max(0, self.highest_seq - self.window_size + 1)
        width = min(self.window_size, self.highest_seq + 1)
        bits = format(self.bitmap & ((1 << width) - 1), f"0{width}b")
        return (
            f"highest_seq={self.highest_seq} range=[{low}..{self.highest_seq}] "
            f"accepted={self.accepted} bitmap={bits}"
        )


class ReplayWindow:
    """Replay history for a single logical stream.

    Uses a sliding bitmap where bit *i* records whether ``highest_seq - i`` has
    been accepted.  The bitmap is an integer, so Python handles arbitrary widths
    without overflow.

    Parameters
    ----------
    size:
        How much history to keep, in records.
    """

    __slots__ = ("_size", "_highest_seq", "_bitmap", "_accepted", "_mask")

    def __init__(self, size: int = DEFAULT_WINDOW_SIZE) -> None:
        self._size = size
        self._highest_seq: int = -1
        self._bitmap: int = 0
        self._accepted: int = 0
        self._mask: int = (1 << size) - 1

    # -- query: must not modify any state ---------------------------------

    def check(self, seq: int) -> ReplayVerdict:
        """Classify ``seq`` without modifying any state.

        This is called on attacker-controlled input before anything has been
        authenticated.  It never mutates, never allocates, and runs in O(1).
        """
        if seq < 0:
            return ReplayVerdict.INVALID

        # First record on this stream: everything is fresh.
        if self._highest_seq < 0:
            return ReplayVerdict.FRESH

        # Ahead of the window: fresh.
        if seq > self._highest_seq:
            return ReplayVerdict.FRESH

        diff = self._highest_seq - seq

        # Too far behind: cannot classify.
        if diff >= self._size:
            return ReplayVerdict.TOO_OLD

        # Within the window: check the bitmap.
        if self._bitmap & (1 << diff):
            return ReplayVerdict.DUPLICATE

        return ReplayVerdict.FRESH

    def seen(self, seq: int) -> bool:
        """Whether ``seq`` is recorded as accepted (test/evidence helper)."""
        if self._highest_seq < 0 or seq < 0:
            return False
        if seq > self._highest_seq:
            return False
        diff = self._highest_seq - seq
        if diff >= self._size:
            return False
        return bool(self._bitmap & (1 << diff))

    # -- commit: state change, authenticated input only --------------------

    def commit(self, seq: int) -> bool:
        """Record ``seq`` as accepted.  Returns True if state changed.

        Total and idempotent: committing a duplicate or an out-of-history value
        is a no-op, not an error.
        """
        if seq < 0:
            return False

        if self._highest_seq < 0 or seq > self._highest_seq:
            # Advance the window.
            if self._highest_seq >= 0:
                shift = seq - self._highest_seq
                if shift >= self._size:
                    # Entire old bitmap is outside the new window.
                    self._bitmap = 1
                else:
                    self._bitmap = ((self._bitmap << shift) | 1) & self._mask
            else:
                self._bitmap = 1
            self._highest_seq = seq
            self._accepted += 1
            return True

        diff = self._highest_seq - seq
        if diff >= self._size:
            # Too old to record; no-op.
            return False

        bit = 1 << diff
        if self._bitmap & bit:
            # Already committed; idempotent no-op.
            return False

        self._bitmap |= bit
        self._accepted += 1
        return True

    # -- introspection -----------------------------------------------------

    @property
    def highest_seq(self) -> int:
        """Highest accepted sequence number, or ``-1`` if none yet."""
        return self._highest_seq

    @property
    def size(self) -> int:
        return self._size

    @property
    def accepted(self) -> int:
        return self._accepted

    def snapshot(self) -> WindowSnapshot:
        return WindowSnapshot(
            highest_seq=self._highest_seq,
            window_size=self._size,
            accepted=self._accepted,
            bitmap=self._bitmap & self._mask,
        )


class ReplayGuard:
    """Manages one :class:`ReplayWindow` per stream.

    Streams are only created in ``commit()`` (post-authentication), so an
    attacker without the key cannot exhaust the ``max_streams`` budget.

    Parameters
    ----------
    window_size:
        Passed through to each per-stream window.
    max_streams:
        Upper bound on tracked streams.  At the cap, new unauthenticated
        streams are reported as ``INVALID`` and new authenticated streams
        cannot be committed.
    """

    __slots__ = ("_window_size", "_max_streams", "_streams", "_evictions")

    def __init__(
        self,
        window_size: int = DEFAULT_WINDOW_SIZE,
        *,
        max_streams: int = DEFAULT_MAX_STREAMS,
    ) -> None:
        self._window_size = window_size
        self._max_streams = max_streams
        self._streams: dict[StreamKey, ReplayWindow] = {}
        self._evictions = 0

    def check(self, key: StreamKey, seq: int) -> ReplayVerdict:
        """Pre-authentication query.  Must not allocate and must not mutate."""
        window = self._streams.get(key)
        if window is None:
            # Unknown stream.  Don't allocate — this is attacker-controlled
            # input.  If we have capacity, treat it as fresh.  If we are at
            # the cap, reject it.
            if len(self._streams) >= self._max_streams:
                return ReplayVerdict.INVALID
            if seq < 0:
                return ReplayVerdict.INVALID
            return ReplayVerdict.FRESH
        return window.check(seq)

    def commit(self, key: StreamKey, seq: int) -> bool:
        """Post-authentication update.

        Creates the stream if it does not exist yet (safe because only
        authenticated records reach this point).
        """
        window = self._streams.get(key)
        if window is None:
            if len(self._streams) >= self._max_streams:
                return False
            window = ReplayWindow(self._window_size)
            self._streams[key] = window
        return window.commit(seq)

    # -- introspection -----------------------------------------------------

    def window_for(self, key: StreamKey) -> ReplayWindow | None:
        return self._streams.get(key)

    @property
    def tracked_streams(self) -> int:
        return len(self._streams)

    @property
    def evictions(self) -> int:
        return self._evictions

    @property
    def window_size(self) -> int:
        return self._window_size

    def reset(self) -> None:
        """Drop all replay state (used when starting a fresh key epoch)."""
        self._streams.clear()
        self._evictions = 0


__all__ = [
    "DEFAULT_WINDOW_SIZE",
    "DEFAULT_MAX_STREAMS",
    "ReplayVerdict",
    "WindowSnapshot",
    "ReplayWindow",
    "ReplayGuard",
    "StreamKey",
]
