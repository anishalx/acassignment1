"""Replay handling (FR-8, SR-5, TR-5).

Strategy: sliding bitmap window over authenticated sequence numbers
------------------------------------------------------------------

The receiver keeps, per logical stream, the highest sequence number it has
accepted and a bitmap of which of the preceding ``W`` sequence numbers it has
already seen.  This is the anti-replay window of IPsec ESP (RFC 4303 s3.4.3,
with the efficient formulation of RFC 6479), and it is the right shape here for
a specific reason.

Why a window and not "seq must equal last + 1"
----------------------------------------------

Strict successor checking is simpler and gives an exact duplicate test, but it
conflates *replay* with *reordering and loss*.  This assignment explicitly puts
reliable delivery, ordering and retransmission out of scope (Section 3.2), which
means the subsystem must tolerate records arriving late or not at all -- over
UDP, across multiple paths, or from a chunked store fetched out of order.  A
strict rule would reject every such record as an attack and the subsystem would
be unusable on exactly the transports it is meant for.

A window keeps the duplicate test exact for anything recent while letting
genuine reordering through, and degrades honestly: a record older than the
window is rejected as ``TOO_OLD`` rather than silently accepted, because at that
distance the receiver has genuinely forgotten whether it saw it before.  That is
a conservative failure, which is the correct direction.

``W`` = 64 by default: one machine word of history, ample for the reordering any
sane transport produces, and cheap.  It is configurable; the cost is one bit of
state per record of tolerated reordering.

Why the sequence number can be trusted for this
-----------------------------------------------

Only because it is authenticated.  ``seq`` lives in the record header, the
header is the AAD, and the AAD is covered by the tag (see :mod:`srp.header`).
An attacker cannot alter a captured record's sequence number without breaking
authentication, so the window is comparing values the legitimate sender chose.
Replay protection layered over an *unauthenticated* counter would be theatre:
the attacker would simply renumber the record they wanted to replay.

The check/commit split
----------------------

The window is queried before decryption but **only updated after the record
authenticates**.  Both halves matter:

*Checking first* means an obvious duplicate costs a bitmap lookup instead of a
full decryption, so a flood of replayed records cannot be used to burn CPU.

*Committing only after authentication* is the security-critical half.  If the
window advanced on the strength of an unverified header, anyone could send a
single forged record carrying ``seq = 2**64 - 1`` and permanently push the
window past every sequence number the real sender will ever use -- a one-packet
denial of service.  Because ``commit`` runs only on records whose tag verified,
attacker-supplied sequence numbers never reach the window state at all.

The same reasoning drives per-stream window *creation*: a window is allocated
only once a record for that stream has authenticated, so unauthenticated traffic
cannot make the receiver allocate unbounded state.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum

from .errors import ConfigurationError
from .nonce import SEQ_SPACE

#: Default window width, in records.
DEFAULT_WINDOW_SIZE = 64

#: Default cap on the number of concurrently tracked streams.  Only
#: authenticated traffic can create entries, so this bounds memory against a
#: chatty legitimate peer rather than against an attacker.
DEFAULT_MAX_STREAMS = 1024


class ReplayVerdict(str, Enum):
    """Result of consulting the replay window."""

    #: Not seen before; may proceed to authentication.
    FRESH = "FRESH"
    #: Already accepted on this stream -- a replay.
    DUPLICATE = "DUPLICATE"
    #: Older than the window; replay cannot be ruled out, so reject.
    TOO_OLD = "TOO_OLD"
    #: Sequence number outside the representable range.
    INVALID = "INVALID"


@dataclass(frozen=True, slots=True)
class WindowSnapshot:
    """Immutable view of a window's state, for logging and test evidence."""

    highest_seq: int
    window_size: int
    accepted: int
    bitmap: int

    def describe(self) -> str:
        if self.highest_seq < 0:
            return f"window(empty, size={self.window_size})"
        width = min(self.window_size, self.highest_seq + 1)
        bits = "".join(
            "1" if (self.bitmap >> i) & 1 else "0" for i in range(width)
        )
        return (
            f"window(highest={self.highest_seq}, size={self.window_size}, "
            f"accepted={self.accepted}, bits[newest..oldest]={bits})"
        )


class ReplayWindow:
    """Sliding bitmap replay window for a single logical stream.

    Bit ``i`` of the bitmap records whether sequence number
    ``highest_seq - i`` has been accepted; bit 0 is therefore always set once
    the window is non-empty.  Python's arbitrary-precision integers make the
    shift-and-mask formulation of RFC 6479 exact at any window size.
    """

    __slots__ = ("_size", "_mask", "_highest", "_bitmap", "_accepted")

    def __init__(self, size: int = DEFAULT_WINDOW_SIZE) -> None:
        if not 1 <= size <= 1 << 16:
            raise ConfigurationError(f"window size {size} out of range 1..65536")
        self._size = size
        self._mask = (1 << size) - 1
        self._highest = -1  # sentinel: nothing accepted yet
        self._bitmap = 0
        self._accepted = 0

    # -- query (no state change; safe on unauthenticated input) -------------

    def check(self, seq: int) -> ReplayVerdict:
        """Classify ``seq`` without modifying any state.

        Safe to call on an attacker-controlled sequence number precisely
        because it is pure.
        """
        if not 0 <= seq < SEQ_SPACE:
            return ReplayVerdict.INVALID
        if self._highest < 0:
            return ReplayVerdict.FRESH
        if seq > self._highest:
            return ReplayVerdict.FRESH
        offset = self._highest - seq
        if offset >= self._size:
            return ReplayVerdict.TOO_OLD
        if (self._bitmap >> offset) & 1:
            return ReplayVerdict.DUPLICATE
        return ReplayVerdict.FRESH  # in-window gap: genuine out-of-order arrival

    def seen(self, seq: int) -> bool:
        """Whether ``seq`` is recorded as accepted (test/evidence helper)."""
        return self.check(seq) is ReplayVerdict.DUPLICATE

    # -- commit (state change; authenticated input only) -------------------

    def commit(self, seq: int) -> bool:
        """Record ``seq`` as accepted.  Call **only** after the tag verified.

        Returns ``True`` if the window state changed.  Idempotent and total:
        committing a duplicate or an out-of-window value is a no-op rather than
        an error, so a caller cannot corrupt the window by mis-sequencing calls.
        """
        if not 0 <= seq < SEQ_SPACE:
            raise ConfigurationError(f"seq {seq} outside 64-bit range")

        if self._highest < 0:
            self._highest = seq
            self._bitmap = 1
        elif seq > self._highest:
            shift = seq - self._highest
            if shift >= self._size:
                # The jump is larger than the window: all history falls out.
                self._bitmap = 1
            else:
                self._bitmap = ((self._bitmap << shift) | 1) & self._mask
            self._highest = seq
        else:
            offset = self._highest - seq
            if offset >= self._size:
                return False  # too old to record; nothing to remember
            if (self._bitmap >> offset) & 1:
                return False  # already recorded
            self._bitmap |= 1 << offset

        self._accepted += 1
        return True

    # -- introspection -----------------------------------------------------

    @property
    def highest_seq(self) -> int:
        """Highest accepted sequence number, or ``-1`` if none yet."""
        return self._highest

    @property
    def size(self) -> int:
        return self._size

    @property
    def accepted(self) -> int:
        return self._accepted

    def snapshot(self) -> WindowSnapshot:
        return WindowSnapshot(
            highest_seq=self._highest,
            window_size=self._size,
            accepted=self._accepted,
            bitmap=self._bitmap,
        )

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<ReplayWindow {self.snapshot().describe()}>"


#: A stream is identified by the session it belongs to and its stream id, both
#: of which are authenticated header fields.
StreamKey = tuple[bytes, int]


class ReplayGuard:
    """Manages one :class:`ReplayWindow` per authenticated stream.

    Streams are keyed by ``(session_id, stream_id)`` so that a record valid on
    one stream cannot be re-injected on another, and so that a new session
    starts with clean replay state.
    """

    __slots__ = ("_window_size", "_max_streams", "_windows", "_evictions")

    def __init__(
        self,
        window_size: int = DEFAULT_WINDOW_SIZE,
        *,
        max_streams: int = DEFAULT_MAX_STREAMS,
    ) -> None:
        if max_streams < 1:
            raise ConfigurationError("max_streams must be positive")
        # Validate eagerly so a bad window size fails at construction, not on
        # the first record.
        ReplayWindow(window_size)
        self._window_size = window_size
        self._max_streams = max_streams
        self._windows: OrderedDict[StreamKey, ReplayWindow] = OrderedDict()
        self._evictions = 0

    def check(self, key: StreamKey, seq: int) -> ReplayVerdict:
        """Pre-authentication query.  Never allocates, never mutates.

        An unknown stream yields ``FRESH``: there is no history to contradict
        the record, and allocating a window here -- before the record has
        authenticated -- is exactly the state-exhaustion hole this design
        avoids.
        """
        window = self._windows.get(key)
        if window is None:
            if not 0 <= seq < SEQ_SPACE:
                return ReplayVerdict.INVALID
            return ReplayVerdict.FRESH
        return window.check(seq)

    def commit(self, key: StreamKey, seq: int) -> bool:
        """Post-authentication update.  Allocates the stream's window if needed."""
        window = self._windows.get(key)
        if window is None:
            window = ReplayWindow(self._window_size)
            self._windows[key] = window
            self._evict_if_needed()
        self._windows.move_to_end(key)
        return window.commit(seq)

    def _evict_if_needed(self) -> None:
        """Bound memory by dropping the least-recently-used stream.

        Eviction loses replay history for that stream, so a record older than
        the eviction could subsequently be replayed.  This is the same bounded-
        memory trade-off IPsec makes.  It is acceptable here because only
        *authenticated* records create windows: an attacker cannot manufacture
        stream churn to force an eviction without first forging a valid record
        for each stream, which is the thing the AEAD already prevents.
        """
        while len(self._windows) > self._max_streams:
            self._windows.popitem(last=False)
            self._evictions += 1

    # -- introspection -----------------------------------------------------

    def window_for(self, key: StreamKey) -> ReplayWindow | None:
        return self._windows.get(key)

    @property
    def tracked_streams(self) -> int:
        return len(self._windows)

    @property
    def evictions(self) -> int:
        return self._evictions

    @property
    def window_size(self) -> int:
        return self._window_size

    def reset(self) -> None:
        """Drop all replay state (used when starting a fresh key epoch)."""
        self._windows.clear()
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
