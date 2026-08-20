"""TR-5 -- Replay Test.

Demonstrates that replayed protected application records are detected and
handled according to the documented replay handling strategy (sliding-window
bitmap).

A replayed record is **byte-identical** to a genuine one, so its AEAD tag
verifies perfectly.  The AEAD alone cannot detect replay — that is precisely
why FR-8 requires a separate mechanism.  This file demonstrates that the
rejection comes from the replay logic, not from a coincidentally broken tag.
"""

from __future__ import annotations

import pytest

from srp import (
    RejectReason,
    SessionPolicy,
    create_channel,
)


# ---- Exact replay --------------------------------------------------------


class TestExactReplay:
    """A byte-identical copy of an accepted record is rejected."""

    def test_replay_rejected(self, channel, actor):
        wire = channel.send(b"replay target")
        v1 = channel.deliver(wire)
        assert v1.accepted

        replayed = actor.replay(wire)
        v2 = channel.deliver(replayed)
        assert v2.rejected
        assert v2.reason is RejectReason.REPLAY_DETECTED
        assert v2.plaintext is None

    def test_replayed_bytes_would_authenticate(self, channel, actor):
        """The replayed bytes are identical, so the AEAD would succeed.
        The rejection provably comes from the replay logic."""
        wire = channel.send(b"auth proof")
        v1 = channel.deliver(wire)
        assert v1.accepted

        replayed = actor.replay(wire)
        assert replayed == wire  # byte-identical
        v2 = channel.deliver(replayed)
        assert v2.rejected
        assert v2.reason is RejectReason.REPLAY_DETECTED


class TestRepeatedReplays:
    """The replay state does not decay — repeated replays stay rejected."""

    def test_many_replays(self, channel, actor):
        wire = channel.send(b"repeat target")
        channel.deliver(wire)

        for _ in range(50):
            v = channel.deliver(actor.replay(wire))
            assert v.rejected
            assert v.reason is RejectReason.REPLAY_DETECTED
            assert v.plaintext is None


# ---- Out-of-order delivery -----------------------------------------------


class TestOutOfOrder:
    """Legitimate out-of-order delivery within tolerance is accepted.

    Section 3.2 puts ordering out of scope, so records may legitimately
    arrive late or out of order.
    """

    def test_out_of_order_accepted(self, channel):
        # Send 5 records but deliver out of order.
        wires = [channel.send(f"record {i}".encode()) for i in range(5)]
        delivery_order = [0, 2, 4, 1, 3]
        for idx in delivery_order:
            v = channel.deliver(wires[idx])
            assert v.accepted, f"record {idx} should be accepted out of order"
            assert v.plaintext == f"record {idx}".encode()

    def test_duplicate_of_out_of_order_caught(self, channel, actor):
        """A duplicate of an out-of-order record is still caught."""
        wires = [channel.send(f"ooo {i}".encode()) for i in range(5)]
        # Deliver out of order: 0, 3, 1
        channel.deliver(wires[0])
        channel.deliver(wires[3])
        channel.deliver(wires[1])

        # Replay record 1 — already accepted.
        v = channel.deliver(actor.replay(wires[1]))
        assert v.rejected
        assert v.reason is RejectReason.REPLAY_DETECTED


# ---- Stale records (too old to classify) ---------------------------------


class TestStaleRecords:
    """Records too old for the replay window are rejected as STALE_RECORD."""

    def test_stale_boundary(self, suite_name, small_policy):
        """With window_size=8, seq 0 becomes stale after highest_seq >= 8."""
        ch = create_channel(suite_name, policy=small_policy)

        # Send and deliver records 0..8.
        wires = [ch.send(f"rec {i}".encode()) for i in range(9)]

        # Deliver seq 0 first.
        v0 = ch.deliver(wires[0])
        assert v0.accepted

        # Skip to seq 8 to push seq 0 out of the window.
        # Window covers [8-7, 8] = [1, 8].  Seq 0 is now stale.
        v8 = ch.deliver(wires[8])
        assert v8.accepted

        # Replay of seq 0 — stale, not replay (it's off the bitmap).
        v_stale = ch.deliver(wires[0])
        assert v_stale.rejected
        assert v_stale.reason is RejectReason.STALE_RECORD
        assert v_stale.plaintext is None

    def test_just_inside_window(self, suite_name, small_policy):
        """A record just inside the window is still trackable."""
        ch = create_channel(suite_name, policy=small_policy)

        wires = [ch.send(f"rec {i}".encode()) for i in range(9)]
        ch.deliver(wires[0])
        ch.deliver(wires[8])

        # Seq 1 is at boundary: highest=8, diff=7, window_size=8 → inside.
        v1 = ch.deliver(wires[1])
        assert v1.accepted, "seq 1 should be inside the window (diff=7 < 8)"


# ---- Renumbering attacks -------------------------------------------------


class TestRenumbering:
    """Changing seq in the header invalidates the AAD, so the tag fails.
    AUTH_FAILED rather than replay catches this."""

    def test_renumber_rejected(self, channel, actor):
        wire = channel.send(b"renumber target")
        channel.deliver(wire)

        tampered = actor.renumber(wire, seq=9999)
        v = channel.deliver(tampered)
        assert v.rejected
        assert v.reason is RejectReason.AUTH_FAILED
        assert v.plaintext is None


# ---- Sequence-number poisoning -------------------------------------------


class TestSequenceNumberPoisoning:
    """The most important test in this file.

    A forged record carrying an enormous sequence number must NOT move the
    replay state.  If it could, a single unauthenticated packet would be a
    permanent denial of service — all subsequent genuine records would fall
    behind the window.
    """

    def test_forged_high_seq_does_not_poison_state(self, channel, actor):
        # Accept a few genuine records.
        wires = [channel.send(f"gen {i}".encode()) for i in range(3)]
        for w in wires:
            v = channel.deliver(w)
            assert v.accepted

        # Forge a record with an enormous seq.
        forged = actor.renumber(wires[0], seq=999999)
        v_forged = channel.deliver(forged)
        assert v_forged.rejected  # AUTH_FAILED (AAD changed)

        # Genuine record with seq=3 should still be accepted.
        genuine = channel.send(b"post-poison genuine")
        v_genuine = channel.deliver(genuine)
        assert v_genuine.accepted
        assert v_genuine.plaintext == b"post-poison genuine"

        # Verify the replay state was not advanced.
        stream_key = (channel.session_id, channel.sender.stream_id)
        window = channel.receiver.replay_guard.window_for(stream_key)
        assert window is not None
        assert window.highest_seq == 3  # Not 999999


# ---- Cross-stream and cross-session replay --------------------------------


class TestCrossStreamReplay:
    """A record replayed onto a different stream is rejected by AUTH_FAILED
    (since stream_id is in the AAD)."""

    def test_cross_stream_rejected(self, channel, actor):
        wire = channel.send(b"stream 1 data")
        channel.deliver(wire)

        tampered = actor.redirect_stream(wire, stream_id=99)
        v = channel.deliver(tampered)
        assert v.rejected
        assert v.reason is RejectReason.AUTH_FAILED
        assert v.plaintext is None


class TestCrossSessionReplay:
    """A record replayed into a different session is rejected."""

    def test_cross_session_rejected(self, suite_name, actor):
        ch1 = create_channel(suite_name)
        ch2 = create_channel(suite_name)

        wire = ch1.send(b"session 1 data")
        ch1.deliver(wire)

        # Deliver to a different session's receiver.
        v = ch2.deliver(wire)
        assert v.rejected
        assert v.plaintext is None


class TestIndependentStreamState:
    """Separate streams keep independent replay state."""

    def test_two_streams(self, suite_name):
        policy = SessionPolicy(pin_session=False)
        ch1 = create_channel(suite_name, stream_id=1, policy=policy)
        ch2 = create_channel(
            suite_name,
            key=ch1.key,
            session_id=ch1.session_id,
            stream_id=2,
            policy=policy,
        )

        # Both streams share the same receiver.  Use ch1's receiver for both.
        wire_s1 = ch1.send(b"stream 1")
        wire_s2 = ch2.send(b"stream 2")

        v1 = ch1.receiver.receive(wire_s1)
        v2 = ch1.receiver.receive(wire_s2)
        assert v1.accepted
        assert v2.accepted

        # Replay stream 1 — rejected on stream 1's state.
        v1r = ch1.receiver.receive(wire_s1)
        assert v1r.rejected
        assert v1r.reason is RejectReason.REPLAY_DETECTED

        # Stream 2 seq 0 was already accepted — also a replay.
        v2r = ch1.receiver.receive(wire_s2)
        assert v2r.rejected
        assert v2r.reason is RejectReason.REPLAY_DETECTED


# ---- Volume test ---------------------------------------------------------


class TestVolumeNoFalsePositives:
    """~10,000 genuine records with zero false replay positives.

    This pairs with TR-7 and makes the replay strategy credible rather than
    merely conservative.
    """

    def test_10k_records(self, suite_name):
        policy = SessionPolicy(record_limit=10_100)
        ch = create_channel(suite_name, policy=policy)
        false_positives = 0
        for i in range(10_000):
            wire = ch.send(f"record {i}".encode())
            verdict = ch.deliver(wire)
            if not verdict.accepted:
                false_positives += 1
        assert false_positives == 0, (
            f"{false_positives} false replay positives in 10,000 records"
        )


# ---- Window state rendering ---------------------------------------------


class TestWindowSnapshotRendering:
    """Render the replay state via WindowSnapshot.describe() so the report
    can show the mechanism working, not just its verdict."""

    def test_snapshot_describe(self, channel):
        wires = [channel.send(f"snap {i}".encode()) for i in range(5)]
        # Deliver in order: 0, 1, 2, 4 (skip 3).
        for idx in [0, 1, 2, 4]:
            v = channel.deliver(wires[idx])
            assert v.accepted

        stream_key = (channel.session_id, channel.sender.stream_id)
        window = channel.receiver.replay_guard.window_for(stream_key)
        assert window is not None
        snapshot = window.snapshot()

        desc = snapshot.describe()
        assert "highest_seq=4" in desc
        assert "accepted=4" in desc
        # The bitmap should show seq 3 as not-seen.
        # Bit 0 = seq 4 (seen), bit 1 = seq 3 (not seen), bit 2 = seq 2 (seen)
        # bit 3 = seq 1 (seen), bit 4 = seq 0 (seen).  Binary: 11011 → "11011"
        # The describe() format shows MSB on left: bitmap contains "11011".
        assert snapshot.bitmap & 1  # seq 4 is seen
        assert not (snapshot.bitmap & 2)  # seq 3 is NOT seen
        assert snapshot.bitmap & 4  # seq 2 is seen
