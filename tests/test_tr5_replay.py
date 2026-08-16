"""TR-5 -- Replay Test.

Objective
    Demonstrate that replay of a previously accepted protected application
    record is detected and handled according to the documented replay handling
    strategy, under both AEAD configurations.

Documented strategy (see :mod:`srp.replay`)
    A sliding bitmap window of ``W`` records per ``(session_id, stream_id)``
    over authenticated sequence numbers.  A record is accepted if its sequence
    number is ahead of the window, or inside it and not yet seen.  It is
    rejected as ``REPLAY_DETECTED`` if already seen, and as ``STALE_RECORD`` if
    it falls below the window, where replay can no longer be ruled out.  The
    window is consulted before decryption and updated only after the tag
    verifies.

Replay is the one attack the AEAD cannot address on its own: a replayed record
is byte-identical to a genuine one, so its tag verifies correctly.  That is why
this mechanism exists as a separate layer, and these tests exercise it as such.
"""

from __future__ import annotations

import pytest

from srp import RejectReason, SessionPolicy, create_channel, parse_record


def test_replay_of_an_accepted_record_is_detected(channel, actor):
    """The canonical TR-5 case."""
    wire = channel.send(b"application record to be replayed")

    first = channel.deliver(wire)
    assert first.accepted
    assert first.plaintext == b"application record to be replayed"

    replayed = actor.replay(wire)
    assert replayed == wire  # a replay is byte-identical, not a modification

    second = channel.deliver(replayed)
    assert second.rejected
    assert second.reason is RejectReason.REPLAY_DETECTED
    assert second.plaintext is None


def test_a_replayed_record_still_has_a_valid_tag(channel, actor):
    """Shows *why* a separate replay mechanism is needed.

    The replayed record authenticates perfectly -- decrypting it directly at the
    AEAD layer succeeds.  Only the replay window distinguishes it from the
    original, which is exactly the gap FR-8 asks the subsystem to close.
    """
    from srp import derive_nonce

    payload = b"valid but repeated"
    wire = channel.send(payload)
    assert channel.deliver(wire).accepted

    record = parse_record(wire)
    nonce = derive_nonce(record.header.nonce_prefix, record.header.seq)
    recovered = channel.receiver.suite.open(
        nonce, record.ciphertext_and_tag, record.header.aad()
    )
    assert recovered == payload  # the cryptography is entirely happy

    # The subsystem is not.
    assert channel.deliver(wire).reason is RejectReason.REPLAY_DETECTED


def test_repeated_replays_are_all_rejected(channel, actor):
    """A flood of replays does not wear the window down."""
    wire = channel.send(b"replay flood target")
    assert channel.deliver(wire).accepted

    for _ in range(100):
        verdict = channel.deliver(actor.replay(wire))
        assert verdict.rejected
        assert verdict.reason is RejectReason.REPLAY_DETECTED

    assert channel.receiver.stats.accepted == 1
    assert channel.receiver.stats.rejected["REPLAY_DETECTED"] == 100


def test_out_of_order_delivery_within_the_window_is_accepted(channel):
    """Reordering is tolerated: it is not an attack, and transport is out of scope."""
    wires = [channel.send(f"record {i}".encode()) for i in range(10)]

    order = [3, 0, 7, 1, 9, 2, 8, 4, 6, 5]
    for index in order:
        verdict = channel.deliver(wires[index])
        assert verdict.accepted, f"record {index} rejected on out-of-order delivery"
        assert verdict.plaintext == f"record {index}".encode()

    assert channel.receiver.stats.accepted == 10
    assert channel.receiver.stats.rejected_total == 0


def test_duplicate_of_an_out_of_order_record_is_detected(channel):
    """The window remembers gaps that have since been filled."""
    wires = [channel.send(f"record {i}".encode()) for i in range(10)]

    assert channel.deliver(wires[9]).accepted  # jump ahead, opening a gap
    assert channel.deliver(wires[4]).accepted  # fill one slot inside the window

    verdict = channel.deliver(wires[4])  # ... and try it again
    assert verdict.rejected
    assert verdict.reason is RejectReason.REPLAY_DETECTED


def test_records_below_the_window_are_rejected_as_stale(suite_name):
    """Beyond the window the receiver has forgotten, so it refuses conservatively."""
    policy = SessionPolicy(replay_window=8)
    channel = create_channel(suite_name, policy=policy)
    wires = [channel.send(f"record {i}".encode()) for i in range(32)]

    assert channel.deliver(wires[19]).accepted  # window now covers seq 12..19

    # seq 12 is the oldest slot still inside the window.
    assert channel.deliver(wires[12]).accepted

    # seq 11 is one step too far back.
    verdict = channel.deliver(wires[11])
    assert verdict.rejected
    assert verdict.reason is RejectReason.STALE_RECORD
    assert verdict.plaintext is None

    # ... as is anything older.
    for index in (0, 5, 10):
        assert channel.deliver(wires[index]).reason is RejectReason.STALE_RECORD


def test_window_state_matches_the_documented_strategy(suite_name):
    """Inspect the window directly, as evidence for the report."""
    policy = SessionPolicy(replay_window=8)
    channel = create_channel(suite_name, policy=policy)
    wires = [channel.send(f"record {i}".encode()) for i in range(16)]

    for index in (0, 1, 2, 5):
        assert channel.deliver(wires[index]).accepted

    window = channel.receiver.window_for_stream(channel.session_id, 1)
    snapshot = window.snapshot()

    assert snapshot.highest_seq == 5
    assert snapshot.accepted == 4
    assert snapshot.window_size == 8
    # bits are newest-first: seq 5,4,3,2,1,0 -> seen at 5,2,1,0
    assert [bool((snapshot.bitmap >> i) & 1) for i in range(6)] == [
        True,   # seq 5
        False,  # seq 4 -- never delivered
        False,  # seq 3 -- never delivered
        True,   # seq 2
        True,   # seq 1
        True,   # seq 0
    ]
    assert window.seen(5) and window.seen(0)
    assert not window.seen(3)


def test_renumbering_a_replayed_record_fails_authentication(channel, actor):
    """The obvious way around the window is blocked by the AAD.

    Changing ``seq`` to slip past the replay check invalidates the tag two ways
    at once: ``seq`` is authenticated as part of the AAD, and it is also an
    input to the nonce.
    """
    wire = channel.send(b"record to renumber")
    assert channel.deliver(wire).accepted

    verdict = channel.deliver(actor.renumber(wire, seq=5000))

    assert verdict.rejected
    assert verdict.reason is RejectReason.AUTH_FAILED
    assert verdict.plaintext is None


def test_forged_high_sequence_number_cannot_poison_the_window(channel, actor):
    """The check/commit split, tested directly.

    If the window advanced on unverified headers, one forged record claiming
    ``seq = 2**63`` would push it past every sequence number the real sender
    will ever use -- a single-packet denial of service.  Because the window is
    committed only after authentication, the forgery leaves no trace.
    """
    wire = channel.send(b"legitimate record 0")
    assert channel.deliver(wire).accepted

    window = channel.receiver.window_for_stream(channel.session_id, 1)
    highest_before = window.highest_seq

    for forged_seq in (2 ** 63, 2 ** 64 - 1, 10 ** 6):
        poison = actor.renumber(channel.send(b"poison"), seq=forged_seq)
        verdict = channel.deliver(poison)
        assert verdict.rejected
        assert verdict.reason is RejectReason.AUTH_FAILED

    assert window.highest_seq == highest_before  # window did not move

    # The channel keeps working normally afterwards.
    for i in range(5):
        assert channel.deliver(channel.send(f"legitimate record {i}".encode())).accepted


def test_replay_onto_a_different_stream_is_rejected(channel, actor):
    """A record cannot be laundered by re-injecting it on another stream."""
    wire = channel.send(b"stream 1 record")
    assert channel.deliver(wire).accepted

    verdict = channel.deliver(actor.redirect_stream(wire, stream_id=2))

    assert verdict.rejected
    assert verdict.reason is RejectReason.AUTH_FAILED
    assert channel.receiver.replay_guard.tracked_streams == 1


def test_replay_across_sessions_is_rejected(suite_name):
    """A record captured in one session cannot be replayed into the next.

    The receiver for a new session starts with clean replay state, so the
    session binding in the AAD -- not the window -- is what stops this.
    """
    from srp import Receiver, Sender, new_session_id, suite_class

    cls = suite_class(suite_name)
    key = cls.generate_key()

    old_session = new_session_id()
    sender = Sender(cls(key), old_session)
    wire = sender.protect(b"record from the previous session")

    new_session = new_session_id()
    receiver = Receiver(cls(key), expected_session_id=new_session)

    verdict = receiver.receive(wire)
    assert verdict.rejected
    assert verdict.reason is RejectReason.SESSION_MISMATCH
    assert verdict.plaintext is None


def test_each_stream_has_an_independent_window(suite_name):
    """Sequence number 0 on stream 2 is not a replay of seq 0 on stream 1."""
    from srp import Receiver, Sender, new_session_id, suite_class

    cls = suite_class(suite_name)
    key = cls.generate_key()
    session_id = new_session_id()
    receiver = Receiver(cls(key), expected_session_id=session_id)

    stream_a = Sender(cls(key), session_id, stream_id=1)
    stream_b = Sender(cls(key), session_id, stream_id=2)

    wire_a = stream_a.protect(b"stream 1 seq 0")
    wire_b = stream_b.protect(b"stream 2 seq 0")

    assert receiver.receive(wire_a).accepted
    assert receiver.receive(wire_b).accepted  # same seq, different stream
    assert receiver.receive(wire_a).reason is RejectReason.REPLAY_DETECTED
    assert receiver.receive(wire_b).reason is RejectReason.REPLAY_DETECTED


def test_ten_thousand_records_no_false_replay_positives(channel):
    """Volume check: in-order delivery of 10,000 records, none misclassified."""
    count = 10_000

    for i in range(count):
        verdict = channel.deliver(channel.send(i.to_bytes(4, "big")))
        assert verdict.accepted

    assert channel.receiver.stats.accepted == count
    assert channel.receiver.stats.rejected_total == 0
    window = channel.receiver.window_for_stream(channel.session_id, 1)
    assert window.highest_seq == count - 1
    assert window.accepted == count
