"""TR-7 -- Nonce Management Verification.

Objective
    Demonstrate that the nonce management approach satisfies the requirements of
    the selected AEAD configuration, including evidence that nonce reuse does
    not occur during normal operation, under both AEAD configurations.

Approach under test (see :mod:`srp.nonce`)
    96-bit nonce = 32-bit per-session random prefix || 64-bit monotonic counter,
    the deterministic construction of NIST SP 800-38D s8.2.1.  A per-key record
    budget is enforced and the sender fails closed on exhaustion.

The guideline in Section 6 suggests ~10,000 records under one key; the volume
test below does exactly that and checks the nonces for uniqueness directly
rather than inferring it.
"""

from __future__ import annotations

import math

import pytest

from srp import (
    NONCE_LEN,
    ConfigurationError,
    NonceExhaustedError,
    NonceManager,
    Receiver,
    Sender,
    SessionPolicy,
    create_channel,
    derive_nonce,
    new_session_id,
    parse_record,
    random_nonce_collision_probability,
    suite_class,
)

RECORD_COUNT = 10_000


def test_ten_thousand_nonces_under_one_key_are_all_distinct(channel):
    """The headline TR-7 evidence.

    Every nonce actually used to protect a record is reconstructed from the
    record's own header and collected.  Uniqueness is then checked directly.
    """
    nonces = []
    for i in range(RECORD_COUNT):
        wire = channel.send(f"application record {i}".encode())
        header = parse_record(wire).header
        nonces.append(derive_nonce(header.nonce_prefix, header.seq))

    assert len(nonces) == RECORD_COUNT
    assert len(set(nonces)) == RECORD_COUNT, "a nonce was reused"
    assert all(len(n) == NONCE_LEN == 12 for n in nonces)


def test_sequence_numbers_are_strictly_increasing(channel):
    """Uniqueness is structural, not probabilistic: the counter cannot repeat."""
    seqs = [
        parse_record(channel.send(b"record")).header.seq
        for _ in range(RECORD_COUNT)
    ]

    assert seqs == list(range(RECORD_COUNT))
    assert all(b - a == 1 for a, b in zip(seqs, seqs[1:]))


def test_nonce_prefix_is_constant_within_a_session(channel):
    """The prefix identifies the session; only the counter varies."""
    prefixes = {
        parse_record(channel.send(b"record")).header.nonce_prefix
        for _ in range(1000)
    }

    assert prefixes == {channel.sender.nonce_prefix}
    assert len(channel.sender.nonce_prefix) == 4


def test_nonce_structure_is_prefix_then_big_endian_counter(channel):
    """The construction is exactly as documented."""
    for expected_seq in (0, 1, 255, 256, 65535):
        while channel.sender.next_seq < expected_seq:
            channel.send(b"skip")
        wire = channel.send(b"probe")
        header = parse_record(wire).header

        nonce = derive_nonce(header.nonce_prefix, header.seq)
        assert nonce[:4] == channel.sender.nonce_prefix
        assert nonce[4:] == header.seq.to_bytes(8, "big")
        assert len(nonce) == 12


def test_all_ten_thousand_records_verify(channel):
    """A reused nonce would not merely be unsafe, it would be observable here.

    Every record is delivered and must be accepted; combined with the
    uniqueness check above, this shows the sender and receiver agree on the
    nonce for all 10,000 records.
    """
    for i in range(RECORD_COUNT):
        verdict = channel.deliver(channel.send(i.to_bytes(4, "big")))
        assert verdict.accepted

    assert channel.receiver.stats.accepted == RECORD_COUNT
    assert channel.receiver.stats.rejected_total == 0
    assert channel.sender.nonces.issued == RECORD_COUNT


def test_receiver_reconstructs_the_senders_nonce_exactly(channel):
    """Sender and receiver derive the nonce from the same authenticated fields."""
    for _ in range(100):
        seq_before = channel.sender.next_seq
        wire = channel.send(b"nonce agreement probe")
        header = parse_record(wire).header

        assert header.seq == seq_before
        assert derive_nonce(header.nonce_prefix, header.seq) == derive_nonce(
            channel.sender.nonce_prefix, seq_before
        )
        assert channel.deliver(wire).accepted


def test_distinct_sessions_get_distinct_nonce_prefixes(suite_name):
    """Restarting under the same key does not restart the nonce space.

    A bare counter would re-emit nonce 0 on every restart -- the classic
    catastrophic failure this prefix exists to prevent.
    """
    cls = suite_class(suite_name)
    shared_key = cls.generate_key()  # deliberately the *same* long-term key

    prefixes = set()
    first_nonces = set()
    for _ in range(200):
        sender = Sender(cls(shared_key), new_session_id())
        header = parse_record(sender.protect(b"first record of a session")).header
        prefixes.add(header.nonce_prefix)
        first_nonces.add(derive_nonce(header.nonce_prefix, header.seq))
        assert header.seq == 0  # the counter does restart ...

    # ... but the nonce does not, because the prefix is fresh each time.
    assert len(prefixes) == 200
    assert len(first_nonces) == 200


def test_concurrent_streams_do_not_share_a_nonce_space(suite_name):
    """Two senders under one key get independent prefixes."""
    cls = suite_class(suite_name)
    key = cls.generate_key()
    session_id = new_session_id()

    senders = [Sender(cls(key), session_id, stream_id=i) for i in range(1, 33)]
    assert len({s.nonce_prefix for s in senders}) == 32

    nonces = set()
    for sender in senders:
        for _ in range(100):
            header = parse_record(sender.protect(b"record")).header
            nonces.add(derive_nonce(header.nonce_prefix, header.seq))

    assert len(nonces) == 32 * 100


def test_sender_fails_closed_when_the_record_budget_is_exhausted(suite_name):
    """SR-3: the sender refuses to emit rather than reuse a nonce."""
    policy = SessionPolicy(record_limit=64)
    channel = create_channel(suite_name, policy=policy)

    nonces = set()
    for _ in range(64):
        header = parse_record(channel.send(b"record")).header
        nonces.add(derive_nonce(header.nonce_prefix, header.seq))
    assert len(nonces) == 64

    with pytest.raises(NonceExhaustedError, match="record budget of 64 exhausted"):
        channel.send(b"one record too many")


def test_exhaustion_is_permanent_and_emits_nothing(suite_name):
    """Retrying after exhaustion yields the same error, never a reused nonce."""
    policy = SessionPolicy(record_limit=8)
    channel = create_channel(suite_name, policy=policy)

    for _ in range(8):
        channel.send(b"record")

    seq_at_exhaustion = channel.sender.next_seq
    issued_at_exhaustion = channel.sender.nonces.issued

    for _ in range(10):
        with pytest.raises(NonceExhaustedError):
            channel.send(b"rejected")

    # The counter did not advance, and no record escaped.
    assert channel.sender.next_seq == seq_at_exhaustion
    assert channel.sender.nonces.issued == issued_at_exhaustion
    assert channel.sender.stats.records_protected == 8
    assert channel.sender.nonces.remaining == 0
    assert channel.sender.nonces.exhausted


def test_default_record_budget_matches_the_documented_policy(suite_name):
    """FR-9: both configurations deploy the same budget, 2**24 records."""
    channel = create_channel(suite_name)
    assert channel.policy.record_limit == 2 ** 24
    assert channel.sender.nonces.record_limit == 2 ** 24
    assert channel.sender.nonces.remaining == 2 ** 24


def test_nonce_manager_rejects_invalid_configuration():
    """Boundary conditions on the manager itself."""
    with pytest.raises(ConfigurationError):
        NonceManager(b"\x00\x00")                      # prefix too short
    with pytest.raises(ConfigurationError):
        NonceManager(record_limit=0)                   # empty budget
    with pytest.raises(ConfigurationError):
        NonceManager(start=-1)                         # negative start
    with pytest.raises(ConfigurationError):
        NonceManager(start=2 ** 64 - 4, record_limit=8)  # would overflow the counter


def test_derive_nonce_rejects_out_of_range_input():
    with pytest.raises(ConfigurationError):
        derive_nonce(b"\x00" * 4, 2 ** 64)
    with pytest.raises(ConfigurationError):
        derive_nonce(b"\x00" * 3, 0)


def test_counter_beats_random_nonces_by_the_birthday_bound():
    """Quantifies why the counter construction was chosen over random nonces.

    With 96-bit random nonces the collision probability grows as q**2 / 2**97.
    The counter's is exactly zero until the 64-bit space wraps.  These are the
    figures quoted in the report's nonce-management discussion.
    """
    # At the assignment's suggested volume the risk is small but not zero ...
    assert 0 < random_nonce_collision_probability(10_000) < 2 ** -68

    # ... and it grows quadratically: 100x the records is ~10000x the risk.
    small = random_nonce_collision_probability(10 ** 4)
    large = random_nonce_collision_probability(10 ** 6)
    assert large / small == pytest.approx(10_000, rel=0.01)

    # NIST SP 800-38D s8.3 caps random nonce construction at 2**32 invocations
    # per key.  That cap is exactly what holds the collision probability at
    # roughly 2**-33, i.e. within the 2**-32 budget the standard targets.
    at_nist_limit = random_nonce_collision_probability(2 ** 32)
    assert 2 ** -34 < at_nist_limit < 2 ** -32

    # Past the cap it degrades fast: by 2**49 records a repeat is more likely
    # than not.  A counter never gets there -- its probability is exactly zero
    # for the entire 2**64 space.
    assert random_nonce_collision_probability(2 ** 49) > 0.5

    # The deployed budget of 2**24 records keeps even the random construction's
    # risk near 2**-49, and the counter's risk is zero regardless.
    assert random_nonce_collision_probability(2 ** 24) < 2 ** -48


def test_nonce_never_repeats_across_a_simulated_restart(suite_name):
    """End-to-end: 5 sessions x 2,000 records under one key, all nonces distinct."""
    cls = suite_class(suite_name)
    key = cls.generate_key()

    all_nonces = set()
    total = 0
    for _ in range(5):
        session_id = new_session_id()
        sender = Sender(cls(key), session_id)
        receiver = Receiver(cls(key), expected_session_id=session_id)
        for i in range(2_000):
            wire = sender.protect(i.to_bytes(4, "big"))
            header = parse_record(wire).header
            all_nonces.add(derive_nonce(header.nonce_prefix, header.seq))
            assert receiver.receive(wire).accepted
            total += 1

    assert total == 10_000
    assert len(all_nonces) == 10_000
