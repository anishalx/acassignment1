"""TR-1 -- Positive Baseline Test.

Objective
    Demonstrate successful protection, transmission, verification and recovery
    of valid application records between the sender and the receiver, under
    both AEAD configurations.

These tests establish the baseline the negative tests are measured against: if
the happy path did not work, "the receiver rejected it" would prove nothing.
"""

from __future__ import annotations

import random

import pytest

from srp import (
    HEADER_LEN,
    TAG_LEN,
    MAX_PAYLOAD_LEN,
    RecordFlags,
    RecordStatus,
    RecordType,
    create_channel,
    parse_record,
)


def test_single_record_roundtrip(channel):
    """A protected record is recovered byte-for-byte by the receiver."""
    payload = b"application record: sensor=temp value=21.5C ts=1755300000"

    wire = channel.send(payload)
    verdict = channel.deliver(wire)

    assert verdict.accepted
    assert verdict.status is RecordStatus.ACCEPTED
    assert verdict.plaintext == payload
    assert verdict.reason is None


def test_plaintext_never_appears_on_the_wire(channel):
    """SR-1: the protected record does not disclose the application record."""
    payload = b"CONFIDENTIAL-MARKER-9f3a2b" * 8

    wire = channel.send(payload)

    assert payload not in wire
    # Not even a distinctive fragment survives.
    assert b"CONFIDENTIAL-MARKER" not in wire
    # The ciphertext body differs from the plaintext at essentially every byte.
    ciphertext = parse_record(wire).ciphertext
    assert ciphertext != payload
    matching = sum(1 for a, b in zip(ciphertext, payload) if a == b)
    assert matching < len(payload) // 4


def test_many_records_of_varied_sizes(channel, payloads):
    """FR-1: each application record is protected and recovered independently."""
    wires = [channel.send(p) for p in payloads]
    verdicts = [channel.deliver(w) for w in wires]

    assert all(v.accepted for v in verdicts)
    assert [v.plaintext for v in verdicts] == payloads


def test_empty_record_is_supported(channel):
    """A zero-length application record is still authenticated."""
    wire = channel.send(b"")
    verdict = channel.deliver(wire)

    assert verdict.accepted
    assert verdict.plaintext == b""
    assert len(wire) == HEADER_LEN + TAG_LEN  # 56 bytes: pure overhead


def test_large_record_roundtrip(channel):
    """A 64 KiB record -- the largest size TR-8 measures -- round-trips."""
    payload = random.Random(1).randbytes(65536)

    verdict = channel.roundtrip(payload)

    assert verdict.accepted
    assert verdict.plaintext == payload


def test_wire_overhead_is_fixed_and_minimal(channel):
    """Overhead is exactly 40 B header + 16 B tag, independent of payload size."""
    for size in (0, 1, 64, 1024, 65536):
        wire = channel.send(bytes(size))
        assert len(wire) == size + HEADER_LEN + TAG_LEN
        assert len(wire) - size == 56


def test_header_fields_are_populated_correctly(channel):
    """The cleartext header describes the record accurately."""
    payload = b"telemetry frame"
    wire = channel.send(payload)
    record = parse_record(wire)

    assert record.header.session_id == channel.session_id
    assert record.header.stream_id == channel.sender.stream_id
    assert record.header.seq == 0
    assert record.header.payload_len == len(payload)
    assert record.header.record_type is RecordType.DATA
    assert record.header.suite_id == channel.sender.suite.suite_id
    assert record.header.nonce_prefix == channel.sender.nonce_prefix
    assert len(record.tag) == TAG_LEN
    assert len(record.ciphertext) == len(payload)


def test_sequence_numbers_advance_monotonically(channel):
    """Each record gets the next sequence number, with no gaps or repeats."""
    wires = [channel.send(f"record {i}".encode()) for i in range(50)]
    seqs = [parse_record(w).header.seq for w in wires]

    assert seqs == list(range(50))
    assert all(channel.deliver(w).accepted for w in wires)


def test_record_types_and_flags_round_trip(channel):
    """Application metadata carried in the header survives verification."""
    wire = channel.send(
        b"stream complete",
        record_type=RecordType.CLOSE,
        flags=RecordFlags.END_OF_STREAM,
    )
    verdict = channel.deliver(wire)

    assert verdict.accepted
    assert verdict.header.record_type is RecordType.CLOSE
    assert verdict.header.flags & RecordFlags.END_OF_STREAM


def test_independent_streams_are_both_accepted(suite_name):
    """Two streams in one session are tracked independently (FR-1)."""
    from srp import Receiver, Sender, new_session_id, suite_class

    cls = suite_class(suite_name)
    key = cls.generate_key()
    session_id = new_session_id()

    stream_a = Sender(cls(key), session_id, stream_id=1)
    stream_b = Sender(cls(key), session_id, stream_id=2)
    receiver = Receiver(cls(key), expected_session_id=session_id)

    # Interleave the two streams; both are accepted, each on its own window.
    for i in range(10):
        assert receiver.receive(stream_a.protect(f"a{i}".encode())).accepted
        assert receiver.receive(stream_b.protect(f"b{i}".encode())).accepted

    assert receiver.replay_guard.tracked_streams == 2
    assert receiver.stats.accepted == 20
    assert receiver.stats.rejected_total == 0


def test_receiver_statistics_reflect_the_run(channel):
    """Counters used as report evidence agree with what was sent."""
    sizes = [0, 10, 100, 1000]
    for size in sizes:
        assert channel.roundtrip(bytes(size)).accepted

    assert channel.sender.stats.records_protected == len(sizes)
    assert channel.sender.stats.plaintext_bytes == sum(sizes)
    assert channel.receiver.stats.accepted == len(sizes)
    assert channel.receiver.stats.plaintext_bytes == sum(sizes)
    assert channel.receiver.stats.rejected_total == 0


def test_oversized_payload_is_refused_by_the_sender(channel):
    """The sender enforces the policy payload limit rather than the receiver."""
    from srp import ConfigurationError

    with pytest.raises(ConfigurationError, match="exceeds policy limit"):
        channel.send(b"\x00" * (MAX_PAYLOAD_LEN + 1))


def test_fresh_channels_produce_different_ciphertexts(suite_name):
    """Identical plaintexts under different keys/sessions look unrelated."""
    payload = b"identical application record"

    first = create_channel(suite_name).send(payload)
    second = create_channel(suite_name).send(payload)

    assert first != second
    # Bodies differ; headers differ only in the random session id and prefix.
    assert first[HEADER_LEN:] != second[HEADER_LEN:]
