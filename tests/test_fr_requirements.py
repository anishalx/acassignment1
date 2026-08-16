"""Functional and security requirements not already covered by a TR test.

Chiefly FR-9 (configuration equivalence) and the fail-closed invariant behind
FR-7 / SR-6, plus the framing validation the negative tests rely on.
"""

from __future__ import annotations

import pytest

from srp import (
    HEADER_LEN,
    MAX_PAYLOAD_LEN,
    MIN_RECORD_LEN,
    SUITE_NAMES,
    TAG_LEN,
    ConfigurationError,
    MaliciousActor,
    MalformedRecordError,
    RecordStatus,
    RejectReason,
    Verdict,
    create_channel,
    parse_record,
    suite_class,
    suite_class_by_id,
)

PAYLOADS = [b"", b"x", b"a typical application record", bytes(4096)]


# --- FR-9: configuration equivalence ------------------------------------


def test_both_configurations_are_supported():
    """FR-2: exactly the two required AEAD configurations, and both usable."""
    assert set(SUITE_NAMES) == {"aes-gcm", "chacha20-poly1305"}
    for name in SUITE_NAMES:
        assert create_channel(name).roundtrip(b"probe").accepted


def test_both_configurations_share_key_nonce_and_tag_sizes():
    """The parameter agreement that makes equivalence structural."""
    classes = [suite_class(n) for n in SUITE_NAMES]
    assert {c.key_len for c in classes} == {32}
    assert {c.nonce_len for c in classes} == {12}
    assert {c.tag_len for c in classes} == {16}


def test_suite_ids_are_distinct_and_resolvable():
    ids = {suite_class(n).suite_id for n in SUITE_NAMES}
    assert ids == {0x01, 0x02}
    for name in SUITE_NAMES:
        cls = suite_class(name)
        assert suite_class_by_id(cls.suite_id) is cls


def test_wire_format_is_identical_across_configurations():
    """Same payload -> same record length and same header layout everywhere."""
    for payload in PAYLOADS:
        lengths = set()
        for name in SUITE_NAMES:
            channel = create_channel(name)
            wire = channel.send(payload)
            lengths.add(len(wire))

            header = parse_record(wire).header
            assert len(wire) == len(payload) + HEADER_LEN + TAG_LEN
            assert header.payload_len == len(payload)
            assert header.suite_id == channel.sender.suite.suite_id
        assert len(lengths) == 1, "record lengths differ between configurations"


def test_identical_scenario_yields_identical_verdicts_across_configurations():
    """FR-9 tested behaviourally: run one script against both, compare outcomes.

    The scenario exercises acceptance, every rejection class, and out-of-order
    delivery.  The two configurations must agree on every verdict; only the
    ciphertext bytes may differ.
    """
    import random

    outcomes: dict[str, list] = {}

    for name in SUITE_NAMES:
        actor = MaliciousActor(random.Random(7))
        channel = create_channel(name)
        results = []

        def note(verdict):
            results.append((verdict.status, verdict.reason))

        note(channel.deliver(channel.send(b"first record")))
        note(channel.deliver(channel.send(b"")))
        note(channel.deliver(channel.send(bytes(65536))))

        held = channel.send(b"held back")
        note(channel.deliver(channel.send(b"sent ahead")))
        note(channel.deliver(held))                        # out of order, accepted
        note(channel.deliver(held))                        # replay

        note(channel.deliver(actor.flip_ciphertext_bit(channel.send(b"payload"))))
        note(channel.deliver(actor.flip_tag_bit(channel.send(b"payload"))))
        note(channel.deliver(actor.relabel_record_type(channel.send(b"payload"))))
        note(channel.deliver(actor.truncate_tag(channel.send(b"payload"))))
        note(channel.deliver(actor.random_bytes(80)))

        outcomes[name] = results

    reference = outcomes[SUITE_NAMES[0]]
    for name in SUITE_NAMES[1:]:
        assert outcomes[name] == reference, f"{name} diverged from {SUITE_NAMES[0]}"

    # And the scenario really did exercise the interesting paths.
    reasons = {reason for _, reason in reference if reason is not None}
    assert reasons == {
        RejectReason.REPLAY_DETECTED,
        RejectReason.AUTH_FAILED,
        RejectReason.MALFORMED,
    }


def test_switching_configuration_changes_only_the_algorithm(suite_name):
    """The same key and session id work under either configuration.

    Keys are not transferable in practice -- a session commits to one suite, and
    the receiver enforces that via ``suite_id`` -- but the *interface* is
    identical, which is what FR-9 asks for.
    """
    key = suite_class(suite_name).generate_key()
    channel = create_channel(suite_name, key=key)

    assert channel.roundtrip(b"identical interface").accepted
    assert channel.sender.suite.name == suite_name
    assert channel.receiver.suite.name == suite_name


# --- FR-7 / SR-6: fail-closed -------------------------------------------


def test_verdict_cannot_carry_plaintext_when_rejected():
    """The invariant is enforced by the type, not by convention."""
    with pytest.raises(ConfigurationError, match="must not carry plaintext"):
        Verdict(
            status=RecordStatus.REJECTED,
            reason=RejectReason.AUTH_FAILED,
            plaintext=b"leaked",
        )


def test_accepted_verdict_requires_plaintext_and_no_reason():
    with pytest.raises(ConfigurationError, match="without plaintext"):
        Verdict(status=RecordStatus.ACCEPTED)
    with pytest.raises(ConfigurationError, match="must not carry a reject reason"):
        Verdict(
            status=RecordStatus.ACCEPTED,
            plaintext=b"ok",
            reason=RejectReason.AUTH_FAILED,
        )
    with pytest.raises(ConfigurationError, match="must state a reason"):
        Verdict(status=RecordStatus.REJECTED)


def test_no_rejection_path_ever_releases_plaintext(channel, actor):
    """Sweep every attack the actor can mount; none yields a plaintext."""
    marker = b"SENTINEL-PLAINTEXT-MUST-NOT-ESCAPE"

    attacks = [
        lambda w: actor.flip_ciphertext_bit(w),
        lambda w: actor.flip_tag_bit(w),
        lambda w: actor.flip_header_bit(w),
        lambda w: actor.zero_tag(w),
        lambda w: actor.replace_tag(w),
        lambda w: actor.truncate_tag(w),
        lambda w: actor.truncate_ciphertext(w),
        lambda w: actor.relabel_record_type(w),
        lambda w: actor.redirect_stream(w, 42),
        lambda w: actor.renumber(w, 12345),
        lambda w: actor.declare_wrong_length(w, 1),
        lambda w: actor.switch_suite_label(w, 0x7F),
        lambda w: actor.reassign_session(w, bytes(16)),
        lambda w: w[:MIN_RECORD_LEN - 1],
        lambda w: w + b"\x00",
        lambda w: b"",
        lambda w: actor.random_bytes(len(w)),
    ]

    for attack in attacks:
        wire = channel.send(marker)
        verdict = channel.deliver(attack(wire))

        assert verdict.rejected, f"{attack} produced an accepted record"
        assert verdict.plaintext is None
        assert verdict.reason is not None
        assert marker not in verdict.describe().encode()

    assert channel.receiver.stats.accepted == 0
    assert channel.receiver.stats.plaintext_bytes == 0


def test_rejection_reasons_do_not_distinguish_the_cause_of_auth_failure(channel, actor):
    """No decryption oracle: bad ciphertext, bad tag, bad AAD and bad key all
    report the same thing with the same detail text."""
    from srp import Receiver

    details = set()

    wire = channel.send(b"payload")
    details.add(channel.deliver(actor.flip_ciphertext_bit(wire)).detail)
    wire = channel.send(b"payload")
    details.add(channel.deliver(actor.flip_tag_bit(wire)).detail)
    wire = channel.send(b"payload")
    details.add(channel.deliver(actor.relabel_record_type(wire)).detail)

    cls = suite_class(channel.suite_name)
    wrong = Receiver(cls(cls.generate_key()), expected_session_id=channel.session_id)
    details.add(wrong.receive(channel.send(b"payload")).detail)

    assert len(details) == 1, f"auth failures are distinguishable: {details}"


# --- framing validation --------------------------------------------------


def test_short_frames_are_rejected_as_malformed(channel):
    for length in range(0, MIN_RECORD_LEN):
        verdict = channel.deliver(bytes(length))
        assert verdict.rejected
        assert verdict.reason is RejectReason.MALFORMED


def test_parse_record_rejects_bad_frames():
    with pytest.raises(MalformedRecordError, match="at least"):
        parse_record(b"")
    with pytest.raises(MalformedRecordError, match="version"):
        parse_record(b"\x99" + bytes(MIN_RECORD_LEN - 1))


def test_absurd_payload_length_is_refused_before_allocation(channel, actor):
    """A huge declared length is rejected on policy, not by trying to allocate."""
    wire = channel.send(b"small record")
    verdict = channel.deliver(actor.declare_wrong_length(wire, MAX_PAYLOAD_LEN + 1))

    assert verdict.rejected
    assert verdict.reason is RejectReason.MALFORMED
    assert "policy limit" in verdict.detail


def test_unknown_suite_name_is_a_configuration_error():
    with pytest.raises(ConfigurationError, match="unknown AEAD configuration"):
        suite_class("aes-cbc")
    with pytest.raises(ConfigurationError, match="unknown suite_id"):
        suite_class_by_id(0xFF)


def test_session_id_length_is_validated(suite_name):
    from srp import Sender

    cls = suite_class(suite_name)
    with pytest.raises(ConfigurationError, match="session_id must be 16 bytes"):
        Sender(cls(cls.generate_key()), b"too short")
