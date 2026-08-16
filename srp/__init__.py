"""Secure Record Protection (SRP) -- CS6530 Assignment 1.

A subsystem that protects generic chunked/packetized application data using
Authenticated Encryption with Associated Data, in either of two configurations:
AES-256-GCM or ChaCha20-Poly1305.

Layering, bottom up::

    suites.py     the only module that touches a crypto library
    header.py     record header, wire format, and the AAD selection
    nonce.py      deterministic prefix||counter nonce management
    replay.py     sliding-window replay detection over authenticated seqs
    sender.py     application record -> protected record
    receiver.py   protected record -> verified application record (or a verdict)
    session.py    pairing the two over a pre-shared key
    adversary.py  the malicious actor used by the negative tests

Quick start::

    from srp import create_channel

    channel = create_channel("aes-gcm")
    wire = channel.send(b"telemetry frame 1")
    verdict = channel.deliver(wire)
    assert verdict.accepted and verdict.plaintext == b"telemetry frame 1"
"""

from __future__ import annotations

__version__ = "1.0.0"

from .adversary import MaliciousActor
from .errors import (
    AuthenticationFailure,
    ConfigurationError,
    MalformedRecordError,
    NonceExhaustedError,
    RecordStatus,
    RejectReason,
    SrpError,
)
from .header import (
    HEADER_LEN,
    MAX_PAYLOAD_LEN,
    MIN_RECORD_LEN,
    PROTOCOL_VERSION,
    TAG_LEN,
    ProtectedRecord,
    RecordFlags,
    RecordHeader,
    RecordType,
    parse_record,
)
from .nonce import (
    NONCE_LEN,
    NonceManager,
    derive_nonce,
    random_nonce_collision_probability,
)
from .receiver import Receiver, ReceiverStats, Verdict
from .replay import ReplayGuard, ReplayVerdict, ReplayWindow
from .sender import Sender, SenderStats, new_session_id
from .session import (
    DEFAULT_POLICY,
    Channel,
    SessionPolicy,
    create_channel,
    create_suite,
)
from .suites import (
    SUITE_NAMES,
    SUITES,
    AeadSuite,
    AesGcmSuite,
    ChaCha20Poly1305Suite,
    suite_class,
    suite_class_by_id,
)

__all__ = [
    "__version__",
    # errors and status
    "SrpError",
    "ConfigurationError",
    "NonceExhaustedError",
    "AuthenticationFailure",
    "MalformedRecordError",
    "RecordStatus",
    "RejectReason",
    # suites
    "AeadSuite",
    "AesGcmSuite",
    "ChaCha20Poly1305Suite",
    "SUITES",
    "SUITE_NAMES",
    "suite_class",
    "suite_class_by_id",
    # records
    "PROTOCOL_VERSION",
    "HEADER_LEN",
    "TAG_LEN",
    "MIN_RECORD_LEN",
    "MAX_PAYLOAD_LEN",
    "RecordType",
    "RecordFlags",
    "RecordHeader",
    "ProtectedRecord",
    "parse_record",
    # nonce
    "NONCE_LEN",
    "derive_nonce",
    "NonceManager",
    "random_nonce_collision_probability",
    # replay
    "ReplayVerdict",
    "ReplayWindow",
    "ReplayGuard",
    # endpoints
    "Sender",
    "SenderStats",
    "new_session_id",
    "Receiver",
    "ReceiverStats",
    "Verdict",
    # sessions
    "SessionPolicy",
    "DEFAULT_POLICY",
    "Channel",
    "create_channel",
    "create_suite",
    # adversary
    "MaliciousActor",
]
