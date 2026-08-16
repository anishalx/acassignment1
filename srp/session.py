"""Session setup: pairing a sender and a receiver over a pre-shared key.

Key *establishment* is out of scope for this assignment (Section 3.2): both
endpoints are assumed to already hold the same secret.  What is in scope is
everything that has to be agreed *besides* the key for the two sides to
interoperate, and this module is where that agreement is made explicit rather
than being scattered across constructor arguments at each call site.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, replace

from .errors import ConfigurationError
from .header import SESSION_ID_LEN
from .receiver import Receiver
from .sender import Sender
from .replay import DEFAULT_MAX_STREAMS, DEFAULT_WINDOW_SIZE
from .suites import AeadSuite, suite_class


@dataclass(frozen=True, slots=True)
class SessionPolicy:
    """Operational parameters both endpoints must agree on.

    ``record_limit`` defaults to 2**24 for *both* AEAD configurations, which is
    the AES-GCM budget (RFC 8446 s5.5) applied uniformly.  ChaCha20-Poly1305
    tolerates far more (see :class:`~srp.suites.ChaCha20Poly1305Suite`), but
    deploying the stricter of the two keeps observable behaviour identical
    across configurations, as FR-9 requires: switching suite must not change
    what the subsystem *does*, only which primitive it calls.
    """

    record_limit: int = 2 ** 24
    replay_window: int = DEFAULT_WINDOW_SIZE
    max_streams: int = DEFAULT_MAX_STREAMS
    pin_session: bool = True

    def with_(self, **changes) -> SessionPolicy:
        return replace(self, **changes)


DEFAULT_POLICY = SessionPolicy()


@dataclass(frozen=True, slots=True)
class Channel:
    """A matched sender/receiver pair sharing one key and session.

    The "channel" is purely logical: no transport is implied, which is what
    Section 3.3 permits.  ``demo/run_network_demo.py`` shows the same objects
    driven over a real socket to make the point that the subsystem is transport
    agnostic.
    """

    suite_name: str
    key: bytes
    session_id: bytes
    sender: Sender
    receiver: Receiver
    policy: SessionPolicy = DEFAULT_POLICY

    def send(self, payload: bytes, **kwargs) -> bytes:
        """Protect a record at the sender (returns the wire encoding)."""
        return self.sender.protect(payload, **kwargs)

    def deliver(self, wire: bytes):
        """Hand a wire record to the receiver and return its verdict."""
        return self.receiver.receive(wire)

    def roundtrip(self, payload: bytes, **kwargs):
        """Protect then immediately verify -- the TR-1 happy path in one call."""
        return self.deliver(self.send(payload, **kwargs))


def create_suite(suite_name: str, key: bytes) -> AeadSuite:
    """Instantiate an AEAD configuration by name over a pre-shared key."""
    return suite_class(suite_name)(key)


def create_channel(
    suite_name: str,
    *,
    key: bytes | None = None,
    session_id: bytes | None = None,
    stream_id: int = 1,
    policy: SessionPolicy = DEFAULT_POLICY,
    nonce_prefix: bytes | None = None,
    start_seq: int = 0,
) -> Channel:
    """Build a sender and receiver that share a key, session and policy.

    ``key`` and ``session_id`` are generated if not supplied.  Note that the
    sender and receiver each get their **own** :class:`AeadSuite` instance over
    the same key bytes: they are separate logical entities and must not share
    mutable state, so that tests exercising a wrong key on one side (TR-6) are
    testing the real thing.
    """
    cls = suite_class(suite_name)

    if key is None:
        key = cls.generate_key()
    elif len(key) != cls.key_len:
        raise ConfigurationError(
            f"{suite_name} requires a {cls.key_len}-byte key, got {len(key)}"
        )

    if session_id is None:
        session_id = os.urandom(SESSION_ID_LEN)
    elif len(session_id) != SESSION_ID_LEN:
        raise ConfigurationError(
            f"session_id must be {SESSION_ID_LEN} bytes, got {len(session_id)}"
        )

    sender = Sender(
        cls(key),
        session_id,
        stream_id=stream_id,
        nonce_prefix=nonce_prefix,
        record_limit=policy.record_limit,
        start_seq=start_seq,
    )
    receiver = Receiver(
        cls(key),
        expected_session_id=session_id if policy.pin_session else None,
        replay_window=policy.replay_window,
        max_streams=policy.max_streams,
    )
    return Channel(
        suite_name=suite_name,
        key=bytes(key),
        session_id=bytes(session_id),
        sender=sender,
        receiver=receiver,
        policy=policy,
    )


__all__ = [
    "SessionPolicy",
    "DEFAULT_POLICY",
    "Channel",
    "create_suite",
    "create_channel",
]
