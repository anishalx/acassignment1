"""AEAD configuration abstraction (FR-2, FR-9).

The subsystem supports two AEAD configurations:

===========================  ========  ===  =====  ===  ==========================
Configuration                suite_id  key  nonce  tag  Reference
===========================  ========  ===  =====  ===  ==========================
AES-256-GCM                      0x01   32     12   16  NIST SP 800-38D, RFC 5116
ChaCha20-Poly1305                0x02   32     12   16  RFC 8439, RFC 7539
===========================  ========  ===  =====  ===  ==========================

Both configurations were chosen at the same 256-bit key size and both use a
96-bit nonce and a 128-bit tag.  That is what makes FR-9 (configuration
equivalence) fall out of the design rather than having to be engineered: the
record header, the nonce construction, the replay window and the wire format are
*byte-for-byte identical* across the two configurations.  The only thing that
changes is which primitive is invoked, and that choice is itself authenticated
because ``suite_id`` is carried in the AAD.

This module is the only place in the subsystem that touches a cryptographic
library.  Nothing above it imports ``cryptography`` directly, so swapping the
backend (or adding e.g. AES-128-GCM or XChaCha20-Poly1305) is a local change.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import ClassVar

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from .errors import AuthenticationFailure, ConfigurationError


class AeadSuite(ABC):
    """One concrete AEAD configuration bound to one key.

    Instances are immutable and cheap to reuse; construct once per session and
    keep, since the underlying library object precomputes key schedules.
    """

    #: Human-readable selector used on the command line and in reports.
    name: ClassVar[str]
    #: One-byte identifier carried in the record header and authenticated.
    suite_id: ClassVar[int]

    key_len: ClassVar[int] = 32
    nonce_len: ClassVar[int] = 12
    tag_len: ClassVar[int] = 16

    #: Algorithm-inherent guidance on how many records may safely be protected
    #: under a single key.  See the subclasses for the justification.
    max_records_per_key: ClassVar[int]

    #: Largest plaintext this configuration may protect in a single invocation,
    #: per RFC 5116.  The subsystem additionally applies its own, much smaller,
    #: policy limit (see :data:`srp.header.MAX_PAYLOAD_LEN`).
    max_plaintext_len: ClassVar[int]

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)):
            raise ConfigurationError("key must be bytes")
        if len(key) != self.key_len:
            raise ConfigurationError(
                f"{self.name} requires a {self.key_len}-byte key, got {len(key)}"
            )
        self._key = bytes(key)
        self._impl = self._build(self._key)

    @staticmethod
    @abstractmethod
    def _build(key: bytes):  # pragma: no cover - trivial
        """Return the backend AEAD object for ``key``."""

    def seal(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        """Authenticated-encrypt ``plaintext``, binding ``aad``.

        Returns ``ciphertext || tag`` (the tag is appended, as in RFC 5116).
        """
        if len(nonce) != self.nonce_len:
            raise ConfigurationError(
                f"{self.name} requires a {self.nonce_len}-byte nonce, got {len(nonce)}"
            )
        return self._impl.encrypt(nonce, plaintext, aad)

    def open(self, nonce: bytes, ciphertext_and_tag: bytes, aad: bytes) -> bytes:
        """Verify and decrypt.

        Raises :class:`AuthenticationFailure` if the tag does not verify --
        that is, if the ciphertext, the tag, the AAD, the nonce or the key is
        wrong.  No plaintext is produced in that case: the backend computes the
        tag over the whole ciphertext before releasing anything, so there is no
        partial-plaintext leak to guard against here (FR-7, SR-6).
        """
        if len(nonce) != self.nonce_len:
            raise ConfigurationError(
                f"{self.name} requires a {self.nonce_len}-byte nonce, got {len(nonce)}"
            )
        if len(ciphertext_and_tag) < self.tag_len:
            # A frame shorter than the tag cannot possibly authenticate.
            raise AuthenticationFailure("ciphertext shorter than authentication tag")
        try:
            return self._impl.decrypt(nonce, ciphertext_and_tag, aad)
        except InvalidTag as exc:
            # InvalidTag carries no detail by design: distinguishing "bad tag"
            # from "bad AAD" would be an oracle.  We preserve that property.
            raise AuthenticationFailure("AEAD tag verification failed") from exc

    @classmethod
    def generate_key(cls) -> bytes:
        """Fresh key from the OS CSPRNG.

        Key *establishment* is out of scope for this assignment (Section 3.2);
        this exists so tests and demos have a shared secret to start from.
        """
        return os.urandom(cls.key_len)

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<{type(self).__name__} name={self.name!r} suite_id=0x{self.suite_id:02x}>"


class AesGcmSuite(AeadSuite):
    """AES-256-GCM (NIST SP 800-38D, RFC 5116 ``AEAD_AES_256_GCM``).

    Record limit: 2**24.  GCM's security bound degrades with the square of the
    number of blocks processed under one key (the GHASH collision term
    sigma^2 / 2^128), so a per-key record budget is a real requirement rather
    than paranoia.  TLS 1.3 (RFC 8446 s5.5) caps AES-GCM at 2**24.5 records
    before rekeying; we round down to 2**24 and enforce it in the nonce manager.
    """

    name = "aes-gcm"
    suite_id = 0x01
    max_records_per_key = 2 ** 24
    max_plaintext_len = 2 ** 36 - 31  # RFC 5116 P_MAX for AEAD_AES_256_GCM

    @staticmethod
    def _build(key: bytes):
        return AESGCM(key)


class ChaCha20Poly1305Suite(AeadSuite):
    """ChaCha20-Poly1305 (RFC 8439, RFC 5116 ``AEAD_CHACHA20_POLY1305``).

    Record limit: 2**48.  ChaCha20 is a 512-bit-state stream cipher, so it has
    no birthday bound analogous to GCM's, and RFC 8446 imposes no record limit
    on it.  The practical ceiling is the 64-bit sequence space; 2**48 is a
    conservative stand-in that is still ~16 million times more permissive than
    the AES-GCM budget.

    Note that the subsystem's *deployed* default limit is the stricter of the
    two (see :class:`srp.session.SessionPolicy`), which keeps observable
    behaviour identical across configurations as FR-9 requires.  This attribute
    documents the algorithm-inherent value.
    """

    name = "chacha20-poly1305"
    suite_id = 0x02
    max_records_per_key = 2 ** 48
    max_plaintext_len = 2 ** 38 - 64  # RFC 5116 P_MAX for AEAD_CHACHA20_POLY1305

    @staticmethod
    def _build(key: bytes):
        return ChaCha20Poly1305(key)


#: All supported AEAD configurations, keyed by their command-line name.
SUITES: dict[str, type[AeadSuite]] = {
    AesGcmSuite.name: AesGcmSuite,
    ChaCha20Poly1305Suite.name: ChaCha20Poly1305Suite,
}

#: Same, keyed by the one-byte identifier that appears in the record header.
SUITES_BY_ID: dict[int, type[AeadSuite]] = {
    cls.suite_id: cls for cls in SUITES.values()
}

#: Canonical ordering used by test parametrisation and benchmark reports, so
#: that "both configurations" always means the same two in the same order.
SUITE_NAMES: tuple[str, ...] = tuple(SUITES)


def suite_class(name: str) -> type[AeadSuite]:
    """Look up an AEAD configuration by name, e.g. ``"aes-gcm"``."""
    try:
        return SUITES[name]
    except KeyError:
        raise ConfigurationError(
            f"unknown AEAD configuration {name!r}; supported: {', '.join(SUITES)}"
        ) from None


def suite_class_by_id(suite_id: int) -> type[AeadSuite]:
    """Look up an AEAD configuration by its one-byte header identifier."""
    try:
        return SUITES_BY_ID[suite_id]
    except KeyError:
        raise ConfigurationError(f"unknown suite_id 0x{suite_id:02x}") from None


__all__ = [
    "AeadSuite",
    "AesGcmSuite",
    "ChaCha20Poly1305Suite",
    "SUITES",
    "SUITES_BY_ID",
    "SUITE_NAMES",
    "suite_class",
    "suite_class_by_id",
]
