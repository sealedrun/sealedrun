"""Hash algorithms of SPEC 4.1 and the base64url and hex encodings of SPEC 3."""

from __future__ import annotations

import base64
import hashlib
from typing import Any, Literal

from sealedrun.canonical import canonicalize

HashAlg = Literal["sha-256", "sha-384"]
HASH_ALGS: dict[str, tuple[str, int]] = {"sha-256": ("sha256", 32), "sha-384": ("sha384", 48)}
DEFAULT_HASH_ALG: HashAlg = "sha-256"


def digest(alg: str, data: bytes) -> bytes:
    """Hash `data` with a registered `hash_alg`; an unregistered name raises KeyError."""
    name, _ = HASH_ALGS[alg]
    return hashlib.new(name, data).digest()


def digest_size(alg: str) -> int:
    """Return the digest length of `alg` in bytes."""
    return HASH_ALGS[alg][1]


def zero_hash(alg: str) -> str:
    """Return the all-zero hex hash that the first record of a run uses as `prev_hash`."""
    return "0" * (digest_size(alg) * 2)


def object_hash(alg: str, protected: dict[str, Any]) -> str:
    """Hash the JCS form of the protected part of an object and return lowercase hex."""
    return digest(alg, canonicalize(protected)).hex()


def b64url_encode(data: bytes) -> str:
    """Encode bytes as base64url without padding (RFC 4648 section 5)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Decode base64url text that carries no padding."""
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def payload_digest(alg: str, body: bytes) -> str:
    """Return the base64url digest of a payload body, as stored in a payload reference."""
    return b64url_encode(digest(alg, body))
