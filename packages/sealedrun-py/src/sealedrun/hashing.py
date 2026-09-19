from __future__ import annotations

import base64
import hashlib
from typing import Any, Literal

from sealedrun.canonical import canonicalize

HashAlg = Literal["sha-256", "sha-384"]
HASH_ALGS: dict[str, tuple[str, int]] = {"sha-256": ("sha256", 32), "sha-384": ("sha384", 48)}
DEFAULT_HASH_ALG: HashAlg = "sha-256"


def digest(alg: str, data: bytes) -> bytes:
    name, _ = HASH_ALGS[alg]
    return hashlib.new(name, data).digest()


def digest_size(alg: str) -> int:
    return HASH_ALGS[alg][1]


def zero_hash(alg: str) -> str:
    return "0" * (digest_size(alg) * 2)


def object_hash(alg: str, protected: dict[str, Any]) -> str:
    return digest(alg, canonicalize(protected)).hex()


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def payload_digest(alg: str, body: bytes) -> str:
    return b64url_encode(digest(alg, body))
