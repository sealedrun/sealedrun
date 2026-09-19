from __future__ import annotations

from typing import Any

from sealedrun.hashing import object_hash
from sealedrun.keys import KeySet, PrivateKeySet

DOMAIN_RECORD = b"sealedrun/record/v1"
DOMAIN_DELEGATION = b"sealedrun/delegation/v1"
DOMAIN_MANIFEST = b"sealedrun/manifest/v1"

UNPROTECTED_FIELDS = ("hash", "signatures", "principal_signatures")


def signing_input(domain: bytes, hash_hex: str) -> bytes:
    return domain + b"\x00" + bytes.fromhex(hash_hex)


def protected_part(obj: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in obj.items() if k not in UNPROTECTED_FIELDS}


def seal(obj: dict[str, Any], domain: bytes, keys: PrivateKeySet) -> dict[str, Any]:
    protected = protected_part(obj)
    hash_hex = object_hash(protected["hash_alg"], protected)
    return {
        **protected,
        "hash": hash_hex,
        "signatures": keys.sign(signing_input(domain, hash_hex)),
    }


def countersign(obj: dict[str, Any], domain: bytes, keys: PrivateKeySet) -> dict[str, Any]:
    return {**obj, "principal_signatures": keys.sign(signing_input(domain, obj["hash"]))}


def check_hash(obj: dict[str, Any]) -> bool:
    return bool(object_hash(obj["hash_alg"], protected_part(obj)) == obj["hash"])


def check_signatures(
    obj: dict[str, Any], domain: bytes, keyset: KeySet, field: str = "signatures"
) -> bool:
    return bool(keyset.verify(signing_input(domain, obj["hash"]), obj[field]))
