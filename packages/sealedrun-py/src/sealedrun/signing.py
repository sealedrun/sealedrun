"""Hashing and hybrid signing of records, delegations and manifests (SPEC 4.4)."""

from __future__ import annotations

from typing import Any

from sealedrun.hashing import object_hash
from sealedrun.keys import KeySet, PrivateKeySet

DOMAIN_RECORD = b"sealedrun/record/v1"
DOMAIN_DELEGATION = b"sealedrun/delegation/v1"
DOMAIN_MANIFEST = b"sealedrun/manifest/v1"

UNPROTECTED_FIELDS = ("hash", "signatures", "principal_signatures")


def signing_input(domain: bytes, hash_hex: str) -> bytes:
    """Build `domain || 0x00 || hash_bytes`, the only byte string that is ever signed.

    The domain prefix stops a signature on one object type from being replayed as another.
    """
    return domain + b"\x00" + bytes.fromhex(hash_hex)


def protected_part(obj: dict[str, Any]) -> dict[str, Any]:
    """Return the object without its hash and signature fields, which the hash does not cover."""
    return {k: v for k, v in obj.items() if k not in UNPROTECTED_FIELDS}


def seal(obj: dict[str, Any], domain: bytes, keys: PrivateKeySet) -> dict[str, Any]:
    """Return the object with `hash` and `signatures` computed over its protected part.

    Any hash or signature fields already on `obj` are discarded.
    """
    protected = protected_part(obj)
    hash_hex = object_hash(protected["hash_alg"], protected)
    return {
        **protected,
        "hash": hash_hex,
        "signatures": keys.sign(signing_input(domain, hash_hex)),
    }


def countersign(obj: dict[str, Any], domain: bytes, keys: PrivateKeySet) -> dict[str, Any]:
    """Add `principal_signatures` over the existing `hash` of an already sealed object."""
    return {**obj, "principal_signatures": keys.sign(signing_input(domain, obj["hash"]))}


def check_hash(obj: dict[str, Any]) -> bool:
    """Recompute the hash of the protected part and compare it with the stored `hash`."""
    return bool(object_hash(obj["hash_alg"], protected_part(obj)) == obj["hash"])


def check_signatures(
    obj: dict[str, Any], domain: bytes, keyset: KeySet, field: str = "signatures"
) -> bool:
    """Verify the signatures in `field` against the stored `hash`; every key of `keyset` must sign.

    The hash itself is not rechecked here; pair this with `check_hash`.
    """
    return bool(keyset.verify(signing_input(domain, obj["hash"]), obj[field]))
