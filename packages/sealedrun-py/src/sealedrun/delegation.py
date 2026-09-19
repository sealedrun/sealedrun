from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from sealedrun.hashing import DEFAULT_HASH_ALG
from sealedrun.keys import KeySet, PrivateKeySet
from sealedrun.signing import DOMAIN_DELEGATION, check_hash, check_signatures, seal
from sealedrun.timeutil import format_timestamp, parse_timestamp

SPEC_VERSION = "0.1"


def create_delegation(
    principal: PrivateKeySet,
    agent_public: KeySet,
    *,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    agent_name: str | None = None,
    scope: dict[str, Any] | None = None,
    hash_alg: str = DEFAULT_HASH_ALG,
    delegation_id: str | None = None,
    principal_id: str | None = None,
) -> dict[str, Any]:
    start = not_before or datetime.now(UTC)
    end = not_after or start + timedelta(days=365)
    doc: dict[str, Any] = {
        "spec_version": SPEC_VERSION,
        "delegation_id": delegation_id or str(uuid4()),
        "principal_id": principal_id or principal.public.kid,
        "principal_keys": principal.public.to_json(),
        "agent_id": agent_public.kid,
        "agent_keys": agent_public.to_json(),
        "not_before": format_timestamp(start),
        "not_after": format_timestamp(end),
        "hash_alg": hash_alg,
    }
    if agent_name is not None:
        doc["agent_name"] = agent_name
    if scope is not None:
        doc["scope"] = scope
    return seal(doc, DOMAIN_DELEGATION, principal)


def verify_delegation(doc: dict[str, Any]) -> str | None:
    principal_keys = KeySet.from_json(doc["principal_keys"])
    agent_keys = KeySet.from_json(doc["agent_keys"])
    if agent_keys.kid != doc["agent_id"]:
        return "agent_id does not match agent_keys"
    if not doc["principal_id"].startswith("did:") and principal_keys.kid != doc["principal_id"]:
        return "principal_id does not match principal_keys"
    if parse_timestamp(doc["not_before"]) >= parse_timestamp(doc["not_after"]):
        return "not_before is not earlier than not_after"
    if not check_hash(doc):
        return "hash mismatch"
    if not check_signatures(doc, DOMAIN_DELEGATION, principal_keys):
        return "principal signature invalid"
    return None


def covers(doc: dict[str, Any], at: datetime) -> bool:
    return parse_timestamp(doc["not_before"]) <= at <= parse_timestamp(doc["not_after"])
