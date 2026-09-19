from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from sealedrun.hashing import payload_digest, zero_hash
from sealedrun.keys import PrivateKeySet
from sealedrun.signing import DOMAIN_RECORD, seal
from sealedrun.timeutil import format_timestamp, now

SPEC_VERSION = "0.1"


def payload_ref(
    hash_alg: str,
    request: bytes | None = None,
    response: bytes | None = None,
    *,
    storage: str = "bundle",
    request_media_type: str | None = None,
    response_media_type: str | None = None,
) -> dict[str, Any]:
    ref: dict[str, Any] = {"storage": storage}
    if request is not None:
        ref["request_hash"] = payload_digest(hash_alg, request)
        ref["request_size"] = len(request)
        if request_media_type:
            ref["request_media_type"] = request_media_type
    if response is not None:
        ref["response_hash"] = payload_digest(hash_alg, response)
        ref["response_size"] = len(response)
        if response_media_type:
            ref["response_media_type"] = response_media_type
    return ref


class RunWriter:
    def __init__(
        self,
        agent: PrivateKeySet,
        delegation: dict[str, Any],
        *,
        run_id: str | None = None,
        clock: Any = now,
        id_factory: Any = lambda: str(uuid4()),
    ):
        self._agent = agent
        self._delegation = delegation
        self._clock = clock
        self._new_id = id_factory
        self.run_id = run_id or self._new_id()
        self.hash_alg: str = delegation["hash_alg"]
        self.principal_id: str = delegation["principal_id"]
        self.agent_id: str = delegation["agent_id"]
        self.records: list[dict[str, Any]] = []
        self.closed = False

    @property
    def seq(self) -> int:
        return len(self.records)

    @property
    def head(self) -> str:
        return self.records[-1]["hash"] if self.records else zero_hash(self.hash_alg)

    def start(self, **fields: Any) -> dict[str, Any]:
        if self.records:
            raise ValueError("run already started")
        extensions = dict(fields.pop("extensions", {}))
        extensions["sealedrun.delegation"] = {
            "delegation_id": self._delegation["delegation_id"],
            "hash": self._delegation["hash"],
        }
        return self.append(
            "run_start",
            target={"type": "none", "name": "run"},
            extensions=extensions,
            **fields,
        )

    def end(self, **fields: Any) -> dict[str, Any]:
        record = self.append("run_end", target={"type": "none", "name": "run"}, **fields)
        self.closed = True
        return record

    def append(
        self,
        kind: str,
        *,
        target: dict[str, Any],
        actor: dict[str, str] | None = None,
        payload: dict[str, Any] | None = None,
        data_labels: list[str] | None = None,
        policy: dict[str, Any] | None = None,
        outcome: str = "success",
        parent_record_id: str | None = None,
        extensions: dict[str, Any] | None = None,
        occurred_at: datetime | None = None,
    ) -> dict[str, Any]:
        if self.closed:
            raise ValueError("run is closed")
        if not self.records and kind != "run_start":
            raise ValueError("first record must be run_start")
        doc: dict[str, Any] = {
            "spec_version": SPEC_VERSION,
            "record_id": self._new_id(),
            "run_id": self.run_id,
            "seq": self.seq,
            "occurred_at": format_timestamp(occurred_at or self._clock()),
            "principal_id": self.principal_id,
            "agent_id": self.agent_id,
            "kind": kind,
            "actor": actor or {"type": "agent", "id": self.agent_id},
            "target": target,
            "data_labels": sorted(set(data_labels or [])),
            "outcome": outcome,
            "hash_alg": self.hash_alg,
            "prev_hash": self.head,
        }
        if payload is not None:
            doc["payload"] = payload
        if policy is not None:
            doc["policy"] = policy
        if parent_record_id is not None:
            doc["parent_record_id"] = parent_record_id
        if extensions:
            doc["extensions"] = extensions
        record = seal(doc, DOMAIN_RECORD, self._agent)
        self.records.append(record)
        return record
