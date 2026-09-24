"""Writing the records of a run as a signed hash chain (SPEC 5)."""

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
    """Build a SPEC 5.5 payload reference: digest and size of each body that is given.

    The bodies themselves are not stored in the record.
    """
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
    """Append-only writer for one run, signing every record with the agent's keys.

    The hash algorithm, `principal_id` and `agent_id` are taken from the delegation. `clock` and
    `id_factory` exist so that test vectors are reproducible.
    """

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
        self.closed = False
        self._records: list[dict[str, Any]] = []
        self._seq = 0
        self._head = zero_hash(self.hash_alg)

    @property
    def records(self) -> list[dict[str, Any]]:
        """Records written by this writer, in seq order."""
        return self._records

    @records.setter
    def records(self, value: list[dict[str, Any]]) -> None:
        """Replace the record list and continue the chain from its last element.

        Used to fork a chain, for example to build negative test vectors.
        """
        self._records = list(value)
        self._seq = self._records[-1]["seq"] + 1 if self._records else 0
        self._head = self._records[-1]["hash"] if self._records else zero_hash(self.hash_alg)

    @classmethod
    def resume(
        cls,
        agent: PrivateKeySet,
        delegation: dict[str, Any],
        *,
        run_id: str,
        seq: int,
        head: str,
        clock: Any = now,
        id_factory: Any = lambda: str(uuid4()),
    ) -> RunWriter:
        """Continue a run whose earlier records live elsewhere, for example in a database.

        `seq` is the number the next record gets and `head` is the hash of the last stored
        record. The writer starts empty but chains from `head`, so `records` holds only what is
        appended after the resume. Raises ValueError unless `seq` is positive: a run with no
        records is started, not resumed.
        """
        if seq < 1:
            raise ValueError("a run with no records cannot be resumed")
        writer = cls(agent, delegation, run_id=run_id, clock=clock, id_factory=id_factory)
        writer._seq = seq
        writer._head = head
        return writer

    @property
    def seq(self) -> int:
        """Sequence number the next record will get."""
        return self._seq

    @property
    def head(self) -> str:
        """Hash of the last record, or the all-zero hash before the first one."""
        return self._head

    def start(self, **fields: Any) -> dict[str, Any]:
        """Write the `run_start` record and bind the run to the delegation (SPEC 6.4).

        `fields` are passed to `append`. Raises ValueError if the run has already started.
        """
        if self._seq:
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
        """Write the `run_end` record and close the run; later appends raise ValueError."""
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
        """Seal one record onto the chain and return it.

        `data_labels` are deduplicated and sorted, and `actor` defaults to the agent. Raises
        ValueError if the run is closed or if the first record is not `run_start`.
        """
        if self.closed:
            raise ValueError("run is closed")
        if not self._seq and kind != "run_start":
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
        self._records.append(record)
        self._seq += 1
        self._head = record["hash"]
        return record
