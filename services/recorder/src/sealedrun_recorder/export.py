"""Export a live run from its database rows as a bundle archive."""

from __future__ import annotations

import io
from typing import Any

from sealedrun import write_bundle
from sqlalchemy import select
from sqlalchemy.orm import Session

from sealedrun_recorder import __version__
from sealedrun_recorder.db import DelegationRow, PayloadRow, RecordRow, RunRow
from sealedrun_recorder.keystore import Identity

SOFTWARE = f"sealedrun-recorder/{__version__}"


class ExportError(Exception):
    """The run cannot be exported; `status` is the HTTP status that describes why."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def build_bundle(session: Session, identity: Identity, run_id: str) -> bytes:
    """Return a bundle archive holding the live run `run_id`, signed by this recorder.

    The recorder's agent key is the exporter and its principal key countersigns. An open run
    is exported as it stands, with `complete` false in the manifest. Imported runs are refused:
    their original bundle is the record. A payload body a record names but the database no
    longer holds is an error, never a silent gap.

    Raises:
        ExportError: 404 when the run is unknown, 409 when it was imported, 500 when a payload
            body or the run's delegation is missing.

    """
    run = session.get(RunRow, run_id)
    if run is None:
        raise ExportError(404, "run not found")
    if run.source != "live":
        raise ExportError(409, "imported run: download its original bundle instead")
    records = [
        row.document
        for row in session.scalars(
            select(RecordRow).where(RecordRow.run_id == run_id).order_by(RecordRow.seq)
        )
    ]
    delegation = _delegation_of(session, records[0])
    payloads: dict[str, bytes] = {}
    for record in records:
        ref = record.get("payload") or {}
        if ref.get("storage") != "bundle":
            continue
        for side in ("request", "response"):
            digest = ref.get(f"{side}_hash")
            if digest is None or digest in payloads:
                continue
            row = session.get(PayloadRow, digest)
            if row is None:
                raise ExportError(500, f"payload body missing from the database: {digest}")
            payloads[digest] = row.body
    anchors = {
        r["record_id"]: r["extensions"]["sealedrun.anchor"]["receipt"]
        for r in records
        if r["kind"] == "anchor"
    }
    out = io.BytesIO()
    write_bundle(
        out,
        exporter=identity.agent,
        software=SOFTWARE,
        delegations=[delegation],
        runs=[records],
        payloads=payloads,
        anchors=anchors,
        principal=identity.principal,
        hash_alg=run.hash_alg,
    )
    return out.getvalue()


def _delegation_of(session: Session, first: dict[str, Any]) -> dict[str, Any]:
    binding = first.get("extensions", {}).get("sealedrun.delegation", {})
    row = session.get(DelegationRow, binding.get("delegation_id", ""))
    if row is None:
        raise ExportError(500, "the run's delegation is not stored")
    return row.document
