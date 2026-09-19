from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, UploadFile
from sealedrun import VerificationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from sealedrun_recorder.db import BundleRow, PayloadRow, RecordRow, RunRow
from sealedrun_recorder.importer import import_bundle

router = APIRouter(prefix="/api")


def get_session(request: Request) -> Any:
    with request.app.state.sessions() as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.post("/bundles", status_code=201)
async def upload_bundle(request: Request, file: UploadFile, session: SessionDep) -> dict[str, Any]:
    limit = request.app.state.settings.max_bundle_bytes
    archive = await file.read(limit + 1)
    if len(archive) > limit:
        raise HTTPException(413, "bundle exceeds size limit")
    try:
        row = import_bundle(session, archive)
    except VerificationError as error:
        raise HTTPException(
            422,
            {"check": error.check, "run_id": error.run_id, "seq": error.seq, "message": str(error)},
        ) from error
    except (ValueError, KeyError, TypeError) as error:
        raise HTTPException(400, f"malformed bundle: {error}") from error
    return _bundle_summary(row)


@router.post("/verify")
async def verify_only(request: Request, file: UploadFile) -> dict[str, Any]:
    from sealedrun import read_bundle, verify_bundle

    limit = request.app.state.settings.max_bundle_bytes
    archive = await file.read(limit + 1)
    if len(archive) > limit:
        raise HTTPException(413, "bundle exceeds size limit")
    try:
        report = verify_bundle(read_bundle(archive))
    except VerificationError as error:
        return {
            "ok": False,
            "check": error.check,
            "run_id": error.run_id,
            "seq": error.seq,
            "message": str(error),
        }
    except (ValueError, KeyError, TypeError) as error:
        raise HTTPException(400, f"malformed bundle: {error}") from error
    return {"ok": True, "bundle_id": report.bundle_id, "runs": [r.__dict__ for r in report.runs]}


@router.get("/bundles")
def list_bundles(session: SessionDep) -> list[dict[str, Any]]:
    rows = session.scalars(select(BundleRow).order_by(BundleRow.imported_at.desc())).all()
    return [_bundle_summary(r) for r in rows]


@router.get("/bundles/{bundle_id}")
def get_bundle(bundle_id: str, session: SessionDep) -> dict[str, Any]:
    row = session.get(BundleRow, bundle_id)
    if row is None:
        raise HTTPException(404, "bundle not found")
    return {**_bundle_summary(row), "manifest": row.manifest, "report": row.report}


@router.get("/bundles/{bundle_id}/archive")
def download_bundle(bundle_id: str, session: SessionDep) -> Response:
    row = session.get(BundleRow, bundle_id)
    if row is None:
        raise HTTPException(404, "bundle not found")
    return Response(
        row.archive,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="sealedrun-{bundle_id}.zip"'},
    )


@router.get("/runs")
def list_runs(session: SessionDep) -> list[dict[str, Any]]:
    rows = session.scalars(select(RunRow).order_by(RunRow.started_at.desc())).all()
    return [_run_summary(r) for r in rows]


@router.get("/runs/{run_id}")
def get_run(run_id: str, session: SessionDep) -> dict[str, Any]:
    row = session.get(RunRow, run_id)
    if row is None:
        raise HTTPException(404, "run not found")
    return _run_summary(row)


@router.get("/runs/{run_id}/records")
def list_records(run_id: str, session: SessionDep) -> list[dict[str, Any]]:
    row = session.get(RunRow, run_id)
    if row is None:
        raise HTTPException(404, "run not found")
    return [r.document for r in row.records]


@router.get("/records/{record_id}")
def get_record(record_id: str, session: SessionDep) -> dict[str, Any]:
    row = session.get(RecordRow, record_id)
    if row is None:
        raise HTTPException(404, "record not found")
    return row.document


@router.get("/records/{record_id}/payload/{side}")
def get_payload(record_id: str, side: str, session: SessionDep) -> Response:
    if side not in ("request", "response"):
        raise HTTPException(404, "side must be request or response")
    row = session.get(RecordRow, record_id)
    if row is None:
        raise HTTPException(404, "record not found")
    ref = row.document.get("payload") or {}
    digest = ref.get(f"{side}_hash")
    if digest is None or ref.get("storage") not in ("bundle", "inline"):
        raise HTTPException(404, f"record has no stored {side} payload")
    payload = session.get(PayloadRow, digest)
    if payload is None:
        raise HTTPException(404, "payload body not stored")
    media_type = ref.get(f"{side}_media_type") or "application/octet-stream"
    return Response(payload.body, media_type=media_type)


def _bundle_summary(row: BundleRow) -> dict[str, Any]:
    return {
        "bundle_id": row.bundle_id,
        "principal_id": row.principal_id,
        "exporter_agent_id": row.exporter_agent_id,
        "created_at": row.created_at,
        "imported_at": row.imported_at.isoformat(),
        "size_bytes": row.size_bytes,
        "runs": [r.run_id for r in row.runs],
    }


def _run_summary(row: RunRow) -> dict[str, Any]:
    return {
        "run_id": row.run_id,
        "bundle_id": row.bundle_id,
        "agent_id": row.agent_id,
        "principal_id": row.principal_id,
        "hash_alg": row.hash_alg,
        "started_at": row.started_at,
        "ended_at": row.ended_at,
        "record_count": row.record_count,
        "first_seq": row.first_seq,
        "last_hash": row.last_hash,
        "complete": row.complete,
        "anchors": row.anchors,
        "labels_sent_to_cloud": row.labels_sent_to_cloud,
    }
