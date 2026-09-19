from __future__ import annotations

import io
import json
import zipfile
from dataclasses import dataclass, field
from typing import Any, BinaryIO
from uuid import uuid4

from sealedrun.errors import VerificationError
from sealedrun.hashing import DEFAULT_HASH_ALG, digest, payload_digest, zero_hash
from sealedrun.keys import KeySet, PrivateKeySet
from sealedrun.schema import validate
from sealedrun.signing import DOMAIN_MANIFEST, check_hash, check_signatures, countersign, seal
from sealedrun.timeutil import format_timestamp, now
from sealedrun.verify import RunReport, verify_run

SPEC_VERSION = "0.1"
MANIFEST = "manifest.json"


@dataclass
class Bundle:
    manifest: dict[str, Any]
    delegations: dict[str, dict[str, Any]]
    runs: dict[str, list[dict[str, Any]]]
    payloads: dict[str, bytes] = field(default_factory=dict)
    anchors: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass
class BundleReport:
    bundle_id: str
    runs: list[RunReport]


def _jsonl(records: list[dict[str, Any]]) -> bytes:
    return "".join(
        json.dumps(r, separators=(",", ":"), sort_keys=True) + "\n" for r in records
    ).encode()


def write_bundle(
    out: BinaryIO,
    *,
    exporter: PrivateKeySet,
    software: str,
    delegations: list[dict[str, Any]],
    runs: list[list[dict[str, Any]]],
    payloads: dict[str, bytes] | None = None,
    anchors: dict[str, dict[str, Any]] | None = None,
    principal: PrivateKeySet | None = None,
    hash_alg: str = DEFAULT_HASH_ALG,
    bundle_id: str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    files: dict[str, bytes] = {}
    for d in delegations:
        files[f"delegations/{d['delegation_id']}.json"] = json.dumps(d, sort_keys=True).encode()
    run_entries = []
    for records in runs:
        first = records[0]
        files[f"runs/{first['run_id']}.jsonl"] = _jsonl(records)
        run_entries.append(
            {
                "run_id": first["run_id"],
                "hash_alg": first["hash_alg"],
                "record_count": len(records),
                "first_seq": first["seq"],
                "first_hash": first["prev_hash"]
                if first["seq"] > 0
                else zero_hash(first["hash_alg"]),
                "last_hash": records[-1]["hash"],
                "complete": records[-1]["kind"] == "run_end",
            }
        )
    for body_hash, body in (payloads or {}).items():
        files[f"payloads/{hash_alg}/{body_hash}"] = body
    for record_id, receipt in (anchors or {}).items():
        files[f"anchors/{record_id}.json"] = json.dumps(receipt, sort_keys=True).encode()

    principal_ids = {d["principal_id"] for d in delegations}
    if len(principal_ids) != 1:
        raise ValueError("bundle must contain delegations of exactly one principal")
    manifest: dict[str, Any] = {
        "spec_version": SPEC_VERSION,
        "bundle_id": bundle_id or str(uuid4()),
        "created_at": created_at or format_timestamp(now()),
        "exporter": {"agent_id": exporter.public.kid, "software": software},
        "principal_id": principal_ids.pop(),
        "delegations": [d["delegation_id"] for d in delegations],
        "runs": run_entries,
        "files": {path: payload_digest(hash_alg, data) for path, data in files.items()},
        "hash_alg": hash_alg,
    }
    manifest = seal(manifest, DOMAIN_MANIFEST, exporter)
    if principal is not None:
        manifest = countersign(manifest, DOMAIN_MANIFEST, principal)

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(MANIFEST, json.dumps(manifest, indent=2, sort_keys=True))
        for path, data in sorted(files.items()):
            zf.writestr(path, data)
    return manifest


def read_bundle(source: BinaryIO | bytes) -> Bundle:
    data = io.BytesIO(source) if isinstance(source, bytes) else source
    if not zipfile.is_zipfile(data):
        raise VerificationError("bundle", "not a zip archive")
    data.seek(0)
    with zipfile.ZipFile(data) as zf:
        names = set(zf.namelist())
        if MANIFEST not in names:
            raise VerificationError("bundle", "manifest.json missing")
        manifest = json.loads(zf.read(MANIFEST))
        errors = validate("bundle.json", manifest)
        if errors:
            raise VerificationError("schema", "; ".join(errors))
        listed = set(manifest["files"])
        extra = names - listed - {MANIFEST}
        if extra:
            raise VerificationError("bundle", f"files not in manifest: {sorted(extra)}")
        missing = listed - names
        if missing:
            raise VerificationError("bundle", f"files missing: {sorted(missing)}")
        bundle = Bundle(manifest, {}, {})
        for path, expected in manifest["files"].items():
            content = zf.read(path)
            if payload_digest(manifest["hash_alg"], content) != expected:
                raise VerificationError("bundle", f"digest mismatch for {path}")
            if path.startswith("delegations/"):
                doc = json.loads(content)
                bundle.delegations[doc["delegation_id"]] = doc
            elif path.startswith("runs/"):
                records = [json.loads(line) for line in content.decode().splitlines() if line]
                bundle.runs[path.removeprefix("runs/").removesuffix(".jsonl")] = records
            elif path.startswith("payloads/"):
                bundle.payloads[path.rsplit("/", 1)[1]] = content
            elif path.startswith("anchors/"):
                bundle.anchors[path.removeprefix("anchors/").removesuffix(".json")] = json.loads(
                    content
                )
    return bundle


def verify_bundle(bundle: Bundle) -> BundleReport:
    manifest = bundle.manifest
    if not check_hash(manifest):
        raise VerificationError("manifest", "manifest hash mismatch")
    exporter_id = manifest["exporter"]["agent_id"]
    exporter_keys = _find_keys(bundle, exporter_id)
    if exporter_keys is None:
        raise VerificationError("manifest", "exporter has no delegation in bundle")
    if not check_signatures(manifest, DOMAIN_MANIFEST, exporter_keys):
        raise VerificationError("manifest", "exporter signature invalid")
    if "principal_signatures" in manifest:
        principal_keys = _principal_keys(bundle)
        if not check_signatures(manifest, DOMAIN_MANIFEST, principal_keys, "principal_signatures"):
            raise VerificationError("manifest", "principal signature invalid")
    if set(manifest["delegations"]) != set(bundle.delegations):
        raise VerificationError("manifest", "delegation list does not match files")
    if {r["run_id"] for r in manifest["runs"]} != set(bundle.runs):
        raise VerificationError("manifest", "run list does not match files")

    reports = []
    for entry in manifest["runs"]:
        records = bundle.runs[entry["run_id"]]
        expected_prev = entry["first_hash"] if entry["first_seq"] > 0 else None
        report = verify_run(
            records, bundle.delegations, payloads=bundle.payloads, expected_prev_hash=expected_prev
        )
        if report.record_count != entry["record_count"] or report.last_hash != entry["last_hash"]:
            raise VerificationError("manifest", "run entry does not match records", entry["run_id"])
        if report.complete != entry["complete"] or report.first_seq != entry["first_seq"]:
            raise VerificationError(
                "manifest", "run entry flags do not match records", entry["run_id"]
            )
        reports.append(report)
    return BundleReport(manifest["bundle_id"], reports)


def _find_keys(bundle: Bundle, agent_id: str) -> KeySet | None:
    for d in bundle.delegations.values():
        if d["agent_id"] == agent_id:
            return KeySet.from_json(d["agent_keys"])
    return None


def _principal_keys(bundle: Bundle) -> KeySet:
    first = next(iter(bundle.delegations.values()))
    return KeySet.from_json(first["principal_keys"])


def file_digest(hash_alg: str, data: bytes) -> str:
    return digest(hash_alg, data).hex()
