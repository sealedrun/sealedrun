import io
import json
import zipfile
from typing import Any

import pytest
from sealedrun import PrivateKeySet, VerificationError, read_bundle, verify_bundle
from sealedrun.schema import validate


def test_roundtrip(bundle_bytes: bytes) -> None:
    bundle = read_bundle(bundle_bytes)
    assert validate("bundle.json", bundle.manifest) == []
    report = verify_bundle(bundle)
    assert len(report.runs) == 1
    assert report.runs[0].complete
    assert len(bundle.payloads) == 2


def _rewrite(bundle_bytes: bytes, path: str, content: bytes | None) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(bundle_bytes)) as src, zipfile.ZipFile(out, "w") as dst:
        for name in src.namelist():
            if name == path:
                if content is not None:
                    dst.writestr(name, content)
            else:
                dst.writestr(name, src.read(name))
        if content is not None and path not in src.namelist():
            dst.writestr(path, content)
    return out.getvalue()


def _paths(bundle_bytes: bytes) -> list[str]:
    with zipfile.ZipFile(io.BytesIO(bundle_bytes)) as zf:
        return zf.namelist()


def test_tampered_payload_byte(bundle_bytes: bytes) -> None:
    path = next(p for p in _paths(bundle_bytes) if p.startswith("payloads/"))
    with zipfile.ZipFile(io.BytesIO(bundle_bytes)) as zf:
        body = bytearray(zf.read(path))
    body[0] ^= 1
    with pytest.raises(VerificationError) as info:
        read_bundle(_rewrite(bundle_bytes, path, bytes(body)))
    assert info.value.check == "bundle"


def test_tampered_record_with_fixed_manifest(bundle_bytes: bytes, agent: PrivateKeySet) -> None:
    from sealedrun.signing import DOMAIN_MANIFEST, seal

    bundle = read_bundle(bundle_bytes)
    run_id, records = next(iter(bundle.runs.items()))
    records[1]["outcome"] = "error"
    jsonl = "".join(
        json.dumps(r, separators=(",", ":"), sort_keys=True) + "\n" for r in records
    ).encode()
    from sealedrun import payload_digest

    manifest = dict(bundle.manifest)
    manifest["files"] = {
        **manifest["files"],
        f"runs/{run_id}.jsonl": payload_digest("sha-256", jsonl),
    }
    manifest.pop("principal_signatures")
    manifest = seal(manifest, DOMAIN_MANIFEST, agent)
    tampered = _rewrite(bundle_bytes, f"runs/{run_id}.jsonl", jsonl)
    tampered = _rewrite(tampered, "manifest.json", json.dumps(manifest).encode())
    with pytest.raises(VerificationError) as info:
        verify_bundle(read_bundle(tampered))
    assert info.value.check == "hash"
    assert info.value.seq == 1


def test_manifest_resigned_by_stranger(bundle_bytes: bytes) -> None:
    from sealedrun.signing import DOMAIN_MANIFEST, seal

    bundle = read_bundle(bundle_bytes)
    manifest = seal(bundle.manifest, DOMAIN_MANIFEST, PrivateKeySet.generate())
    tampered = _rewrite(bundle_bytes, "manifest.json", json.dumps(manifest).encode())
    with pytest.raises(VerificationError) as info:
        verify_bundle(read_bundle(tampered))
    assert info.value.check == "manifest"


def test_extra_and_missing_files(bundle_bytes: bytes) -> None:
    with pytest.raises(VerificationError):
        read_bundle(_rewrite(bundle_bytes, "payloads/sha-256/extra", b"x"))
    path = next(p for p in _paths(bundle_bytes) if p.startswith("payloads/"))
    with pytest.raises(VerificationError):
        read_bundle(_rewrite(bundle_bytes, path, None))


def test_missing_payload_body_detected_by_run_check(bundle_bytes: bytes) -> None:
    bundle = read_bundle(bundle_bytes)
    bundle.payloads.clear()
    with pytest.raises(VerificationError) as info:
        verify_bundle(bundle)
    assert info.value.check == "payload"


def test_manifest_flags_must_match(bundle_bytes: bytes) -> None:
    bundle = read_bundle(bundle_bytes)
    entry: dict[str, Any] = bundle.manifest["runs"][0]
    entry["complete"] = False
    bundle.manifest["hash"] = "0" * 64
    with pytest.raises(VerificationError) as info:
        verify_bundle(bundle)
    assert info.value.check == "manifest"
