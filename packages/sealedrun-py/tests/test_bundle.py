import io
import json
import time
import zipfile
from typing import Any

import pytest
from sealedrun import PrivateKeySet, VerificationError, read_bundle, verify_bundle, write_bundle
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


def _bomb(size: int) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", b"{}")
        zf.writestr("payloads/zeros", b"\0" * size)
    return out.getvalue()


def test_entry_size_limit() -> None:
    with pytest.raises(VerificationError, match="entry exceeds"):
        read_bundle(_bomb(2_000_000), max_entry_bytes=1_000_000)


def test_total_size_limit() -> None:
    with pytest.raises(VerificationError, match="uncompressed size") as info:
        read_bundle(_bomb(2_000_000), max_total_bytes=1_000_000)
    assert "2 MB claimed, limit 1 MB" in str(info.value)


def test_total_size_limit_names_gigabytes() -> None:
    # The central directory claims 1.19 GB; the reader refuses before inflating anything.
    patched = _claim_size(_bomb(10), "payloads/zeros", 1_190_000_000)
    with pytest.raises(VerificationError, match=r"1\.19 GB claimed, limit 1 GB"):
        read_bundle(patched, max_entry_bytes=2_000_000_000, max_total_bytes=1_000_000_000)


def _claim_size(archive: bytes, name: str, size: int) -> bytes:
    """Return `archive` with the central-directory uncompressed size of `name` set to `size`."""
    data = bytearray(archive)
    marker = b"PK\x01\x02"
    pos = data.find(marker)
    while pos >= 0:
        name_len = int.from_bytes(data[pos + 28 : pos + 30], "little")
        if data[pos + 46 : pos + 46 + name_len].decode() == name:
            data[pos + 24 : pos + 28] = size.to_bytes(4, "little")
        pos = data.find(marker, pos + 4)
    return bytes(data)


def test_manifest_size_limit() -> None:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", b" " * (4 * 1024 * 1024 + 1))
    with pytest.raises(VerificationError, match="entry exceeds"):
        read_bundle(out.getvalue())


def test_unsortable_array_fails_fast(bundle_bytes: bytes) -> None:
    with zipfile.ZipFile(io.BytesIO(bundle_bytes)) as zf:
        manifest = json.loads(zf.read("manifest.json"))
    manifest["delegations"] = [{"a": i} for i in range(4000)]
    started = time.perf_counter()
    with pytest.raises(VerificationError) as info:
        read_bundle(_rewrite(bundle_bytes, "manifest.json", json.dumps(manifest).encode()))
    assert info.value.check == "schema"
    assert time.perf_counter() - started < 2


def test_limits_do_not_affect_valid_bundle(bundle_bytes: bytes) -> None:
    assert read_bundle(bundle_bytes, max_entry_bytes=1_000_000).manifest["bundle_id"]


def test_malformed_archive_has_generic_message(bundle_bytes: bytes) -> None:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("manifest.json", b"{not json")
    with pytest.raises(VerificationError, match="malformed archive"):
        read_bundle(out.getvalue())


def test_manifest_principal_must_match_delegations(
    bundle_bytes: bytes, agent: PrivateKeySet
) -> None:
    from sealedrun.signing import DOMAIN_MANIFEST, seal

    manifest = dict(read_bundle(bundle_bytes).manifest)
    manifest.pop("principal_signatures")
    manifest["principal_id"] = PrivateKeySet.generate().public.kid
    manifest = seal(manifest, DOMAIN_MANIFEST, agent)
    tampered = _rewrite(bundle_bytes, "manifest.json", json.dumps(manifest).encode())
    with pytest.raises(VerificationError, match="principal differs"):
        verify_bundle(read_bundle(tampered))


def test_open_run_exports_incomplete(
    agent: PrivateKeySet, principal: PrivateKeySet, delegation: dict[str, Any]
) -> None:
    from sealedrun import RunWriter, write_bundle

    writer = RunWriter(agent, delegation)
    writer.start()
    writer.append("note", target={"type": "none", "name": "step"})
    out = io.BytesIO()
    write_bundle(
        out,
        exporter=agent,
        software="test/0",
        delegations=[delegation],
        runs=[writer.records],
        principal=principal,
    )
    report = verify_bundle(read_bundle(out.getvalue()), [principal.public.kid])
    assert report.runs[0].complete is False
    assert report.runs[0].record_count == 2
    assert report.principal_trusted


def _two_runs(
    agent: PrivateKeySet,
    principal: PrivateKeySet,
    delegation: dict[str, Any],
    first_ids: Any,
    second_ids: Any,
) -> tuple[bytes, str]:
    """Bundle two started-and-ended runs; return the archive and the second run's id."""
    from sealedrun import RunWriter, write_bundle

    runs = []
    for number, ids in enumerate((first_ids, second_ids)):
        writer = RunWriter(
            agent, delegation, run_id=f"0192b3c4-5d6e-7f80-9a1b-0000000000a{number}", id_factory=ids
        )
        writer.start()
        writer.end()
        runs.append(writer.records)
    out = io.BytesIO()
    write_bundle(
        out,
        exporter=agent,
        software="test/0",
        delegations=[delegation],
        runs=runs,
        principal=principal,
    )
    return out.getvalue(), runs[1][0]["run_id"]


def _counter(start: int) -> Any:
    numbers = iter(range(start, start + 100))
    return lambda: f"0192b3c4-5d6e-7f80-9a1b-{next(numbers):012x}"


def test_record_id_repeating_across_runs_fails(
    agent: PrivateKeySet, principal: PrivateKeySet, delegation: dict[str, Any]
) -> None:
    data, second = _two_runs(agent, principal, delegation, _counter(1), _counter(1))
    with pytest.raises(VerificationError, match="across the runs") as info:
        verify_bundle(read_bundle(data))
    assert (info.value.check, info.value.run_id, info.value.seq) == ("record_id", second, 0)


def test_record_id_shared_by_last_records_is_reported_at_that_seq(
    agent: PrivateKeySet, principal: PrivateKeySet, delegation: dict[str, Any]
) -> None:
    data, second = _two_runs(agent, principal, delegation, _counter(1), _counter(2))
    with pytest.raises(VerificationError) as info:
        verify_bundle(read_bundle(data))
    assert (info.value.check, info.value.run_id, info.value.seq) == ("record_id", second, 0)
    data, second = _two_runs(agent, principal, delegation, _counter(2), _counter(1))
    with pytest.raises(VerificationError) as info:
        verify_bundle(read_bundle(data))
    assert (info.value.check, info.value.run_id, info.value.seq) == ("record_id", second, 1)


def test_two_runs_with_their_own_record_ids_pass(
    agent: PrivateKeySet, principal: PrivateKeySet, delegation: dict[str, Any]
) -> None:
    data, _ = _two_runs(agent, principal, delegation, _counter(1), _counter(50))
    report = verify_bundle(read_bundle(data))
    assert [r.record_count for r in report.runs] == [2, 2]


def test_record_id_repeating_inside_one_run_keeps_the_run_error(
    agent: PrivateKeySet, principal: PrivateKeySet, delegation: dict[str, Any]
) -> None:
    same = "0192b3c4-5d6e-7f80-9a1b-000000000001"
    data, _ = _two_runs(agent, principal, delegation, lambda: same, _counter(50))
    with pytest.raises(VerificationError, match="within the run") as info:
        verify_bundle(read_bundle(data))
    assert (info.value.check, info.value.seq) == ("record_id", 1)


def test_write_bundle_refuses_bodies_with_payloads_omitted() -> None:
    from sealedrun.vectors import build_delegation, build_run, keys_for, payload_map

    principal, agent = keys_for("principal"), keys_for("agent")
    delegation = build_delegation(principal, agent)
    run = build_run(agent, delegation)
    with pytest.raises(ValueError, match="payloads_omitted excludes"):
        write_bundle(
            io.BytesIO(),
            exporter=agent,
            software="t/0",
            delegations=[delegation],
            runs=[run.records],
            payloads=payload_map(delegation["hash_alg"]),
            payloads_omitted=True,
        )


def test_write_bundle_streams_lazy_payloads() -> None:
    """Twenty 2 MB bodies fetched one at a time must not peak near 40 MB in memory."""
    import tracemalloc
    from collections.abc import Iterator, Mapping

    from sealedrun.hashing import payload_digest
    from sealedrun.vectors import build_delegation, build_run, keys_for

    principal, agent = keys_for("principal"), keys_for("agent")
    delegation = build_delegation(principal, agent)
    run = build_run(agent, delegation)
    size = 2 * 1024 * 1024
    bodies = {payload_digest("sha-256", bytes([i]) * size): i for i in range(20)}

    class Lazy(Mapping[str, bytes]):
        fetched = 0

        def __getitem__(self, key: str) -> bytes:
            Lazy.fetched += 1
            return bytes([bodies[key]]) * size

        def __iter__(self) -> Iterator[str]:
            return iter(bodies)

        def __len__(self) -> int:
            return len(bodies)

    out = io.BytesIO()
    tracemalloc.start()
    manifest = write_bundle(
        out,
        exporter=agent,
        software="t/0",
        delegations=[delegation],
        runs=[run.records],
        payloads=Lazy(),
        principal=principal,
    )
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert Lazy.fetched == 20
    assert peak < 12 * size, f"peak {peak / 1024 / 1024:.1f} MB"
    with zipfile.ZipFile(io.BytesIO(out.getvalue())) as zf:
        names = zf.namelist()
        assert names[-1] == "manifest.json" and len(manifest["files"]) == len(names) - 1
        assert sum(1 for n in names if n.startswith("payloads/")) == 20
    assert read_bundle(out.getvalue()).manifest["bundle_id"] == manifest["bundle_id"]
