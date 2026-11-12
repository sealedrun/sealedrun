import io
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest
from sealedrun import (
    PrivateKeySet,
    RunWriter,
    VerificationError,
    read_bundle,
    verify_bundle,
    write_bundle,
)
from sealedrun.__main__ import main
from sealedrun.schema import SCHEMA_DIR, validate

BUNDLES = SCHEMA_DIR.parent / "vectors" / "bundle"
WINDOW = {"since": "2026-09-16T12:00:02.000Z", "until": "2026-09-16T12:00:04.000Z"}


def _export(
    agent: PrivateKeySet,
    delegation: dict[str, Any],
    run: RunWriter,
    payloads: dict[str, bytes],
    query: dict[str, str] | None,
) -> bytes:
    from sealedrun import payload_digest

    out = io.BytesIO()
    write_bundle(
        out,
        exporter=agent,
        software="test/0",
        delegations=[delegation],
        runs=[run.records],
        payloads={payload_digest("sha-256", body): body for body in payloads.values()},
        query=query,
    )
    return out.getvalue()


def test_query_is_signed_and_reported(
    agent: PrivateKeySet, delegation: dict[str, Any], run: RunWriter, payloads: dict[str, bytes]
) -> None:
    bundle = read_bundle(_export(agent, delegation, run, payloads, WINDOW))
    assert validate("bundle.json", bundle.manifest) == []
    report = verify_bundle(bundle)
    assert report.query == WINDOW
    assert report.outside_window == {run.records[0]["run_id"]: len(run.records) - 2}


def test_bundle_without_query_reports_none(bundle_bytes: bytes) -> None:
    report = verify_bundle(read_bundle(bundle_bytes))
    assert report.query is None
    assert report.outside_window == {}


def test_changed_query_breaks_the_manifest(
    agent: PrivateKeySet, delegation: dict[str, Any], run: RunWriter, payloads: dict[str, bytes]
) -> None:
    data = _export(agent, delegation, run, payloads, WINDOW)
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as src, zipfile.ZipFile(out, "w") as dst:
        for name in src.namelist():
            content = src.read(name)
            if name == "manifest.json":
                manifest = json.loads(content)
                manifest["query"]["until"] = "2026-09-16T12:00:03.000Z"
                content = json.dumps(manifest).encode()
            dst.writestr(name, content)
    with pytest.raises(VerificationError) as info:
        verify_bundle(read_bundle(out.getvalue()))
    assert info.value.check == "manifest"


@pytest.mark.parametrize(
    "query",
    [
        {"since": "2026-09-16T12:00:02.000Z"},
        {**WINDOW, "since": "2026-09-16"},
        {**WINDOW, "label": ""},
        {**WINDOW, "note": "x" * 257},
        {**WINDOW, "agent": "extra"},
    ],
)
def test_malformed_query_fails_the_schema(
    agent: PrivateKeySet,
    delegation: dict[str, Any],
    run: RunWriter,
    payloads: dict[str, bytes],
    query: dict[str, str],
) -> None:
    with pytest.raises(VerificationError) as info:
        read_bundle(_export(agent, delegation, run, payloads, query))
    assert info.value.check == "schema"


def test_label_is_not_checked_on_a_slice(
    agent: PrivateKeySet, delegation: dict[str, Any], run: RunWriter
) -> None:
    out = io.BytesIO()
    write_bundle(
        out,
        exporter=agent,
        software="test/0",
        delegations=[delegation],
        runs=[run.records[2:]],
        query={**WINDOW, "label": "billing-agent"},
    )
    report = verify_bundle(read_bundle(out.getvalue()))
    assert report.outside_window == {run.records[0]["run_id"]: 2}


def test_cli_prints_the_window(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(BUNDLES / "window-label.zip")]) == 0
    out = capsys.readouterr().out
    assert (
        "exported window: 2026-09-16T12:00:03.000Z to 2026-09-16T12:10:02.000Z, "
        "run label billing-agent" in out
    )
    assert "exporter's note: incident 2026-09-16, exported by on-call" in out
    assert out.count("records outside the exported window: 2") == 2
    assert main([str(BUNDLES / "valid.zip")]) == 0
    assert "window" not in capsys.readouterr().out
    assert main([str(BUNDLES / "window-run-outside.zip")]) == 1
    assert capsys.readouterr().out.startswith("FAIL query")


def test_cli_strips_control_characters_from_the_query(
    agent: PrivateKeySet,
    delegation: dict[str, Any],
    run: RunWriter,
    payloads: dict[str, bytes],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "hostile.zip"
    hostile = {**WINDOW, "note": "\x1b[2K\x1b[HFAIL forged"}
    target.write_bytes(_export(agent, delegation, run, payloads, hostile))
    assert main([str(target)]) == 0
    assert "\x1b" not in capsys.readouterr().out
