from pathlib import Path

import pytest
from sealedrun.__main__ import main
from sealedrun.schema import SCHEMA_DIR

BUNDLES = SCHEMA_DIR.parent / "vectors" / "bundle"


def test_cli_reports_witness_verified_anchors(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(BUNDLES / "valid.zip")]) == 0
    out = capsys.readouterr().out
    assert "OK bundle" in out and "principal not confirmed" in out
    assert "anchors 1, witness verified 1" in out


def test_cli_trusted_principal_and_failures(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    import json

    keys = json.loads((SCHEMA_DIR.parent / "vectors" / "keys.json").read_text())
    assert main([str(BUNDLES / "valid.zip"), keys["principal"]["kid"]]) == 0
    assert "principal trusted" in capsys.readouterr().out
    assert main([str(BUNDLES / "tampered-record.zip")]) == 1
    assert capsys.readouterr().out.startswith("FAIL bundle")
    broken = tmp_path / "x.zip"
    broken.write_bytes(b"not a zip")
    assert main([str(broken)]) == 1
    assert capsys.readouterr().out.startswith("FAIL bundle")
    assert main([]) == 2


def test_cli_never_prints_terminal_control_characters(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    import json
    import zipfile

    with zipfile.ZipFile(BUNDLES / "valid.zip") as source:
        manifest = json.loads(source.read("manifest.json"))
        members = {name: source.read(name) for name in source.namelist()}
    hostile = "runs/\x1b[2K\x1b[HOK bundle looks fine"
    manifest["files"][hostile] = next(iter(manifest["files"].values()))
    members["manifest.json"] = json.dumps(manifest).encode()
    target = tmp_path / "hostile.zip"
    with zipfile.ZipFile(target, "w") as sink:
        for name, data in members.items():
            sink.writestr(name, data)
    assert main([str(target)]) == 1
    out = capsys.readouterr().out
    assert out.startswith("FAIL")
    assert "\x1b" not in out


def test_cli_max_total_bytes_flag(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--max-total-bytes", "100", str(BUNDLES / "valid.zip")]) == 1
    out = capsys.readouterr().out
    assert out.startswith("FAIL bundle") and "claimed, limit 100 B" in out
    assert main([str(BUNDLES / "valid.zip"), "--max-total-bytes", "100000000"]) == 0
    assert main(["--max-total-bytes", "0", str(BUNDLES / "valid.zip")]) == 2
    assert main(["--max-total-bytes", "x", str(BUNDLES / "valid.zip")]) == 2


def test_cli_reports_omitted_payloads(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(BUNDLES / "payloads-omitted.zip")]) == 0
    assert "payloads omitted by exporter (bodies not checked)" in capsys.readouterr().out
    assert main([str(BUNDLES / "valid.zip")]) == 0
    assert "omitted" not in capsys.readouterr().out
