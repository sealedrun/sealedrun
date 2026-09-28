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
