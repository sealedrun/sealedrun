"""Schema upgrade: a database written by an earlier release opens on this one."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sealedrun_recorder.db import ensure_schema, make_engine
from sealedrun_recorder.main import create_app
from sealedrun_recorder.settings import Settings
from sqlalchemy import inspect

RUNS_0_2_0 = """
CREATE TABLE runs (
    run_id VARCHAR(36) NOT NULL,
    bundle_id VARCHAR(36),
    source VARCHAR(16) NOT NULL,
    agent_id VARCHAR(128) NOT NULL,
    principal_id VARCHAR(128) NOT NULL,
    hash_alg VARCHAR(16) NOT NULL,
    started_at VARCHAR(24) NOT NULL,
    ended_at VARCHAR(24),
    record_count INTEGER NOT NULL,
    first_seq INTEGER NOT NULL,
    last_hash VARCHAR(96) NOT NULL,
    complete BOOLEAN NOT NULL,
    anchors INTEGER NOT NULL,
    labels_sent_to_cloud JSON NOT NULL,
    run_label VARCHAR(128),
    PRIMARY KEY (run_id)
)
"""
RUN_ID = "0b0e9f0c-5a54-4c0e-9d3b-2f6f1f6f0a01"


def _write_0_2_0_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.execute(RUNS_0_2_0)
    connection.execute(
        "INSERT INTO runs VALUES (?, NULL, 'live', 'agent-1', 'principal-1', 'sha256', "
        "'2026-09-26T10:00:00.000Z', NULL, 3, 0, 'sha256:00', 0, 0, '{\"nda\": 1}', 'nightly')",
        (RUN_ID,),
    )
    connection.commit()
    connection.close()


def test_a_0_2_0_database_opens_and_keeps_its_runs(tmp_path: Path) -> None:
    _write_0_2_0_database(tmp_path / "sealedrun.db")
    settings = Settings(data_dir=tmp_path, ui_dir=tmp_path / "no-ui")
    with TestClient(create_app(settings), base_url="http://localhost") as client:
        listing = client.get("/api/runs")
        assert listing.status_code == 200
        (run,) = [row for row in listing.json() if row["run_id"] == RUN_ID]
        assert run["labels_sent_to_cloud"] == {"nda": 1}
        assert run["labels_self_reported"] == {}
        assert run["run_label"] == "nightly"
        assert client.get(f"/api/runs/{RUN_ID}").status_code == 200


def test_upgrade_adds_the_missing_columns_once(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "sealedrun.db"
    _write_0_2_0_database(path)
    with caplog.at_level("WARNING", logger="sealedrun.recorder"):
        engine = make_engine(f"sqlite:///{path}")
    assert "runs.labels_self_reported, runs.last_anchor_at" in caplog.text
    columns = {column["name"] for column in inspect(engine).get_columns("runs")}
    assert {"labels_self_reported", "last_anchor_at"} <= columns
    assert ensure_schema(engine) == []
    engine.dispose()

    caplog.clear()
    with caplog.at_level("WARNING", logger="sealedrun.recorder"):
        make_engine(f"sqlite:///{path}").dispose()
    assert caplog.text == ""


def test_a_new_database_needs_no_upgrade(tmp_path: Path) -> None:
    engine = make_engine(f"sqlite:///{tmp_path / 'new.db'}")
    assert ensure_schema(engine) == []
