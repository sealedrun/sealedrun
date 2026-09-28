import os
import stat
from datetime import UTC, datetime
from typing import Any

import pytest
from sealedrun import verify_bundle
from sealedrun.trust import Witness

from .conftest import FakeRekorHttp, FakeTsa, FakeUpstream, load_fake_rekor, load_test_tsa
from .test_anchoring import AUTH, CONFIG, TSA, export, records_of, start_run, trust_for

REKOR = "https://rekor.test"


@pytest.fixture(scope="module")
def modules() -> tuple[Any, Any]:
    return load_test_tsa(), load_fake_rekor()


def log_trust(log: Any) -> Witness:
    return Witness(
        type="rekor",
        uri=REKOR,
        subject="test log",
        start=datetime(2025, 1, 1, tzinfo=UTC),
        public_key=log.log_key_pem,
        log_id=log.log_id,
    )


def test_identity_publishes_the_anchor_key(make_proxy: Any, tmp_path: Any) -> None:
    client = make_proxy(CONFIG)
    with client:
        identity = client.get("/api/identity", headers=AUTH).json()
        assert identity["anchor_public_key"].startswith("-----BEGIN PUBLIC KEY-----")
        key_file = tmp_path / "keys" / "anchor.pem"
        assert stat.S_IMODE(os.stat(key_file).st_mode) == 0o600
        first = identity["anchor_public_key"]
    with client:
        assert client.get("/api/identity", headers=AUTH).json()["anchor_public_key"] == first


def test_both_witnesses_anchor_the_same_head(
    make_proxy: Any, upstream: FakeUpstream, modules: tuple[Any, Any]
) -> None:
    tsa_module, rekor_module = modules
    authority = tsa_module.TestAuthority()
    log = rekor_module.FakeRekor()
    log.fill(4)
    tsa = FakeTsa(authority)
    rekor_http = FakeRekorHttp(log)
    upstream.routes["/api/v1/timestamp"] = tsa.timestamp
    upstream.routes["/api/v1/timestamp/certchain"] = tsa.certchain
    upstream.routes["/api/v1/log/entries"] = rekor_http.entries
    client = make_proxy(
        CONFIG, anchor_tsa_url=TSA, anchor_rekor_url=REKOR + "/", anchor_interval_seconds=3600
    )
    with client:
        run_id = start_run(client, steps=2)
        bundle = export(client, run_id, end=True)
        records = records_of(bundle, run_id)
        kinds = [r["kind"] for r in records]
        assert kinds == ["run_start", "tool_call", "tool_call", "anchor", "anchor", "run_end"]
        first, second = (r["extensions"]["sealedrun.anchor"] for r in records[3:5])
        assert (first["type"], second["type"]) == ("rfc3161", "rekor")
        assert first["anchored_seq"] == second["anchored_seq"] == 2
        assert first["anchored_hash"] == second["anchored_hash"] == records[2]["hash"]
        assert second["witness"] == REKOR
        assert (
            second["receipt"]["public_key"]
            == client.get("/api/identity", headers=AUTH).json()["anchor_public_key"]
        )
        assert second["receipt"]["inclusion_proof"]["tree_size"] == 5
        report = verify_bundle(bundle, witnesses=[*trust_for(authority), log_trust(log)])
        assert (report.runs[0].anchors, report.runs[0].anchors_witness_verified) == (2, 2)
        report = verify_bundle(bundle, witnesses=[log_trust(log)])
        assert report.runs[0].anchors_witness_verified == 1
        assert (tsa.requests, rekor_http.requests) == (1, 1)


def test_rekor_only_and_rekor_failure(
    make_proxy: Any, upstream: FakeUpstream, modules: tuple[Any, Any]
) -> None:
    _, rekor_module = modules
    log = rekor_module.FakeRekor()
    rekor_http = FakeRekorHttp(log, fail=1)
    upstream.routes["/api/v1/log/entries"] = rekor_http.entries
    client = make_proxy(CONFIG, anchor_rekor_url=REKOR, anchor_interval_seconds=3600)
    with client:
        assert client.app.state.anchoring.enabled is True
        run_id = start_run(client)
        bundle = export(client, run_id)
        assert [r["kind"] for r in records_of(bundle, run_id)] == ["run_start", "tool_call"]
        bundle = export(client, run_id)
        records = records_of(bundle, run_id)
        assert [r["kind"] for r in records] == ["run_start", "tool_call", "anchor"]
        assert records[2]["extensions"]["sealedrun.anchor"]["type"] == "rekor"
        report = verify_bundle(bundle, witnesses=[log_trust(log)])
        assert report.runs[0].anchors_witness_verified == 1
        assert rekor_http.requests == 2
