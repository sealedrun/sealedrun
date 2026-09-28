import asyncio
import io
import json
import time
import zipfile
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sealedrun import read_bundle, verify_bundle
from sealedrun.trust import Witness

from .conftest import PROXY_TOKEN, FakeTsa, FakeUpstream, load_test_tsa

TSA = "https://tsa.test/api/v1/timestamp"
FALLBACK = "http://tsa2.test/fallback"
CONFIG = "upstreams: []\n"
AUTH = {"Authorization": f"Bearer {PROXY_TOKEN}", "Sec-Fetch-Site": "same-origin"}


@pytest.fixture(scope="module")
def tsa_module() -> Any:
    return load_test_tsa()


@pytest.fixture
def authority(tsa_module: Any) -> Any:
    return tsa_module.TestAuthority()


def trust_for(authority: Any, uri: str = TSA) -> list[Witness]:
    return [
        Witness(
            type="rfc3161",
            uri=uri,
            subject="Test TSA Root",
            start=datetime(2025, 1, 1, tzinfo=UTC),
            end=datetime(2035, 1, 1, tzinfo=UTC),
            roots=(authority.root_pem,),
        )
    ]


def mount(upstream: FakeUpstream, tsa: FakeTsa, fallback: FakeTsa | None = None) -> None:
    upstream.routes["/api/v1/timestamp"] = tsa.timestamp
    upstream.routes["/api/v1/timestamp/certchain"] = tsa.certchain
    if fallback is not None:
        upstream.routes["/fallback"] = fallback.timestamp
        upstream.routes["/fallback/certchain"] = fallback.certchain


def start_run(client: TestClient, steps: int = 1) -> str:
    live = client.app.state.live  # type: ignore[attr-defined]
    run_id = str(live.start()["run_id"])
    for i in range(steps):
        live.append(run_id, "tool_call", target={"type": "tool", "name": f"step-{i}"})
    return run_id


def export(client: TestClient, run_id: str, end: bool = False) -> Any:
    reply = client.post(f"/api/runs/{run_id}/export", params={"end": end}, headers=AUTH)
    assert reply.status_code == 200, reply.text
    return read_bundle(io.BytesIO(reply.content))


def records_of(bundle: Any, run_id: str) -> list[dict[str, Any]]:
    return list(bundle.runs[run_id])


def test_off_by_default(make_proxy: Any) -> None:
    client = make_proxy(CONFIG)
    with client:
        assert client.app.state.anchoring.enabled is False
        run_id = start_run(client)
        bundle = export(client, run_id, end=True)
        assert [r["kind"] for r in records_of(bundle, run_id)] == [
            "run_start",
            "tool_call",
            "run_end",
        ]
        summary = client.get(f"/api/runs/{run_id}", headers=AUTH).json()
        assert summary["last_anchor_at"] is None


def test_export_anchors_the_head_and_the_bundle_verifies(
    make_proxy: Any, upstream: FakeUpstream, authority: Any
) -> None:
    tsa = FakeTsa(authority)
    mount(upstream, tsa)
    client = make_proxy(CONFIG, anchor_tsa_url=TSA, anchor_interval_seconds=3600)
    with client:
        run_id = start_run(client, steps=2)
        bundle = export(client, run_id)
        records = records_of(bundle, run_id)
        assert [r["kind"] for r in records] == ["run_start", "tool_call", "tool_call", "anchor"]
        anchor = records[3]["extensions"]["sealedrun.anchor"]
        assert anchor["type"] == "rfc3161"
        assert anchor["witness"] == TSA
        assert anchor["anchored_seq"] == 2
        assert anchor["anchored_hash"] == records[2]["hash"]
        assert anchor["receipt"]["chain"] == authority.chain_pems
        assert records[3]["target"] == {"type": "witness", "name": "tsa.test", "endpoint": TSA}
        assert bundle.anchors[records[3]["record_id"]] == anchor["receipt"]
        report = verify_bundle(bundle, witnesses=trust_for(authority))
        assert (report.runs[0].anchors, report.runs[0].anchors_witness_verified) == (1, 1)
        untrusted = verify_bundle(bundle, witnesses=[])
        assert untrusted.runs[0].anchors_witness_verified == 0
        summary = client.get(f"/api/runs/{run_id}", headers=AUTH).json()
        assert summary["last_anchor_at"] == records[3]["occurred_at"]
        assert summary["anchors"] == 1
        assert (tsa.requests, tsa.chain_requests) == (1, 1)

        again = export(client, run_id)
        assert len(records_of(again, run_id)) == 4
        assert tsa.requests == 1

        client.app.state.live.append(run_id, "tool_call", target={"type": "tool", "name": "more"})
        ended = export(client, run_id, end=True)
        kinds = [r["kind"] for r in records_of(ended, run_id)]
        assert kinds[-3:] == ["tool_call", "anchor", "run_end"]
        assert tsa.chain_requests == 1
        report = verify_bundle(ended, witnesses=trust_for(authority))
        assert (report.runs[0].anchors, report.runs[0].anchors_witness_verified) == (2, 2)


def test_full_chain_authority_without_certchain(
    make_proxy: Any, upstream: FakeUpstream, authority: Any
) -> None:
    tsa = FakeTsa(authority, include="chain")
    mount(upstream, tsa)
    client = make_proxy(CONFIG, anchor_tsa_url=TSA, anchor_interval_seconds=3600)
    with client:
        run_id = start_run(client)
        bundle = export(client, run_id)
        anchor = records_of(bundle, run_id)[-1]["extensions"]["sealedrun.anchor"]
        assert anchor["receipt"]["chain"] == []
        report = verify_bundle(bundle, witnesses=trust_for(authority))
        assert report.runs[0].anchors_witness_verified == 1


def test_retry_then_fallback(make_proxy: Any, upstream: FakeUpstream, authority: Any) -> None:
    primary = FakeTsa(authority, fail=2)
    fallback = FakeTsa(authority, include="chain")
    mount(upstream, primary, fallback)
    client = make_proxy(
        CONFIG, anchor_tsa_url=TSA, anchor_tsa_fallback_url=FALLBACK, anchor_interval_seconds=3600
    )
    with client:
        run_id = start_run(client)
        bundle = export(client, run_id)
        anchor = records_of(bundle, run_id)[-1]["extensions"]["sealedrun.anchor"]
        assert anchor["witness"] == FALLBACK
        assert (primary.requests, fallback.requests) == (2, 1)
        report = verify_bundle(bundle, witnesses=trust_for(authority, FALLBACK))
        assert report.runs[0].anchors_witness_verified == 1


def test_single_retry_on_one_authority(
    make_proxy: Any, upstream: FakeUpstream, authority: Any
) -> None:
    tsa = FakeTsa(authority, fail=1)
    mount(upstream, tsa)
    client = make_proxy(CONFIG, anchor_tsa_url=TSA, anchor_interval_seconds=3600)
    with client:
        run_id = start_run(client)
        bundle = export(client, run_id)
        assert records_of(bundle, run_id)[-1]["kind"] == "anchor"
        assert tsa.requests == 2


def test_witness_failure_never_blocks_the_run(
    make_proxy: Any, upstream: FakeUpstream, authority: Any, caplog: pytest.LogCaptureFixture
) -> None:
    tsa = FakeTsa(authority, fail=99)
    mount(upstream, tsa)
    client = make_proxy(CONFIG, anchor_tsa_url=TSA, anchor_interval_seconds=3600)
    with client:
        run_id = start_run(client)
        with caplog.at_level("WARNING", logger="sealedrun.anchoring"):
            bundle = export(client, run_id, end=True)
        kinds = [r["kind"] for r in records_of(bundle, run_id)]
        assert kinds == ["run_start", "tool_call", "run_end"]
        assert tsa.requests == 2
        assert "every authority failed" in caplog.text

        upstream.fail = "down"
        other = start_run(client)
        bundle = export(client, other)
        assert [r["kind"] for r in records_of(bundle, other)] == ["run_start", "tool_call"]


def test_bad_token_is_not_recorded(make_proxy: Any, upstream: FakeUpstream, authority: Any) -> None:
    def wrong_nonce(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=authority.respond(request.content, nonce=1))

    upstream.routes["/api/v1/timestamp"] = wrong_nonce
    client = make_proxy(CONFIG, anchor_tsa_url=TSA, anchor_interval_seconds=3600)
    with client:
        run_id = start_run(client)
        bundle = export(client, run_id)
        assert [r["kind"] for r in records_of(bundle, run_id)] == ["run_start", "tool_call"]


def test_background_loop_anchors_open_runs(
    make_proxy: Any, upstream: FakeUpstream, authority: Any
) -> None:
    tsa = FakeTsa(authority)
    mount(upstream, tsa)
    client = make_proxy(CONFIG, anchor_tsa_url=TSA, anchor_interval_seconds=0.05)
    with client:
        run_id = start_run(client)
        closed = start_run(client)
        client.app.state.live.end(closed)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            summary = client.get(f"/api/runs/{run_id}", headers=AUTH).json()
            if summary["anchors"] == 1:
                break
            time.sleep(0.05)
        assert summary["anchors"] == 1
        time.sleep(0.3)
        assert client.get(f"/api/runs/{run_id}", headers=AUTH).json()["anchors"] == 1
        assert client.get(f"/api/runs/{closed}", headers=AUTH).json()["anchors"] == 0
        assert tsa.requests == 1
        client.app.state.live.append(run_id, "tool_call", target={"type": "tool", "name": "x"})
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            summary = client.get(f"/api/runs/{run_id}", headers=AUTH).json()
            if summary["anchors"] == 2:
                break
            time.sleep(0.05)
        assert summary["anchors"] == 2
        assert tsa.requests == 2


def test_head_reports_last_record(make_proxy: Any) -> None:
    client = make_proxy(CONFIG)
    with client:
        live = client.app.state.live
        run_id = start_run(client)
        assert live.head(run_id)[0] == 1 and live.head(run_id)[2] == "tool_call"
        assert run_id in live.open_runs()
        live.end(run_id)
        assert run_id not in live.open_runs()
        with pytest.raises(Exception, match="closed"):
            live.head(run_id)


def test_anchor_receipt_file_in_zip(
    make_proxy: Any, upstream: FakeUpstream, authority: Any
) -> None:
    mount(upstream, FakeTsa(authority))
    client = make_proxy(CONFIG, anchor_tsa_url=TSA, anchor_interval_seconds=3600)
    with client:
        run_id = start_run(client)
        reply = client.post(f"/api/runs/{run_id}/export", headers=AUTH)
        with zipfile.ZipFile(io.BytesIO(reply.content)) as zf:
            names = [n for n in zf.namelist() if n.startswith("anchors/")]
            assert len(names) == 1
            receipt = json.loads(zf.read(names[0]))
            assert receipt["imprint_alg"] == "sha256" and receipt["token"]
    assert asyncio  # the loop task is cancelled on shutdown without errors


def test_oversize_witness_reply_is_a_failed_attempt(
    make_proxy: Any, upstream: FakeUpstream, authority: Any, caplog: pytest.LogCaptureFixture
) -> None:
    from sealedrun_recorder.anchoring import WITNESS_REPLY_BYTES

    tsa = FakeTsa(authority)
    mount(upstream, tsa)
    upstream.routes["/api/v1/timestamp"] = lambda r: httpx.Response(
        200, content=b"\x30" * (WITNESS_REPLY_BYTES + 1)
    )
    client = make_proxy(CONFIG, anchor_tsa_url=TSA, anchor_interval_seconds=3600)
    with client:
        run_id = start_run(client)
        with caplog.at_level("WARNING", logger="sealedrun.anchoring"):
            bundle = export(client, run_id, end=True)
    assert [r["kind"] for r in records_of(bundle, run_id)] == ["run_start", "tool_call", "run_end"]
    assert "exceeds size limit" in caplog.text
    assert client.app.state.anchoring._busy == {}  # type: ignore[attr-defined]
