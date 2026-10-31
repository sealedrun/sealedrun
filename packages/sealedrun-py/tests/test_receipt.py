import copy
from typing import Any

import pytest
from sealedrun import (
    PrivateKeySet,
    RunWriter,
    VerificationError,
    payload_digest,
    payload_ref,
    receipt_for,
    verify_run,
)
from sealedrun.schema import validate_extensions
from sealedrun.signing import DOMAIN_RECORD, seal

CLOUD = {"type": "model", "name": "gpt-4.1", "location": "cloud", "provider": "openai"}
GIT = {"type": "tool", "name": "git/commit", "location": "local", "provider": "git"}


def proxied(alg: str, receipt: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload_ref(alg, b"req", b"resp")
    extensions: dict[str, Any] = {
        "sealedrun.proxy": {"upstream": "openai", "dialect": "openai", "status": 200}
    }
    if receipt is not None:
        extensions["sealedrun.receipt"] = receipt
    return {"kind": "llm_call", "target": CLOUD, "payload": payload, "extensions": extensions}


def proxy_receipt(alg: str, body: bytes = b"resp") -> dict[str, Any]:
    return {
        "kind": "http_response",
        "observed_by": "proxy",
        "digest": payload_digest(alg, body),
        "digest_alg": alg,
        "issuer": "api.openai.com",
        "status": 200,
    }


def run_with(agent: PrivateKeySet, delegation: dict[str, Any], *steps: dict[str, Any]) -> list:
    writer = RunWriter(agent, delegation)
    writer.start()
    for step in steps:
        writer.append(step.pop("kind"), **step)
    writer.end()
    return writer.records


def test_proxy_and_self_reported_receipts_are_counted(
    agent: PrivateKeySet, delegation: dict[str, Any]
) -> None:
    alg = delegation["hash_alg"]
    records = run_with(
        agent,
        delegation,
        proxied(alg, proxy_receipt(alg)),
        {
            "kind": "tool_call",
            "target": GIT,
            "extensions": {
                "sealedrun.step": {"source": "self_reported"},
                "sealedrun.receipt": {
                    **receipt_for("git_commit", ref="abc"),
                    "observed_by": "self_reported",
                },
            },
        },
    )
    report = verify_run(records, {delegation["delegation_id"]: delegation})
    assert (report.receipts_proxy, report.receipts_self_reported) == (1, 1)
    for record in records:
        assert validate_extensions(record.get("extensions", {})) == []


def _expect_receipt_failure(
    agent: PrivateKeySet, delegation: dict[str, Any], step: dict[str, Any], message: str
) -> None:
    records = run_with(agent, delegation, step)
    with pytest.raises(VerificationError) as info:
        verify_run(records, {delegation["delegation_id"]: delegation})
    assert (info.value.check, info.value.seq) == ("receipt", 1)
    assert message in str(info.value)


def test_proxy_receipt_must_match_response_hash(
    agent: PrivateKeySet, delegation: dict[str, Any]
) -> None:
    alg = delegation["hash_alg"]
    _expect_receipt_failure(
        agent, delegation, proxied(alg, proxy_receipt(alg, b"other")), "response_hash"
    )
    missing = proxy_receipt(alg)
    del missing["digest"]
    _expect_receipt_failure(agent, delegation, proxied(alg, missing), "response_hash")


def test_proxy_receipt_needs_proxy_extension_and_http_kind(
    agent: PrivateKeySet, delegation: dict[str, Any]
) -> None:
    alg = delegation["hash_alg"]
    step = proxied(alg, proxy_receipt(alg))
    del step["extensions"]["sealedrun.proxy"]
    _expect_receipt_failure(agent, delegation, step, "without sealedrun.proxy")
    _expect_receipt_failure(
        agent,
        delegation,
        proxied(alg, {**proxy_receipt(alg), "kind": "git_commit"}),
        "http_response",
    )
    other_alg = "sha-384" if alg == "sha-256" else "sha-256"
    _expect_receipt_failure(
        agent,
        delegation,
        proxied(alg, {**proxy_receipt(alg), "digest_alg": other_alg}),
        "digest_alg",
    )


def test_self_reported_receipt_is_refused_on_proxied_record(
    agent: PrivateKeySet, delegation: dict[str, Any]
) -> None:
    alg = delegation["hash_alg"]
    _expect_receipt_failure(
        agent,
        delegation,
        proxied(alg, {"kind": "opaque", "observed_by": "self_reported", "ref": "t"}),
        "self-reported receipt on a proxied record",
    )


def test_tampered_receipt_is_caught_even_when_resealed(
    agent: PrivateKeySet, delegation: dict[str, Any]
) -> None:
    alg = delegation["hash_alg"]
    records = run_with(agent, delegation, proxied(alg, proxy_receipt(alg)))
    edited = copy.deepcopy(records)
    edited[1]["extensions"]["sealedrun.receipt"]["digest"] = payload_digest(alg, b"x")
    with pytest.raises(VerificationError) as info:
        verify_run(edited, {delegation["delegation_id"]: delegation})
    assert info.value.check == "hash"
    edited[1] = seal(edited[1], DOMAIN_RECORD, agent)
    with pytest.raises(VerificationError) as info:
        verify_run(edited, {delegation["delegation_id"]: delegation})
    assert (info.value.check, info.value.seq) == ("receipt", 1)


def test_receipt_for_builds_the_extension() -> None:
    receipt = receipt_for("file_hash", ref="/tmp/out.txt", data=b"hello", issuer="host")
    assert receipt == {
        "kind": "file_hash",
        "ref": "/tmp/out.txt",
        "digest": payload_digest("sha-256", b"hello"),
        "digest_alg": "sha-256",
        "issuer": "host",
    }
    assert receipt_for("db_tx", ref="tx-1", status=201)["status"] == 201
    with pytest.raises(ValueError, match="db_tx"):
        receipt_for("blockchain")
    assert (
        validate_extensions({"sealedrun.receipt": {**receipt, "observed_by": "self_reported"}})
        == []
    )
    assert validate_extensions({"sealedrun.receipt": {"kind": "opaque"}}) != []
