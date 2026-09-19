import copy
import json

import pytest
from jsonschema import Draft202012Validator
from sealedrun.schema import SCHEMA_DIR, SCHEMA_FILES, validate, validate_extensions

ZERO = "0" * 64
UUID = "0192b3c4-5d6e-7f80-9a1b-2c3d4e5f6a7b"
B64 = "AQID"

KEYSET = {"ed25519": B64, "ml-dsa-65": B64}
SIGS = {"ed25519": B64, "ml-dsa-65": B64}

RUN_START = {
    "spec_version": "0.1",
    "record_id": UUID,
    "run_id": UUID,
    "seq": 0,
    "occurred_at": "2026-09-16T12:00:00.000Z",
    "principal_id": "abc",
    "agent_id": "abc",
    "kind": "run_start",
    "actor": {"type": "agent", "id": "abc"},
    "target": {"type": "none", "name": "run"},
    "data_labels": [],
    "outcome": "success",
    "extensions": {"sealedrun.delegation": {"delegation_id": UUID, "hash": "a" * 64}},
    "hash_alg": "sha-256",
    "prev_hash": ZERO,
    "hash": "b" * 64,
    "signatures": SIGS,
}

LLM_CALL = {
    **RUN_START,
    "seq": 1,
    "kind": "llm_call",
    "target": {
        "type": "model",
        "name": "gpt-4.1",
        "endpoint": "https://api.openai.com/v1/chat/completions",
        "location": "cloud",
        "provider": "openai",
    },
    "payload": {
        "request_hash": B64,
        "request_size": 10,
        "response_hash": B64,
        "response_size": 5,
        "storage": "bundle",
    },
    "data_labels": ["pii", "acme:tier-1"],
    "policy": {"rule_id": "r1", "decision": "allow", "reason": "no rule matched"},
    "extensions": {"sealedrun.llm": {"model": "gpt-4.1", "stream": False}},
    "prev_hash": "b" * 64,
    "hash": "c" * 64,
}

DELEGATION = {
    "spec_version": "0.1",
    "delegation_id": UUID,
    "principal_id": "abc",
    "principal_keys": KEYSET,
    "agent_id": "abc",
    "agent_keys": KEYSET,
    "not_before": "2026-09-16T00:00:00.000Z",
    "not_after": "2027-09-16T00:00:00.000Z",
    "hash_alg": "sha-256",
    "hash": "a" * 64,
    "signatures": SIGS,
}

MANIFEST = {
    "spec_version": "0.1",
    "bundle_id": UUID,
    "created_at": "2026-09-16T12:00:00.000Z",
    "exporter": {"agent_id": "abc", "software": "sealedrun-recorder/0.1.0"},
    "principal_id": "abc",
    "delegations": [UUID],
    "runs": [
        {
            "run_id": UUID,
            "hash_alg": "sha-256",
            "record_count": 2,
            "first_seq": 0,
            "first_hash": ZERO,
            "last_hash": "c" * 64,
            "complete": False,
        }
    ],
    "files": {f"runs/{UUID}.jsonl": B64, f"delegations/{UUID}.json": B64},
    "hash_alg": "sha-256",
    "hash": "d" * 64,
    "signatures": SIGS,
}


@pytest.mark.parametrize("name", SCHEMA_FILES)
def test_schema_files_are_valid_drafts(name: str) -> None:
    Draft202012Validator.check_schema(json.loads((SCHEMA_DIR / name).read_text()))


def test_valid_documents() -> None:
    assert validate("record.json", RUN_START) == []
    assert validate("record.json", LLM_CALL) == []
    assert validate("delegation.json", DELEGATION) == []
    assert validate("bundle.json", MANIFEST) == []
    assert validate_extensions(RUN_START["extensions"]) == []
    assert validate_extensions(LLM_CALL["extensions"]) == []


def _mutate(base: dict, **changes: object) -> dict:
    doc = copy.deepcopy(base)
    for key, value in changes.items():
        if value is None:
            doc.pop(key, None)
        else:
            doc[key] = value
    return doc


@pytest.mark.parametrize(
    "doc",
    [
        _mutate(RUN_START, kind="llm_call"),
        _mutate(RUN_START, prev_hash="1" + "0" * 63),
        _mutate(RUN_START, extensions={}),
        _mutate(LLM_CALL, seq=0),
        _mutate(LLM_CALL, hash="c" * 96),
        _mutate(LLM_CALL, hash_alg="sha-384"),
        _mutate(LLM_CALL, signatures={"ed25519": B64}),
        _mutate(LLM_CALL, signatures={"ed25519": B64, "ml-dsa-87": B64, "ml-dsa-65": B64}),
        _mutate(LLM_CALL, data_labels=["PII"]),
        _mutate(LLM_CALL, occurred_at="2026-09-16T12:00:00Z"),
        _mutate(LLM_CALL, policy={"rule_id": "r", "decision": "block", "reason": "x"}),
        _mutate(
            LLM_CALL,
            policy={"rule_id": "r", "decision": "redirect", "reason": "x"},
            outcome="success",
        ),
        _mutate(LLM_CALL, kind="human_approval"),
        _mutate(LLM_CALL, payload={"storage": "bundle", "request_hash": B64}),
        _mutate(LLM_CALL, unknown_field=1),
        _mutate(LLM_CALL, extensions={"nodot": {}}),
    ],
)
def test_invalid_records(doc: dict) -> None:
    assert validate("record.json", doc) != []


def test_invalid_extension_payloads() -> None:
    assert validate_extensions({"sealedrun.llm": {"stream": True}}) != []
    assert validate_extensions({"sealedrun.anchor": {"type": "rekor"}}) != []
    assert validate_extensions({"com.acme.custom": {"anything": 1}}) == []


def test_invalid_delegation_and_manifest() -> None:
    assert validate("delegation.json", _mutate(DELEGATION, agent_keys={"ed25519": B64})) != []
    assert validate("bundle.json", _mutate(MANIFEST, delegations=[])) != []
    assert validate("bundle.json", _mutate(MANIFEST, files={"manifest.json": B64})) != []
