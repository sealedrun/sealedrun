from typing import Any

import pytest
from sealedrun import PrivateKeySet, RunWriter, VerificationError, create_delegation, verify_run
from sealedrun.schema import validate
from sealedrun.scope import Scope, glob_match

LOCAL_MODEL = {"type": "model", "name": "qwen2.5:14b", "location": "local", "provider": "ollama"}
READ_FILE = {
    "type": "tool",
    "name": "filesystem/read_file",
    "location": "local",
    "provider": "mcp:filesystem",
}
WRITE_FILE = {**READ_FILE, "name": "filesystem/write_file"}
CLOUD_MODEL = {"type": "model", "name": "gpt-4.1", "location": "cloud", "provider": "openai"}
SCOPE = {
    "allowed_targets": [
        {"type": "tool", "name": "filesystem/read_*", "provider": "mcp:filesystem"},
        {"type": "model", "provider": "ollama"},
    ],
    "allowed_locations": ["local"],
    "denied_labels": ["pii"],
    "max_records": 4,
    "budget_usd": 10,
}


def scoped(principal: PrivateKeySet, agent: PrivateKeySet, scope: Any) -> dict[str, Any]:
    return create_delegation(principal, agent.public, scope=scope)


def run_with(agent: PrivateKeySet, delegation: dict[str, Any], *steps: dict[str, Any]) -> list:
    writer = RunWriter(agent, delegation)
    writer.start()
    for step in steps:
        writer.append(step.pop("kind"), **step)
    writer.end()
    return writer.records


def findings_of(records: list, delegation: dict[str, Any]) -> list[tuple[str, int]]:
    report = verify_run(records, {delegation["delegation_id"]: delegation})
    assert report.complete
    return [(f.check, f.seq) for f in report.findings]


def test_scope_schema_accepts_structured_and_free_form_keys(
    principal: PrivateKeySet, agent: PrivateKeySet
) -> None:
    assert validate("delegation.json", scoped(principal, agent, SCOPE)) == []
    bad = scoped(principal, agent, {"allowed_targets": [{"endpoint": "x"}]})
    assert validate("delegation.json", bad) != []


def test_in_scope_run_has_no_findings(principal: PrivateKeySet, agent: PrivateKeySet) -> None:
    d = scoped(principal, agent, SCOPE)
    records = run_with(
        agent,
        d,
        {"kind": "llm_call", "target": LOCAL_MODEL},
        {"kind": "tool_call", "target": READ_FILE},
    )
    assert findings_of(records, d) == []


def test_target_outside_glob(principal: PrivateKeySet, agent: PrivateKeySet) -> None:
    d = scoped(principal, agent, SCOPE)
    records = run_with(agent, d, {"kind": "tool_call", "target": WRITE_FILE})
    assert findings_of(records, d) == [("scope.target", 1)]


def test_provider_mismatch_is_out_of_scope(principal: PrivateKeySet, agent: PrivateKeySet) -> None:
    d = scoped(principal, agent, SCOPE)
    records = run_with(
        agent, d, {"kind": "tool_call", "target": {**READ_FILE, "provider": "mcp:other"}}
    )
    assert findings_of(records, d) == [("scope.target", 1)]


def test_cloud_target_reports_target_and_location(
    principal: PrivateKeySet, agent: PrivateKeySet
) -> None:
    d = scoped(principal, agent, SCOPE)
    records = run_with(agent, d, {"kind": "llm_call", "target": CLOUD_MODEL})
    assert findings_of(records, d) == [("scope.target", 1), ("scope.location", 1)]


def test_blocked_attempt_is_still_reported(principal: PrivateKeySet, agent: PrivateKeySet) -> None:
    d = scoped(principal, agent, SCOPE)
    records = run_with(agent, d, {"kind": "llm_call", "target": CLOUD_MODEL, "outcome": "blocked"})
    assert ("scope.location", 1) in findings_of(records, d)


def test_denied_label(principal: PrivateKeySet, agent: PrivateKeySet) -> None:
    d = scoped(principal, agent, SCOPE)
    records = run_with(
        agent, d, {"kind": "tool_call", "target": READ_FILE, "data_labels": ["legal", "pii"]}
    )
    assert findings_of(records, d) == [("scope.label", 1)]


def test_max_records_reported_once(principal: PrivateKeySet, agent: PrivateKeySet) -> None:
    d = scoped(principal, agent, SCOPE)
    steps = [{"kind": "tool_call", "target": dict(READ_FILE)} for _ in range(4)]
    records = run_with(agent, d, *steps)
    assert len(records) == 6
    assert findings_of(records, d) == [("scope.max_records", 4)]


def test_strict_scope_fails_at_first_finding(
    principal: PrivateKeySet, agent: PrivateKeySet
) -> None:
    d = scoped(principal, agent, SCOPE)
    records = run_with(agent, d, {"kind": "llm_call", "target": CLOUD_MODEL})
    with pytest.raises(VerificationError) as info:
        verify_run(records, {d["delegation_id"]: d}, strict_scope=True)
    assert (info.value.check, info.value.seq) == ("scope.target", 1)


def test_human_and_none_targets_skip_location(
    principal: PrivateKeySet, agent: PrivateKeySet
) -> None:
    d = scoped(principal, agent, {"allowed_locations": ["local"]})
    records = run_with(
        agent,
        d,
        {
            "kind": "human_approval",
            "actor": {"type": "human", "id": "reviewer@example.com"},
            "target": {"type": "human", "name": "reviewer"},
        },
        {"kind": "note", "target": {"type": "none", "name": "note"}},
        {"kind": "memory_read", "target": {"type": "memory", "name": "kv"}},
    )
    assert findings_of(records, d) == [("scope.location", 3)]


def test_structural_records_are_exempt(principal: PrivateKeySet, agent: PrivateKeySet) -> None:
    d = scoped(
        principal, agent, {"allowed_targets": [{"type": "tool"}], "allowed_locations": ["local"]}
    )
    records = run_with(agent, d)
    assert findings_of(records, d) == []


def test_no_scope_or_free_form_only_means_no_findings(
    principal: PrivateKeySet, agent: PrivateKeySet
) -> None:
    for scope in (None, {"budget_usd": 10}):
        d = scoped(principal, agent, scope)
        records = run_with(
            agent, d, {"kind": "llm_call", "target": CLOUD_MODEL, "data_labels": ["pii"]}
        )
        assert findings_of(records, d) == []


def test_malformed_scope_fails_schema(principal: PrivateKeySet, agent: PrivateKeySet) -> None:
    d = scoped(principal, agent, {"max_records": 0})
    records = run_with(agent, d)
    with pytest.raises(VerificationError) as info:
        verify_run(records, {d["delegation_id"]: d})
    assert info.value.check == "schema"
    for bad in ({"allowed_targets": "x"}, {"denied_labels": [1]}, {"allowed_targets": [{}]}):
        with pytest.raises(ValueError):
            Scope.parse(bad)


def test_glob_match_only_star() -> None:
    assert glob_match("filesystem/*", "filesystem/read_file")
    assert glob_match("*", "")
    assert glob_match("a*b*c", "a-b-c") and glob_match("a*b*c", "abc")
    assert not glob_match("filesystem/read_?", "filesystem/read_x")
    assert not glob_match("filesystem/*", "other/read_file")
    assert not glob_match("a.b", "axb")
