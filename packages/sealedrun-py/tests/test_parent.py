from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sealedrun import (
    PrivateKeySet,
    RunWriter,
    VerificationError,
    check_parent_links,
    create_delegation,
    parent_of,
    scope_within,
    verify_run,
)
from sealedrun.schema import validate_extensions
from sealedrun.scope import Scope

START = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)


class Clock:
    def __init__(self, start: datetime = START):
        self.current = start

    def __call__(self) -> datetime:
        self.current += timedelta(seconds=1)
        return self.current


class Ids:
    def __init__(self, start: int = 0) -> None:
        self.n = start

    def __call__(self) -> str:
        self.n += 1
        return f"0192b3c4-5d6e-7f80-9a1b-{self.n:012x}"


A2A = {"type": "tool", "name": "planner/message", "location": "cloud", "provider": "a2a:planner"}
LOCAL = {"type": "model", "name": "qwen2.5:14b", "location": "local", "provider": "ollama"}


def parent_run(agent: PrivateKeySet, delegation: dict[str, Any], kind: str = "tool_call") -> list:
    writer = RunWriter(agent, delegation, clock=Clock(), id_factory=Ids())
    writer.start()
    if kind == "tool_call":
        writer.append(
            kind,
            target=A2A,
            extensions={"sealedrun.a2a": {"agent": "planner", "method": "SendMessage"}},
        )
    else:
        writer.append(kind, target={"type": "none", "name": "n"})
    writer.end()
    return writer.records


def child_run(
    agent: PrivateKeySet, delegation: dict[str, Any], parent: list, **override: Any
) -> list:
    link = {
        "run_id": parent[0]["run_id"],
        "record_id": parent[1]["record_id"],
        "delegation_hash": parent[0]["extensions"]["sealedrun.delegation"]["hash"],
        **override,
    }
    clock = Clock(START + timedelta(seconds=override.pop("offset", 10)))
    writer = RunWriter(agent, delegation, clock=clock, id_factory=Ids(0x100))
    writer.start(parent={k: v for k, v in link.items() if k != "offset"})
    writer.append("llm_call", target=LOCAL)
    writer.end()
    return writer.records


def test_start_writes_the_parent_link(agent: PrivateKeySet, delegation: dict[str, Any]) -> None:
    parent = parent_run(agent, delegation)
    child = child_run(agent, delegation, parent)
    binding = child[0]["extensions"]["sealedrun.delegation"]
    assert binding["parent_run_id"] == parent[0]["run_id"]
    assert binding["parent_record_id"] == parent[1]["record_id"]
    assert binding["parent_delegation_hash"] == delegation["hash"]
    assert validate_extensions(child[0]["extensions"]) == []
    assert parent_of(child) == {
        "run_id": parent[0]["run_id"],
        "record_id": parent[1]["record_id"],
        "delegation_hash": delegation["hash"],
    }
    assert parent_of(parent) is None
    verify_run(child, {delegation["delegation_id"]: delegation})
    with pytest.raises(ValueError, match="delegation_hash"):
        RunWriter(agent, delegation).start(parent={"run_id": "x", "record_id": "y"})


def test_partial_parent_fields_fail_schema(
    agent: PrivateKeySet, delegation: dict[str, Any]
) -> None:
    parent = parent_run(agent, delegation)
    child = child_run(agent, delegation, parent)
    binding = dict(child[0]["extensions"]["sealedrun.delegation"])
    del binding["parent_record_id"]
    assert validate_extensions({"sealedrun.delegation": binding}) != []


def _runs(*runs: list) -> dict[str, list]:
    return {r[0]["run_id"]: r for r in runs}


def test_linked_pair_passes_and_lone_child_is_unresolved(
    agent: PrivateKeySet, delegation: dict[str, Any]
) -> None:
    parent = parent_run(agent, delegation)
    child = child_run(agent, delegation, parent)
    delegations = {delegation["delegation_id"]: delegation}
    assert check_parent_links(_runs(parent, child), delegations) == []
    assert check_parent_links(_runs(child), delegations) == [child[0]["run_id"]]
    assert check_parent_links(_runs(parent), delegations) == []


@pytest.mark.parametrize(
    ("override", "check"),
    [
        ({"record_id": "0192b3c4-5d6e-7f80-9a1b-0000000000ff"}, "parent.record"),
        ({"delegation_hash": "b" * 64}, "parent.delegation"),
        ({"offset": -30}, "parent.time"),
    ],
)
def test_broken_links_fail_on_the_child(
    agent: PrivateKeySet, delegation: dict[str, Any], override: dict[str, Any], check: str
) -> None:
    parent = parent_run(agent, delegation)
    child = child_run(agent, delegation, parent, **override)
    with pytest.raises(VerificationError) as info:
        check_parent_links(_runs(parent, child), {delegation["delegation_id"]: delegation})
    assert (info.value.check, info.value.run_id, info.value.seq) == (check, child[0]["run_id"], 0)


def test_parent_record_must_be_a_tool_call(
    agent: PrivateKeySet, delegation: dict[str, Any]
) -> None:
    parent = parent_run(agent, delegation, kind="note")
    child = child_run(agent, delegation, parent)
    with pytest.raises(VerificationError) as info:
        check_parent_links(_runs(parent, child), {delegation["delegation_id"]: delegation})
    assert info.value.check == "parent.kind"


def test_child_scope_must_be_within_the_parents(
    principal: PrivateKeySet, agent: PrivateKeySet
) -> None:
    window = {"not_before": START - timedelta(days=1), "not_after": START + timedelta(days=30)}
    wide = create_delegation(
        principal, agent.public, scope={"allowed_locations": ["local", "cloud"]}, **window
    )
    narrow = create_delegation(
        principal, agent.public, scope={"allowed_locations": ["local"]}, **window
    )
    unlimited = create_delegation(principal, agent.public, **window)
    delegations = {d["delegation_id"]: d for d in (wide, narrow, unlimited)}
    parent = parent_run(agent, wide)
    assert check_parent_links(_runs(parent, child_run(agent, narrow, parent)), delegations) == []
    with pytest.raises(VerificationError) as info:
        check_parent_links(_runs(parent, child_run(agent, unlimited, parent)), delegations)
    assert info.value.check == "parent.scope"
    assert (
        check_parent_links(
            _runs(
                parent_run(agent, unlimited), child_run(agent, wide, parent_run(agent, unlimited))
            ),
            delegations,
        )
        == []
    )


def test_scope_within_rules() -> None:
    parent = Scope.parse(
        {
            "allowed_targets": [
                {"type": "tool", "name": "filesystem/*"},
                {"type": "model", "provider": "ollama"},
            ],
            "allowed_locations": ["local", "cloud"],
            "denied_labels": ["secret"],
            "max_records": 100,
        }
    )
    ok = Scope.parse(
        {
            "allowed_targets": [
                {"type": "tool", "name": "filesystem/read_*", "provider": "mcp:fs"}
            ],
            "allowed_locations": ["local"],
            "denied_labels": ["secret", "pii"],
            "max_records": 50,
        }
    )
    assert scope_within(ok, parent) is None
    assert scope_within(parent, parent) is None
    assert "allowed_targets" in (
        scope_within(
            Scope.parse(
                {"allowed_locations": ["local"], "denied_labels": ["secret"], "max_records": 1}
            ),
            parent,
        )
        or ""
    )
    assert "target" in (
        scope_within(
            Scope.parse({**_as_dict(ok), "allowed_targets": [{"type": "tool", "name": "other/*"}]}),
            parent,
        )
        or ""
    )
    assert "target" in (
        scope_within(Scope.parse({**_as_dict(ok), "allowed_targets": [{"type": "model"}]}), parent)
        or ""
    )
    assert "locations unknown" in (
        scope_within(
            Scope.parse({**_as_dict(ok), "allowed_locations": ["local", "unknown"]}), parent
        )
        or ""
    )
    assert "deny labels secret" in (
        scope_within(Scope.parse({**_as_dict(ok), "denied_labels": ["pii"]}), parent) or ""
    )
    assert "max_records" in (
        scope_within(Scope.parse({**_as_dict(ok), "max_records": 101}), parent) or ""
    )
    assert "max_records" in (
        scope_within(
            Scope.parse({k: v for k, v in _as_dict(ok).items() if k != "max_records"}), parent
        )
        or ""
    )
    assert scope_within(Scope.parse(None), Scope.parse(None)) is None


def _as_dict(scope: Scope) -> dict[str, Any]:
    out: dict[str, Any] = {"denied_labels": sorted(scope.denied_labels)}
    if scope.allowed_targets is not None:
        out["allowed_targets"] = list(scope.allowed_targets)
    if scope.allowed_locations is not None:
        out["allowed_locations"] = sorted(scope.allowed_locations)
    if scope.max_records is not None:
        out["max_records"] = scope.max_records
    return out
