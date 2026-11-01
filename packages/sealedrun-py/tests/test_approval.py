from typing import Any

import pytest
from sealedrun import PrivateKeySet, RunWriter, VerificationError, create_delegation, verify_run
from sealedrun.records import payload_ref
from sealedrun.schema import validate_extensions

SEND = {"type": "tool", "name": "mail/send", "location": "cloud", "provider": "mcp:mail"}
REQUIRE = {
    "rule_id": "eu-strict/require-approval",
    "decision": "require_approval",
    "reason": "external delivery",
}
REQUEST = b'{"to":"jane@example.com"}'


def answer(alg: str, decision: str, body: bytes = REQUEST, **extra: Any) -> dict[str, Any]:
    return {
        "kind": "human_approval",
        "actor": {"type": "human", "id": "jane.doe@example.com"},
        "target": SEND,
        "payload": payload_ref(alg, body),
        "extensions": {"sealedrun.approval": {"decision": decision}},
        **extra,
    }


def executed(alg: str, body: bytes = REQUEST, **extra: Any) -> dict[str, Any]:
    return {
        "kind": "tool_call",
        "target": SEND,
        "policy": dict(REQUIRE),
        "payload": payload_ref(alg, body, b"sent"),
        **extra,
    }


def findings_of(
    agent: PrivateKeySet, delegation: dict[str, Any], *steps: dict[str, Any], strict: bool = False
) -> list[tuple[str, int]]:
    writer = RunWriter(agent, delegation)
    writer.start()
    for step in steps:
        writer.append(step.pop("kind"), **step)
    writer.end()
    report = verify_run(
        writer.records, {delegation["delegation_id"]: delegation}, strict_approval=strict
    )
    assert report.complete
    return [(f.check, f.seq) for f in report.findings]


@pytest.fixture
def delegation(principal: PrivateKeySet, agent: PrivateKeySet) -> dict[str, Any]:
    return create_delegation(principal, agent.public)


def test_granted_before_the_step_leaves_no_finding(
    agent: PrivateKeySet, delegation: dict[str, Any]
) -> None:
    alg = delegation["hash_alg"]
    assert findings_of(agent, delegation, answer(alg, "granted"), executed(alg)) == []


def test_step_without_approval_is_a_finding(
    agent: PrivateKeySet, delegation: dict[str, Any]
) -> None:
    alg = delegation["hash_alg"]
    assert findings_of(agent, delegation, executed(alg)) == [("approval.missing", 1)]


def test_denied_then_executed_is_a_finding(
    agent: PrivateKeySet, delegation: dict[str, Any]
) -> None:
    alg = delegation["hash_alg"]
    assert findings_of(agent, delegation, answer(alg, "denied"), executed(alg)) == [
        ("approval.denied_but_executed", 2)
    ]


def test_approval_after_the_step_does_not_count(
    agent: PrivateKeySet, delegation: dict[str, Any]
) -> None:
    alg = delegation["hash_alg"]
    assert findings_of(agent, delegation, executed(alg), answer(alg, "granted")) == [
        ("approval.missing", 1)
    ]


def test_approval_of_another_request_does_not_count(
    agent: PrivateKeySet, delegation: dict[str, Any]
) -> None:
    alg = delegation["hash_alg"]
    assert findings_of(agent, delegation, answer(alg, "granted", b"other"), executed(alg)) == [
        ("approval.missing", 2)
    ]


def test_one_approval_covers_one_execution(
    agent: PrivateKeySet, delegation: dict[str, Any]
) -> None:
    alg = delegation["hash_alg"]
    assert findings_of(agent, delegation, answer(alg, "granted"), executed(alg), executed(alg)) == [
        ("approval.missing", 3)
    ]


def test_blocked_step_and_steps_without_policy_are_not_checked(
    agent: PrivateKeySet, delegation: dict[str, Any]
) -> None:
    alg = delegation["hash_alg"]
    blocked = executed(alg, outcome="blocked")
    plain = {"kind": "tool_call", "target": SEND, "payload": payload_ref(alg, REQUEST)}
    assert findings_of(agent, delegation, blocked, plain) == []


def test_legacy_human_approval_without_extension_matches_nothing(
    agent: PrivateKeySet, delegation: dict[str, Any]
) -> None:
    alg = delegation["hash_alg"]
    legacy = answer(alg, "granted")
    legacy["extensions"] = {}
    assert findings_of(agent, delegation, legacy, executed(alg)) == [("approval.missing", 2)]


def test_strict_mode_fails_at_the_first_finding(
    agent: PrivateKeySet, delegation: dict[str, Any]
) -> None:
    alg = delegation["hash_alg"]
    with pytest.raises(VerificationError) as info:
        findings_of(agent, delegation, answer(alg, "denied"), executed(alg), strict=True)
    assert (info.value.check, info.value.seq) == ("approval.denied_but_executed", 2)


def test_approval_extension_schema() -> None:
    assert validate_extensions({"sealedrun.approval": {"decision": "granted"}}) == []
    assert validate_extensions({"sealedrun.approval": {"decision": "granted", "note": "ok"}}) == []
    assert validate_extensions({"sealedrun.approval": {"decision": "maybe"}}) != []
    assert validate_extensions({"sealedrun.approval": {}}) != []
