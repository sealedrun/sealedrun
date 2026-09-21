from typing import Any

from sealedrun import PrivateKeySet, create_delegation, verify_delegation
from sealedrun.schema import validate
from sealedrun.signing import DOMAIN_DELEGATION, seal


def test_valid(delegation: dict[str, Any]) -> None:
    assert verify_delegation(delegation) is None
    assert validate("delegation.json", delegation) == []


def test_wrong_agent_id(delegation: dict[str, Any]) -> None:
    assert verify_delegation({**delegation, "agent_id": "x"}) is not None


def test_forged_by_other_principal(delegation: dict[str, Any]) -> None:
    forged = seal(delegation, DOMAIN_DELEGATION, PrivateKeySet.generate())
    assert "signature" in (verify_delegation(forged) or "")


def test_self_delegation(agent: PrivateKeySet) -> None:
    d = create_delegation(agent, agent.public)
    assert d["principal_id"] == d["agent_id"]
    assert verify_delegation(d) is None


def test_did_principal_rejected(principal: PrivateKeySet, agent: PrivateKeySet) -> None:
    d = create_delegation(principal, agent.public, principal_id="did:web:example.com")
    assert "did" in (verify_delegation(d) or "")


def test_wrong_principal_id(delegation: dict[str, Any]) -> None:
    assert verify_delegation({**delegation, "principal_id": "x"}) is not None
