import io
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sealedrun import PrivateKeySet, RunWriter, create_delegation, payload_ref, write_bundle

START = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)


def seeded(prefix: bytes, profile: str = "sealedrun-hybrid-1") -> PrivateKeySet:
    from sealedrun.keys import PROFILES

    return PrivateKeySet.from_seeds(
        {alg: (prefix + alg.encode()).ljust(32, b"\0") for alg in PROFILES[profile]}
    )


class Clock:
    def __init__(self, start: datetime = START):
        self.current = start

    def __call__(self) -> datetime:
        self.current += timedelta(seconds=1)
        return self.current


class Ids:
    def __init__(self) -> None:
        self.n = 0

    def __call__(self) -> str:
        self.n += 1
        return f"0192b3c4-5d6e-7f80-9a1b-{self.n:012x}"


@pytest.fixture
def keyfactory() -> Any:
    return seeded


@pytest.fixture
def principal() -> PrivateKeySet:
    return seeded(b"principal-")


@pytest.fixture
def agent() -> PrivateKeySet:
    return seeded(b"agent-")


@pytest.fixture
def delegation(principal: PrivateKeySet, agent: PrivateKeySet) -> dict[str, Any]:
    return create_delegation(
        principal,
        agent.public,
        not_before=START - timedelta(days=1),
        not_after=START + timedelta(days=30),
        agent_name="test-agent",
        delegation_id="0192b3c4-5d6e-7f80-9a1b-000000000000",
    )


@pytest.fixture
def payloads() -> dict[str, bytes]:
    return {"req": b'{"messages":[{"role":"user","content":"hello"}]}', "res": b'{"choices":[]}'}


@pytest.fixture
def run(agent: PrivateKeySet, delegation: dict[str, Any], payloads: dict[str, bytes]) -> RunWriter:
    writer = RunWriter(agent, delegation, clock=Clock(), id_factory=Ids())
    writer.start()
    writer.append(
        "llm_call",
        target={
            "type": "model",
            "name": "gpt-4.1",
            "endpoint": "https://api.openai.com/v1",
            "location": "cloud",
            "provider": "openai",
        },
        payload=payload_ref("sha-256", payloads["req"], payloads["res"]),
        data_labels=["pii"],
        policy={"rule_id": "default", "decision": "allow", "reason": "no rule"},
        extensions={"sealedrun.llm": {"model": "gpt-4.1"}},
    )
    writer.append(
        "tool_call",
        target={
            "type": "tool",
            "name": "filesystem/read_file",
            "location": "local",
            "provider": "mcp:filesystem",
        },
        payload=payload_ref("sha-256", b"{}", storage="none"),
        parent_record_id=writer.records[-1]["record_id"],
        extensions={
            "sealedrun.mcp": {
                "server": "filesystem",
                "transport": "stdio",
                "method": "tools/call",
                "tool": "read_file",
            }
        },
    )
    writer.append(
        "anchor",
        target={"type": "witness", "name": "rekor"},
        extensions={
            "sealedrun.anchor": {
                "type": "rekor",
                "anchored_hash": writer.head,
                "anchored_seq": 2,
                "receipt": {"log_index": 1},
                "witness": "https://rekor.sigstore.dev",
            }
        },
    )
    writer.end()
    return writer


def body_map(payloads: dict[str, bytes]) -> dict[str, bytes]:
    from sealedrun import payload_digest

    return {payload_digest("sha-256", b): b for b in payloads.values()}


@pytest.fixture
def bundle_bytes(
    agent: PrivateKeySet,
    principal: PrivateKeySet,
    delegation: dict[str, Any],
    run: RunWriter,
    payloads: dict[str, bytes],
) -> bytes:
    out = io.BytesIO()
    write_bundle(
        out,
        exporter=agent,
        software="sealedrun-test/0.1.0",
        delegations=[delegation],
        runs=[run.records],
        payloads=body_map(payloads),
        principal=principal,
        bundle_id="0192b3c4-5d6e-7f80-9a1b-0000000000ff",
        created_at="2026-09-16T13:00:00.000Z",
    )
    return out.getvalue()
