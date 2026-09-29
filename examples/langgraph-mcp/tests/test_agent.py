"""The agent posts through the proxy and wraps the MCP server; no model or recorder needed."""

import os
import sys
from pathlib import Path
from typing import Any

import pytest
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import agent


class FakeToolModel(GenericFakeChatModel):
    """A scripted chat model that accepts tools, as `create_agent` needs."""

    def bind_tools(self, tools: Any, **kwargs: Any) -> Any:
        return self


def test_model_is_pointed_at_the_recorder_with_the_run_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(agent, "TOKEN", "change-me")
    model: Any = agent.make_model("openai:gpt-4.1-mini")
    assert str(model.openai_api_base or model.client._client.base_url).startswith(agent.RECORDER)
    assert model.default_headers == {"X-SealedRun-Run": agent.RUN}
    ollama: Any = agent.make_model("ollama:qwen3:8b")
    assert ollama.base_url == agent.RECORDER
    assert ollama.client_kwargs["headers"]["X-SealedRun-Run"] == agent.RUN
    with pytest.raises(SystemExit):
        agent.make_model("mistral:x")


def test_filesystem_server_runs_under_the_wrapper() -> None:
    server = agent.filesystem_server()
    args: Any = server["args"]
    assert server["command"] == "sealedrun-mcp-wrap"
    assert args[: args.index("--")] == [
        "--server",
        "filesystem",
        "--run",
        agent.RUN,
        "--url",
        agent.RECORDER,
    ]
    command = args[args.index("--") + 1 :]
    assert command[:3] == ["npx", "-y", "@modelcontextprotocol/server-filesystem"]
    env: Any = server["env"]
    assert "SEALEDRUN_TOKEN" in env


async def test_agent_answers_with_a_fake_model_and_a_fake_mcp_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_server = Path(__file__).with_name("fake_mcp_server.py")
    monkeypatch.setattr(
        agent,
        "filesystem_server",
        lambda: {
            "transport": "stdio",
            "command": sys.executable,
            "args": [str(fake_server)],
            "env": dict(os.environ),
        },
    )
    call = {"name": "read_file", "args": {"path": "notes.txt"}, "id": "call_1"}
    scripted = [AIMessage(content="", tool_calls=[call]), AIMessage(content="It is about a demo.")]
    model = FakeToolModel(messages=iter(scripted))
    answer = await agent.run_agent(model)
    assert answer == "It is about a demo."
