"""A small LangGraph agent whose model and tool calls are recorded by SealedRun.

The model is reached through the recorder's LLM proxy and the filesystem MCP server is
wrapped by ``sealedrun-mcp-wrap``, so both kinds of call land in one signed run.

Environment:
    SEALEDRUN_URL     recorder address (default http://127.0.0.1:8080)
    SEALEDRUN_TOKEN   recorder token (``SEALEDRUN_API_TOKEN`` of the recorder)
    SEALEDRUN_RUN     run label (default ``langgraph-demo``)
    MODEL             ``ollama:qwen3:8b`` (default) or ``openai:gpt-4.1-mini``
    WORKDIR           directory the filesystem tool may read (default: this folder)
"""

import asyncio
import os
import sys
from pathlib import Path

from langchain.agents import create_agent
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_mcp_adapters.client import MultiServerMCPClient

RECORDER = os.environ.get("SEALEDRUN_URL", "http://127.0.0.1:8080")
TOKEN = os.environ.get("SEALEDRUN_TOKEN", "")
RUN = os.environ.get("SEALEDRUN_RUN", "langgraph-demo")
RUN_HEADER = {"X-SealedRun-Run": RUN}
WORKDIR = Path(os.environ.get("WORKDIR", Path(__file__).parent)).resolve()
QUESTION = (
    "Read the file notes.txt in the allowed directory and answer in one sentence: what is it about?"
)


def make_model(spec: str) -> BaseChatModel:
    """Build the chat model behind ``spec`` with its base URL pointed at the recorder."""
    provider, _, name = spec.partition(":")
    if provider == "openai":
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=name,
            base_url=f"{RECORDER}/v1",
            api_key=TOKEN,
            default_headers=RUN_HEADER,
            temperature=0,
        )
    if provider == "ollama":
        from langchain_ollama import ChatOllama

        headers = {"Authorization": f"Bearer {TOKEN}", **RUN_HEADER}
        return ChatOllama(model=name, base_url=RECORDER, client_kwargs={"headers": headers})
    raise SystemExit(f"unknown model provider {provider!r}; use ollama:<name> or openai:<name>")


def filesystem_server() -> dict[str, object]:
    """Describe the filesystem MCP server, launched under ``sealedrun-mcp-wrap`` (stdio)."""
    return {
        "transport": "stdio",
        "command": "sealedrun-mcp-wrap",
        "args": [
            "--server",
            "filesystem",
            "--run",
            RUN,
            "--url",
            RECORDER,
            "--",
            "npx",
            "-y",
            "@modelcontextprotocol/server-filesystem",
            str(WORKDIR),
        ],
        "env": {**os.environ, "SEALEDRUN_TOKEN": TOKEN},
    }


async def run_agent(model: BaseChatModel, question: str = QUESTION) -> str:
    """Ask the agent one question with the filesystem tools and return its last message."""
    client = MultiServerMCPClient({"filesystem": filesystem_server()})  # type: ignore[dict-item]
    tools = await client.get_tools()
    agent = create_agent(model, tools, system_prompt="Use the tools to look at files. Be brief.")
    result = await agent.ainvoke({"messages": [{"role": "user", "content": question}]})
    last = result["messages"][-1]
    return str(last.content) if isinstance(last, AIMessage) else ""


def main() -> None:
    """Run one turn and print the answer and where the run is."""
    if not TOKEN:
        sys.exit("set SEALEDRUN_TOKEN to the recorder's SEALEDRUN_API_TOKEN")
    answer = asyncio.run(run_agent(make_model(os.environ.get("MODEL", "ollama:qwen3:8b"))))
    print(answer)
    print(f"\nrun {RUN!r} is in the recorder: {RECORDER}/api/runs")


if __name__ == "__main__":
    main()
