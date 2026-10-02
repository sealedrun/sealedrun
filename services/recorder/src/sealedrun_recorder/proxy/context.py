"""What produced a run: the `sealedrun.context` extension of its `run_start` record (SPEC 10.6).

The recorder names itself, the policy set in force and, when the run opens on an MCP
`tools/list`, the tool inventory the agent saw. The agent names itself through the
`X-SealedRun-Agent: <name>/<version>` header on the first call of a run, through the MCP
`io.modelcontextprotocol/clientInfo` request metadata, or through the `gen_ai.agent.*` span
attributes; `agent_source` records which. The header never reaches an upstream: no dialect
lists it among the headers that pass through.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from fastapi import Request
from sealedrun.canonical import canonicalize

from sealedrun_recorder import __version__
from sealedrun_recorder.policy import Rule

AGENT_HEADER = "x-sealedrun-agent"
AGENT_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
AGENT_VERSION = re.compile(r"^[A-Za-z0-9._+-]{1,32}$")
CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
RECORDER_SOFTWARE = f"sealedrun-recorder/{__version__}"


class AgentError(ValueError):
    """The agent header cannot be used; the message says why."""


def header_agent(request: Request) -> tuple[str, str] | None:
    """Return `(name, version)` from the agent header; None when absent.

    Raises AgentError when the header is not `<name>/<version>` within the SPEC 10.6 patterns.
    """
    raw = request.headers.get(AGENT_HEADER)
    if raw is None:
        return None
    name, slash, version = raw.strip().partition("/")
    if not slash or not AGENT_NAME.match(name) or not AGENT_VERSION.match(version):
        raise AgentError(f"{AGENT_HEADER} must be <name>/<version>: {AGENT_NAME.pattern}")
    return name, version


def client_info_agent(message: Any) -> tuple[str, str] | None:
    """Return `(name, version)` from a JSON-RPC request's `_meta` clientInfo, else None."""
    if not isinstance(message, dict):
        return None
    params = message.get("params")
    meta = params.get("_meta") if isinstance(params, dict) else None
    info = meta.get(CLIENT_INFO) if isinstance(meta, dict) else None
    return _agent_pair(info)


def otel_agent(attributes: dict[str, Any]) -> tuple[str, str] | None:
    """Return `(name, version)` from `gen_ai.agent.name` / `gen_ai.agent.version`, else None."""
    return _agent_pair(
        {
            "name": attributes.get("gen_ai.agent.name"),
            "version": attributes.get("gen_ai.agent.version"),
        }
    )


def tool_inventory_digest(result: Any) -> str | None:
    """Return the SHA-256 of a `tools/list` result's `tools` sorted by name, else None."""
    tools = result.get("tools") if isinstance(result, dict) else None
    if not isinstance(tools, list) or not all(
        isinstance(tool, dict) and isinstance(tool.get("name"), str) for tool in tools
    ):
        return None
    ordered = sorted(tools, key=lambda tool: str(tool["name"]))
    return hashlib.sha256(canonicalize(ordered)).hexdigest()


def run_context(
    rule: Rule,
    agent: tuple[str, str] | None,
    source: str | None,
    *,
    tools: tuple[str, str] | None = None,
) -> dict[str, Any]:
    """Build the `sealedrun.context` object for a run that opens now.

    `agent` and `source` name the agent and where its name came from; `tools` is
    `(server, digest)` when the opening call is a `tools/list`.
    """
    context: dict[str, Any] = {"recorder_software": RECORDER_SOFTWARE}
    if agent is not None and source is not None:
        context["agent_software"], context["agent_version"] = agent
        context["agent_source"] = source
    if rule.set_hash is not None:
        context["policy_set_hash"] = rule.set_hash
    if tools is not None:
        context["tool_inventory_server"], context["tool_inventory_hash"] = tools
    return context


def _agent_pair(info: Any) -> tuple[str, str] | None:
    if not isinstance(info, dict):
        return None
    name, version = info.get("name"), info.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        return None
    if not AGENT_NAME.match(name) or not AGENT_VERSION.match(version):
        return None
    return name, version
