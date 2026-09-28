"""Upstream model providers the proxy forwards to, read from a YAML file.

Example file::

    upstreams:
      - name: openai
        url: https://api.openai.com/v1
        dialect: openai
        key_env: OPENAI_API_KEY
        location: cloud
        models: ["gpt-*", "o*", "text-embedding-*"]
      - name: ollama
        url: http://127.0.0.1:11434/v1
        dialect: openai
        location: local
        models: ["*:*"]
      - name: anthropic-subscription
        url: https://api.anthropic.com
        dialect: anthropic
        client_auth: passthrough
        location: cloud
        models: ["claude-*"]
    mcp_servers:
      - name: github
        url: https://api.githubcopilot.com/mcp/
        key_env: GITHUB_MCP_TOKEN
        location: cloud

`url` is the base URL the vendor's own SDK would use for that wire format. A request is routed to
the first upstream of its wire format whose `models` patterns match the requested model, so one
model can be reachable through several formats. Upstream URLs come only from this file, never
from a request. See `upstreams.example.yaml` for the common providers.

`mcp_servers` lists the MCP servers reachable at `/mcp/<name>`; their `url` is the server's
Streamable HTTP endpoint. `a2a_agents` lists A2A agents reachable at `/a2a/<name>` with the same
fields; their `url` is the agent's JSON-RPC endpoint from its agent card. All lists are optional.
"""

from __future__ import annotations

import fnmatch
import os
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml
from pydantic import SecretStr

DIALECTS = frozenset({"openai", "anthropic", "ollama", "gemini"})
LOCATIONS = frozenset({"local", "cloud", "unknown"})
CLIENT_AUTH = {"replace": False, "passthrough": True}
AUTH_STYLES = frozenset({"bearer", "x-api-key", "x-goog-api-key", "api-key", "none"})
MCP_AUTH_STYLES = frozenset({"bearer", "x-api-key", "api-key", "none"})
MCP_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
DEFAULT_AUTH = {
    "openai": "bearer",
    "anthropic": "x-api-key",
    "ollama": "bearer",
    "gemini": "x-goog-api-key",
}
CREDENTIAL_HEADERS = frozenset(
    {"authorization", "x-api-key", "x-goog-api-key", "api-key", "cookie", "proxy-authorization"}
)


def _check_url(url: Any, where: str) -> str:
    """Return `url` if it is a bare http(s) URL: no credentials, query or fragment.

    The URL is sealed into every record's `target.endpoint`, so a secret in it would be signed,
    exported and impossible to remove; credentials belong in `key_env` or `headers`.
    """
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        raise UpstreamConfigError(f"{where}: url must be http(s)")
    parts = urlsplit(url)
    if parts.username is not None or parts.password is not None:
        raise UpstreamConfigError(f"{where}: url must not carry credentials; use key_env")
    if parts.query or parts.fragment:
        raise UpstreamConfigError(f"{where}: url must not carry a query string or fragment")
    return url


class UpstreamConfigError(ValueError):
    """The upstreams file is malformed."""


@dataclass(frozen=True)
class Upstream:
    """One provider endpoint and the credential the proxy swaps in for it.

    `key_env` names the variable the key is read from; when it is set in the file but missing
    from the environment, `key` is None and calls to this upstream are refused. With
    `client_auth` the client's own credential is forwarded instead, when the client sent one
    (Claude Code on a subscription login); the configured key, if any, is the fallback.
    """

    name: str
    url: str
    dialect: str
    location: str
    models: tuple[str, ...]
    auth: str = "none"
    key_env: str | None = None
    key: SecretStr | None = None
    headers: Mapping[str, str] = field(default_factory=dict)
    client_auth: bool = False

    @property
    def missing_key(self) -> bool:
        """Tell whether a key is configured but its environment variable is not set."""
        return self.key_env is not None and self.key is None

    def ready(self, client: Mapping[str, str] | None = None) -> bool:
        """Tell whether a call can be authenticated, with `client` credential headers if any."""
        return not self.missing_key or bool(self.client_auth and client)

    def serves(self, model: str) -> bool:
        """Tell whether `model` matches one of this upstream's model patterns."""
        return any(fnmatch.fnmatchcase(model, pattern) for pattern in self.models)

    def endpoint(self, path: str) -> str:
        """Join the upstream base URL and an API path such as `/chat/completions`."""
        return self.url.rstrip("/") + path

    def request_headers(self, client: Mapping[str, str] | None = None) -> dict[str, str]:
        """Return the static headers of this upstream plus its credential header.

        `client` holds the caller's own credential headers; they replace the configured key
        only on an upstream with `client_auth`.
        """
        return _with_credential(self, client)


@dataclass(frozen=True)
class McpServer:
    """One MCP server behind `/mcp/<name>` and the credential the proxy swaps in for it.

    Credentials work as for an `Upstream`: `key_env` with `auth`, or the client's own
    `Authorization` with `client_auth`.
    """

    name: str
    url: str
    location: str
    auth: str = "none"
    key_env: str | None = None
    key: SecretStr | None = None
    headers: Mapping[str, str] = field(default_factory=dict)
    client_auth: bool = False

    @property
    def missing_key(self) -> bool:
        """Tell whether a key is configured but its environment variable is not set."""
        return self.key_env is not None and self.key is None

    def ready(self, client: Mapping[str, str] | None = None) -> bool:
        """Tell whether a call can be authenticated, with `client` credential headers if any."""
        return not self.missing_key or bool(self.client_auth and client)

    def request_headers(self, client: Mapping[str, str] | None = None) -> dict[str, str]:
        """Return the static headers of this server plus its credential header."""
        return _with_credential(self, client)


def _with_credential(
    target: Upstream | McpServer, client: Mapping[str, str] | None
) -> dict[str, str]:
    headers = dict(target.headers)
    if target.client_auth and client:
        return {**headers, **client}
    if target.key is None or target.auth == "none":
        return headers
    secret = target.key.get_secret_value()
    if target.auth == "bearer":
        headers["authorization"] = f"Bearer {secret}"
    else:
        headers[target.auth] = secret
    return headers


A2aAgent = McpServer


class Upstreams:
    """The configured upstreams in file order, and the MCP servers and A2A agents by name."""

    def __init__(
        self,
        upstreams: list[Upstream],
        mcp_servers: list[McpServer] | None = None,
        a2a_agents: list[A2aAgent] | None = None,
    ):
        self._upstreams = upstreams
        self._mcp = {server.name: server for server in mcp_servers or []}
        self._a2a = {agent.name: agent for agent in a2a_agents or []}

    def __iter__(self) -> Iterator[Upstream]:
        return iter(self._upstreams)

    def route(self, dialect: str, model: str) -> Upstream | None:
        """Return the first upstream of `dialect` serving `model`, or None."""
        return next((u for u in self._upstreams if u.dialect == dialect and u.serves(model)), None)

    def dialects_for(self, model: str) -> list[str]:
        """Return the wire formats through which `model` is reachable, in file order."""
        return list(dict.fromkeys(u.dialect for u in self._upstreams if u.serves(model)))

    def mcp(self, name: str) -> McpServer | None:
        """Return the MCP server called `name`, or None."""
        return self._mcp.get(name)

    @property
    def mcp_servers(self) -> list[McpServer]:
        """The MCP servers in file order."""
        return list(self._mcp.values())

    def a2a(self, name: str) -> A2aAgent | None:
        """Return the A2A agent called `name`, or None."""
        return self._a2a.get(name)

    @property
    def a2a_agents(self) -> list[A2aAgent]:
        """The A2A agents in file order."""
        return list(self._a2a.values())


def load_upstreams(path: Path, environ: Mapping[str, str] | None = None) -> Upstreams:
    """Read the upstreams file; a missing file means no upstreams.

    Raises UpstreamConfigError when an entry is malformed or a name repeats.
    """
    if not path.is_file():
        return Upstreams([])
    env = os.environ if environ is None else environ
    try:
        document = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as error:
        raise UpstreamConfigError(f"{path}: {error}") from error
    if not isinstance(document, dict):
        raise UpstreamConfigError(
            f"{path}: expected a mapping with 'upstreams' / 'mcp_servers' / 'a2a_agents'"
        )
    entries = document.get("upstreams", [])
    if not isinstance(entries, list):
        raise UpstreamConfigError(f"{path}: 'upstreams' must be a list")
    servers = document.get("mcp_servers", [])
    if not isinstance(servers, list):
        raise UpstreamConfigError(f"{path}: 'mcp_servers' must be a list")
    agents = document.get("a2a_agents", [])
    if not isinstance(agents, list):
        raise UpstreamConfigError(f"{path}: 'a2a_agents' must be a list")
    upstreams = [_parse(entry, env) for entry in entries]
    mcp_servers = [_parse_mcp(entry, env) for entry in servers]
    a2a_agents = [_parse_mcp(entry, env, "A2A agent") for entry in agents]
    for kind, names in (
        ("upstream", [u.name for u in upstreams]),
        ("MCP server", [s.name for s in mcp_servers]),
        ("A2A agent", [a.name for a in a2a_agents]),
    ):
        if len(names) != len(set(names)):
            raise UpstreamConfigError(f"{path}: {kind} names must be unique")
    return Upstreams(upstreams, mcp_servers, a2a_agents)


def _parse(entry: Any, env: Mapping[str, str]) -> Upstream:
    if not isinstance(entry, dict):
        raise UpstreamConfigError("each upstream must be a mapping")
    name = entry.get("name")
    if not isinstance(name, str) or not name:
        raise UpstreamConfigError("upstream needs a name")
    url = entry.get("url")
    dialect = entry.get("dialect", "openai")
    location = entry.get("location", "unknown")
    models = entry.get("models", ["*"])
    key_env = entry.get("key_env")
    headers = entry.get("headers", {})
    client_auth = entry.get("client_auth", "replace")
    url = _check_url(url, f"upstream {name}")
    if dialect not in DIALECTS:
        raise UpstreamConfigError(f"upstream {name}: dialect must be one of {sorted(DIALECTS)}")
    if location not in LOCATIONS:
        raise UpstreamConfigError(f"upstream {name}: location must be one of {sorted(LOCATIONS)}")
    if not isinstance(models, list) or not all(isinstance(m, str) and m for m in models):
        raise UpstreamConfigError(f"upstream {name}: models must be a list of patterns")
    if key_env is not None and (not isinstance(key_env, str) or not key_env):
        raise UpstreamConfigError(f"upstream {name}: key_env must be a variable name")
    auth = entry.get("auth", DEFAULT_AUTH[dialect] if key_env else "none")
    if auth not in AUTH_STYLES:
        raise UpstreamConfigError(f"upstream {name}: auth must be one of {sorted(AUTH_STYLES)}")
    _check_common(f"upstream {name}", client_auth, headers)
    value = env.get(key_env) if key_env else None
    return Upstream(
        name=name,
        url=url,
        dialect=dialect,
        location=location,
        models=tuple(models),
        auth=auth,
        key_env=key_env,
        key=SecretStr(value) if value else None,
        headers={k.lower(): v for k, v in headers.items()},
        client_auth=CLIENT_AUTH[client_auth],
    )


def _parse_mcp(entry: Any, env: Mapping[str, str], what: str = "MCP server") -> McpServer:
    if not isinstance(entry, dict):
        raise UpstreamConfigError(f"each {what} must be a mapping")
    name = entry.get("name")
    if not isinstance(name, str) or not MCP_NAME.match(name):
        raise UpstreamConfigError(f"{what} needs a name matching {MCP_NAME.pattern}")
    url = entry.get("url")
    location = entry.get("location", "unknown")
    key_env = entry.get("key_env")
    headers = entry.get("headers", {})
    client_auth = entry.get("client_auth", "replace")
    where = f"{what} {name}"
    url = _check_url(url, where)
    if location not in LOCATIONS:
        raise UpstreamConfigError(f"{where}: location must be one of {sorted(LOCATIONS)}")
    if key_env is not None and (not isinstance(key_env, str) or not key_env):
        raise UpstreamConfigError(f"{where}: key_env must be a variable name")
    auth = entry.get("auth", "bearer" if key_env else "none")
    if auth not in MCP_AUTH_STYLES:
        raise UpstreamConfigError(f"{where}: auth must be one of {sorted(MCP_AUTH_STYLES)}")
    _check_common(where, client_auth, headers)
    value = env.get(key_env) if key_env else None
    return McpServer(
        name=name,
        url=url,
        location=location,
        auth=auth,
        key_env=key_env,
        key=SecretStr(value) if value else None,
        headers={k.lower(): v for k, v in headers.items()},
        client_auth=CLIENT_AUTH[client_auth],
    )


def _check_common(where: str, client_auth: Any, headers: Any) -> None:
    if client_auth not in CLIENT_AUTH:
        raise UpstreamConfigError(f"{where}: client_auth must be one of {sorted(CLIENT_AUTH)}")
    if not isinstance(headers, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in headers.items()
    ):
        raise UpstreamConfigError(f"{where}: headers must map names to strings")
    if CREDENTIAL_HEADERS & {k.lower() for k in headers}:
        raise UpstreamConfigError(f"{where}: put credentials in key_env, not headers")
