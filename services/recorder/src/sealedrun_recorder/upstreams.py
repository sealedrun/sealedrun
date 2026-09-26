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

`url` is the base URL the vendor's own SDK would use for that wire format. A request is routed to
the first upstream of its wire format whose `models` patterns match the requested model, so one
model can be reachable through several formats. Upstream URLs come only from this file, never
from a request. See `upstreams.example.yaml` for the common providers.
"""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import SecretStr

DIALECTS = frozenset({"openai", "anthropic", "ollama", "gemini"})
LOCATIONS = frozenset({"local", "cloud", "unknown"})
CLIENT_AUTH = {"replace": False, "passthrough": True}
AUTH_STYLES = frozenset({"bearer", "x-api-key", "x-goog-api-key", "api-key", "none"})
DEFAULT_AUTH = {
    "openai": "bearer",
    "anthropic": "x-api-key",
    "ollama": "bearer",
    "gemini": "x-goog-api-key",
}
CREDENTIAL_HEADERS = frozenset(
    {"authorization", "x-api-key", "x-goog-api-key", "api-key", "cookie", "proxy-authorization"}
)


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
        headers = dict(self.headers)
        if self.client_auth and client:
            return {**headers, **client}
        if self.key is None or self.auth == "none":
            return headers
        secret = self.key.get_secret_value()
        if self.auth == "bearer":
            headers["authorization"] = f"Bearer {secret}"
        else:
            headers[self.auth] = secret
        return headers


class Upstreams:
    """The configured upstreams in file order."""

    def __init__(self, upstreams: list[Upstream]):
        self._upstreams = upstreams

    def __iter__(self) -> Iterator[Upstream]:
        return iter(self._upstreams)

    def route(self, dialect: str, model: str) -> Upstream | None:
        """Return the first upstream of `dialect` serving `model`, or None."""
        return next((u for u in self._upstreams if u.dialect == dialect and u.serves(model)), None)

    def dialects_for(self, model: str) -> list[str]:
        """Return the wire formats through which `model` is reachable, in file order."""
        return list(dict.fromkeys(u.dialect for u in self._upstreams if u.serves(model)))


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
    entries = document.get("upstreams") if isinstance(document, dict) else None
    if not isinstance(entries, list):
        raise UpstreamConfigError(f"{path}: 'upstreams' must be a list")
    upstreams = [_parse(entry, env) for entry in entries]
    names = [u.name for u in upstreams]
    if len(names) != len(set(names)):
        raise UpstreamConfigError(f"{path}: upstream names must be unique")
    return Upstreams(upstreams)


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
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        raise UpstreamConfigError(f"upstream {name}: url must be http(s)")
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
    if client_auth not in CLIENT_AUTH:
        raise UpstreamConfigError(
            f"upstream {name}: client_auth must be one of {sorted(CLIENT_AUTH)}"
        )
    if not isinstance(headers, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in headers.items()
    ):
        raise UpstreamConfigError(f"upstream {name}: headers must map names to strings")
    if CREDENTIAL_HEADERS & {k.lower() for k in headers}:
        raise UpstreamConfigError(f"upstream {name}: put credentials in key_env, not headers")
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
