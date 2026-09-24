from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sealedrun_recorder.upstreams import UpstreamConfigError, load_upstreams

EXAMPLE = Path(__file__).resolve().parents[1] / "upstreams.example.yaml"

# (dialect, model, upstream, base url, credential header, key variable)
EXAMPLE_ROUTES = [
    ("openai", "llama3.2:3b", "ollama", "http://127.0.0.1:11434/v1", None, None),
    ("anthropic", "qwen3-coder:30b", "ollama-anthropic", "http://127.0.0.1:11434", None, None),
    ("ollama", "llama3.2", "ollama-native", "http://127.0.0.1:11434", None, None),
    ("openai", "lmstudio-community/gemma-3", "lmstudio", "http://127.0.0.1:1234/v1", None, None),
    ("openai", "Qwen/Qwen3-8B", "vllm", "http://127.0.0.1:8000/v1", None, None),
    ("openai", "local-gguf", "llamacpp", "http://127.0.0.1:8081/v1", None, None),
    ("openai", "gpt-5", "openai", "https://api.openai.com/v1", "authorization", "OPENAI_API_KEY"),
    ("openai", "o3-mini", "openai", "https://api.openai.com/v1", "authorization", "OPENAI_API_KEY"),
    (
        "openai",
        "azure-gpt-5",
        "azure-openai",
        "https://YOUR-RESOURCE.openai.azure.com/openai/v1",
        "api-key",
        "AZURE_OPENAI_API_KEY",
    ),
    (
        "anthropic",
        "claude-sonnet-5",
        "anthropic",
        "https://api.anthropic.com",
        "x-api-key",
        "ANTHROPIC_API_KEY",
    ),
    (
        "gemini",
        "gemini-3-flash",
        "gemini",
        "https://generativelanguage.googleapis.com",
        "x-goog-api-key",
        "GEMINI_API_KEY",
    ),
    (
        "openai",
        "gemini-3-flash",
        "gemini-openai",
        "https://generativelanguage.googleapis.com/v1beta/openai",
        "authorization",
        "GEMINI_API_KEY",
    ),
    (
        "openai",
        "deepseek-chat",
        "deepseek",
        "https://api.deepseek.com/v1",
        "authorization",
        "DEEPSEEK_API_KEY",
    ),
    (
        "anthropic",
        "deepseek-chat",
        "deepseek-anthropic",
        "https://api.deepseek.com/anthropic",
        "x-api-key",
        "DEEPSEEK_API_KEY",
    ),
    (
        "openai",
        "kimi-k2.6",
        "kimi",
        "https://api.moonshot.ai/v1",
        "authorization",
        "MOONSHOT_API_KEY",
    ),
    (
        "anthropic",
        "kimi-k2.6",
        "kimi-anthropic",
        "https://api.moonshot.ai/anthropic",
        "x-api-key",
        "MOONSHOT_API_KEY",
    ),
    (
        "openai",
        "qwen3.6-plus",
        "qwen",
        "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        "authorization",
        "DASHSCOPE_API_KEY",
    ),
    (
        "anthropic",
        "qwen3.6-plus",
        "qwen-anthropic",
        "https://dashscope-intl.aliyuncs.com/apps/anthropic",
        "x-api-key",
        "DASHSCOPE_API_KEY",
    ),
    ("openai", "glm-5.1", "glm", "https://api.z.ai/api/paas/v4", "authorization", "ZAI_API_KEY"),
    (
        "anthropic",
        "glm-5.1",
        "glm-anthropic",
        "https://api.z.ai/api/anthropic",
        "x-api-key",
        "ZAI_API_KEY",
    ),
    (
        "openai",
        "MiniMax-M2.7",
        "minimax",
        "https://api.minimax.io/v1",
        "authorization",
        "MINIMAX_API_KEY",
    ),
    (
        "anthropic",
        "MiniMax-M2.7",
        "minimax-anthropic",
        "https://api.minimax.io/anthropic",
        "x-api-key",
        "MINIMAX_API_KEY",
    ),
    (
        "openai",
        "mistral-large-latest",
        "mistral",
        "https://api.mistral.ai/v1",
        "authorization",
        "MISTRAL_API_KEY",
    ),
    ("openai", "grok-4", "xai", "https://api.x.ai/v1", "authorization", "XAI_API_KEY"),
    (
        "openai",
        "llama-3.3-70b-versatile",
        "groq",
        "https://api.groq.com/openai/v1",
        "authorization",
        "GROQ_API_KEY",
    ),
    (
        "openai",
        "deepseek/deepseek-v4-flash",
        "openrouter",
        "https://openrouter.ai/api/v1",
        "authorization",
        "OPENROUTER_API_KEY",
    ),
]


def _example_env() -> dict[str, str]:
    names = {route[5] for route in EXAMPLE_ROUTES if route[5]}
    return {name: f"key-of-{name}" for name in names}


@pytest.mark.parametrize(("dialect", "model", "name", "url", "header", "key_env"), EXAMPLE_ROUTES)
def test_example_file_routes_each_provider(
    dialect: str, model: str, name: str, url: str, header: str | None, key_env: str | None
) -> None:
    upstream = load_upstreams(EXAMPLE, environ=_example_env()).route(dialect, model)
    assert upstream is not None
    assert (upstream.name, upstream.url) == (name, url)
    headers = upstream.request_headers()
    credentials = {
        k for k in headers if k in {"authorization", "x-api-key", "x-goog-api-key", "api-key"}
    }
    if header is None:
        assert credentials == set()
        assert upstream.location == "local"
    else:
        assert credentials == {header}
        expected = f"key-of-{key_env}"
        assert headers[header] == (f"Bearer {expected}" if header == "authorization" else expected)
        assert upstream.location == "cloud"


def test_example_file_covers_every_upstream() -> None:
    names = {u.name for u in load_upstreams(EXAMPLE, environ={})}
    assert names == {route[2] for route in EXAMPLE_ROUTES}


def test_example_file_loads_without_keys() -> None:
    upstreams = list(load_upstreams(EXAMPLE, environ={}))
    assert all(u.key is None for u in upstreams)
    assert {u.name for u in upstreams if u.missing_key} == {
        u.name for u in upstreams if u.key_env is not None
    }


def test_openrouter_example_sends_its_static_headers() -> None:
    upstream = load_upstreams(EXAMPLE, environ={}).route("openai", "a/b")
    assert upstream is not None
    assert upstream.request_headers() == {
        "http-referer": "https://sealedrun.com",
        "x-title": "SealedRun",
    }


def test_example_file_through_the_proxy(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    secrets: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-openai")
    upstream.routes["/chat/completions"] = {"model": "gpt-4.1", "choices": []}
    with make_proxy(EXAMPLE.read_text()) as client:
        headers = {"Authorization": f"Bearer {secrets['token']}"}
        body = {"model": "gpt-4.1", "messages": []}
        assert client.post("/v1/chat/completions", json=body, headers=headers).status_code == 200
    assert str(upstream.calls[0].url) == "https://api.openai.com/v1/chat/completions"
    assert upstream.calls[0].headers["authorization"] == "Bearer sk-real-openai"


def test_missing_file_means_no_upstreams(tmp_path: Path) -> None:
    assert list(load_upstreams(tmp_path / "none.yaml")) == []


@pytest.mark.parametrize(
    "text",
    [
        "upstreams: {}",
        "[1, 2]",
        "upstreams: [1]",
        "upstreams: [{url: http://x}]",
        "upstreams: [{name: a, url: ftp://x}]",
        "upstreams: [{name: a, url: http://x, dialect: grpc}]",
        "upstreams: [{name: a, url: http://x, location: moon}]",
        "upstreams: [{name: a, url: http://x, models: gpt}]",
        "upstreams: [{name: a, url: http://x, key_env: K, auth: basic}]",
        "upstreams: [{name: a, url: http://x, key_env: ''}]",
        "upstreams: [{name: a, url: http://x, headers: {X-Api-Key: s}}]",
        "upstreams: [{name: a, url: http://x, headers: {Authorization: s}}]",
        "upstreams: [{name: a, url: http://x, headers: [1]}]",
        "upstreams: [{name: a, url: http://x}, {name: a, url: http://y}]",
        "upstreams: [unclosed",
    ],
)
def test_upstream_config_errors(tmp_path: Path, text: str) -> None:
    path = tmp_path / "u.yaml"
    path.write_text(text)
    with pytest.raises(UpstreamConfigError):
        load_upstreams(path, environ={})


def test_key_style_follows_dialect(tmp_path: Path) -> None:
    path = tmp_path / "u.yaml"
    path.write_text(
        "upstreams:\n"
        "  - {name: a, url: http://a, dialect: anthropic, key_env: K}\n"
        "  - {name: g, url: http://g, dialect: gemini, key_env: K}\n"
        "  - {name: o, url: http://o, dialect: openai, key_env: K}\n"
        "  - {name: n, url: http://n, dialect: openai, key_env: K, auth: none}\n"
    )
    auth = {u.name: u.request_headers() for u in load_upstreams(path, environ={"K": "v"})}
    assert auth == {
        "a": {"x-api-key": "v"},
        "g": {"x-goog-api-key": "v"},
        "o": {"authorization": "Bearer v"},
        "n": {},
    }
