import gzip
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sealedrun_recorder.upstreams import UpstreamConfigError, load_upstreams

SSE_TYPE = "text/event-stream"
EXAMPLE = Path(__file__).resolve().parents[1] / "upstreams.example.yaml"

CONFIG = """
mcp_servers:
  - name: tools
    url: http://mcp.test/mcp
    location: local
  - name: keyed
    url: https://mcp.test/keyed
    key_env: TEST_UPSTREAM_KEY
  - name: nokey
    url: https://mcp.test/nokey
    key_env: TEST_MISSING_KEY
  - name: login
    url: https://mcp.test/login
    key_env: TEST_MISSING_KEY
    client_auth: passthrough
"""


def _load(tmp_path: Path, text: str, environ: dict[str, str] | None = None) -> Any:
    path = tmp_path / "u.yaml"
    path.write_text(text)
    return load_upstreams(path, environ=environ or {})


def test_mcp_servers_load_by_name(tmp_path: Path) -> None:
    config = _load(tmp_path, CONFIG, {"TEST_UPSTREAM_KEY": "sk-1"})
    assert [s.name for s in config.mcp_servers] == ["tools", "keyed", "nokey", "login"]
    assert list(config) == []
    tools = config.mcp("tools")
    assert (tools.url, tools.location, tools.request_headers()) == (
        "http://mcp.test/mcp",
        "local",
        {},
    )
    assert config.mcp("keyed").request_headers() == {"authorization": "Bearer sk-1"}
    assert config.mcp("nokey").missing_key
    assert config.mcp("absent") is None


def test_mcp_auth_styles_and_static_headers(tmp_path: Path) -> None:
    config = _load(
        tmp_path,
        "mcp_servers:\n"
        "  - {name: a, url: http://a, key_env: K, auth: x-api-key}\n"
        "  - {name: b, url: http://b, key_env: K, auth: api-key, headers: {X-Team: t}}\n"
        "  - {name: c, url: http://c, key_env: K, auth: none}\n",
        {"K": "v"},
    )
    assert config.mcp("a").request_headers() == {"x-api-key": "v"}
    assert config.mcp("b").request_headers() == {"x-team": "t", "api-key": "v"}
    assert config.mcp("c").request_headers() == {}


def test_mcp_client_auth_passthrough(tmp_path: Path) -> None:
    server = _load(tmp_path, CONFIG).mcp("login")
    client = {"authorization": "Bearer user-oauth"}
    assert not server.ready()
    assert server.ready(client)
    assert server.request_headers(client) == client


def test_both_lists_in_one_file(tmp_path: Path) -> None:
    config = _load(
        tmp_path,
        "upstreams: [{name: m, url: http://m}]\nmcp_servers: [{name: m, url: http://m/mcp}]\n",
    )
    assert [u.name for u in config] == ["m"]
    assert config.mcp("m") is not None


def test_example_file_mcp_servers() -> None:
    config = load_upstreams(EXAMPLE, environ={"GITHUB_MCP_TOKEN": "ghp-x"})
    assert [s.name for s in config.mcp_servers] == ["local", "github"]
    assert config.mcp("github").request_headers() == {"authorization": "Bearer ghp-x"}
    assert config.mcp("local").location == "local"


@pytest.mark.parametrize(
    "text",
    [
        "mcp_servers: {}",
        "mcp_servers: [1]",
        "mcp_servers: [{url: http://x}]",
        "mcp_servers: [{name: 'a/b', url: http://x}]",
        "mcp_servers: [{name: a, url: ftp://x}]",
        "mcp_servers: [{name: a, url: http://x, location: moon}]",
        "mcp_servers: [{name: a, url: http://x, key_env: K, auth: x-goog-api-key}]",
        "mcp_servers: [{name: a, url: http://x, key_env: ''}]",
        "mcp_servers: [{name: a, url: http://x, client_auth: maybe}]",
        "mcp_servers: [{name: a, url: http://x, headers: {Authorization: s}}]",
        "mcp_servers: [{name: a, url: http://x}, {name: a, url: http://y}]",
    ],
)
def test_mcp_config_errors(tmp_path: Path, text: str) -> None:
    with pytest.raises(UpstreamConfigError):
        _load(tmp_path, text)


def _auth(secrets: dict[str, str]) -> dict[str, str]:
    return {"X-SealedRun-Token": secrets["token"]}


@pytest.mark.parametrize("method", ["POST", "GET", "DELETE"])
def test_mcp_route_needs_token(
    make_proxy: Callable[..., TestClient], upstream: Any, method: str
) -> None:
    with make_proxy(CONFIG) as client:
        assert client.request(method, "/mcp/tools").status_code == 401
        wrong = {"Authorization": "Bearer nope"}
        assert client.request(method, "/mcp/tools", headers=wrong).status_code == 401
    assert upstream.calls == []


def test_mcp_route_accepts_bearer_token(
    make_proxy: Callable[..., TestClient], upstream: Any, secrets: dict[str, str]
) -> None:
    upstream.routes["/mcp"] = RESULT
    with make_proxy(CONFIG) as client:
        headers = {"Authorization": f"Bearer {secrets['token']}"}
        assert client.post("/mcp/tools", headers=headers, json={}).status_code == 200


def test_mcp_unknown_server_is_404(
    make_proxy: Callable[..., TestClient], upstream: Any, secrets: dict[str, str]
) -> None:
    with make_proxy(CONFIG) as client:
        reply = client.post("/mcp/absent", headers=_auth(secrets), json={})
    assert reply.status_code == 404
    assert reply.json()["jsonrpc"] == "2.0"
    assert "absent" in reply.json()["error"]["message"]
    assert upstream.calls == []


def test_mcp_missing_key_is_503(
    make_proxy: Callable[..., TestClient], upstream: Any, secrets: dict[str, str]
) -> None:
    with make_proxy(CONFIG) as client:
        reply = client.post("/mcp/nokey", headers=_auth(secrets), json={})
        passthrough = client.post(
            "/mcp/login",
            headers={**_auth(secrets), "Authorization": "Bearer user-oauth"},
            json={},
        )
    assert reply.status_code == 503
    assert "TEST_MISSING_KEY" in reply.json()["error"]["message"]
    assert passthrough.status_code == 404  # reached the fake server, which has no route


def test_mcp_route_without_recorder_token_configured(
    make_proxy: Callable[..., TestClient], secrets: dict[str, str]
) -> None:
    with make_proxy(CONFIG, api_token=None) as client:
        assert client.post("/mcp/tools", headers=_auth(secrets), json={}).status_code == 503


CALL = (
    b'{"jsonrpc":"2.0","id":7,"method":"tools/call",'
    b'"params":{"name":"add","arguments":{"a":1,"b":2}}}'
)
RESULT = {"jsonrpc": "2.0", "id": 7, "result": {"content": [{"type": "text", "text": "3"}]}}
SSE_REPLY = (
    b'event: message\ndata: {"jsonrpc":"2.0","method":"notifications/progress",'
    b'"params":{"progress":1}}\n\n'
    b'event: message\ndata: {"jsonrpc":"2.0","id":7,"result":{"content":[]}}\n\n'
)
NEW_ERA = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
    "MCP-Protocol-Version": "2026-07-28",
    "Mcp-Method": "tools/call",
    "Mcp-Name": "=?base64?YWRk?=",
    "Mcp-Param-Region": "eu",
    "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
}


def _reply(status: int = 200, **kwargs: Any) -> Callable[[Any], httpx.Response]:
    return lambda request: httpx.Response(status, **kwargs)


def test_post_is_forwarded_unchanged_with_allowed_headers(
    make_proxy: Callable[..., TestClient], upstream: Any, secrets: dict[str, str]
) -> None:
    upstream.routes["/mcp"] = RESULT
    extra = {"Cookie": "c=1", "X-Other": "o", "X-SealedRun-Run": "r1"}
    with make_proxy(CONFIG) as client:
        reply = client.post(
            "/mcp/tools?tenant=a", content=CALL, headers={**_auth(secrets), **NEW_ERA, **extra}
        )
    assert reply.status_code == 200
    assert reply.json() == RESULT
    sent = upstream.calls[0]
    assert str(sent.url) == "http://mcp.test/mcp?tenant=a"
    assert sent.method == "POST"
    assert sent.content == CALL
    for name, value in NEW_ERA.items():
        assert sent.headers[name] == value
    assert sent.headers["accept-encoding"] == "identity"
    for name in ("cookie", "x-other", "x-sealedrun-run", "x-sealedrun-token", "authorization"):
        assert name not in sent.headers
    assert secrets["token"] not in str(sent.headers)


def test_server_key_is_swapped_in(
    make_proxy: Callable[..., TestClient], upstream: Any, secrets: dict[str, str]
) -> None:
    upstream.routes["/keyed"] = RESULT
    with make_proxy(CONFIG) as client:
        headers = {"Authorization": f"Bearer {secrets['token']}", **NEW_ERA}
        assert client.post("/mcp/keyed", content=CALL, headers=headers).status_code == 200
    assert upstream.calls[0].headers["authorization"] == f"Bearer {secrets['upstream_key']}"


def test_client_authorization_passes_through(
    make_proxy: Callable[..., TestClient], upstream: Any, secrets: dict[str, str]
) -> None:
    upstream.routes["/login"] = RESULT
    with make_proxy(CONFIG) as client:
        headers = {**_auth(secrets), "Authorization": "Bearer user-oauth"}
        assert client.post("/mcp/login", content=CALL, headers=headers).status_code == 200
    assert upstream.calls[0].headers["authorization"] == "Bearer user-oauth"


def test_sse_reply_is_relayed_unbuffered(
    make_proxy: Callable[..., TestClient], upstream: Any, secrets: dict[str, str]
) -> None:
    upstream.routes["/mcp"] = _reply(
        content=SSE_REPLY, headers={"content-type": "text/event-stream", "x-internal": "i"}
    )
    with make_proxy(CONFIG) as client:
        reply = client.post("/mcp/tools", content=CALL, headers={**_auth(secrets), **NEW_ERA})
    assert reply.status_code == 200
    assert reply.content == SSE_REPLY
    assert reply.headers["content-type"] == "text/event-stream"
    assert reply.headers["x-accel-buffering"] == "no"
    assert "x-internal" not in reply.headers


def test_notification_202_passes_through(
    make_proxy: Callable[..., TestClient], upstream: Any, secrets: dict[str, str]
) -> None:
    upstream.routes["/mcp"] = _reply(202)
    note = b'{"jsonrpc":"2.0","method":"notifications/initialized"}'
    with make_proxy(CONFIG) as client:
        reply = client.post("/mcp/tools", content=note, headers=_auth(secrets))
    assert (reply.status_code, reply.content) == (202, b"")


def test_header_mismatch_400_passes_through(
    make_proxy: Callable[..., TestClient], upstream: Any, secrets: dict[str, str]
) -> None:
    mismatch = {"jsonrpc": "2.0", "id": 7, "error": {"code": -32020, "message": "HeaderMismatch"}}
    upstream.routes["/mcp"] = _reply(400, json=mismatch)
    with make_proxy(CONFIG) as client:
        headers = {**_auth(secrets), **NEW_ERA, "Mcp-Name": "other"}
        reply = client.post("/mcp/tools", content=CALL, headers=headers)
    assert (reply.status_code, reply.json()) == (400, mismatch)
    assert upstream.calls[0].headers["mcp-name"] == "other"


def test_oauth_challenge_passes_through(
    make_proxy: Callable[..., TestClient], upstream: Any, secrets: dict[str, str]
) -> None:
    challenge = 'Bearer resource_metadata="https://mcp.test/.well-known/oauth-protected-resource"'
    upstream.routes["/mcp"] = _reply(401, headers={"www-authenticate": challenge})
    with make_proxy(CONFIG) as client:
        reply = client.post("/mcp/tools", content=CALL, headers=_auth(secrets))
    assert reply.status_code == 401
    assert reply.headers["www-authenticate"] == challenge


def test_legacy_session_get_stream_and_delete(
    make_proxy: Callable[..., TestClient], upstream: Any, secrets: dict[str, str]
) -> None:
    def server(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            init = {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-11-25"}}
            return httpx.Response(200, json=init, headers={"mcp-session-id": "s-1"})
        if request.method == "GET":
            stream = (
                b'id: 5\ndata: {"jsonrpc":"2.0","method":"notifications/tools/list_changed"}\n\n'
            )
            return httpx.Response(200, content=stream, headers={"content-type": SSE_TYPE})
        return httpx.Response(204)

    upstream.routes["/mcp"] = server
    init = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
    with make_proxy(CONFIG) as client:
        opened = client.post("/mcp/tools", content=init, headers=_auth(secrets))
        session = {**_auth(secrets), "Mcp-Session-Id": opened.headers["mcp-session-id"]}
        stream = client.get(
            "/mcp/tools", headers={**session, "Accept": SSE_TYPE, "Last-Event-ID": "4"}
        )
        ended = client.delete("/mcp/tools", headers=session)
    assert opened.headers["mcp-session-id"] == "s-1"
    assert stream.status_code == 200
    assert b"list_changed" in stream.content
    assert ended.status_code == 204
    get, delete = upstream.calls[1], upstream.calls[2]
    assert (get.method, get.headers["mcp-session-id"], get.headers["last-event-id"]) == (
        "GET",
        "s-1",
        "4",
    )
    assert (delete.method, delete.headers["mcp-session-id"]) == ("DELETE", "s-1")
    assert get.content == b"" and delete.content == b""


def test_server_without_get_stream_405_passes_through(
    make_proxy: Callable[..., TestClient], upstream: Any, secrets: dict[str, str]
) -> None:
    upstream.routes["/mcp"] = _reply(405)
    with make_proxy(CONFIG) as client:
        assert client.get("/mcp/tools", headers=_auth(secrets)).status_code == 405


def test_unreachable_server_is_502(
    make_proxy: Callable[..., TestClient], upstream: Any, secrets: dict[str, str]
) -> None:
    upstream.fail = "down"
    with make_proxy(CONFIG) as client:
        reply = client.post("/mcp/tools", content=CALL, headers=_auth(secrets))
    assert reply.status_code == 502
    assert "unreachable" in reply.json()["error"]["message"]


@pytest.mark.parametrize(
    ("browser", "status"),
    [
        ({"Sec-Fetch-Site": "cross-site"}, 403),
        ({"Origin": "https://evil.test"}, 403),
        ({"Sec-Fetch-Site": "same-origin", "Origin": "http://localhost"}, 200),
        ({"Origin": "http://localhost"}, 200),
        ({}, 200),
    ],
)
def test_cross_site_browser_calls_are_refused(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    secrets: dict[str, str],
    browser: dict[str, str],
    status: int,
) -> None:
    upstream.routes["/mcp"] = RESULT
    with make_proxy(CONFIG) as client:
        reply = client.post("/mcp/tools", content=CALL, headers={**_auth(secrets), **browser})
    assert reply.status_code == status
    assert len(upstream.calls) == (1 if status == 200 else 0)


def test_oversized_body_is_413(
    make_proxy: Callable[..., TestClient], upstream: Any, secrets: dict[str, str]
) -> None:
    with make_proxy(CONFIG, proxy_max_body_bytes=16) as client:
        reply = client.post("/mcp/tools", content=CALL, headers=_auth(secrets))
    assert reply.status_code == 413
    assert upstream.calls == []


def test_compressed_reply_reaches_client_decoded(
    make_proxy: Callable[..., TestClient], upstream: Any, secrets: dict[str, str]
) -> None:
    upstream.routes["/mcp"] = _reply(
        content=gzip.compress(SSE_REPLY),
        headers={"content-type": SSE_TYPE, "content-encoding": "gzip"},
    )
    with make_proxy(CONFIG) as client:
        reply = client.post("/mcp/tools", content=CALL, headers=_auth(secrets))
    assert reply.content == SSE_REPLY
    assert "content-encoding" not in reply.headers
