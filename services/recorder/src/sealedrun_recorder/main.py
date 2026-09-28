"""Application factory and the uvicorn entry point of the recorder."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import Headers, MutableHeaders
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sealedrun_recorder import __version__
from sealedrun_recorder.anchoring import Anchoring
from sealedrun_recorder.api import public_router, router
from sealedrun_recorder.db import make_engine, session_factory
from sealedrun_recorder.keystore import load_identity
from sealedrun_recorder.live import LiveRuns
from sealedrun_recorder.otlp import SpansSeen
from sealedrun_recorder.otlp import router as otlp_router
from sealedrun_recorder.policy import Rule
from sealedrun_recorder.proxy import RunGrouper
from sealedrun_recorder.proxy import router as proxy_router
from sealedrun_recorder.proxy.mcp import ListSeen
from sealedrun_recorder.settings import Settings, load_settings
from sealedrun_recorder.upstreams import load_upstreams

log = logging.getLogger("sealedrun.recorder")

# The Inspector is a static export with inline scripts and styles (Next.js), so both need
# 'unsafe-inline'; everything else stays on this origin and nothing may frame the page.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; worker-src 'self' blob:; "
    "object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)
SECURITY_HEADERS = {
    "content-security-policy": CONTENT_SECURITY_POLICY,
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
}


class ForwardedHostMiddleware:
    """Refuse a request whose `X-Forwarded-Host` names a host the recorder does not answer to.

    A development proxy in front of the recorder (the Next dev server's rewrite) replaces the
    Host header with its own target, so `TrustedHostMiddleware` alone can no longer tell a
    DNS-rebound page apart from the developer's own tab. The proxy keeps the browser's Host in
    `X-Forwarded-Host`, and that name gets the same check.
    """

    def __init__(self, app: ASGIApp, allowed_hosts: list[str]) -> None:
        self.app = app
        self.allowed_hosts = allowed_hosts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Forward the request unless the forwarded host is unknown; then answer 400."""
        if scope["type"] == "http":
            forwarded = Headers(scope=scope).get("x-forwarded-host")
            if forwarded is not None and not host_allowed(forwarded, self.allowed_hosts):
                response = PlainTextResponse("Invalid forwarded host header", status_code=400)
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


def host_allowed(header: str, allowed_hosts: list[str]) -> bool:
    """Match a host header (port dropped) against the patterns `TrustedHostMiddleware` takes."""
    host = header.split(",", 1)[0].strip().split(":", 1)[0].lower()
    for pattern in allowed_hosts:
        if pattern == "*" or host == pattern.lower():
            return True
        if pattern.startswith("*") and host.endswith(pattern[1:].lower()):
            return True
    return False


class SecurityHeadersMiddleware:
    """Add the browser security headers to every HTTP response, UI and API alike.

    A plain ASGI wrapper around `send`, not `BaseHTTPMiddleware`: the latter buffers streamed
    responses and hides client disconnects from the proxy relays.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Forward the request; stamp the headers on the response start message."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    if name not in headers:
                        headers[name] = value
            await send(message)

        await self.app(scope, receive, send_with_headers)


@asynccontextmanager
async def lifespan(app: FastAPI) -> Any:
    """Open the database, load the signing keys and the upstreams, and close them on shutdown.

    Keys and the delegation are generated under `data_dir/keys` on the first start. A broken
    upstreams file or policy rule stops the start rather than leaving the proxy half configured.
    With an anchoring authority configured, one background task anchors the open runs every
    interval.
    """
    settings: Settings = app.state.settings
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    engine = make_engine(settings.resolved_database_url)
    app.state.engine = engine
    app.state.sessions = session_factory(engine)
    app.state.live = LiveRuns(app.state.sessions, load_identity(settings.data_dir))
    app.state.runs = RunGrouper(app.state.live, settings.proxy_run_idle_seconds)
    app.state.upstreams = load_upstreams(settings.upstreams_file)
    app.state.policy = Rule(tuple(settings.policy_block_to_cloud))
    app.state.mcp_lists = ListSeen()
    app.state.otel_seen = SpansSeen()
    app.state.http = httpx.AsyncClient(transport=app.state.http_transport, follow_redirects=False)
    app.state.anchoring = Anchoring(app.state.live, app.state.http, settings)
    task = asyncio.create_task(app.state.anchoring.loop()) if app.state.anchoring.enabled else None
    if task is not None:
        task.add_done_callback(_anchoring_ended)
    yield
    if task is not None:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
    await app.state.http.aclose()
    engine.dispose()


def _anchoring_ended(task: asyncio.Task[None]) -> None:
    """Log how the anchoring task ended; it should only ever end by cancellation."""
    if task.cancelled():
        return
    error = task.exception()
    if error is not None:
        log.error("anchoring loop stopped: %r", error)


def create_app(
    settings: Settings | None = None, *, http_transport: httpx.AsyncBaseTransport | None = None
) -> FastAPI:
    """Build the FastAPI app with Host header checking, the API routers, the proxy and the UI.

    The UI is mounted only when its directory exists, so the API also runs without a built UI.
    `http_transport` replaces the network for upstream calls, for tests.
    """
    settings = settings or load_settings()
    app = FastAPI(title="SealedRun Recorder", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.state.http_transport = http_transport
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    app.add_middleware(ForwardedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    app.add_middleware(SecurityHeadersMiddleware)
    app.include_router(public_router)
    app.include_router(router)
    app.include_router(proxy_router)
    app.include_router(otlp_router)
    ui_dir = settings.ui_dir or _default_ui_dir()
    if ui_dir is not None and ui_dir.is_dir():
        _mount_ui(app, ui_dir)
    return app


def _default_ui_dir() -> Path | None:
    for candidate in (Path("ui"), Path(__file__).resolve().parents[4] / "apps" / "web" / "out"):
        if candidate.is_dir():
            return candidate
    return None


def _mount_ui(app: FastAPI, ui_dir: Path) -> None:
    index = ui_dir / "index.html"

    @app.get("/", include_in_schema=False)
    def root() -> FileResponse:
        return FileResponse(index)

    app.mount("/", StaticFiles(directory=ui_dir, html=True), name="ui")


class QueryStringFilter(logging.Filter):
    """Drop the query string from uvicorn access log lines.

    A Gemini SDK sends the recorder token as `?key=`; a log line must never hold it. The access
    record's arguments are `(client, method, path, http_version, status)`.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Rewrite the path argument in place; the line is always kept."""
        args = record.args
        if isinstance(args, tuple) and len(args) == 5 and isinstance(args[2], str):
            record.args = (*args[:2], args[2].partition("?")[0], *args[3:])
        return True


def run() -> None:
    """Serve the recorder with uvicorn on the configured host and port."""
    settings = load_settings()
    logging.getLogger("uvicorn.access").addFilter(QueryStringFilter())
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port)


app = create_app()
