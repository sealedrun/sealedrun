"""Application factory and the uvicorn entry point of the recorder."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from sealedrun_recorder import __version__
from sealedrun_recorder.api import public_router, router
from sealedrun_recorder.db import make_engine, session_factory
from sealedrun_recorder.keystore import load_identity
from sealedrun_recorder.live import LiveRuns
from sealedrun_recorder.proxy import RunGrouper
from sealedrun_recorder.proxy import router as proxy_router
from sealedrun_recorder.settings import Settings, load_settings
from sealedrun_recorder.upstreams import load_upstreams


@asynccontextmanager
async def lifespan(app: FastAPI) -> Any:
    """Open the database, load the signing keys and the upstreams, and close them on shutdown.

    Keys and the delegation are generated under `data_dir/keys` on the first start. A broken
    upstreams file stops the start rather than leaving the proxy half configured.
    """
    settings: Settings = app.state.settings
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    engine = make_engine(settings.resolved_database_url)
    app.state.engine = engine
    app.state.sessions = session_factory(engine)
    app.state.live = LiveRuns(app.state.sessions, load_identity(settings.data_dir))
    app.state.runs = RunGrouper(app.state.live, settings.proxy_run_idle_seconds)
    app.state.upstreams = load_upstreams(settings.upstreams_file)
    app.state.http = httpx.AsyncClient(transport=app.state.http_transport, follow_redirects=False)
    yield
    await app.state.http.aclose()
    engine.dispose()


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
    app.include_router(public_router)
    app.include_router(router)
    app.include_router(proxy_router)
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


def run() -> None:
    """Serve the recorder with uvicorn on the configured host and port."""
    settings = load_settings()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port)


app = create_app()
