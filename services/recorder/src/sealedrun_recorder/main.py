"""Application factory and the uvicorn entry point of the recorder."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from sealedrun_recorder import __version__
from sealedrun_recorder.api import public_router, router
from sealedrun_recorder.db import make_engine, session_factory
from sealedrun_recorder.settings import Settings, load_settings


@asynccontextmanager
async def lifespan(app: FastAPI) -> Any:
    """Create the data directory and database engine on startup, dispose the engine on shutdown."""
    settings: Settings = app.state.settings
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    engine = make_engine(settings.resolved_database_url)
    app.state.engine = engine
    app.state.sessions = session_factory(engine)
    yield
    engine.dispose()


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the FastAPI app with Host header checking, the API routers and the web UI.

    The UI is mounted only when its directory exists, so the API also runs without a built UI.
    """
    settings = settings or load_settings()
    app = FastAPI(title="SealedRun Recorder", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    app.include_router(public_router)
    app.include_router(router)
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
