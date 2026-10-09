"""FastAPI application factory."""

from __future__ import annotations

import mimetypes
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .api import build_router
from .config import Settings
from .core import Hub

WEB_DIR = Path(__file__).parent / "web"

# Windows registries often map .js to text/plain, which browsers refuse for ES modules.
mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("text/css", ".css")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    hub = Hub(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await hub.start()
        try:
            yield
        finally:
            await hub.stop()

    app = FastAPI(title="Atrium", version=__version__, lifespan=lifespan, docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.state.hub = hub

    # The hub can run commands, so it defends against cross-site requests and DNS rebinding:
    # only known Host headers are accepted, and state-changing API calls need a custom header
    # that browsers will not send cross-origin without a CORS preflight (which we never grant).
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)

    @app.middleware("http")
    async def require_hub_header(request: Request, call_next):
        if request.url.path.startswith("/api/") and request.method not in ("GET", "HEAD", "OPTIONS"):
            if request.headers.get("x-hub-request") != "1":
                return JSONResponse({"detail": "Missing X-Hub-Request header"}, status_code=403)
        return await call_next(request)

    app.include_router(build_router(hub), prefix="/api")
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
    return app
