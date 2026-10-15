"""FastAPI application factory."""

from __future__ import annotations

import mimetypes
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .api import build_router
from .auth.policy import authorize, is_api
from .auth.routes import build_auth_router
from .auth.service import AuthError, bearer_token
from .bus import Trace, conversation
from .config import Settings
from .core import Hub

WEB_DIR = Path(__file__).parent / "web"
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
# Every response forbids framing (clickjacking): no other site can embed the UI. The portal's iframes are the tools'
# own responses, so they are not affected.
FRAME_HEADERS = ((b"x-frame-options", b"DENY"), (b"content-security-policy", b"frame-ancestors 'none'"))


class FrameDenialMiddleware:
    """Adds FRAME_HEADERS to every HTTP response. Plain ASGI, so the event stream keeps streaming."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                names = {name.lower() for name, _ in message.get("headers") or []}
                extra = [h for h in FRAME_HEADERS if h[0] not in names]
                message = {**message, "headers": [*(message.get("headers") or []), *extra]}
            await send(message)

        await self.app(scope, receive, send_with_headers)


class RevalidateUiMiddleware:
    """The UI is plain ES modules without a build step: a browser that keeps an old app.js from its heuristic cache
    next to newer modules after an update fails to start (a blank page). Every UI file is revalidated instead (a cheap
    304 thanks to the ETag); /api responses set their own caching."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path", "").startswith("/api"):
            await self.app(scope, receive, send)
            return

        async def send_with_header(message):
            if message["type"] == "http.response.start":
                headers = message.get("headers") or []
                if not any(name.lower() == b"cache-control" for name, _ in headers):
                    message = {**message, "headers": [*headers, (b"cache-control", b"no-cache")]}
            await send(message)

        await self.app(scope, receive, send_with_header)

# Windows registries often map .js to text/plain, which browsers refuse for ES modules.
mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("text/css", ".css")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    hub = Hub(settings)
    try:
        hub.auth.bootstrap()
    except Exception:
        hub.store.close()
        raise

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await hub.start()
        try:
            yield
        finally:
            await hub.stop()

    app = FastAPI(title="Atrium", version=__version__, lifespan=lifespan, docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.state.hub = hub

    # Every /api call is checked in this order: trusted Host header (the first check, inside FrameDenialMiddleware), the
    # X-Hub-Request header on browser mutations (a custom header cross-site pages cannot send without a CORS
    # preflight, which we never grant; Bearer-token clients are exempt), who is calling, and what their role allows.
    # Static files stay public: the UI itself shows the sign-in screen.
    @app.middleware("http")
    async def guard(request: Request, call_next):
        path = request.url.path
        if not is_api(path):
            return await call_next(request)
        if request.method not in SAFE_METHODS and bearer_token(request) is None:
            if request.headers.get("x-hub-request") != "1":
                return JSONResponse({"detail": "Missing X-Hub-Request header"}, status_code=403)
        principal = hub.auth.resolve(request)
        request.state.principal = principal
        denied = authorize(principal, request.method, path)
        if denied:
            return JSONResponse(denied[1], status_code=denied[0])
        with conversation(Trace()) as trace:  # what one request sends on the bus is one conversation (hub/bus.py)
            response = await call_next(request)
        if trace is not None and trace.thread:
            response.headers["X-Atrium-Thread"] = trace.thread  # the UI links "how the agents worked on this"
        return response

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    app.add_middleware(RevalidateUiMiddleware)
    app.add_middleware(FrameDenialMiddleware)  # outermost: refusals (bad Host, 401, 403) carry the headers too

    @app.exception_handler(AuthError)
    async def auth_error(request: Request, exc: AuthError) -> JSONResponse:
        return JSONResponse({"detail": exc.detail}, status_code=exc.status, headers=exc.headers)

    # FastAPI's default 422 echoes each error's `input` (for a missing field: the whole body, API keys and passwords
    # included) and `ctx`; only where and why go back.
    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [{"loc": list(e.get("loc", ())), "msg": str(e.get("msg", "")), "type": str(e.get("type", ""))}
                  for e in exc.errors()]
        return JSONResponse({"detail": errors}, status_code=422)

    app.include_router(build_auth_router(hub), prefix="/api")
    app.include_router(build_router(hub), prefix="/api")
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
    return app
