"""Atrium bridge adapters for Python web frameworks - contract atrium-bridge/1.

VENDORED FILE: Atrium adds it byte-identical (as atrium_bridge.py, next to atrium_bridge_core.py) and checks its
SHA-256; do not edit it. Mount the bridge on the tool's main application, before anything that reads request bodies:

    FastAPI    app.include_router(atrium_bridge.fastapi_router(glue))
    Starlette  routes += atrium_bridge.starlette_routes(glue)   or   Mount("/.atrium", app=atrium_bridge.asgi_app(glue))
    any ASGI   app = atrium_bridge.asgi_middleware(app, glue)
    Flask      app.register_blueprint(atrium_bridge.flask_blueprint(glue))
    any WSGI   app = atrium_bridge.wsgi_middleware(app, glue)

`glue` is the tool's glue module: `actions`, `current_user(request)`, `service_principal()` and optionally MANIFEST,
PANEL_JS, GRANT_STORE, NONCE_STORE and SYNC_WAIT. A tool served by several processes shares the grant and nonce stores
(SqliteGrants, SqliteNonces); the panel's questions and the events outbox live in each process, so serve the bridge's
routes from one process where possible. The tool's code queues events with atrium_bridge.emit(name, payload).
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

try:  # inside a package (atrium/atrium_bridge.py) or as top-level modules
    from . import atrium_bridge_core as core
except ImportError:  # pragma: no cover - the top-level layout
    import atrium_bridge_core as core  # type: ignore[no-redef]

Bridge, Context, emit, bridge_for = core.Bridge, core.Context, core.emit, core.bridge_for
MemoryGrants, SqliteGrants, SqliteNonces = core.MemoryGrants, core.SqliteGrants, core.SqliteNonces
MARK = "/.atrium/"


def bridge_path(path: str, root_path: str = "") -> Optional[str]:
    """The path from "/.atrium/" on, whatever prefix the tool is served under; None when it is not a bridge path."""
    at = path.find(MARK)
    if at >= 0:
        return path[at:]
    if root_path.rstrip("/").endswith("/.atrium"):  # mounted at /.atrium by a framework that strips the prefix
        return "/.atrium" + (path if path.startswith("/") else "/" + path)
    return None


def _headers(pairs: Iterable[Tuple[str, str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for name, value in pairs:
        key = name.lower()
        out[key] = f"{out[key]}, {value}" if key in out else value
    return out


def _too_long(length: Optional[str]) -> bool:
    try:
        return length is not None and int(length) > core.MAX_BODY
    except ValueError:
        return True


# --------------------------------------------------------------------------------------
# ASGI: Starlette, FastAPI and any ASGI application
# --------------------------------------------------------------------------------------


class AsgiBridge:
    """The bridge as a raw ASGI application (it also serves as a Starlette route endpoint)."""

    def __init__(self, glue: Any):
        self.bridge = bridge_for(glue)

    async def __call__(self, scope: Dict[str, Any], receive: Callable[..., Any], send: Callable[..., Any]) -> None:
        if scope.get("type") != "http":
            return
        path = bridge_path(scope.get("path", ""), scope.get("root_path", "")) or scope.get("path", "")
        headers = _headers((k.decode("latin-1"), v.decode("latin-1")) for k, v in scope.get("headers", []))
        oversize = _too_long(headers.get("content-length"))
        body = b""
        if scope.get("method") == "POST" and not oversize:
            while True:
                message = await receive()
                if message.get("type") != "http.request":
                    break
                body += message.get("body", b"")
                if len(body) > core.MAX_BODY:
                    oversize, body = True, b""
                    break
                if not message.get("more_body"):
                    break
        native: Any = scope
        try:  # the framework's request, so the current-user hook sees the session (request.user, request.session)
            from starlette.requests import Request as StarletteRequest
            native = StarletteRequest(scope)
        except ImportError:  # pragma: no cover - plain ASGI
            pass
        client = scope.get("client")
        req = core.Request(scope.get("method", "GET"), path, scope.get("query_string", b"").decode("latin-1"), headers,
                           body, client[0] if client else None, native, oversize)
        answer = await self.bridge.ahandle(req)
        await send({"type": "http.response.start", "status": answer.status,
                    "headers": [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in answer.headers.items()]
                    + [(b"content-length", str(len(answer.body)).encode())]})
        await send({"type": "http.response.body", "body": answer.body})


def asgi_app(glue: Any) -> AsgiBridge:
    """For Mount("/.atrium", app=asgi_app(glue)) or any ASGI router."""
    return AsgiBridge(glue)


def asgi_middleware(app: Callable[..., Any], glue: Any) -> Callable[..., Any]:
    """Wrap an ASGI application: /.atrium/ requests go to the bridge, everything else to the application."""
    bridge = AsgiBridge(glue)

    async def wrapped(scope: Dict[str, Any], receive: Callable[..., Any], send: Callable[..., Any]) -> None:
        if scope.get("type") == "http" and bridge_path(scope.get("path", ""), scope.get("root_path", "")):
            await bridge(scope, receive, send)
        else:
            await app(scope, receive, send)
    return wrapped


def starlette_routes(glue: Any) -> List[Any]:
    from starlette.routing import Route
    return [Route("/.atrium/{rest:path}", endpoint=AsgiBridge(glue))]


def fastapi_router(glue: Any) -> Any:
    from fastapi import APIRouter
    router = APIRouter()
    router.add_route("/.atrium/{rest:path}", AsgiBridge(glue), include_in_schema=False)
    return router


# --------------------------------------------------------------------------------------
# WSGI: Flask and any WSGI application
# --------------------------------------------------------------------------------------


def _wsgi_body(environ: Dict[str, Any]) -> Tuple[bytes, bool]:
    length = environ.get("CONTENT_LENGTH") or None
    if _too_long(length):
        return b"", True
    stream = environ.get("wsgi.input")
    if stream is None or environ.get("REQUEST_METHOD") != "POST":
        return b"", False
    if length is None and not environ.get("wsgi.input_terminated"):
        return b"", False  # no length and a stream that may not end: read nothing (PEP 3333)
    body = stream.read(core.MAX_BODY + 1 if length is None else int(length))
    return (b"", True) if len(body) > core.MAX_BODY else (body, False)


def _wsgi_request(environ: Dict[str, Any], native: Any = None) -> core.Request:
    path = (environ.get("SCRIPT_NAME", "") or "") + (environ.get("PATH_INFO", "") or "")
    try:  # PEP 3333 hands the path over as latin-1 decoded bytes
        path = path.encode("latin-1").decode("utf-8")
    except (UnicodeError, ValueError):
        pass
    headers = {k[5:].replace("_", "-").lower(): v for k, v in environ.items() if k.startswith("HTTP_")}
    for name in ("CONTENT_TYPE", "CONTENT_LENGTH"):
        if environ.get(name):
            headers[name.replace("_", "-").lower()] = environ[name]
    body, oversize = _wsgi_body(environ)
    return core.Request(environ.get("REQUEST_METHOD", "GET"), bridge_path(path) or path,
                        environ.get("QUERY_STRING", ""), headers, body, environ.get("REMOTE_ADDR"),
                        environ if native is None else native, oversize)


def wsgi_app(glue: Any) -> Callable[..., Any]:
    """The bridge as a WSGI application (sync: long-polls wait at most the glue's SYNC_WAIT seconds, default 0)."""
    bridge = bridge_for(glue)

    def app(environ: Dict[str, Any], start_response: Callable[..., Any]) -> List[bytes]:
        answer = bridge.handle(_wsgi_request(environ))
        start_response(f"{answer.status} {_REASONS.get(answer.status, 'Status')}",
                       list(answer.headers.items()) + [("Content-Length", str(len(answer.body)))])
        return [answer.body]
    return app


def wsgi_middleware(app: Callable[..., Any], glue: Any) -> Callable[..., Any]:
    """Wrap a WSGI application: /.atrium/ requests go to the bridge, everything else to the application."""
    bridge = wsgi_app(glue)

    def wrapped(environ: Dict[str, Any], start_response: Callable[..., Any]) -> Any:
        path = (environ.get("SCRIPT_NAME", "") or "") + (environ.get("PATH_INFO", "") or "")
        return bridge(environ, start_response) if bridge_path(path) else app(environ, start_response)
    return wrapped


def flask_blueprint(glue: Any, name: str = "atrium_bridge") -> Any:
    """A Flask blueprint: the current-user hook runs inside Flask's request context (flask_login.current_user)."""
    from flask import Blueprint, Response, request

    bridge = bridge_for(glue)
    blueprint = Blueprint(name, __name__)

    @blueprint.route("/.atrium/<path:rest>", methods=["GET", "POST"])
    def atrium(rest: str) -> Any:
        answer = bridge.handle(_wsgi_request(request.environ, native=request))
        return Response(answer.body, status=answer.status, headers=answer.headers)
    return blueprint


_REASONS = {200: "OK", 304: "Not Modified", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 409: "Conflict",
            413: "Payload Too Large", 422: "Unprocessable Entity", 429: "Too Many Requests",
            500: "Internal Server Error", 503: "Service Unavailable"}
