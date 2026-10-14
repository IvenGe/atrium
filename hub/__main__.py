"""Command line entry point: `atrium` (or `python -m hub`).

    atrium [serve] [--host H] [--port P] [--data-dir D]      run the hub (the default)
    atrium user list|create|passwd ... [--data-dir D]        manage accounts offline, e.g. after a lockout
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from datetime import datetime
from pathlib import Path

from .config import USER_ROLES, Settings, default_public_url

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def _options(parser: argparse.ArgumentParser, *, serve: bool, nested: bool) -> None:
    # Nested parsers use SUPPRESS so they never overwrite a value given before the subcommand.
    default = argparse.SUPPRESS if nested else None
    if serve:
        parser.add_argument("--host", default=default, help="interface to bind (default 127.0.0.1)")
        parser.add_argument("--port", type=int, default=default, help="port (default 8710)")
    parser.add_argument("--data-dir", default=default, help="where the hub keeps its database and workspace (default ./.hub)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="atrium", description="Run Atrium - the agent-run tool hub.")
    _options(parser, serve=True, nested=False)
    commands = parser.add_subparsers(dest="command", metavar="{serve,user}")
    _options(commands.add_parser("serve", help="run the hub (the default)"), serve=True, nested=True)

    user = commands.add_parser("user", help="manage hub accounts offline (works while the hub is stopped)")
    _options(user, serve=False, nested=True)
    actions = user.add_subparsers(dest="action", metavar="{list,create,passwd}", required=True)
    _options(actions.add_parser("list", help="list accounts"), serve=False, nested=True)
    create = actions.add_parser("create", help="create a local account")
    create.add_argument("username")
    create.add_argument("--role", choices=USER_ROLES, default="viewer", help="default viewer")
    create.add_argument("--display-name", default="")
    create.add_argument("--email")
    create.add_argument("--password-stdin", action="store_true", help="read the password from the first line of stdin")
    _options(create, serve=False, nested=True)
    passwd = actions.add_parser("passwd", help="set a password and sign the account out everywhere")
    passwd.add_argument("username")
    passwd.add_argument("--password-stdin", action="store_true", help="read the password from the first line of stdin")
    _options(passwd, serve=False, nested=True)
    return parser


def _settings(args: argparse.Namespace) -> Settings:
    settings = Settings.from_env()
    if getattr(args, "host", None):
        settings.host = args.host
    if getattr(args, "port", None):
        settings.port = args.port
    if getattr(args, "data_dir", None):
        settings.data_dir = Path(args.data_dir).expanduser().resolve()
    if not os.environ.get("HUB_PUBLIC_URL"):
        settings.public_url = default_public_url(settings.host, settings.port)
    return settings


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        settings = _settings(args)
        if args.command == "user":
            return user_command(args, settings)
        return serve(settings)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def serve(settings: Settings) -> int:
    import uvicorn

    from .app import create_app

    if settings.host not in LOOPBACK:
        print(
            f"WARNING: binding to {settings.host}. The hub can run commands on this machine; serve it over HTTPS "
            "(a TLS reverse proxy, with HUB_PUBLIC_URL and HUB_COOKIE_SECURE=1) and list its hostname in HUB_ALLOWED_HOSTS.",
            file=sys.stderr,
        )
        settings.allowed_hosts.append(settings.host)

    app = create_app(settings)
    # flush: when stdout is a pipe (systemd, docker), the setup link must not sit in a buffer while uvicorn runs
    print(f"Atrium running at http://{settings.host}:{settings.port}  (data: {settings.data_dir})", flush=True)
    token = app.state.hub.auth.setup_token
    if token:
        print(f"First run: create the administrator at {settings.public_url}/#/setup?token={token}", flush=True)
    # HUB_TRUSTED_PROXIES: whose X-Forwarded-For uvicorn believes, so sign-in throttling sees each client's own
    # address behind a reverse proxy (review F16); unset: uvicorn's FORWARDED_ALLOW_IPS, else 127.0.0.1 only
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="warning", proxy_headers=True,
                forwarded_allow_ips=settings.trusted_proxies)
    return 0


# -- offline account management -----------------------------------------------------------


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    first = getpass.getpass("New password: ")
    if getpass.getpass("Repeat the password: ") != first:
        raise ValueError("The passwords do not match.")
    return first


def _when(ts: float | None) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "never"


def user_command(args: argparse.Namespace, settings: Settings) -> int:
    from .auth.service import AuthError
    from .core import Hub

    if args.action != "create" and not settings.db_path.is_file():
        print(f"error: no hub database in {settings.data_dir}", file=sys.stderr)
        return 1
    hub = Hub(settings)
    try:
        auth = hub.auth
        if args.action == "list":
            print(f"{'USERNAME':<24} {'ROLE':<9} {'SIGN-IN':<8} {'STATUS':<9} LAST LOGIN")
            for user in auth.users():
                status = "disabled" if user.disabled else "active"
                print(f"{user.username:<24} {user.role:<9} {user.auth_source:<8} {status:<9} {_when(user.last_login)}")
            return 0
        if args.action == "create":
            password = _read_password(args.password_stdin)
            user = auth.create_user(args.username, password, role=args.role, display_name=args.display_name,
                                    email=args.email, actor="cli")
            print(f"Created {user.role} account {user.username}.")
            return 0
        user = auth.find_user(args.username)
        if user is None:
            print(f"error: no account named {args.username}", file=sys.stderr)
            return 1
        auth.set_password(user, _read_password(args.password_stdin), must_change_password=False, actor="cli")
        print(f"Password of {user.username} changed; all of its sessions were signed out.")
        return 0
    except AuthError as exc:
        print(f"error: {exc.detail}", file=sys.stderr)
        return 1
    finally:
        hub.store.close()


if __name__ == "__main__":
    sys.exit(main())
