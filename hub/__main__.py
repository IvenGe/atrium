"""Command line entry point: `hub` or `python -m hub`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import uvicorn

from .app import create_app
from .config import Settings

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="atrium", description="Run Atrium - the agent-run tool hub.")
    parser.add_argument("--host", help="interface to bind (default 127.0.0.1)")
    parser.add_argument("--port", type=int, help="port (default 8710)")
    parser.add_argument("--data-dir", help="where the hub keeps its database and workspace (default ./.hub)")
    args = parser.parse_args(argv)

    settings = Settings.from_env()
    if args.host:
        settings.host = args.host
    if args.port:
        settings.port = args.port
    if args.data_dir:
        settings.data_dir = Path(args.data_dir).expanduser().resolve()
    if settings.host not in LOOPBACK:
        print(
            f"WARNING: binding to {settings.host}. The hub can run commands on this machine; only expose it behind "
            "an authenticating reverse proxy, and list its hostname in HUB_ALLOWED_HOSTS.",
            file=sys.stderr,
        )
        settings.allowed_hosts.append(settings.host)

    print(f"Atrium running at http://{settings.host}:{settings.port}  (data: {settings.data_dir})")
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port, log_level="warning")


if __name__ == "__main__":
    main()
