"""atrium-sidecar: python -m hub.subsidiary.sidecar --config config.json [--once | --check]

Exit codes: 0 done (--once, a passing --check); 1 a bad config.json or a failing --check; 3 the sidecar needs a (new)
enrollment; 4 Atrium stopped the subsidiary.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from typing import Any, Sequence

from .client import EXIT_STOPPED, EXIT_TOKEN
from .config import ConfigError, load
from .runtime import LOG, VERSION, Runtime
from .spool import MaskFilter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="atrium-sidecar",
        description="The sidecar of an Atrium subsidiary: the agent team's office next to its tool.",
        epilog=f"Exit codes: 1 bad configuration or a failing check, {EXIT_TOKEN} enroll again (the token or the "
               f"enrollment code no longer works), {EXIT_STOPPED} Atrium stopped the subsidiary. The first start "
               "enrolls with the one-time code in ATRIUM_ENROLLMENT_CODE.")
    parser.add_argument("--config", required=True, help="config.json from the bundle Atrium generated")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="one pass of every task, then exit (operations, tests)")
    mode.add_argument("--check", action="store_true",
                      help="check Atrium, the bridge and the conformance vectors Atrium sends, then exit")
    parser.add_argument("--verbose", action="store_true", help="log debug messages")
    parser.add_argument("--version", action="version", version=VERSION)
    return parser


def main(argv: Sequence[str] | None = None, **runtime_options: Any) -> int:
    args = build_parser().parse_args(argv)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOG.addHandler(handler)
    LOG.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    try:
        try:
            config = load(args.config)
        except ConfigError as exc:
            print(f"atrium-sidecar: {exc}", file=sys.stderr)
            return 1
        rt = Runtime(config, **runtime_options)
        handler.addFilter(next(f for f in LOG.filters if isinstance(f, MaskFilter)))
        if args.once:
            return asyncio.run(rt.once())
        if args.check:
            return asyncio.run(rt.check())
        return asyncio.run(rt.run())
    except KeyboardInterrupt:
        return 130
    finally:
        LOG.removeHandler(handler)


if __name__ == "__main__":
    sys.exit(main())
