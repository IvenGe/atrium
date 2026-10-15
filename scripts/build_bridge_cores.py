#!/usr/bin/env python3
"""Pin the "Ask the team" widget's hash in the vendored bridge cores and write hub/subsidiary/templates/cores/MANIFEST.json.

    python scripts/build_bridge_cores.py [--check]

Each core (Python, Node, Go) serves panel.js only when its SHA-256 equals the hash pinned in the core, so a changed
widget must be re-pinned in all three; MANIFEST.json then lists every vendored file with its SHA-256, which the bridge
patch's static checks compare. --check exits 1 when anything is out of date and changes nothing.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from hub.subsidiary import templates as t  # noqa: E402


def pinned() -> dict[Path, str]:
    """Each core's text with the current widget hash pinned."""
    pin = t.panel_sha256()
    out = {}
    for spec in t.CORES.values():
        path = t.ROOT / spec["core"]
        text = path.read_text(encoding="utf-8")
        out[path] = spec["pin"].sub(lambda m: m.group(0).replace(m.group(1), pin), text, count=1)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when anything is out of date")
    args = parser.parse_args(argv)
    if args.check:
        found = t.problems()
        print("\n".join(found) if found else "the bridge cores and MANIFEST.json are up to date")
        return 1 if found else 0
    for path, text in pinned().items():
        if path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8")
            print(f"pinned the widget hash in {path.relative_to(ROOT)}")
    t.MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    t.MANIFEST_PATH.write_text(t.render_manifest(t.build_manifest()), encoding="utf-8")
    print(f"wrote {t.MANIFEST_PATH.relative_to(ROOT)}")
    found = t.problems()
    if found:
        print("\n".join(found))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
