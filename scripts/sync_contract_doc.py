#!/usr/bin/env python3
"""Copy the bridge contract (hub/subsidiary/contract/SPEC.md) into docs/SUBSIDIARIES.md.

    python scripts/sync_contract_doc.py [--check]

SPEC.md is the one normative text of atrium-bridge/1; the docs publish it between the markers
``<!-- contract:begin -->`` and ``<!-- contract:end -->`` (without its title, its headings one level down). --check
exits 1 when the page is out of date and changes nothing; the test suite checks it too.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "hub" / "subsidiary" / "contract" / "SPEC.md"
DOC = ROOT / "docs" / "SUBSIDIARIES.md"
BEGIN, END = "<!-- contract:begin -->", "<!-- contract:end -->"


def section(spec: str) -> str:
    """SPEC.md as a section of the docs: the title dropped, every heading outside code one level down."""
    lines, fenced = [], False
    for line in spec.splitlines()[1:]:
        if line.startswith("```"):
            fenced = not fenced
        lines.append("#" + line if not fenced and line.startswith("#") else line)
    return "\n".join(lines).strip("\n")


def render(doc: str, spec: str) -> str:
    head, sep, rest = doc.partition(BEGIN)
    _, sep2, tail = rest.partition(END)
    if not sep or not sep2:
        raise SystemExit(f"{DOC.name} lacks the markers {BEGIN} and {END}")
    return f"{head}{BEGIN}\n\n{section(spec)}\n\n{END}{tail}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when the page is out of date")
    args = parser.parse_args(argv)
    doc = DOC.read_text(encoding="utf-8")
    wanted = render(doc, SPEC.read_text(encoding="utf-8"))
    if doc == wanted:
        print(f"{DOC.relative_to(ROOT)} is current")
        return 0
    if args.check:
        print(f"{DOC.relative_to(ROOT)} is out of date: run scripts/sync_contract_doc.py", file=sys.stderr)
        return 1
    DOC.write_text(wanted, encoding="utf-8")
    print(f"wrote {DOC.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
