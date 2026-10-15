"""The documentation: every relative link and #anchor in README.md, docs/*.md and the bridge contract resolves, and
docs/SUBSIDIARIES.md publishes the current text of the contract (hub/subsidiary/contract/SPEC.md)."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "hub" / "subsidiary" / "contract" / "SPEC.md"
PAGES = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md")), SPEC]
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)\)")
HEADING = re.compile(r"^#{1,6}\s+(.*)$")


def outside_code(path: Path) -> list[tuple[int, str]]:
    """The page's lines outside fenced code blocks, with inline code removed."""
    lines, fenced = [], False
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.startswith("```"):
            fenced = not fenced
        elif not fenced:
            lines.append((number, re.sub(r"`[^`]*`", "", line)))
    return lines


def slug(heading: str) -> str:
    """GitHub's anchor for a heading: lower case, punctuation dropped, spaces as hyphens."""
    text = re.sub(r"<[^>]+>", "", heading).strip().lower()
    return re.sub(r"[^\w\- ]", "", text).replace(" ", "-")


def anchors(path: Path) -> set[str]:
    found: set[str] = set()
    seen: dict[str, int] = {}
    fenced = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("```"):
            fenced = not fenced
            continue
        match = None if fenced else HEADING.match(line)
        if match:
            base = slug(match.group(1))
            n = seen.get(base, 0)
            found.add(base if n == 0 else f"{base}-{n}")
            seen[base] = n + 1
    return found


@pytest.mark.parametrize("page", PAGES, ids=lambda p: str(p.relative_to(ROOT)))
def test_relative_links_and_anchors_resolve(page):
    broken = []
    for number, line in outside_code(page):
        for target in LINK.findall(line):
            if re.match(r"^[a-z][a-z+.-]*:", target):  # http(s), mailto: not checked here
                continue
            path, _, fragment = target.partition("#")
            dest = (page.parent / path).resolve() if path else page
            if not dest.exists():
                broken.append(f"line {number}: {target} (no such file)")
            elif fragment and dest.suffix == ".md" and fragment not in anchors(dest):
                broken.append(f"line {number}: {target} (no such heading)")
    assert not broken, broken


def test_the_subsidiaries_page_publishes_the_current_bridge_contract():
    spec = importlib.util.spec_from_file_location("sync_contract_doc", ROOT / "scripts" / "sync_contract_doc.py")
    sync = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sync)
    doc = sync.DOC.read_text(encoding="utf-8")
    assert doc == sync.render(doc, sync.SPEC.read_text(encoding="utf-8")), \
        "docs/SUBSIDIARIES.md is out of date: run scripts/sync_contract_doc.py"
    assert "### 8. Verification order" in doc and "#### Test vectors" in doc  # headings one level down
