"""The web UI's JavaScript: every module under hub/web/js parses (``node --check``), and the pure modules (the canvas
engine, the UI toolkit's helpers) pass their unit tests (``node --test tests/js/*.test.mjs``, Node's built-in runner).
Skipped when ``node`` is not on PATH, so Node stays optional for the Python suite."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")


def node(*args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run([NODE or "node", *args], cwd=ROOT, capture_output=True, text=True, timeout=timeout)


def test_every_web_module_parses():
    files = sorted((ROOT / "hub" / "web" / "js").rglob("*.js"))
    assert files
    failed = {str(f.relative_to(ROOT)): (r.stderr or r.stdout)[-800:] for f in files if (r := node("--check", str(f))).returncode}
    assert not failed, failed


def test_canvas_unit_tests():
    tests = sorted(str(p.relative_to(ROOT)) for p in (ROOT / "tests" / "js").glob("*.test.mjs"))
    assert tests
    result = node("--test", *tests)
    assert result.returncode == 0, (result.stdout + result.stderr)[-4000:]
