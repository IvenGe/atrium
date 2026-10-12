"""Run the canvas unit tests with Node. Skips when node is not installed."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_canvas_modules():
    proc = subprocess.run(
        ["node", "--experimental-detect-module", "--test", "tests/js/canvas.test.mjs"],
        cwd=ROOT, capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
