"""The vendored Go bridge core (hub/subsidiary/templates/go/atriumbridge) against the contract's vectors: ``go test``
in a temporary module holding the core, the vendored widget and tests/bridge_cores/go/core_test.go, plus the glue
skeleton compiled against it. Skipped when ``go`` is not on PATH; never downloads anything (GOPROXY=off)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "hub" / "subsidiary" / "templates"
GO = shutil.which("go")
pytestmark = pytest.mark.skipif(GO is None, reason="go is not installed")


def go(*args: str, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([GO or "go", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=600)


@pytest.fixture
def module(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    package = tmp_path / "tool" / "atriumbridge"
    package.mkdir(parents=True)
    shutil.copy(TEMPLATES / "go" / "atriumbridge" / "core.go", package / "core.go")
    shutil.copy(TEMPLATES / "panel" / "panel.js", package / "panel.js")
    shutil.copy(ROOT / "tests" / "bridge_cores" / "go" / "core_test.go", package / "core_test.go")
    (tmp_path / "tool" / "go.mod").write_text("module example.com/tool\n\ngo 1.20\n")
    glue = (TEMPLATES / "go" / "glue_skeleton.go").read_text().replace("__MODULE__", "example.com/tool")
    (tmp_path / "tool" / "atrium_glue.go").write_text(glue)
    (tmp_path / "tool" / "main.go").write_text("package main\n\nfunc main() { _ = atriumBridge() }\n")
    env = {**os.environ, "GOPROXY": "off", "GOFLAGS": "-mod=mod", "GOTOOLCHAIN": "local", "GOWORK": "off",
           "CGO_ENABLED": "0", "ATRIUM_VECTORS": str(ROOT / "hub" / "subsidiary" / "contract" / "vectors.json")}
    env.setdefault("GOCACHE", str(tmp_path / "gocache"))
    return tmp_path / "tool", env


def test_go_core_passes_the_vectors_and_its_own_tests(module):
    cwd, env = module
    result = go("test", "-count=1", "./...", cwd=cwd, env=env)
    assert result.returncode == 0, (result.stdout + result.stderr)[-6000:]


def test_go_core_and_glue_skeleton_vet_clean(module):
    cwd, env = module
    result = go("vet", "./...", cwd=cwd, env=env)
    assert result.returncode == 0, (result.stdout + result.stderr)[-4000:]
