"""The installers: static checks of install.ps1, install.sh and the Docker files, and unit tests of
scripts/install_copy.py. Nothing here installs anything or writes outside pytest's temporary folders."""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from hub.__main__ import build_parser
from hub.app import create_app
from hub.config import Settings

ROOT = Path(__file__).resolve().parent.parent
INSTALLER_FILES = ("install.ps1", "install.sh", "Dockerfile", "docker-compose.yml", ".dockerignore",
                   "scripts/install_copy.py")


def _load_install_copy():
    spec = importlib.util.spec_from_file_location("install_copy", ROOT / "scripts" / "install_copy.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


install_copy = _load_install_copy()


def read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


# -- all installer files ------------------------------------------------------------------


@pytest.mark.parametrize("name", INSTALLER_FILES)
def test_installer_file_exists_and_holds_no_secrets(name: str) -> None:
    text = read(name)
    assert text.strip()
    assert not re.search(r"sk-ant-[A-Za-z0-9_-]{8,}", text)
    assert "PRIVATE KEY-----" not in text
    secret = r"(ANTHROPIC_API_KEY|HUB_ADMIN_PASSWORD|HUB_OIDC_CLIENT_SECRET|HUB_SETUP_TOKEN)"
    assert not re.search(rf"(?m)^\s*-?\s*{secret}\s*[:=]\s*[\"']?[^\s\"'$]", text), "a secret is set in " + name
    assert not re.search(r"(?i)(password|secret|token)\s*[:=]\s*[\"'][^\"'$]{4,}[\"']", text)


# -- install.ps1 --------------------------------------------------------------------------


def powershell() -> str | None:
    return shutil.which("powershell") or shutil.which("pwsh")


def test_install_ps1_is_ascii_for_windows_powershell() -> None:
    # Windows PowerShell 5.1 reads a script without a byte order mark in the ANSI code page.
    assert (ROOT / "install.ps1").read_bytes().isascii()


def test_install_ps1_has_its_options_and_never_overwrites_env() -> None:
    text = read("install.ps1")
    for option in ("[string]$InstallDir", "[int]$Port", "[switch]$NoShortcut", "[switch]$Dev"):
        assert option in text
    assert "ai,ssh" in text
    assert re.search(r"if \(Test-Path -LiteralPath \$envFile\).*?elseif.*?Copy-Item -LiteralPath \$envExample",
                     text, re.S)
    for written in ("start-atrium.cmd", "start-atrium.ps1", "Atrium.lnk", "#/setup?token="):
        assert written in text


def test_install_ps1_parses() -> None:
    shell = powershell()
    if not shell:
        pytest.skip("PowerShell is not installed")
    script = ("$tokens = $null; $errors = $null; "
              "[void][System.Management.Automation.Language.Parser]::ParseFile($env:ATRIUM_PS1, [ref]$tokens, [ref]$errors); "
              "$errors | ForEach-Object { $_.ToString() }; exit @($errors).Count")
    result = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True,
                            text=True, timeout=120, env={**os.environ, "ATRIUM_PS1": str(ROOT / "install.ps1")})
    assert result.returncode == 0, result.stdout + result.stderr


def test_install_ps1_rejects_a_bad_port_before_doing_anything() -> None:
    shell = powershell()
    if not shell:
        pytest.skip("PowerShell is not installed")
    result = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                             str(ROOT / "install.ps1"), "-Port", "0", "-NoShortcut"],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode != 0
    assert "Looking for Python" not in result.stdout


# -- install.sh ---------------------------------------------------------------------------


def bash() -> str | None:
    if os.name != "nt":
        return shutil.which("bash")
    # Git for Windows' bash. C:\Windows\System32\bash.exe starts WSL, which sees other paths.
    found = shutil.which("bash")
    if found and "system32" not in found.lower() and "windowsapps" not in found.lower():
        return found
    git = shutil.which("git")
    for folder in Path(git).resolve().parents if git else ():
        if (folder / "bin" / "bash.exe").is_file():
            return str(folder / "bin" / "bash.exe")
    return None


def run_install_sh(*args: str) -> subprocess.CompletedProcess[str]:
    shell = bash()
    if not shell:
        pytest.skip("bash is not installed")
    return subprocess.run([shell, (ROOT / "install.sh").as_posix(), *args], capture_output=True, text=True,
                          timeout=120, cwd=ROOT)


def test_install_sh_syntax() -> None:
    shell = bash()
    if not shell:
        pytest.skip("bash is not installed")
    result = subprocess.run([shell, "-n", (ROOT / "install.sh").as_posix()], capture_output=True, text=True,
                            timeout=60)
    assert result.returncode == 0, result.stderr


def test_install_sh_is_strict_and_only_writes_the_unit() -> None:
    text = read("install.sh")
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "\r" not in text
    assert "set -euo pipefail" in text
    assert "ai,ssh" in text and "start-atrium.sh" in text and "--service" in text
    # The unit is written, never enabled: systemctl only shows up in the printed instructions.
    for line in text.splitlines():
        if "systemctl" in line and not line.lstrip().startswith("#"):
            assert "printf" in line, line
    assert re.search(r'if \[ -e "\$env_file" \].*?elif.*?cp -- "\$target/\.env\.example" "\$env_file"', text, re.S)


def test_install_sh_help() -> None:
    result = run_install_sh("--help")
    assert result.returncode == 0, result.stderr
    assert "--install-dir" in result.stdout and "--service" in result.stdout


@pytest.mark.parametrize("args", [("--port", "70000"), ("--port", "80a"), ("--port",), ("--bogus",),
                                  ("--install-dir",)])
def test_install_sh_rejects_bad_options_before_doing_anything(args: tuple[str, ...]) -> None:
    result = run_install_sh(*args)
    assert result.returncode == 2
    assert "error:" in result.stderr
    assert "Looking for Python" not in result.stdout


def test_install_sh_service_needs_linux() -> None:
    if sys.platform.startswith("linux"):
        pytest.skip("on Linux --service is allowed")
    result = run_install_sh("--service")
    assert result.returncode == 2
    assert "needs Linux" in result.stderr


# -- Docker -------------------------------------------------------------------------------


def dockerfile() -> list[tuple[str, str]]:
    """(INSTRUCTION, arguments) pairs, continuation lines joined."""
    joined = re.sub(r"\\\n", " ", read("Dockerfile"))
    pairs = []
    for line in joined.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            instruction, _, args = line.partition(" ")
            pairs.append((instruction.upper(), args.strip()))
    return pairs


def test_dockerfile() -> None:
    steps = dockerfile()
    args = {a.split("=")[0]: a.split("=")[1] for i, a in steps if i == "ARG" and "=" in a}
    froms = [a for i, a in steps if i == "FROM"]
    assert froms == ["python:${PYTHON_VERSION}-slim"]
    major, minor = (int(part) for part in args["PYTHON_VERSION"].split("."))
    assert (major, minor) >= (3, 12)
    run = " ".join(a for i, a in steps if i == "RUN")
    assert "git" in run and "openssh-client" in run and "rm -rf /var/lib/apt/lists/*" in run
    assert re.search(r"pip install \"\.\[ai,ssh\]\"", run)
    env = " ".join(a for i, a in steps if i == "ENV")
    for setting in ("HUB_HOST=0.0.0.0", "HUB_DATA_DIR=/data", "HUB_PORT=8710"):
        assert setting in env
    users = [a for i, a in steps if i == "USER"]
    assert users and users[-1] not in ("root", "0")
    assert ("EXPOSE", "8710") in steps
    assert ("VOLUME", '["/data"]') in steps
    health = [a for i, a in steps if i == "HEALTHCHECK"]
    assert len(health) == 1 and '"python"' in health[0] and "/api/health" in health[0]
    assert ("ENTRYPOINT", '["atrium"]') in steps and ("CMD", '["serve"]') in steps


def test_dockerfile_command_parses() -> None:
    assert build_parser().parse_args(["serve"]).command == "serve"


def test_health_check_needs_no_sign_in_and_accepts_the_container_host(tmp_path: Path) -> None:
    app = create_app(Settings(data_dir=tmp_path / "data", start_background_tasks=False))
    with TestClient(app, base_url="http://127.0.0.1:8710") as client:
        for host in ("127.0.0.1:8710", "localhost:8710"):
            response = client.get("/api/health", headers={"Host": host})
            assert response.status_code == 200, response.text
            assert response.json() == {"ok": True}
        assert client.get("/api/health", headers={"Host": "evil.example"}).status_code == 400


def test_docker_compose(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    compose = yaml.safe_load(read("docker-compose.yml"))
    service = compose["services"]["atrium"]
    assert service["build"] == "."
    assert service["ports"] == ["127.0.0.1:8710:8710"]
    assert service["env_file"] == [{"path": ".env", "required": False}]
    volume, _, mount = service["volumes"][0].partition(":")
    assert mount == "/data" and volume in compose["volumes"]
    env = service["environment"]
    assert env["HUB_HOST"] == "0.0.0.0" and env["HUB_DATA_DIR"] == "/data" and env["HUB_PORT"] == "8710"

    # What the hub makes of these settings when .env sets nothing (Compose expands ${X:-} to an empty string).
    expand = lambda value: re.sub(r"\$\{[A-Z_]+:-([^}]*)\}", r"\1", str(value))  # noqa: E731
    monkeypatch.chdir(tmp_path)
    for key, value in env.items():
        monkeypatch.setenv(key, expand(value))
    settings = Settings.from_env()
    assert {"localhost", "127.0.0.1"} <= set(settings.allowed_hosts)
    assert settings.public_url == "http://localhost:8710"
    assert settings.data_dir == Path("/data").resolve()


def test_dockerignore_keeps_secrets_and_local_state_out() -> None:
    patterns = [line.strip() for line in read(".dockerignore").splitlines() if line.strip() and not line.startswith("#")]
    for pattern in (".git", ".venv", ".hub*", ".env", "**/.env", "**/__pycache__", "**/.pytest_cache"):
        assert pattern in patterns
    assert patterns.index("!.env.example") > patterns.index(".env.*")


# -- scripts/install_copy.py --------------------------------------------------------------

CHECKOUT = {
    "pyproject.toml": '[project]\nname = "atrium"\nversion = "0"\n',
    "README.md": "readme",
    ".env.example": "ANTHROPIC_API_KEY=\n",
    ".env": "local settings",
    ".env.local": "local settings",
    "hub/__init__.py": "",
    "hub/app.py": "app",
    "hub/web/index.html": "<html>",
    "hub/__pycache__/app.cpython-314.pyc": "",
    "docs/build/page.md": "nested build folders are content",
    "examples/app/.env": "local settings",
    "examples/app/.env.example": "",
    "examples/app/node_modules/x.js": "",
    "examples/app/.venv/pyvenv.cfg": "",
    ".venv/pyvenv.cfg": "",
    "venv/pyvenv.cfg": "",
    ".hub/hub.db": "",
    ".hub-dev/hub.db": "",
    ".git/HEAD": "",
    ".claude/launch.json": "",
    "atrium.egg-info/PKG-INFO": "",
    "build/lib/x.py": "",
    "start-atrium.cmd": "",
    "start-atrium.sh": "",
}
COPIED = {"pyproject.toml", "README.md", ".env.example", "hub/__init__.py", "hub/app.py", "hub/web/index.html",
          "docs/build/page.md", "examples/app/.env.example"}


def write_tree(root: Path, files: dict[str, str]) -> Path:
    for name, content in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(content, encoding="utf-8")
    return root


def tree(root: Path) -> set[str]:
    return {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}


def test_copy_leaves_local_state_out(tmp_path: Path) -> None:
    source = write_tree(tmp_path / "checkout", CHECKOUT)
    copied, removed = install_copy.copy_tree(source, tmp_path / "install dir")
    assert tree(tmp_path / "install dir") == COPIED
    assert (copied, removed) == (len(COPIED), 0)
    assert install_copy.is_atrium(tmp_path / "install dir")


def test_copy_again_keeps_local_state_and_mirrors_the_package(tmp_path: Path) -> None:
    source = write_tree(tmp_path / "checkout", CHECKOUT)
    target = tmp_path / "install"
    install_copy.copy_tree(source, target)
    write_tree(target, {".env": "mine", ".venv/pyvenv.cfg": "venv", ".hub/hub.db": "data", "notes.txt": "mine",
                        "hub/__pycache__/gone.cpython-314.pyc": ""})
    (source / "hub" / "app.py").unlink()
    write_tree(source, {"hub/api.py": "api", "README.md": "new readme"})

    copied, removed = install_copy.copy_tree(source, target)
    assert removed == 1
    assert not (target / "hub" / "app.py").exists()
    assert (target / "hub" / "api.py").read_text(encoding="utf-8") == "api"
    assert (target / "README.md").read_text(encoding="utf-8") == "new readme"
    for name, content in {".env": "mine", ".venv/pyvenv.cfg": "venv", ".hub/hub.db": "data", "notes.txt": "mine"}.items():
        assert (target / name).read_text(encoding="utf-8") == content


def test_copy_refuses_dangerous_targets(tmp_path: Path) -> None:
    source = write_tree(tmp_path / "checkout", CHECKOUT)
    with pytest.raises(ValueError, match="inside the checkout"):
        install_copy.copy_tree(source, source / "install")
    with pytest.raises(ValueError, match="contains the checkout"):
        install_copy.copy_tree(source, tmp_path)
    foreign = write_tree(tmp_path / "documents", {"letter.txt": "keep me"})
    with pytest.raises(ValueError, match="not empty"):
        install_copy.copy_tree(source, foreign)
    assert tree(foreign) == {"letter.txt"}
    with pytest.raises(ValueError, match="not an Atrium checkout"):
        install_copy.copy_tree(foreign, tmp_path / "install")
    assert install_copy.copy_tree(source, source) == (0, 0)


def test_copy_into_an_empty_or_interrupted_install(tmp_path: Path) -> None:
    source = write_tree(tmp_path / "checkout", CHECKOUT)
    (tmp_path / "empty").mkdir()
    install_copy.copy_tree(source, tmp_path / "empty")
    interrupted = write_tree(tmp_path / "interrupted", {"pyproject.toml": CHECKOUT["pyproject.toml"]})
    install_copy.copy_tree(source, interrupted)
    assert tree(tmp_path / "empty") == tree(interrupted) == COPIED


def test_copy_command_line(tmp_path: Path) -> None:
    source = write_tree(tmp_path / "check out", CHECKOUT)
    script = str(ROOT / "scripts" / "install_copy.py")
    ok = subprocess.run([sys.executable, "-I", script, str(source), str(tmp_path / "in stall")], capture_output=True,
                        text=True, timeout=60)
    assert ok.returncode == 0, ok.stderr
    assert f"Copied {len(COPIED)} files" in ok.stdout
    failed = subprocess.run([sys.executable, "-I", script, str(tmp_path), str(tmp_path / "x")], capture_output=True,
                            text=True, timeout=60)
    assert failed.returncode == 1 and failed.stderr.startswith("error: ")
    usage = subprocess.run([sys.executable, "-I", script], capture_output=True, text=True, timeout=60)
    assert usage.returncode == 2


def test_copy_of_this_checkout(tmp_path: Path) -> None:
    target = tmp_path / "atrium"
    install_copy.copy_tree(ROOT, target)
    assert install_copy.is_atrium(target)
    for present in ("install.ps1", "install.sh", "scripts/install_copy.py", ".env.example", "hub/web/index.html"):
        assert (target / present).is_file(), present
    for absent in (".env", ".venv", ".git", ".hub", ".hub-dev", ".claude"):
        assert not (target / absent).exists(), absent
    assert not any(path.name == "__pycache__" for path in target.rglob("*"))
