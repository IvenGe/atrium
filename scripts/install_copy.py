"""Copy an Atrium checkout to an install folder (used by install.ps1 and install.sh).

    python scripts/install_copy.py SOURCE TARGET

Local state is left out: virtual environments, hub data (.hub*), .env files, git metadata, caches and build output.
Files are added or replaced and nothing outside the hub package is ever deleted, so the target's .venv, .env and
.hub survive a rerun. When the target already is an Atrium install, its hub package is mirrored so modules removed
from the checkout do not linger there. A folder that is neither empty nor an Atrium install is refused.
"""

from __future__ import annotations

import fnmatch
import os
import shutil
import sys
import tomllib
from pathlib import Path

PACKAGE = "hub"
KEEP = (".env.example",)
TOP_LEVEL_SKIP = (".git", "venv", ".hub", ".hub-*", ".claude", ".idea", ".vscode", "build", "dist", "*.egg-info",
                  "start-atrium.*")
ANYWHERE_SKIP = (".env", ".env.*", ".venv", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache",
                 ".ruff_cache", "*.py[cod]", ".DS_Store", "Thumbs.db")


def skipped(name: str, top_level: bool) -> bool:
    if name in KEEP:
        return False
    patterns = ANYWHERE_SKIP + (TOP_LEVEL_SKIP if top_level else ())
    return any(fnmatch.fnmatch(name, pattern) for pattern in patterns)


def project_name(folder: Path) -> str | None:
    try:
        project = tomllib.loads((folder / "pyproject.toml").read_text(encoding="utf-8")).get("project", {})
    except (OSError, ValueError):
        return None
    return project.get("name") if isinstance(project, dict) else None


def is_atrium(folder: Path) -> bool:
    return project_name(folder) == "atrium" and (folder / PACKAGE).is_dir()


def prune(source: Path, target: Path) -> int:
    """Delete what an earlier install's package has but the checkout no longer does."""
    removed = 0
    for folder, dirs, files in os.walk(target):
        here = Path(folder)
        mirror = source / here.relative_to(target)
        for name in list(dirs):
            if skipped(name, False):
                dirs.remove(name)
            elif not (mirror / name).is_dir():
                shutil.rmtree(here / name)
                dirs.remove(name)
                removed += 1
        for name in files:
            if not skipped(name, False) and not (mirror / name).is_file():
                (here / name).unlink()
                removed += 1
    return removed


def copy_tree(source: Path, target: Path) -> tuple[int, int]:
    """(files copied, stale package files removed)."""
    source, target = source.resolve(), target.resolve()
    if not is_atrium(source):
        raise ValueError(f"{source} is not an Atrium checkout")
    if target == source:
        return 0, 0
    if source in target.parents:
        raise ValueError(f"the install folder {target} is inside the checkout {source}; choose a folder outside it")
    if target in source.parents:
        raise ValueError(f"the install folder {target} contains the checkout {source}; choose another folder")
    # An interrupted earlier copy has pyproject.toml (it is copied first) and may lack the package: still ours.
    if target.is_dir() and any(target.iterdir()) and project_name(target) != "atrium":
        raise ValueError(f"the install folder {target} is not empty and holds no Atrium install; "
                         "choose a new or empty folder")
    upgrade = is_atrium(target)
    copied = 0
    for folder, dirs, files in os.walk(source):
        here = Path(folder)
        top = here == source
        dirs[:] = [name for name in dirs if not skipped(name, top)]
        dest = target / here.relative_to(source)
        dest.mkdir(parents=True, exist_ok=True)
        for name in sorted(files, key=lambda name: name != "pyproject.toml"):  # first, see the check above
            if not skipped(name, top):
                shutil.copy2(here / name, dest / name)
                copied += 1
    removed = prune(source / PACKAGE, target / PACKAGE) if upgrade else 0
    return copied, removed


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    try:
        copied, removed = copy_tree(Path(argv[0]), Path(argv[1]))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    stale = f", removed {removed} stale package files" if removed else ""
    print(f"Copied {copied} files to {Path(argv[1]).resolve()}{stale}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
