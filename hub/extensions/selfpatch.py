"""Self-patching: changes to Atrium's own repository, proposed by the Patch Agent (with Claude) when an extension pack
cannot express what a new tool needs.

1. Only while the allow_self_patching guardrail is on and Atrium runs from a git checkout.
2. The change lands in a git worktree on a new branch "atrium/self-<id>" under the workspace
   (workspace/self-patches/<id>); the user's checkout is not touched. Paths are validated: relative, inside the
   repository, never .git, .env*, .hub*, .venv / venv or the data directory, never through a symlink. A change that
   contains a known secret is refused.
3. Atrium's test suite runs in the worktree with the current interpreter (timeout; the tail of the output is kept),
   with credentials and the hub's settings removed from its environment.
4. Approval kind "self_patch" shows the diff and the test result; with failing tests it cannot be approved while
   self_patch_requires_tests is on, and only administrators decide it. With self_patch_requires_approval off a change
   that would be merged locally (tests passed) is applied at once - a pull request never is.
5. On approval: with self_patch_via_pull_request on, the GitHub CLI authenticated and an "origin" remote, the branch
   is pushed and a pull request opened (this outward action only ever follows a person's approval). Otherwise the
   branch is merged into the current branch - only when the working tree is clean - and Atrium shows "restart
   required" until it is restarted.

The test command and every git / gh call go through `SelfPatchConfig` (hub.self_patch), so tests inject fakes and
never run the real suite or reach the network.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Literal

from pydantic import BaseModel, Field

from .. import guardrails
from ..connectors.base import redact
from ..execution.runner import CommandResult, run_exec
from ..models import FileChange
from ..store import new_id

if TYPE_CHECKING:
    from ..core import Hub
    from ..models import Approval

COLLECTION = "self_patches"
MAX_FILES = 20
MAX_FILE = 200_000
MAX_DIFF = 200_000
TAIL = 6000
GIT_ID = ["-c", "user.name=Atrium Patch Agent", "-c", "user.email=patch-agent@atrium.local"]
FORBIDDEN_TOP = {".git", ".venv", "venv", "env", "node_modules", "__pycache__"}
SECRET_NAME = re.compile(r"(?i)(secret|token|password|passwd|credential|api[_-]?key|private[_-]?key|cookie|session|auth)")

Runner = Callable[[list[str], "Path | None", float, "dict[str, str] | None"], Awaitable[CommandResult]]


async def default_runner(args: list[str], cwd: Path | None, timeout: float, env: dict[str, str] | None = None) -> CommandResult:
    try:
        return await run_exec(args, cwd, timeout, env=env)
    except OSError as exc:  # the program is not installed
        return CommandResult(127, f"{args[0]}: {exc.strerror or exc}", 0.0)


def default_test_command() -> list[str]:
    return [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider"]


@dataclass
class SelfPatchConfig:
    """Where Atrium's repository is and how it is tested and changed (tests replace every part)."""

    repo: Path | None = None  # None: the folder above the hub package, when it is a git checkout
    test_command: list[str] | None = None  # None: pytest with the current interpreter
    test_timeout: float = 1800
    git: Runner = default_runner  # called with ["git", ...]
    gh: Runner = default_runner  # called with ["gh", ...]
    tests: Runner = default_runner  # runs test_command in the worktree
    extra: dict[str, Any] = field(default_factory=dict)

    def root(self) -> Path | None:
        """Atrium's checkout: `repo`, else the folder above the hub package - unless HUB_SELF_PATCH=off (the test
        suite sets it, so nothing ever patches or tests the real checkout from a test)."""
        if self.repo is None and os.environ.get("HUB_SELF_PATCH", "").strip().lower() == "off":
            return None
        root = (self.repo or Path(__file__).resolve().parents[2]).resolve()
        return root if (root / ".git").exists() else None


class SelfPatch(BaseModel):
    id: str = Field(default_factory=lambda: new_id("sp_"))
    title: str
    rationale: str = ""
    goal: str = ""
    tool_id: str | None = None
    requested_by: str = ""
    changes: list[FileChange] = []
    files: list[str] = []
    branch: str = ""
    worktree: str = ""
    base_branch: str = ""
    base_commit: str = ""
    commit: str = ""
    diff: str = ""
    tests: dict[str, Any] | None = None  # {ok, exit_code, timed_out, duration, command, tail, at}
    status: Literal["testing", "proposed", "approved", "merged", "pull_request", "rejected", "failed"] = "testing"
    mode: Literal["merge", "pull_request"] | None = None  # how an approval would apply it (checked again then)
    mode_reason: str = ""
    approval_id: str | None = None
    pr_url: str | None = None
    merge_commit: str | None = None
    error: str | None = None
    decided_by: str | None = None
    created_at: float = Field(default_factory=time.time)
    applied_at: float | None = None


class SelfPatchError(RuntimeError):
    pass


def config(hub: "Hub") -> SelfPatchConfig:
    return hub.self_patch


def get(hub: "Hub", patch_id: str) -> SelfPatch | None:
    doc = hub.store.get(COLLECTION, patch_id)
    return SelfPatch.model_validate(doc) if doc else None


def all_patches(hub: "Hub") -> list[SelfPatch]:
    return sorted((SelfPatch.model_validate(d) for d in hub.store.list(COLLECTION)), key=lambda p: -p.created_at)


def save(hub: "Hub", patch: SelfPatch) -> SelfPatch:
    hub.store.put(COLLECTION, patch.model_dump(mode="json"))
    hub.bus.publish("self_patch", public(patch, diff=False))
    return patch


def public(patch: SelfPatch, diff: bool = True) -> dict[str, Any]:
    out = patch.model_dump(mode="json", exclude={"changes"} | (set() if diff else {"diff"}))
    out["tests_passed"] = bool(patch.tests and patch.tests.get("ok"))
    return out


def availability(hub: "Hub") -> dict[str, Any]:
    """Whether a self-patch could be proposed now (no subprocess: the GitHub CLI is checked when one is applied)."""
    root = config(hub).root()
    return {"allowed": bool(guardrails.value(hub, "allow_self_patching")), "claude": hub.llm.available,
            "git_checkout": root is not None, "repo": str(root) if root else None,
            "requires_tests": bool(guardrails.value(hub, "self_patch_requires_tests")),
            "requires_approval": bool(guardrails.value(hub, "self_patch_requires_approval")),
            "via_pull_request": bool(guardrails.value(hub, "self_patch_via_pull_request"))}


# --------------------------------------------------------------------------------------
# safety
# --------------------------------------------------------------------------------------


def known_secrets(hub: "Hub") -> list[str]:
    """Secret values this process knows: settings and secret-looking environment variables."""
    s = hub.settings
    values = [s.secret_key, s.oidc_client_secret, s.admin_password, s.setup_token]
    values += [v for k, v in os.environ.items() if SECRET_NAME.search(k)]
    return [v for v in values if isinstance(v, str) and len(v) >= 8]


def check_path(hub: "Hub", root: Path, raw: str) -> PurePosixPath:
    """A path inside the repository that a self-patch may write."""
    text = raw.replace("\\", "/").strip()
    rel = PurePosixPath(text)
    if not text or rel.is_absolute() or re.match(r"^[A-Za-z]:", text) or ".." in rel.parts or not rel.parts:
        raise ValueError(f"Unsafe path: {raw}")
    top = rel.parts[0]
    if top in FORBIDDEN_TOP or top.startswith((".hub", ".env")) or any(p == ".git" for p in rel.parts) \
            or rel.name.startswith(".env"):
        raise ValueError(f"A self-patch may not change {raw}")
    data = hub.settings.data_dir.resolve()
    if (root / rel).resolve().is_relative_to(data) or data.is_relative_to((root / rel).resolve()):
        raise ValueError(f"A self-patch may not change Atrium's data directory ({raw})")
    return rel


def check_changes(hub: "Hub", root: Path, changes: list[FileChange]) -> list[FileChange]:
    if not changes:
        raise ValueError("The change is empty")
    if len(changes) > MAX_FILES:
        raise ValueError(f"A self-patch changes at most {MAX_FILES} files")
    secrets = known_secrets(hub)
    out, seen = [], set()
    for change in changes:
        rel = check_path(hub, root, change.path).as_posix()
        if rel in seen:
            raise ValueError(f"{rel} is changed twice")
        if len(change.content) > MAX_FILE:
            raise ValueError(f"The change of {rel} is too large")
        if any(s in change.content for s in secrets):
            raise ValueError(f"Refusing a change that contains a secret ({rel})")
        seen.add(rel)
        out.append(FileChange(path=rel, content=change.content))
    return out


def write_changes(worktree: Path, changes: list[FileChange]) -> None:
    """Write the files; refuse anything that would leave the worktree through a symlink."""
    base = worktree.resolve()
    for change in changes:
        dest = worktree / change.path
        current = worktree
        for part in PurePosixPath(change.path).parts:
            current = current / part
            if current.is_symlink():
                raise ValueError(f"Refusing to write through a symbolic link: {change.path}")
        if not dest.resolve().is_relative_to(base):
            raise ValueError(f"Unsafe path: {change.path}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(change.content, encoding="utf-8")


def test_env() -> dict[str, str]:
    """The test run's environment: no credentials and none of the running hub's settings; no model calls."""
    env = {k: v for k, v in os.environ.items()
           if not SECRET_NAME.search(k) and not k.startswith(("HUB_", "ANTHROPIC_", "GH_", "GITHUB_"))}
    return {**env, "HUB_LLM": "off", "PYTHONDONTWRITEBYTECODE": "1"}


# --------------------------------------------------------------------------------------
# git
# --------------------------------------------------------------------------------------


def _subcommand(args: list[str]) -> str:
    i = 0
    while i < len(args) and args[i] in ("-C", "-c"):
        i += 2
    return args[i] if i < len(args) else ""


async def _git(hub: "Hub", args: list[str], cwd: Path | None = None, timeout: float = 120,
               check: bool = True) -> CommandResult:
    result = await config(hub).git(["git", *args], cwd, timeout, None)
    if check and result.exit_code != 0:
        raise SelfPatchError(f"git {_subcommand(args)} failed: {redact(result.output.strip()[-500:], known_secrets(hub))}")
    return result


async def cleanup(hub: "Hub", patch: SelfPatch, delete_branch: bool = True) -> None:
    """Remove the worktree (and the branch, unless it was pushed or merged elsewhere)."""
    root = config(hub).root()
    if root is not None and patch.worktree:
        await _git(hub, ["-C", str(root), "worktree", "remove", "--force", patch.worktree], check=False)
        await _git(hub, ["-C", str(root), "worktree", "prune"], check=False)
        if delete_branch and patch.branch:
            await _git(hub, ["-C", str(root), "branch", "-D", patch.branch], check=False)
    if patch.worktree and Path(patch.worktree).exists():
        shutil.rmtree(patch.worktree, ignore_errors=True)


async def predict_mode(hub: "Hub") -> tuple[str, str]:
    """("pull_request" | "merge", why): a pull request needs the guardrail on, an origin remote and an authenticated
    GitHub CLI."""
    if not guardrails.value(hub, "self_patch_via_pull_request"):
        return "merge", "self_patch_via_pull_request is off"
    root = config(hub).root()
    if root is None:
        return "merge", "not a git checkout"
    origin = await _git(hub, ["-C", str(root), "remote", "get-url", "origin"], check=False)
    if origin.exit_code != 0:
        return "merge", "the repository has no origin remote"
    auth = await config(hub).gh(["gh", "auth", "status"], root, 60, None)
    if auth.exit_code != 0:
        return "merge", "the GitHub CLI (gh) is not installed or not signed in"
    return "pull_request", f"pull request on {redact(origin.output.strip(), known_secrets(hub))}"


# --------------------------------------------------------------------------------------
# proposing
# --------------------------------------------------------------------------------------


async def propose(hub: "Hub", *, title: str, rationale: str, changes: list[FileChange], goal: str = "",
                  tool_id: str | None = None, requested_by: str = "patcher") -> SelfPatch:
    """Commit the change on a new branch in a worktree and run the test suite there. Raises ValueError when it may
    not be proposed (guardrail, no git checkout, unsafe paths or a secret)."""
    if not guardrails.value(hub, "allow_self_patching"):
        raise ValueError("Self-patching is switched off (guardrail allow_self_patching)")
    cfg = config(hub)
    root = cfg.root()
    if root is None:
        raise ValueError("Atrium does not run from a git checkout, so it cannot patch itself")
    changes = check_changes(hub, root, changes)
    patch = SelfPatch(title=title.strip()[:120] or "Change Atrium", rationale=rationale.strip()[:4000], goal=goal[:4000],
                      tool_id=tool_id, requested_by=requested_by, changes=changes, files=[c.path for c in changes])
    patch.branch = f"atrium/self-{patch.id.removeprefix('sp_')}"
    worktree = hub.settings.workspace / "self-patches" / patch.id
    patch.base_commit = (await _git(hub, ["-C", str(root), "rev-parse", "HEAD"])).output.strip()
    head = await _git(hub, ["-C", str(root), "symbolic-ref", "--quiet", "--short", "HEAD"], check=False)
    patch.base_branch = head.output.strip() if head.exit_code == 0 else ""
    worktree.parent.mkdir(parents=True, exist_ok=True)
    await _git(hub, ["-C", str(root), "worktree", "add", "-b", patch.branch, str(worktree), patch.base_commit])
    patch.worktree = str(worktree)
    try:
        write_changes(worktree, changes)
        await _git(hub, ["-C", str(worktree), "add", "-A"])
        await _git(hub, ["-C", str(worktree), *GIT_ID, "commit", "--no-verify", "-m",
                         f"Atrium self-patch: {patch.title}\n\n{patch.rationale}"])
        patch.commit = (await _git(hub, ["-C", str(worktree), "rev-parse", "HEAD"])).output.strip()
        diff = await _git(hub, ["-C", str(worktree), "diff", "--no-color", patch.base_commit, patch.commit], timeout=60)
        patch.diff = redact(diff.output, known_secrets(hub))[:MAX_DIFF]
    except Exception:
        await cleanup(hub, patch)
        raise
    save(hub, patch)
    hub.activity(requested_by, "info", f"Self-patch '{patch.title}' on branch {patch.branch}: running the tests",
                 self_patch_id=patch.id)
    command = cfg.test_command or default_test_command()
    started = time.time()
    result = await cfg.tests(command, worktree, cfg.test_timeout, test_env())
    patch.tests = {"ok": result.exit_code == 0 and not result.timed_out, "exit_code": result.exit_code,
                   "timed_out": result.timed_out, "duration": round(time.time() - started, 2),
                   "command": " ".join(Path(command[0]).name if i == 0 else a for i, a in enumerate(command)),
                   "tail": redact(result.output[-TAIL:], known_secrets(hub)), "at": time.time()}
    patch.mode, patch.mode_reason = await predict_mode(hub)  # type: ignore[assignment]
    patch.status = "proposed"
    return save(hub, patch)


def approval_payload(patch: SelfPatch) -> dict[str, Any]:
    tests = patch.tests or {}
    return {"self_patch_id": patch.id, "title": patch.title, "branch": patch.branch, "base_branch": patch.base_branch,
            "files": patch.files, "tool_id": patch.tool_id, "mode": patch.mode, "mode_reason": patch.mode_reason,
            "tests": {k: tests.get(k) for k in ("ok", "exit_code", "timed_out", "duration", "command", "tail")}}


async def submit(hub: "Hub", patch: SelfPatch, requester: str) -> SelfPatch:
    """Queue the tested change for approval - or, with self_patch_requires_approval off, merge it at once when it
    would be merged locally and its tests passed (a pull request always waits for a person)."""
    ok = bool(patch.tests and patch.tests.get("ok"))
    verdict = "tests passed" if ok else "TESTS FAILED"
    detail = (f"{patch.rationale}\n\nBranch {patch.branch} ({len(patch.files)} file(s): {', '.join(patch.files[:8])}); "
              f"{verdict}. On approval: "
              + ("pushed and opened as a pull request." if patch.mode == "pull_request" else
                 f"merged into {patch.base_branch or 'the current branch'} (needs a clean working tree), then Atrium "
                 "must be restarted."))
    approval = hub.approvals.create("self_patch", f"Change Atrium: {patch.title}", detail, approval_payload(patch),
                                    requester)
    patch.approval_id = approval.id
    save(hub, patch)
    tests_ok = ok or not guardrails.value(hub, "self_patch_requires_tests")
    if not guardrails.value(hub, "self_patch_requires_approval") and patch.mode == "merge" and tests_ok:
        hub.approvals.approve_automatically(approval.id, requester,
                                            "Applied without approval (guardrail self_patch_requires_approval is off)")
        await decided(hub, approval.id, True, requester)
    return get(hub, patch.id) or patch


# --------------------------------------------------------------------------------------
# deciding and applying
# --------------------------------------------------------------------------------------


def check_decision(hub: "Hub", approval: "Approval", approve: bool) -> None:
    """Approvals guard: failing tests make a self-patch unapprovable while self_patch_requires_tests is on."""
    if not approve:
        return
    patch = get(hub, str(approval.payload.get("self_patch_id")))
    if patch is None:
        raise ValueError("The self-patch no longer exists")
    if guardrails.value(hub, "self_patch_requires_tests") and not (patch.tests and patch.tests.get("ok")):
        raise ValueError("The tests failed on this change, so it cannot be approved while the guardrail "
                         "self_patch_requires_tests is on - reject it")


async def decided(hub: "Hub", approval_id: str, approved: bool, actor: str) -> None:
    approval = hub.approvals.get(approval_id)
    if approval is None or approval.kind != "self_patch":
        return
    patch = get(hub, str(approval.payload.get("self_patch_id")))
    if patch is None or patch.status != "proposed":
        return
    patch.decided_by = actor
    if not approved:
        patch.status = "rejected"
        await cleanup(hub, patch)
        patch.worktree = ""
        save(hub, patch)
        hub.activity(actor, "info", f"Self-patch '{patch.title}' rejected; its branch was removed", self_patch_id=patch.id)
        return
    patch.status = "approved"
    save(hub, patch)
    result = await apply(hub, patch, actor)
    hub.approvals.complete(approval_id, result["ok"], result)


async def apply(hub: "Hub", patch: SelfPatch, actor: str) -> dict[str, Any]:
    """Open a pull request or merge an approved self-patch. {ok, mode, detail, pr_url?, commit?, restart_required}.
    A refusal (e.g. a dirty working tree) keeps the patch approved, so it can be applied again later."""
    try:
        if patch.status != "approved":
            raise SelfPatchError(f"The self-patch is {patch.status}, not approved")
        if guardrails.value(hub, "self_patch_requires_tests") and not (patch.tests and patch.tests.get("ok")):
            raise SelfPatchError("The tests failed on this change (guardrail self_patch_requires_tests)")
        root = config(hub).root()
        if root is None:
            raise SelfPatchError("Atrium no longer runs from a git checkout")
        mode, reason = await predict_mode(hub)
        patch.mode, patch.mode_reason = mode, reason  # type: ignore[assignment]
        if mode == "pull_request":
            result = await _pull_request(hub, root, patch)
        else:
            result = await _merge(hub, root, patch, actor)
    except SelfPatchError as exc:
        patch.error = str(exc)
        save(hub, patch)
        hub.activity(actor, "warn", f"Self-patch '{patch.title}' not applied: {exc}", self_patch_id=patch.id)
        return {"ok": False, "mode": patch.mode, "detail": str(exc), "restart_required": False}
    patch.error, patch.applied_at = None, time.time()
    save(hub, patch)
    return result


async def _pull_request(hub: "Hub", root: Path, patch: SelfPatch) -> dict[str, Any]:
    worktree = Path(patch.worktree)
    if not worktree.is_dir():
        raise SelfPatchError("The self-patch's worktree is gone - propose the change again")
    await _git(hub, ["-C", str(worktree), "push", "--set-upstream", "origin", patch.branch], timeout=300)
    tests = patch.tests or {}
    body = (f"{patch.rationale}\n\nProposed by Atrium's Patch Agent"
            + (f" for the tool `{patch.tool_id}`" if patch.tool_id else "")
            + f" and approved by {patch.decided_by}.\n\nTests in the worktree: "
            + ("passed" if tests.get("ok") else f"failed (exit code {tests.get('exit_code')})")
            + f" - `{tests.get('command', '')}`.")
    args = ["gh", "pr", "create", "--head", patch.branch, "--title", f"Atrium self-patch: {patch.title}",
            "--body", redact(body, known_secrets(hub))]
    if patch.base_branch:
        args += ["--base", patch.base_branch]
    result = await config(hub).gh(args, root, 300, None)
    if result.exit_code != 0:
        raise SelfPatchError(f"gh pr create failed: {redact(result.output.strip()[-500:], known_secrets(hub))}")
    url = next((line.strip() for line in reversed(result.output.splitlines()) if line.strip().startswith("https://")), "")
    patch.status, patch.pr_url = "pull_request", url or None
    await cleanup(hub, patch, delete_branch=False)  # the branch lives on in the pull request
    patch.worktree = ""
    hub.activity(patch.decided_by or "patcher", "info", f"Self-patch '{patch.title}' opened as a pull request"
                 + (f": {url}" if url else ""), self_patch_id=patch.id)
    return {"ok": True, "mode": "pull_request", "pr_url": patch.pr_url, "branch": patch.branch,
            "detail": f"Pull request opened{': ' + url if url else ''}", "restart_required": False}


async def _merge(hub: "Hub", root: Path, patch: SelfPatch, actor: str) -> dict[str, Any]:
    dirty = await _git(hub, ["-C", str(root), "status", "--porcelain", "--untracked-files=no"])
    if dirty.output.strip():
        raise SelfPatchError(f"The working tree of {root} has uncommitted changes - commit or stash them, then apply the "
                             "self-patch again")
    head = await _git(hub, ["-C", str(root), "symbolic-ref", "--quiet", "--short", "HEAD"], check=False)
    if head.exit_code != 0:
        raise SelfPatchError("The checkout is on a detached HEAD - switch to a branch, then apply the self-patch again")
    branch = head.output.strip()
    merged = await _git(hub, ["-C", str(root), *GIT_ID, "merge", "--no-ff", "--no-edit", "-m",
                              f"Merge Atrium self-patch: {patch.title}", patch.branch], timeout=300, check=False)
    if merged.exit_code != 0:
        await _git(hub, ["-C", str(root), "merge", "--abort"], check=False)
        raise SelfPatchError(f"git merge failed (aborted, nothing changed): "
                             f"{redact(merged.output.strip()[-400:], known_secrets(hub))}")
    commit = (await _git(hub, ["-C", str(root), "rev-parse", "HEAD"])).output.strip()
    patch.status, patch.merge_commit = "merged", commit
    await cleanup(hub, patch)
    patch.worktree = ""
    hub.restart_required = {"self_patch_id": patch.id, "title": patch.title, "branch": branch, "commit": commit,
                            "at": time.time(), "by": actor}
    hub.bus.publish("restart_required", hub.restart_required)
    hub.activity(actor, "warn", f"Self-patch '{patch.title}' merged into {branch} ({commit[:10]}): restart Atrium to "
                                "load it", self_patch_id=patch.id)
    return {"ok": True, "mode": "merge", "branch": branch, "commit": commit, "restart_required": True,
            "detail": f"Merged into {branch} - restart Atrium to load the change"}
