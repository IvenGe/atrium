"""Self-patching against a temporary git repository: the worktree on its own branch, the injected test command, the
"self_patch" approval (admins only, unapprovable with failing tests), merge on a clean tree with "restart required",
a dirty tree refused, pull request mode with a mocked GitHub CLI, path and secret checks, the guardrails, and the
change Claude writes (a fake model). Nothing here runs the real test suite or reaches the network."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_llm_paths import FakeLLM

from hub.execution.runner import CommandResult
from hub.extensions import selfpatch
from hub.models import FileChange, Manifest, Tool

HELLO = FileChange(path="hub/hello.py", content="def hello():\n    return 'hi'\n")


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A small checkout standing in for Atrium's own repository (its own git config: no signing, no hooks)."""
    config = tmp_path / "gitconfig"
    config.write_text("[user]\n\tname = Test\n\temail = test@example.com\n[init]\n\tdefaultBranch = main\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    root = tmp_path / "atrium"
    (root / "hub").mkdir(parents=True)
    (root / "hub" / "__init__.py").write_text('__version__ = "0.1.0"\n')
    (root / "README.md").write_text("# Atrium\n")
    (root / ".gitignore").write_text(".hub/\n")
    subprocess.run(["git", "init", "-q", "-b", "main", str(root)], check=True)
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "initial")
    return root


class FakeRunner:
    """Records every call; answers the first entry whose tokens all appear in the arguments, else delegates (or
    fails as a missing program would)."""

    def __init__(self, answers: dict[tuple[str, ...], CommandResult] | None = None, delegate=None):
        self.answers, self.delegate, self.calls = answers or {}, delegate, []

    async def __call__(self, args, cwd, timeout, env=None):
        self.calls.append({"args": list(args), "cwd": cwd, "env": env})
        for tokens, result in self.answers.items():
            if all(t in args for t in tokens):
                return result
        if self.delegate is not None:
            return await self.delegate(args, cwd, timeout, env)
        return CommandResult(127, f"{args[0]}: not available in the tests", 0.0)


def configure(client, repo: Path, *, tests_ok: bool = True, gh: FakeRunner | None = None,
              git_runner=None) -> FakeRunner:
    output = "....\n3 passed in 0.01s\n" if tests_ok else "FAILED tests/test_hello.py::test_hello - AssertionError\n1 failed\n"
    tests = FakeRunner({(): CommandResult(0 if tests_ok else 1, output, 0.4)})
    client.app.state.hub.self_patch = selfpatch.SelfPatchConfig(
        repo=repo, test_command=["python", "-m", "pytest", "-q"], tests=tests, gh=gh or FakeRunner(),
        git=git_runner or selfpatch.default_runner)
    return tests


def propose(client, changes: list[FileChange] | None = None, title: str = "Add hello") -> selfpatch.SelfPatch:
    hub = client.app.state.hub

    async def run() -> selfpatch.SelfPatch:
        patch = await selfpatch.propose(hub, title=title, rationale="Greets people.", changes=changes or [HELLO],
                                        goal="say hi", requested_by="patcher")
        return await selfpatch.submit(hub, patch, "patcher")
    return client.portal.call(run)


def approval_of(client, approval_id: str) -> dict:
    return next(a for a in client.get("/api/approvals").json() if a["id"] == approval_id)


def control(client, control_id: str) -> dict:
    client.post("/api/grc/evaluate")
    return next(c for c in client.get("/api/grc").json()["controls"] if c["id"] == control_id)


def test_worktree_tests_admin_approval_and_merge_with_restart_required(client, repo, sign_in, wait_for):
    hub = client.app.state.hub
    tests = configure(client, repo)
    patch = propose(client)
    worktree = Path(patch.worktree)
    assert patch.status == "proposed" and patch.tests["ok"] and "3 passed" in patch.tests["tail"]
    assert worktree.is_relative_to(hub.settings.workspace / "self-patches") and (worktree / "hub" / "hello.py").is_file()
    assert patch.branch == f"atrium/self-{patch.id.removeprefix('sp_')}" and git(repo, "branch", "--list", patch.branch)
    assert "+def hello():" in patch.diff and patch.base_branch == "main" and patch.mode == "merge"
    assert patch.mode_reason == "the repository has no origin remote"
    assert not (repo / "hub" / "hello.py").exists()  # the checkout itself is untouched
    assert tests.calls[0]["cwd"] == worktree and tests.calls[0]["args"] == ["python", "-m", "pytest", "-q"]

    [approval] = [a for a in client.get("/api/approvals?status=pending").json() if a["kind"] == "self_patch"]
    assert approval["payload"]["tests"]["ok"] and approval["payload"]["files"] == ["hub/hello.py"]
    assert approval["payload"]["branch"] == patch.branch and approval["payload"]["mode"] == "merge"
    assert "+def hello():" in approval["self_patch"]["diff"] and approval["self_patch"]["tests_passed"]
    assert "then Atrium must be restarted" in approval["detail"]
    assert sign_in("viewer").get("/api/self-patches").json()["patches"][0]["id"] == patch.id
    refused = sign_in("operator").post(f"/api/approvals/{approval['id']}", json={"approve": True})
    assert refused.status_code == 403 and "administrators" in refused.json()["detail"]

    client.post(f"/api/approvals/{approval['id']}", json={"approve": True})
    done = wait_for(lambda: (a := approval_of(client, approval["id"]))["status"] == "done" and a)
    assert done["result"]["mode"] == "merge" and done["result"]["restart_required"] and done["result"]["branch"] == "main"
    assert (repo / "hub" / "hello.py").read_text() == HELLO.content
    assert git(repo, "log", "-1", "--pretty=%s") == "Merge Atrium self-patch: Add hello"
    assert not worktree.exists() and not git(repo, "branch", "--list", patch.branch)
    listing = client.get("/api/self-patches").json()
    assert listing["restart_required"]["self_patch_id"] == patch.id and listing["restart_required"]["by"] == "admin"
    assert listing["patches"][0]["status"] == "merged" and "diff" not in listing["patches"][0]
    assert "+def hello():" in client.get(f"/api/self-patches/{patch.id}").json()["diff"]
    assert client.get("/api/overview").json()["restart_required"] is True
    assert any(e["level"] == "warn" and "restart Atrium" in e["text"] for e in client.get("/api/activity").json())


def test_failing_tests_cannot_be_approved_and_a_rejection_removes_the_branch(client, repo, wait_for):
    hub = client.app.state.hub
    configure(client, repo, tests_ok=False)
    patch = propose(client)
    assert not patch.tests["ok"] and patch.tests["exit_code"] == 1 and "1 failed" in patch.tests["tail"]
    assert "TESTS FAILED" in approval_of(client, patch.approval_id)["detail"]
    refused = client.post(f"/api/approvals/{patch.approval_id}", json={"approve": True})
    assert refused.status_code == 409 and "self_patch_requires_tests" in refused.json()["detail"]
    assert approval_of(client, patch.approval_id)["status"] == "pending"
    client.post(f"/api/approvals/{patch.approval_id}", json={"approve": False})
    wait_for(lambda: selfpatch.get(hub, patch.id).status == "rejected")
    assert not Path(patch.worktree).exists() and not git(repo, "branch", "--list", patch.branch)

    # with the guardrail off a failing change can be approved - and HB-CM-2 fails meanwhile
    client.patch("/api/settings/guardrails", json={"self_patch_requires_tests": False})
    second = propose(client)
    client.post(f"/api/approvals/{second.approval_id}", json={"approve": True})
    wait_for(lambda: approval_of(client, second.approval_id)["status"] == "done")
    assert (repo / "hub" / "hello.py").is_file()
    state = wait_for(lambda: (c := control(client, "HB-CM-2"))["status"] == "fail" and c)
    assert "Self-patches must pass the tests" in state["detail"]


def test_a_dirty_working_tree_is_refused_until_it_is_clean(client, repo, sign_in, wait_for):
    hub = client.app.state.hub
    configure(client, repo)
    patch = propose(client)
    (repo / "README.md").write_text("# Atrium\nan edit nobody committed\n")
    client.post(f"/api/approvals/{patch.approval_id}", json={"approve": True})
    failed = wait_for(lambda: (a := approval_of(client, patch.approval_id))["status"] == "failed" and a)
    assert "uncommitted changes" in failed["result"]["detail"] and not failed["result"]["restart_required"]
    current = selfpatch.get(hub, patch.id)
    assert current.status == "approved" and "uncommitted changes" in current.error
    assert not (repo / "hub" / "hello.py").exists() and git(repo, "log", "-1", "--pretty=%s") == "initial"
    assert hub.restart_required is None

    assert sign_in("operator").post(f"/api/self-patches/{patch.id}/apply").status_code == 403
    git(repo, "checkout", "--", "README.md")
    applied = client.post(f"/api/self-patches/{patch.id}/apply").json()
    assert applied["ok"] and applied["self_patch"]["status"] == "merged" and applied["restart_required"]
    assert approval_of(client, patch.approval_id)["status"] == "done"
    assert client.post(f"/api/self-patches/{patch.id}/apply").status_code == 400  # merged already


def test_pull_request_mode_with_a_mocked_github_cli(client, repo, wait_for):
    hub = client.app.state.hub
    git(repo, "remote", "add", "origin", "https://x-access-token:ghs_notreal123@github.com/example/atrium.git")
    git_runner = FakeRunner({("push",): CommandResult(0, "branch pushed", 0.1)}, delegate=selfpatch.default_runner)
    gh = FakeRunner({("auth", "status"): CommandResult(0, "Logged in to github.com", 0.1),
                     ("pr", "create"): CommandResult(0, "Creating pull request\nhttps://github.com/example/atrium/pull/7\n", 0.2)})
    configure(client, repo, gh=gh, git_runner=git_runner)
    head = git(repo, "rev-parse", "HEAD")
    patch = propose(client)
    assert patch.mode == "pull_request" and patch.mode_reason == "pull request on https://github.com/example/atrium.git"
    assert "opened as a pull request" in approval_of(client, patch.approval_id)["detail"]
    assert not any("pr" in c["args"] for c in gh.calls)  # nothing outward before a person approves

    client.post(f"/api/approvals/{patch.approval_id}", json={"approve": True})
    done = wait_for(lambda: (a := approval_of(client, patch.approval_id))["status"] == "done" and a)
    assert done["result"]["pr_url"] == "https://github.com/example/atrium/pull/7" and not done["result"]["restart_required"]
    push = next(c["args"] for c in git_runner.calls if "push" in c["args"])
    assert push[-2:] == ["origin", patch.branch] and "--force" not in push
    create = next(c["args"] for c in gh.calls if "create" in c["args"])
    assert create[create.index("--head") + 1] == patch.branch and create[create.index("--base") + 1] == "main"
    assert "Tests in the worktree: passed" in create[create.index("--body") + 1]
    current = selfpatch.get(hub, patch.id)
    assert current.status == "pull_request" and current.pr_url.endswith("/pull/7") and not Path(patch.worktree).exists()
    assert git(repo, "rev-parse", "HEAD") == head and git(repo, "branch", "--list", patch.branch)  # nothing merged
    assert hub.restart_required is None

    # even without approval required, a pull request (an outward action) waits for a person
    client.patch("/api/settings/guardrails", json={"self_patch_requires_approval": False})
    second = propose(client, title="Second")
    assert second.status == "proposed" and approval_of(client, second.approval_id)["status"] == "pending"
    # ... while a local merge of a tested change is applied at once
    client.patch("/api/settings/guardrails", json={"self_patch_via_pull_request": False})
    third = propose(client, [FileChange(path="hub/third.py", content="THIRD = 3\n")], title="Third")
    assert third.status == "merged" and (repo / "hub" / "third.py").is_file()
    approval = approval_of(client, third.approval_id)
    assert approval["status"] == "done" and "self_patch_requires_approval is off" in approval["note"]
    assert hub.restart_required["self_patch_id"] == third.id


@pytest.mark.parametrize("path", [".env", ".env.local", "config/.env", ".git/config", "hub/../.git/hooks/pre-commit",
                                  ".venv/bin/python", "venv/x.py", ".hub/hub.db", ".hub-dev/x", "../outside.py",
                                  "/etc/passwd", "C:/Windows/system.ini", "hub/.git/x", ""])
def test_unsafe_paths_are_refused(client, repo, path):
    configure(client, repo)
    with pytest.raises(ValueError):
        selfpatch.check_changes(client.app.state.hub, repo, [FileChange(path=path, content="x")])


def test_symlinks_secrets_the_data_dir_and_the_guardrail(client, repo, tmp_path, monkeypatch):
    hub = client.app.state.hub
    configure(client, repo)
    outside = tmp_path / "outside"
    outside.mkdir()
    (repo / "linked").symlink_to(outside, target_is_directory=True)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "a link")
    with pytest.raises(ValueError, match="symbolic link"):
        propose(client, [FileChange(path="linked/evil.py", content="x = 1\n")])
    assert list(outside.iterdir()) == [] and not git(repo, "branch", "--list", "atrium/self-*")
    assert not any((hub.settings.workspace / "self-patches").iterdir())  # the failed worktree was removed

    monkeypatch.setenv("SUPPLIER_API_TOKEN", "tok-1234567890abcdef")
    with pytest.raises(ValueError, match="secret"):
        propose(client, [FileChange(path="hub/leak.py", content="TOKEN = 'tok-1234567890abcdef'\n")])
    fake = SimpleNamespace(settings=SimpleNamespace(data_dir=repo / "data"))
    with pytest.raises(ValueError, match="data directory"):
        selfpatch.check_path(fake, repo, "data/hub.db")
    with pytest.raises(ValueError, match="at most"):
        selfpatch.check_changes(hub, repo, [FileChange(path=f"hub/m{i}.py", content="") for i in range(21)])

    client.patch("/api/settings/guardrails", json={"allow_self_patching": False})
    with pytest.raises(ValueError, match="allow_self_patching"):
        propose(client)
    client.patch("/api/settings/guardrails", json={"allow_self_patching": True})
    hub.self_patch = selfpatch.SelfPatchConfig(repo=tmp_path / "plain")
    with pytest.raises(ValueError, match="git checkout"):
        propose(client)


def test_the_reviewer_sees_the_code_as_it_is(client, repo):
    """No generic "password=..." masking in the diff: it could hide what a line does."""
    configure(client, repo)
    patch = propose(client, [FileChange(path="hub/cfg.py", content="password=os.system('curl example.com')\n")])
    assert "+password=os.system('curl example.com')" in patch.diff


def test_the_test_run_gets_no_credentials(client, repo, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-a-real-key-123")
    monkeypatch.setenv("HUB_SECRET_KEY", "not-a-real-fernet-key-1234567")
    monkeypatch.setenv("BACKUP_PASSWORD", "hunter2hunter2")
    monkeypatch.setenv("GH_TOKEN", "ghp_notreal1234567890")
    tests = configure(client, repo)
    propose(client)
    env = tests.calls[0]["env"]
    for name in ("ANTHROPIC_API_KEY", "HUB_SECRET_KEY", "BACKUP_PASSWORD", "GH_TOKEN"):
        assert name not in env, name
    assert env["HUB_LLM"] == "off" and env["PATH"]


def test_claude_writes_the_change_through_the_api(client, repo, wait_for):
    hub = client.app.state.hub
    assert client.post("/api/self-patches", json={"goal": "x"}).json()["detail"].startswith("Self-patches need Claude")
    hub.llm = FakeLLM(json_result={"title": "Add an Acme connector", "rationale": "Acme only speaks GraphQL.",
                                   "changes": [{"path": "hub/acme.py", "content": "ACME = True\n"}]})
    refused = client.post("/api/self-patches", json={"goal": "x"})  # HUB_SELF_PATCH=off and no repo configured
    assert refused.status_code == 400 and "git checkout" in refused.json()["detail"]
    configure(client, repo)
    accepted = client.post("/api/self-patches", json={"goal": "Read Acme's GraphQL API"})
    assert accepted.status_code == 202 and accepted.json()["accepted"]
    approval = wait_for(lambda: next((a for a in client.get("/api/approvals?status=pending").json()
                                      if a["kind"] == "self_patch"), None))
    patch = selfpatch.get(hub, approval["payload"]["self_patch_id"])
    assert patch.title == "Add an Acme connector" and patch.goal == "Read Acme's GraphQL API" and patch.files == ["hub/acme.py"]
    prompt = hub.llm.calls[0]["prompt"]
    assert "<goal>Read Acme's GraphQL API</goal>" in prompt and "hub/__init__.py" in prompt
    assert hub.llm.calls[0]["schema"]["required"] == ["title", "rationale", "changes"]

    # Claude may only rewrite files it was shown
    hub.llm = FakeLLM(json_result={"title": "x", "rationale": "y", "changes": [{"path": "README.md", "content": "pwned"}]})
    client.post("/api/self-patches", json={"goal": "Change the readme"})
    wait_for(lambda: any("without having seen it" in e["text"] for e in client.get("/api/activity").json()))
    assert (repo / "README.md").read_text() == "# Atrium\n"


class ScriptedLLM(FakeLLM):
    def __init__(self, results: list[dict]):
        super().__init__()
        self.results = list(results)

    async def json(self, **kwargs):
        self.calls.append(kwargs)
        return self.results.pop(0)


def test_a_gap_only_code_can_close_requests_a_self_patch_once(client, repo, wait_for):
    hub = client.app.state.hub
    configure(client, repo)
    tool = Tool(id="acme", name="Acme", source_type="saas", source="https://acme.example.com", status="ready",
                manifest=Manifest(id="acme", name="Acme", kind="saas", api={"type": "grpc"}))
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    hub.llm = ScriptedLLM([
        {"rationale": "", "pack_json": "", "needs_code": True, "code_goal": "Add a gRPC connector for Acme"},
        {"title": "gRPC connector for Acme", "rationale": "A pack cannot call gRPC.",
         "changes": [{"path": "hub/acme_grpc.py", "content": "GRPC = True\n"}]},
    ])
    result = client.post("/api/tools/acme/extend").json()
    assert result["self_patch"] == "requested" and not result["proposed"]
    assert [g["kind"] for g in result["gaps"]] == ["connector"] and result["gaps"][0]["expressible"] is False
    approval = wait_for(lambda: next((a for a in client.get("/api/approvals?status=pending").json()
                                      if a["kind"] == "self_patch"), None))
    assert approval["payload"]["tool_id"] == "acme"
    assert selfpatch.get(hub, approval["payload"]["self_patch_id"]).goal == "Add a gRPC connector for Acme"
    assert client.post("/api/tools/acme/extend").json()["self_patch"] is None  # one self-patch per tool
