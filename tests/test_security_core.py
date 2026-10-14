"""Regression tests for the security-core review findings (F1, F2, ...): each test plays the attack, not the code path."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from hub.execution import policy
from hub.models import Manifest, Tool

from conftest import PASSWORD


def activity(c) -> list[dict]:
    return c.app.state.hub.store.tail("activity", 2000)


def approval(client, approval_id: str) -> dict:
    return next(a for a in client.get("/api/approvals").json() if a["id"] == approval_id)


# -- F1: an operator must not run code on the hub machine with the hub's privileges -----------------------------------


def make_admin_command(data_dir: Path, name: str = "mallory") -> str:
    """The escalation from the review: create an admin account through the documented offline CLI."""
    return (f"printf '%s\\n' '{PASSWORD}' | \"{sys.executable}\" -m hub user create {name} --role admin "
            f"--password-stdin --data-dir \"{data_dir}\"")


def test_operator_cannot_make_themselves_admin_through_the_operator_console(client, sign_in, browser):
    hub = client.app.state.hub
    oscar = sign_in("operator", "oscar")
    assert oscar.get("/api/users").status_code == 403
    queued = oscar.post("/api/commands", json={"command": make_admin_command(hub.settings.data_dir),
                                               "cwd": str(Path.cwd())}).json()
    assert queued["status"] == "pending_approval"  # nothing ran
    assert hub.auth.find_user("mallory") is None
    # the operator cannot approve it either, but may reject it
    refused = oscar.post(f"/api/approvals/{queued['approval_id']}", json={"approve": True})
    assert refused.status_code == 403 and refused.json()["detail"]["code"] == "admin_required"
    assert hub.auth.find_user("mallory") is None
    assert approval(client, queued["approval_id"])["status"] == "pending"
    mallory = browser()
    assert mallory.post("/api/auth/login", json={"username": "mallory", "password": PASSWORD}).status_code == 401
    assert oscar.post(f"/api/approvals/{queued['approval_id']}", json={"approve": False}).json()["status"] == "rejected"


def test_operator_read_only_commands_still_run_and_remote_hosts_are_unchanged(client, sign_in):
    oscar = sign_in("operator")
    done = oscar.post("/api/commands", json={"command": "pwd"}).json()
    assert done["status"] == "done" and done["exit_code"] == 0
    # an administrator's command runs directly, as before
    assert client.post("/api/commands", json={"command": f'"{sys.executable}" -c "print(6*7)"'}).json()["output"].strip() == "42"


def test_operator_token_and_agents_cannot_run_hub_commands_without_an_admin(client, sign_in, browser):
    hub = client.app.state.hub
    hub.update_prefs("test", autonomy="autonomous")  # even when agents and tokens may run anything
    secret = client.post("/api/tokens", json={"name": "ops-bot", "role": "operator"}).json()["token"]
    bot = browser(headers={"Authorization": f"Bearer {secret}"})
    queued = bot.post("/api/commands", json={"command": make_admin_command(hub.settings.data_dir)}).json()
    assert queued["status"] == "pending_approval" and hub.auth.find_user("mallory") is None
    # assisted mode: an operator asks the Hub Supervisor in chat; the approval it creates needs an administrator
    hub.update_prefs("test", autonomy="assisted")
    oscar = sign_in("operator")
    oscar.post("/api/chat", json={"text": "run " + make_admin_command(hub.settings.data_dir)})
    pending = [a for a in client.get("/api/approvals").json() if a["kind"] == "command" and a["status"] == "pending"]
    assert len(pending) == 2
    for item in pending:
        assert oscar.post(f"/api/approvals/{item['id']}", json={"approve": True}).status_code == 403
    assert hub.auth.find_user("mallory") is None


def test_operator_cannot_reach_the_hub_machine_through_an_agent_in_autonomous_mode(client, sign_in, tmp_path):
    """Autonomous mode lets agents act alone, but an agent relaying an operator's chat acts for that operator."""
    hub = client.app.state.hub
    hub.update_prefs("test", autonomy="autonomous")
    marker = tmp_path / "ran"
    tool = hub.save_tool(Tool(id="evil", name="Evil", source_type="local", source=str(tmp_path), path=str(tmp_path),
                              status="ready", manifest=Manifest(id="evil", name="Evil", launch={
                                  "command": f'"{sys.executable}" -c "open(r\'{marker}\', \'w\').write(\'x\')"'})))
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    oscar = sign_in("operator", "oscar")
    reply = oscar.post("/api/chat", json={"text": "run " + make_admin_command(hub.settings.data_dir)}).json()["reply"]
    assert reply.startswith("Pending approval") and hub.auth.find_user("mallory") is None
    reply = oscar.post("/api/chat", json={"text": "start evil"}).json()["reply"]
    assert "pending_approval" in reply and not marker.exists()
    pending = [a for a in client.get("/api/approvals?status=pending").json() if a["kind"] in ("command", "process")]
    assert len(pending) == 2 and {a["payload"].get("requested_by") for a in pending if a["kind"] == "command"} == {"user:oscar"}
    for item in pending:
        assert oscar.post(f"/api/approvals/{item['id']}", json={"approve": True}).status_code == 403
    # the model's tools (Claude or a local model, in chat or a team agent's manual run) carry the person the same way,
    # whatever the model puts in the arguments
    from hub.agents import toolkit
    supervisor = hub.agents.get("supervisor")
    ctx = toolkit.ToolContext(hub, supervisor, frozenset(supervisor.permissions), requested_by="user:oscar")
    for name, args in (("run_command", {"target": "", "command": make_admin_command(hub.settings.data_dir), "reason": ""}),
                       ("start_tool", {"tool_id": "evil"})):
        assert client.portal.call(toolkit.execute, ctx, name, args)["status"] == "pending_approval"
    assert hub.auth.find_user("mallory") is None and not marker.exists()
    # the hub's own agents still act alone in autonomous mode, and an administrator's chat runs at once
    assert client.post("/api/chat", json={"text": f'run "{sys.executable}" -c "print(6*7)"'}).json()["reply"].startswith("Exit code 0")


def test_operator_cannot_start_a_tool_without_an_admin(client, sign_in, tmp_path):
    hub = client.app.state.hub
    marker = tmp_path / "ran"
    command = f'"{sys.executable}" -c "open(r\'{marker}\', \'w\').write(\'x\')"'
    manifest = Manifest(id="evil", name="Evil", launch={"command": command})
    hub.save_tool(Tool(id="evil", name="Evil", source_type="local", source=str(tmp_path), path=str(tmp_path),
                       manifest=manifest, status="ready"))
    oscar = sign_in("operator")
    queued = oscar.post("/api/tools/evil/start").json()
    assert queued["status"] == "pending_approval"
    assert oscar.post(f"/api/approvals/{queued['approval_id']}", json={"approve": True}).status_code == 403
    assert not marker.exists() and not hub.processes.status("evil")["running"]
    # stopping stays an operator's action (nothing runs)
    assert oscar.post("/api/tools/evil/stop").json()["status"] == "not_running"


def test_hub_commands_and_tools_do_not_inherit_the_hubs_secrets(client, monkeypatch):
    monkeypatch.setenv("HUB_SECRET_KEY", "hub-key-should-stay-in-the-hub")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-should-stay")
    monkeypatch.setenv("SOME_SERVICE_PASSWORD", "pw-should-stay")
    probe = (f'"{sys.executable}" -c "import os; print(sorted(k for k in os.environ if k.startswith(\'HUB_\') '
             f'or k in (\'ANTHROPIC_API_KEY\', \'SOME_SERVICE_PASSWORD\')))"')
    out = client.post("/api/commands", json={"command": probe}).json()["output"]
    assert out.strip() == "[]", out
    from hub.execution.runner import child_env
    assert child_env({"PORT": "4000"})["PORT"] == "4000" and "HUB_SECRET_KEY" not in child_env()


def test_read_only_commands_cannot_read_or_write_the_hubs_files(client, sign_in):
    hub = client.app.state.hub
    key_file = hub.settings.data_dir / "secret.key"
    for command in (f"git diff --no-index {key_file} /dev/null", f"git log --output={hub.settings.data_dir}/hub.db",
                    "git diff --outp=/tmp/x", "git show --ext-diff HEAD", "git log -p --textconv",
                    "git branch -D main", "git branch -f main HEAD~3", "git tag -d v1", "date -s 2020-01-01",
                    "date --set=2020-01-01", "hostname evil", "hostname -F /etc/hostname",
                    # two paths: git compares the files without --no-index outside a work tree (the caller picks cwd)
                    f"git diff {key_file} /dev/null", "git diff secret.key hub.db", "git diff -- a b",
                    "kubectl get secrets -o yaml", "kubectl get secret/db -n web"):
        assert policy.classify(command)[0] == "change", command
    for command in ("git log --oneline", "git branch -a", "git tag --list", "git status", "date -u", "hostname -f", "ls -la",
                    "git diff", "git diff --stat HEAD~1", "git diff main..feature", "kubectl get pods -n web"):
        assert policy.classify(command)[0] == "read_only", command
    if key_file.exists():
        oscar = sign_in("operator")
        for command, cwd in ((f"git diff --no-index {key_file} /dev/null", None),
                             ("git diff secret.key hub.db", str(hub.settings.data_dir))):
            reply = oscar.post("/api/commands", json={"command": command, "cwd": cwd}).json()
            assert reply["status"] == "pending_approval", reply
            assert key_file.read_text().strip() not in json.dumps(reply)


# -- F2: an API token acts for the account that created it ------------------------------------------------------------


def control(client, control_id: str) -> dict:
    client.post("/api/grc/evaluate")
    return next(c for c in client.get("/api/grc").json()["controls"] if c["id"] == control_id)


def test_leavers_admin_token_stops_working_when_offboarded(client, sign_in, browser):
    hub = client.app.state.hub
    alice = sign_in("admin", "alice", email="alice@corp.example")
    token = alice.post("/api/tokens", json={"name": "alice-scripts", "role": "admin"}).json()["token"]
    bot = browser(headers={"Authorization": f"Bearer {token}"})
    assert bot.get("/api/users").status_code == 200
    person = client.post("/api/people", json={"display_name": "Alice A", "email": "alice@corp.example",
                                              "status": "terminated"}).json()
    assert control(client, "HB-AC-7")["status"] == "fail"
    done = client.post(f"/api/people/{person['id']}/actions/disable_atrium_account").json()
    assert done["disabled"] == ["alice"]
    assert control(client, "HB-AC-7")["status"] == "pass"
    # ... and that is true now: the token that only alice ever saw no longer opens anything
    assert bot.get("/api/users").status_code == 401
    assert bot.post("/api/users", json={"username": "backdoor", "password": PASSWORD, "role": "admin"}).status_code == 401
    alice_id = hub.auth.find_user("alice").id
    assert bot.patch(f"/api/users/{alice_id}", json={"disabled": False}).status_code == 401
    assert hub.auth.find_user("backdoor") is None and hub.auth.find_user("alice").disabled
    assert not [t for t in client.get("/api/tokens").json() if t["name"] == "alice-scripts"]  # revoked with the account
    assert any("revoked 1 API token" in e["text"] for e in activity(client))


def test_demoted_admins_token_is_capped_and_deleted_accounts_token_is_dead(client, sign_in, browser):
    hub = client.app.state.hub
    alice = sign_in("admin", "alice")
    token = alice.post("/api/tokens", json={"name": "alice-ci", "role": "admin"}).json()["token"]
    child = browser(headers={"Authorization": f"Bearer {token}"}).post(
        "/api/tokens", json={"name": "alice-child", "role": "admin"}).json()["token"]  # made with her token
    bot, child_bot = (browser(headers={"Authorization": f"Bearer {t}"}) for t in (token, child))
    alice_id = hub.auth.find_user("alice").id
    assert client.patch(f"/api/users/{alice_id}", json={"role": "viewer"}).json()["role"] == "viewer"
    for b in (bot, child_bot):  # never more than the owner's current role
        assert b.patch(f"/api/users/{alice_id}", json={"role": "admin"}).status_code == 403
        assert b.get("/api/users").status_code == 403
        assert b.get("/api/overview").status_code == 200  # still a viewer
    assert hub.auth.find_user("alice").role == "viewer"
    assert client.patch(f"/api/users/{alice_id}", json={"role": "admin"}).status_code == 200
    assert child_bot.get("/api/users").status_code == 200  # her role is back, so is her token's
    # deleting her account revokes both, and a new account with her name does not bring them back
    assert client.delete(f"/api/users/{alice_id}").status_code == 200
    hub.auth.create_user("alice", PASSWORD, role="admin", actor="test")
    assert bot.get("/api/users").status_code == 401 and child_bot.get("/api/users").status_code == 401


def test_tokens_stored_before_owners_existed_follow_their_creator(client, browser):
    """Tokens from before owner_id: bound to their creator's account at first use, refused without one."""
    hub = client.app.state.hub
    hub.auth.create_user("carol", PASSWORD, role="operator", actor="test")
    tokens = {}
    for name, creator in (("legacy", "carol"), ("orphan", "someone-deleted")):
        from hub.auth.service import TOKEN_PREFIX, sha256
        from hub.models import ApiToken
        value = TOKEN_PREFIX + f"{name}-secret-value-0123456789"
        hub.store.put("tokens", ApiToken(name=name, role="admin", token_hash=sha256(value), prefix="x",
                                         created_by=creator).model_dump(mode="json"))
        tokens[name] = browser(headers={"Authorization": f"Bearer {value}"})
    assert tokens["orphan"].get("/api/overview").status_code == 401
    assert tokens["legacy"].get("/api/users").status_code == 403  # capped at carol's role (operator)
    assert tokens["legacy"].get("/api/overview").status_code == 200
    stored = next(t for t in hub.auth.tokens() if t.name == "legacy")
    assert stored.owner_id == hub.auth.find_user("carol").id


# -- F3: credentials in an import URL never reach viewers, the activity log, assets or the model ----------------------

URL_TOKEN = "glpat-SuperSecretToken123456"


def test_import_refuses_credentials_in_urls(client, sign_in):
    hub = client.app.state.hub
    operator = sign_in("operator")
    for body in ({"source_type": "github", "source": f"https://oauth2:{URL_TOKEN}@gitlab.example.com/team/tool.git"},
                 {"source_type": "github", "source": f"https://{URL_TOKEN}@github.com/team/tool"},
                 {"source_type": "saas", "source": f"https://admin:{URL_TOKEN}@app.example.com"},
                 {"source_type": "saas", "source": f"https://app.example.com/?access_token={URL_TOKEN}"},
                 {"source_type": "saas", "source": "https://app.example.com",
                  "openapi_url": f"https://api.example.com/openapi.json?api_key={URL_TOKEN}"}):
        response = operator.post("/api/tools/import", json=body)
        assert response.status_code == 400 and "must not contain credentials" in response.json()["detail"], body
    assert hub.tools() == []
    assert URL_TOKEN not in json.dumps(activity(client))
    # ordinary addresses still import
    assert operator.post("/api/tools/import", json={"source_type": "saas", "source": "https://app.example.com",
                                                    "openapi_url": "https://api.example.com/openapi.json?v=3"}).status_code == 202


def test_tool_stored_with_credentials_shows_none_to_viewers_or_assets(client, sign_in, wait_for):
    """A tool imported before the check keeps its stored source, but viewers, the event stream, the model and the
    asset register only ever see it without the credential."""
    hub = client.app.state.hub
    queue = hub.bus.subscribe()
    try:
        hub.save_tool(Tool(id="legacy", name="Legacy", source_type="github",
                           source=f"https://oauth2:{URL_TOKEN}@gitlab.example.com/team/legacy.git",
                           openapi_url=f"https://api.example.com/spec.json?token={URL_TOKEN}", status="ready",
                           manifest=Manifest(id="legacy", name="Legacy")))
        events = []
        while not queue.empty():
            events.append(queue.get_nowait())
    finally:
        hub.bus.unsubscribe(queue)
    viewer = sign_in("viewer")
    listed = viewer.get("/api/tools").json()
    assert listed[0]["source"] == "https://gitlab.example.com/team/legacy.git"
    assert URL_TOKEN not in json.dumps(listed) and URL_TOKEN not in viewer.get("/api/tools/legacy").text
    assert URL_TOKEN not in json.dumps(events)
    described = client.portal.call(hub.bus.request, "user:admin", "tool:legacy", "describe") \
        if hub.agents.get("tool:legacy") else {}
    assert URL_TOKEN not in json.dumps(described)
    client.post("/api/assets/sync")
    asset = wait_for(lambda: next((a for a in viewer.get("/api/assets").json() if a.get("source") == "tool:legacy"), None))
    assert asset["facts"]["source"] == "https://gitlab.example.com/team/legacy.git"
    assert URL_TOKEN not in viewer.get("/api/assets").text


# -- F13: the reassign_port patch never copies launch.env values -------------------------------------------------------

DB_PASSWORD = "Zq9-UniqueDbPass-7731"


def native_tool(root: Path, name: str, port: int, env: dict[str, str]) -> Path:
    import yaml
    root.mkdir(parents=True)
    (root / "app.py").write_text("print('hi')\n")
    (root / "hub.manifest.yaml").write_text(yaml.safe_dump({"id": name, "name": name, "kind": "oss",
                                                            "launch": {"command": "python app.py", "port": port, "env": env}}))
    return root


def test_port_clash_patch_shows_viewers_no_launch_env_values(client, sign_in, wait_for, tmp_path):
    hub = client.app.state.hub
    queue = hub.bus.subscribe()
    viewer = sign_in("viewer")
    try:
        for name, env in (("alpha", {"LOG_LEVEL": "info"}),
                          ("beta", {"DATABASE_URL": f"postgres://app:{DB_PASSWORD}@db/app", "API_KEY": DB_PASSWORD})):
            root = native_tool(tmp_path / name, name, 8080, env)
            assert client.post("/api/tools/import", json={"source_type": "local", "source": str(root)}).status_code == 202
        pending = wait_for(lambda: [x for x in viewer.get("/api/approvals?status=pending").json()
                                    if x["kind"] == "patch" and (x.get("patch") or {}).get("strategy") == "reassign_port"])
        events = []
        while not queue.empty():
            events.append(queue.get_nowait())
    finally:
        hub.bus.unsubscribe(queue)
    patch = pending[0]["patch"]
    tool_id = patch["tool_id"]
    for text in (json.dumps(pending), viewer.get(f"/api/patches/{patch['id']}").text, viewer.get(f"/api/tools/{tool_id}").text,
                 json.dumps([e for e in events if e["type"] in ("patch", "approval", "tool")])):
        assert DB_PASSWORD not in text
    # applying it moves the port and keeps the tool's own environment
    assert client.post(f"/api/approvals/{pending[0]['id']}", json={"approve": True}).status_code == 200
    new_port = patch["manifest_update"]["launch"]["port"]
    tool = wait_for(lambda: (t := hub.get_tool(tool_id)) and t.manifest.launch.port == new_port and t)
    env = tool.manifest.launch.env
    assert env["PORT"] == str(new_port)
    if tool_id == "beta":
        assert env["DATABASE_URL"] == f"postgres://app:{DB_PASSWORD}@db/app" and env["API_KEY"] == DB_PASSWORD


# -- F11: a shared login never merges two people who have different emails --------------------------------------------


def test_same_login_different_emails_stay_two_people(client):
    from hub import people
    hub = client.app.state.hub
    people.apply_people(hub, "hr", [{"external_id": "e1", "display_name": "John Smith", "email": "john.smith@corp.example",
                                     "login": "jsmith", "status": "active"}])
    counts = people.apply_people(hub, "vendor", [{"external_id": "v9", "display_name": "Jane Smith",
                                                  "email": "jane.smith@vendor.example", "login": "jsmith",
                                                  "status": "terminated"}])
    assert counts["merged"] == 0 and counts["created"] == 1
    everyone = {p.display_name: p for p in people.all_people(hub)}
    john, jane = everyone["John Smith"], everyone["Jane Smith"]
    assert (john.email, john.status, list(john.sources)) == ("john.smith@corp.example", "active", ["hr"])
    assert (jane.email, jane.status) == ("jane.smith@vendor.example", "terminated")
    # Jane's GitLab account is not linked to John, and John's leaver to-do never names it
    people.apply_accounts(hub, "gitlab", [{"external_id": "g1", "login": "jsmith", "email": "jane.smith@vendor.example",
                                           "active": True}])
    account = people.all_accounts(hub, "gitlab")[0]
    assert account.person_id == jane.id
    leavers = {f["display_name"]: f for f in people.leavers(hub)}
    assert "John Smith" not in leavers and leavers["Jane Smith"]["todo"] == ["Disable or remove jsmith in gitlab"]
    # a login match where one side has no email still links (the documented rule)
    people.apply_accounts(hub, "wiki", [{"external_id": "w1", "login": "jsmith", "email": None, "active": True}])
    assert people.all_accounts(hub, "wiki")[0].person_id == john.id


# -- F17: an SSO email change at the provider neither hides a leaver nor borrows someone else's identity ---------------

def sso_client(tmp_path):
    from fastapi.testclient import TestClient
    from test_oidc import CLIENT_ID, CLIENT_SECRET, ISSUER, FakeIdP

    from conftest import ADMIN_PASSWORD, make_settings
    from hub.app import create_app
    from hub.auth.oidc import OidcClient
    idp = FakeIdP()
    settings = make_settings(tmp_path, oidc_issuer=ISSUER, oidc_client_id=CLIENT_ID, oidc_client_secret=CLIENT_SECRET)
    c = TestClient(create_app(settings), headers={"X-Hub-Request": "1"})
    c.__enter__()
    hub = c.app.state.hub
    hub.auth.oidc = OidcClient(hub.settings, transport=idp.transport)
    hub.auth.create_user("admin", ADMIN_PASSWORD, role="admin", actor="test")
    assert c.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}).status_code == 200
    return c, idp


def test_sso_email_change_does_not_hide_a_leaver_or_impersonate(tmp_path):
    from test_oidc import sso

    from conftest import new_browser
    client, idp = sso_client(tmp_path)
    try:
        hub = client.app.state.hub
        mallory_claims = {"sub": "m-1", "preferred_username": "mallory", "email": "mallory@corp.example", "groups": []}
        assert sso(new_browser(client), idp, claims=mallory_claims).headers["location"] == "/#/"
        mallory = client.post("/api/people", json={"display_name": "Mallory", "email": "mallory@corp.example"}).json()
        ceo = client.post("/api/people", json={"display_name": "The CEO", "email": "ceo@corp.example"}).json()
        # 1. an unverified address from the provider's self-service is not taken
        sso(new_browser(client), idp, claims={**mallory_claims, "email": "ceo@corp.example", "email_verified": False})
        assert hub.auth.find_user("mallory").email == "mallory@corp.example"
        assert client.get(f"/api/people/{ceo['id']}").json()["atrium"] is None
        # 2. a verified change (to a private address) keeps her account linked to her own person, and says so
        sso(new_browser(client), idp, claims={**mallory_claims, "email": "mallory@private.example", "email_verified": True})
        assert hub.auth.find_user("mallory").email == "mallory@private.example"
        assert any("Email of mallory changed" in e["text"] for e in activity(client))
        client.patch(f"/api/people/{mallory['id']}", json={"status": "terminated"})
        leavers = client.get("/api/people/leavers").json()["leavers"]
        assert [u["username"] for f in leavers if f["person_id"] == mallory["id"] for u in f["atrium_accounts"]] == ["mallory"]
        done = client.post(f"/api/people/{mallory['id']}/actions/disable_atrium_account").json()
        assert done["disabled"] == ["mallory"] and hub.auth.find_user("mallory").disabled
    finally:
        client.__exit__(None, None, None)


# -- F27: the leaver action disables only the account the administrator confirmed --------------------------------------


def test_disable_action_never_picks_among_accounts_by_an_editable_email(client, sign_in):
    hub = client.app.state.hub
    hub.auth.create_user("bob-admin", PASSWORD, role="admin", email="bob@corp.example", actor="test")
    hub.auth.create_user("bob-alt", PASSWORD, role="viewer", email="bob@corp.example", actor="test")
    operator = sign_in("operator")
    # an operator points a leaver's person record at another administrator's email
    person = operator.post("/api/people", json={"display_name": "Eve", "email": "eve@corp.example"}).json()
    operator.patch(f"/api/people/{person['id']}", json={"email": "bob@corp.example", "status": "terminated"})
    refused = client.post(f"/api/people/{person['id']}/actions/disable_atrium_account")
    assert refused.status_code == 409 and "bob-admin" in refused.json()["detail"]
    assert not hub.auth.find_user("bob-admin").disabled and not hub.auth.find_user("bob-alt").disabled
    # with the accounts the administrator saw: only those, and only while they are still this person's
    alt = hub.auth.find_user("bob-alt")
    done = client.post(f"/api/people/{person['id']}/actions/disable_atrium_account", json={"user_ids": [alt.id]}).json()
    assert done["disabled"] == ["bob-alt"] and not hub.auth.find_user("bob-admin").disabled
    stranger = hub.auth.find_user("admin")
    wrong = client.post(f"/api/people/{person['id']}/actions/disable_atrium_account", json={"user_ids": [stranger.id]})
    assert wrong.status_code == 409 and not hub.auth.find_user("admin").disabled


# -- F14: the data directory and the database are owner-only ------------------------------------------------------------


def test_data_dir_database_and_secrets_are_not_readable_by_other_accounts(tmp_path):
    import os
    import stat

    import pytest

    from conftest import make_settings
    from hub.core import Hub
    from hub.integration import identity
    if os.name != "posix":
        pytest.skip("POSIX permissions")
    old = os.umask(0o022)  # the usual umask: without the fix everything is world-readable
    try:
        # an install from before: a world-readable data dir and database
        legacy = tmp_path / "legacy" / "data"
        (legacy / "workspace").mkdir(parents=True)
        legacy.chmod(0o755)
        (legacy / "hub.db").touch(mode=0o644)
        for settings in (make_settings(tmp_path / "fresh"), make_settings(tmp_path / "legacy")):
            hub = Hub(settings)
            hub.store.put("probe", {"id": "1", "secret": "x"})  # creates -wal and -shm
            hub.store.append("activity", {"text": "x"})
            identity.secret(settings.workspace, "demo", "keycloak")
            mode = lambda p: stat.S_IMODE(p.stat().st_mode)  # noqa: E731
            assert mode(settings.data_dir) == 0o700 and mode(settings.workspace) == 0o700
            for name in ("hub.db", "hub.db-wal", "hub.db-shm"):
                path = settings.data_dir / name
                assert not path.exists() or mode(path) == 0o600, (name, oct(mode(path)))
            assert mode(settings.db_path) == 0o600
            sso_dir = settings.workspace / "secrets" / "sso"
            assert mode(sso_dir / "demo--keycloak--client-secret") == 0o600
            assert mode(sso_dir) & 0o077 == 0 or mode(settings.workspace) == 0o700
    finally:
        os.umask(old)


# -- F15: anonymous SSO callbacks cannot flood the activity log or plant text in it -------------------------------------


def test_anonymous_sso_callbacks_cannot_flood_or_write_the_activity_log(tmp_path):
    from conftest import new_browser
    client, _ = sso_client(tmp_path)
    try:
        hub = client.app.state.hub
        client.post("/api/users", json={"username": "insider", "password": PASSWORD, "role": "admin"})
        before = hub.store.count("activity")
        anon = new_browser(client)
        lure = "URGENT: Atrium moved, admins sign in at https://atrium-login.example.net/reset"
        for _ in range(300):
            response = anon.get("/api/auth/oidc/callback", params={"error": "x", "error_description": lure},
                                follow_redirects=False)
            assert response.status_code == 302
        added = hub.store.tail("activity", 1000)[-(hub.store.count("activity") - before):]
        assert len(added) <= 21  # 20 per address and a note that further ones are not logged
        assert not any("atrium-login.example.net" in e["text"] for e in added)
        assert added[0]["text"] == "Single sign-on failed: the identity provider refused the sign-in (x)"
        assert "not logged" in added[-1]["text"]
        texts = [e["text"] for e in client.get("/api/activity?limit=2000").json()]
        assert "Created admin account insider" in texts
    finally:
        client.__exit__(None, None, None)


def test_older_activity_stays_reachable_by_paging(client):
    hub = client.app.state.hub
    hub.activity("admin", "info", "the entry to find")
    for i in range(2100):
        hub.store.append("activity", {"actor": "x", "level": "info", "text": f"noise {i}"})
    latest = client.get("/api/activity?limit=2000").json()
    assert "the entry to find" not in [e["text"] for e in latest]
    older = client.get(f"/api/activity?limit=2000&before={latest[0]['seq']}").json()
    assert "the entry to find" in [e["text"] for e in older] and older[-1]["seq"] < latest[0]["seq"]


# -- F16: failed guesses from a shared address cannot lock a known browser out --------------------------------------------


def test_lockout_from_a_shared_proxy_address_spares_known_browsers(client, browser, monkeypatch):
    from conftest import ADMIN_PASSWORD
    owner = browser()  # the administrator's own browser: signed in before
    assert owner.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}).status_code == 200
    owner.post("/api/auth/logout")
    attacker = browser()  # every client reaches the hub from the same proxy address
    for i in range(25):
        attacker.post("/api/auth/login", json={"username": "admin" if i < 5 else f"user{i}", "password": "wrong guess!"})
    assert attacker.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}).status_code == 429
    assert owner.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}).status_code == 200
    # the known browser has its own limit: guessing with it locks it too
    owner.post("/api/auth/logout")
    for _ in range(5):
        assert owner.post("/api/auth/login", json={"username": "admin", "password": "wrong guess!"}).status_code == 401
    assert owner.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}).status_code == 429
    # a forged device cookie is an unknown browser
    forged = browser(cookies={"atrium_device": "not-a-real-device-cookie"})
    assert forged.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}).status_code == 429


def test_trusted_proxies_reach_uvicorn(tmp_path, monkeypatch):
    from hub.__main__ import main
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HUB_TRUSTED_PROXIES", "172.18.0.1, 10.0.0.0/8")
    monkeypatch.setenv("HUB_ADMIN_USERNAME", "root")
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", PASSWORD)
    served = []
    monkeypatch.setattr("uvicorn.run", lambda app, **kwargs: served.append(kwargs))
    assert main(["--port", "8798", "--data-dir", str(tmp_path / "data")]) == 0
    assert served[0]["forwarded_allow_ips"] == "172.18.0.1, 10.0.0.0/8" and served[0]["proxy_headers"] is True


# -- F18 / F28 / F29: who single sign-on lets in ------------------------------------------------------------------------


def test_sso_default_role_none_refuses_people_outside_the_atrium_groups(tmp_path):
    from test_oidc import sso

    from conftest import new_browser
    client, idp = sso_client(tmp_path)
    try:
        hub = client.app.state.hub
        saved = client.put("/api/auth/sso", json={"default_role": "none", "viewer_values": ["atrium-viewers"]})
        assert saved.status_code == 200 and saved.json()["values"]["default_role"] == "none"
        from hub.auth.oidc import OidcClient
        hub.auth.oidc = OidcClient(hub.auth.oidc.settings, transport=idp.transport)
        stranger = new_browser(client)
        refused = sso(stranger, idp, claims={"sub": "g-1", "email": "someone@gmail.com", "groups": []})
        assert refused.headers["location"] == "/#/login"
        assert "not in an Atrium group" in stranger.get("/api/auth/me").json()["sso_error"]
        assert stranger.get("/api/people").status_code == 401 and hub.auth.find_user("someone") is None
        viewer = new_browser(client)
        sso(viewer, idp, claims={"sub": "v-1", "preferred_username": "vic", "groups": ["atrium-viewers"]})
        assert viewer.get("/api/auth/me").json()["user"]["role"] == "viewer"
        # removed from the group at the provider: the next sign-in is refused and the old sessions end
        sso(new_browser(client), idp, claims={"sub": "v-1", "preferred_username": "vic", "groups": []})
        assert viewer.get("/api/auth/me").json()["authenticated"] is False
    finally:
        client.__exit__(None, None, None)


def test_sso_allowed_domains_and_new_settings_default(tmp_path, monkeypatch):
    from hub.auth import sso_settings
    from hub.config import Settings
    assert sso_settings.clean({"issuer": "https://accounts.google.com"}, {}, set())["default_role"] == "none"
    # saved settings keep the default role they have
    assert sso_settings.clean({"scopes": "openid"}, {"preset": "google", "default_role": "viewer"}, set())["default_role"] == "viewer"
    monkeypatch.setenv("HUB_OIDC_DEFAULT_ROLE", "none")
    monkeypatch.setenv("HUB_OIDC_ALLOWED_DOMAINS", "Corp.example")
    settings = Settings.from_env()
    assert settings.oidc_default_role == "none" and settings.oidc_allowed_domains == ["corp.example"]
    import pytest

    from hub.auth.oidc import OidcClient, OidcError
    oidc = OidcClient(settings)
    oidc._check_domain({"hd": "corp.example", "email": "a@corp.example"})
    oidc._check_domain({"email": "a@corp.example", "email_verified": True})
    for claims in ({"email": "a@gmail.com", "email_verified": True}, {"email": "a@corp.example"},
                   {"email": "a@corp.example", "email_verified": False}, {"hd": "evil.example"}):
        with pytest.raises(OidcError):
            oidc._check_domain(claims)


def test_sso_before_setup_cannot_take_the_hub(tmp_path):
    from fastapi.testclient import TestClient
    from test_oidc import CLIENT_ID, CLIENT_SECRET, ISSUER, FakeIdP, sso

    from conftest import make_settings
    from hub.app import create_app
    from hub.auth.oidc import OidcClient
    idp = FakeIdP()
    settings = make_settings(tmp_path, oidc_issuer=ISSUER, oidc_client_id=CLIENT_ID, oidc_client_secret=CLIENT_SECRET,
                             setup_token="first-run-token")
    with TestClient(create_app(settings), headers={"X-Hub-Request": "1"}) as c:
        hub = c.app.state.hub
        hub.auth.oidc = OidcClient(hub.settings, transport=idp.transport)
        assert hub.auth.setup_required
        refused = sso(c, idp, claims={"groups": []})
        assert refused.headers["location"] == "/#/login" and "not set up yet" in c.get("/api/auth/me").json()["sso_error"]
        assert hub.auth.users() == [] and hub.auth.setup_required
        done = c.post("/api/auth/setup", json={"token": "first-run-token", "username": "root", "password": PASSWORD})
        assert done.status_code == 200 and hub.auth.find_user("root").role == "admin"


def test_sso_role_sync_never_demotes_the_last_admin(tmp_path):
    from test_oidc import sso

    from conftest import new_browser
    client, idp = sso_client(tmp_path)
    try:
        hub = client.app.state.hub
        boss = new_browser(client)
        sso(boss, idp, claims={"sub": "b-1", "preferred_username": "boss", "groups": ["atrium-admins"]})
        boss_id = hub.auth.find_user("boss").id
        local = hub.auth.find_user("admin")
        assert boss.delete(f"/api/users/{local.id}").status_code == 200  # the SSO admin removes the local one
        sso(new_browser(client), idp, claims={"sub": "b-1", "preferred_username": "boss", "groups": ["atrium-operators"]})
        assert hub.auth.get_user(boss_id).role == "admin"
        assert [u.username for u in hub.auth.users() if u.role == "admin" and not u.disabled] == ["boss"]
        assert any("last enabled administrator" in e["text"] for e in activity(client))
    finally:
        client.__exit__(None, None, None)


# -- F30: anonymous sign-in starts cannot push a person's sign-in out ----------------------------------------------------


def test_a_flood_of_sso_starts_does_not_expire_a_sign_in_in_progress(tmp_path, monkeypatch):
    from test_oidc import callback, start

    from conftest import new_browser
    from hub.auth import oidc as oidc_module
    monkeypatch.setattr(oidc_module, "MAX_PENDING", 50)
    client, idp = sso_client(tmp_path)
    try:
        victim = new_browser(client)
        url, state = start(victim)  # the victim is at the provider, typing a password
        attacker = new_browser(client)
        for _ in range(200):
            attacker.get("/api/auth/oidc/login", follow_redirects=False)
        done = callback(victim, idp.authorize(url, claims={"sub": "v-9", "preferred_username": "vera"}), state)
        assert done.headers["location"] == "/#/" and victim.get("/api/auth/me").json()["authenticated"]
    finally:
        client.__exit__(None, None, None)


# -- F31: an integration token publishes events as its own tool only -----------------------------------------------------


def test_integration_token_cannot_publish_as_another_tool(client, browser):
    hub = client.app.state.hub
    secret = client.post("/api/tokens", json={"name": "grafana-events", "role": "integration", "tool_id": "grafana"}).json()["token"]
    bot = browser(headers={"Authorization": f"Bearer {secret}"})
    forged = bot.post("/api/bus/publish", json={"source": "keycloak", "event": "user.deleted", "payload": {"user": "ceo"}})
    assert forged.status_code == 403
    assert not [e for e in hub.store.tail("toolbus", 50) if e["source"] == "keycloak"]
    assert bot.post("/api/bus/publish", json={"source": "grafana", "event": "alert.fired", "payload": {}}).status_code == 200
    assert hub.store.tail("toolbus", 1)[0]["by"] == "token:grafana-events"
    assert client.get("/api/integration").json()["deliveries"][-1]["by"] == "token:grafana-events"
    # a token from before the binding is bound to the first source it publishes as
    from hub.auth.service import TOKEN_PREFIX, sha256
    from hub.models import ApiToken
    value = TOKEN_PREFIX + "legacy-integration-0123456789"
    hub.store.put("tokens", ApiToken(name="old-adapter", role="integration", token_hash=sha256(value), prefix="x",
                                     created_by="admin").model_dump(mode="json"))
    old = browser(headers={"Authorization": f"Bearer {value}"})
    assert old.post("/api/bus/publish", json={"source": "wiki", "event": "page.saved", "payload": {}}).status_code == 200
    assert old.post("/api/bus/publish", json={"source": "keycloak", "event": "user.deleted", "payload": {}}).status_code == 403
    # only integration tokens carry a tool
    assert client.post("/api/tokens", json={"name": "ops", "role": "operator", "tool_id": "x"}).status_code == 400
