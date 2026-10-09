"""People: identities merged from several directories, accounts, person <-> asset links (incl. Snipe-IT pulls), the
person API, the leavers control HB-AC-7 and its one-click actions - with fake directory connectors (no network)."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from hub import connectors, people
from hub.connectors.base import Connector, ConnectorField, check
from hub.grc.checks import Snapshot, check_leavers
from hub.models import Account, Asset, Manifest, Person, Tool, User

TOKEN = "directory-secret-token-5a4b3c2d"


class Directory:
    def __init__(self):
        self.people: dict[str, list[dict[str, Any]]] = {"fake_dir": [], "fake_hr": []}
        self.accounts: list[dict[str, Any]] = []


class FakeDirectory(Connector):
    kind, title = "fake_dir", "Fake Directory"
    data: Directory
    fields = [ConnectorField(name="base_url", label="URL", kind="url", required=True),
              ConnectorField(name="token", label="Token", kind="secret", required=True)]
    capabilities = {"people": {"read"}}

    async def test(self):
        return {"ok": True, "detail": "ok", "checks": [check("api", True)], "domains": self.domains()}

    async def pull(self, domain, since=None):
        assert self.secrets["token"] == TOKEN
        return list(self.data.people[self.kind]) if domain == "people" else list(self.data.accounts)


class FakeHr(FakeDirectory):
    kind, title = "fake_hr", "Fake HR"


class FakeApp(FakeDirectory):
    kind, title = "fake_app", "Fake App"
    capabilities = {"accounts": {"read"}}


@pytest.fixture
def directory(client, monkeypatch) -> Directory:
    state = Directory()
    for cls in (FakeDirectory, FakeHr, FakeApp):
        monkeypatch.setattr(cls, "data", state, raising=False)
        monkeypatch.setitem(connectors.REGISTRY, cls.kind, cls)
    return state


def add_tool(client, tool_id: str, name: str) -> None:
    hub = client.app.state.hub
    tool = Tool(id=tool_id, name=name, source_type="saas", source=f"https://{tool_id}.example.com", status="ready",
                manifest=Manifest(id=tool_id, name=name, kind="saas"))
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)


def connect_and_plan(client, wait_for, tool_id: str, kind: str, config: dict | None = None,
                     secrets: dict | None = None) -> list[dict]:
    """Connect a tool, test it (which plans its flows), approve the proposals; returns its enabled flows."""
    response = client.put(f"/api/tools/{tool_id}/connection", json={
        "kind": kind, "config": config or {"base_url": f"https://{tool_id}.example.com"},
        "secrets": secrets or {"token": TOKEN}})
    assert response.status_code == 200, response.text
    assert client.post(f"/api/tools/{tool_id}/connection/test").json()["ok"]
    pending = wait_for(lambda: [a for a in client.get("/api/approvals?status=pending").json()
                                if a["kind"] == "flow" and a["payload"]["tool_id"] == tool_id])
    for approval in pending:
        assert client.post(f"/api/approvals/{approval['id']}", json={"approve": True}).status_code == 200
    return wait_for(lambda: (found := client.get(f"/api/flows?tool_id={tool_id}").json())
                    and all(f["status"] == "enabled" for f in found) and found)


def run(client, flow_id: str) -> dict:
    result = client.post(f"/api/flows/{flow_id}/run").json()
    assert result["ok"], result
    return result


def control(client, control_id: str) -> dict:
    client.post("/api/grc/evaluate")
    return next(c for c in client.get("/api/grc").json()["controls"] if c["id"] == control_id)


def by_email(client) -> dict[str, dict]:
    return {p["email"]: p for p in client.get("/api/people").json()["people"]}


# -- merging -------------------------------------------------------------------------------------


def test_identities_merge_by_email_then_login_and_the_most_left_status_wins(client, directory, wait_for):
    directory.people["fake_dir"] = [
        {"external_id": "d1", "display_name": "Alice Doe", "email": "Alice@Acme.com", "login": "alice", "title": "Engineer",
         "groups": ["eng"], "manager_external_id": "d3"},
        {"external_id": "d2", "display_name": "Bob", "email": None, "login": "bob", "status": "active"},
        {"external_id": "d3", "display_name": "Carol Boss", "email": "carol@acme.com", "login": "carol"},
    ]
    directory.people["fake_hr"] = [
        {"external_id": "h1", "display_name": "Alice D.", "email": "alice@acme.com", "department": "R&D",
         "groups": ["staff"], "status": "terminated"},
        {"external_id": "h2", "display_name": "Robert", "email": "bob@acme.com", "login": "BOB", "phone": "+32 1"},
    ]
    add_tool(client, "okta", "Okta")
    add_tool(client, "hr", "HR")
    [dir_flow] = connect_and_plan(client, wait_for, "okta", "fake_dir")
    assert (dir_flow["domain"], dir_flow["direction"], dir_flow["owner"]) == ("people", "pull", "module:people")
    assert run(client, dir_flow["id"])["counts"]["created"] == 3
    [hr_flow] = connect_and_plan(client, wait_for, "hr", "fake_hr")
    counts = run(client, hr_flow["id"])["counts"]
    assert (counts["created"], counts["merged"]) == (0, 2)

    listing = client.get("/api/people").json()
    assert listing["total"] == 3 and listing["statuses"] == {"active": 2, "suspended": 0, "terminated": 1}
    people_ = {p["display_name"]: p for p in listing["people"]}
    alice = people_["Alice D."]  # the last source's name; empty fields never erase another source's
    assert alice["sources"] == {"okta": "d1", "hr": "h1"} and alice["status"] == "terminated" and alice["terminated_at"]
    assert alice["source_status"] == {"okta": "active", "hr": "terminated"}
    assert (alice["title"], alice["department"], alice["groups"]) == ("Engineer", "R&D", ["eng", "staff"])
    assert alice["manager"]["display_name"] == "Carol Boss" and alice["initials"] == "AD"
    bob = people_["Robert"]  # matched by login (no email in the first directory)
    assert bob["sources"] == {"okta": "d2", "hr": "h2"} and bob["email"] == "bob@acme.com" and bob["phone"] == "+32 1"

    detail = client.get(f"/api/people/{people_['Carol Boss']['id']}").json()
    assert [r["display_name"] for r in detail["reports"]] == ["Alice D."]
    # filters
    assert [p["display_name"] for p in client.get("/api/people?status=terminated").json()["people"]] == ["Alice D."]
    assert [p["display_name"] for p in client.get("/api/people?q=r%26d").json()["people"]] == ["Alice D."]
    assert len(client.get("/api/people?source=hr").json()["people"]) == 2

    # someone who disappears from a directory has left it
    directory.people["fake_dir"] = directory.people["fake_dir"][:2]
    assert run(client, dir_flow["id"])["counts"]["left"] == 1
    carol = client.get(f"/api/people/{people_['Carol Boss']['id']}").json()
    assert carol["status"] == "terminated" and carol["source_status"] == {"okta": "terminated"}
    # directory entries are accounts too: carol's is gone, alice's is inactive in HR
    accounts = {a["id"]: a for a in client.get("/api/accounts").json()}
    assert "okta|d3" not in accounts and accounts["hr|h1"]["active"] is False and accounts["okta|d1"]["active"]
    assert accounts["okta|d1"]["person"]["id"] == alice["id"]
    # the token never shows
    assert TOKEN not in json.dumps([client.get("/api/people").json(), client.get("/api/activity?limit=500").json(),
                                    client.get("/api/accounts").json(), client.get("/api/flows").json()])


def test_merge_rules_on_their_own(client):
    hub = client.app.state.hub
    counts = people.apply_people(hub, "dir", [
        {"external_id": "1", "display_name": "Ann", "email": "ann@x.com", "login": "ann", "status": "active"},
        {"external_id": "2", "display_name": "Ann Two", "email": "ann@x.com", "login": "ann2", "status": "suspended"},
    ])
    assert counts["created"] == 2  # two entries of one directory with the same email stay two people
    first = next(p for p in people.all_people(hub) if p.sources.get("dir") == "1")
    first.manual_status = "active"
    people.save(hub, people.recompute(first))
    people.apply_people(hub, "dir", [{"external_id": "1", "display_name": "Ann", "email": "ann@x.com", "status": "suspended"},
                                     {"external_id": "2", "display_name": "Ann Two", "email": "ann@x.com"}])
    assert people.get(hub, first.id).status == "suspended"  # a hand-set "active" does not hide a leaver
    people.forget_tool(hub, "dir")  # the tool leaves the hub: what it said about leavers is kept
    kept = people.get(hub, first.id)
    assert kept.sources == {} and kept.status == "suspended" and kept.manual_status == "suspended"


# -- accounts, assets and leavers -----------------------------------------------------------------


def test_leavers_fail_the_control_until_access_and_assets_are_cleaned_up(client, directory, wait_for, sign_in):
    hub = client.app.state.hub
    hub.auth.create_user("dana", "plenty of entropy 42", role="operator", email="dana@acme.com", actor="test")
    directory.people["fake_dir"] = [
        {"external_id": "1", "display_name": "Dana Left", "email": "dana@acme.com", "status": "active"},
        {"external_id": "2", "display_name": "Eve Stays", "email": "eve@acme.com"},
    ]
    directory.accounts = [{"external_id": "a1", "login": "DANA@acme.com", "active": True, "last_login": "2026-09-01"},
                          {"external_id": "a2", "login": "eve", "email": "eve@acme.com", "active": True},
                          {"external_id": "a3", "login": "service-bot", "active": True}]
    add_tool(client, "dir", "Directory")
    add_tool(client, "app", "Wiki")
    [people_flow] = connect_and_plan(client, wait_for, "dir", "fake_dir")
    run(client, people_flow["id"])
    [accounts_flow] = connect_and_plan(client, wait_for, "app", "fake_app")
    assert accounts_flow["domain"] == "accounts"
    assert run(client, accounts_flow["id"])["counts"]["linked"] == 2
    dana = by_email(client)["dana@acme.com"]
    laptop = client.post("/api/assets", json={"name": "Laptop D", "type": "workstation",
                                              "assigned_person_id": dana["id"]}).json()
    assert laptop["assigned_person_id"] == dana["id"] and laptop["assigned_source"] == "manual"
    assert control(client, "HB-AC-7")["status"] == "pass"
    assert client.get("/api/users").json()[-1]["person"]["id"] == dana["id"]  # Atrium users link by email

    directory.people["fake_dir"][0]["status"] = "terminated"
    run(client, people_flow["id"])
    state = control(client, "HB-AC-7")
    assert state["status"] == "fail" and "Dana Left (terminated) still has 1 asset(s), Atrium account dana, 1 active tool" in state["detail"]
    [finding] = client.get("/api/people/leavers").json()["leavers"]
    assert finding["severity"] == "fail" and [a["id"] for a in finding["actions"]] == ["unassign_assets", "disable_atrium_account"]
    assert finding["accounts"] == [{"id": "app|a1", "tool_id": "app", "tool": "Wiki", "login": "DANA@acme.com", "app": None}]
    assert finding["todo"] == ["Disable or remove DANA@acme.com in Wiki"]
    assert any(e["text"].startswith("Leaver: Dana Left") for e in client.get("/api/activity?limit=300").json())
    risks = [r for r in client.get("/api/grc/risks").json() if r["source"] == "auto:HB-AC-7"]
    assert risks and risks[0]["title"] == "Former staff keep access or company devices" and risks[0]["status"] == "open"

    viewer, operator = sign_in("viewer"), sign_in("operator")
    assert viewer.post(f"/api/people/{dana['id']}/actions/unassign_assets").status_code == 403
    assert operator.post(f"/api/people/{dana['id']}/actions/disable_atrium_account").status_code == 403
    done = operator.post(f"/api/people/{dana['id']}/actions/unassign_assets").json()
    assert done["changed"] == [laptop["id"]] and done["person"]["assets"] == []
    disabled = client.post(f"/api/people/{dana['id']}/actions/disable_atrium_account").json()
    assert disabled["disabled"] == ["dana"] and hub.auth.find_user("dana").disabled
    assert client.post(f"/api/people/{dana['id']}/actions/explode").status_code == 404

    directory.accounts = directory.accounts[1:]  # removed in the wiki
    assert run(client, accounts_flow["id"])["counts"]["removed"] == 1
    assert control(client, "HB-AC-7")["status"] == "pass" and client.get("/api/people/leavers").json()["leavers"] == []


def test_leaver_check_is_partial_with_only_assets_and_na_without_people():
    gone = Person(display_name="Gone", email="g@x.com", status="suspended")
    asset = Asset(id="a1", name="Phone", assigned_person_id=gone.id)
    snap = dict(tools=[], hosts=[], assets=[asset], risks=[], policies=[], patches=[], autonomy="assisted", audit_entries=0)
    assert check_leavers(Snapshot(**snap))[0] == "na"
    assert check_leavers(Snapshot(**snap, people=[gone]))[0] == "partial"
    user = User(username="gone", email="G@x.com")
    assert check_leavers(Snapshot(**{**snap, "users": [user]}, people=[gone]))[0] == "fail"
    account = Account(id="t|1", tool_id="t", external_id="1", person_id=gone.id, active=False)
    retired = asset.model_copy(update={"status": "retired"})
    assert check_leavers(Snapshot(**{**snap, "assets": [retired]}, people=[gone], accounts=[account]))[0] == "pass"


SNIPE_TOKEN = "snipe-token-for-people-0123"


def snipe(rows: list[dict[str, Any]], users: list[dict[str, Any]]):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == f"Bearer {SNIPE_TOKEN}"
        path = request.url.path.removeprefix("/api/v1")
        if path == "/version":
            return httpx.Response(200, json={"version": "v8.3.1"})
        if path == "/users/me":
            return httpx.Response(200, json={"username": "sync"})
        if path in ("/hardware", "/users"):
            items = rows if path == "/hardware" else users
            offset, limit = int(request.url.params.get("offset", 0)), int(request.url.params.get("limit", 50))
            return httpx.Response(200, json={"total": len(items), "rows": items[offset:offset + limit]})
        return httpx.Response(404, json={"status": "error", "messages": "404 endpoint not found"})
    return handler


def hardware(id_: int, user: dict | None) -> dict[str, Any]:
    return {"id": id_, "name": f"laptop-{id_}", "asset_tag": f"T{id_}", "serial": f"S{id_}",
            "category": {"id": 1, "name": "Laptops"}, "status_label": {"status_type": "deployable"},
            "assigned_to": {"id": user["id"], "type": "user", "name": user["name"], "username": user["username"],
                            "email": user["email"]} if user else None, "custom_fields": {}}


def test_snipe_it_pulls_link_devices_to_their_users(client, wait_for):
    hub = client.app.state.hub
    frank = client.post("/api/people", json={"display_name": "Frank", "email": "frank@acme.com", "login": "frank"}).json()
    gina = client.post("/api/people", json={"display_name": "Gina", "login": "gina"}).json()
    users = [{"id": 7, "name": "Frank F", "username": "frank", "email": "FRANK@acme.com", "activated": True,
              "last_login": {"datetime": "2026-09-01 10:00:00"}},
             {"id": 8, "name": "Gina G", "username": "gina", "email": "", "activated": False}]
    rows = [hardware(1, users[0]), hardware(2, users[1]), hardware(3, None)]
    hub.connector_transport = httpx.MockTransport(snipe(rows, users))
    add_tool(client, "snipe", "Snipe-IT")
    found = connect_and_plan(client, wait_for, "snipe", "snipeit",
                             config={"base_url": "https://snipe.example.com", "read_accounts": True},
                             secrets={"token": SNIPE_TOKEN})
    flows_ = {f["domain"]: f for f in found}
    assert set(flows_) == {"assets", "accounts"} and flows_["accounts"]["owner"] == "module:people"
    counts = run(client, flows_["assets"]["id"])["counts"]
    assert counts["created"] == 3 and counts["people_linked"] == 2
    assets = {a["name"]: a for a in client.get("/api/assets").json() if a["source"] == "sync:snipe"}
    assert assets["laptop-1"]["assigned_person_id"] == frank["id"]  # by email
    assert assets["laptop-2"]["assigned_person_id"] == gina["id"]  # by login
    assert assets["laptop-3"]["assigned_person_id"] is None
    assert assets["laptop-1"]["facts"]["assigned_email"] == "FRANK@acme.com"
    assert run(client, flows_["accounts"]["id"])["counts"]["linked"] == 2
    accounts = {a["login"]: a for a in client.get("/api/accounts?tool_id=snipe").json()}
    assert accounts["frank"]["person"]["id"] == frank["id"] and accounts["gina"]["active"] is False

    # a person's choice sticks; "auto" links it from the inventory again
    patched = client.patch(f"/api/assets/{assets['laptop-1']['id']}", json={"assigned_person_id": gina["id"]}).json()
    assert patched["assigned_person_id"] == gina["id"] and patched["assigned_source"] == "manual"
    rows[0]["name"] = "laptop-1b"
    run(client, flows_["assets"]["id"])
    assert client.get(f"/api/people/{gina['id']}").json()["assets_assigned"] == 2
    back = client.patch(f"/api/assets/{assets['laptop-1']['id']}", json={"assigned_source": "auto"}).json()
    assert back["assigned_person_id"] == frank["id"]
    # the device is checked in at Snipe-IT: the link goes, and so do the stale assignment facts
    rows[0]["assigned_to"] = None
    run(client, flows_["assets"]["id"])
    laptop = next(a for a in client.get("/api/assets").json() if a["id"] == assets["laptop-1"]["id"])
    assert laptop["assigned_person_id"] is None and "assigned_email" not in laptop["facts"]
    assert client.patch(f"/api/assets/{laptop['id']}", json={"owner_person_id": "p_missing"}).status_code == 400
    owned = client.patch(f"/api/assets/{laptop['id']}", json={"owner_person_id": frank["id"]}).json()
    assert owned["owner"] == "Frank"  # the free-text owner follows the person picked


# -- the person API ---------------------------------------------------------------------------------


def test_person_api_crud_links_and_roles(client, sign_in):
    viewer, operator = sign_in("viewer"), sign_in("operator")
    assert viewer.post("/api/people", json={"display_name": "X"}).status_code == 403
    boss = operator.post("/api/people", json={"display_name": "Hana Boss", "email": "hana@acme.com",
                                             "department": "Ops", "groups": ["leads"]}).json()
    assert boss["sources"] == {"manual": boss["id"]} and boss["groups"] == ["leads"] and boss["status"] == "active"
    ivan = operator.post("/api/people", json={"display_name": "Ivan", "email": "ivan@acme.com", "manager_id": boss["id"]}).json()
    assert ivan["manager"]["id"] == boss["id"]
    assert operator.post("/api/people", json={"display_name": "Dup", "email": "HANA@acme.com"}).status_code == 409
    assert operator.post("/api/people", json={"display_name": "Bad", "email": "not-an-email"}).status_code in (400, 422)
    loop = operator.patch(f"/api/people/{boss['id']}", json={"manager_id": ivan["id"]})
    assert loop.status_code == 400 and "reports to" in loop.json()["detail"]
    assert operator.patch(f"/api/people/{boss['id']}", json={"manager_id": boss["id"]}).status_code == 400

    risk = operator.post("/api/grc/risks", json={"title": "Key person", "owner_person_id": boss["id"]}).json()
    assert risk["owner"] == "Hana Boss" and risk["owner_person_id"] == boss["id"]
    policy = operator.post("/api/grc/policies", json={"title": "Access", "category": "access"}).json()
    assert operator.patch(f"/api/grc/policies/{policy['id']}", json={"owner_person_id": "nope"}).status_code == 400
    operator.patch(f"/api/grc/policies/{policy['id']}", json={"owner_person_id": boss["id"]})
    asset = operator.post("/api/assets", json={"name": "Server", "owner_person_id": boss["id"]}).json()
    assert asset["owner"] == "Hana Boss"

    detail = viewer.get(f"/api/people/{boss['id']}").json()
    assert [r["title"] for r in detail["risks"]] == ["Key person"] and [p["title"] for p in detail["policies"]] == ["Access"]
    assert detail["assets"][0]["relation"] == "owner" and detail["reports"][0]["id"] == ivan["id"]
    kinds = {n["kind"] for n in detail["graph"]["nodes"]}
    assert {"asset", "group"} <= kinds and detail["graph"]["center"]["initials"] == "HB"
    assert any(e["data"].get("person_id") == boss["id"] for e in detail["activity"])

    suspended = operator.patch(f"/api/people/{ivan['id']}", json={"status": "suspended", "title": "Analyst"}).json()
    assert suspended["status"] == "suspended" and suspended["manual_status"] == "suspended"
    assert operator.patch(f"/api/people/{ivan['id']}", json={"status": None}).json()["status"] == "active"

    assert viewer.delete(f"/api/people/{boss['id']}").status_code == 403
    assert operator.delete(f"/api/people/{boss['id']}").json() == {"ok": True}
    assert operator.get(f"/api/people/{boss['id']}").status_code == 404
    assert operator.get(f"/api/people/{ivan['id']}").json()["manager"] is None
    assert next(r for r in operator.get("/api/grc/risks").json() if r["id"] == risk["id"])["owner_person_id"] is None
    assert next(a for a in operator.get("/api/assets").json() if a["id"] == asset["id"])["owner_person_id"] is None


def test_accounts_can_be_linked_by_hand(client):
    hub = client.app.state.hub
    joe = client.post("/api/people", json={"display_name": "Joe", "email": "joe@acme.com"}).json()
    people.apply_accounts(hub, "wiki", [{"external_id": "9", "login": "jj", "active": True}])
    assert client.get("/api/accounts?unlinked=true").json()[0]["id"] == "wiki|9"
    linked = client.patch("/api/accounts/wiki|9", json={"person_id": joe["id"]}).json()
    assert linked["person_id"] == joe["id"] and linked["person_source"] == "manual"
    people.apply_accounts(hub, "wiki", [{"external_id": "9", "login": "jj", "active": True}])  # a pull keeps the link
    assert client.get(f"/api/accounts?person_id={joe['id']}").json()[0]["id"] == "wiki|9"
    assert client.patch("/api/accounts/wiki|9", json={"auto": True}).json()["person_id"] is None
    assert client.patch("/api/accounts/wiki|404", json={"auto": True}).status_code == 404


def test_people_supervisor_is_a_module_team_lead(client):
    agents = {a["id"]: a for a in client.get("/api/agents").json()}
    assert agents["module:people"]["name"] == "People Supervisor" and agents["module:people"]["team"] == "module:people"
    teams = {t["team"]: t for t in client.get("/api/agents/teams").json()["teams"]}
    assert teams["module:people"]["name"] == "People" and teams["module:people"]["lead"]["id"] == "module:people"
    member = client.post("/api/agents", json={"name": "Leaver watch", "team": "module:people",
                                              "permissions": ["read", "commands"]}).json()
    assert member["effective_permissions"] == ["read"] and member["clamped"] == ["commands"]
    reply = client.post(f"/api/agents/{member['id']}/run", json={"task": "summary"}).json()
    assert reply["ok"] and "People:" in reply["reply"]
