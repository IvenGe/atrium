"""People: the workforce directory merged from every connected directory, the accounts people hold in tools, and the
links from people to assets, risks, policies and Atrium accounts.

- A person is matched to a pulled directory record by the record's id in that tool, else by email, else by login
  (case-insensitive). Fields a record carries overwrite the person's; empty ones never erase what another source said.
- A person's status is the most "left" of their source statuses (and of a status set by hand): terminated beats
  suspended beats active. A person who disappears from a directory has left it ("terminated" there).
- Accounts (collection "accounts", id "<tool id>|<external id>") come from accounts flows and, for directories, from
  the people flow itself (origin "people"). They link to a person by email, then login, unless someone linked one by
  hand.
- Assets link to people through owner_person_id (set by people) and assigned_person_id (set by people, or linked
  automatically from the inventory's assigned user - facts assigned_email / assigned_username - while
  assigned_source is "auto"). Atrium users link to the person with the same email.
- Leavers (control HB-AC-7): suspended or terminated people who still own or use active assets, have an enabled Atrium
  account or an active account in a tool.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import TYPE_CHECKING, Any

from .models import (OPEN_STATES, PERSON_STATUS_RANK, SEVERITY_ORDER, Account, Asset, Person, Policy, Risk, User,
                     Vulnerability)

if TYPE_CHECKING:
    from .auth.service import Principal
    from .core import Hub

COLLECTION = "people"
ACCOUNTS = "accounts"
LEFT = ("suspended", "terminated")
PROFILE_FIELDS = ("display_name", "email", "login", "title", "department", "location", "phone")
LIMITS = {"display_name": 200, "email": 254, "login": 254, "title": 200, "department": 200, "location": 200, "phone": 64}
ASSIGNMENT_FACTS = ("assigned_type", "assigned_name", "assigned_username", "assigned_email", "assigned_employee_number")
ACTIONS = {
    "unassign_assets": {"title": "Unassign assets", "role": "operator",
                        "description": "Take the person off the assets they own or use (the hub's links; return the "
                                       "devices and update the inventory tool too)."},
    "disable_atrium_account": {"title": "Disable Atrium account", "role": "admin",
                               "description": "Disable the person's Atrium account and end its sessions."},
}


def key(value: str | None) -> str:
    return (value or "").strip().lower()


def initials(name: str) -> str:
    parts = [p for p in re.split(r"[\s._@-]+", name or "") if p]
    return ("".join(p[0] for p in parts[:2]) or "?").upper()


# --------------------------------------------------------------------------------------
# storage
# --------------------------------------------------------------------------------------


def all_people(hub: "Hub") -> list[Person]:
    return hub.all(COLLECTION, Person)


def get(hub: "Hub", person_id: str) -> Person | None:
    return hub.one(COLLECTION, person_id, Person)


def save(hub: "Hub", person: Person) -> Person:
    person.updated_at = time.time()
    return hub.save(COLLECTION, person, "person")


def all_accounts(hub: "Hub", tool_id: str | None = None) -> list[Account]:
    items = hub.all(ACCOUNTS, Account)
    return [a for a in items if a.tool_id == tool_id] if tool_id else items


def save_account(hub: "Hub", account: Account) -> Account:
    account.updated_at = time.time()
    return hub.save(ACCOUNTS, account, "account")


def account_id(tool_id: str, external_id: str) -> str:
    return f"{tool_id}|{external_id}"


def recompute(person: Person) -> Person:
    """Status from the sources and the hand-set status; terminated_at follows it."""
    states = [*person.source_status.values(), *([person.manual_status] if person.manual_status else [])]
    status = max(states, key=lambda s: PERSON_STATUS_RANK[s]) if states else "active"
    if status == "terminated" and person.status != "terminated":
        person.terminated_at = person.terminated_at or time.time()
    elif status != "terminated":
        person.terminated_at = None
    person.status = status  # type: ignore[assignment]
    person.groups = sorted({g for groups in person.source_groups.values() for g in groups}, key=str.lower)
    return person


@dataclass
class Index:
    """email / login -> person id (first registered wins), and each person's email."""

    emails: dict[str, str]
    logins: dict[str, str]
    person_emails: dict[str, str] = dataclass_field(default_factory=dict)

    @classmethod
    def of(cls, people: list[Person]) -> "Index":
        index = cls({}, {})
        for p in sorted(people, key=lambda x: x.created_at):
            index.add(p)
        return index

    def match(self, email: str | None, login: str | None) -> str | None:
        """By email, then by login (a login that is an email address also matches an email) - but never by login when
        both sides have an email and they differ: two people who share a short login (jsmith, admin) in different
        tools are different people (review F11)."""
        if email and key(email) in self.emails:
            return self.emails[key(email)]
        if login:
            found = self.logins.get(key(login)) or self.emails.get(key(login))
            theirs = self.person_emails.get(found or "")
            if found and email and theirs and theirs != key(email):
                return None
            return found
        return None

    def add(self, person: Person) -> None:
        if person.email:
            self.emails.setdefault(key(person.email), person.id)
            self.person_emails[person.id] = key(person.email)
        if person.login:
            self.logins.setdefault(key(person.login), person.id)


# --------------------------------------------------------------------------------------
# pulls: people and accounts
# --------------------------------------------------------------------------------------


def _changed(before: dict[str, Any], person: Person) -> bool:
    return before != person.model_dump(mode="json", exclude={"updated_at"})


def apply_people(hub: "Hub", tool_id: str, records: list[dict[str, Any]], retire_missing: bool = True) -> dict[str, int]:
    """Merge one directory's people (canonical "people" records) into the People app."""
    people = {p.id: p for p in all_people(hub)}
    by_source = {p.sources[tool_id]: p.id for p in people.values() if tool_id in p.sources}
    index = Index.of(list(people.values()))
    external_ids = {str(r["external_id"]) for r in records}
    counts = {"total": len(records), "created": 0, "updated": 0, "merged": 0, "unchanged": 0, "left": 0}
    seen: dict[str, str] = {}  # external id -> person id
    managers: dict[str, str] = {}
    dirty: set[str] = set()
    for record in records:
        external = str(record["external_id"])
        person = people.get(by_source.get(external, ""))
        how = "updated"
        if person is None:
            match = people.get(index.match(record.get("email"), record.get("login")) or "")
            other = match.sources.get(tool_id) if match else None
            if match is not None and other not in (None, external) and other in external_ids:
                match = None  # another entry of the same directory with the same email: a different person
            person, how = (match, "merged") if match is not None else (None, "created")
        if person is None:
            person = Person(display_name=str(record.get("display_name") or record.get("login") or external)[:200])
            people[person.id] = person
        before = person.model_dump(mode="json", exclude={"updated_at"}) if how != "created" else {}
        for field in PROFILE_FIELDS:
            value = record.get(field)
            if value:
                setattr(person, field, str(value)[:LIMITS[field]])
        person.sources = {**person.sources, tool_id: external}
        person.source_status = {**person.source_status, tool_id: record.get("status") or "active"}
        person.source_groups = {**person.source_groups, tool_id: list(record.get("groups") or [])}
        recompute(person)
        index.add(person)
        seen[external] = person.id
        if record.get("manager_external_id"):
            managers[person.id] = str(record["manager_external_id"])
        if how == "created" or _changed(before, person):
            counts[how] += 1
            dirty.add(person.id)
        else:
            counts["unchanged"] += 1
    sourced = {ext: pid for ext, pid in {**by_source, **seen}.items()}
    for pid, ref in managers.items():
        target = sourced.get(ref) or index.match(ref if "@" in ref else None, ref)
        person = people[pid]
        if target and target != pid and target in people and person.manager_id != target:
            person.manager_id = target
            dirty.add(pid)
    if retire_missing:
        found = set(seen.values())  # a person this pull saw under a new id (re-created in the directory) has not left
        for external, pid in by_source.items():
            person = people.get(pid)
            if external in seen or pid in found or person is None or person.source_status.get(tool_id) == "terminated":
                continue
            person.source_status = {**person.source_status, tool_id: "terminated"}  # gone from the directory
            recompute(person)
            dirty.add(pid)
            counts["left"] += 1
    for pid in dirty:
        save(hub, people[pid])
    # the directory itself is an account the person holds (inactive unless they are active there)
    _sync_accounts(hub, tool_id, "people", [{
        "external_id": str(r["external_id"]), "login": r.get("login"), "email": r.get("email"),
        "display_name": r.get("display_name"), "active": r.get("status") == "active", "last_login": None,
        "app": None, "person_id": seen[str(r["external_id"])]} for r in records], retire_missing)
    return counts


def apply_accounts(hub: "Hub", tool_id: str, records: list[dict[str, Any]], retire_missing: bool = True) -> dict[str, int]:
    """Store one tool's user accounts (canonical "accounts" records) and link them to people."""
    return _sync_accounts(hub, tool_id, "accounts", records, retire_missing)


def _sync_accounts(hub: "Hub", tool_id: str, origin: str, records: list[dict[str, Any]],
                   retire_missing: bool) -> dict[str, int]:
    existing = {a.id: a for a in all_accounts(hub, tool_id) if a.origin == origin}
    index = Index.of(all_people(hub))
    counts = {"total": len(records), "created": 0, "updated": 0, "unchanged": 0, "removed": 0, "linked": 0}
    seen: set[str] = set()
    for record in records:
        aid = account_id(tool_id, str(record["external_id"]))
        current = existing.get(aid)
        account = Account(id=aid, tool_id=tool_id, external_id=str(record["external_id"]), origin=origin,  # type: ignore[arg-type]
                          login=record.get("login"), email=record.get("email"), display_name=record.get("display_name"),
                          app=record.get("app"), active=bool(record.get("active", True)),
                          last_login=record.get("last_login"))
        if current is not None and current.person_source == "manual":
            account.person_id, account.person_source = current.person_id, "manual"
        else:
            account.person_id = record.get("person_id") or index.match(account.email, account.login)
        seen.add(aid)
        if account.person_id:
            counts["linked"] += 1
        if current is not None and current.model_dump(exclude={"updated_at"}) == account.model_dump(exclude={"updated_at"}):
            counts["unchanged"] += 1
            continue
        counts["updated" if current is not None else "created"] += 1
        save_account(hub, account)
    if retire_missing:
        for aid in set(existing) - seen:
            hub.store.delete(ACCOUNTS, aid)
            counts["removed"] += 1
        if counts["removed"]:
            hub.bus.publish("accounts_removed", {"tool_id": tool_id, "count": counts["removed"]})
    return counts


def relink(hub: "Hub") -> dict[str, int]:
    """Re-link automatically linked accounts and assets after people changed."""
    people = all_people(hub)
    index, ids = Index.of(people), {p.id for p in people}
    sourced = {(tool, ext): p.id for p in people for tool, ext in p.sources.items()}
    accounts = 0
    for account in all_accounts(hub):
        if account.person_source == "manual" and (account.person_id is None or account.person_id in ids):
            continue
        directory = sourced.get((account.tool_id, account.external_id)) if account.origin == "people" else None
        target = directory or index.match(account.email, account.login)
        if target != account.person_id:
            account.person_id, account.person_source = target, "auto"
            save_account(hub, account)
            accounts += 1
    return {"accounts": accounts, "assets": link_assets(hub, index, ids)}


def assigned_person(asset: Asset, index: Index) -> str | None:
    facts = asset.facts
    email = facts.get("assigned_email") if isinstance(facts.get("assigned_email"), str) else None
    login = facts.get("assigned_username") if isinstance(facts.get("assigned_username"), str) else None
    return index.match(email, login) if email or login else None


def link_assets(hub: "Hub", index: Index | None = None, ids: set[str] | None = None) -> int:
    """Link assets to the person their inventory assigns them to (only while assigned_source is "auto"); drop links
    to people who no longer exist."""
    if index is None or ids is None:
        people = all_people(hub)
        index, ids = Index.of(people), {p.id for p in people}
    changed = 0
    for asset in hub.all("assets", Asset):
        before = (asset.assigned_person_id, asset.owner_person_id)
        if asset.assigned_source == "auto":
            asset.assigned_person_id = assigned_person(asset, index)
        elif asset.assigned_person_id and asset.assigned_person_id not in ids:
            asset.assigned_person_id = None
        if asset.owner_person_id and asset.owner_person_id not in ids:
            asset.owner_person_id = None
        if (asset.assigned_person_id, asset.owner_person_id) != before:
            asset.updated_at = time.time()
            hub.save("assets", asset, "asset")
            changed += 1
    return changed


def forget_tool(hub: "Hub", tool_id: str) -> None:
    """A tool left the hub: its accounts go, and people lose it as a source - keeping what it said about leavers."""
    for account in all_accounts(hub, tool_id):
        hub.store.delete(ACCOUNTS, account.id)
    for person in all_people(hub):
        if tool_id not in person.sources and tool_id not in person.source_status:
            continue
        said = person.source_status.get(tool_id)
        if said in LEFT and person.status == said and PERSON_STATUS_RANK[said] > PERSON_STATUS_RANK[person.manual_status or "active"]:
            person.manual_status = said  # type: ignore[assignment]
        person.sources = {k: v for k, v in person.sources.items() if k != tool_id}
        person.source_status = {k: v for k, v in person.source_status.items() if k != tool_id}
        person.source_groups = {k: v for k, v in person.source_groups.items() if k != tool_id}
        save(hub, recompute(person))


# --------------------------------------------------------------------------------------
# leavers (pure: also used by the compliance check)
# --------------------------------------------------------------------------------------


@dataclass
class Links:
    """What links to each person, indexed once (not per person): their active assets (in the order given), their tool
    accounts, and Atrium users by email."""

    assets: dict[str, list[Asset]]
    accounts: dict[str, list[Account]]
    users: dict[str, list[User]]

    @classmethod
    def of(cls, assets: list[Asset], accounts: list[Account], users: list[User]) -> "Links":
        held: dict[str, list[Asset]] = {}
        for a in assets:
            if a.status == "retired":
                continue
            for pid in dict.fromkeys(p for p in (a.owner_person_id, a.assigned_person_id) if p):
                held.setdefault(pid, []).append(a)
        mine: dict[str, list[Account]] = {}
        for account in accounts:
            if account.person_id:
                mine.setdefault(account.person_id, []).append(account)
        by_email: dict[str, list[User]] = {}
        for u in users:  # an account stays linked through the emails single sign-on replaced (review F17)
            for email in dict.fromkeys(key(e) for e in (u.email, *u.previous_emails) if key(e)):
                by_email.setdefault(email, []).append(u)
        return cls(held, mine, by_email)

    def users_of(self, person: Person) -> list[User]:
        return self.users.get(key(person.email), []) if key(person.email) else []


def find_leavers(people: list[Person], assets: list[Asset], users: list[User], accounts: list[Account],
                 tool_names: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """One finding per suspended or terminated person who still holds something: "fail" with access (an enabled
    Atrium account, an active tool account), "partial" with only assets."""
    names = tool_names or {}
    links = Links.of(assets, accounts, users)
    out = []
    for person in people:
        if person.status not in LEFT:
            continue
        held = [{"id": a.id, "name": a.name, "type": a.type,
                 "relation": "owner" if a.owner_person_id == person.id else "assigned"}
                for a in links.assets.get(person.id, [])]
        atrium = [{"id": u.id, "username": u.username, "role": u.role} for u in links.users_of(person) if not u.disabled]
        active = [{"id": a.id, "tool_id": a.tool_id, "tool": names.get(a.tool_id, a.tool_id), "login": a.login or a.email,
                   "app": a.app} for a in links.accounts.get(person.id, []) if a.active]
        if not (held or atrium or active):
            continue
        actions = []
        if held:
            actions.append({"id": "unassign_assets", **ACTIONS["unassign_assets"]})
        if atrium:
            actions.append({"id": "disable_atrium_account", **ACTIONS["disable_atrium_account"]})
        parts = [f"{len(held)} asset(s)" if held else "", f"Atrium account {', '.join(u['username'] for u in atrium)}"
                 if atrium else "", f"{len(active)} active tool account(s)" if active else ""]
        out.append({
            "person_id": person.id, "display_name": person.display_name, "email": person.email, "status": person.status,
            "terminated_at": person.terminated_at, "severity": "fail" if atrium or active else "partial",
            "assets": held, "atrium_accounts": atrium, "accounts": active, "actions": actions,
            "summary": f"{person.display_name} ({person.status}) still has " + ", ".join(p for p in parts if p),
            "todo": [f"Disable or remove {a['login'] or 'the account'}{' (' + a['app'] + ')' if a['app'] else ''} in "
                     f"{a['tool']}" for a in active],
        })
    return sorted(out, key=lambda f: (f["severity"] != "fail", f["display_name"].lower()))


def leavers(hub: "Hub") -> list[dict[str, Any]]:
    return find_leavers(all_people(hub), hub.all("assets", Asset), hub.auth.users(), all_accounts(hub),
                        {t.id: t.name for t in hub.tools()})


# --------------------------------------------------------------------------------------
# views
# --------------------------------------------------------------------------------------


def source_names(hub: "Hub") -> dict[str, str]:
    return {"manual": "Added by hand", **{t.id: t.name for t in hub.tools()}}


def brief(person: Person | None) -> dict[str, Any] | None:
    if person is None:
        return None
    return {"id": person.id, "display_name": person.display_name, "email": person.email, "title": person.title,
            "status": person.status, "initials": initials(person.display_name)}


def user_for(person: Person, users: list[User]) -> User | None:
    return next((u for u in users if person.email and key(u.email) == key(person.email)), None)


def person_for_user(user: User, people: list[Person]) -> Person | None:
    return next((p for p in people if user.email and key(p.email) == key(user.email)), None)


def public(person: Person, *, names: dict[str, str] | None = None, links: Links | None = None,
           people: dict[str, Person] | None = None) -> dict[str, Any]:
    names = names or {}
    held = links.assets.get(person.id, []) if links else []
    mine = links.accounts.get(person.id, []) if links else []
    user = next(iter(links.users_of(person)), None) if links else None
    manager = (people or {}).get(person.manager_id or "")
    return {
        **person.model_dump(mode="json"), "initials": initials(person.display_name),
        "source_list": [{"id": k, "name": names.get(k, k), "external_id": v, "status": person.source_status.get(k)}
                        for k, v in person.sources.items()],
        "manager": brief(manager), "assets_owned": sum(1 for a in held if a.owner_person_id == person.id),
        "assets_assigned": sum(1 for a in held if a.assigned_person_id == person.id),
        "accounts": len(mine), "active_accounts": sum(1 for a in mine if a.active),
        "atrium_user": {"id": user.id, "username": user.username, "role": user.role, "disabled": user.disabled}
        if user else None,
    }


def listing(hub: "Hub", *, q: str = "", status: str = "", department: str = "", source: str = "",
            short: bool = False) -> dict[str, Any]:
    """The People list (`short`: only what pickers need - no counts, links or leavers)."""
    people = all_people(hub)
    by_id = {p.id: p for p in people}
    names = source_names(hub)
    assets, accounts, users = ([], [], []) if short else (hub.all("assets", Asset), all_accounts(hub), hub.auth.users())
    links = Links.of(assets, accounts, users)
    needle = key(q)
    statuses = {s.strip() for s in status.split(",") if s.strip()}
    items = []
    for p in people:
        if statuses and p.status not in statuses or department and key(p.department) != key(department):
            continue
        if source and source not in p.sources:
            continue
        if needle and needle not in " ".join(filter(None, (p.display_name, p.email, p.login, p.title, p.department,
                                                           *p.groups))).lower():
            continue
        items.append(brief(p) if short else public(p, names=names, links=links, people=by_id))
    items.sort(key=lambda x: x["display_name"].lower())
    return {
        "people": items, "total": len(people),
        "departments": sorted({p.department for p in people if p.department}, key=str.lower),
        "sources": [{"id": s, "name": names.get(s, s)} for s in sorted({s for p in people for s in p.sources})],
        "statuses": {s: sum(1 for p in people if p.status == s) for s in ("active", "suspended", "terminated")},
        "leavers": None if short else len(find_leavers(people, assets, users, accounts)),
    }


def detail(hub: "Hub", person: Person) -> dict[str, Any]:
    """Everything the person page shows, with a small relationship graph (person in the middle)."""
    people = {p.id: p for p in all_people(hub)}
    names = source_names(hub)
    assets = hub.all("assets", Asset)
    accounts = all_accounts(hub)
    users = hub.auth.users()
    view = public(person, names=names, links=Links.of(assets, accounts, users), people=people)
    related = [a for a in assets if person.id in (a.owner_person_id, a.assigned_person_id)]
    asset_rows = [{"id": a.id, "name": a.name, "type": a.type, "status": a.status, "criticality": a.criticality,
                   "source": a.source, "relation": "owner" if a.owner_person_id == person.id else "assigned",
                   "also_assigned": a.owner_person_id == person.id and a.assigned_person_id == person.id,
                   "assigned_source": a.assigned_source} for a in related]
    mine = [a for a in accounts if a.person_id == person.id]
    per_tool: dict[str, list[dict[str, Any]]] = {}
    for a in mine:
        per_tool.setdefault(a.tool_id, []).append(a.model_dump(mode="json"))
    asset_ids = {a.id for a in related if a.status != "retired"}
    vulns = sorted((v for v in hub.all("vulnerabilities", Vulnerability) if v.asset_id in asset_ids and v.status in OPEN_STATES),
                   key=lambda v: (SEVERITY_ORDER.index(v.severity), v.due_at or float("inf")))
    user = user_for(person, users)
    risks = [r for r in hub.all("risks", Risk) if r.owner_person_id == person.id]
    policies = [p for p in hub.all("policies", Policy) if p.owner_person_id == person.id]
    activity = [e for e in hub.store.tail("activity", 2000)
                if (e.get("data") or {}).get("person_id") == person.id or (e.get("data") or {}).get("asset_id") in asset_ids
                or (user is not None and e.get("actor") == user.username)][-30:]
    finding = next(iter(find_leavers([person], assets, users, accounts, names)), None)
    tools = {t: names.get(t, t) for t in {*per_tool, *(s for s in person.sources if s != "manual")}}
    nodes = [{"id": f"asset:{a['id']}", "kind": "asset", "label": a["name"], "ref": a["id"], "relation": a["relation"]}
             for a in asset_rows if a["status"] != "retired"]
    nodes += [{"id": f"tool:{t}", "kind": "tool", "label": name, "ref": t,
               "relation": "account" if t in per_tool else "directory"} for t, name in sorted(tools.items())]
    nodes += [{"id": f"group:{g}", "kind": "group", "label": g, "ref": g, "relation": "member"} for g in person.groups[:12]]
    manager = people.get(person.manager_id or "")
    if manager:
        nodes.append({"id": f"person:{manager.id}", "kind": "manager", "label": manager.display_name, "ref": manager.id,
                      "relation": "manager"})
    if user:
        nodes.append({"id": "atrium", "kind": "atrium", "label": f"Atrium ({user.role})", "ref": user.id,
                      "relation": "disabled" if user.disabled else "account"})
    return {
        **view,
        "reports": [brief(p) for p in people.values() if p.manager_id == person.id],
        "assets": asset_rows,
        "accounts_by_tool": [{"tool_id": t, "tool": names.get(t, t), "accounts": rows} for t, rows in sorted(per_tool.items())],
        "atrium": {"id": user.id, "username": user.username, "role": user.role, "disabled": user.disabled,
                   "auth_source": user.auth_source, "last_login": user.last_login} if user else None,
        "risks": [{"id": r.id, "title": r.title, "score": r.score, "status": r.status} for r in risks],
        "policies": [{"id": p.id, "title": p.title, "status": p.status, "version": p.version} for p in policies],
        "vulnerabilities": [{"id": v.id, "title": v.title, "severity": v.severity, "asset_id": v.asset_id,
                             "host": v.host, "status": v.status, "due_at": v.due_at, "overdue": v.overdue}
                            for v in vulns[:100]],
        "vulnerabilities_open": len(vulns),
        "activity": activity,
        "leaver": finding,
        "actions": [{"id": k, **v} for k, v in ACTIONS.items()],
        "graph": {"center": {"id": f"person:{person.id}", "label": person.display_name, "initials": initials(person.display_name),
                             "status": person.status}, "nodes": nodes,
                  "edges": [{"from": f"person:{person.id}", "to": n["id"], "kind": n["relation"]} for n in nodes]},
    }


# --------------------------------------------------------------------------------------
# changes people make
# --------------------------------------------------------------------------------------

EDITABLE = ("display_name", "email", "login", "title", "department", "manager_id", "location", "phone")


def _check_manager(hub: "Hub", person_id: str | None, manager_id: str | None) -> None:
    if not manager_id:
        return
    if manager_id == person_id:
        raise ValueError("A person cannot be their own manager")
    seen, current = set(), get(hub, manager_id)
    if current is None:
        raise ValueError(f"Unknown manager '{manager_id}'")
    while current is not None and current.id not in seen:  # no reporting loops
        if current.id == person_id:
            raise ValueError("That manager reports to this person")
        seen.add(current.id)
        current = get(hub, current.manager_id) if current.manager_id else None


def _check_email(hub: "Hub", person_id: str | None, email: str | None) -> None:
    if email and any(p.id != person_id and key(p.email) == key(email) for p in all_people(hub)):
        raise LookupError(f"Another person already has the email {email}")


def create(hub: "Hub", values: dict[str, Any], actor: str) -> Person:
    _check_email(hub, None, values.get("email"))
    person = Person.model_validate({k: v for k, v in values.items() if k in (*EDITABLE, "groups") and v is not None})
    _check_manager(hub, person.id, person.manager_id)
    person.sources = {"manual": person.id}
    person.source_groups = {"manual": list(values.get("groups") or [])} if values.get("groups") else {}
    status = values.get("status")
    person.manual_status = status if status and status != "active" else None
    save(hub, recompute(person))
    hub.activity(actor, "info", f"Added person {person.display_name}", person_id=person.id)
    relink(hub)
    return person


def update(hub: "Hub", person: Person, changes: dict[str, Any], actor: str) -> Person:
    if "email" in changes:
        _check_email(hub, person.id, changes.get("email"))
    if "manager_id" in changes:
        _check_manager(hub, person.id, changes.get("manager_id"))
    data = person.model_dump()
    data.update({k: v for k, v in changes.items() if k in EDITABLE})
    if "groups" in changes:
        data["source_groups"] = {**person.source_groups, "manual": list(changes.get("groups") or [])}
    if "status" in changes:
        data["manual_status"] = changes["status"]
    updated = recompute(Person.model_validate(data))
    save(hub, updated)
    what = ", ".join(sorted(k for k in changes if k in (*EDITABLE, "groups", "status")))
    hub.activity(actor, "info", f"Updated person {updated.display_name}" + (f": {what}" if what else ""),
                 person_id=updated.id)
    if {"email", "login"} & set(changes):
        relink(hub)
    return updated


def delete(hub: "Hub", person: Person, actor: str) -> None:
    """Remove a person and every link to them (a directory that still lists them brings them back on its next pull)."""
    hub.store.delete(COLLECTION, person.id)
    hub.bus.publish("person_removed", {"id": person.id})
    for other in all_people(hub):
        if other.manager_id == person.id:
            other.manager_id = None
            save(hub, other)
    for collection, model in (("risks", Risk), ("policies", Policy)):
        for item in hub.all(collection, model):
            if item.owner_person_id == person.id:
                item.owner_person_id = None
                hub.save(collection, item, "risk" if collection == "risks" else "policy")
    for account in all_accounts(hub):
        if account.person_id == person.id:
            account.person_id, account.person_source = None, "auto"
            save_account(hub, account)
    relink(hub)
    hub.activity(actor, "info", f"Removed person {person.display_name}", person_id=person.id)


def unassign_assets(hub: "Hub", person: Person, actor: str, asset_ids: list[str] | None = None) -> dict[str, Any]:
    """Take a person off the assets they own or use. Assignments made from the inventory stay off (assigned_source
    "manual") until someone links them again, so return the device in the inventory tool as well."""
    changed, from_tools = [], []
    for asset in hub.all("assets", Asset):
        if asset_ids and asset.id not in asset_ids or person.id not in (asset.owner_person_id, asset.assigned_person_id):
            continue
        if asset.assigned_person_id == person.id:
            asset.assigned_person_id, asset.assigned_source = None, "manual"
            if asset.facts.get("assigned_email") or asset.facts.get("assigned_username"):
                from_tools.append(asset.name)
        if asset.owner_person_id == person.id:
            asset.owner_person_id = None
            if asset.owner == person.display_name:
                asset.owner = None
        asset.updated_at = time.time()
        hub.save("assets", asset, "asset")
        changed.append(asset.id)
    if changed:
        hub.activity(actor, "info", f"Unassigned {len(changed)} asset(s) from {person.display_name}", person_id=person.id,
                     asset_ids=changed)
    note = (f"Still checked out in the inventory tool: {', '.join(from_tools[:5])} - check them in there too."
            if from_tools else "")
    return {"ok": True, "changed": changed, "detail": note or f"{len(changed)} asset(s) unassigned."}


class AmbiguousAccounts(LookupError):
    """More than one enabled Atrium account is linked to the person: the administrator picks (review F27)."""


def disable_atrium_account(hub: "Hub", person: Person, principal: "Principal",
                           user_ids: list[str] | None = None) -> dict[str, Any]:
    """Disable the person's enabled Atrium account(s) - those linked by email (the leaver finding lists them). With
    `user_ids` (the accounts the administrator saw and confirmed) only those, and only while they are still linked;
    without, only when exactly one account is linked: a person's email can be edited by operators and account emails
    are not unique, so the hub never picks among several accounts by itself (review F27)."""
    linked = [u for u in Links.of([], [], hub.auth.users()).users_of(person) if not u.disabled]
    if user_ids is not None:
        chosen = [u for u in linked if u.id in set(user_ids)]
        if len(chosen) != len(set(user_ids)):
            raise LookupError("Those accounts are not (or no longer) the enabled Atrium accounts of this person - "
                              "reload and check who they are")
    elif len(linked) > 1:
        raise AmbiguousAccounts(f"More than one enabled Atrium account uses this person's email "
                                f"({', '.join(u.username for u in linked)}) - choose the account(s) to disable")
    else:
        chosen = linked
    disabled = []
    for user in chosen:
        hub.auth.update_user(user.id, {"disabled": True}, principal)  # AuthError for yourself / the last admin
        disabled.append(user.username)
    if disabled:
        hub.activity(principal.actor, "warn", f"Disabled the Atrium account of {person.display_name} "
                                              f"({', '.join(disabled)}): {person.status}", person_id=person.id)
    return {"ok": True, "disabled": disabled,
            "detail": f"Disabled {', '.join(disabled)}." if disabled else "No enabled Atrium account has this email."}
