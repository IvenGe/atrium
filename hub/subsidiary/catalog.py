"""The catalog of an API-only subsidiary (sidecar-only mode, 5.4): the actions its staff may take, derived by Atrium
from the connector class of the tool's connection (trusted code), never from the tool.

- ``records.<domain>.list`` (read) for each domain the connection reads: run in the sidecar with the dedicated,
  read-only credential (at most 50 records, sanitized);
- ``records.<domain>.upsert`` (write, not reversible) for each domain it writes: always an approval, carried out in
  Atrium by the Tool Supervisor with the connection's own credential after a person approved it.

The domains follow the toolkit's READ_DOMAINS (never ``network`` or ``frameworks``). Identity domains (people,
accounts) are read only: changing who can do what in a tool is never a subsidiary's to request. Connector actions,
extension domains and OpenAPI-derived catalogs are not offered in round 4.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from .. import connectors
from ..connectors.base import ASSET_TYPES, SEVERITIES
from ..integration import connections
from . import contract

if TYPE_CHECKING:
    from ..core import Hub

READ = ("assets", "vulnerabilities", "risks", "controls", "people", "accounts")  # = toolkit.READ_DOMAINS
WRITE = ("assets", "vulnerabilities", "risks", "controls")  # never people or accounts (identity)
ACTION_RE = re.compile(r"^records\.([a-z][a-z0-9_]{0,40})\.(list|upsert)$")
NOUNS = {"assets": ("assets", "an asset"), "vulnerabilities": ("findings", "a finding"),
         "risks": ("risks", "a risk"), "controls": ("controls", "a control"), "people": ("people", "a person"),
         "accounts": ("accounts", "an account")}


def _text(limit: int) -> dict[str, Any]:
    return {"type": "string", "maxLength": limit}


def _enum(values: tuple[str, ...] | list[str]) -> dict[str, Any]:
    return {"enum": list(values)}


LIST_PARAMS = {"type": "object", "additionalProperties": False, "required": [],
               "properties": {"q": _text(200), "limit": {"type": "integer", "minimum": 1, "maximum": 50}}}
# what a person approves for each domain: the record's fields Atrium knows (connectors.base record models), without
# free-form objects or names the contract forbids (e.g. a vulnerability's "host")
UPSERT_FIELDS: dict[str, dict[str, dict[str, Any]]] = {
    "assets": {"name": _text(200), "type": _enum(ASSET_TYPES), "owner": _text(200),
               "status": _enum(("active", "maintenance", "retired")),
               "addresses": {"type": "array", "items": _text(100), "maxItems": 20}},
    "vulnerabilities": {"title": _text(300), "severity": _enum(SEVERITIES), "description": _text(10_000),
                        "solution": _text(10_000), "port": _text(20),
                        "cves": {"type": "array", "items": _text(30), "maxItems": 20}},
    "risks": {"title": _text(300), "description": _text(10_000), "likelihood": {"type": "integer", "minimum": 1,
                                                                               "maximum": 5},
              "impact": {"type": "integer", "minimum": 1, "maximum": 5},
              "status": _enum(("open", "in_treatment", "closed")), "treatment": _text(2000)},
    "controls": {"ref_id": _text(100), "name": _text(300), "description": _text(10_000),
                 "status": _enum(("pass", "partial", "fail", "manual", "na"))},
}
REQUIRED = {"assets": ["name"], "vulnerabilities": ["title"], "risks": ["title"], "controls": ["ref_id", "name"]}


def upsert_params(domain: str) -> dict[str, Any]:
    return {"type": "object", "additionalProperties": False, "required": ["external_id", *REQUIRED[domain]],
            "properties": {"external_id": _text(500), **UPSERT_FIELDS[domain]}}


def domains(hub: "Hub", tool_id: str) -> dict[str, list[str]]:
    """The connection's domains and operations (as its last test narrowed them), limited to the catalog's."""
    conn = connections.get(hub, tool_id)
    found = connections.capabilities(conn) if conn is not None else {}
    out = {}
    for domain in READ:
        ops = [op for op in ("read", "write") if op in found.get(domain, []) and (op == "read" or domain in WRITE)]
        if ops:
            out[domain] = ops
    return out


def build(hub: "Hub", tool_id: str) -> list[dict[str, Any]]:
    """The catalog: manifest-shaped actions (contract.validate_manifest's rules), risks at their floors."""
    out = []
    for domain, ops in domains(hub, tool_id).items():
        plural, single = NOUNS[domain]
        if "read" in ops:
            out.append({"id": f"records.{domain}.list", "title": f"List {plural}",
                        "description": f"{plural.capitalize()} in the tool (at most 50, newest data the API gives)",
                        "risk": "read", "category": "data", "on_behalf_of": False, "params": LIST_PARAMS})
        if "write" in ops:
            out.append({"id": f"records.{domain}.upsert", "title": f"Create or update {single}",
                        "description": f"Create {single} in the tool, or update the one with this external_id",
                        "risk": "write", "category": "data", "reversible": False, "external_effect": False,
                        "on_behalf_of": False, "params": upsert_params(domain)})
    return contract.check_catalog(out, limit=contract.MAX_ACTIONS).actions  # the same checks as a bridge's


def parse(action_id: str) -> tuple[str, str] | None:
    """(domain, "list" | "upsert") of a catalog action id."""
    found = ACTION_RE.match(action_id or "")
    return (found.group(1), found.group(2)) if found and found.group(1) in READ else None


def connector_title(hub: "Hub", tool_id: str) -> str:
    conn = connections.get(hub, tool_id)
    if conn is None:
        return "the tool's API"
    return connectors.connector_class(conn.kind).title
