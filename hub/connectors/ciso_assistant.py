"""CISO Assistant connector: the hub's compliance work lands in CISO Assistant, its risk scenarios come back.

What goes where: hub assets -> supporting assets; hub controls -> applied controls (ref_id = the hub control id), each
with one evidence holding the automated check results (external id "<applied control id>|<evidence id>"); hub
findings -> vulnerabilities (linked to the CISO Assistant asset of the same name); risk scenarios -> hub risks, with
likelihood and impact rescaled from the scenario's risk matrix to 1-5. The chosen folder (domain) receives everything
the hub creates and limits what is read; without one, new objects go to the root (Global) folder and reads cover
every folder the token's user can see.

API facts this relies on, checked against the CISO Assistant community source (backend/core/urls.py, models.py,
serializers.py, pagination.py, permissions.py; iam/models.py, iam/urls.py) and its API reference
(ca-api-doc.pages.dev) in October 2026:

- the REST API lives under /api; personal access tokens are Knox tokens, sent as "Authorization: Token <token>";
- lists use limit/offset pagination ({count, next, previous, results}); a plain list is accepted as well;
- related objects read as {"id", "str"} and are written as ids; object ids are UUIDs;
- folders: content_type GL (the root) | DO (domain) | EN (enclave, kept for third parties - not offered);
- assets: type PR (primary) | SP (supporting), read as the label; no address fields, so the hub writes them into the
  description ("Addresses: ...") and reads that line back. In asset and applied control descriptions the hub only
  rewrites the block below its marker line; what a person wrote above it stays;
- applied controls: status to_do | in_progress | on_hold | active | degraded | deprecated | "--" (undefined; recent
  versions add degraded, older ones refuse it - so a hub "partial" is sent as in_progress unless the connection asks for
  degraded); an evidence links to applied controls through its applied_controls list; an evidence keeps its
  attachments, links and observations in revisions, created only when one of them is sent - the hub sends an
  observation with the check result, so the evidence gets a revision (and goes to in_review) instead of staying an
  empty draft;
- risk scenarios: treatment open | mitigate | accept | avoid | transfer | cancelled; current_proba / current_impact
  read as {"value": index into the matrix's probability / impact list, "name", ...}, -1 when not rated;
- vulnerabilities (recent versions only - test() reports whether the instance has them): severity -1 undefined,
  0 info, 1 low, 2 medium, 3 high, 4 critical (read as the label); status "--" | potential | exploitable | mitigated |
  fixed | not_exploitable | unaffected;
- names are unique within a folder (fields_to_check: name for assets and evidence, ref_id + name for applied controls
  and vulnerabilities), so the hub adopts an object of the same name (the same ref_id for applied controls) that no
  other hub record is linked to, instead of failing on a duplicate; finding names carry host and port;
- permissions are checked per object and folder (RBACPermissions.has_permission is always true), so write access
  cannot be probed without writing: the first push shows it.

Frameworks (domain ``frameworks``, read; shapes in grcmodel.py), from the community source (core/models.py, views.py,
library/views.py, main branch, read 2026-10-09):

- frameworks/ lists the loaded frameworks (library frameworks live in the root folder, so they are read unfiltered);
  requirement-nodes/?framework=<id> their nodes (filters: framework and urn only - nodes are matched by ref_id here,
  since some URNs do not follow the ref_id); compliance-assessments/ (folder-filtered) the assessments, with
  requirement-assessments/?compliance_assessment=<id> one row per node (result not_assessed | partially_compliant |
  non_compliant | compliant | not_applicable, score, documentation_score) and global_score/ their scores;
  requirement-mapping-sets/ the mapping sets; loaded-libraries/ which libraries are loaded (test() reports CyFun 2025,
  CyFun 2023 and the CRA; importing a library needs CISO Assistant rights and is never done by Atrium);
- CyFun requirement ids carry level prefixes in CyFun 2023 (BASIC_ID.AM-1.1): the hub strips them.

Self-assessments (domain ``assessments``, write - only when an administrator switches on "Send CyFun
self-assessments" in the connection): each hub assessment becomes a compliance assessment of the loaded CyFun
framework (selected_implementation_groups = [the target level]); every requirement the hub scored is written with
PATCH requirement-assessments/<id>/ (result, status, score, documentation_score, is_scored, observation), and
requirements the hub did not score are left alone. UNVERIFIED: the fields CISO Assistant requires to create a
compliance assessment (name, framework and folder are sent) and the format of selected_implementation_groups (a list
of group ref_ids, inferred) - the first push shows a clear error if either differs.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import ValidationError

from ..grc.frameworks import LIBRARY_NAMES, LIBRARY_URNS
from .base import ASSET_TYPES, Connector, ConnectorError, ConnectorField, check, to_timestamp
from .grcmodel import AssessmentPush

PAGE = 500  # the server caps a page at PAGINATE_MAX (5000 by default)
MAX_PAGES = 200
MAX_RECORDS = 10_000
NAME, REF, TEXT = 200, 100, 20_000  # CISO Assistant's name and ref_id lengths; descriptions are kept readable
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
ADDRESSES_RE = re.compile(r"(?im)^\s*addresses\s*:\s*(.+)$")
TYPE_RE = re.compile(r"(?im)^\s*type\s*:\s*([a-z]+)\s*$")
ROOT_FOLDERS, ENCLAVE_FOLDERS = {"GL", "GLOBAL"}, {"EN", "ENCLAVE"}
# assets and applied controls keep what a person wrote above this line; the hub rewrites what follows it
MARKER = "--- Managed by Atrium: text below this line is rewritten on every sync ---"

# hub control status -> applied control status. Assumption: "--" (undefined) is accepted on write - it is one of the
# model's choices, although the published API reference lists only the other five.
CONTROL_STATUS = {"pass": "active", "partial": "in_progress", "fail": "to_do", "manual": "--", "na": "--"}
PARTIAL_STATUSES = ("in_progress", "degraded")
VULN_SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# a scanner finding is "potential" until someone confirms it; accepted findings still exist, so they stay potential
VULN_STATUS = {"open": "potential", "in_progress": "potential", "accepted": "potential", "false_positive": "unaffected",
               "fixed": "fixed"}
# risk scenario treatment -> hub (status, treatment)
RISK_TREATMENT = {"open": ("open", None), "mitigate": ("in_treatment", "mitigate"), "accept": ("in_treatment", "accept"),
                  "avoid": ("in_treatment", "avoid"), "transfer": ("in_treatment", "transfer"),
                  "cancelled": ("closed", None)}
# asset class name (recent versions) -> hub asset type, first match wins
ASSET_CLASSES = (("workstation", ("workstation", "laptop", "desktop", "endpoint", "mobile")),
                 ("network", ("network", "router", "switch", "firewall")),
                 ("server", ("server", "virtual machine")),
                 ("saas", ("saas",)), ("cloud", ("cloud",)),
                 ("software", ("software", "application")),
                 ("data", ("data", "information")))
# what test() reads: (check name, path, domain, operations it enables)
PROBES = (("Assets", "assets/", "assets", ("read", "write")),
          ("Applied controls", "applied-controls/", "controls", ("write",)),
          ("Evidence", "evidences/", "controls", ("write",)),
          ("Risk scenarios", "risk-scenarios/", "risks", ("read",)),
          ("Vulnerabilities", "vulnerabilities/", "vulnerabilities", ("write",)))
# CyFun frameworks Atrium ships its own catalog of: their requirement text is not read into the hub
CYFUN_FRAMEWORKS = {"urn:intuitem:risk:framework:ccb-cyfun2025", "urn:intuitem:risk:framework:ccb-cff-2023-03-01"}
LEVEL_PREFIX = re.compile(r"^(BASIC|IMPORTANT|ESSENTIAL)_", re.I)
RESULT_NAMES = ("not_assessed", "partially_compliant", "non_compliant", "compliant", "not_applicable")


class _Abort(ConnectorError):
    """A failure every other record of the push would share (a missing endpoint): fails the whole push."""


class _RecordError(ConnectorError):
    """A failure of one pushed record only."""


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


def _id(value: Any) -> str | None:
    """The id of a related object ({"id", "str"}) or a plain id."""
    if isinstance(value, dict):
        value = value.get("id")
    return str(value).lower() if value not in (None, "") else None


def _label(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("str") or value.get("name") or value.get("email")
    text = str(value).strip() if value not in (None, "") else ""
    return text or None


def _labels(value: Any) -> list[str]:
    return [text for text in (_label(v) for v in (value if isinstance(value, list) else [])) if text]


def _is_root(folder: dict[str, Any]) -> bool:
    """The root (Global) folder: by its content type, else as the one folder without a parent."""
    kind = str(folder.get("content_type") or "").upper()
    if kind in ROOT_FOLDERS:
        return True
    return kind not in ENCLAVE_FOLDERS and "parent_folder" in folder and not folder["parent_folder"]


def _uuid(value: Any) -> str | None:
    text = str(value or "").strip()
    return text.lower() if UUID_RE.match(text) else None


def _day(value: Any) -> str | None:
    ts = to_timestamp(value)
    return datetime.fromtimestamp(ts, timezone.utc).date().isoformat() if ts is not None else None


def _when(value: Any) -> str | None:
    ts = to_timestamp(value)
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if ts is not None else None


def _level(value: Any) -> int | None:
    """A risk-matrix index from {"value": n, ...} or n; None when not rated (-1)."""
    if isinstance(value, dict):
        value = value.get("value")
    if isinstance(value, bool):
        return None
    try:
        index = int(value)
    except (TypeError, ValueError):
        return None
    return index if index >= 0 else None


def rescale(index: int | None, levels: int | None) -> int | None:
    """A risk-matrix index (0 = lowest) on the hub's 1-5 scale. Without the matrix size, five levels are assumed."""
    if index is None:
        return None
    if not levels:
        return max(1, min(5, index + 1))
    if levels < 2:
        return 3
    return max(1, min(5, 1 + round(min(index, levels - 1) * 4 / (levels - 1))))


def validation_text(response: httpx.Response) -> str:
    """Django REST framework errors ({"field": ["message"]}, ["message"], {"detail": "..."}) on one line, wording kept."""
    try:
        body = response.json()
    except ValueError:
        return response.text[:300]

    def flat(value: Any) -> str:
        if isinstance(value, list):
            return " ".join(flat(v) for v in value)
        if isinstance(value, dict):
            return "; ".join(f"{k}: {flat(v)}" for k, v in value.items())
        return str(value)

    if isinstance(body, dict):
        parts = [flat(v) if k in ("detail", "non_field_errors", "__all__", "error") else f"{k}: {flat(v)}"
                 for k, v in body.items()]
        return "; ".join(parts)[:500]
    return flat(body)[:500]


def asset_type(asset_class: str | None, description: str) -> str:
    match = TYPE_RE.search(description)
    if match and match.group(1).lower() in ASSET_TYPES:  # the line the hub writes
        return match.group(1).lower()
    text = (asset_class or "").lower()
    return next((kind for kind, words in ASSET_CLASSES if any(w in text for w in words)), "other")


def asset_record(item: dict[str, Any]) -> dict[str, Any]:
    description = str(item.get("description") or "")
    addresses: list[str] = []
    for line in ADDRESSES_RE.findall(description):
        addresses += [a for a in re.split(r"[,;\s]+", line) if a and a not in addresses]
    asset_class = _label(item.get("asset_class"))
    primary = str(item.get("type") or "").strip().upper() in ("PR", "PRIMARY")
    return {
        "external_id": item.get("id"), "name": item.get("name"), "type": asset_type(asset_class, description),
        "owner": ", ".join(_labels(item.get("owner"))) or None, "status": "active", "addresses": addresses,
        "facts": {"ciso_assistant_type": "primary" if primary else "supporting", "ref_id": item.get("ref_id"),
                  "folder": _label(item.get("folder")), "asset_class": asset_class,
                  "business_value": item.get("business_value"), "reference_link": item.get("reference_link"),
                  "parent_assets": _labels(item.get("parent_assets"))},
        "updated_at": item.get("updated_at"),
    }


def risk_record(item: dict[str, Any], levels: tuple[int | None, int | None]) -> dict[str, Any]:
    proba = _level(item.get("current_proba"))
    impact = _level(item.get("current_impact"))
    if proba is None or impact is None:  # not rated yet: fall back to the inherent rating
        proba = proba if proba is not None else _level(item.get("inherent_proba"))
        impact = impact if impact is not None else _level(item.get("inherent_impact"))
    status, treatment = RISK_TREATMENT.get(str(item.get("treatment") or "open").lower(), ("open", None))
    lines = [str(item.get("description") or "").strip()]
    assessment = _label(item.get("risk_assessment"))
    level = item.get("current_level")
    if assessment:
        lines.append(f"CISO Assistant risk assessment: {assessment}")
    if isinstance(level, dict) and _level(level) is not None and level.get("name"):
        lines.append(f"Current level: {level['name']}")
    controls = _labels(item.get("applied_controls"))
    if controls:
        lines.append("Applied controls: " + ", ".join(controls[:20]))
    name = str(item.get("name") or "").strip()
    ref = str(item.get("ref_id") or "").strip()
    return {"external_id": item.get("id"), "title": f"{ref} {name}".strip() if ref and ref not in name else name,
            "description": "\n".join(line for line in lines if line), "likelihood": rescale(proba, levels[0]),
            "impact": rescale(impact, levels[1]), "status": status, "treatment": treatment}


def _count(answer: Any) -> int | None:
    if isinstance(answer, dict) and isinstance(answer.get("count"), int):
        return answer["count"]
    return len(answer) if isinstance(answer, list) else None


def hub_ref(ref_id: Any, aliases: dict[str, str] | None = None) -> str:
    """A CISO Assistant requirement ref_id as Atrium writes it: CyFun 2023's level prefixes (BASIC_) removed."""
    ref = LEVEL_PREFIX.sub("", str(ref_id or "").strip())
    return (aliases or {}).get(ref, ref)


def _node_records(nodes: list[dict[str, Any]], own_text: bool) -> list[dict[str, Any]]:
    """Requirement nodes with their depth (from the parent links); names and descriptions only when `own_text`."""
    parents = {str(n.get("urn") or ""): str(n.get("parent_urn") or "") for n in nodes if n.get("urn")}
    depths: dict[str, int] = {}

    def depth(urn: str) -> int:
        chain, current = [], urn
        while current in parents and current not in depths and current not in chain and len(chain) < 20:
            chain.append(current)
            current = parents[current]
        base = depths.get(current, 0)
        for offset, item in enumerate(reversed(chain), start=1):
            depths[item] = base + offset
        return depths.get(urn, 1)

    out = []
    for node in nodes:
        urn = str(node.get("urn") or "").strip()
        if not urn:
            continue
        out.append({"id": _uuid(node.get("id")) or "", "urn": urn, "ref_id": hub_ref(node.get("ref_id")),
                    "name": node.get("name") if own_text else "", "description": node.get("description") if own_text else "",
                    "parent_urn": node.get("parent_urn") or None, "depth": min(depth(urn), 20),
                    "assessable": bool(node.get("assessable")),
                    "implementation_groups": node.get("implementation_groups") or []})
    return out


def merge_text(current: Any, block: str) -> str:
    """A description with the person's own text (above the marker line) kept and the hub's block below it replaced."""
    own = str(current or "").split(MARKER)[0].rstrip()
    return f"{own}\n\n{MARKER}\n{block}" if own else f"{MARKER}\n{block}"


def asset_description(record: dict[str, Any]) -> str:
    lines = []
    for label, key in (("Type", "type"), ("Criticality", "criticality"), ("Owner", "owner")):
        if record.get(key):
            lines.append(f"{label}: {record[key]}")
    if record.get("status") not in (None, "", "active"):
        lines.append(f"Status: {record['status']}")
    if record.get("addresses"):
        lines.append("Addresses: " + ", ".join(str(a) for a in record["addresses"]))
    facts = [(k, v) for k, v in (record.get("facts") or {}).items() if v not in (None, "", [], {})][:20]
    if facts:
        lines += ["Facts:"] + [f"- {k}: {v}" for k, v in facts]
    return "\n".join(lines)[:TEXT]


def control_description(record: dict[str, Any]) -> str:
    lines = [str(record.get("description") or "").strip().replace(MARKER, ""), ""]
    result = f"Atrium check: {record.get('status') or 'manual'}"
    if record.get("detail"):
        result += f" - {record['detail']}"
    lines.append(result)
    refs = record.get("refs") or {}
    if refs:
        lines.append("Mapped to: " + " · ".join(f"{k} {v}" for k, v in refs.items()))
    return "\n".join(lines).strip()[:TEXT]


def evidence_text(record: dict[str, Any]) -> str:
    when = _when(record.get("evaluated_at"))
    lines = [f"Automated evidence from Atrium for {record.get('ref_id')} {record.get('name')}.",
             f"Result: {record.get('status') or 'manual'}" + (f", evaluated {when}" if when else "") + "."]
    items = [str(e) for e in record.get("evidence") or [] if str(e).strip()]
    if items:
        lines += [""] + [f"- {e}" for e in items[:100]]
    return "\n".join(lines)[:TEXT]


def evidence_observation(record: dict[str, Any]) -> str:
    when = _when(record.get("evaluated_at"))
    line = f"Atrium check: {record.get('status') or 'manual'}" + (f" ({when})" if when else "")
    return (line + (f" - {record['detail']}" if record.get("detail") else ""))[:2000]


def vulnerability_name(record: dict[str, Any]) -> str:
    """Title plus where it was found: one scanner check on several hosts must not clash on CISO Assistant's
    unique names."""
    where = str(record.get("host") or "")
    if where and record.get("port"):
        where += f":{record['port']}"
    title = str(record.get("title") or "Untitled finding")
    suffix = f" on {where}" if where else ""
    return title[:NAME - len(suffix)] + suffix if len(suffix) < NAME else title[:NAME]


def vulnerability_description(record: dict[str, Any]) -> str:
    lines = [str(record.get("description") or "").strip()]
    if record.get("solution"):
        lines += ["", f"Solution: {record['solution']}"]
    where = [f"{label}: {record[key]}" for label, key in (("Host", "host"), ("Port", "port"), ("Asset", "asset"))
             if record.get(key)]
    facts = [f"{label}: {record[key]}" for label, key in (("CVSS", "cvss"), ("Scanner", "scanner")) if record.get(key)]
    status = [f"Atrium status: {record.get('status') or 'open'}"]
    if _day(record.get("due_at")):
        status.append(f"due {_day(record.get('due_at'))}")
    if _day(record.get("first_seen") or record.get("detected_at")):
        status.append(f"first seen {_day(record.get('first_seen') or record.get('detected_at'))}")
    lines += [""] + [" · ".join(part) for part in (where, facts) if part]
    if record.get("cves"):
        lines.append("CVEs: " + ", ".join(record["cves"]))
    lines.append(" · ".join(status))
    return "\n".join(lines).strip()[:TEXT]


# --------------------------------------------------------------------------------------
# connector
# --------------------------------------------------------------------------------------


class CisoAssistantConnector(Connector):
    kind = "ciso_assistant"
    title = "CISO Assistant"
    description = "GRC: receives hub controls with evidence, assets and findings; risk scenarios flow into the hub."
    fields = [
        ConnectorField(name="base_url", label="CISO Assistant URL", kind="url", required=True,
                       placeholder="https://ciso.example.com",
                       help="The address CISO Assistant is served at, with or without /api."),
        ConnectorField(name="token", label="API token", kind="secret", required=True,
                       help="A personal access token of a CISO Assistant user who may read and write assets, applied "
                            'controls, evidence, risk scenarios and vulnerabilities. Sent as "Authorization: Token <token>".'),
        ConnectorField(name="folder_id", label="Folder (domain)", kind="select", options=True,
                       help="Where the hub creates objects, and whose assets and risk scenarios it reads. Empty: new "
                            "objects go to the Global folder and every folder the user can see is read."),
        ConnectorField(name="verify_tls", label="Verify TLS certificate", kind="bool", default=True),
        ConnectorField(name="partial_status", label="Status of partially effective controls", kind="select",
                       default="in_progress",
                       choices=[{"value": "in_progress", "label": "In progress (every version)"},
                                {"value": "degraded", "label": "Degraded (recent versions)"}],
                       help="The applied control status a hub control that only partly passes gets."),
        ConnectorField(name="push_assessments", label="Send CyFun self-assessments", kind="bool", default=False,
                       help="Write the hub's CyFun self-assessments (result and both maturity scores per requirement) "
                            "into compliance assessments in CISO Assistant. Off: frameworks and assessments are only "
                            "read. Needs the CyFun library loaded in CISO Assistant (Atrium never imports libraries)."),
    ]
    capabilities = {"assets": {"read", "write"}, "controls": {"write"}, "risks": {"read"}, "vulnerabilities": {"write"},
                    "frameworks": {"read"}, "assessments": {"write"}}

    def __init__(self, config: dict[str, Any], secrets: dict[str, str], transport: httpx.AsyncBaseTransport | None = None):
        super().__init__(config, secrets, transport)
        self._root: str | None = None
        self._indexes: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
        self._claimed: set[str] = set()  # objects a hub record is linked to: never adopted for another one
        self._frameworks: list[dict[str, Any]] | None = None
        self._no_degraded = False

    @classmethod
    def detect(cls, tool) -> int:
        return cls.name_score(tool, ("ciso-assistant", "ciso assistant", "cisoassistant"), ("grc.compliance", "grc.risks"))

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        base = str(config.get("base_url") or "").strip().rstrip("/")
        parts = urlsplit(base)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ConnectorError("The CISO Assistant URL must start with http:// or https://")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ConnectorError("Put the token in the API token field, not in the URL (no user:password@, query or #)")
        out = {**config, "base_url": base}
        folder = str(config.get("folder_id") or "").strip()
        if folder and not UUID_RE.match(folder):
            raise ConnectorError("The folder must be a CISO Assistant folder id - choose one from the list")
        if folder:
            out["folder_id"] = folder.lower()
        else:
            out.pop("folder_id", None)
        if out.get("partial_status") not in (None, *PARTIAL_STATUSES):
            raise ConnectorError("The status of partially effective controls must be in_progress or degraded")
        if "push_assessments" in out and not isinstance(out["push_assessments"], bool):
            raise ConnectorError("Send CyFun self-assessments must be true or false")
        return out

    def domains(self) -> dict[str, list[str]]:
        """Self-assessments are only written when an administrator switched it on in the connection."""
        out = super().domains()
        if not self.config.get("push_assessments"):
            out.pop("assessments", None)
        return out

    # -- HTTP ----------------------------------------------------------------------

    @property
    def api(self) -> str:
        base = str(self.config.get("base_url") or "").strip().rstrip("/")
        return base if base.lower().endswith("/api") else f"{base}/api"

    @property
    def folder(self) -> str | None:
        return _uuid(self.config.get("folder_id"))

    def client(self) -> httpx.AsyncClient:
        headers = {"Accept": "application/json", "Accept-Language": "en"}  # labels such as GLOBAL are translated
        if self.secrets.get("token"):
            headers["Authorization"] = f"Token {self.secrets['token']}"
        return self.http(self.api + "/", headers=headers, verify=bool(self.config.get("verify_tls", True)))

    def raise_for_status(self, response: httpx.Response, what: str = "") -> None:
        if response.status_code == 400:  # validation errors: the tool's own words, field by field
            where = f" ({what})" if what else ""
            raise self.error(f"CISO Assistant rejected the request (HTTP 400){where}: {validation_text(response)}",
                             status=400, excerpt=response.text)
        if response.status_code == 401:
            raise self.error("CISO Assistant rejected the API token (HTTP 401) - it may be wrong, revoked or expired; "
                             "create a new personal access token", status=401, excerpt=response.text)
        super().raise_for_status(response, what)

    def _in_scope(self, item: dict[str, Any], folder: str | None) -> bool:
        found = _id(item.get("folder"))
        return not folder or found is None or found == folder

    async def _list(self, client: httpx.AsyncClient, path: str, params: dict[str, Any] | None = None,
                    what: str = "", folder: str | None = None) -> list[dict[str, Any]]:
        """Every item of a list endpoint (limit/offset pages, or a plain list), optionally only one folder's."""
        what = what or path.strip("/")
        query = {**(params or {}), **({"folder": folder} if folder else {})}
        items: list[dict[str, Any]] = []
        offset = 0
        for _ in range(MAX_PAGES):
            try:
                answer = await self.request_json(client, "GET", path, params={**query, "limit": PAGE, "offset": offset},
                                                 what=f"list {what}")
            except ConnectorError as exc:
                if exc.status == 404:
                    raise _Abort(f"CISO Assistant has no {what} endpoint at {self.api}/{path} (HTTP 404) - check the "
                                 "URL, or this CISO Assistant version lacks it", status=404, excerpt=exc.excerpt) from exc
                raise
            if isinstance(answer, list):
                items = [i for i in answer if isinstance(i, dict)]
                break
            if not isinstance(answer, dict) or not isinstance(answer.get("results"), list):
                raise self.error(f"CISO Assistant answered the {what} list without results - is the URL the CISO "
                                 "Assistant API?", excerpt=json.dumps(answer, default=str))
            page = answer["results"]
            items += [i for i in page if isinstance(i, dict)]
            offset += len(page)
            count = answer.get("count")
            if not page or len(items) >= MAX_RECORDS or (isinstance(count, int) and offset >= count) \
                    or (not isinstance(count, int) and not answer.get("next")):
                break
        return [i for i in items if self._in_scope(i, folder)][:MAX_RECORDS]

    # -- test and choices ----------------------------------------------------------

    async def test(self) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []
        async with self.client() as client:
            try:
                user = await self.request_json(client, "GET", "iam/current-user/", what="current user")
            except ConnectorError as exc:
                return self._unreachable(exc)
            version = await self._version(client)
            who = _label(user.get("email") if isinstance(user, dict) else None) \
                or (_label(user.get("username")) if isinstance(user, dict) else None) or "the token's user"
            checks.append(check("API", True, f"CISO Assistant{' ' + version if version else ''} at {self.api}"))
            checks.append(check("API token", True, f"Signed in as {who}"))
            folder_ok = await self._check_folder(client, checks)
            readable: dict[str, list[bool]] = {}
            missing: list[str] = []
            for name, path, domain, _ops in PROBES:  # a folder that failed its check would only add filter errors
                ok = await self._probe(client, name, path, domain, checks, missing, self.folder if folder_ok else None)
                readable.setdefault(domain, []).append(ok)
            frameworks = await self._check_frameworks(client, checks, missing, self.folder if folder_ok else None)
        domains = {domain: sorted(ops) for name, path, domain, ops in PROBES if all(readable.get(domain) or [False])}
        if frameworks:
            domains["frameworks"] = ["read"]
            if self.config.get("push_assessments"):
                domains["assessments"] = ["write"]
        failed = [c["name"] for c in checks if not c["ok"]]
        ok = folder_ok and bool(domains)
        if ok:
            detail = f"Connected as {who}: " + ", ".join(f"{d} ({'/'.join(o)})" for d, o in sorted(domains.items()))
            if missing:
                detail += f"; not on this instance: {', '.join(missing)}"
            if failed:
                detail += f"; failed: {', '.join(failed)}"
        else:
            detail = "Connected, but " + (f"failed: {', '.join(failed)}" if failed else "nothing can be exchanged")
        return {"ok": ok, "detail": detail + ".", "checks": checks, "domains": domains}

    def _unreachable(self, exc: ConnectorError) -> dict[str, Any]:
        """test() when the very first call failed: say which part is wrong."""
        if exc.status in (401, 403):
            checks = [check("API", True, f"CISO Assistant answered at {self.api}"),
                      check("API token", False, exc.message)]
        elif exc.status == 404 or (exc.status is not None and exc.status < 400):
            # not found, a redirect, or a web page instead of JSON: not the API root
            checks = [check("API", False, f"No CISO Assistant API at {self.api}: {exc.message}. Enter the address "
                                          "CISO Assistant is served at (the hub adds /api), not the address of one "
                                          "of its pages")]
        else:  # unreachable, a server error or rate limiting
            checks = [check("API", False, exc.message)]
        return {"ok": False, "detail": checks[-1]["detail"], "checks": checks, "domains": {}}

    async def _version(self, client: httpx.AsyncClient) -> str | None:
        try:
            build = await self.request_json(client, "GET", "build/", what="build")
        except ConnectorError:
            return None  # informational only (older versions may not have it)
        version = build.get("version") if isinstance(build, dict) else None
        return str(version)[:40] if version else None

    async def _check_folder(self, client: httpx.AsyncClient, checks: list[dict[str, Any]]) -> bool:
        if not self.folder:
            checks.append(check("Folder", True, "None chosen: new objects go to the Global folder; assets and risk "
                                                "scenarios are read from every folder this user can see"))
            return True
        try:
            folder = await self.request_json(client, "GET", f"folders/{self.folder}/", what="folder")
        except ConnectorError as exc:
            detail = "The chosen folder does not exist any more - choose another one" if exc.status == 404 else exc.message
            checks.append(check("Folder", False, detail))
            return False
        name = _label(folder.get("name") if isinstance(folder, dict) else None) or self.folder
        kind = str(folder.get("content_type") or "").upper() if isinstance(folder, dict) else ""
        if kind in ENCLAVE_FOLDERS:
            checks.append(check("Folder", False, f"'{name}' is an enclave (third-party) folder - choose a domain"))
            return False
        checks.append(check("Folder", True, f"New objects go to '{name}'; its assets and risk scenarios are read"))
        return True

    async def _probe(self, client: httpx.AsyncClient, name: str, path: str, domain: str,
                     checks: list[dict[str, Any]], missing: list[str], folder: str | None) -> bool:
        try:
            answer = await self.request_json(client, "GET", path, params={**({"folder": folder} if folder else {}),
                                                                         "limit": 1}, what=f"list {name.lower()}")
        except ConnectorError as exc:
            if exc.status == 404 and domain == "vulnerabilities":
                missing.append(domain)
                checks.append(check(name, True, "Not available on this CISO Assistant version: hub findings are not "
                                                "sent (upgrade CISO Assistant to receive them)"))
            elif exc.status == 403:
                checks.append(check(name, False, f"This user may not read {name.lower()} (HTTP 403) - give its role "
                                                 "access in CISO Assistant"))
            else:
                checks.append(check(name, False, exc.message))
            return False
        count = _count(answer)
        if count is None:
            checks.append(check(name, False, "The answer is not a list - is the URL the CISO Assistant API?"))
            return False
        where = "in the folder" if folder else "visible to this user"
        does = {"assets": "read, and receive hub assets", "controls": "receive hub controls and evidence",
                "risks": "pulled into the hub's risk register", "vulnerabilities": "receive hub findings"}[domain]
        checks.append(check(name, True, f"{count} {where} - {does} (write access shows on the first push)"
                            if domain != "risks" else f"{count} {where} - {does}"))
        return True

    async def _check_frameworks(self, client: httpx.AsyncClient, checks: list[dict[str, Any]], missing: list[str],
                                folder: str | None) -> bool:
        """Frameworks and compliance assessments readable; which libraries are loaded; whether results are sent."""
        counts = {}
        for name, path, params in (("frameworks", "frameworks/", {}),
                                   ("compliance assessments", "compliance-assessments/", {"folder": folder} if folder else {})):
            try:
                counts[name] = _count(await self.request_json(client, "GET", path, params={**params, "limit": 1},
                                                              what=f"list {name}"))
            except ConnectorError as exc:
                if exc.status == 404:
                    missing.append("frameworks")
                    checks.append(check("Frameworks", True, f"No {name} endpoint on this CISO Assistant version: "
                                                            "frameworks are not read"))
                elif exc.status == 403:
                    checks.append(check("Frameworks", False, f"This user may not read {name} (HTTP 403) - give its "
                                                             "role access in CISO Assistant"))
                else:
                    checks.append(check("Frameworks", False, exc.message))
                return False
        where = "in the folder" if folder else "visible to this user"
        checks.append(check("Frameworks", True, f"{counts['frameworks']} loaded, {counts['compliance assessments']} "
                                                f"compliance assessments {where} - shown read-only in the Compliance hub"))
        loaded: dict[str, dict[str, Any]] = {}
        try:
            loaded = {str(item.get("urn") or "").lower(): item
                      for item in await self._list(client, "loaded-libraries/", what="loaded libraries")}
        except ConnectorError as exc:
            checks.append(check("Libraries", True, f"Could not list the loaded libraries: {exc.message}"))
        else:
            have = [f"{LIBRARY_NAMES[k]} (version {loaded[u].get('version') or '?'})" for k, u in LIBRARY_URNS.items()
                    if u in loaded]
            lack = [LIBRARY_NAMES[k] for k, u in LIBRARY_URNS.items() if u not in loaded]
            detail = ("Loaded: " + ", ".join(have)) if have else "None of CyFun 2025, CyFun 2023 or the CRA is loaded"
            if lack:
                detail += (f"; not loaded: {', '.join(lack)} - an administrator of CISO Assistant can import them "
                           "(Catalog > Libraries); Atrium never imports libraries")
            checks.append(check("Libraries", True, detail))
        if self.config.get("push_assessments"):
            cyfun = any(LIBRARY_URNS[k] in loaded for k in ("cyfun2025", "cyfun2023"))
            checks.append(check("Self-assessments", True,
                                "Atrium writes its CyFun self-assessments into compliance assessments (write access "
                                "shows on the first push)" + ("" if cyfun or not loaded else
                                                             "; load a CyFun library in CISO Assistant first")))
        else:
            checks.append(check("Self-assessments", True, "Not sent: an administrator can switch on 'Send CyFun "
                                                          "self-assessments' in this connection"))
        return True

    async def options(self, field_name: str) -> list[dict[str, str]]:
        if field_name != "folder_id":
            return await super().options(field_name)
        async with self.client() as client:
            folders = await self._list(client, "folders/", what="folders")
        out = []
        for folder in folders:
            if not _uuid(folder.get("id")) or str(folder.get("content_type") or "").upper() in ENCLAVE_FOLDERS:
                continue
            root = _is_root(folder)
            name = _label(folder.get("name")) or _label(folder.get("str")) or str(folder["id"])
            out.append((not root, name.lower(), {"value": str(folder["id"]), "label": f"{name} ({'global' if root else 'domain'})"}))
        return [item for _, _, item in sorted(out, key=lambda t: (t[0], t[1]))]

    # -- reading -------------------------------------------------------------------
    # `since` is not used: the hub retires assets and closes risks that a full read no longer contains.

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        async with self.client() as client:
            if domain == "assets":
                return [asset_record(i) for i in await self._list(client, "assets/", what="assets", folder=self.folder)]
            if domain == "risks":
                scenarios = await self._list(client, "risk-scenarios/", what="risk scenarios", folder=self.folder)
                levels = await self._matrix_levels(client, scenarios)
                return [risk_record(s, levels.get(_id(s.get("risk_matrix")) or "", (None, None))) for s in scenarios]
            if domain == "frameworks":
                return await self._pull_frameworks(client)
        return await super().pull(domain, since)

    async def _optional_list(self, client: httpx.AsyncClient, path: str, what: str) -> list[dict[str, Any]]:
        """A list that older versions or narrower roles may not have: empty instead of failing the whole read."""
        try:
            return await self._list(client, path, what=what)
        except ConnectorError as exc:
            if exc.status == 401:
                raise
            return []

    async def _pull_frameworks(self, client: httpx.AsyncClient) -> list[dict[str, Any]]:
        frameworks = await self._list(client, "frameworks/", what="frameworks")
        assessments = await self._list(client, "compliance-assessments/", what="compliance assessments",
                                       folder=self.folder)
        libraries = {_id(item.get("id")): str(item.get("urn") or "")
                     for item in await self._optional_list(client, "loaded-libraries/", "loaded libraries")}
        urns = {_id(f.get("id")): str(f.get("urn") or "") for f in frameworks}
        mapping_sets = await self._optional_list(client, "requirement-mapping-sets/", "mapping sets")
        out = []
        for framework in frameworks:
            framework_id = _uuid(framework.get("id"))
            urn = str(framework.get("urn") or "").strip()
            if not framework_id or not urn:
                continue
            nodes = await self._list(client, "requirement-nodes/", {"framework": framework_id}, what="requirement nodes")
            nodes = [n for n in nodes if _id(n.get("framework")) in (None, framework_id)]
            own_text = urn.lower() not in CYFUN_FRAMEWORKS  # never keep the CCB's requirement text
            requirements = _node_records(nodes, own_text)
            by_node = {n["id"]: n for n in requirements if n["id"]}
            states = []
            for assessment in assessments:
                if _id(assessment.get("framework")) == framework_id and _uuid(assessment.get("id")):
                    states.append(await self._assessment_state(client, assessment, by_node))
            out.append({
                "external_id": framework_id, "urn": urn, "ref_id": framework.get("ref_id"), "name": framework.get("name"),
                "description": framework.get("description") if own_text else "",
                "provider": _label(framework.get("provider")) or "",
                "library_urn": libraries.get(_id(framework.get("library")), ""),
                "min_score": framework.get("min_score"), "max_score": framework.get("max_score"),
                "implementation_groups": [{"ref_id": g.get("ref_id"), "name": g.get("name")}
                                          for g in framework.get("implementation_groups_definition") or []
                                          if isinstance(g, dict)],
                "requirements": requirements, "assessments": states,
                "mappings": [{"external_id": m.get("id"), "name": m.get("name"),
                              "source": urns.get(_id(m.get("source_framework")), ""),
                              "target": urns.get(_id(m.get("target_framework")), "")}
                             for m in mapping_sets if framework_id in (_id(m.get("source_framework")),
                                                                       _id(m.get("target_framework")))],
            })
        return out

    async def _assessment_state(self, client: httpx.AsyncClient, assessment: dict[str, Any],
                                by_node: dict[str, dict[str, Any]]) -> dict[str, Any]:
        assessment_id = _uuid(assessment.get("id")) or ""
        rows = await self._list(client, "requirement-assessments/", {"compliance_assessment": assessment_id},
                                what="requirement assessments")
        results: dict[str, int] = {}
        requirements = []
        for row in rows:
            node = by_node.get(_id(row.get("requirement")) or "")
            if node is None or not node["assessable"] or _id(row.get("compliance_assessment")) not in (None, assessment_id):
                continue
            result = str(row.get("result") or "not_assessed")
            result = result if result in RESULT_NAMES else "not_assessed"
            results[result] = results.get(result, 0) + 1
            requirements.append({"urn": node["urn"], "ref_id": node["ref_id"], "result": result,
                                 "status": row.get("status"), "score": row.get("score") if row.get("is_scored", True) else None,
                                 "documentation_score": row.get("documentation_score")})
        try:
            score = await self.request_json(client, "GET", f"compliance-assessments/{assessment_id}/global_score/",
                                            what="global score")
        except ConnectorError as exc:
            if exc.status == 401:
                raise
            score = {}
        score = score if isinstance(score, dict) else {}
        return {"external_id": assessment_id, "name": assessment.get("name"), "ref_id": assessment.get("ref_id"),
                "status": assessment.get("status"), "version": assessment.get("version"),
                "folder": _label(assessment.get("folder")) or "",
                "selected_implementation_groups": assessment.get("selected_implementation_groups"),
                "updated_at": assessment.get("updated_at"), "outcomes": assessment.get("computed_outcome"),
                "scores": {"implementation": score.get("implementation_score"),
                           "documentation": score.get("documentation_score"), "maturity": score.get("maturity_score")},
                "results": results, "requirements": requirements}

    async def _matrix_levels(self, client: httpx.AsyncClient,
                             scenarios: list[dict[str, Any]]) -> dict[str, tuple[int | None, int | None]]:
        """risk matrix id -> (probability levels, impact levels); scenarios without a risk_matrix id (older versions)
        get it from their risk assessment. Unreadable matrices fall back to five levels."""
        if not scenarios:
            return {}
        try:
            matrices = await self._list(client, "risk-matrices/", what="risk matrices")
        except ConnectorError:
            return {}
        out: dict[str, tuple[int | None, int | None]] = {}
        for matrix in matrices:
            definition = matrix.get("json_definition")
            if isinstance(definition, str):
                try:
                    definition = json.loads(definition)
                except ValueError:
                    definition = None
            if isinstance(definition, dict) and _id(matrix.get("id")):
                out[_id(matrix["id"]) or ""] = (len(definition.get("probability") or []) or None,
                                                len(definition.get("impact") or []) or None)
        if any(not s.get("risk_matrix") and s.get("risk_assessment") for s in scenarios):
            try:
                assessments = {_id(a.get("id")): _id(a.get("risk_matrix"))
                               for a in await self._list(client, "risk-assessments/", what="risk assessments")}
            except ConnectorError:
                assessments = {}
            for scenario in scenarios:
                if not scenario.get("risk_matrix"):
                    scenario["risk_matrix"] = assessments.get(_id(scenario.get("risk_assessment")))
        return out

    # -- writing -------------------------------------------------------------------

    async def push(self, domain: str, records: list[dict[str, Any]], links: dict[str, str]) -> list[dict[str, Any]]:
        handlers = {"assets": self._push_asset, "controls": self._push_control,
                    "vulnerabilities": self._push_vulnerability, "assessments": self._push_assessment}
        handler = handlers.get(domain)
        if handler is None:
            return await super().push(domain, records, links)
        self._claimed = {part.lower() for value in links.values() for part in str(value or "").split("|") if part}
        self._indexes = {}
        results = []
        async with self.client() as client:
            folder = await self._target_folder(client)
            for record in records:
                hub_id = record.get("hub_id")
                external = links.get(hub_id or "")
                try:
                    new_external, action = await handler(client, record, external, folder)
                except _Abort:
                    raise
                except ConnectorError as exc:
                    if exc.status in (None, 401, 403) and not isinstance(exc, _RecordError):
                        raise  # unreachable or not allowed: every other record fails alike
                    results.append({"hub_id": hub_id, "external_id": external, "action": "failed", "error": exc.message})
                    continue
                results.append({"hub_id": hub_id, "external_id": new_external, "action": action, "error": None})
        return results

    async def _target_folder(self, client: httpx.AsyncClient) -> str | None:
        """The chosen folder, else the root folder (where CISO Assistant puts objects created without one)."""
        if self.folder:
            return self.folder
        if self._root is None:
            try:
                folders = await self._list(client, "folders/", what="folders")
            except ConnectorError as exc:
                if exc.status == 401:
                    raise
                return None
            self._root = next((_uuid(f.get("id")) for f in folders if _is_root(f)), None) or ""
        return self._root or None

    async def _index(self, client: httpx.AsyncClient, path: str, key: str, folder: str | None) -> dict[str, dict[str, Any]]:
        """The folder's objects at `path` by lower-cased `key` (name or ref_id), read once per push."""
        if (path, key) not in self._indexes:
            index: dict[str, dict[str, Any]] = {}
            for item in await self._list(client, path, folder=folder):
                value = str(item.get(key) or "").strip().lower()
                if value and _uuid(item.get("id")):
                    index.setdefault(value, item)
            self._indexes[(path, key)] = index
        return self._indexes[(path, key)]

    async def _adoptable(self, client: httpx.AsyncClient, path: str, key: str, value: str,
                         folder: str | None) -> dict[str, Any] | None:
        """An existing object with this name / ref_id that no hub record is linked to yet."""
        if not value.strip():
            return None
        item = (await self._index(client, path, key, folder)).get(value.strip().lower())
        found = _uuid(item.get("id")) if item else None
        return item if found and found not in self._claimed else None

    async def _get(self, client: httpx.AsyncClient, path: str, object_id: str, what: str) -> dict[str, Any] | None:
        """One object; None when it is gone (deleted in CISO Assistant)."""
        try:
            answer = await self.request_json(client, "GET", f"{path}{object_id}/", what=what)
        except ConnectorError as exc:
            if exc.status == 404:
                return None
            raise
        return answer if isinstance(answer, dict) else None

    async def _create(self, client: httpx.AsyncClient, path: str, body: dict[str, Any], what: str,
                      key: str | None = None) -> str:
        try:
            answer = await self.request_json(client, "POST", path, json=body, what=f"create {what}")
        except ConnectorError as exc:
            if exc.status == 404:
                raise _Abort(f"CISO Assistant has no {path.strip('/')} endpoint at {self.api} (HTTP 404) - check the "
                             "URL, or this CISO Assistant version lacks it", status=404, excerpt=exc.excerpt) from exc
            raise
        new_id = _uuid(answer.get("id")) if isinstance(answer, dict) else None
        if not new_id:  # ids go into later request paths: only a UUID is accepted
            raise _RecordError(f"CISO Assistant created the {what} but did not answer with its id", status=201)
        self._claimed.add(new_id)
        if key and body.get(key) and (path, key) in self._indexes:  # never seed an index that was not read yet
            self._indexes[(path, key)][str(body[key]).strip().lower()] = {"id": new_id}
        return new_id

    async def _patch(self, client: httpx.AsyncClient, path: str, object_id: str, body: dict[str, Any], what: str) -> bool:
        """Update an object; False when it is gone (deleted in CISO Assistant)."""
        try:
            await self.request_json(client, "PATCH", f"{path}{object_id}/", json=body, what=f"update {what}")
        except ConnectorError as exc:
            if exc.status == 404:
                return False
            raise
        self._claimed.add(object_id)
        return True

    async def _upsert(self, client: httpx.AsyncClient, path: str, external: str | None, key: str,
                      update: dict[str, Any], create: dict[str, Any], what: str, folder: str | None,
                      keep_own_text: bool = False) -> tuple[str, str]:
        """Update the linked object, else adopt an unlinked one with the same key, else create one. With
        `keep_own_text`, what a person wrote above the marker line of the description stays."""

        def body_for(current: dict[str, Any] | None) -> dict[str, Any]:
            if not keep_own_text:
                return update
            return {**update, "description": merge_text((current or {}).get("description"), update["description"])}

        linked = _uuid(external)
        if linked:
            current = await self._get(client, path, linked, what) if keep_own_text else {}
            if current is not None and await self._patch(client, path, linked, body_for(current), what):
                return linked, "updated"
        adopted = await self._adoptable(client, path, key, str(update.get(key) or ""), folder)
        if adopted:
            adopted_id = _uuid(adopted["id"]) or ""
            if not await self._patch(client, path, adopted_id, body_for(adopted), what):
                raise _RecordError(f"The {what} '{update.get(key)}' disappeared from CISO Assistant during the sync",
                                   status=404)
            return adopted_id, "updated"
        body = {**body_for(None), **create, **({"folder": folder} if folder else {})}
        return await self._create(client, path, body, what, key), "created"

    async def _push_asset(self, client: httpx.AsyncClient, record: dict[str, Any], external: str | None,
                          folder: str | None) -> tuple[str, str]:
        update = {"name": str(record.get("name") or "unnamed")[:NAME], "description": asset_description(record)}
        return await self._upsert(client, "assets/", external, "name", update, {"type": "SP"}, "asset", folder,
                                  keep_own_text=True)

    async def _push_control(self, client: httpx.AsyncClient, record: dict[str, Any], external: str | None,
                            folder: str | None) -> tuple[str, str]:
        ref = str(record.get("ref_id") or record.get("external_id") or "")[:REF]
        control_part, _, evidence_part = str(external or "").partition("|")
        status = CONTROL_STATUS.get(record.get("status"), "--")
        if record.get("status") == "partial" and self.config.get("partial_status") == "degraded" and not self._no_degraded:
            status = "degraded"
        control = {"name": str(record.get("name") or ref)[:NAME], "ref_id": ref,
                   "description": control_description(record), "status": status}
        try:
            control_id, action = await self._upsert(client, "applied-controls/", control_part, "ref_id", control, {},
                                                    "applied control", folder, keep_own_text=True)
        except ConnectorError as exc:  # a version without "degraded": fall back to in_progress for the whole push
            if status != "degraded" or exc.status != 400 or "status" not in exc.message:
                raise
            self._no_degraded = True
            control["status"] = "in_progress"
            control_id, action = await self._upsert(client, "applied-controls/", control_part, "ref_id", control, {},
                                                    "applied control", folder, keep_own_text=True)
        relink = control_id != _uuid(control_part)  # a new or adopted control: point the evidence at it
        # the observation creates an evidence revision (a visible record, in_review) instead of an empty draft
        evidence = {"name": f"{ref} automated evidence (Atrium)"[:NAME], "description": evidence_text(record),
                    "observation": evidence_observation(record)}
        linked = _uuid(evidence_part)
        if linked and await self._patch(client, "evidences/", linked,
                                        {**evidence, **({"applied_controls": [control_id]} if relink else {})}, "evidence"):
            evidence_id = linked
        else:
            evidence_id, _ = await self._upsert(client, "evidences/", None, "name",
                                                {**evidence, "applied_controls": [control_id]}, {}, "evidence", folder)
        return f"{control_id}|{evidence_id}", action

    async def _push_vulnerability(self, client: httpx.AsyncClient, record: dict[str, Any], external: str | None,
                                  folder: str | None) -> tuple[str, str]:
        update = {"name": vulnerability_name(record), "description": vulnerability_description(record),
                  "ref_id": ", ".join(record.get("cves") or [])[:REF],
                  "severity": VULN_SEVERITY.get(str(record.get("severity") or ""), -1),
                  "status": VULN_STATUS.get(str(record.get("status") or "open"), "--")}
        create: dict[str, Any] = {}
        detected = _day(record.get("detected_at") or record.get("first_seen"))
        if detected:
            create["detected_at"] = detected  # ignored by versions without the field
        if record.get("asset"):  # link the CISO Assistant asset of the same name, e.g. one the hub pushed
            try:
                assets = await self._index(client, "assets/", "name", folder)
            except ConnectorError as exc:
                if exc.status == 401:
                    raise
                assets = self._indexes[("assets/", "name")] = {}  # unreadable assets: findings go unlinked
            asset_id = _uuid((assets.get(str(record["asset"]).strip().lower()) or {}).get("id"))
            if asset_id:
                create["assets"] = [asset_id]
        return await self._upsert(client, "vulnerabilities/", external, "name", update, create, "vulnerability", folder)

    async def _framework(self, client: httpx.AsyncClient, urn: str) -> dict[str, Any] | None:
        """A loaded framework by URN (the frameworks list has no URN filter: read once per push)."""
        if self._frameworks is None:
            self._frameworks = await self._list(client, "frameworks/", what="frameworks")
        return next((f for f in self._frameworks
                     if str(f.get("urn") or "").lower() == urn.lower() and _uuid(f.get("id"))), None)

    async def _push_assessment(self, client: httpx.AsyncClient, record: dict[str, Any], external: str | None,
                               folder: str | None) -> tuple[str, str]:
        try:
            data = AssessmentPush.model_validate(record)
        except ValidationError as exc:
            raise _RecordError(f"Not a valid self-assessment record: {exc.errors()[0]['msg']}") from exc
        framework = await self._framework(client, data.framework_urn)
        if framework is None:
            raise _RecordError(f"{data.framework_urn} is not loaded in CISO Assistant - an administrator of CISO "
                               "Assistant can import the library (Catalog > Libraries); Atrium never imports libraries",
                               status=404)
        framework_id = _uuid(framework["id"]) or ""
        body: dict[str, Any] = {"name": data.name[:NAME], "selected_implementation_groups": [data.level]}
        current = None
        if _uuid(external):
            current = await self._get(client, "compliance-assessments/", _uuid(external) or "", "compliance assessment")
            if current is not None and _id(current.get("framework")) != framework_id:
                current = None  # the linked assessment is of another framework: write a new one
        if current is None:
            adopted = await self._adoptable(client, "compliance-assessments/", "name", body["name"], folder)
            if adopted and _id(adopted.get("framework")) == framework_id:
                current = adopted
        if current is not None:
            assessment_id = _uuid(current["id"]) or ""
            body["observation"] = merge_text(current.get("observation"), data.summary)
            if not await self._patch(client, "compliance-assessments/", assessment_id, body, "compliance assessment"):
                raise _RecordError("The compliance assessment disappeared from CISO Assistant during the sync", status=404)
            action = "updated"
        else:
            create = {**body, "framework": framework_id, "version": "1.0", "status": "in_progress",
                      "observation": merge_text(None, data.summary), **({"folder": folder} if folder else {})}
            assessment_id = await self._create(client, "compliance-assessments/", create, "compliance assessment", "name")
            action = "created"
        problems = await self._write_requirements(client, assessment_id, framework_id, data)
        if problems:
            shown = "; ".join(problems[:5]) + (f" (and {len(problems) - 5} more)" if len(problems) > 5 else "")
            raise _RecordError(f"{len(problems)} requirement(s) could not be written: {shown}", status=400)
        return assessment_id, action

    async def _write_requirements(self, client: httpx.AsyncClient, assessment_id: str, framework_id: str,
                                  data: AssessmentPush) -> list[str]:
        """Write the hub's scored requirements; leave the others (and unchanged ones) alone."""
        nodes = await self._list(client, "requirement-nodes/", {"framework": framework_id}, what="requirement nodes")
        by_ref: dict[str, str] = {}
        for node in nodes:
            if node.get("assessable") and _uuid(node.get("id")) and _id(node.get("framework")) in (None, framework_id):
                by_ref.setdefault(hub_ref(node.get("ref_id"), data.ref_aliases), _uuid(node["id"]) or "")
        rows = await self._list(client, "requirement-assessments/", {"compliance_assessment": assessment_id},
                                what="requirement assessments")
        by_node = {_id(r.get("requirement")): r for r in rows
                   if _uuid(r.get("id")) and _id(r.get("compliance_assessment")) in (None, assessment_id)}
        if data.requirements and not by_node:
            return ["CISO Assistant has no requirement assessments for this compliance assessment yet - run the flow "
                    "again in a moment"]
        problems = []
        for requirement in data.requirements:
            row = by_node.get(by_ref.get(requirement.ref_id, ""))
            if row is None:
                problems.append(f"{requirement.ref_id} is not in CISO Assistant's framework")
                continue
            desired: dict[str, Any] = {"result": requirement.result, "status": "done"}
            if requirement.result != "not_applicable":
                desired.update({"is_scored": True, "score": requirement.score,
                                "documentation_score": requirement.documentation_score})
            if requirement.observation or MARKER in str(row.get("observation") or ""):
                desired["observation"] = merge_text(row.get("observation"), requirement.observation)
            if all(row.get(k) == v for k, v in desired.items()):
                continue
            try:
                await self.request_json(client, "PATCH", f"requirement-assessments/{_uuid(row['id'])}/", json=desired,
                                        what=f"update requirement {requirement.ref_id}")
            except ConnectorError as exc:
                if exc.status in (None, 401, 403):
                    raise
                problems.append(f"{requirement.ref_id}: {exc.message}")
        return problems
