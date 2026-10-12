"""The audit pack of a framework self-assessment: a ZIP an auditor can read offline and verify.

    summary.html          self-contained and printable: scores per level, function and category, the conformity
                          verdict per level with its reasons, gaps and key measures (no scripts, no external files)
    requirements.csv      one row per requirement with both maturity scores, N/A, owner, notes and evidence
    evidence/index.csv    every evidence link of the assessment
    evidence/controls.json  the hub controls' latest automated results (status, detail, evidence lines) and the CyFun
                          requirements they are mapped to
    evidence/items.json   metadata of the linked policies, risks, URLs and files (never their content)
    assessment.json       the assessment and its evaluation as data
    manifest.json         SHA-256 and size of every file above, the framework source and who exported it
    SHA256SUMS            the same hashes for ``sha256sum -c``

No secrets: the pack holds assessment data, control results and metadata only, and every text taken from the hub's
state passes through the connector SDK's redaction (credential-looking key=value pairs masked).
"""

from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import time
import zipfile
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from ... import people as people_app
from ...connectors.base import redact
from ..baseline import CONTROLS_BY_ID
from . import LEVEL_NAMES, load, mapping
from .assessments import FrameworkAssessment, control_states, evaluation, evidence_view
from .scoring import fmt, requirement_maturity

if TYPE_CHECKING:
    from ...core import Hub

FORMULA_START = ("=", "+", "-", "@", "\t", "\r")
VERDICTS = {"met": "Met", "not_met": "Not met", "incomplete": "Incomplete"}


def _when(ts: float | None) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if ts else ""


def _cell(value: Any) -> str:
    """A CSV cell that spreadsheet programs never run as a formula."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(FORMULA_START) else text


def _csv(header: list[str], rows: list[list[Any]]) -> bytes:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(header)
    writer.writerows([[_cell(v) for v in row] for row in rows])
    return ("﻿" + out.getvalue()).encode("utf-8")  # BOM: spreadsheet programs read it as UTF-8


def _clean(value: Any) -> Any:
    """Hub state as data for the pack: strings redacted, recursively."""
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, str):
        return redact(value)
    return value


CSS = """
body{font:13px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:#1d2330;margin:24px;max-width:1100px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px;border-bottom:1px solid #ccd;padding-bottom:4px}
h3{font-size:14px;margin:16px 0 6px}.muted{color:#5b6475}.notice{background:#f4f6fa;border:1px solid #d9deea;
padding:8px 12px;border-radius:6px;margin:12px 0}table{border-collapse:collapse;width:100%;margin:6px 0 12px}
th,td{border:1px solid #d9deea;padding:4px 6px;text-align:left;vertical-align:top}th{background:#f4f6fa}
td.num{text-align:right;font-variant-numeric:tabular-nums}.met{color:#106b2e;font-weight:600}
.not_met{color:#a31515;font-weight:600}.incomplete{color:#8a5a00;font-weight:600}.chip{display:inline-block;
border:1px solid #c5ccdb;border-radius:9px;padding:0 6px;margin-right:3px;font-size:11px}
@media print{body{margin:0}h2{break-after:avoid}tr{break-inside:avoid}}
"""


def _table(header: list[str], rows: list[list[Any]], numeric: set[int] | None = None) -> str:
    numeric = numeric or set()
    head = "".join(f"<th>{html.escape(h)}</th>" for h in header)
    body = "".join("<tr>" + "".join(f'<td class="num">{html.escape(str(c))}</td>' if i in numeric
                                     else f"<td>{html.escape(str(c))}</td>" for i, c in enumerate(row)) + "</tr>"
                   for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def summary_html(assessment: FrameworkAssessment, result: dict[str, Any], meta: dict[str, Any]) -> str:
    catalog = load(assessment.framework)
    e = html.escape
    parts = [
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        f"<title>{e(catalog.short_name)} self-assessment - {e(assessment.name)}</title><style>{CSS}</style></head><body>",
        f"<h1>{e(catalog.name)} self-assessment</h1>",
        f"<div class=\"muted\">{e(assessment.name)} &middot; target level {e(LEVEL_NAMES[assessment.target_level])} "
        f"&middot; status {e(assessment.status.replace('_', ' '))} &middot; exported {e(meta['exported_at'])} by "
        f"{e(meta['exported_by'])}</div>",
        "<div class=\"notice\">",
        f"<p>{e(catalog.data['notice'])} Requirement text: <a href=\"{e(catalog.data['text_url'])}\">"
        f"{e(catalog.data['text_url'])}</a>.</p>",
        f"<p>{e(result['method']['source'])} Scoring: {e(result['method']['calculation'])}; N/A counts as "
        f"{fmt(result['method']['na_counts_as'])}; a missing documentation maturity counts as 1. Scores are a "
        "self-assessment by people; Atrium's automated control results are listed as evidence only.</p>",
        f"<p>Framework source: {e(catalog.data['source']['library_name'])} (library "
        f"{e(catalog.data['source']['library_urn'])}, version {e(str(catalog.data['source']['version']))}, "
        f"{e(catalog.data['source']['publication_date'])}).</p>",
    ]
    window = catalog.transition()
    if window:
        parts.append(f"<p>{e(window['note'])}</p>")
    parts.append("</div>")
    if assessment.scope:
        parts += ["<h2>Scope</h2>", f"<p>{e(assessment.scope)}</p>"]

    progress = result["progress"]
    parts += ["<h2>Conformity</h2>",
              f"<p>Target level: <b>{e(result['target_name'])}</b> &mdash; verdict "
              f"<span class=\"{e(result['verdict'])}\">{e(VERDICTS[result['verdict']])}</span>. "
              f"{progress['scored']} scored, {progress['na']} N/A, {progress['unscored']} not scored of "
              f"{progress['total']} requirements in scope ({progress['percent']}% done).</p>"]
    rows = []
    for level in result["levels"]:
        groups = level["groups"]
        rows.append([level["name"] + ("" if level["targeted"] else " (not targeted)"), VERDICTS[level["verdict"]],
                     fmt(groups[level["level"]]["maturity"]), fmt(groups[f"{level['level']}K"]["min_maturity"]),
                     groups[level["level"]]["na"], "; ".join(level["reasons"]) or "All rules met"])
    parts.append(_table(["Level", "Verdict", "Maturity", "Lowest key measure", "N/A", "Reasons"], rows, {2, 3, 4}))
    for level in result["levels"]:
        if not level["targeted"]:
            continue
        parts.append(f"<h3>{e(level['name'])}: rules</h3>")
        parts.append(_table(["Rule", "Result", "Value", "Threshold", "Reasons"],
                            [[r["label"], "met" if r["ok"] else "not met",
                              fmt(r["value"]) if isinstance(r["value"], float) else ("" if r["value"] is None else r["value"]),
                              fmt(r["threshold"]) if isinstance(r["threshold"], float) else r["threshold"],
                              "; ".join(r["reasons"])] for r in level["rules"]], {2, 3}))

    parts.append("<h2>Scores per group</h2>")
    group_rows = []
    for level in result["levels"]:
        for group, scores in level["groups"].items():
            group_rows.append([group, fmt(scores["implementation"]), fmt(scores["documentation"]),
                               fmt(scores["maturity"]), fmt(scores["min_maturity"]), scores["scored"], scores["total"],
                               scores["na"], fmt(catalog.group_target(group))])
    parts.append(_table(["Group", "Implementation", "Documentation", "Maturity", "Lowest", "Scored", "Of", "N/A",
                         "Target"], group_rows, {1, 2, 3, 4, 5, 6, 7, 8}))
    parts.append("<h2>Scores per function</h2>")
    parts.append(_table(["Function", "Title", "Implementation", "Documentation", "Maturity", "Scored", "Of"],
                        [[f["id"], f["title"], fmt(f["implementation"]), fmt(f["documentation"]), fmt(f["maturity"]),
                          f["scored"], f["total"]] for f in result["functions"]], {2, 3, 4, 5, 6}))
    parts.append("<h2>Scores per category</h2>")
    parts.append(_table(["Category", "Title", "Maturity", "Target", "Below target", "Scored", "Of"],
                        [[c["id"], c["title"], fmt(c["maturity"]), fmt(c["target"]), "yes" if c["below"] else "",
                          c["scored"], c["total"]] for c in result["categories"]], {2, 3, 5, 6}))
    parts.append("<h2>Key measures</h2>")
    parts.append(_table(["Requirement", "Title", "Maturity", "Threshold", "Result"],
                        [[k["ref_id"], k["title"], fmt(k["maturity"]), fmt(k["threshold"]),
                          "N/A (not allowed)" if k["na"] else ("met" if k["ok"] else
                                                               "not scored" if k["maturity"] is None else "below")]
                         for k in result["key_measures"]], {2, 3}))
    parts.append("<h2>Gaps</h2>")
    if result["gaps"]:
        parts.append(_table(["Requirement", "Title", "Maturity", "Target", "Key measure"],
                            [[g["ref_id"], g["title"], fmt(g["maturity"]), fmt(g["target"]),
                              "yes" if g["key_measure"] else ""] for g in result["gaps"]], {2, 3}))
    else:
        parts.append("<p>No scored requirement is below its target.</p>")
    if result["unscored"]:
        parts.append(f"<p>Not scored yet ({len(result['unscored'])}): {e(', '.join(result['unscored']))}</p>")
    na = [(ref, entry) for ref, entry in sorted(assessment.requirements.items()) if entry.na]
    parts.append("<h2>Requirements marked N/A</h2>")
    parts.append(_table(["Requirement", "Justification"], [[ref, entry.na_justification] for ref, entry in na])
                 if na else "<p>None.</p>")
    parts.append(f"<p class=\"muted\">Files in this pack and their SHA-256 are listed in manifest.json and "
                 f"SHA256SUMS. Generated by Atrium {e(meta['generator'])}.</p></body></html>")
    return "".join(parts)


def build(hub: "Hub", assessment: FrameworkAssessment, actor: str) -> tuple[bytes, str]:
    """(zip bytes, file name)."""
    catalog = load(assessment.framework)
    result = evaluation(assessment)
    states = control_states(hub)
    people = {p.id: p for p in people_app.all_people(hub)}
    now = time.time()
    meta = {"exported_at": _when(now), "exported_by": actor, "generator": __import__("hub").__version__}

    rows, evidence_rows, items = [], [], {}
    for requirement in catalog.requirements:
        entry = assessment.requirements.get(requirement.ref_id)
        owner = people.get(entry.owner_person_id) if entry and entry.owner_person_id else None
        links = [evidence_view(hub, link, states) for link in (entry.evidence if entry else [])]
        rows.append([requirement.ref_id, requirement.function, requirement.category, requirement.subcategory,
                     requirement.title, " ".join(requirement.tags), LEVEL_NAMES[requirement.level()],
                     "yes" if requirement.in_level(assessment.target_level) else "no",
                     "yes" if requirement.key_measure(assessment.target_level) else "",
                     entry.implementation if entry and entry.implementation else "",
                     entry.documentation if entry and entry.documentation else "",
                     fmt(requirement_maturity(catalog, entry)) if entry else "-", "yes" if entry and entry.na else "",
                     entry.na_justification if entry else "", owner.display_name if owner else "",
                     entry.notes if entry else "", "; ".join(f"{link['kind']}:{link['ref']}" for link in links),
                     entry.updated_by if entry else "", _when(entry.updated_at) if entry else "", catalog.data["text_url"]])
        for link in links:
            evidence_rows.append([requirement.ref_id, link["kind"], link["ref"], link.get("title", ""),
                                  link.get("status", ""), link.get("added_by") or "", _when(link.get("added_at"))])
            if link["kind"] != "control":
                items[f"{link['kind']}:{link['ref']}"] = {k: v for k, v in link.items() if k not in ("added_by", "added_at")}

    controls = []
    for control_id, rows_for in sorted(_mapped_controls(catalog.id).items()):
        control, state = CONTROLS_BY_ID[control_id], states.get(control_id)
        controls.append({"id": control_id, "title": control.title, "family": control.family,
                         "status": state.status if state else "manual", "detail": state.detail if state else "",
                         "evidence": state.evidence if state else [], "evaluated_at": state.evaluated_at if state else None,
                         "set_by_hand": bool(state and state.manual), "refs": control.refs,
                         "requirements": rows_for})

    files: dict[str, bytes] = {
        "summary.html": summary_html(assessment, result, meta).encode("utf-8"),
        "requirements.csv": _csv(["ref_id", "function", "category", "subcategory", "title", "tags", "level", "in_scope",
                                  "key_measure", "implementation", "documentation", "maturity", "na",
                                  "na_justification", "owner", "notes", "evidence", "updated_by", "updated_at",
                                  "requirement_text"], rows),
        "evidence/index.csv": _csv(["ref_id", "kind", "ref", "title", "status", "added_by", "added_at"], evidence_rows),
        "evidence/controls.json": _json(_clean({"note": "Automated results of Atrium's hub controls at export time; "
                                                        "the fit of each mapping is analyst judgement.",
                                                "controls": controls})),
        "evidence/items.json": _json(_clean({"note": "Metadata of the linked evidence; content is not included.",
                                             "items": list(items.values())})),
        "assessment.json": _json(_clean({"assessment": assessment.model_dump(mode="json"), "evaluation": result,
                                         "framework": {k: catalog.data[k] for k in ("id", "name", "edition", "source",
                                                                                     "conformity", "notice")}})),
    }
    manifest = {"generator": f"Atrium {meta['generator']}", "exported_at": meta["exported_at"], "exported_by": actor,
                "assessment_id": assessment.id, "framework": catalog.id,
                "framework_source": {k: catalog.data["source"][k] for k in ("library_urn", "version",
                                                                             "publication_date", "url", "sha256")},
                "files": [{"path": path, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
                          for path, data in files.items()]}
    files["manifest.json"] = _json(manifest)
    files["SHA256SUMS"] = "".join(f"{f['sha256']}  {f['path']}\n" for f in manifest["files"]).encode()
    buffer = io.BytesIO()
    stamp = datetime.fromtimestamp(now, timezone.utc).timetuple()[:6]
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, data in files.items():
            info = zipfile.ZipInfo(path, date_time=stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)
    day = datetime.fromtimestamp(now, timezone.utc).strftime("%Y%m%d")
    return buffer.getvalue(), f"atrium-{catalog.id}-{assessment.id}-{day}.zip"


def _mapped_controls(framework_id: str) -> dict[str, list[dict[str, str]]]:
    out: dict[str, list[dict[str, str]]] = {}
    for ref, rows in mapping.by_requirement(framework_id).items():
        for row in rows:
            out.setdefault(row["control"], []).append({"ref_id": ref, "fit": row["fit"]})
    return out


def _json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False, default=str) + "\n").encode("utf-8")
