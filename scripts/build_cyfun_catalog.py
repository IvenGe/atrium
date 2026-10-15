#!/usr/bin/env python3
"""Build Atrium's CyberFundamentals (CyFun) catalogs from the CISO Assistant library files.

    python scripts/build_cyfun_catalog.py [--cache-dir DIR] [--offline] [--check]

Downloads (into a cache directory outside the repository; never committed):

- the CyFun 2025 and CyFun 2023 libraries that ship with CISO Assistant (intuitem/ciso-assistant-community,
  backend/library/libraries/cyfun2025.yaml and ccb-cff-2023-03-01.yaml), for requirement ids, tree, level tags,
  key measures, management aspects, the maturity scale and the conformity rules;
- the NIST Cybersecurity Framework 2.0 and 1.1 data from NIST's Cybersecurity and Privacy Reference Tool (CPRT), for
  the titles: category names and subcategory statements (US government works, public domain).

Writes hub/grc/frameworks/cyfun2025.json and cyfun2023.json, plus tests/data/cyfun_library_fingerprints.json (short
SHA-256 fingerprints of every requirement text of the libraries, so the tests can prove no CCB text is shipped
without shipping it).

Licensing: the CCB's requirement text, descriptions and annotations are NOT copied. Per requirement the catalog keeps
only its ref_id, its function / category / subcategory ids, its level tags and a title taken from the NIST CSF
subcategory it belongs to (or a short neutral title written for Atrium where the NIST statement equals a library text).
The requirement text itself is on https://cyfun.eu. The build refuses to write a catalog in which any title equals a
library text or contains one.

Checks (the build fails loudly when the library changes in a way a person must review): assessable requirement
counts, the four-level tree, id formats, cumulative levels (B => I => E, BK => IK => EK, BG => IG => EG, XK/XG => X),
key measures present at every level, and the conformity rules (outcomes_definition) and group targets equal to the
values Atrium's scoring code was written for.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "hub" / "grc" / "frameworks"
FINGERPRINTS = ROOT / "tests" / "data" / "cyfun_library_fingerprints.json"
CA_RAW = "https://raw.githubusercontent.com/intuitem/ciso-assistant-community/main/backend/library/libraries/"
CPRT = "https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/{}/export/json?element=all"
NIST_CSF = {"csf_2_0_0": ("NIST Cybersecurity Framework 2.0 (NIST CSWP 29)", "https://doi.org/10.6028/NIST.CSWP.29"),
            "csf_1_1_0": ("NIST Framework for Improving Critical Infrastructure Cybersecurity 1.1",
                          "https://doi.org/10.6028/NIST.CSWP.04162018")}

LEVELS = (("B", "Basic"), ("I", "Important"), ("E", "Essential"))
GROUPS = ("B", "I", "E", "BK", "IK", "EK", "BG", "IG", "EG")
SCALE_NAMES = {1: "Initial", 2: "Repeatable", 3: "Defined", 4: "Managed", 5: "Optimizing"}
PREFIX = re.compile(r"^(BASIC|IMPORTANT|ESSENTIAL)_")
REQ_ID = re.compile(r"^(?P<cat>(?P<fn>[A-Z]{2})\.[A-Z]{2})-(?P<sub>\d{1,2})\.(?P<n>\d{1,2})$")

# The conformity rules Atrium's scoring implements (hub/grc/frameworks/scoring.py), as written in the CyFun 2025
# library's outcomes_definition. The CCB's own documents were unreachable (HTTP 403); these are the library's values.
EXPECTED_OUTCOMES = {
    "basic_maturity": 'groups["B"].maturity_score >= 2.5',
    "basic_key_measures": 'groups["BK"].min_maturity_score >= 2.5',
    "basic_exclusions": 'groups["B"].not_applicable_count <= 1 && groups["BK"].not_applicable_count == 0',
    "important_maturity": 'groups["I"].maturity_score >= 3.0',
    "important_key_measures": 'groups["IK"].min_maturity_score >= 3.0',
    "important_exclusions": 'groups["I"].not_applicable_count <= 3 && groups["IK"].not_applicable_count == 0',
    "essential_maturity": 'groups["E"].maturity_score >= 3.5',
    "essential_key_measures": 'groups["EK"].min_maturity_score >= 3.0',
    "essential_categories": "sections.all(s, sections[s].depth != 2 || sections[s].maturity_score >= 3.0)",
    "essential_exclusions": ('groups["E"].not_applicable_count <= 5 && groups["EK"].not_applicable_count == 0 '
                             '&& groups["EG"].not_applicable_count == 0'),
}
CONFORMITY = {
    "B": {"maturity_min": 2.5, "key_measure_min": 2.5, "category_min": None, "na_max": 1, "na_max_key": 0,
          "na_max_management": None},
    "I": {"maturity_min": 3.0, "key_measure_min": 3.0, "category_min": None, "na_max": 3, "na_max_key": 0,
          "na_max_management": None},
    "E": {"maturity_min": 3.5, "key_measure_min": 3.0, "category_min": 3.0, "na_max": 5, "na_max_key": 0,
          "na_max_management": 0},
}
GROUP_TARGETS = {"B": 2.5, "BK": 2.5, "BG": 2.5, "I": 3.0, "IK": 3.0, "IG": 3.0, "E": 3.0, "EK": 3.0, "EG": 3.0}

EDITIONS: dict[str, dict[str, Any]] = {
    "cyfun2025": {
        "file": "cyfun2025.yaml", "nist": "csf_2_0_0", "requirements": 218, "functions": 6,
        "name": "CyberFundamentals 2025", "short_name": "CyFun 2025", "edition": "2025", "based_on": "NIST CSF 2.0",
        "management_aspects": True, "outcomes": True,
        "corrections": {}, "own_titles": {},
        "transition": None,
    },
    "cyfun2023": {
        "file": "ccb-cff-2023-03-01.yaml", "nist": "csf_1_1_0", "requirements": 219, "functions": 5,
        "name": "CyberFundamentals 2023", "short_name": "CyFun 2023", "edition": "2023", "based_on": "NIST CSF 1.1",
        "management_aspects": False, "outcomes": False,
        # obvious typos in the library's ref_ids (the parent node is PR.AC-3)
        "corrections": {"R.AC-3.4": "PR.AC-3.4", "R.AC-3.5": "PR.AC-3.5"},
        # the NIST CSF 1.1 statement of ID.BE-3 equals the library text of requirement ID.BE-3.1: a short title of our
        # own for the subcategory and its requirements
        "own_titles": {"ID.BE-3": "Priorities for mission, objectives and activities set and communicated"},
        # CISO Assistant's CyFun 2023 -> 2025 mapping, aligned on the CCB transposition table (ids and relationships)
        "mapping": {"file": "mapping-ccb-cff-2023-03-01-and-ccb-cyfun2025.yaml", "target": "cyfun2025"},
        # BELAC, transition plan CyberFundamentals (10.12.2025)
        "transition": {"assess_until": "2027-04-18", "valid_until": "2028-04-18",
                       "note": "CyFun 2023 may still be applied, verified and certified until 18 April 2027; its "
                               "statements and certificates stay valid until 18 April 2028 at the latest. New "
                               "assessments should use CyFun 2025."},
    },
}


class BuildError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BuildError(message)


# -- sources -------------------------------------------------------------------------------------------------------


def default_cache() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "atrium" / "cyfun-build"


def fetch(url: str, target: Path, offline: bool) -> bytes:
    if target.exists() and (offline or target.stat().st_size > 0):
        return target.read_bytes()
    require(not offline, f"{target.name} is not in the cache and --offline was given")
    print(f"downloading {url}", file=sys.stderr)
    response = httpx.get(url, timeout=120, follow_redirects=False)
    require(response.status_code == 200, f"{url}: HTTP {response.status_code}")
    target.write_bytes(response.content)
    return response.content


def sha256(data: bytes | str) -> str:
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


def norm(text: Any) -> str:
    """Text compared case-, punctuation- and whitespace-insensitively."""
    return re.sub(r"[\W_]+", " ", str(text or "").casefold()).strip()


def fingerprint(text: Any) -> str:
    return sha256(norm(text))[:16]


def library_texts(nodes: list[dict[str, Any]], framework: dict[str, Any], translations: bool = True) -> set[str]:
    """The CCB's own texts a title must not reproduce: every requirement's (assessable node's) name, description and
    annotation and the framework description, in English and the translations. (The subcategory and category nodes
    above them mostly repeat the NIST CSF statements, which are public domain - those are what the titles use.)"""
    texts: set[str] = set()
    for item in [framework, *(n for n in nodes if n.get("assessable"))]:
        for key in ("name", "description", "annotation", "typical_evidence"):
            if item.get(key):
                texts.add(norm(item[key]))
        for translation in (item.get("translations") or {}).values() if translations else ():
            for key in ("name", "description", "annotation", "typical_evidence"):
                if isinstance(translation, dict) and translation.get(key):
                    texts.add(norm(translation[key]))
    return {t for t in texts if t}


def nist_elements(raw: bytes) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    elements = json.loads(raw)["response"]["elements"]["elements"]
    of = lambda kind, field: {e["element_identifier"]: str(e[field]).strip() for e in elements if e["element_type"] == kind}
    return of("function", "title"), of("category", "title"), of("subcategory", "text")


# -- building ------------------------------------------------------------------------------------------------------


def hub_ref(ref: str, corrections: dict[str, str]) -> str:
    """CISO Assistant's ref_id -> Atrium's: CyFun 2023's level prefixes (BASIC_, IMPORTANT_) become tags."""
    ref = PREFIX.sub("", ref.strip())
    return corrections.get(ref, ref)


def check_tags(ref: str, tags: list[str], management: bool) -> None:
    allowed = set(GROUPS if management else GROUPS[:6])
    require(set(tags) <= allowed, f"{ref}: unknown level tags {sorted(set(tags) - allowed)}")
    require(any(t in tags for t in ("B", "I", "E")), f"{ref}: no level tag")
    rules = [("B", "I"), ("I", "E"), ("BK", "IK"), ("IK", "EK"), ("BG", "IG"), ("IG", "EG"),
             ("BK", "B"), ("IK", "I"), ("EK", "E"), ("BG", "B"), ("IG", "I"), ("EG", "E")]
    for has, needs in rules:
        require(has not in tags or needs in tags, f"{ref}: tagged {has} but not {needs} - levels are not cumulative")


def check_outcomes(framework: dict[str, Any]) -> None:
    found = {o["ref_id"]: re.sub(r"\s+", " ", o["expression"]).strip() for o in framework.get("outcomes_definition") or []}
    for key, expression in EXPECTED_OUTCOMES.items():
        require(found.get(key) == expression,
                f"conformity rule {key} changed in the library: {found.get(key)!r} (Atrium implements {expression!r}) "
                "- review hub/grc/frameworks/scoring.py and EXPECTED_OUTCOMES")
    targets = {g["ref_id"]: g.get("target_score") for g in framework.get("implementation_groups_definition") or []}
    for group, target in GROUP_TARGETS.items():
        require(targets.get(group) == target, f"group {group} target changed: {targets.get(group)} (expected {target})")
    require(framework.get("target_score") == 3.0, "the framework target score changed")
    # scoring.py counts an N/A requirement at the target score (3.0) in every average and minimum, as the library does
    require(framework.get("anchor_na_to_target") is True, "the library no longer anchors N/A requirements to the target")


def build(key: str, raw: bytes, nist_raw: bytes, source_url: str,
          nist_url: str) -> tuple[dict[str, Any], list[str], dict[str, str]]:
    """The catalog, the fingerprints of the library's texts, and node URN -> Atrium ref_id of every requirement."""
    spec = EDITIONS[key]
    library = yaml.safe_load(raw)
    framework = library["objects"]["framework"]
    nodes = framework["requirement_nodes"]
    by_urn = {n["urn"]: n for n in nodes}
    fn_titles, cat_titles, sub_titles = nist_elements(nist_raw)
    texts = library_texts(nodes, framework)

    require(framework.get("min_score") == 1 and framework.get("max_score") == 5, "the maturity scale is not 1-5")
    names = {s["score"]: s["name"] for s in framework.get("scores_definition") or []}
    require(names == SCALE_NAMES, f"the maturity level names changed: {names}")
    require(framework.get("score_calculation_method") == "average_of_averages",
            f"{key}: the score calculation method changed: {framework.get('score_calculation_method')}")
    if spec["outcomes"]:
        check_outcomes(framework)
    else:
        require(not framework.get("outcomes_definition"), f"{key}: the library now defines conformity rules - use them")

    functions: list[dict[str, Any]] = []
    categories: list[dict[str, Any]] = []
    subcategories: list[dict[str, Any]] = []
    requirements: list[dict[str, Any]] = []
    seen: set[str] = set()
    own_titles_used: list[str] = []
    urns: dict[str, str] = {}

    def nist_title(table: dict[str, str], ident: str, what: str) -> str:
        title = table.get(ident, "")
        require(bool(title), f"{key}: NIST CSF has no {what} {ident}")
        return title

    for node in nodes:
        depth, ref = int(node["depth"]), str(node["ref_id"]).strip()
        parent = by_urn.get(node.get("parent_urn") or "")
        require(depth == 1 or (parent is not None and int(parent["depth"]) == depth - 1),
                f"{key}: {ref} is not under a node one level up")
        require(bool(node.get("assessable")) == (depth == 4), f"{key}: {ref} assessable={node.get('assessable')} at depth {depth}")
        if depth == 1:
            functions.append({"id": ref, "title": nist_title(fn_titles, ref, "function").title()})
        elif depth == 2:
            require(ref.startswith(parent["ref_id"] + "."), f"{key}: category {ref} not in function {parent['ref_id']}")
            categories.append({"id": ref, "function": parent["ref_id"], "title": nist_title(cat_titles, ref, "category")})
        elif depth == 3:
            require(ref.startswith(parent["ref_id"] + "-"), f"{key}: subcategory {ref} not in {parent['ref_id']}")
            title = spec["own_titles"].get(ref) or nist_title(sub_titles, ref, "subcategory")
            own_titles_used += [ref] if ref in spec["own_titles"] else []
            subcategories.append({"id": ref, "category": parent["ref_id"], "title": title})
        else:
            hub_id = hub_ref(ref, spec["corrections"])
            match = REQ_ID.match(hub_id)
            require(match is not None, f"{key}: unexpected requirement id {ref}")
            sub_id = parent["ref_id"]
            require(hub_id.rsplit(".", 1)[0] == sub_id, f"{key}: {hub_id} is not under subcategory {sub_id}")
            require(hub_id not in seen, f"{key}: duplicate requirement {hub_id}")
            seen.add(hub_id)
            urns[str(node["urn"]).strip().lower()] = hub_id
            tags = [str(t) for t in node.get("implementation_groups") or []]
            tags = [g for g in GROUPS if g in tags] + sorted(set(tags) - set(GROUPS))
            check_tags(hub_id, tags, spec["management_aspects"])
            prefix = PREFIX.match(ref)  # CyFun 2023's BASIC_ / IMPORTANT_ prefix is the lowest level tag
            require(prefix is None or next(t for t in "BIE" if t in tags) == prefix.group(1)[0],
                    f"{key}: {ref} is prefixed {prefix.group(1) if prefix else ''} but tagged {tags}")
            title = spec["own_titles"].get(sub_id) or nist_title(sub_titles, sub_id, "subcategory")
            requirements.append({"ref_id": hub_id, "function": match["fn"], "category": match["cat"],
                                 "subcategory": sub_id, "tags": tags, "title": title})

    require(len(requirements) == spec["requirements"],
            f"{key}: {len(requirements)} assessable requirements, expected {spec['requirements']} - review the library")
    require(len(functions) == spec["functions"], f"{key}: {len(functions)} functions")
    require(sorted(own_titles_used) == sorted(spec["own_titles"]), f"{key}: own titles for unknown subcategories")
    counts = {g: sum(1 for r in requirements if g in r["tags"]) for g in GROUPS
              if spec["management_aspects"] or not g.endswith("G")}
    for level, _ in LEVELS:
        require(counts[level + "K"] > 0, f"{key}: no key measures at level {level}")
    require(counts["B"] < counts["I"] < counts["E"] == len(requirements), f"{key}: level counts {counts}")

    for title in [r["title"] for r in requirements] + [s["title"] for s in subcategories] + [c["title"] for c in categories]:
        t = norm(title)
        require(t not in texts, f"{key}: the title {title!r} equals a library text - give it an own title")
        require(not any(len(x) > 40 and x in t for x in texts), f"{key}: the title {title!r} contains a library text")
        require(0 < len(title) <= 240, f"{key}: title length {len(title)}")  # NIST statements, verbatim

    nist_name, nist_doc = NIST_CSF[spec["nist"]]
    catalog = {
        "id": key,
        "name": spec["name"],
        "short_name": spec["short_name"],
        "edition": spec["edition"],
        "publisher": "Centre for Cybersecurity Belgium (CCB)",
        "based_on": spec["based_on"],
        "text_url": "https://cyfun.eu",
        "notice": ("Requirement ids, structure and level tags of the CCB CyberFundamentals framework. The requirement "
                   "text, guidance and annotations are the CCB's and are not included: read them on cyfun.eu. Titles "
                   f"are the {nist_name} category names and subcategory statements (a US government work, public "
                   "domain) or short titles written for Atrium."),
        "source": {
            "library_urn": library["urn"], "framework_urn": framework["urn"], "library_ref_id": library["ref_id"],
            "library_name": library["name"], "version": library["version"],
            "publication_date": str(library["publication_date"]), "provider": library.get("provider"),
            "packager": library.get("packager"), "copyright": library.get("copyright"),
            "url": source_url, "sha256": sha256(raw),
            "titles": {"name": nist_name, "document": nist_doc, "url": nist_url, "sha256": sha256(nist_raw)},
        },
        "generated_by": "scripts/build_cyfun_catalog.py",
        "generated_on": date.today().isoformat(),
        "transition": spec["transition"],
        "corrections": [{"library_ref_id": k, "ref_id": v, "reason": "typo in the library's ref_id (level prefix removed)"}
                        for k, v in spec["corrections"].items()],
        "own_titles": sorted(spec["own_titles"]),
        "levels": [{"id": level, "name": name, "key_measures": level + "K",
                    "management_aspects": level + "G" if spec["management_aspects"] else None} for level, name in LEVELS],
        "scale": {"min": 1, "max": 5, "target": 3.0, "method": "average_of_averages",
                  "levels": [{"score": s, "name": n} for s, n in SCALE_NAMES.items()]},
        "conformity": {
            "source": ("The CyFun 2025 library's outcomes_definition (CISO Assistant library copy; the CCB originals "
                       "were unreachable)" if spec["outcomes"] else
                       "UNVERIFIED: the CyFun 2023 library defines no conformity rules; Atrium applies the CyFun 2025 "
                       "library's rules (CISO Assistant library copy) to CyFun 2023 as well"),
            "verified_against_library": bool(spec["outcomes"]),
            "group_targets": GROUP_TARGETS,
            # how the library's scores are computed (hub/grc/frameworks/scoring.py): an N/A requirement counts at the
            # framework target in every average and minimum; a missing documentation maturity counts as 1
            "na_counts_as": 3.0,
            "na_anchor_verified": bool(spec["outcomes"]),
            "levels": CONFORMITY,
        },
        "counts": {"requirements": len(requirements), "functions": len(functions), "categories": len(categories),
                   "subcategories": len(subcategories), **counts},
        "functions": functions,
        "categories": categories,
        "subcategories": subcategories,
        "requirements": requirements,
    }
    return catalog, sorted({fingerprint(t) for t in library_texts(nodes, framework, translations=False)}), urns


def edition_mapping(raw: bytes, url: str, source: dict[str, Any], urns: dict[str, dict[str, str]],
                    target_key: str) -> dict[str, Any]:
    """The requirement mapping from one edition to the next as [source ref_id, target ref_id, relationship] (no text)."""
    library = yaml.safe_load(raw)
    sets = library["objects"]["requirement_mapping_sets"]
    forward = [m for m in sets if m["source_framework_urn"] == source["framework_urn"]]
    require(len(forward) == 1, f"mapping: expected one set from {source['framework_urn']}, found {len(forward)}")
    pairs: set[tuple[str, str, str]] = set()
    for item in forward[0]["requirement_mappings"]:
        relationship = str(item.get("relationship") or "")
        require(relationship in ("equal", "intersect", "subset", "superset", "not_related"),
                f"mapping: unknown relationship {relationship!r}")
        if relationship == "not_related":
            continue
        src = urns[source["id"]].get(str(item["source_requirement_urn"]).strip().lower())
        dst = urns[target_key].get(str(item["target_requirement_urn"]).strip().lower())
        require(src is not None and dst is not None,
                f"mapping: {item['source_requirement_urn']} -> {item['target_requirement_urn']} is not a requirement")
        pairs.add((src, dst, relationship))
    require(len(pairs) > 150, f"mapping: only {len(pairs)} pairs - review the mapping library")
    return {"target": target_key, "relationship_note": "equal: same requirement; intersect: overlapping requirements",
            "source": {"library_urn": library["urn"], "version": library["version"],
                       "publication_date": str(library["publication_date"]), "provider": library.get("provider"),
                       "url": url, "sha256": sha256(raw),
                       "aligned_on": "the CCB transposition table CyFun 2023 - CyFun 2025 (as stated by the library)"},
            "pairs": [list(p) for p in sorted(pairs)]}


# -- output --------------------------------------------------------------------------------------------------------


def dumps(catalog: dict[str, Any]) -> str:
    """Pretty JSON with one list item per line for the long lists (readable diffs when the library changes)."""
    lines = ["{"]
    keys = list(catalog)
    for index, key in enumerate(keys):
        value = catalog[key]
        comma = "," if index < len(keys) - 1 else ""
        if key in ("functions", "categories", "subcategories", "requirements"):
            items = [json.dumps(v, ensure_ascii=False) for v in value]
            lines.append(f'  "{key}": [')
            lines += [f"    {item}{',' if i < len(items) - 1 else ''}" for i, item in enumerate(items)]
            lines.append(f"  ]{comma}")
        elif key == "edition_mapping":  # one pair per line
            head = json.dumps({k: v for k, v in value.items() if k != "pairs"}, ensure_ascii=False, indent=2)
            pairs = [json.dumps(v, ensure_ascii=False) for v in value["pairs"]]
            lines.append(f'  "{key}": ' + head[:-2].replace("\n", "\n  ") + ",")
            lines.append('    "pairs": [')
            lines += [f"      {item}{',' if i < len(pairs) - 1 else ''}" for i, item in enumerate(pairs)]
            lines += ["    ]", f"  }}{comma}"]
        else:
            text = json.dumps(value, ensure_ascii=False, indent=2).replace("\n", "\n  ")
            lines.append(f'  "{key}": {text}{comma}')
    lines.append("}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--cache-dir", type=Path, default=default_cache(),
                        help="where the downloaded files are kept (outside the repository)")
    parser.add_argument("--offline", action="store_true", help="use the cached files only")
    parser.add_argument("--refresh", action="store_true", help="download again even when cached")
    parser.add_argument("--check", action="store_true",
                        help="build and compare with the committed catalogs (ignoring generated_on); write nothing")
    args = parser.parse_args(argv)
    cache = args.cache_dir.resolve()
    if cache == ROOT or ROOT in cache.parents:
        print("error: the cache directory must be outside the repository (the library files are not committed)",
              file=sys.stderr)
        return 2
    cache.mkdir(parents=True, exist_ok=True)
    if args.refresh:
        for item in cache.iterdir():
            item.unlink()
    fingerprints: dict[str, Any] = {}
    outputs: dict[Path, str] = {}
    catalogs: dict[str, dict[str, Any]] = {}
    urns: dict[str, dict[str, str]] = {}
    try:
        for key, spec in EDITIONS.items():
            url, nist_url = CA_RAW + spec["file"], CPRT.format(spec["nist"])
            raw = fetch(url, cache / spec["file"], args.offline)
            nist_raw = fetch(nist_url, cache / f"nist-{spec['nist']}.json", args.offline)
            catalog, prints, urns[key] = build(key, raw, nist_raw, url, nist_url)
            catalogs[key] = catalog
            fingerprints[key] = {"library_sha256": catalog["source"]["sha256"], "text_fingerprints": prints}
            c = catalog["counts"]
            print(f"{key}: {c['requirements']} requirements (B {c['B']}, I {c['I']}, E {c['E']}; key measures "
                  f"BK {c['BK']}, IK {c['IK']}, EK {c['EK']}), library v{catalog['source']['version']} "
                  f"{catalog['source']['publication_date']}", file=sys.stderr)
        for key, spec in EDITIONS.items():
            if spec.get("mapping"):
                url = CA_RAW + spec["mapping"]["file"]
                raw = fetch(url, cache / spec["mapping"]["file"], args.offline)
                catalogs[key]["edition_mapping"] = edition_mapping(
                    raw, url, {"id": key, "framework_urn": catalogs[key]["source"]["framework_urn"]}, urns,
                    spec["mapping"]["target"])
                print(f"{key}: {len(catalogs[key]['edition_mapping']['pairs'])} mapped requirement pairs to "
                      f"{spec['mapping']['target']}", file=sys.stderr)
        for key, catalog in catalogs.items():
            outputs[OUT_DIR / f"{key}.json"] = dumps(catalog)
    except BuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    note = ("sha256(normalised text)[:16] of every requirement name, description and annotation of the libraries "
            "(English); generated by scripts/build_cyfun_catalog.py")
    outputs[FINGERPRINTS] = json.dumps({"note": note, **fingerprints}, indent=1) + "\n"
    if args.check:
        same = lambda text: re.sub(r'"generated_on": "[^"]*"', "", text)
        stale = [str(p.relative_to(ROOT)) for p, text in outputs.items()
                 if not p.exists() or same(p.read_text(encoding="utf-8")) != same(text)]
        print("up to date" if not stale else "stale: " + ", ".join(stale), file=sys.stderr)
        return 1 if stale else 0
    for path, text in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
