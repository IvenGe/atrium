"""The vendored bridge cores, the "Ask the team" widget and the sidecar bundle templates (contract atrium-bridge/1).

A bridge patch copies the core of the tool's language byte-identical into the tool (bridgegen); only the glue is
written for the tool. cores/MANIFEST.json lists every vendored file with its SHA-256, so Atrium's static checks can
tell a vendored file from a changed one; scripts/build_bridge_cores.py writes it (and pins the widget's hash in each
core), ``--check`` verifies it, and so does the test suite.

| Family | Vendored files (destination name -> template) | Glue skeleton |
| --- | --- | --- |
| python | atrium_bridge_core.py, atrium_bridge.py (adapters), panel.js | glue.py |
| node | atrium-bridge-core.cjs, atrium-bridge-core.mjs, panel.js | glue.cjs / glue.mjs |
| go | atriumbridge/core.go, atriumbridge/panel.js | atrium_glue.go |

The sidecar bundle (subsidiary/sidecar/ in the tool's adapter folder) is rendered by sidecar_bundle(): config.json,
docker-compose.yml, atrium-sidecar.service and README.md, none holding a secret.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping

from .. import contract

ROOT = Path(__file__).resolve().parent
MANIFEST_PATH = ROOT / "cores" / "MANIFEST.json"
PANEL_TEMPLATE = "panel/panel.js"

CORES: dict[str, dict[str, Any]] = {
    "python": {
        "version": "python/1.0.0",
        "dependency": "cryptography",
        "files": {"atrium_bridge_core.py": "python/atrium_bridge_core.py", "atrium_bridge.py": "python/adapters.py",
                  "panel.js": PANEL_TEMPLATE},
        "glue": {"glue.py": "python/glue_skeleton.py"},
        "core": "python/atrium_bridge_core.py",
        "pin": re.compile(r'^PANEL_JS_SHA256 = "([0-9a-f]{64})"', re.M),
        "version_re": re.compile(r'^CORE_VERSION = "([^"]+)"', re.M),
    },
    "node": {
        "version": "node/1.0.0",
        "dependency": None,
        "files": {"atrium-bridge-core.cjs": "node/atrium-bridge-core.cjs",
                  "atrium-bridge-core.mjs": "node/atrium-bridge-core.mjs", "panel.js": PANEL_TEMPLATE},
        "glue": {"glue.cjs": "node/glue_skeleton.cjs", "glue.mjs": "node/glue_skeleton.mjs"},
        "core": "node/atrium-bridge-core.cjs",
        "pin": re.compile(r"^const PANEL_JS_SHA256 = '([0-9a-f]{64})';", re.M),
        "version_re": re.compile(r"^const CORE_VERSION = '([^']+)';", re.M),
    },
    "go": {
        "version": "go/1.0.0",
        "dependency": None,
        "files": {"atriumbridge/core.go": "go/atriumbridge/core.go", "atriumbridge/panel.js": PANEL_TEMPLATE},
        "glue": {"atrium_glue.go": "go/glue_skeleton.go"},
        "core": "go/atriumbridge/core.go",
        "pin": re.compile(r'^\s*PanelJSSHA256 = "([0-9a-f]{64})"', re.M),
        "version_re": re.compile(r'^\s*CoreVersion\s*= "([^"]+)"', re.M),
    },
}
SIDECAR_FILES = {"config.json": "sidecar/config.json", "docker-compose.yml": "sidecar/docker-compose.yml",
                 "atrium-sidecar.service": "sidecar/atrium-sidecar.service", "README.md": "sidecar/README.md"}
PLACEHOLDER = re.compile(r"\{\{([a-z][a-z0-9_]*)\}\}")
SAFE_VALUE = re.compile(r"^[A-Za-z0-9._:/@+=%-]{1,300}$")  # no spaces, quotes, "$", "#", "{" or newlines


def read(template: str) -> bytes:
    path = (ROOT / template).resolve()
    if ROOT not in path.parents:
        raise ValueError("a template path stays inside the templates folder")
    return path.read_bytes()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def panel_js() -> bytes:
    """The vendored widget, as every core serves it."""
    return read(PANEL_TEMPLATE)


def panel_sha256() -> str:
    return sha256(panel_js())


def build_manifest() -> dict[str, Any]:
    """cores/MANIFEST.json as the files on disk make it."""
    cores = {}
    for family, spec in CORES.items():
        cores[family] = {
            "version": spec["version"],
            "stacks": list(contract.CORE_FAMILIES[family]),
            "dependency": spec["dependency"],
            "files": [{"path": dest, "template": src, "sha256": sha256(read(src))} for dest, src in spec["files"].items()],
            "glue": [{"path": dest, "template": src} for dest, src in spec["glue"].items()],
        }
    return {
        "contract": contract.CONTRACT,
        "generator": "scripts/build_bridge_cores.py",
        "panel": {"template": PANEL_TEMPLATE, "sha256": panel_sha256()},
        "cores": cores,
        "sidecar": [{"path": f"subsidiary/sidecar/{dest}", "template": src} for dest, src in SIDECAR_FILES.items()],
    }


def render_manifest(doc: Mapping[str, Any]) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def manifest() -> dict[str, Any]:
    """The committed cores/MANIFEST.json."""
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def problems() -> list[str]:
    """What is out of date: a core whose pinned widget hash or version differs, or a MANIFEST.json that differs from
    the files (run scripts/build_bridge_cores.py)."""
    found = []
    pin = panel_sha256()
    for family, spec in CORES.items():
        text = read(spec["core"]).decode("utf-8")
        match, version = spec["pin"].search(text), spec["version_re"].search(text)
        if not match or match.group(1) != pin:
            found.append(f"the {family} core pins another panel.js hash")
        if not version or version.group(1) != spec["version"]:
            found.append(f"the {family} core is not version {spec['version']}")
    try:
        if MANIFEST_PATH.read_text(encoding="utf-8") != render_manifest(build_manifest()):
            found.append("cores/MANIFEST.json differs from the files")
    except OSError:
        found.append("cores/MANIFEST.json is missing")
    return found


def family_of(stack: str) -> str | None:
    """The vendored core of a stack (python, node, go), or None when a model writes the core."""
    return contract.core_family(stack)


def vendored(family: str) -> dict[str, bytes]:
    """The files a bridge patch adds byte-identical, by destination name (relative to the bridge folder)."""
    return {dest: read(src) for dest, src in CORES[family]["files"].items()}


def vendored_sha256s() -> dict[str, str]:
    """SHA-256 -> template, for every vendored file (the static checks recognise an unchanged vendored file)."""
    return {sha256(read(src)): src for spec in CORES.values() for src in spec["files"].values()}


def glue_skeletons(family: str) -> dict[str, bytes]:
    """The glue skeleton(s) of a family: built-ins only, the tool's actions as commented TODO handlers."""
    return {dest: read(src) for dest, src in CORES[family]["glue"].items()}


def render(text: str, values: Mapping[str, Any], *, trusted: Mapping[str, str] | None = None) -> str:
    """Fill {{name}} placeholders. Values must be plain tokens (SAFE_VALUE) so no file format can be broken out of;
    `trusted` holds Atrium's own phrases. A placeholder without a value refuses."""
    merged = {**{k: str(v) for k, v in values.items() if v is not None}, **(trusted or {})}
    for key, value in values.items():
        if value is not None and not SAFE_VALUE.match(str(value)):
            raise ValueError(f"{key} holds characters a generated file cannot take")

    def fill(match: re.Match[str]) -> str:
        if match.group(1) not in merged:
            raise ValueError(f"no value for {{{{{match.group(1)}}}}}")
        return merged[match.group(1)]
    return PLACEHOLDER.sub(fill, text)


def sidecar_bundle(*, atrium_url: str, subsidiary_id: str, tool_id: str, mode: str, bridge_url: str | None = None,
                   ca_file: str | None = None, atrium_cert_sha256: str | None = None,
                   image: str = "atrium-sidecar:local", network: str | None = None, memory: str = "512m",
                   cpus: str = "1.0", executable: str = "/usr/local/bin/atrium-sidecar") -> dict[str, bytes]:
    """The sidecar bundle Atrium writes to the tool's adapter folder (subsidiary/sidecar/), by file name. No secret:
    the sidecar makes its own key and gets its token by enrolling with a one-time code shown to an administrator."""
    if mode not in ("bridge", "sidecar_only"):
        raise ValueError("mode is bridge or sidecar_only")
    if not contract.SUBSIDIARY_ID_RE.match(subsidiary_id) or not contract.TOOL_ID_RE.match(tool_id):
        raise ValueError("a subsidiary id and a tool id")
    if not re.match(r"^https?://", atrium_url) or (bridge_url is not None and not re.match(r"^https?://", bridge_url)):
        raise ValueError("Atrium's and the bridge's addresses are http(s) URLs")
    if atrium_cert_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", atrium_cert_sha256):
        raise ValueError("atrium_cert_sha256 is 64 lowercase hex digits")
    if not re.fullmatch(r"[0-9]{1,5}[mg]", memory) or not re.fullmatch(r"[0-9]{1,2}(\.[0-9]{1,2})?", cpus):
        raise ValueError("memory is like 512m and cpus like 1.0")
    values = {"atrium_url": atrium_url, "subsidiary_id": subsidiary_id, "tool_id": tool_id, "mode": mode,
              "bridge_url": bridge_url, "ca_file": ca_file, "atrium_cert_sha256": atrium_cert_sha256}
    config = json.loads(read(SIDECAR_FILES["config.json"]))
    out_config = {}
    for key, value in config.items():
        found = PLACEHOLDER.fullmatch(value) if isinstance(value, str) else None
        if found is None:
            out_config[key] = value
        elif values.get(found.group(1)) is not None:
            out_config[key] = render(value, values)
    text_values = {**values, "image": image, "network": network or f"{tool_id.lower()}_default", "memory": memory,
                   "cpus": cpus, "memory_max": memory[:-1] + memory[-1].upper(), "executable": executable}
    reach = (f"through its bridge ({bridge_url})" if bridge_url else
             "through its bridge" if mode == "bridge" else
             "through the tool's API, with a dedicated read-only credential it fetches from Atrium at start")
    files = {"config.json": (json.dumps(out_config, indent=2) + "\n").encode()}
    for name in ("docker-compose.yml", "atrium-sidecar.service", "README.md"):
        files[name] = render(read(SIDECAR_FILES[name]).decode("utf-8"), text_values,
                             trusted={"reach": reach}).encode("utf-8")
    return files
