"""Profiles of well-known products: how to recognise them, run them, check their health and reach their API.

The analyzer's generic rules read a folder; a profile adds what Atrium knows about a product whatever the folder looks
like (a release folder, a source checkout, a compose folder or a hosted service): its launcher or official container
image, its default port, the health endpoint and the environment that switches it on, its API and the built-in
connector that talks to it. Profiles only fill fields the analysis left empty, a tool's own ``hub.manifest.*`` beats
them, and hub-side overrides (applied patches, administrators' edits) beat both (docs/MANIFEST.md).

Facts that change between product versions are ``Versioned``: ``((since_version | None, value), ...)``, the last pair
whose version applies wins, and an unknown version counts as the newest.

This module imports the models only: the analyzer imports it, so analyzer helpers are imported inside functions, and
connector kinds are plain strings (hub/connectors REGISTRY keys).
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml

from ..models import KnownMatch, Manifest, Tool

Versioned = tuple[tuple[str | None, Any], ...]
COMPOSE_FILES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
MARKER_BYTES = 8_000  # a marker's `contains` is looked for in the first 8 KB of the file
RELEASE_RE = re.compile(r"^\d+\.\d+(?:\.\d+)?$")  # a version a container image is tagged with
VERSION_RE = re.compile(r"^\s*v?(\d+(?:\.\d+)*)")
CONTAINER_RUN_RE = re.compile(r"^\s*(?:sudo\s+)?(?:docker|podman)\s+(?:container\s+)?run\b")
COMPOSE_CMD_RE = re.compile(r"^\s*(?:sudo\s+)?(?:(?:docker|podman)\s+compose|docker-compose|podman-compose)\b")
SHAPE_LABEL = {"release": "release folder", "source": "source code", "compose": "compose folder", "saas": "SaaS",
               "other": "folder"}


def _version_key(version: str | None) -> tuple[int, ...] | None:
    match = VERSION_RE.match(version or "")
    return tuple(int(p) for p in match.group(1).split(".")) if match else None


def pick(values: Versioned, version: str | None) -> Any:
    """The value of the last pair whose since-version is at most `version` (None since = always). An unknown or
    non-numeric version counts as the newest; "999.0.0-SNAPSHOT" (a development build) is the newest anyway."""
    current = _version_key(version)
    found = None
    for since, value in values:
        if since is None or current is None or current >= (_version_key(since) or ()):
            found = value
    return found


@dataclass(frozen=True)
class Marker:
    """A file that identifies the product and the shape of the folder (checked with analyzer.repo_file, so a marker in
    a folder the generic listing skips - bin/ - still counts)."""

    path: str
    shape: str
    contains: str | None = None  # text the first 8 KB must hold


@dataclass(frozen=True)
class HealthSpec:
    path: str
    env: dict[str, str]  # what switches the endpoint on ({} = always on)
    port: int | None = None  # None = the main port


@dataclass(frozen=True)
class ApiFacts:
    type: str
    base_path: str
    label: str
    spec: str | None = None  # an absolute URL, or a path under the tool's root URL


@dataclass(frozen=True)
class Profile:
    """What Atrium knows about one product. A container recipe needs `image` and `default_tag`; an `image` alone only
    recognises the product's service in a compose file. `requires` maps a shape to what the hub machine needs."""

    id: str
    title: str
    names: tuple[str, ...]  # substrings of the tool's id or name (or the SaaS host name)
    provides: tuple[str, ...] = ()
    sso: str | None = None  # "oidc" for identity providers
    markers: tuple[Marker, ...] = ()
    default_port: int | None = None
    health: Versioned = ()  # -> HealthSpec | None
    api: Versioned = ()  # -> ApiFacts | None
    connector: str | None = None  # built-in connector kind
    image: str | None = None
    default_tag: str | None = None
    run_args: tuple[str, ...] = ()
    release_launcher: tuple[str, str] | None = None  # (posix, windows)
    container_env: Versioned = ()  # -> (constant env, secret env names) of the container recipe
    requires: dict[str, str] = field(default_factory=dict)
    version_files: tuple[tuple[str, str], ...] = ()  # (path, regex with one group)
    events: str | None = None  # why events need more than the hub's poller (None = unknown)
    notes: tuple[str, ...] = ()  # e.g. why there is no single-container recipe
    port_env: str | None = None  # the variable it reads its HTTP port from (how reassign_port moves it), if any

    def matches(self, text: str) -> bool:
        """The legacy KNOWN_TOOLS rule: a name is a substring of `text`, also with dots removed (wiki.js, wikijs)."""
        lowered = text.lower()
        return any(n in lowered or n.replace(".", "") in lowered.replace(".", "") for n in self.names)


KC_HEALTH = {"KC_HEALTH_ENABLED": "true"}
DOCKER = "Docker on the hub machine"
LOOPBACK = "127.0.0.1"  # the host address a container recipe publishes its ports on

PROFILES: dict[str, Profile] = {p.id: p for p in (
    Profile(
        id="keycloak", title="Keycloak", names=("keycloak",), provides=("auth.oidc", "auth.saml", "identity.source"),
        sso="oidc",
        markers=(Marker("bin/kc.sh", "release"), Marker("bin/kc.bat", "release"),
                 Marker("pom.xml", "source", "<artifactId>keycloak-parent</artifactId>")),
        default_port=8080,
        health=((None, None), ("17", HealthSpec("/health/ready", KC_HEALTH)),
                ("25", HealthSpec("/health/ready", KC_HEALTH, 9000))),
        api=((None, ApiFacts("rest", "/auth/admin/realms", "Keycloak admin REST API")),
             ("17", ApiFacts("rest", "/admin/realms", "Keycloak admin REST API",
                             "https://www.keycloak.org/docs-api/latest/rest-api/openapi.json"))),
        connector="keycloak", image="quay.io/keycloak/keycloak", default_tag="26.0", run_args=("start-dev",),
        release_launcher=("bin/kc.sh", "bin\\kc.bat"),
        container_env=((None, ({"KEYCLOAK_ADMIN": "admin"}, ("KEYCLOAK_ADMIN_PASSWORD",))),
                       ("26", ({"KC_BOOTSTRAP_ADMIN_USERNAME": "admin"}, ("KC_BOOTSTRAP_ADMIN_PASSWORD",)))),
        requires={"release": "Java 17 or later", "source": DOCKER, "other": DOCKER},
        version_files=(("version.txt", r"Version\s+(\d+\.\d+(?:\.\d+)?)"),),
        events=("Keycloak records admin and login events only when they are switched on per realm, and serves them "
                "through its admin API with a token; the hub's event poller cannot read them yet."),
        port_env="KC_HTTP_PORT",
    ),
    Profile(
        id="authentik", title="authentik", names=("authentik",), provides=("auth.oidc", "auth.saml"), sso="oidc",
        default_port=9000, health=((None, HealthSpec("/-/health/ready/", {})),),
        api=((None, ApiFacts("rest", "/api/v3", "authentik API", "/api/v3/schema/")),),
        image="ghcr.io/goauthentik/server",
        notes=("authentik runs as a server and a worker container with PostgreSQL: import the folder with its "
               "docker-compose.yml.",),
    ),
    Profile(
        id="zitadel", title="ZITADEL", names=("zitadel",), provides=("auth.oidc",), sso="oidc", default_port=8080,
        health=((None, HealthSpec("/debug/ready", {})),),
        notes=("ZITADEL needs a PostgreSQL database: import the folder with its docker-compose.yml.",),
    ),
    Profile(
        id="authelia", title="Authelia", names=("authelia",), provides=("auth.oidc",), sso="oidc", default_port=9091,
        health=((None, HealthSpec("/api/health", {})),),
        notes=("Authelia needs its configuration.yml: import the folder that holds it.",),
    ),
    Profile(id="okta", title="Okta", names=("okta",), provides=("auth.oidc", "auth.saml", "identity.source"), sso="oidc",
            api=((None, ApiFacts("rest", "/api/v1", "Okta API")),), connector="okta",
            notes=("Okta is a hosted service: import it as a SaaS tool.",)),
    Profile(id="snipeit", title="Snipe-IT", names=("snipe-it", "snipeit"), provides=("assets.inventory",),
            api=((None, ApiFacts("rest", "/api/v1", "Snipe-IT API")),), connector="snipeit"),
    Profile(id="ciso-assistant", title="CISO Assistant", names=("ciso-assistant",),
            provides=("grc.compliance", "grc.risks"), api=((None, ApiFacts("rest", "/api", "CISO Assistant API")),),
            connector="ciso_assistant"),
    Profile(id="openvas", title="OpenVAS", names=("openvas", "greenbone", "gvm"), provides=("vuln.scanner",),
            connector="openvas"),  # GMP, not REST
    Profile(id="opnsense", title="OPNsense", names=("opnsense",), api=((None, ApiFacts("rest", "/api", "OPNsense API")),),
            connector="opnsense", notes=("OPNsense is an appliance: the hub does not start it.",)),
    Profile(id="pfsense", title="pfSense", names=("pfsense",), connector="pfsense",
            notes=("pfSense is an appliance: the hub does not start it.",)),
    Profile(id="mikrotik", title="MikroTik RouterOS", names=("mikrotik", "routeros"),
            api=((None, ApiFacts("rest", "/rest", "RouterOS REST API")),), connector="mikrotik",
            notes=("RouterOS runs on a device: the hub does not start it.",)),
    Profile(id="fortigate", title="FortiGate", names=("fortigate", "fortios"),
            api=((None, ApiFacts("rest", "/api/v2", "FortiOS REST API")),), connector="fortigate",
            notes=("FortiGate is an appliance: the hub does not start it.",)),
    Profile(id="panos", title="PAN-OS", names=("pan-os", "panos"), connector="panos",  # XML API
            notes=("PAN-OS runs on a firewall: the hub does not start it.",)),
    Profile(id="cisco-iosxe", title="Cisco IOS XE", names=("ios-xe", "iosxe"), connector="cisco_iosxe",  # NETCONF
            notes=("IOS XE runs on a device: the hub does not start it.",)),
    Profile(id="grafana", title="Grafana", names=("grafana",), provides=("monitoring.dashboards",), default_port=3000,
            health=((None, HealthSpec("/api/health", {})),), port_env="GF_SERVER_HTTP_PORT"),
    Profile(id="prometheus", title="Prometheus", names=("prometheus",), provides=("monitoring.metrics",),
            default_port=9090, health=((None, HealthSpec("/-/ready", {})),)),
    Profile(id="minio", title="MinIO", names=("minio",), provides=("storage.s3",), default_port=9000,
            health=((None, HealthSpec("/minio/health/live", {})),)),
    Profile(id="gitea", title="Gitea", names=("gitea",), provides=("git.hosting", "webhooks"), default_port=3000,
            health=((None, HealthSpec("/api/healthz", {})),)),
    Profile(id="n8n", title="n8n", names=("n8n",), provides=("automation", "webhooks"), default_port=5678,
            health=((None, HealthSpec("/healthz", {})),), port_env="N8N_PORT"),
    Profile(id="mattermost", title="Mattermost", names=("mattermost",), provides=("chat", "webhooks"), default_port=8065,
            health=((None, HealthSpec("/api/v4/system/ping", {})),)),
    # capability-only profiles (the former KNOWN_TOOLS entries): what they provide, nothing about running them
    *(Profile(id=name, title=title, names=(name,), provides=provides) for name, title, provides in (
        ("forgejo", "Forgejo", ("git.hosting", "webhooks")), ("gitlab", "GitLab", ("git.hosting", "ci", "webhooks")),
        ("rocket.chat", "Rocket.Chat", ("chat", "webhooks")), ("nextcloud", "Nextcloud", ("storage.files",)),
        ("uptime-kuma", "Uptime Kuma", ("monitoring.uptime",)), ("wiki.js", "Wiki.js", ("docs.wiki",)),
        ("bookstack", "BookStack", ("docs.wiki",)), ("outline", "Outline", ("docs.wiki",)),
        ("glpi", "GLPI", ("assets.inventory", "ticketing")), ("zammad", "Zammad", ("ticketing",)),
        ("osticket", "osTicket", ("ticketing",)), ("vaultwarden", "Vaultwarden", ("secrets.vault",)),
        ("mailpit", "Mailpit", ("notify.email",)), ("mailhog", "MailHog", ("notify.email",)),
        ("postgres", "PostgreSQL", ("db.postgres",)), ("redis", "Redis", ("cache.redis",)),
        ("openldap", "OpenLDAP", ("directory.ldap",)),
    )),
)}


@dataclass(frozen=True)
class Match:
    profile: Profile
    shape: str
    by: str
    version: str | None


def get(profile_id: str | None) -> Profile | None:
    return PROFILES.get(profile_id) if profile_id else None


def for_manifest(m: Manifest) -> Profile | None:
    return get(m.known.profile) if m.known else None


def _describing(p: Profile | None) -> bool:
    return bool(p and (p.release_launcher or (p.image and p.default_tag) or p.default_port or p.health or p.api
                       or p.connector))


def describes(m: Manifest) -> bool:
    """Whether the recognised product's profile says how to run, check or reach it (not only what it provides): a
    launcher or container recipe, a default port, a health endpoint, an API or a built-in connector."""
    return _describing(for_manifest(m))


# --------------------------------------------------------------------------------------
# recognising a product
# --------------------------------------------------------------------------------------


def _marker_hit(root: Path, marker: Marker) -> bool:
    """The marker file is there (and holds `contains`). In a pom.xml only the project's own coordinates count: a
    Keycloak extension or theme names keycloak-parent as its <parent> or imports it as a BOM, and is not Keycloak."""
    from .analyzer import read_repo_file, repo_file

    if marker.contains is None:
        return repo_file(root, marker.path) is not None
    text = read_repo_file(root, marker.path, MARKER_BYTES)
    if text is not None and marker.path.rsplit("/", 1)[-1] == "pom.xml":
        text = _pom_head(text)
    return text is not None and marker.contains in text


def _services(compose: dict | None) -> list[tuple[str, dict[str, Any]]]:
    services = (compose or {}).get("services") if isinstance(compose, dict) else None
    return [(str(k), v) for k, v in services.items() if isinstance(v, dict)] if isinstance(services, dict) else []


def _image_profile(service: dict[str, Any]) -> Profile | None:
    """The profile whose official image (or image name) a compose service runs."""
    image = str(service.get("image") or "").lower()
    repo = image.rsplit("/", 1)[-1].split(":")[0].split("@")[0]
    if not image:
        return None
    return next((p for p in PROFILES.values() if (p.image and p.image in image) or (repo and p.matches(repo))), None)


def _main_image(compose: dict | None) -> Profile | None:
    """The product a compose folder runs, by the images of its main services - those that publish ports (every
    service when none does): one product Atrium describes, besides backing services it knows only by what they
    provide (PostgreSQL, Redis). None when one of them runs an image Atrium does not know (the folder's own app),
    or two products are in it: a folder named "iam-stack" running Keycloak is Keycloak, "shop" with its own image
    and a Keycloak beside it is not."""
    services = [s for _, s in _services(compose)]
    main = [s for s in services if s.get("ports")] or services
    found: set[str] = set()
    for service in main:
        p = _image_profile(service)
        if p is None:
            return None
        if _describing(p):
            found.add(p.id)
    return PROFILES[found.pop()] if len(found) == 1 else None


def _service(p: Profile, compose: dict | None) -> dict[str, Any] | None:
    """The compose service that runs `p`: the first whose image holds the profile's image or whose image name matches
    the profile's names, else the first whose service name matches (a "keycloak-db" PostgreSQL service listed before
    the Keycloak one is not it)."""
    services = _services(compose)
    for _, service in services:
        image = str(service.get("image") or "").lower()
        repo = image.rsplit("/", 1)[-1].split(":")[0].split("@")[0]
        if (p.image and image and p.image in image) or (repo and p.matches(repo)):
            return service
    return next((service for name, service in services if p.matches(name)), None)


def _image_tag(service: dict[str, Any] | None) -> str | None:
    image = str((service or {}).get("image") or "").split("@")[0]
    last = image.rsplit("/", 1)[-1]
    return last.split(":", 1)[1] if ":" in last else None


def _pom_head(text: str) -> str:
    """A pom.xml's own coordinates: without comments and its <parent>, and cut before the first block that names other
    artifacts (properties, dependencies, dependencyManagement, build, modules, profiles)."""
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    text = re.sub(r"<parent>.*?</parent>", "", text, flags=re.S)
    return re.split(r"<(?:properties|dependencies|dependencyManagement|build|modules|profiles)>", text, maxsplit=1)[0]


def _pom_version(root: Path) -> str | None:
    """The project's own <version> in a root pom.xml (not its parent's), when it looks like a release (26.0.5)."""
    from .analyzer import read_repo_file

    text = read_repo_file(root, "pom.xml", 64_000)
    if not text:
        return None
    match = re.search(r"<version>\s*([^<\s]+)\s*</version>", _pom_head(text))
    return match.group(1) if match and RELEASE_RE.match(match.group(1)) else None


def detect_version(p: Profile, root: Path | None = None, compose: dict | None = None) -> str | None:
    """The product version: from its version files, then the compose image tag, then a release-like root pom.xml.
    Pass `root` only when a marker file showed the folder is the product itself: a folder recognised by its name
    alone may be something else (a "keycloak-theme" project), whose files carry its own version."""
    from .analyzer import read_repo_file

    if root is not None:
        for path, pattern in p.version_files:
            text = read_repo_file(root, path, MARKER_BYTES)
            match = re.search(pattern, text or "")
            if match:
                return match.group(1)[:40]
    tag = _image_tag(_service(p, compose))
    if tag and VERSION_RE.match(tag):
        return tag[:40]
    if root is not None:
        version = _pom_version(root)
        if version:
            return version[:40]
    return None


def recognise(names: list[str], *, root: Path | None = None, host: str | None = None,
              compose: dict | None = None) -> Match | None:
    """The product a folder or SaaS service is, if Atrium knows it: by a marker file, else by the tool's id or name
    when it names the product itself (``named``), else by the image its root compose file's main service runs
    (``_main_image``: a compose folder imported under any name), else by the SaaS host name. The shape: a release
    marker > the product's service in the root compose file > a source marker > "other"; a SaaS host makes it
    "saas"."""
    found: tuple[Profile, str] | None = None
    if root is not None:
        found = next(((p, "marker") for p in PROFILES.values() if any(_marker_hit(root, mk) for mk in p.markers)), None)
    if found is None:
        found = next(((p, "name") for p in PROFILES.values() if any(named(p, n) for n in names if n)), None)
    if found is None and compose is not None and host is None:
        main = _main_image(compose)
        found = (main, "image") if main is not None else None
    if found is None and host:
        found = next(((p, "host") for p in PROFILES.values() if p.matches(host)), None)
    if found is None:
        return None
    p, by = found
    if host is not None:
        shape = "saas"
    else:
        hits = {mk.shape for mk in p.markers if root is not None and _marker_hit(root, mk)}
        shape = ("release" if "release" in hits else "compose" if _service(p, compose) is not None
                 else "source" if "source" in hits else "other")
    version = None if shape == "saas" else detect_version(p, root if by == "marker" else None, compose)
    return Match(profile=p, shape=shape, by=by, version=version)


# what may follow a product's name in a tool's id or name that still names the product itself: a version, or a word
# about how it is packaged ("keycloak-26.0.5", "mattermost-server", "keycloak-main" - a GitHub archive)
NAME_WORDS = ("server", "main", "master", "src", "source", "release", "dist", "oss", "ce", "ee", "community", "docker",
              "compose", "stack", "deploy", "app", "latest", "stable")
_NEUTRAL = re.compile(r"v?\d[\w.]*|" + "|".join(NAME_WORDS))


def named(p: Profile, text: str) -> bool:
    """`text` (a tool's id or name) names the product itself: one of its names, alone or followed by a version or a
    packaging word (NAME_WORDS) - "keycloak", "Keycloak 26.0.5", "mattermost-server". A project merely named after the
    product ("keycloak-theme", "prometheus-node-exporter", "redis-commander") is not the product: it is not
    recognised by its name (its marker files still can), and keeps only the legacy capabilities of the name."""
    lowered = text.lower().strip()
    for name in p.names:
        for form in dict.fromkeys((name, name.replace(".", ""), name.replace("-", ""))):
            if lowered.startswith(form) and all(_NEUTRAL.fullmatch(w) for w in re.split(r"[\s_./-]+",
                                                                                           lowered[len(form):]) if w):
                return True
    return False


def read_compose(root: Path) -> dict[str, Any] | None:
    """The root compose file of a folder, parsed (None when there is none or it cannot be read)."""
    from .analyzer import read_repo_file

    for name in COMPOSE_FILES:
        text = read_repo_file(root, name)
        if text is None:
            continue
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError:
            return None
        return data if isinstance(data, dict) else None
    return None


def recognise_tool(tool: Tool) -> Match | None:
    """recognise() for a stored tool (its folder and root compose file, or its SaaS host)."""
    if tool.source_type == "saas":
        return recognise([tool.id, tool.name], host=urlsplit(tool.source or "").hostname or "")
    root = Path(tool.path) if tool.path else None
    if root is not None and not root.is_dir():
        root = None
    return recognise([tool.id, tool.name], root=root, compose=read_compose(root) if root is not None else None)


# --------------------------------------------------------------------------------------
# filling a manifest
# --------------------------------------------------------------------------------------


def _add(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def legacy_capabilities(m: Manifest, text: str) -> list[str]:
    """What the products named in `text` (compose service and image names) provide, and single sign-on for identity
    providers - the former apply_known_tools. Sets no `known`. Returns the names found."""
    found = []
    for p in PROFILES.values():
        if not text or not p.matches(text):
            continue
        found += [n for n in p.names if n in text.lower() or n.replace(".", "") in text.lower().replace(".", "")]
        for capability in p.provides:
            _add(m.provides, capability)
        if p.sso:
            m.auth.sso = p.sso  # type: ignore[assignment]
    return found


def _root_url(m: Manifest) -> str | None:
    """Where the tool answers: the SaaS address (scheme and host), else http://localhost:<port> once a port is known."""
    if m.known and m.known.shape == "saas":
        parts = urlsplit(m.ui.url or m.health.url or m.api.base_url or "")
        return f"{parts.scheme or 'https'}://{parts.netloc}" if parts.netloc else None
    return f"http://localhost:{int(m.launch.port)}" if m.launch.port else None


def _health_spec(m: Manifest) -> HealthSpec | None:
    p = for_manifest(m)
    return pick(p.health, m.known.version) if p and m.known else None


def _flags_missing(command: str, env: dict[str, str], port: int | None) -> list[str]:
    """The -e/-p flags a container command lacks to switch health on."""
    missing = [f"-e {k}={v}" for k, v in env.items()
               if not re.search(rf"(?:-e|--env)[ =]['\"]?{re.escape(k)}={re.escape(v)}\b", command, re.I)]
    if port and not re.search(rf"(?:-p|--publish)[ =](?:[\d.]+:)?\d+:{port}\b", command):
        missing.append(f"-p {LOOPBACK}:{port}:{port}")
    return missing


PUBLISH_RE = re.compile(r"(?P<flag>(?:-p|--publish)[ =])(?P<addr>(?:\[[0-9a-fA-F:.]+\]|[\d.]+):)?(?P<host>\d+)"
                        r"(?P<rest>:\d+(?:/(?:tcp|udp))?)(?=\s|$)")


def publish_elsewhere(command: str, port: int, new_port: int) -> str | None:
    """A container command (docker/podman run) that publishes host port `new_port` where it published `port`
    ("-p 8080:8080" -> "-p 8081:8080", the host address kept); None when it publishes no `port` on the host."""
    found = False

    def swap(match: re.Match[str]) -> str:
        nonlocal found
        if int(match.group("host")) != port:
            return match.group(0)
        found = True
        return f"{match.group('flag')}{match.group('addr') or ''}{new_port}{match.group('rest')}"

    moved = PUBLISH_RE.sub(swap, command)
    return moved if found else None


def _compose_health(m: Manifest, spec: HealthSpec, compose: dict | None) -> str | None:
    """The health URL when the product's compose service already switches health on and publishes its port."""
    p = for_manifest(m)
    service = _service(p, compose) if p else None
    if service is None:
        return None
    env = service.get("environment") or {}
    if isinstance(env, list):
        env = dict(str(item).split("=", 1) if "=" in str(item) else (str(item), "") for item in env)
    if not isinstance(env, dict) or any(str(env.get(k, "")).strip().lower() != v.lower() for k, v in spec.env.items()):
        return None
    published: dict[int, int] = {}  # container port -> host port
    for port in service.get("ports") or []:
        if isinstance(port, dict):
            target, host = str(port.get("target", "")), str(port.get("published", ""))
        else:
            parts = str(port).split("/")[0].split(":")
            target, host = parts[-1], (parts[-2] if len(parts) >= 2 else parts[-1])
        if target.isdigit() and host.isdigit():
            published[int(target)] = int(host)
    port = spec.port or (p.default_port if p else None) or m.launch.port
    host_port = published.get(port) if port else None
    return f"http://localhost:{host_port}{spec.path}" if host_port else None


def apply(m: Manifest, match: Match, *, root: Path | None = None, compose: dict | None = None) -> list[str]:
    """Record the recognised product on `m` and fill the fields the analysis left EMPTY from its profile: version,
    provides, single sign-on, a launch command for a release folder, the port (not for a source checkout, whose
    launch_command patch sets it, nor for SaaS), the API, and a health URL that works as found. A tool never consumes
    what it provides. Returns a note for the person ("Recognised Keycloak 26.0.5 (release folder).")."""
    p = match.profile
    # never m.version: that is a SaaS's API document's, or the own project's of a folder recognised by its name only
    version = match.version or (None if match.shape == "saas" else
                                detect_version(p, root if match.by == "marker" else None, compose))
    m.known = KnownMatch(profile=p.id, shape=match.shape, by=match.by, version=version)  # type: ignore[arg-type]
    m.version = m.version or version
    for capability in p.provides:
        _add(m.provides, capability)
    if p.sso:
        m.auth.sso = p.sso  # type: ignore[assignment]
    m.consumes = [c for c in m.consumes if c not in m.provides]

    if match.shape in ("release", "compose", "other") and not m.launch.port and p.default_port:
        m.launch.port = p.default_port
    if match.shape == "release" and not m.launch.command:
        plan = launch_plan(m, m.id)
        if plan:
            m.launch.command, m.launch.cwd = plan.command, "."

    facts = api_info(m)
    if facts and m.api.type == "none":
        base = _root_url(m)
        spec = facts.spec if facts.spec and facts.spec.startswith(("http://", "https://")) else (
            f"{base}{facts.spec}" if facts.spec and base else None)
        m.api = m.api.model_copy(update={"type": facts.type, "spec": spec,
                                         "base_url": f"{base}{facts.base_path}" if base else None})

    if not m.health.url:
        spec = _health_spec(m)
        plan = health_plan(m, m.id)
        if spec and match.shape == "compose":
            m.health.url = _compose_health(m, spec, compose)
        elif plan and plan.via == "builtin" and plan.url:
            m.health.url = plan.url
    label = f"{p.title} {version}" if version else p.title
    return [f"Recognised {label} ({SHAPE_LABEL.get(match.shape, match.shape)})."]


# --------------------------------------------------------------------------------------
# plans the patches and checks use
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class LaunchPlan:
    command: str
    port: int | None
    cwd: str = "."
    setup: str | None = None
    env: dict[str, str] = field(default_factory=dict)  # constants only, never secrets
    secret_env: tuple[str, ...] = ()  # generated when the patch is applied
    health_url: str | None = None  # set when the command switches health on
    api_base_url: str | None = None
    ui_url: str | None = None
    requires: str = ""
    summary: str = ""  # "the official container image quay.io/keycloak/keycloak:26.0"
    notes: tuple[str, ...] = ()


def _container_recipe(m: Manifest, p: Profile, tool_id: str) -> LaunchPlan | None:
    if not (p.image and p.default_tag and p.default_port):
        return None
    version = m.known.version if m.known else None
    tag = version if version and RELEASE_RE.match(version) else p.default_tag
    spec = pick(p.health, version)
    constants, secret_names = pick(p.container_env, version) or ({}, ())
    port = p.default_port
    ports = [port] + ([spec.port] if spec and spec.port and spec.port != port else [])
    env = {**(spec.env if spec else {}), **constants}
    parts = ["docker", "run", "--rm", "--name", f"atrium-{tool_id}"]
    for published in ports:  # on loopback only: Docker's own rules would otherwise publish past a host firewall, and
        parts += ["-p", f"{LOOPBACK}:{published}:{published}"]  # the hub reaches it through http://localhost anyway
    for key, value in env.items():
        parts += ["-e", f"{key}={value}"]
    for name in secret_names:
        parts += ["-e", name]
    parts += [f"{p.image}:{tag}", *p.run_args]
    facts = pick(p.api, version)
    shape = m.known.shape if m.known else "other"
    return LaunchPlan(
        command=" ".join(shlex.quote(x) for x in parts), port=port, secret_env=tuple(secret_names),
        health_url=f"http://localhost:{spec.port or port}{spec.path}" if spec else None,
        api_base_url=f"http://localhost:{port}{facts.base_path}" if facts else None, ui_url=f"http://localhost:{port}",
        requires=p.requires.get(shape) or DOCKER, summary=f"the official container image {p.image}:{tag}",
        notes=p.notes)


def launch_plan(m: Manifest, tool_id: str) -> LaunchPlan | None:
    """How the hub can start the recognised product: a release folder runs its launcher (the Windows one on Windows);
    a source checkout (or any other folder) of a product with an official image runs the container recipe; a SaaS
    service or a compose folder has nothing to plan (None)."""
    p = for_manifest(m)
    if p is None or m.known is None or m.known.shape in ("saas", "compose"):
        return None
    if m.known.shape == "release":
        if not p.release_launcher:
            return None
        launcher = p.release_launcher[1 if os.name == "nt" else 0]
        port = m.launch.port or p.default_port
        spec = pick(p.health, m.known.version)
        facts = api_info(m)
        return LaunchPlan(
            command=" ".join([launcher, *p.run_args]), port=port,
            health_url=f"http://localhost:{spec.port or port}{spec.path}" if spec and not spec.env and port else None,
            api_base_url=f"http://localhost:{port}{facts.base_path}" if facts and port else None,
            ui_url=f"http://localhost:{port}" if port else None, requires=p.requires.get("release", ""),
            summary=f"its own launcher {launcher}", notes=p.notes)
    return _container_recipe(m, p, tool_id)


@dataclass(frozen=True)
class HealthPlan:
    url: str | None
    env: dict[str, str]
    via: Literal["builtin", "config", "launch", "compose"]
    note: str


def health_plan(m: Manifest, tool_id: str = "") -> HealthPlan | None:
    """How the recognised product's health endpoint gets used (None: the profile knows none for this version):

    - builtin: it is always on (the URL is usable once a port is known), or the launch environment already
      switches it on;
    - config: the hub can switch it on by passing env through launch.env (release or other folder whose launch
      command is not a container command);
    - launch: there is no launch command yet, and launch_plan() switches it on;
    - compose: a person must add the env and publish the port in the compose file (the note says exactly what).

    A container launch command that lacks the env or the port gives url None (via builtin) with a note naming the
    -e / -p flags to add: the check then falls back to a probe and shows the note."""
    p, spec = for_manifest(m), _health_spec(m)
    if p is None or m.known is None or spec is None:
        return None
    known_port = spec.port or m.launch.port  # a URL needs a port that is known; a note may name the default one
    port = known_port or p.default_port
    shape = m.known.shape
    if shape == "saas":
        base = _root_url(m)
        return HealthPlan(f"{base}{spec.path}" if base else None, {}, "builtin", "") if not spec.env else None
    url = f"http://localhost:{known_port}{spec.path}" if known_port else None
    env_text = ", ".join(f"{k}={v}" for k, v in spec.env.items())
    command = (m.launch.command or "").strip()
    if not spec.env:
        return HealthPlan(url, {}, "builtin", "")
    if shape == "compose" or COMPOSE_CMD_RE.match(command):
        return HealthPlan(None, dict(spec.env), "compose", (
            f"{p.title} serves {spec.path} only with {env_text}: add it to the environment of the {p.title} service in "
            f"the compose file and publish port {port} (\"{port}:{port}\"), then Re-analyse."))
    if CONTAINER_RUN_RE.match(command):  # the launch environment does not reach the container: its flags must
        missing = _flags_missing(command, spec.env, spec.port)
        if not missing:
            return HealthPlan(url, dict(spec.env), "builtin", "")
        return HealthPlan(None, dict(spec.env), "builtin", (
            f"{p.title} serves {spec.path} on port {port} only with {env_text}: add {' '.join(missing)} to the "
            "launch command, then Re-analyse."))
    if all(str(m.launch.env.get(k, "")).lower() == v.lower() for k, v in spec.env.items()):
        return HealthPlan(url, dict(spec.env), "builtin", "")
    if not command or command.upper().startswith("TODO"):  # a TODO placeholder is no command
        plan = launch_plan(m, tool_id or m.id)
        return HealthPlan(plan.health_url if plan else None, dict(spec.env), "launch",
                          f"{p.title} serves {spec.path} on port {port} once {env_text} is set: the launch_command "
                          "patch switches it on.")
    return HealthPlan(url, dict(spec.env), "config",
                      f"{p.title} serves {spec.path} on port {port} once {env_text} is set: the hub passes it in the "
                      "launch environment.")


def api_info(m: Manifest) -> ApiFacts | None:
    """The recognised product's API for its version (None when the profile knows none)."""
    p = for_manifest(m)
    return pick(p.api, m.known.version) if p and m.known else None


def events_note(m: Manifest) -> str | None:
    """Why the recognised product's events need more than the hub's event poller (None when nothing is known)."""
    p = for_manifest(m)
    return p.events if p else None
