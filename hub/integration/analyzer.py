"""Understands an imported tool and produces its hub manifest.

The analyzer is deterministic: it reads well-known files (package manifests,
Dockerfiles, compose files, .env examples, OpenAPI specs, README) and infers
the stack, launch command, port, health endpoint, SSO support and the
capabilities a tool provides or consumes. A tool that ships its own
``hub.manifest.yaml`` is treated as native and its manifest wins.
"""

from __future__ import annotations

import json
import os
import re
import stat
import tomllib
from pathlib import Path, PurePath
from typing import Any
from urllib.parse import urlparse

import httpx
import yaml

from ..models import Manifest

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__", ".next",
    "target", ".idea", ".vscode", ".tox", "coverage", ".cache", "bin", "obj",
}
SOURCE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java", ".kt", ".php", ".rs", ".cs", ".ex", ".scala"}
BINARY_EXT = {".exe", ".dll", ".so", ".dylib", ".jar", ".msi", ".appimage", ".bin"}
ENV_FILES = (".env.example", ".env.sample", ".env.template", ".env.dist", "env.example", "example.env", "sample.env")
COMPOSE_FILES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
OPENAPI_NAMES = {"openapi.json", "openapi.yaml", "openapi.yml", "swagger.json", "swagger.yaml", "swagger.yml"}
MANIFEST_NAMES = ("hub.manifest.yaml", "hub.manifest.yml", "hub.manifest.json")
MAX_FILES = 4000
MAX_SCAN_BYTES = 200_000

# Environment variable prefixes -> (capability consumed, SSO mode)
ENV_RULES: list[tuple[re.Pattern[str], str | None, str | None]] = [
    (re.compile(r"^(OIDC|OPENID|KEYCLOAK|AUTHENTIK|ZITADEL|AUTHELIA)_"), "auth.oidc", "oidc"),
    (re.compile(r"^(OAUTH2?|GITHUB_CLIENT|GOOGLE_CLIENT|AZURE_AD)_"), None, "oauth2"),
    (re.compile(r"^SAML_"), None, "saml"),
    (re.compile(r"^LDAP_"), "directory.ldap", "ldap"),
    (re.compile(r"^(POSTGRES|POSTGRESQL|PG)_"), "db.postgres", None),
    (re.compile(r"^(MYSQL|MARIADB)_"), "db.mysql", None),
    (re.compile(r"^(MONGO|MONGODB)_"), "db.mongo", None),
    (re.compile(r"^REDIS_"), "cache.redis", None),
    (re.compile(r"^(S3|AWS_S3|MINIO)_"), "storage.s3", None),
    (re.compile(r"^(SMTP|MAIL|EMAIL)_"), "notify.email", None),
    (re.compile(r"^(AMQP|RABBITMQ)_"), "queue.amqp", None),
    (re.compile(r"^(ELASTICSEARCH|OPENSEARCH|MEILI)_"), "search.index", None),
]
# Keys a tool's .env example uses to configure its own OIDC / OAuth2 login (the generic SSO strategy fills these).
SSO_ENV_RE = re.compile(r"^(OIDC|OPENID|OAUTH2?)_")
URL_SCHEMES = {"postgres": "db.postgres", "postgresql": "db.postgres", "mysql": "db.mysql", "mariadb": "db.mysql",
               "mongodb": "db.mongo", "mongodb+srv": "db.mongo", "redis": "cache.redis", "rediss": "cache.redis",
               "amqp": "queue.amqp", "amqps": "queue.amqp"}

# Dependency name -> (field, value). Fields: provides | consumes | sso | stack
DEP_RULES: dict[str, tuple[str, str]] = {
    # web frameworks -> REST API
    **{name: ("provides", "api.rest") for name in (
        "express", "fastify", "koa", "@nestjs/core", "hono", "fastapi", "flask", "django", "starlette",
        "djangorestframework", "gin-gonic/gin", "labstack/echo", "gofiber/fiber", "go-chi/chi", "rails",
        "sinatra", "spring-boot-starter-web", "actix-web", "axum", "laravel/framework", "symfony/framework-bundle",
    )},
    **{name: ("provides", "api.graphql") for name in ("graphql", "apollo-server", "@apollo/server", "strawberry-graphql", "graphene", "ariadne", "99designs/gqlgen")},
    # identity
    **{name: ("sso", "oidc") for name in (
        "openid-client", "next-auth", "@auth/core", "passport-openidconnect", "authlib", "mozilla-django-oidc",
        "python-keycloak", "coreos/go-oidc", "omniauth_openid_connect", "keycloak-js", "oidc-client-ts",
    )},
    **{name: ("sso", "saml") for name in ("passport-saml", "@node-saml/passport-saml", "python3-saml", "pysaml2", "ruby-saml", "crewjam/saml")},
    **{name: ("sso", "ldap") for name in ("ldapjs", "python-ldap", "ldap3", "go-ldap/ldap")},
    # data stores and services
    **{name: ("consumes", "db.postgres") for name in ("pg", "postgres", "psycopg", "psycopg2", "psycopg2-binary", "asyncpg", "lib/pq", "jackc/pgx")},
    **{name: ("consumes", "db.mysql") for name in ("mysql", "mysql2", "pymysql", "mysqlclient", "go-sql-driver/mysql")},
    **{name: ("consumes", "db.mongo") for name in ("mongodb", "mongoose", "pymongo", "motor")},
    **{name: ("consumes", "cache.redis") for name in ("redis", "ioredis", "go-redis/redis", "redis/go-redis")},
    **{name: ("consumes", "notify.email") for name in ("nodemailer", "@sendgrid/mail", "flask-mail", "django-anymail")},
    **{name: ("consumes", "storage.s3") for name in ("@aws-sdk/client-s3", "aws-sdk", "minio", "boto3", "minio-go")},
    **{name: ("consumes", "queue.amqp") for name in ("amqplib", "pika", "aio-pika", "celery", "streadway/amqp")},
    # UI frameworks
    **{name: ("stack", "web-ui") for name in ("react", "vue", "svelte", "next", "nuxt", "@angular/core", "vite")},
}

# Well-known open-source tools and what they provide to the rest of the suite.
KNOWN_TOOLS: dict[str, list[str]] = {
    "keycloak": ["auth.oidc", "auth.saml", "identity.source"], "okta": ["auth.oidc", "auth.saml", "identity.source"],
    "authentik": ["auth.oidc", "auth.saml"], "zitadel": ["auth.oidc"],
    "openvas": ["vuln.scanner"], "greenbone": ["vuln.scanner"], "gvm": ["vuln.scanner"],
    "ciso-assistant": ["grc.compliance", "grc.risks"], "snipeit": ["assets.inventory"],
    "authelia": ["auth.oidc"], "gitea": ["git.hosting", "webhooks"], "forgejo": ["git.hosting", "webhooks"],
    "gitlab": ["git.hosting", "ci", "webhooks"], "mattermost": ["chat", "webhooks"], "rocket.chat": ["chat", "webhooks"],
    "nextcloud": ["storage.files"], "minio": ["storage.s3"], "grafana": ["monitoring.dashboards"],
    "prometheus": ["monitoring.metrics"], "uptime-kuma": ["monitoring.uptime"], "wiki.js": ["docs.wiki"],
    "bookstack": ["docs.wiki"], "outline": ["docs.wiki"], "n8n": ["automation", "webhooks"],
    "glpi": ["assets.inventory", "ticketing"], "snipe-it": ["assets.inventory"], "zammad": ["ticketing"],
    "osticket": ["ticketing"], "vaultwarden": ["secrets.vault"], "mailpit": ["notify.email"], "mailhog": ["notify.email"],
    "postgres": ["db.postgres"], "redis": ["cache.redis"], "openldap": ["directory.ldap"],
}

DEFAULT_PORTS = {"next": 3000, "react": 3000, "nuxt": 3000, "rails": 3000, "express": 3000, "django": 8000,
                 "fastapi": 8000, "flask": 5000, "go": 8080, "spring": 8080, "php": 8000}

HEALTH_RE = re.compile(r"""["'`](/(?:api/)?(?:v\d+/)?(?:healthz?|healthcheck|health-check|livez|readyz|ping|status))["'`]""")
WEBHOOK_RE = re.compile(r"webhook", re.IGNORECASE)
PORT_ENV_RE = re.compile(r"^(?:APP_|HTTP_|SERVER_|WEB_)?PORT\s*=\s*\"?(\d{2,5})", re.MULTILINE)
PORT_ARG_RE = re.compile(r"(?:--port[= ]|-p\s+)(\d{2,5})")
EXPOSE_RE = re.compile(r"^\s*EXPOSE\s+(\d{2,5})", re.MULTILINE | re.IGNORECASE)


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


def repo_file(root: Path, rel: str | PurePath) -> Path | None:
    """`root/rel` when it is a regular file inside `root`, reached without a symbolic link; else None.

    Repositories are untrusted: a README.md that links to ../../../secret.key (or a docs/ folder that links to /) must
    not be read, because what the hub reads from a repository ends up in its manifest, its prompts and its diffs."""
    try:
        base = root.resolve(strict=True)
        path = root / rel
        if not stat.S_ISREG(path.lstat().st_mode):  # lstat: a symbolic link is not a regular file
            return None
        if not path.resolve(strict=True).is_relative_to(base):  # a linked folder on the way out of the root
            return None
    except (OSError, RuntimeError, ValueError):
        return None
    return path


def read_repo_file(root: Path, rel: str | PurePath, limit: int = MAX_SCAN_BYTES) -> str | None:
    """Up to `limit` bytes of `root/rel` as text, only when repo_file() allows it (opened without following a link)."""
    path = repo_file(root, rel)
    if path is None:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):  # swapped for something else since the check
            return None
        return fh.read(limit).decode("utf-8", errors="replace")


def _read(root: Path, rel: str | PurePath, limit: int = MAX_SCAN_BYTES) -> str:
    return read_repo_file(root, rel, limit) or ""


def list_files(root: Path, limit: int = MAX_FILES) -> list[Path]:
    """Relative paths of the repository's files, skipping vendored and build directories."""
    found: list[Path] = []
    stack = [root]
    while stack and len(found) < limit:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda p: p.name)
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in SKIP_DIRS:
                    stack.append(entry)
            elif entry.is_file():
                found.append(entry.relative_to(root))
                if len(found) >= limit:
                    break
    return found


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _add(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def readme_summary(root: Path) -> str:
    for name in ("README.md", "readme.md", "README.rst", "README.txt", "README"):
        found = read_repo_file(root, name, 40_000)
        if found is not None:
            text = found
            break
    else:
        return ""
    paragraph: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "![", "[![", "<", "=", "---", "```", "|", ">")):
            if len(" ".join(paragraph)) >= 30:
                break
            paragraph = []
            continue
        paragraph.append(line)
    summary = " ".join(paragraph)
    summary = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", summary)
    summary = re.sub(r"[*_`]", "", summary)
    return summary[:280].strip()


def detect_license(root: Path) -> str | None:
    for path in sorted(root.iterdir()) if root.is_dir() else []:
        if path.name.upper().startswith(("LICENSE", "LICENCE", "COPYING")) and repo_file(root, path.name):
            text = _read(root, path.name, 3000)
            for marker, name in (
                ("GNU AFFERO", "AGPL-3.0"), ("GNU LESSER", "LGPL"), ("GNU GENERAL PUBLIC", "GPL"),
                ("Apache License", "Apache-2.0"), ("Mozilla Public License", "MPL-2.0"), ("MIT License", "MIT"),
                ("Permission is hereby granted, free of charge", "MIT"), ("BSD", "BSD"), ("ISC License", "ISC"),
                ("Business Source License", "BUSL-1.1"), ("Elastic License", "Elastic"),
            ):
                if marker.lower() in text.lower():
                    return name
            return "custom"
    return None


def _req_name(line: str) -> str:
    return re.split(r"[<>=!~\[;\s]", line.strip(), maxsplit=1)[0].lower()


def collect_dependencies(root: Path, files: list[Path]) -> tuple[set[str], dict[str, Any]]:
    """Dependency names across ecosystems, plus a few raw facts (package.json, pyproject)."""
    deps: set[str] = set()
    facts: dict[str, Any] = {}
    names = {f.as_posix() for f in files}

    if "package.json" in names:
        try:
            pkg = json.loads(_read(root, "package.json"))
            facts["package.json"] = pkg
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                deps.update(k.lower() for k in (pkg.get(section) or {}))
        except (json.JSONDecodeError, AttributeError):
            pass
    for f in files:
        if f.parent == Path(".") and re.match(r"requirements.*\.txt$", f.name):
            for line in _read(root, f).splitlines():
                if line.strip() and not line.strip().startswith(("#", "-")):
                    deps.add(_req_name(line))
    if "pyproject.toml" in names:
        try:
            py = tomllib.loads(_read(root, "pyproject.toml"))
            facts["pyproject"] = py
            for dep in (py.get("project", {}).get("dependencies") or []):
                deps.add(_req_name(dep))
            deps.update(k.lower() for k in py.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {})
        except (tomllib.TOMLDecodeError, AttributeError):
            pass
    if "go.mod" in names:
        for match in re.finditer(r"^\s*(?:require\s+)?([\w.-]+\.[\w]+/[\w./-]+)\s+v", _read(root, "go.mod"), re.MULTILINE):
            module = match.group(1).lower()
            deps.add(module)
            parts = module.split("/")
            if len(parts) >= 3:
                deps.add("/".join(parts[1:3]))
    if "Gemfile" in names:
        deps.update(m.group(1).lower() for m in re.finditer(r"""^\s*gem\s+["']([\w-]+)["']""", _read(root, "Gemfile"), re.MULTILINE))
    if "composer.json" in names:
        try:
            deps.update(k.lower() for k in (json.loads(_read(root, "composer.json")).get("require") or {}))
        except (json.JSONDecodeError, AttributeError):
            pass
    if "Cargo.toml" in names:
        try:
            cargo = tomllib.loads(_read(root, "Cargo.toml"))
            facts["cargo"] = cargo
            deps.update(k.lower() for k in cargo.get("dependencies", {}) or {})
        except tomllib.TOMLDecodeError:
            pass
    if "pom.xml" in names:
        deps.update(m.group(1).lower() for m in re.finditer(r"<artifactId>([\w.-]+)</artifactId>", _read(root, "pom.xml")))
    return deps, facts


def _env_keys_from_compose(compose: dict[str, Any]) -> tuple[list[str], list[int], list[str]]:
    """Environment keys, published host ports, and service/image names of a compose file."""
    keys: list[str] = []
    ports: list[int] = []
    names: list[str] = []
    for name, service in (compose.get("services") or {}).items():
        if not isinstance(service, dict):
            continue
        names += [str(name), str(service.get("image", "")).rsplit("/", 1)[-1].split(":")[0]]
        env = service.get("environment") or {}
        if isinstance(env, dict):
            keys.extend(str(k) for k in env)
        elif isinstance(env, list):
            keys.extend(str(item).split("=", 1)[0] for item in env)
        for port in service.get("ports") or []:
            host_part = str(port.get("published", "") if isinstance(port, dict) else port).split(":")
            candidate = host_part[-2] if len(host_part) >= 2 else host_part[0]
            candidate = candidate.split("/")[0]
            if candidate.isdigit():
                ports.append(int(candidate))
    return keys, ports, names


def apply_env_rules(manifest: Manifest, keys: list[str], values: dict[str, str]) -> None:
    for key in keys:
        upper = key.upper()
        for pattern, capability, sso in ENV_RULES:
            if pattern.search(upper):
                if capability:
                    _add(manifest.consumes, capability)
                if sso and manifest.auth.sso in ("unknown", "none"):
                    manifest.auth.sso = sso  # type: ignore[assignment]
        if "WEBHOOK" in upper:
            _add(manifest.provides, "webhooks")
    for value in values.values():
        scheme = value.split("://", 1)[0].lower() if "://" in value else ""
        if scheme in URL_SCHEMES:
            _add(manifest.consumes, URL_SCHEMES[scheme])


def parse_env_file(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.removeprefix("export ").strip()] = value.strip().strip("\"'")
    return values


# --------------------------------------------------------------------------------------
# repositories (open-source projects, local projects, closed-source installs)
# --------------------------------------------------------------------------------------


def load_native_manifest(root: Path) -> tuple[dict[str, Any] | None, str | None]:
    for name in MANIFEST_NAMES:
        if repo_file(root, name):
            try:
                data = yaml.safe_load(_read(root, name)) or {}
                if not isinstance(data, dict):
                    return None, f"{name} is not a mapping"
                return data, None
            except yaml.YAMLError as exc:
                return None, f"{name} could not be parsed: {exc}"
    return None, None


def analyze_repo(root: Path, tool_id: str, name: str) -> tuple[Manifest, list[str]]:
    """Infer a manifest for a folder on disk. Returns the manifest and human-readable notes."""
    notes: list[str] = []
    files = list_files(root)
    names = {f.as_posix() for f in files}
    lower_names = {n.lower() for n in names}
    m = Manifest(id=tool_id, name=name)

    source_files = [f for f in files if f.suffix.lower() in SOURCE_EXT]
    binaries = [f for f in files if f.suffix.lower() in BINARY_EXT]
    if not source_files and binaries:
        m.kind = "closed"
        notes.append(f"No source code found, {len(binaries)} binaries - treating as closed source.")
    m.description = readme_summary(root)
    m.license = detect_license(root)

    deps, facts = collect_dependencies(root, files)
    for dep in sorted(deps):
        rule = DEP_RULES.get(dep)
        if not rule:
            continue
        field, value = rule
        if field == "provides":
            _add(m.provides, value)
        elif field == "consumes":
            _add(m.consumes, value)
        elif field == "stack":
            _add(m.stack, value)
        elif field == "sso" and m.auth.sso in ("unknown", "none"):
            m.auth.sso = value  # type: ignore[assignment]

    # stacks
    pkg = facts.get("package.json") or {}
    if pkg:
        _add(m.stack, "node")
        m.version = m.version or pkg.get("version")
    if "pyproject.toml" in names or any(n.startswith("requirements") for n in names) or "manage.py" in names:
        _add(m.stack, "python")
        m.version = m.version or (facts.get("pyproject") or {}).get("project", {}).get("version")
    if "go.mod" in names:
        _add(m.stack, "go")
    if "Cargo.toml" in names:
        _add(m.stack, "rust")
        m.version = m.version or (facts.get("cargo") or {}).get("package", {}).get("version")
    if "pom.xml" in names or "build.gradle" in names or "build.gradle.kts" in names:
        _add(m.stack, "java")
    if "Gemfile" in names:
        _add(m.stack, "ruby")
    if "composer.json" in names:
        _add(m.stack, "php")
    if "Dockerfile" in names:
        _add(m.stack, "docker")

    # environment variables -> consumed services, SSO
    env_values: dict[str, str] = {}
    for env_name in ENV_FILES:
        if env_name in names:
            env_values.update(parse_env_file(_read(root, env_name)))
    ports: list[int] = []
    service_names: list[str] = []
    compose_name = next((c for c in COMPOSE_FILES if c in names), None)
    if compose_name:
        _add(m.stack, "compose")
        try:
            compose = yaml.safe_load(_read(root, compose_name)) or {}
            keys, compose_ports, service_names = _env_keys_from_compose(compose if isinstance(compose, dict) else {})
            ports.extend(compose_ports)
            apply_env_rules(m, keys, {})
        except yaml.YAMLError:
            notes.append(f"{compose_name} could not be parsed.")
    apply_env_rules(m, list(env_values), env_values)
    m.auth.env_keys = sorted(k for k in env_values if SSO_ENV_RE.match(k.upper()))

    # ports
    for env_text in (_read(root, n) for n in ENV_FILES if n in names):
        ports.extend(int(p) for p in PORT_ENV_RE.findall(env_text))
    if "Dockerfile" in names:
        ports.extend(int(p) for p in EXPOSE_RE.findall(_read(root, "Dockerfile")))
    for script in (pkg.get("scripts") or {}).values():
        ports.extend(int(p) for p in PORT_ARG_RE.findall(str(script)))
    if not ports:
        for key, port in DEFAULT_PORTS.items():
            if key in deps or key in m.stack:
                ports.append(port)
                notes.append(f"Port {port} guessed from the {key} default.")
                break
    m.launch.port = ports[0] if ports else None

    # launch command
    scripts = pkg.get("scripts") or {}
    if compose_name:
        m.launch.command = "docker compose up"
    elif "start" in scripts:
        m.launch.setup, m.launch.command = "npm install", "npm start"
    elif "dev" in scripts:
        m.launch.setup, m.launch.command = "npm install", "npm run dev"
    elif "manage.py" in names:
        m.launch.command = f"python manage.py runserver 0.0.0.0:{m.launch.port or 8000}"
    elif "fastapi" in deps and ("main.py" in names or "app/main.py" in names):
        module = "main:app" if "main.py" in names else "app.main:app"
        m.launch.command = f"uvicorn {module} --host 0.0.0.0 --port {m.launch.port or 8000}"
    elif "flask" in deps:
        m.launch.command = f"flask run --host 0.0.0.0 --port {m.launch.port or 5000}"
    elif "go.mod" in names:
        m.launch.command = "go run ."
    elif "Cargo.toml" in names:
        m.launch.command = "cargo run --release"
    elif "Makefile" in names and re.search(r"^run:", _read(root, "Makefile"), re.MULTILINE):
        m.launch.command = "make run"
    elif "Dockerfile" in names:
        port = m.launch.port or 8080
        m.launch.setup = f"docker build -t hub-{tool_id} ."
        m.launch.command = f"docker run --rm -p {port}:{port} hub-{tool_id}"
    elif m.kind == "closed":
        launchers = [b for b in binaries if b.parent == Path(".") and b.suffix.lower() in (".exe", ".appimage", ".bin")]
        if launchers:
            m.launch.command = f'"{launchers[0].as_posix()}"'
    if m.launch.command:
        m.launch.cwd = "."

    # scan source for health endpoints and webhooks
    health_route = None
    for f in source_files[:600]:
        text = _read(root, f)
        if health_route is None:
            match = HEALTH_RE.search(text)
            if match:
                health_route = match.group(1)
        if "webhooks" not in m.provides and WEBHOOK_RE.search(text):
            _add(m.provides, "webhooks")
        if health_route and "webhooks" in m.provides:
            break
    if health_route and m.launch.port:
        m.health.url = f"http://localhost:{m.launch.port}{health_route}"

    # API specs
    spec = next((f for f in files if f.name.lower() in OPENAPI_NAMES), None)
    if spec:
        m.api.type = "rest"
        m.api.spec = spec.as_posix()
        try:
            doc = yaml.safe_load(_read(root, spec, 2_000_000)) or {}
            m.api.endpoints = count_operations(doc)
        except yaml.YAMLError:
            pass
    elif "api.rest" in m.provides:
        m.api.type = "rest"
    elif "api.graphql" in m.provides:
        m.api.type = "graphql"
    if m.api.type != "none" and m.launch.port:
        m.api.base_url = f"http://localhost:{m.launch.port}"

    apply_known_tools(m, " ".join([tool_id, name, *service_names]))
    if "webhooks" in m.provides:
        _add(m.events.emits, f"{tool_id}.*")
    if m.launch.port:
        m.ui.url = f"http://localhost:{m.launch.port}"
    if "web-ui" in m.stack:
        m.ui.embed = True
    if m.auth.sso == "unknown" and m.kind == "oss" and source_files:
        m.auth.sso = "none"
    if not source_files and not binaries and "dockerfile" not in lower_names:
        notes.append("The folder contains no recognisable source code or binaries.")

    native, problem = load_native_manifest(root)
    if problem:
        notes.append(f"Ignored the tool's own manifest: {problem}")
    if native:
        ui = native.get("ui")
        if isinstance(ui, dict) and "widgets" in ui:  # the tool's own dashboard widgets: bad ones are left out, not all
            from ..extensions.pack import widget_decls

            ui["widgets"], problems = widget_decls(ui["widgets"])
            notes.extend(f"Ignored a dashboard widget of the tool's own manifest: {p}" for p in problems)
        merged = deep_merge(m.model_dump(), {k: v for k, v in native.items() if k != "id"})
        merged["native"] = True
        try:
            m = Manifest.model_validate(merged)
            notes.append("Found a native hub manifest - it overrides inferred values.")
        except ValueError as exc:
            notes.append(f"Ignored the tool's own manifest, it is invalid: {exc}")
    return m, notes


def apply_known_tools(m: Manifest, text: str) -> list[str]:
    """Add what the well-known tools named in `text` (ids, names, service or host names) provide; their names."""
    lowered = text.lower()
    found = []
    for known, capabilities in KNOWN_TOOLS.items():
        if known in lowered or known.replace(".", "") in lowered.replace(".", ""):
            found.append(known)
            for capability in capabilities:
                _add(m.provides, capability)
            if any(c.startswith("auth.") for c in capabilities):
                m.auth.sso = "oidc"
    return found


def count_operations(doc: dict[str, Any]) -> int:
    methods = {"get", "put", "post", "delete", "patch", "head", "options"}
    paths = doc.get("paths") or {}
    return sum(1 for item in paths.values() if isinstance(item, dict) for method in item if method in methods)


# --------------------------------------------------------------------------------------
# SaaS services
# --------------------------------------------------------------------------------------


async def analyze_saas(tool_id: str, name: str, base_url: str, openapi_url: str | None) -> tuple[Manifest, list[str]]:
    """A SaaS tool's manifest: what its OpenAPI spec says, plus what a well-known tool (recognised by its id, name or
    host name - a hosted Keycloak, Okta, Snipe-IT, ...) provides, as for a repository."""
    m, notes = await _saas_from_spec(tool_id, name, base_url, openapi_url)
    sso = m.auth.sso
    known = apply_known_tools(m, " ".join([tool_id, name, urlparse(base_url).hostname or ""]))
    if known:
        if sso not in ("unknown", "none"):  # what the spec says about sign-in is more specific than the name
            m.auth.sso = sso
        if "webhooks" in m.provides and not m.events.emits:
            m.events.emits = [f"{tool_id}.*"]
        notes.append(f"Recognised a well-known tool ({', '.join(known)}): it provides {', '.join(m.provides)}.")
    return m, notes


async def _saas_from_spec(tool_id: str, name: str, base_url: str, openapi_url: str | None) -> tuple[Manifest, list[str]]:
    notes: list[str] = []
    m = Manifest(id=tool_id, name=name, kind="saas", license="proprietary")
    m.ui.url = base_url
    m.health.url = base_url
    m.stack = ["saas"]
    if not openapi_url:
        notes.append("No OpenAPI spec given - its API is unknown until one is added.")
        return m, notes
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
            response = await client.get(openapi_url)
            response.raise_for_status()
        doc = yaml.safe_load(response.text) or {}
    except (httpx.HTTPError, yaml.YAMLError) as exc:
        notes.append(f"Could not read the OpenAPI spec: {exc}")
        return m, notes
    if not isinstance(doc, dict):
        notes.append("The OpenAPI document is not an object.")
        return m, notes

    info = doc.get("info") or {}
    m.description = str(info.get("description") or info.get("title") or "")[:280]
    m.version = str(info.get("version")) if info.get("version") else None
    m.api = m.api.model_copy(update={"type": "rest", "spec": openapi_url, "endpoints": count_operations(doc)})
    servers = doc.get("servers") or []
    if servers and isinstance(servers[0], dict) and servers[0].get("url"):
        m.api.base_url = servers[0]["url"]
    elif doc.get("host"):
        m.api.base_url = f"{(doc.get('schemes') or ['https'])[0]}://{doc['host']}{doc.get('basePath', '')}"
    _add(m.provides, "api.rest")

    schemes = (doc.get("components") or {}).get("securitySchemes") or doc.get("securityDefinitions") or {}
    kinds = {str(s.get("type", "")).lower() for s in schemes.values() if isinstance(s, dict)}
    if "openidconnect" in kinds:
        m.auth.sso = "oidc"
    elif "oauth2" in kinds:
        m.auth.sso = "oauth2"
    elif kinds:
        m.auth.sso = "none"
        m.auth.notes = "API keys / tokens only"

    webhooks = doc.get("webhooks") or doc.get("x-webhooks") or {}
    if isinstance(webhooks, dict) and webhooks:
        _add(m.provides, "webhooks")
        m.events.emits = [f"{tool_id}.{key}" for key in list(webhooks)[:50]]
    elif any("webhook" in str(p).lower() for p in (doc.get("paths") or {})):
        _add(m.provides, "webhooks")
        m.events.emits = [f"{tool_id}.*"]
    notes.append(f"Read OpenAPI spec: {m.api.endpoints} operations.")
    return m, notes
