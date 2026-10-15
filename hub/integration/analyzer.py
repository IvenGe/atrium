"""Understands an imported tool and produces its hub manifest.

The analyzer is deterministic: it reads well-known files (package manifests,
Dockerfiles, compose files, .env examples, OpenAPI specs, README) and infers
the stack, launch command, port, health endpoint, SSO support and the
capabilities a tool provides or consumes. A well-known product's profile
(known_tools) fills what the generic rules left empty, and a tool that ships
its own ``hub.manifest.yaml`` is treated as native and its manifest wins.
"""

from __future__ import annotations

import json
import os
import re
import stat
import tomllib
from collections import deque
from pathlib import Path, PurePath
from typing import Any
from urllib.parse import urlparse, urlsplit

import httpx
import yaml

from ..models import MANIFEST_HUB_KEYS, Manifest
from . import known_tools

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__", ".next",
    "target", ".idea", ".vscode", ".tox", "coverage", ".cache", "bin", "obj",
}
# Test suites are listed after everything else (a big one must not use up the listing before the tool's own files)
# and never searched for the tool's OpenAPI spec.
TEST_DIRS = {"test", "tests", "testsuite", "test-framework", "__tests__", "spec", "e2e", "testing", "fixtures"}
BUILD_FILES = ("pom.xml", "build.gradle", "build.gradle.kts")
SOURCE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java", ".kt", ".php", ".rs", ".cs", ".ex", ".scala"}
BINARY_EXT = {".exe", ".dll", ".so", ".dylib", ".jar", ".msi", ".appimage", ".bin"}
ENV_FILES = (".env.example", ".env.sample", ".env.template", ".env.dist", "env.example", "example.env", "sample.env")
COMPOSE_FILES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
OPENAPI_NAMES = {"openapi.json", "openapi.yaml", "openapi.yml", "swagger.json", "swagger.yaml", "swagger.yml"}
MANIFEST_NAMES = ("hub.manifest.yaml", "hub.manifest.yml", "hub.manifest.json")
MAX_FILES = 4000
MAX_SCAN_BYTES = 200_000
SPEC_SEARCH_ENTRIES = 30_000  # find_spec: the deep OpenAPI search past the listing cap
SPEC_SEARCH_DEPTH = 8
# Manifest fields where a "TODO: ..." string in a tool's own manifest is a placeholder, never a value
PLACEHOLDER_FIELDS = ("launch.command", "launch.setup", "health.url", "api.base_url", "api.spec", "ui.url")

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
        "quarkus-rest", "quarkus-resteasy", "quarkus-resteasy-reactive", "quarkus-rest-jackson",
        "quarkus-resteasy-jackson", "spring-boot-starter-webflux",
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

# Well-known tools and what they provide to the rest of the suite (read-only, derived from known_tools.PROFILES, which
# also knows how to run them; kept for callers of the former table).
KNOWN_TOOLS: dict[str, list[str]] = {
    name: list(p.provides) for p in known_tools.PROFILES.values() if p.provides for name in p.names
}

DEFAULT_PORTS = {"next": 3000, "react": 3000, "nuxt": 3000, "rails": 3000, "express": 3000, "django": 8000,
                 "fastapi": 8000, "flask": 5000, "go": 8080, "spring": 8080, "php": 8000, "quarkus": 8080}

HEALTH_RE = re.compile(r"""["'`](/(?:api/)?(?:v\d+/)?(?:healthz?|healthcheck|health-check|livez|readyz|ping|status))["'`]""")
WEBHOOK_RE = re.compile(r"webhook", re.IGNORECASE)
PORT_ENV_RE = re.compile(r"^(?:APP_|HTTP_|SERVER_|WEB_)?PORT\s*=\s*\"?(\d{2,5})", re.MULTILINE)
PORT_ARG_RE = re.compile(r"(?:--port[= ]|-p\s+)(\d{2,5})")
EXPOSE_RE = re.compile(r"^\s*EXPOSE\s+(\d{2,5})", re.MULTILINE | re.IGNORECASE)
GRADLE_DEP_RE = re.compile(r"""["']([\w.-]+):([\w.-]+)(?::[^"'\s]*)?["']""")  # 'group:artifact:version'


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


def _test_dir(name: str) -> bool:
    return name.lower() in TEST_DIRS


def list_files(root: Path, limit: int = MAX_FILES) -> list[Path]:
    """Relative paths of the repository's files, skipping vendored and build directories and symbolic links.

    Breadth-first in name order, so the files that describe a tool (near its root) come first, and folders of test
    suites (TEST_DIRS, with everything under them) only after all other folders: a big test suite cannot use up the
    `limit` before the tool's own files are listed."""
    found: list[Path] = []
    queues: tuple[deque[Path], deque[Path]] = (deque([root]), deque())  # (other folders, test folders)
    while (queues[0] or queues[1]) and len(found) < limit:
        late = not queues[0]
        current = (queues[1] if late else queues[0]).popleft()
        try:
            with os.scandir(current) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name not in SKIP_DIRS:
                        queues[1 if late or _test_dir(entry.name) else 0].append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    found.append(Path(entry.path).relative_to(root))
                    if len(found) >= limit:
                        break
            except OSError:
                continue
    return found


def bin_launchers(root: Path) -> list[str]:
    """The launcher scripts of a release folder: bin/*.sh (bin/*.bat on Windows), regular files only (no links), sorted.
    bin/ is in SKIP_DIRS, so list_files never shows them."""
    suffix = ".bat" if os.name == "nt" else ".sh"
    try:
        with os.scandir(root / "bin") as it:
            names = sorted(e.name for e in it if e.name.lower().endswith(suffix) and not e.is_symlink())
    except OSError:
        return []
    return [f"bin/{n}" for n in names if repo_file(root, f"bin/{n}") is not None]


def find_spec(root: Path) -> Path | None:
    """The shallowest OpenAPI / Swagger file (OPENAPI_NAMES) of a repository, searched past list_files' cap:
    breadth-first, skipping SKIP_DIRS, TEST_DIRS and symbolic links, at most SPEC_SEARCH_ENTRIES entries and
    SPEC_SEARCH_DEPTH folders deep."""
    queue: deque[tuple[Path, int]] = deque([(root, 0)])
    seen = 0
    while queue and seen < SPEC_SEARCH_ENTRIES:
        current, depth = queue.popleft()
        try:
            with os.scandir(current) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            continue
        for entry in entries:
            seen += 1
            if seen > SPEC_SEARCH_ENTRIES:
                break
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if depth + 1 < SPEC_SEARCH_DEPTH and entry.name not in SKIP_DIRS and not _test_dir(entry.name):
                        queue.append((Path(entry.path), depth + 1))
                elif entry.name.lower() in OPENAPI_NAMES and entry.is_file(follow_symlinks=False):
                    rel = Path(entry.path).relative_to(root)
                    if repo_file(root, rel) is not None:
                        return rel
            except OSError:
                continue
    return None


def placeholder(value: Any) -> bool:
    """Whether a manifest value is a "TODO ..." placeholder, which never counts as a value."""
    return isinstance(value, str) and value.strip().upper().startswith("TODO")


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
    for gradle in ("build.gradle", "build.gradle.kts"):
        if gradle in names:
            deps.update(m.group(2).lower() for m in GRADLE_DEP_RE.finditer(_read(root, gradle)))
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
    """Infer a manifest for a folder on disk. Returns the manifest and human-readable notes.

    In this order: generic inference (kind, dependencies, stack, environment, compose file, ports, launch rules); the
    profile of a well-known product (known_tools: fills empty fields only); generic fallbacks for what is still empty
    (a bin/ launcher, a health route in the source, an OpenAPI spec - searched past the listing cap too - and the
    addresses); then the tool's own hub.manifest.*, which wins (without the hub-only keys and TODO placeholders)."""
    notes: list[str] = []
    files = list_files(root)
    names = {f.as_posix() for f in files}
    lower_names = {n.lower() for n in names}
    m = Manifest(id=tool_id, name=name)

    source_files = [f for f in files if f.suffix.lower() in SOURCE_EXT]
    binaries = [f for f in files if f.suffix.lower() in BINARY_EXT]
    launchers = bin_launchers(root)
    # a Java distribution (Keycloak, Tomcat, ...): jars plus bin/ launchers and nothing to build - runnable, not closed
    java_dist = bool(binaries and launchers and all(f.suffix.lower() == ".jar" for f in binaries)
                     and not any(b in names for b in BUILD_FILES))
    if not source_files and binaries and not java_dist:
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
    if any(b in names for b in BUILD_FILES):
        _add(m.stack, "java")
        build_text = " ".join(_read(root, b) for b in BUILD_FILES if b in names).lower()
        if "quarkus" in build_text:
            _add(m.stack, "quarkus")
        if "spring-boot" in build_text or "org.springframework.boot" in build_text:
            _add(m.stack, "spring")
    if java_dist:
        _add(m.stack, "java")
        _add(m.stack, "dist")
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
    compose: dict[str, Any] | None = None
    compose_name = next((c for c in COMPOSE_FILES if c in names), None)
    if compose_name:
        _add(m.stack, "compose")
        try:
            loaded = yaml.safe_load(_read(root, compose_name)) or {}
            compose = loaded if isinstance(loaded, dict) else {}
            keys, compose_ports, service_names = _env_keys_from_compose(compose)
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
    guessed: str | None = None
    if not ports:
        for key, port in DEFAULT_PORTS.items():
            if key in deps or key in m.stack:
                ports.append(port)
                guessed = f"Port {port} guessed from the {key} default."
                notes.append(guessed)
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
        exes = [b for b in binaries if b.parent == Path(".") and b.suffix.lower() in (".exe", ".appimage", ".bin")]
        if exes:
            m.launch.command = f'"{exes[0].as_posix()}"'
    if m.launch.command:
        m.launch.cwd = "."

    # a well-known product: its profile fills what is still empty (a guessed default port gives way to the product's
    # own, unless the launch command was built with it)
    match = known_tools.recognise([tool_id, name], root=root, compose=compose)
    if match:
        if (guessed and match.profile.default_port and match.shape not in ("source", "saas")
                and str(m.launch.port) not in (m.launch.command or "")):
            notes.remove(guessed)
            m.launch.port = None
        notes += known_tools.apply(m, match, root=root, compose=compose)
    # what the products named in compose services provide - and, for a project merely named after a product
    # ("keycloak-theme"), what its name gave before profiles existed (it is not that product: no profile facts)
    known_tools.legacy_capabilities(m, " ".join(service_names if match else [tool_id, name, *service_names]))

    # generic fallbacks for what is still empty: a release folder's launcher
    if not m.launch.command and launchers:
        launcher = _pick_launcher(launchers, tool_id, name, release=java_dist or not source_files)
        if launcher:
            m.launch.command = launcher.replace("/", "\\") if os.name == "nt" else launcher
            m.launch.cwd = "."
            notes.append(f"Launch command taken from the release folder's launcher {launcher}.")

    # scan source for health endpoints (unless the product's profile knows its own) and webhooks
    want_health = m.health.url is None and (match is None or known_tools.health_plan(m, tool_id) is None)
    health_route = None
    for f in source_files[:600]:
        if not want_health and "webhooks" in m.provides:
            break
        text = _read(root, f)
        if want_health and health_route is None:
            found = HEALTH_RE.search(text)
            if found:
                health_route = found.group(1)
        if "webhooks" not in m.provides and WEBHOOK_RE.search(text):
            _add(m.provides, "webhooks")
        if (health_route or not want_health) and "webhooks" in m.provides:
            break
    if want_health and health_route and m.launch.port:
        m.health.url = f"http://localhost:{m.launch.port}{health_route}"

    # API specs: a listed one (the tool's own before a test suite's), else one past the listing cap
    if m.api.type == "none":
        specs = [f for f in files if f.name.lower() in OPENAPI_NAMES]
        spec = next((f for f in specs if not any(_test_dir(part) for part in f.parts[:-1])), specs[0] if specs else None)
        if spec is None and len(files) >= MAX_FILES:
            spec = find_spec(root)
        if spec:
            m.api.type = "rest"
            m.api.spec = spec.as_posix()
            try:
                doc = yaml.safe_load(_read(root, spec, 2_000_000)) or {}
                m.api.endpoints = count_operations(doc) if isinstance(doc, dict) else 0
            except yaml.YAMLError:
                pass
        elif "api.rest" in m.provides:
            m.api.type = "rest"
        elif "api.graphql" in m.provides:
            m.api.type = "graphql"
    if m.api.type != "none" and m.launch.port and not m.api.base_url:
        m.api.base_url = f"http://localhost:{m.launch.port}"

    if "webhooks" in m.provides:
        _add(m.events.emits, f"{tool_id}.*")
    if m.launch.port and not m.ui.url:
        m.ui.url = f"http://localhost:{m.launch.port}"
    if "web-ui" in m.stack:
        m.ui.embed = True
    if m.auth.sso == "unknown" and m.kind == "oss" and source_files:
        m.auth.sso = "none"
    m.consumes = [c for c in m.consumes if c not in m.provides]  # a tool never consumes what it provides
    if not source_files and not binaries and not launchers and "dockerfile" not in lower_names:
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
        own = {k: v for k, v in native.items() if k not in MANIFEST_HUB_KEYS}  # the hub's own keys are not the tool's
        file_name = next((n for n in MANIFEST_NAMES if repo_file(root, n)), MANIFEST_NAMES[0])
        for path in PLACEHOLDER_FIELDS:
            section, key = path.split(".")
            block = own.get(section)
            if isinstance(block, dict) and placeholder(block.get(key)):
                own[section] = {k: v for k, v in block.items() if k != key}
                notes.append(f"Ignored a TODO placeholder in {file_name}: {path}")
        merged = deep_merge(m.model_dump(), own)
        merged["native"] = True
        try:
            m = _follow_port(Manifest.model_validate(merged), m.launch.port, own)
            notes.append("Found a native hub manifest - it overrides inferred values.")
        except ValueError as exc:
            notes.append(f"Ignored the tool's own manifest, it is invalid: {exc}")
    return m, notes


def _follow_port(m: Manifest, inferred: int | None, own: dict[str, Any]) -> Manifest:
    """The addresses Atrium derived from the inferred port (the portal URL, the API base URL, a profile's health URL:
    http://localhost:<port>...) moved to the port the tool's own manifest sets, unless that file sets them itself."""
    port = m.launch.port
    if not inferred or not port or port == inferred:
        return m

    def given(section: str, key: str) -> bool:
        block = own.get(section)
        return isinstance(block, dict) and block.get(key) is not None

    def moved(url: str | None) -> str | None:
        if not url or urlsplit(url).hostname not in ("localhost", "127.0.0.1"):
            return url
        return re.sub(rf":{inferred}(?=[/?#]|$)", f":{port}", url, count=1)

    if not given("ui", "url"):
        m.ui.url = moved(m.ui.url)
    if not given("api", "base_url"):
        m.api.base_url = moved(m.api.base_url)
    if not given("api", "spec") and m.api.spec and m.api.spec.startswith(("http://localhost", "http://127.0.0.1")):
        m.api.spec = moved(m.api.spec)
    if not given("health", "url"):
        m.health.url = moved(m.health.url)
    return m


# bin/ scripts that do something else than start the program (a deploy, stop or build script is no launch command)
NOT_LAUNCHER = re.compile(r"(?:^|[-_.])(?:deploy|release|stop|shutdown|kill|install|uninstall|build|test|tests|lint|"
                          r"setup|backup|restore|clean|migrate|upgrade|update|bench|check|format|fmt|ci|env|common|"
                          r"functions|lib|config|configure)(?:[-_.]|$)")


def _pick_launcher(launchers: list[str], tool_id: str, name: str, *, release: bool = False) -> str | None:
    """The bin/ launcher that starts the tool: the one named like the tool, else a run/start/server/startup script,
    else - only in a release folder (built jars, no source to build: `release`) - the only script whose name is not
    one of another job (NOT_LAUNCHER: deploy, stop, build, test, ...). A source repository's lone bin/deploy.sh is no
    launch command: the launch stays empty, and the launch_command patch (an AI proposal or the editor) applies."""
    def squash(text: str) -> str:
        return re.sub(r"[^a-z0-9]", "", text.lower())

    stems = {PurePath(launcher).stem.lower(): launcher for launcher in launchers}
    wanted = {squash(tool_id), squash(name)} - {""}
    for stem, launcher in stems.items():
        if squash(stem) in wanted:
            return launcher
    for generic in ("run", "start", "server", "startup"):
        if generic in stems:
            return stems[generic]
    starters = [launcher for stem, launcher in stems.items() if not NOT_LAUNCHER.search(stem)]
    return starters[0] if release and len(starters) == 1 else None


def apply_known_tools(m: Manifest, text: str) -> list[str]:
    """Add what the well-known tools named in `text` (ids, names, service or host names) provide; their names.
    Kept for callers of the former table: known_tools.legacy_capabilities (which sets no recognised product)."""
    return known_tools.legacy_capabilities(m, text)


def count_operations(doc: dict[str, Any]) -> int:
    methods = {"get", "put", "post", "delete", "patch", "head", "options"}
    paths = doc.get("paths") or {}
    return sum(1 for item in paths.values() if isinstance(item, dict) for method in item if method in methods)


# --------------------------------------------------------------------------------------
# SaaS services
# --------------------------------------------------------------------------------------


async def analyze_saas(tool_id: str, name: str, base_url: str, openapi_url: str | None) -> tuple[Manifest, list[str]]:
    """A SaaS tool's manifest: what its OpenAPI spec says, plus what Atrium knows about a well-known product
    (recognised by its id, name or host name - a hosted Keycloak, Okta, Snipe-IT, ...): what it provides and, when
    the spec said nothing, its API under the service's address."""
    m, notes = await _saas_from_spec(tool_id, name, base_url, openapi_url)
    sso = m.auth.sso
    host = urlparse(base_url).hostname or ""
    match = known_tools.recognise([tool_id, name], host=host)
    if match is None:  # named after a product without being it: what the name gave before profiles existed
        known_tools.legacy_capabilities(m, " ".join([tool_id, name, host]))
    if match:
        known_tools.apply(m, match)
        if sso not in ("unknown", "none"):  # what the spec says about sign-in is more specific than the name
            m.auth.sso = sso
        if "webhooks" in m.provides and not m.events.emits:
            m.events.emits = [f"{tool_id}.*"]
        provides = f": it provides {', '.join(m.provides)}." if m.provides else "."
        notes.append(f"Recognised a well-known tool ({match.profile.title}){provides}")
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
