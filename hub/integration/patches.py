"""Patch planning and application.

When a tool does not fit the hub well, the Patch Agent turns each gap into a
patch. Patches land in one of three places:

* ``repo``     - a change to the tool's own source, committed on a new branch in a
                 separate git worktree (the user's checkout is never touched).
* ``adapter``  - files the hub keeps next to the tool (health probes, an SSO proxy,
                 event pollers). This is how closed-source and SaaS tools are integrated.
* ``manifest`` - a hub-side override of the tool's manifest (e.g. a new port).

Every patch goes through the approval queue unless the hub runs autonomously.

Single sign-on patches (``sso_connect``, ``sso_code``, ``sso_proxy``) also register the tool as a client at the
suite's identity provider. Their client secret only exists as a placeholder until the patch is applied; then the
hub generates it (once per tool and provider) and writes it into the adapter folder - never into a repository.
"""

from __future__ import annotations

import re
import textwrap
import zlib
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

import yaml

from ..execution.runner import run_exec
from ..models import FileChange, Manifest, Patch, SsoPlan, Tool
from ..store import new_id
from . import identity, sso_catalog
from .analyzer import deep_merge
from .identity import CLIENT_SECRET, COOKIE_SECRET, ClientSpec, IdentityPrefs, IdentityProvider
from .sso_catalog import client_id_for, env_text, tool_url

if TYPE_CHECKING:
    from ..core import Hub

STRATEGY_TITLES = {
    "add_manifest": "Adopt a hub manifest",
    "health_endpoint": "Add a health endpoint",
    "health_probe": "Add a health probe adapter",
    "sso_connect": "Connect single sign-on to the identity provider",
    "sso_code": "Add OpenID Connect sign-in to the code",
    "sso_proxy": "Put an SSO proxy in front of the tool",
    "event_adapter": "Add an event adapter",
    "api_adapter": "Add an API adapter skeleton",
    "reassign_port": "Move the tool to a free port",
}
OIDC_CALLBACK = "/auth/oidc/callback"  # where code patches put the OIDC callback


def sso_code_goal(tool: Tool, provider: IdentityProvider) -> str:
    url = tool_url(tool.manifest) if tool.manifest else ""
    return (
        f"Add OpenID Connect single sign-on (sign-in through {provider.name}) using the framework and libraries the "
        "project already uses; add one well-maintained OIDC client library if it has none. Read the configuration only "
        "from the environment variables OIDC_ISSUER (issuer URL; use its /.well-known/openid-configuration for discovery), "
        f"OIDC_CLIENT_ID, OIDC_CLIENT_SECRET and OIDC_REDIRECT_URI (default {url}{OIDC_CALLBACK}). Use the authorization "
        f"code flow with state, nonce and PKCE, validate the ID token, start the sign-in at GET /auth/oidc/login and handle "
        f"the callback at GET {OIDC_CALLBACK}, then sign the person in with the application's existing session mechanism. "
        "Keep the existing login working when OIDC_ISSUER is not set. Never hard-code or commit secrets. "
        "Set health_path to an empty string."
    )


def selected_provider(tool: Tool, others: list[Tool], idp: IdentityPrefs | None = None) -> IdentityProvider | None:
    idp = idp or IdentityPrefs()
    return identity.select(tool, identity.list_providers(others, idp.settings), idp).provider


def _sso_manifest(protocol: str, provider: IdentityProvider, how: str) -> dict[str, Any]:
    return {"auth": {"sso": protocol, "provider": provider.tool_id, "notes": f"{how} ({provider.name})"}}


def plan_sso_connect(tool: Tool, provider: IdentityProvider, extra: tuple[Any, ...] = ()) -> Patch | None:
    """Configure the tool's own OIDC/SAML support for `provider` and register it there as a client. `extra`: SSO
    recipes from extension packs."""
    config = sso_catalog.generate(tool, provider, extra)
    if config is None or tool.manifest is None:
        return None
    url, cid = tool_url(tool.manifest), client_id_for(tool)
    spec = ClientSpec(client_id=config.entity_id or cid, name=tool.name, protocol=config.protocol,
                      redirect_uris=config.redirect_uris, root_url=url, public=config.public_client, app_slug=cid,
                      acs_url=config.acs_url, slo_url=config.slo_url)
    reg = identity.registration(provider, spec, f"idp/{provider.tool_id}")
    proto = config.protocol.upper()
    secret_note = (" No client secret is involved." if config.protocol == "saml" or config.public_client else
                   f" The client secret is generated when the patch is applied and written only to the hub's adapter "
                   f"folder for {tool.name}.")
    return Patch(
        id=new_id("p_"), tool_id=tool.id, title=f"Connect to {provider.name} ({proto})", strategy="sso_connect",
        target="adapter",
        rationale=f"{tool.name} supports {proto} natively. This patch configures it to sign people in through "
                  f"{provider.name} and registers it there as client {spec.client_id}.{secret_note}",
        changes=[*config.files, *reg.files],
        sso=SsoPlan(provider=provider.tool_id, provider_name=provider.name, protocol=config.protocol,
                    client_id=spec.client_id, issuer=provider.client_issuer(cid), redirect_uris=config.redirect_uris,
                    steps=[*reg.steps, *config.steps], register_script=reg.script),
        manifest_update=_sso_manifest(config.protocol, provider, "connected by the Patch Agent"),
    )


def attach_sso(tool: Tool, provider: IdentityProvider, patch: Patch) -> Patch:
    """Complete a code patch that adds OIDC sign-in: the client registration and the environment, kept by the hub."""
    assert tool.manifest is not None
    if any(identity.has_secret(c) for c in patch.changes):
        raise ValueError("A code patch must not contain client secrets")
    url, cid = tool_url(tool.manifest), client_id_for(tool)
    redirect = f"{url}{OIDC_CALLBACK}"
    spec = ClientSpec(client_id=cid, name=tool.name, redirect_uris=[redirect], root_url=url, app_slug=cid)
    reg = identity.registration(provider, spec, f"idp/{provider.tool_id}")
    issuer = provider.client_issuer(cid)
    env = FileChange(path="sso/oidc.env", content=env_text(
        f"Environment for {tool.name}'s OpenID Connect sign-in through {provider.name}",
        {"OIDC_ISSUER": issuer, "OIDC_CLIENT_ID": cid, "OIDC_CLIENT_SECRET": CLIENT_SECRET, "OIDC_REDIRECT_URI": redirect}))
    patch.adapter_changes = [env, *reg.files]
    patch.sso = SsoPlan(provider=provider.tool_id, provider_name=provider.name, protocol="oidc", client_id=cid,
                        issuer=issuer, redirect_uris=[redirect], register_script=reg.script,
                        steps=[*reg.steps, f"Start {tool.name} with the variables from sso/oidc.env in the hub's adapter "
                                           "folder (not committed to the repository)."])
    patch.manifest_update = {**patch.manifest_update, **_sso_manifest("oidc", provider, "OIDC login added by a code patch")}
    patch.rationale = (f"{patch.rationale}\n\nThe code reads OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET from the "
                       f"environment. The hub registers {tool.name} at {provider.name} as client {cid}; the values, with a "
                       "secret generated when the patch is applied, stay in the hub's adapter folder.")
    return patch


def manifest_yaml(manifest: Manifest) -> str:
    data = manifest.model_dump(exclude={"native"}, exclude_defaults=False)
    return "# Hub manifest - see docs/MANIFEST.md in the hub repository\n" + yaml.safe_dump(data, sort_keys=False)


def _free_port(start: int, used: set[int]) -> int:
    port = max(start, 1024)
    while port in used:
        port += 1
    return port


def plan_patch(tool: Tool, others: list[Tool], strategy: str, hub_url: str, idp: IdentityPrefs | None = None) -> Patch | None:
    """Deterministic, template-based patch for one integration gap (no LLM needed)."""
    m = tool.manifest
    if m is None:
        return None
    pid = new_id("p_")
    title = STRATEGY_TITLES.get(strategy, strategy)
    port = m.launch.port

    if strategy == "sso_connect":
        provider = selected_provider(tool, others, idp)
        return plan_sso_connect(tool, provider, idp.catalog if idp else ()) if provider else None

    if strategy == "add_manifest":
        target = "repo" if (m.kind == "oss" and tool.path) else "adapter"
        draft = m.model_copy(deep=True)
        if not draft.launch.command and m.kind != "saas":
            draft.launch.command = "TODO: command that starts the tool"
        return Patch(
            id=pid, tool_id=tool.id, title=title, strategy=strategy, target=target,
            rationale="Commit the manifest the hub inferred so the tool's integration contract is explicit, reviewed "
                      "and versioned. Edit any TODO values before merging.",
            changes=[FileChange(path="hub.manifest.yaml", content=manifest_yaml(draft))],
            manifest_update={"native": True},
        )

    if strategy in ("health_probe", "health_endpoint"):
        if port and m.kind != "saas":
            probe = {"type": "tcp", "host": "127.0.0.1", "port": port}
            url = f"tcp://127.0.0.1:{port}"
        elif m.ui.url or m.api.base_url:
            url = m.ui.url or m.api.base_url
            probe = {"type": "http", "url": url, "expect_status_below": 500}
        else:
            return None
        return Patch(
            id=pid, tool_id=tool.id, title=STRATEGY_TITLES["health_probe"], strategy="health_probe", target="adapter",
            rationale="The tool has no health endpoint, so the hub will probe it from the outside instead.",
            changes=[FileChange(path="health.yaml", content=yaml.safe_dump({"probe": probe}, sort_keys=False))],
            manifest_update={"health": {"url": url}},
        )

    if strategy == "sso_proxy":
        if not port:
            return None
        provider = selected_provider(tool, others, idp)
        cid = client_id_for(tool)
        issuer = provider.client_issuer(cid) if provider else "https://idp.example.com/realms/hub"
        proxy_port = 4180 + zlib.crc32(tool.id.encode()) % 400
        proxy_url = f"http://localhost:{proxy_port}"
        compose = textwrap.dedent(f"""\
            # SSO proxy for {tool.name}, generated by the Hub Patch Agent.
            # Users sign in once with the suite's identity provider; the proxy forwards to {tool.name}.
            services:
              sso-proxy:
                image: quay.io/oauth2-proxy/oauth2-proxy:v7.6.0
                restart: unless-stopped
                ports:
                  - "{proxy_port}:4180"
                env_file: .env
                extra_hosts:
                  - "host.docker.internal:host-gateway"
                command:
                  - --provider=oidc
                  - --oidc-issuer-url=${{OIDC_ISSUER_URL}}
                  - --client-id=${{OIDC_CLIENT_ID}}
                  - --client-secret=${{OIDC_CLIENT_SECRET}}
                  - --cookie-secret=${{COOKIE_SECRET}}
                  - --email-domain=*
                  - --http-address=0.0.0.0:4180
                  - --upstream=http://host.docker.internal:{port}
                  - --redirect-url=http://localhost:{proxy_port}/oauth2/callback
            """)
        env = textwrap.dedent(f"""\
            # Fill these in, then rename to .env (never commit real secrets)
            OIDC_ISSUER_URL={issuer}
            OIDC_CLIENT_ID={cid}
            OIDC_CLIENT_SECRET=change-me
            # 32 random bytes, base64: python -c "import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
            COOKIE_SECRET=change-me
            """)
        changes = [FileChange(path="sso-proxy/docker-compose.yml", content=compose),
                   FileChange(path="sso-proxy/.env.example", content=env)]
        update: dict[str, Any] = {"auth": {"sso": "oidc", "notes": "via oauth2-proxy adapter"}, "ui": {"url": proxy_url}}
        if provider is None:
            return Patch(
                id=pid, tool_id=tool.id, title=title, strategy=strategy, target="adapter",
                rationale=f"{tool.name} has no single sign-on. An oauth2-proxy in front of it enforces suite-wide login "
                          "without changing the tool itself. Import an identity provider to connect it.",
                changes=changes, manifest_update=update,
            )
        redirect = f"{proxy_url}/oauth2/callback"
        spec = ClientSpec(client_id=cid, name=f"{tool.name} (SSO proxy)", redirect_uris=[redirect], root_url=proxy_url, app_slug=cid)
        reg = identity.registration(provider, spec, f"idp/{provider.tool_id}")
        changes.insert(1, FileChange(path="sso-proxy/.env", content=env_text(
            f"oauth2-proxy for {tool.name}, signing in through {provider.name}",
            {"OIDC_ISSUER_URL": issuer, "OIDC_CLIENT_ID": cid, "OIDC_CLIENT_SECRET": CLIENT_SECRET, "COOKIE_SECRET": COOKIE_SECRET})))
        update["auth"]["provider"] = provider.tool_id
        return Patch(
            id=pid, tool_id=tool.id, title=f"{title} ({provider.name})", strategy=strategy, target="adapter",
            rationale=f"{tool.name} has no single sign-on {provider.name} can be connected to natively. An oauth2-proxy in "
                      f"front of it enforces suite-wide login using {provider.name} as identity provider without changing "
                      f"the tool itself; the proxy is registered at {provider.name} as client {cid}. Its client and cookie "
                      "secrets are generated when the patch is applied and written only to the hub's adapter folder.",
            changes=[*changes, *reg.files], manifest_update=update,
            sso=SsoPlan(provider=provider.tool_id, provider_name=provider.name, protocol="oidc", client_id=cid,
                        issuer=issuer, redirect_uris=[redirect], register_script=reg.script,
                        steps=[*reg.steps, f"Start the proxy: docker compose up -d in sso-proxy/ of the adapter folder, then "
                                           f"open {tool.name} at {proxy_url}."]),
        )

    if strategy == "event_adapter":
        base = m.api.base_url or m.ui.url or (f"http://localhost:{port}" if port else "https://example.com")
        script = textwrap.dedent(f'''\
            """Event adapter for {tool.name}, generated by the Hub Patch Agent.

            Polls the tool and publishes a "{tool.id}.changed" event on the hub bus whenever
            the watched resource changes. Point WATCH_URL at the most useful endpoint.

            The hub only accepts events from authenticated callers: an admin creates an API token
            with the "integration" role (Users & access in the hub) and you pass it as HUB_TOKEN.
            Run it with: HUB_TOKEN=atr_... python adapter.py
            """
            import hashlib
            import json
            import os
            import time
            import urllib.request

            HUB_URL = os.environ.get("HUB_URL", "{hub_url}")
            HUB_TOKEN = os.environ.get("HUB_TOKEN", "")
            WATCH_URL = os.environ.get("WATCH_URL", "{base}")
            INTERVAL = int(os.environ.get("POLL_SECONDS", "60"))


            def fingerprint(url: str) -> str:
                with urllib.request.urlopen(url, timeout=15) as resp:
                    return hashlib.sha256(resp.read()).hexdigest()


            def publish(event: str, payload: dict) -> None:
                body = json.dumps({{"source": "{tool.id}", "event": event, "payload": payload}}).encode()
                headers = {{"Content-Type": "application/json", "X-Hub-Request": "1"}}
                if HUB_TOKEN:
                    headers["Authorization"] = f"Bearer {{HUB_TOKEN}}"
                req = urllib.request.Request(f"{{HUB_URL}}/api/bus/publish", data=body, method="POST", headers=headers)
                urllib.request.urlopen(req, timeout=15).close()


            if __name__ == "__main__":
                last = None
                while True:
                    try:
                        current = fingerprint(WATCH_URL)
                        if last is not None and current != last:
                            publish("{tool.id}.changed", {{"url": WATCH_URL}})
                        last = current
                    except Exception as exc:  # keep polling through transient errors
                        print("poll failed:", exc)
                    time.sleep(INTERVAL)
            ''')
        return Patch(
            id=pid, tool_id=tool.id, title=title, strategy=strategy, target="adapter",
            rationale=f"{tool.name} does not emit events. A small poller turns its changes into hub bus events "
                      "other tools can subscribe to.",
            changes=[FileChange(path="events/adapter.py", content=script)],
            manifest_update={"events": {"emits": sorted(set(m.events.emits) | {f"{tool.id}.changed"})}},
        )

    if strategy == "api_adapter":
        adapter_port = _free_port((port or 9000) + 100, set())
        script = textwrap.dedent(f'''\
            """API adapter skeleton for {tool.name}, generated by the Hub Patch Agent.

            {tool.name} has no API. This tiny HTTP service gives the hub one by wrapping
            whatever the tool does offer (CLI, files, database). Fill in the TODOs.
            Run it with: python adapter.py
            """
            import json
            from http.server import BaseHTTPRequestHandler, HTTPServer


            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    if self.path == "/healthz":
                        return self._send(200, {{"status": "ok"}})
                    if self.path == "/status":
                        # TODO: call the tool's CLI or read its data and return something useful
                        return self._send(200, {{"tool": "{tool.id}", "status": "unknown"}})
                    self._send(404, {{"error": "not found"}})

                def _send(self, code, payload):
                    body = json.dumps(payload).encode()
                    self.send_response(code)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)


            if __name__ == "__main__":
                HTTPServer(("127.0.0.1", {adapter_port}), Handler).serve_forever()
            ''')
        return Patch(
            id=pid, tool_id=tool.id, title=title, strategy=strategy, target="adapter",
            rationale=f"{tool.name} exposes no API. An adapter service gives agents and other tools a stable way to "
                      "query it. It is a skeleton - a person (or the Patch Agent with an LLM) fills in the calls.",
            changes=[FileChange(path="api/adapter.py", content=script)],
            manifest_update={"api": {"type": "rest", "base_url": f"http://127.0.0.1:{adapter_port}"}},
        )

    if strategy == "reassign_port" and port:
        used = {o.manifest.launch.port for o in others if o.manifest and o.manifest.launch.port}
        new_port = _free_port(port + 1, used)
        update: dict[str, Any] = {
            "launch": {"port": new_port, "env": {**m.launch.env, "PORT": str(new_port)}},
            "ui": {"url": f"http://localhost:{new_port}"},
        }
        if m.health.url:
            update["health"] = {"url": re.sub(rf":{port}\b", f":{new_port}", m.health.url)}
        if m.api.base_url:
            update["api"] = {"base_url": re.sub(rf":{port}\b", f":{new_port}", m.api.base_url)}
        return Patch(
            id=pid, tool_id=tool.id, title=f"{title} ({port} -> {new_port})", strategy=strategy, target="manifest",
            rationale=f"Port {port} is already taken by another tool in the suite. The hub will start {tool.name} on "
                      f"{new_port} and pass PORT={new_port} in its environment.",
            changes=[FileChange(path="manifest override", content=yaml.safe_dump(update, sort_keys=False))],
            manifest_update=update,
        )
    return None


# --------------------------------------------------------------------------------------
# applying patches
# --------------------------------------------------------------------------------------


def safe_relative(path: str) -> PurePosixPath:
    rel = PurePosixPath(path.replace("\\", "/"))
    if rel.is_absolute() or ".." in rel.parts or not rel.parts or re.match(r"^[A-Za-z]:", path):
        raise ValueError(f"Unsafe patch path: {path}")
    return rel


def write_changes(root: Path, changes: list[FileChange]) -> list[str]:
    written = []
    for change in changes:
        rel = safe_relative(change.path)
        dest = (root / rel).resolve()
        if not dest.is_relative_to(root.resolve()):
            raise ValueError(f"Unsafe patch path: {change.path}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(change.content, encoding="utf-8")
        written.append(rel.as_posix())
    return written


async def _is_git_repo(path: Path) -> bool:
    result = await run_exec(["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"], timeout=30)
    return result.exit_code == 0 and result.output.strip() == "true"


def write_adapter(workspace: Path, tool_id: str, patch: Patch, changes: list[FileChange]) -> Path:
    """Write files to the tool's adapter folder; SSO placeholders become the generated secrets (files kept private)."""
    root = workspace / "adapters" / tool_id
    private = {c.path for c in changes if identity.has_secret(c)}
    if patch.sso:
        changes = identity.fill_secrets(workspace, tool_id, patch.sso.provider, changes)
    write_changes(root, changes)
    for path in private:
        identity.private_file(root / safe_relative(path))
    return root


def _refuse_secrets(workspace: Path, tool_id: str, patch: Patch) -> None:
    if patch.sso is None:
        return
    known = identity.existing_secrets(workspace, tool_id, patch.sso.provider)
    if any(identity.has_secret(c) or any(s in c.content for s in known) for c in patch.changes):
        raise ValueError("Refusing to commit a client secret to the tool's repository")


async def apply_patch(hub: "Hub", patch: Patch) -> Patch:
    tool = hub.get_tool(patch.tool_id)
    if tool is None or tool.manifest is None:
        raise ValueError("The tool for this patch no longer exists")
    workspace = hub.settings.workspace
    adapters = workspace / "adapters" / tool.id

    if patch.target == "adapter":
        patch.location = str(write_adapter(workspace, tool.id, patch, patch.changes))
    elif patch.target == "repo":
        _refuse_secrets(workspace, tool.id, patch)
        repo = Path(tool.path or "")
        if repo.is_dir() and await _is_git_repo(repo):
            branch = f"hub/{patch.strategy.replace('_', '-')}-{patch.id[2:8]}"
            worktree = workspace / "patches" / patch.id
            result = await run_exec(["git", "-C", str(repo), "worktree", "add", "-b", branch, str(worktree), "HEAD"], timeout=120)
            if result.exit_code != 0:
                raise RuntimeError(f"git worktree failed: {result.output.strip()[-400:]}")
            write_changes(worktree, patch.changes)
            await run_exec(["git", "-C", str(worktree), "add", "-A"], timeout=60)
            result = await run_exec([
                "git", "-C", str(worktree), "-c", "user.name=Hub Patch Agent", "-c", "user.email=patch-agent@hub.local",
                "commit", "-m", f"hub: {patch.title}\n\n{patch.rationale}",
            ], timeout=120)
            if result.exit_code != 0:
                raise RuntimeError(f"git commit failed: {result.output.strip()[-400:]}")
            patch.branch, patch.location = branch, str(worktree)
        else:
            root = workspace / "patches" / patch.id
            write_changes(root, patch.changes)
            patch.location = str(root)
    # "manifest" patches only change the hub's view of the tool.
    if patch.adapter_changes:
        write_adapter(workspace, tool.id, patch, patch.adapter_changes)
    if patch.sso and patch.sso.register_script:
        patch.sso.register_command = f'bash "{(adapters / safe_relative(patch.sso.register_script)).as_posix()}"'

    if patch.manifest_update:
        merged = deep_merge(tool.manifest.model_dump(), patch.manifest_update)
        tool.manifest = Manifest.model_validate(merged)
        hub.save_tool(tool)
    patch.status = "applied"
    return hub.save_patch(patch)
