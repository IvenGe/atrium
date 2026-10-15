"""Patch planning and application.

When a tool does not fit the hub well, the Patch Agent turns each gap into a
patch. Patches land in one of three places:

* ``repo``     - a change to the tool's own source, committed on a new branch in a
                 separate git worktree (the user's checkout is never touched). What a code
                 patch sets in the manifest (a health URL, single sign-on) waits until a
                 person merged it and an analysis finds it in the folder (``merged_now``):
                 an unmerged branch is never a pass.
* ``adapter``  - files the hub keeps next to the tool (health probes, an SSO proxy,
                 event pollers). This is how closed-source and SaaS tools are integrated.
* ``manifest`` - a hub-side override of the tool's manifest (e.g. a new port, how the hub starts the tool).

Every patch goes through the approval queue unless the hub runs autonomously (a patch that changes what runs on the
hub machine never skips it: hub/integration/gapfix.py ``touches_launch``). What an applied patch sets in the manifest
is also kept in ``Tool.manifest_overrides`` (hub/integration/overrides.py), so it survives every re-analysis.

``plan`` answers a Patch, or a ``Skip`` that says in plain words why no patch fits and what the next step is: no gap is
ever dropped silently.

Single sign-on patches (``sso_connect``, ``sso_code``, ``sso_proxy``) also register the tool as a client at the
suite's identity provider. Their client secret only exists as a placeholder until the patch is applied; then the
hub generates it (once per tool and provider) and writes it into the adapter folder - never into a repository.
A launch_command patch names the launch secrets a recipe needs (an admin password); their values are generated when
the patch is applied, into the private adapters/<id>/launch/secrets.env (hub/integration/launch_secrets.py) - never
into the patch, the manifest or the API.
"""

from __future__ import annotations

import os
import re
import textwrap
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import yaml

from ..execution.policy import classify, proposed_command_problem
from ..execution.runner import run_exec
from ..models import MANIFEST_HUB_KEYS, FileChange, Manifest, Patch, SsoPlan, Tool
from ..store import new_id
from . import identity, known_tools, launch_secrets, overrides, sso_catalog
from .analyzer import PLACEHOLDER_FIELDS, placeholder, read_repo_file, repo_file
from .identity import CLIENT_SECRET, COOKIE_SECRET, ClientSpec, IdentityPrefs, IdentityProvider
from .sso_catalog import client_id_for, env_text, tool_url

if TYPE_CHECKING:
    from ..agents.reader import LaunchProposal
    from ..core import Hub

# Why no patch fits (shared with the checks and the Patch Agent; {tool}, {hint}, {why} filled in)
R_NEEDS_LAUNCH = ("Atrium does not know how to start {tool}. An administrator can set the launch command in "
                  "Integration > Launch > Edit{hint}.")
R_NEEDS_PORT = ("Atrium does not know which port {tool} listens on. An administrator can set the port in "
                "Integration > Launch > Edit{hint}.")
NO_MODEL_HINT = "; with an AI model (Settings > AI providers) the Patch Agent can propose one from the README"
R_NO_ADDRESS = ("No port or address is known for {tool} yet: set how it starts first (Integration > Launch > Edit or "
                "the launch_command patch), then propose again.")
R_BLOCKED_CMD = "The command is blocked by the command policy ({why})."


@dataclass(frozen=True)
class Skip:
    """Why a gap gets no patch, in plain language naming the next step. `needs_input`: a person must supply something
    (Integration > ... > Edit), as opposed to a gap another patch or a change of the tool closes."""

    reason: str
    needs_input: bool = False


STRATEGY_TITLES = {
    "launch_command": "Set how the hub starts the tool",
    "health_config": "Switch on the tool's own health check",
    "add_manifest": "Adopt a hub manifest",
    "health_endpoint": "Add a health endpoint",
    "health_probe": "Add a health probe adapter",
    "sso_connect": "Connect single sign-on to the identity provider",
    "sso_code": "Add OpenID Connect sign-in to the code",
    "sso_proxy": "Put an SSO proxy in front of the tool",
    "event_adapter": "Add an event adapter",
    "api_adapter": "Add an API adapter skeleton",
    "reassign_port": "Move the tool to a free port",
    "atrium_bridge": "Add an Atrium bridge so an agent team can work inside the tool",  # hub/subsidiary/bridgepatch.py
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
    """The manifest as a tool's own hub.manifest.yaml: without the keys only the hub sets (``id``, ``native``,
    ``known``, ``adopted``), without the names of the hub's private launch secrets or any credential-looking
    constant (overrides.secret_like), and without TODO placeholders."""
    data = manifest.model_dump(exclude=set(MANIFEST_HUB_KEYS), exclude_defaults=False)
    launch = data["launch"]
    launch.pop("secret_env", None)  # and no credential-looking constant either: the draft is shown to every viewer
    launch["env"] = {k: v for k, v in (launch.get("env") or {}).items() if not overrides.secret_like(k, v)}
    launch["env_files"] = [f for f in launch.get("env_files") or [] if f != launch_secrets.ENV_FILE]
    for path in PLACEHOLDER_FIELDS:
        section, key = path.split(".")
        if placeholder((data.get(section) or {}).get(key)):
            data[section][key] = None
    return "# Hub manifest - see docs/MANIFEST.md in the hub repository\n" + yaml.safe_dump(data, sort_keys=False)


def _free_port(start: int, used: set[int]) -> int:
    port = max(start, 1024)
    while port in used:
        port += 1
    return port


def _product(tool: Tool) -> str:
    """The product's name: its profile's title when Atrium recognised it, else the tool's name."""
    profile = known_tools.for_manifest(tool.manifest) if tool.manifest else None
    return profile.title if profile else tool.name


def _command(m: Manifest) -> str | None:
    """The launch command, None when there is none or it is a TODO placeholder."""
    command = (m.launch.command or "").strip()
    return command if command and not placeholder(command) else None


def _blocked(command: str | None) -> str | None:
    """Why the command policy blocks `command` (None when it may run)."""
    if not command:
        return None
    risk, why = classify(command)
    return why if risk == "blocked" else None


def _ports(*urls: str | None) -> list[int]:
    out: list[int] = []
    for url in urls:
        try:
            port = urlsplit(url or "").port
        except ValueError:
            port = None
        if port and port not in out:
            out.append(port)
    return out


def _and(items: list[str]) -> str:
    return items[0] if len(items) == 1 else f"{', '.join(items[:-1])} and {items[-1]}"


def _secrets_note(tool: Tool, names: list[str]) -> str:
    what = ("The admin password" if len(names) == 1 and "PASSWORD" in names[0] and "ADMIN" in names[0]
            else "The value of" if len(names) == 1 else "The values of")
    verb = "is" if len(names) == 1 else "are"
    return (f"{what} ({_and(names)}) {verb} generated when the patch is applied and kept in the hub's private "
            f"adapters/{tool.id}/{launch_secrets.ENV_FILE}; an administrator can set their own in "
            "Integration > Launch > Edit.")


def _hint(tool: Tool) -> str:
    """The AI hint of R_NEEDS_LAUNCH: an AI model can only propose a command from the tool's own folder. (plan() is
    only reached without a proposal when no model could make one; the Patch Agent words a model failure itself.)"""
    return NO_MODEL_HINT if tool.path and tool.source_type != "saas" else ""


def _launch_from_profile(tool: Tool, lp: known_tools.LaunchPlan, pid: str) -> Patch | Skip:
    """A launch_command patch from the recognised product's recipe (known_tools.launch_plan)."""
    m = tool.manifest
    assert m is not None
    why = _blocked(lp.command) or _blocked(lp.setup)
    if why:
        return Skip(R_BLOCKED_CMD.format(why=why))
    product = _product(tool)
    launch: dict[str, Any] = {"command": lp.command, "port": lp.port, "cwd": lp.cwd or "."}
    if lp.port is None:  # unknown: an override of None would clear a port set elsewhere
        launch.pop("port")
    if lp.setup:
        launch["setup"] = lp.setup
    if lp.env:
        launch["env"] = dict(lp.env)  # constants only: the secrets are names, their values never in a patch
    names = list(lp.secret_env)
    if names:
        launch["secret_env"] = names
        if launch_secrets.ENV_FILE not in m.launch.env_files:
            launch["env_files"] = [*m.launch.env_files, launch_secrets.ENV_FILE]
    update: dict[str, Any] = {"launch": launch}
    if lp.health_url:
        update["health"] = {"url": lp.health_url}
    if not m.api.base_url and lp.api_base_url:
        update["api"] = {"base_url": lp.api_base_url}
    if lp.ui_url:
        update["ui"] = {"url": lp.ui_url}

    shape = m.known.shape if m.known else "other"
    container = bool(known_tools.CONTAINER_RUN_RE.match(lp.command))
    if shape == "release":
        lines = [f"This folder is a {product} release: the hub starts it with {lp.summary}."]
    elif shape == "source":
        lines = [f"This folder is {product}'s source code; the hub does not build it. It runs "
                 f"{'the official container image' if container else lp.summary} instead."]
    else:
        lines = [f"Atrium recognised {product} but found no way to start it from this folder. It runs {lp.summary}."]
    if lp.requires:
        lines.append(f"Requires {lp.requires}.")
    ports = _ports(lp.ui_url or (f"http://localhost:{lp.port}" if lp.port else None), lp.health_url)
    if ports:
        listed = _and([str(p) for p in ports])
        lines.append(f"Publishes port{'s' if len(ports) > 1 else ''} {listed} on the hub machine (they must be free)."
                     if container else f"Listens on port{'s' if len(ports) > 1 else ''} {listed}.")
    if lp.health_url:
        lines.append(f"Switches on its health check at {lp.health_url}.")
    if names:
        lines.append(_secrets_note(tool, names))
    lines += list(lp.notes)
    lines.append("When a person starts the tool, the command runs on the hub machine with Atrium's privileges, so only "
                 "an administrator can approve this patch.")
    return Patch(
        id=pid, tool_id=tool.id, title=f"Start {product} with {lp.summary}", strategy="launch_command",
        target="manifest", rationale="\n".join(lines),
        changes=[FileChange(path="manifest override", content=yaml.safe_dump(update, sort_keys=False))],
        manifest_update=update,
    )


def _launch_from_proposal(tool: Tool, proposal: "LaunchProposal", pid: str) -> Patch | Skip:
    """A launch_command patch from an AI model's reading of the tool's folder (reader.propose_launch): only what the
    manifest misses, marked as the model's work for the administrator who approves it."""
    m = tool.manifest
    assert m is not None
    launch: dict[str, Any] = {}
    command = (proposal.command or "").strip() or None
    if command and not _command(m):
        if placeholder(command):
            return Skip("The AI model proposed a TODO placeholder, not a launch command: an administrator can set it in "
                        "Integration > Launch > Edit.", needs_input=True)
        launch["command"], launch["cwd"] = command, proposal.cwd or "."
    setup = (proposal.setup or "").strip() or None
    if setup and not m.launch.setup and not placeholder(setup):
        launch["setup"] = setup
    why = _blocked(launch.get("command")) or _blocked(launch.get("setup"))
    if why:
        return Skip(R_BLOCKED_CMD.format(why=why))
    root = Path(tool.path) if tool.path else None
    cwd = str(launch.get("cwd") or proposal.cwd or ".")

    def in_folder(path: str) -> bool:  # a program of the tool's own folder (./mvnw, bin/kc.sh), from its cwd
        rel = os.path.normpath(os.path.join("" if cwd == "." else cwd, path))
        return root is not None and not rel.startswith("..") and repo_file(root, rel) is not None

    for key, what in (("command", "launch command"), ("setup", "setup command")):
        problem = proposed_command_problem(launch[key], in_folder) if launch.get(key) else None
        if problem:  # the floor for a model's command, checked again where the patch is planned
            return Skip(f"The AI model's {what} is refused: {problem}. An administrator can set it in "
                        "Integration > Launch > Edit.", needs_input=True)
    if proposal.port and not m.launch.port:
        if not 1 <= int(proposal.port) <= 65535:
            return Skip(f"The AI model proposed port {proposal.port}, which is not a port: an administrator can set "
                        "it in Integration > Launch > Edit.", needs_input=True)
        launch["port"] = int(proposal.port)
    update: dict[str, Any] = {"launch": launch} if launch else {}
    port = m.launch.port or launch.get("port")
    base = f"http://localhost:{port}" if port else None
    if base and proposal.health_path and not m.health.url:
        update["health"] = {"url": f"{base}{proposal.health_path}"}
    if base and not m.ui.url:
        update["ui"] = {"url": base}
    if base and m.api.type != "none" and not m.api.base_url:
        update["api"] = {"base_url": base}
    if not launch:
        return Skip(f"The AI model found nothing to add to how {tool.name} starts: an administrator can set it in "
                    "Integration > Launch > Edit.", needs_input=True)
    by = proposal.generated_by or {}
    label = by.get("label") or by.get("model") or by.get("provider") or "an AI model"
    evidence = ", ".join(proposal.evidence) or "the tool's files"
    lines = [f"The AI model read {evidence} and proposes how the hub starts {tool.name}."]
    if proposal.rationale:
        lines.append(f"Its reasoning: {proposal.rationale}")
    lines.append("When a person starts the tool, the command runs on the hub machine with Atrium's privileges: check "
                 "it before approving (only an administrator can).")
    what = "Launch command" if "command" in launch else "Launch settings"
    return Patch(
        id=pid, tool_id=tool.id, title=f"{what} proposed by {label} - check {'it' if 'command' in launch else 'them'} "
                                       "before approving",
        strategy="launch_command", target="manifest", rationale="\n".join(lines),
        changes=[FileChange(path="manifest override", content=yaml.safe_dump(update, sort_keys=False))],
        manifest_update=update, generated_by=dict(proposal.generated_by or {}),
    )


def _plan_launch(tool: Tool, pid: str, proposal: "LaunchProposal | None") -> Patch | Skip:
    m = tool.manifest
    assert m is not None
    if m.kind == "saas" or tool.source_type == "saas":
        return Skip("A SaaS service is not started by the hub.")
    lp = known_tools.launch_plan(m, tool.id) if not _command(m) else None
    if lp is not None:
        return _launch_from_profile(tool, lp, pid)
    if proposal is not None:
        return _launch_from_proposal(tool, proposal, pid)
    if _command(m) and m.launch.port:
        return Skip(f"{tool.name} already has a launch command and a port: there is nothing to set.")
    text = R_NEEDS_PORT if _command(m) else R_NEEDS_LAUNCH
    return Skip(text.format(tool=tool.name, hint=_hint(tool)), needs_input=True)


def _plan_health_config(tool: Tool, pid: str) -> Patch | Skip:
    m = tool.manifest
    assert m is not None
    product = _product(tool)
    hp = known_tools.health_plan(m, tool.id)
    if hp is None:
        return Skip(f"Atrium knows no built-in health check of {product} it could switch on: a health probe checks "
                    "it from the outside instead.")
    command = _command(m) or ""
    container = bool(known_tools.CONTAINER_RUN_RE.match(command) or known_tools.COMPOSE_CMD_RE.match(command))
    if container and hp.note:  # the launch environment does not reach a container: its command must change
        return Skip(hp.note, needs_input=True)
    if hp.via == "launch":
        return Skip(hp.note or "The launch_command patch switches it on.")
    if hp.via == "compose":
        return Skip(hp.note, needs_input=True)
    if not hp.url:
        return Skip(R_NO_ADDRESS.format(tool=tool.name), needs_input=True)
    update: dict[str, Any] = {"health": {"url": hp.url}}
    if hp.via == "config" and hp.env:
        update = {"launch": {"env": dict(hp.env)}, **update}
        env = ", ".join(f"{k}={v}" for k, v in hp.env.items())
        port = _ports(hp.url)
        rationale = (f"{product} serves its health endpoint only when {env} is set. The hub passes {env} in the launch "
                     f"environment and checks {hp.url}" + (f" (port {port[0]})" if port else "") + ". The change takes "
                     "effect the next time the hub starts the tool; it changes what runs on the hub machine, so only "
                     "an administrator can approve it.")
        title = f"Switch on {product}'s own health check"
    else:
        rationale = f"{product} has a built-in health endpoint: the hub checks {hp.url}."
        title = f"Use {product}'s own health check"
    return Patch(
        id=pid, tool_id=tool.id, title=title, strategy="health_config", target="manifest", rationale=rationale,
        changes=[FileChange(path="manifest override", content=yaml.safe_dump(update, sort_keys=False))],
        manifest_update=update,
    )


# The variable a framework reads its HTTP port from (the hub passes PORT to every tool it starts anyway)
STACK_PORT_ENV = (("spring", "SERVER_PORT"), ("quarkus", "QUARKUS_HTTP_PORT"))


def moved_launch(tool: Tool, port: int, new_port: int) -> tuple[dict[str, Any] | None, str]:
    """How the hub makes `tool` listen on `new_port` instead of `port`: the launch settings to set and a plain sentence
    saying how - or None and why it cannot (a Skip for a person). A container command publishes the new host port
    (-p {new}:{container}); a recognised product reads its own variable (known_tools.Profile.port_env, e.g.
    KC_HTTP_PORT); a Spring Boot or Quarkus app SERVER_PORT / QUARKUS_HTTP_PORT; any other program the PORT convention.
    A compose command, or a product whose port Atrium cannot set, cannot be moved by the hub."""
    m = tool.manifest
    assert m is not None
    command = (m.launch.command or "").strip()
    by_hand = (f"An administrator can set its port and launch command in Integration > Launch > Edit, or move the "
               "other tool.")
    if known_tools.CONTAINER_RUN_RE.match(command):
        moved = known_tools.publish_elsewhere(command, port, new_port)
        if moved is None:
            return None, f"Its container command does not publish port {port} (-p {port}:...): {by_hand}"
        return {"port": new_port, "command": moved}, f"its container command publishes port {new_port} instead"
    if known_tools.COMPOSE_CMD_RE.match(command) or (m.known is not None and m.known.shape == "compose"):
        return None, (f"{tool.name} is started from a compose file: change its published port there and Re-analyse. "
                      f"{by_hand}")
    profile = known_tools.for_manifest(m)
    if profile is not None:
        if not profile.port_env:
            return None, f"Atrium does not know how to make {profile.title} listen on another port. {by_hand}"
        name = profile.port_env
    else:
        name = next((env for stack, env in STACK_PORT_ENV if stack in m.stack), "PORT")
    return {"port": new_port, "env": {name: str(new_port)}}, f"it passes {name}={new_port} in its environment"


def plan(tool: Tool, others: list[Tool], strategy: str, hub_url: str, idp: IdentityPrefs | None = None, *,
         proposal: "LaunchProposal | None" = None) -> Patch | Skip:
    """Deterministic, template-based patch for one integration gap (no model call here: an AI launch proposal comes
    in as `proposal`), or a Skip saying why none fits and what the next step is."""
    m = tool.manifest
    if m is None:
        return Skip(f"{tool.name} has not been analysed yet: Re-analyse it, then propose again.")
    pid = new_id("p_")
    title = STRATEGY_TITLES.get(strategy, strategy)
    port = m.launch.port

    if strategy == "launch_command":
        return _plan_launch(tool, pid, proposal)

    if strategy == "health_config":
        return _plan_health_config(tool, pid)

    if strategy == "sso_connect":
        provider = selected_provider(tool, others, idp)
        if provider is None:
            return Skip(f"No identity provider is selected for {tool.name}: import one (or choose one in Integration > "
                        "Single sign-on), then propose again.", needs_input=True)
        patch = plan_sso_connect(tool, provider, idp.catalog if idp else ())
        return patch or Skip(f"Atrium has no recipe to connect {tool.name}'s own sign-in to {provider.name}: the SSO "
                             "proxy or an OpenID Connect code patch signs people in instead.")

    if strategy == "add_manifest":
        target = "repo" if (m.kind == "oss" and tool.path) else "adapter"
        missing = [path for path, gap in (
            ("launch.command", m.kind != "saas" and not _command(m)), ("launch.port", m.kind != "saas" and not port),
            ("health.url", not m.health.url or placeholder(m.health.url)),
            ("api", m.api.type == "none")) if gap]
        rationale = ("Commit the manifest the hub inferred so the tool's integration contract is explicit, reviewed "
                     "and versioned. The hub records where it waits; it counts as the tool's own manifest once it is "
                     "merged into the tool's folder and the tool is re-analysed.")
        if missing:
            rationale += (f" Still unknown (left empty): {', '.join(missing)} - fill them in before merging, or let an "
                          "administrator set them in Integration (Edit on the Launch, Health and API rows).")
        return Patch(
            id=pid, tool_id=tool.id, title=title, strategy=strategy, target=target, rationale=rationale,
            changes=[FileChange(path="hub.manifest.yaml", content=manifest_yaml(m))],
            manifest_update={},  # set when applied: {"adopted": the branch or folder} - never "native"
        )

    if strategy in ("health_probe", "health_endpoint"):
        if port and m.kind != "saas":
            probe = {"type": "tcp", "host": "127.0.0.1", "port": port}
            url = f"tcp://127.0.0.1:{port}"
        elif m.ui.url or m.api.base_url:
            url = m.ui.url or m.api.base_url
            probe = {"type": "http", "url": url, "expect_status_below": 500}
        else:
            return Skip(R_NO_ADDRESS.format(tool=tool.name), needs_input=True)
        return Patch(
            id=pid, tool_id=tool.id, title=STRATEGY_TITLES["health_probe"], strategy="health_probe", target="adapter",
            rationale="The tool has no health endpoint, so the hub will probe it from the outside instead.",
            changes=[FileChange(path="health.yaml", content=yaml.safe_dump({"probe": probe}, sort_keys=False))],
            manifest_update={"health": {"url": url}},
        )

    if strategy == "sso_proxy":
        if not port:
            return Skip(f"An SSO proxy needs the port {tool.name} listens on, and none is known: set how it starts first "
                        "(Integration > Launch > Edit or the launch_command patch), then propose again.",
                        needs_input=True)
        provider = selected_provider(tool, others, idp)
        cid = client_id_for(tool)
        issuer = provider.client_issuer(cid) if provider else ""  # no made-up address: a person fills it in
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
            # OIDC_ISSUER_URL: the issuer URL of the suite's identity provider (its /.well-known/openid-configuration)
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
        note = known_tools.events_note(m)
        if note:  # the product's events need more than a poller of one address (e.g. a token and a per-realm switch)
            return Skip(note)
        base = m.api.base_url or m.ui.url or (f"http://localhost:{port}" if port else None)
        if not base:  # a poller of a made-up address would never see a change
            return Skip(R_NO_ADDRESS.format(tool=tool.name), needs_input=True)
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
            rationale=f"{tool.name} does not emit events. A small poller of {base} turns its changes into hub bus "
                      "events other tools can subscribe to. The hub does not run it: start it with an integration "
                      "token (see the script).",
            changes=[FileChange(path="events/adapter.py", content=script)],
            manifest_update={"events": {"emits": [f"{tool.id}.changed"]}},  # unioned with the others when applied
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
                      "query it. It is a skeleton - a person (or the Patch Agent with an LLM) fills in the calls. The "
                      f"hub does not run it: once it runs (it listens on http://127.0.0.1:{adapter_port}), set that "
                      "address as the API in Integration > API > Edit.",
            changes=[FileChange(path="api/adapter.py", content=script)],
            manifest_update={},  # a skeleton full of TODOs is no API: the Programmable API check stays open (no pass)
        )

    if strategy == "reassign_port" and port:
        used = {o.manifest.launch.port for o in others if o.manifest and o.manifest.launch.port}
        new_port = _free_port(port + 1, used)
        launch, how = moved_launch(tool, port, new_port)
        if launch is None:  # nothing the hub controls would make it listen elsewhere: a person decides
            return Skip(how, needs_input=True)
        # Only the port variable: apply_patch deep-merges, so the tool's other launch.env values stay without being
        # copied into the patch, which viewers and the event stream read (review F13: env values are never shown).
        update: dict[str, Any] = {"launch": launch, "ui": {"url": f"http://localhost:{new_port}"}}
        if m.health.url:
            update["health"] = {"url": re.sub(rf":{port}\b", f":{new_port}", m.health.url)}
        if m.api.base_url:
            update["api"] = {"base_url": re.sub(rf":{port}\b", f":{new_port}", m.api.base_url)}
        return Patch(
            id=pid, tool_id=tool.id, title=f"{title} ({port} -> {new_port})", strategy=strategy, target="manifest",
            rationale=f"Port {port} is already taken by another tool in the suite. The hub will start {tool.name} on "
                      f"{new_port}: {how}.",
            changes=[FileChange(path="manifest override", content=yaml.safe_dump(update, sort_keys=False))],
            manifest_update=update,
        )
    if strategy == "reassign_port":
        return Skip(f"{tool.name} has no port to move: set how it starts first (Integration > Launch > Edit).",
                    needs_input=True)
    if strategy in ("sso_code", "atrium_bridge"):
        return Skip(f"'{title}' is written by the Patch Agent's AI model, not planned from a template.")
    return Skip(f"Atrium has no ready-made patch for '{title}'.")


def plan_patch(tool: Tool, others: list[Tool], strategy: str, hub_url: str, idp: IdentityPrefs | None = None) -> Patch | None:
    """plan() for callers that only want a patch: a Skip is None (kept for back-compatibility)."""
    result = plan(tool, others, strategy, hub_url, idp)
    return result if isinstance(result, Patch) else None


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


def code_change(patch: Patch) -> bool:
    """A change to the tool's own source (target "repo"), made on a branch or in a folder of its own, whose manifest
    settings wait for the merge - not an adopted manifest (``adopted`` records where it waits, and the analysis sees
    the file once merged) and not a bridge patch, which has its own lifecycle (hub/subsidiary/bridgepatch.py)."""
    return patch.target == "repo" and patch.strategy not in ("atrium_bridge", "add_manifest")


def _same_content(root: Path, change: FileChange) -> bool:
    """The file at the change's path in `root` holds the change's content (line endings and trailing blanks aside)."""
    text = read_repo_file(root, safe_relative(change.path).as_posix(), 2 * len(change.content.encode()) + 1024)
    return text is not None and text.replace("\r\n", "\n").rstrip() == change.content.replace("\r\n", "\n").rstrip()


async def merged_now(tool: Tool, items: list[Patch]) -> list[Patch]:
    """The tool's applied code patches waiting for their merge (``merged`` False) whose change is in its folder now:
    their branch is merged into the folder's checkout (git), or every file they write holds their content there (a
    squash merge, a copy). An analysis then applies what they set (ToolSupervisor.on_analyze)."""
    root = Path(tool.path or "")
    waiting = [p for p in items if p.tool_id == tool.id and p.status == "applied" and p.merged is False]
    if not waiting or not tool.path or not root.is_dir():
        return []
    git = await _is_git_repo(root)
    found = []
    for patch in waiting:
        if patch.branch and git:
            result = await run_exec(["git", "-C", str(root), "merge-base", "--is-ancestor", patch.branch, "HEAD"],
                                    timeout=30)
            if result.exit_code == 0:
                found.append(patch)
                continue
        try:
            if patch.changes and all(_same_content(root, c) for c in patch.changes):
                found.append(patch)
        except ValueError:  # an unsafe path never matches
            continue
    return found


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
    elif patch.target == "repo" and patch.branch and patch.location:
        pass  # committed on its branch when it was proposed (bridge patches): the approval is bound to that commit
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

    if patch.strategy == "add_manifest":  # the draft waits on its branch (or folder): adopted, not native, until merged
        where = patch.branch or patch.location
        patch.manifest_update = {"adopted": where} if where else {}
    if code_change(patch):  # its change waits on its branch (or folder): what it sets applies once a person merged it
        patch.merged = False  # into the tool's folder and an analysis found it there (merged_now) - never before
    elif patch.manifest_update:
        # the tool as it is now (an analysis may have finished while git worked); what the patch sets is kept in the
        # hub-side overrides too, so every later analysis applies it again (hub/integration/overrides.py)
        tool = hub.get_tool(patch.tool_id) or tool
        assert tool.manifest is not None
        manifest = overrides.apply(tool.manifest, patch.manifest_update, strict=True)  # invalid: the patch fails
        names = (patch.manifest_update.get("launch") or {}).get("secret_env") or []
        if names:  # generated now, into the private adapters/<id>/launch/secrets.env - never into the patch
            if launch_secrets.ensure(workspace, tool.id, names):
                mask = getattr(getattr(hub, "llm", None), "mask", None)
                if mask is not None:  # masked from now on in prompts and the logs, not after the mask's refresh
                    mask.invalidate()
        tool.manifest_overrides = overrides.merge(tool.manifest_overrides, patch.manifest_update)
        tool.manifest = manifest
        hub.save_tool(tool)
    patch.status = "applied"
    return hub.save_patch(patch)
