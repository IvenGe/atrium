"""AI model provider records (collection "llm_providers"): the built-in Claude ("anthropic") and OpenAI ("openai")
records, Azure OpenAI resources (kind "openai", variant "azure") and model servers with an OpenAI-compatible API
(Ollama, LM Studio, vLLM, llama.cpp's server) people add. The network code lives in the provider layer
(hub/llm/adapters/).

The optional API key is Fernet-encrypted with the hub's secret key, never returned, logged or broadcast, and only sent
to the endpoint (scheme, host and port) it was entered for; the built-in providers' addresses are fixed and an Azure
address must be an Azure OpenAI one. Where a local server runs (self-hosted or a third party) is computed from its
address; a server on a public address must use https unless an administrator confirms it is their own.
"""

from __future__ import annotations

import os
import re
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from .connectors.base import endpoint_of
from .llm.types import ProviderError
from .models import LlmProvider, ModelCaps, Supplier

if TYPE_CHECKING:
    from .core import Hub

COLLECTION = "llm_providers"
DEFAULT_BASE_URL = "http://localhost:11434/v1"
BUILTIN = ("anthropic", "openai")
RESERVED = {"anthropic", "rules", "claude", "local", "openai", "auto", "inherit", "azure", "default"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
MAX_PINNED = 50
AZURE_HINT = ("The Azure OpenAI base URL is https://<resource>.openai.azure.com/openai/v1 (or "
              "https://<resource>.services.ai.azure.com/openai/v1)")
__all__ = ["ProviderError"]


# --------------------------------------------------------------------------------------
# storage
# --------------------------------------------------------------------------------------


def get(hub: "Hub", provider_id: str) -> LlmProvider | None:
    doc = hub.store.get(COLLECTION, provider_id)
    return LlmProvider.model_validate(doc) if doc else None


def all_providers(hub: "Hub") -> list[LlmProvider]:
    """Every record, the built-in ones included: callers that mean the model servers people add use local()."""
    return [LlmProvider.model_validate(d) for d in hub.store.list(COLLECTION)]


def local(hub: "Hub") -> list[LlmProvider]:
    """The OpenAI-compatible model servers people added."""
    return [p for p in all_providers(hub) if p.kind == "openai_compatible"]


def ordered(hub: "Hub") -> list[LlmProvider]:
    """Every record in the order the UI shows them: Claude, OpenAI, Azure OpenAI resources, then local servers."""
    rank = {"anthropic": 0, "openai": 1}
    return sorted(all_providers(hub), key=lambda p: (rank.get(p.id, 2 if p.kind == "openai" else 3), p.name.lower(), p.id))


def key_source(provider: LlmProvider) -> str | None:
    """Where the key comes from: "env" (ANTHROPIC_API_KEY / OPENAI_API_KEY, which win over a stored key), "profile"
    (an `ant auth login` profile), "stored", or None."""
    source = None
    if provider.id == "anthropic":
        from .llm.adapters.anthropic import env_source

        source = env_source()
    elif provider.id == "openai" and os.environ.get("OPENAI_API_KEY"):
        source = "env"
    return source or ("stored" if provider.api_key else None)


def public(provider: LlmProvider) -> dict[str, Any]:
    """What the API shows: everything but the key, whether one is set and where the key comes from."""
    return {**provider.model_dump(mode="json", exclude={"api_key", "endpoint"}), "api_key_set": bool(provider.api_key),
            "key_source": key_source(provider)}


def put(hub: "Hub", provider: LlmProvider) -> LlmProvider:
    """Written straight to the store; the event stream only carries the public view."""
    hub.store.put(COLLECTION, provider.model_dump(mode="json"))
    hub.bus.publish("llm_provider", public(provider))
    llm = getattr(hub, "llm", None)
    if llm is not None and hasattr(llm, "invalidate"):
        llm.invalidate()
    return provider


_put = put


def clean_base_url(value: str) -> str:
    text = (value or "").strip().rstrip("/")
    parts = urlsplit(text)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("The base URL must start with http:// or https://, e.g. " + DEFAULT_BASE_URL)
    if parts.username or parts.password:
        raise ValueError("The base URL must not contain credentials - use the API key field")
    if parts.query or parts.fragment:
        raise ValueError("The base URL must not have a query or fragment")
    return text


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40] or "local"


def clean_models(values: list[str]) -> list[str]:
    """Model (or Azure deployment) names an administrator typed: trimmed, without duplicates."""
    models = [m for m in dict.fromkeys(str(v).strip() for v in values) if m]
    if len(models) > MAX_PINNED or any(len(m) > 200 for m in models):
        raise ValueError(f"At most {MAX_PINNED} model names of up to 200 characters")
    return models


def _location(data: dict[str, Any], current: LlmProvider | None, values: dict[str, Any]) -> None:
    """Where a local server runs. Computed from its address; an administrator may mark it a third party (e.g. a
    proxy to a cloud service) or - with an explicit confirmation - mark a public address as their own server."""
    computed = location_of(data["base_url"])
    wanted = values.get("location")
    confirm = values.get("confirm_self_hosted")
    same_host = current is not None and urlsplit(current.base_url).hostname == urlsplit(data["base_url"]).hostname
    if wanted == "third_party":
        data["location"], data["location_confirmed"] = "third_party", False
    elif computed == "third_party" and (confirm or (wanted == "self_hosted" and confirm is not False)):
        data["location"], data["location_confirmed"] = "self_hosted", True
    elif wanted is None and confirm is None and same_host and current is not None:
        data["location"], data["location_confirmed"] = current.location, current.location_confirmed
    else:
        data["location"], data["location_confirmed"] = computed, False
    if computed == "third_party" and not data["location_confirmed"] and urlsplit(data["base_url"]).scheme != "https":
        raise ValueError("A model server on a public address must use https:// - or, if the server is your own, "
                         "confirm that it is self-hosted")


def save(hub: "Hub", provider_id: str | None, values: dict[str, Any], actor: str) -> tuple[LlmProvider, bool]:
    """Create (provider_id None) or update a provider. `api_key`: a value sets it, None or "" keeps the stored one
    - while the endpoint stays the same; `clear_api_key` removes it. Returns the provider and whether the key changed.
    New records are local servers (kind "openai_compatible") or Azure OpenAI resources (kind "openai", variant
    "azure"); Claude and OpenAI are built in (their name and address are fixed)."""
    current = get(hub, provider_id) if provider_id else None
    if provider_id and current is None:
        raise KeyError(provider_id)
    data = current.model_dump() if current else {}
    builtin = current is not None and current.id in BUILTIN
    kind = current.kind if current is not None else (values.get("kind") or "openai_compatible")
    if current is None:
        if kind == "anthropic" or (kind == "openai" and (values.get("variant") or "azure") != "azure"):
            raise ValueError("Claude and OpenAI are built in: set their API key on the providers 'anthropic' and "
                             "'openai'")
        data["kind"], data["variant"] = kind, "azure" if kind == "openai" else None
    local_server = kind == "openai_compatible"
    for key in ("name", "default_model", "timeout", "enabled", "tools", "structured_output", "send_effort",
                "max_concurrency"):
        value = values.get(key)
        if value is None or (builtin and key == "name") or (not local_server and key in ("tools", "structured_output",
                                                                                         "send_effort")):
            continue
        data[key] = value.strip() if isinstance(value, str) else value
    if values.get("requests_per_minute") is not None:  # 0: no limit
        data["requests_per_minute"] = values["requests_per_minute"] or None
    if values.get("pinned_models") is not None:
        data["pinned_models"] = clean_models(values["pinned_models"])
    if values.get("supplier") is not None:  # the whole record (owner, terms reviewed, notes): HB-SC-1
        supplier = Supplier.model_validate(values["supplier"])
        if supplier.reviewed_at is not None and not 0 < supplier.reviewed_at <= time.time() + 86400:
            raise ValueError("The terms review date cannot be in the future")
        data["supplier"] = supplier.model_copy(update={"owner": supplier.owner.strip(),
                                                       "notes": supplier.notes.strip()}).model_dump()
    if current is None or (values.get("base_url") is not None and not builtin):  # a built-in's address is fixed
        if kind == "openai":
            from .llm.adapters.openai import azure_url_ok

            url = (values.get("base_url") or "").strip()
            if not azure_url_ok(url):
                raise ValueError(AZURE_HINT)
            data["base_url"] = url.rstrip("/")
        else:
            data["base_url"] = clean_base_url(values.get("base_url") or DEFAULT_BASE_URL)
    if current is None:
        wanted = _slug(values.get("id") or data.get("name") or "local")
        if not ID_RE.match(wanted) or wanted in RESERVED:
            raise ValueError(f"'{wanted}' cannot be a provider id")
        data["id"], n = wanted, 2
        while get(hub, data["id"]) is not None:
            if values.get("id"):
                raise ValueError(f"A provider '{wanted}' already exists")
            data["id"], n = f"{wanted}-{n}", n + 1
        data["created_by"] = actor
    target = endpoint_of(data["base_url"])
    key, changed = values.get("api_key"), False
    if values.get("clear_api_key"):
        data["api_key"], changed = None, bool(current and current.api_key)
    elif key:
        if len(key) > 4096:
            raise ValueError("The API key is too long")
        data["api_key"], changed = hub.secrets.encrypt(key), True
        if kind == "openai" and values.get("enabled") is None:
            data["enabled"] = True  # a key is how OpenAI gets switched on
    elif current and current.api_key and current.endpoint != target:
        raise ValueError("Enter the API key again (or remove it): a stored key is only sent to the address it was "
                         "entered for")
    if builtin and kind == "openai" and values.get("enabled") is None and current is not None \
            and current.updated_by == "hub" and os.environ.get("OPENAI_API_KEY"):
        data["enabled"] = True  # it ran on OPENAI_API_KEY: the first edit keeps it on
    if local_server and (current is None or any(values.get(k) is not None for k in
                                                ("base_url", "location", "confirm_self_hosted"))):
        _location(data, current, values)
    elif not local_server:
        data["location"], data["location_confirmed"] = "third_party", False
    if current is None or current.endpoint != target:
        data["models"], data["last_test"] = [], None
    data["endpoint"], data["updated_by"], data["updated_at"] = target, actor, time.time()
    saved = _put(hub, LlmProvider.model_validate(data))
    if changed and getattr(hub, "llm", None) is not None:
        hub.llm.secrets_changed()  # the new key is masked in every prompt from now on
    return saved, changed


def delete(hub: "Hub", provider_id: str) -> bool:
    if provider_id in BUILTIN:
        raise ValueError("built in - remove the key instead")
    removed = hub.store.delete(COLLECTION, provider_id)
    if removed:
        hub.bus.publish("llm_provider_removed", {"id": provider_id})
        hub.llm.invalidate()
    return removed


def location_of(base_url: str) -> str:
    from .llm.registry import location_of as where

    return where(base_url)


# --------------------------------------------------------------------------------------
# testing a provider (the provider layer talks to it)
# --------------------------------------------------------------------------------------


def _adapter(hub: "Hub", provider: LlmProvider) -> Any:
    if provider.id == "anthropic":
        return hub.llm.adapters["anthropic"]
    if provider.kind == "openai":
        from .llm.adapters.openai import OpenAIAdapter

        return OpenAIAdapter(hub, provider)
    from .llm.adapters.compat import CompatAdapter

    return CompatAdapter(hub, provider)


async def list_models(hub: "Hub", provider: LlmProvider) -> list[dict[str, Any]]:
    """The provider's models: [{id, hidden?, caps?, lifecycle?, retires_at?}] (`hidden`: not a text model)."""
    return await _adapter(hub, provider).list_models()


def _merge_caps(current: LlmProvider, listed: list[dict[str, Any]]) -> None:
    """Capabilities from a models list (source "api"); what a probe, learning or an administrator found stays."""
    for item in listed:
        caps, lifecycle = item.get("caps"), {k: item.get(k) for k in ("lifecycle", "retires_at") if item.get(k)}
        if caps is None and not lifecycle:
            continue
        old = current.capabilities.get(item["id"])
        fresh = ModelCaps.model_validate({**(caps.model_dump() if caps is not None else {}), **lifecycle})
        if old is not None and old.source in ("probe", "learned", "admin"):
            kept = {k: v for k, v in old.model_dump().items() if v is not None and k not in ("lifecycle", "retires_at")}
            fresh = fresh.model_copy(update=kept)
        current.capabilities[item["id"]] = fresh


async def test(hub: "Hub", provider: LlmProvider) -> dict[str, Any]:
    """List the provider's models (Azure: and make the smallest call on the default deployment); the result, the
    model list and what the list says about each model are stored with the provider."""
    listed: list[dict[str, Any]] = []
    try:
        listed = await list_models(hub, provider)
        models = [m["id"] for m in listed if not m.get("hidden")]
        hidden = len(listed) - len(models)
        detail = f"Connected: {len(models)} model(s)." + (
            f" {hidden} other model(s) (embeddings, audio, images) are not listed." if hidden else "")
        result = {"ok": True, "detail": detail, "models": models}
        if provider.kind == "openai" and provider.variant == "azure":
            result = await _ping_azure(hub, provider, models)
    except ProviderError as exc:
        result = {"ok": False, "detail": str(exc), "models": []}
    current = get(hub, provider.id) or provider
    if result["ok"]:
        current.models = result["models"]
        _merge_caps(current, listed)
        if not current.default_model and len(result["models"]) == 1:
            current.default_model = result["models"][0]
    current.last_test = {"ok": result["ok"], "detail": result["detail"], "at": time.time()}
    put(hub, current)
    caps = {m: current.capabilities[m].model_dump(mode="json") for m in result["models"] if m in current.capabilities}
    return {**result, "provider": public(current), "capabilities": caps}


async def _ping_azure(hub: "Hub", provider: LlmProvider, models: list[str]) -> dict[str, Any]:
    """Azure's test: the smallest Responses call on the default deployment (listing deployments is not relied on)."""
    from .llm.adapters.openai import SMALLEST_OUTPUT
    from .llm.types import Msg, Request

    if not provider.default_model:
        return {"ok": False, "detail": "Enter a deployment name as the default model, then test again", "models": models}
    request = Request(purpose="chat", agent_id="hub", system="Answer with one word.", model=provider.default_model,
                      messages=[Msg(role="user", text="ping")], max_output_tokens=SMALLEST_OUTPUT)
    await hub.llm.complete(provider.id, request, learn=())
    return {"ok": True, "detail": f"Connected: the deployment {provider.default_model} answered.",
            "models": models or [provider.default_model]}
