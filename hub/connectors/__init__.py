"""Connectors: the hub's built-in clients for tools' own APIs (see base.py for the SDK and the canonical records).

Adding a connector is one line in REGISTRY ("module:Class", imported on first use). Tests may register a class
directly.
"""

from __future__ import annotations

import importlib
import os
from typing import TYPE_CHECKING, Any

import httpx

from .base import Connector, ConnectorError, ConnectorField

if TYPE_CHECKING:
    from ..models import Tool

REGISTRY: dict[str, str | type[Connector]] = {
    "snipeit": "hub.connectors.snipeit:SnipeItConnector",
    "ciso_assistant": "hub.connectors.ciso_assistant:CisoAssistantConnector",
    "openvas": "hub.connectors.openvas:OpenVasConnector",
    "okta": "hub.connectors.okta:OktaConnector",
    "keycloak": "hub.connectors.keycloak:KeycloakConnector",
    "scim": "hub.connectors.scim:ScimConnector",
    "generic_rest": "hub.connectors.generic_rest:GenericRestConnector",
    "opnsense": "hub.connectors.opnsense:OpnsenseConnector",
    "pfsense": "hub.connectors.pfsense:PfsenseConnector",
    "mikrotik": "hub.connectors.mikrotik:MikrotikConnector",
    "fortigate": "hub.connectors.fortigate:FortigateConnector",
    "panos": "hub.connectors.panos:PanosConnector",
    "hostfw": "hub.connectors.hostfw:HostFirewallConnector",
    "windows_firewall": "hub.connectors.windows_firewall:WindowsFirewallConnector",
    "cisco_iosxe": "hub.connectors.cisco_iosxe:CiscoIosXeConnector",
}
if os.environ.get("HUB_DEV_FAKE_DEVICES") == "1":  # an in-memory firewall to try the Network app (never in production)
    REGISTRY["fake_firewall"] = "hub.connectors.fake_firewall:FakeFirewallConnector"

__all__ = ["REGISTRY", "Connector", "ConnectorError", "ConnectorField", "build", "catalog", "connector_class", "detect"]


def connector_class(kind: str) -> type[Connector]:
    target = REGISTRY.get(kind)
    if target is None:
        raise ConnectorError(f"Unknown connector kind '{kind}'")
    if isinstance(target, str):
        module, _, name = target.partition(":")
        target = getattr(importlib.import_module(module), name)
    return target  # type: ignore[return-value]


def catalog() -> list[dict[str, Any]]:
    out = []
    for kind in REGISTRY:
        try:
            out.append(connector_class(kind).describe())
        except Exception as exc:  # a broken optional connector must not hide the others
            out.append({"kind": kind, "title": kind, "description": "", "fields": [], "capabilities": {},
                        "actions": [], "system_of_record": [], "error": f"{exc.__class__.__name__}: {exc}"})
    return out


def detect(tool: "Tool") -> list[dict[str, Any]]:
    """Connector kinds that may fit `tool`, best first."""
    scored = []
    for kind in REGISTRY:
        try:
            cls = connector_class(kind)
            score = max(0, min(100, int(cls.detect(tool))))
        except Exception:
            continue
        if score:
            scored.append({"kind": kind, "title": cls.title, "score": score})
    return sorted(scored, key=lambda s: -s["score"])


def build(kind: str, config: dict[str, Any], secrets: dict[str, str],
          transport: httpx.AsyncBaseTransport | None = None) -> Connector:
    return connector_class(kind)(config, secrets, transport)
