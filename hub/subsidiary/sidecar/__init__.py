"""The sidecar: a subsidiary's office next to its tool (round 4, section 6).

It runs the team's staff over Atrium's model gateway and works inside the tool through the bridge (or, without a
bridge, through the tool's API with a dedicated read credential). It connects out only - to Atrium and to the tool -
and never listens on a port. Atrium decides when staff work, approves every write, and can pause or stop it.

    atrium-sidecar --config /etc/atrium-sidecar/config.json [--once | --check]

Modules: config (config.json and the state directory), client (Atrium), bridge_client (the bridge), runtime (the
tasks), runner (runs and grants), tools (a run's model and tools), panel ("Ask the team"), events (the relay),
spool (the claimed audit trail, secret masking), connector_backend (API-only mode).

It imports only hub.subsidiary.contract, wire and models, hub.agents.loops and, in API-only mode, hub.connectors -
never hub.core, hub.store, FastAPI or a model SDK.
"""

from .config import ConfigError, SidecarConfig, load
from .runtime import VERSION, Runtime

__all__ = ["VERSION", "ConfigError", "Runtime", "SidecarConfig", "load"]
