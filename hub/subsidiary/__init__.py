"""Subsidiaries: agent teams that work inside a tool, governed by Atrium as the parent company.

A bridge patch adds an "Atrium bridge" to the tool's own code (typed actions, an "Ask the team" panel, an events outbox,
a public health route); the team runs in a sidecar next to the tool, thinks through Atrium's model gateway and acts
through the bridge. Atrium approves the charter, every risky action, and can pause, stop or kill-switch the team.

Modules shared with the sidecar (it imports only these, never hub.core, hub.store, FastAPI or a model SDK):

* contract.py - the bridge contract ``atrium-bridge/1``: constants, manifest rules, tickets, grants, request
  signatures, params validation and the conformance vectors (the Python reference; contract/SPEC.md is the text);
* wire.py     - delimitation of tool data and the model gateway's message format;
* models.py   - the stored documents and the sidecar API's request and response bodies.

keys.py (Atrium only) keeps each subsidiary's Ed25519 signing keys, encrypted with the hub's secret key.

Atrium only, the parent's side:

* governance.py  - statuses and flags, enrollment and the sidecar's token, tickets, the dedicated credential, pause,
  resume, stop, the kill switch, the staff's hold, the tick, the approvals' guards and the HB-AC-8 facts;
* audit.py       - the hash-chained audit trail of each subsidiary;
* runtime.py     - ``hub.subsidiaries`` (in-process state), ``hub.subsidiary_config`` and the sidecar's inbox;
* conformance.py - the conformance vectors, Atrium-run or sidecar-run;
* routes.py      - the people's routes and the sidecar API (/api/subsidiary/v1/*);
* bridgegen.py   - the Patch Agent's bridge patch: stack, vendored cores, the model's survey and glue (or the
  templates), the auto-mount, atrium-bridge.json and the static checks;
* bridgepatch.py - the bridge patch's branch, the tool's tests in a container, the approval and its guard, apply and
  reject, and the rule that staff never patch their own bridge.

The sidecar itself (``atrium-sidecar``, runs next to the tool, never inside Atrium) is the package ``sidecar/``.
"""
