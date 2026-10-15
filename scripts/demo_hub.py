"""A demo hub filled with made-up but realistic data - for the screenshots and for trying Atrium by hand.

    .venv/bin/python scripts/demo_hub.py [--port 8790] [--data-dir DIR]

It starts small fake tool APIs on 127.0.0.1 (Snipe-IT, Keycloak's admin API, a Greenbone / OpenVAS manager speaking
GMP over plain TCP, CISO Assistant, plain web pages for Grafana and Wazuh, and two AI model servers with an
OpenAI-compatible API - a pay-per-token cloud service and an Ollama on the company's GPU server - that answer with
canned text), then a hub with HUB_DEV_FAKE_DEVICES=1 (the in-memory fake firewall) and HUB_LLM=off (Claude and OpenAI
off: no real model is ever called) on a temporary data directory and a port other than 8710, and seeds it through the
hub's own REST API only: accounts for every role, the imported tools and their connections, approved data flows that
pull assets, people and accounts from the fakes, a vulnerability scan, a CyFun 2025 self-assessment, policies and
risks, the fake firewall with its network flow, the two model servers as AI providers with agents on different models
and the Hub Supervisor's own settings, a shared dashboard of tool widgets and a personal one, an API-only subsidiary
of CISO Assistant whose scripted sidecar (FakeSidecar) enrolls and asks for a change in the tool, and pending
proposals (a firewall change, a data flow, agent teams, that in-tool change) in Approvals. Ctrl+C stops everything and
removes the data directory.

Every name, address, e-mail address and credential here is invented (example.com, 10.0.0.0/8, 203.0.113.0/24);
the "secrets" only unlock the fakes in this file. `scripts/screenshots.py` uses this module.
"""

from __future__ import annotations

import argparse
import base64
import html
import json
import os
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit
from xml.sax.saxutils import escape, quoteattr

import httpx

ROOT = Path(__file__).resolve().parent.parent
DAY = 86400
DOMAIN = "example.com"
NS = uuid.UUID("6f1c2b4e-58a9-4f0e-9d7a-3c2b1a0e9f11")  # stable ids: the same demo every run

# -- the demo organisation ---------------------------------------------------------------------------------------------

# Atrium accounts: (username, role, display name). The password is chosen at start (--password or random).
USERS = [("ava", "admin", "Ava Martens"), ("noah", "admin", "Noah Willems"), ("jonas", "operator", "Jonas Peeters"),
         ("lena", "viewer", "Lena Claes")]

# people in the Keycloak realm: (login, first, last, title, department, manager login, enabled, groups, location)
PEOPLE = [
    ("ava.martens", "Ava", "Martens", "Head of IT", "IT", None, True, ["it", "admins"], "Ghent"),
    ("noah.willems", "Noah", "Willems", "Security Engineer", "IT", "ava.martens", True, ["it", "security"], "Ghent"),
    ("jonas.peeters", "Jonas", "Peeters", "Network Engineer", "IT", "ava.martens", True, ["it", "network"], "Ghent"),
    ("lena.claes", "Lena", "Claes", "Compliance Officer", "Risk & Compliance", "ava.martens", True, ["compliance"],
     "Brussels"),
    ("emma.janssens", "Emma", "Janssens", "Finance Controller", "Finance", None, True, ["finance"], "Brussels"),
    ("pieter.desmet", "Pieter", "De Smet", "Accountant", "Finance", "emma.janssens", False, ["finance"], "Brussels"),
    ("lucas.maes", "Lucas", "Maes", "Sales Manager", "Sales", None, True, ["sales"], "Antwerp"),
    ("sofie.jacobs", "Sofie", "Jacobs", "HR Business Partner", "HR", None, True, ["hr"], "Ghent"),
    ("milan.mertens", "Milan", "Mertens", "Software Developer", "Engineering", "ava.martens", True, ["engineering"],
     "Ghent"),
    ("julie.wouters", "Julie", "Wouters", "Office Manager", "Operations", None, True, ["operations"], "Antwerp"),
]
LEAVER = "pieter.desmet"  # disabled in Keycloak, still holds a laptop and a Snipe-IT login

# hardware in Snipe-IT: (tag, name, category, manufacturer, model, ip, assigned login, os)
# zones of the fake firewall: LAN 10.0.10.0/24, SERVERS 10.0.20.0/24, GUEST 10.0.30.0/24, MGMT 10.0.99.0/24
HARDWARE = [
    ("SRV-0001", "web-01", "Servers", "Dell", "PowerEdge R660", "10.0.20.10", None, "Ubuntu 24.04 LTS"),
    ("SRV-0002", "db-01", "Servers", "Dell", "PowerEdge R660", "10.0.20.11", None, "Debian 12"),
    ("SRV-0003", "app-01", "Virtual Machines", "VMware", "Virtual Machine", "10.0.20.12", None, "Ubuntu 22.04 LTS"),
    ("SRV-0004", "files-01", "Storage", "Synology", "RackStation RS1221+", "10.0.20.20", None, "DSM 7.2"),
    ("SRV-0005", "mail-01", "Virtual Machines", "VMware", "Virtual Machine", "10.0.20.25", None, "Debian 12"),
    ("SRV-0010", "esx-01", "Servers", "Dell", "PowerEdge R760", "10.0.99.20", None, "VMware ESXi 7.0"),
    ("SRV-0011", "backup-01", "Storage", "Synology", "RackStation RS2423+", "10.0.99.30", None, "DSM 7.2"),
    ("NET-0001", "core-switch-01", "Switches", "Cisco", "Catalyst 9300-24T", "10.0.99.2", None, "IOS-XE 17.9"),
    ("LT-1041", "LT-1041", "Laptops", "Lenovo", "ThinkPad T14 Gen 5", "10.0.10.41", "ava.martens", "Windows 11"),
    ("LT-1042", "LT-1042", "Laptops", "Lenovo", "ThinkPad T14 Gen 5", "10.0.10.42", "noah.willems", "Ubuntu 24.04 LTS"),
    ("LT-1043", "LT-1043", "Laptops", "Dell", "Latitude 7450", "10.0.10.43", "jonas.peeters", "Windows 11"),
    ("LT-1044", "LT-1044", "Laptops", "Apple", "MacBook Pro 14", "10.0.10.44", "lena.claes", "macOS 15"),
    ("LT-1045", "LT-1045", "Laptops", "Dell", "Latitude 7450", "10.0.10.45", "emma.janssens", "Windows 11"),
    ("LT-1046", "LT-1046", "Laptops", "Dell", "Latitude 5450", "10.0.10.46", "pieter.desmet", "Windows 11"),
    ("LT-1047", "LT-1047", "Laptops", "Apple", "MacBook Air 13", "10.0.10.47", "lucas.maes", "macOS 15"),
    ("LT-1048", "LT-1048", "Laptops", "Lenovo", "ThinkPad X1 Carbon", "10.0.10.48", "sofie.jacobs", "Windows 11"),
    ("LT-1049", "LT-1049", "Laptops", "Apple", "MacBook Pro 16", "10.0.10.49", "milan.mertens", "macOS 15"),
    ("KSK-0001", "lobby-kiosk", "Desktops", "HP", "Elite Mini 800 G9", "10.0.30.15", None, "Windows 11 IoT"),
]
SERVER_OWNERS = {"web-01": "milan.mertens", "db-01": "milan.mertens", "app-01": "milan.mertens",
                 "files-01": "ava.martens", "mail-01": "ava.martens", "esx-01": "jonas.peeters",
                 "backup-01": "jonas.peeters", "core-switch-01": "jonas.peeters"}
CRITICALITY = {"web-01": "high", "db-01": "critical", "app-01": "high", "esx-01": "critical", "backup-01": "high",
               "core-switch-01": "high", "files-01": "medium", "mail-01": "medium"}

OID = "1.3.6.1.4.1.25623.1.0."
# Greenbone findings per host: (oid suffix, name, severity, port, cves, age in days, summary, solution)
FINDINGS: dict[str, list[tuple[str, str, float, str, list[str], int, str, str]]] = {
    "10.0.20.10": [
        ("114678", "Apache HTTP Server < 2.4.62 Multiple Vulnerabilities", 7.5, "443/tcp", ["CVE-2024-38476",
         "CVE-2024-38477"], 9, "The installed Apache HTTP Server is prone to multiple vulnerabilities.",
         "Update to version 2.4.62 or later."),
        ("117274", "SSL/TLS: Report Weak Cipher Suites", 5.0, "443/tcp", [], 9,
         "The remote service accepts weak SSL/TLS cipher suites.", "Disable the weak cipher suites."),
        ("117335", "SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection", 4.3, "443/tcp", [], 9,
         "The remote service accepts the deprecated TLSv1.0 and TLSv1.1 protocols.", "Allow TLSv1.2 and later only."),
    ],
    "10.0.20.11": [
        ("170846", "PostgreSQL 16.x < 16.4 SQL Injection Vulnerability", 8.8, "5432/tcp", ["CVE-2024-7348"], 15,
         "A race condition in pg_dump lets an object creator run arbitrary SQL as the user running pg_dump.",
         "Update to version 16.4 or later."),
    ],
    "10.0.20.12": [
        ("153812", "Apache Tomcat Remote Code Execution Vulnerability (Mar 2025)", 9.8, "8080/tcp",
         ["CVE-2025-24813"], 12, "Apache Tomcat is prone to a remote code execution vulnerability via partial PUT.",
         "Update to version 10.1.35, 11.0.3 or later."),
        ("108440", "Jolokia JMX Endpoint Exposed", 5.3, "8080/tcp", [], 12,
         "A Jolokia JMX endpoint is reachable without authentication.", "Restrict access to the endpoint."),
    ],
    "10.0.20.20": [
        ("150712", "Samba < 4.19.5 Information Disclosure", 6.5, "445/tcp", ["CVE-2023-42670"], 30,
         "Samba is prone to an information disclosure vulnerability.", "Update to version 4.19.5 or later."),
    ],
    "10.0.20.25": [
        ("114674", "OpenSSH < 9.8 Race Condition RCE (regreSSHion)", 8.1, "22/tcp", ["CVE-2024-6387"], 4,
         "A signal handler race condition in sshd allows unauthenticated remote code execution.",
         "Update to version 9.8p1 or later."),
        ("103185", "SMTP Server STARTTLS Not Enforced", 2.6, "25/tcp", [], 4,
         "The remote SMTP server accepts mail without STARTTLS.", "Require STARTTLS for submission."),
    ],
    "10.0.99.20": [
        ("104660", "VMware ESXi OpenSLP Heap Overflow (VMSA-2021-0002)", 8.8, "427/udp", ["CVE-2021-21974"], 40,
         "The OpenSLP service of VMware ESXi has a heap overflow.", "Apply the patch named in VMSA-2021-0002, or "
         "disable the SLP service."),
    ],
    "10.0.99.30": [
        ("105611", "Weak MAC Algorithm(s) Supported (SSH)", 2.6, "22/tcp", [], 20,
         "The remote SSH server is configured to allow weak MAC algorithms.", "Disable the weak MAC algorithms."),
    ],
    "10.0.99.2": [
        ("103416", "SNMP Agent Default Community Name (public)", 7.5, "161/udp", ["CVE-1999-0517"], 22,
         "The SNMP agent accepts the default community name 'public'.", "Change or disable the community name."),
    ],
}

# Wazuh alerts entered in the Alerts app (the extension pack Atrium proposes for Wazuh):
# (title, severity, status, rule, host, user login, hours ago)
ALERTS = [
    ("Multiple authentication failures for sshd", "high", "open", "5712", "10.0.20.25", None, 3),
    ("New user added to the local Administrators group", "high", "acknowledged", "60154", "10.0.10.46",
     "pieter.desmet@example.com", 20),
    ("File integrity: /etc/sudoers changed", "medium", "new", "550", "10.0.20.11", None, 6),
    ("Web server 400 error codes from one source", "low", "closed", "31151", "10.0.20.10", None, 50),
]

# demo credentials: they only open the fakes below
SNIPEIT_TOKEN = "demo-snipeit-api-token"
KEYCLOAK_SECRET = "demo-keycloak-client-secret"
GREENBONE_PASSWORD = "demo-greenbone-password"
CISO_TOKEN = "demo-ciso-assistant-token"
CISO_TEAM_TOKEN = "demo-ciso-assistant-team-token"  # the subsidiary's own account: read-only
FIREWALL_KEY = "demo-firewall-api-key"
MODEL_CLOUD_KEY = "demo-model-cloud-api-key"

# AI model servers: (provider id, name, models; the first is the default). The cloud one is a third party.
MODEL_CLOUD = ("model-cloud", "EU model cloud", ["chat-large-v3", "chat-small-v3"])
MODEL_LOCAL = ("gpu-01", "Ollama on gpu-01", ["qwen3:32b", "llama3.3:70b", "gpt-oss:20b"])
CLOUD_PRICE = {"input": 2.5, "cached_input": 0.25, "output": 10.0}  # USD per 1M tokens, set by an administrator
# the CISO Assistant subsidiary: what it is for, the task an operator gives its clerk and the change the clerk asks for
TEAM_GOALS = ("Keep CISO Assistant's controls in step with what IT really runs: record new security measures as "
              "controls and point out controls without evidence.")
TEAM_TASK = ("MFA for remote access is enforced for every account since September (change CHG-2026-097). Record it "
             "as a control in CISO Assistant.")
TEAM_CHANGE = {"external_id": "atrium:control:mfa-remote-access", "ref_id": "PR.AA-03", "name": "MFA for remote access",
               "description": "Every remote access (VPN, webmail, admin portals) needs a second factor since "
                              "September 2026 (CHG-2026-097).", "status": "pass"}
TEAM_REASON = ("Jonas reports that MFA for remote access has been enforced since September (CHG-2026-097); CISO "
               "Assistant has no control for it yet, so I ask to create one with status pass.")
# canned answers of the fake models: (words in the question, answer)
REPLIES = [
    (("leaver",), "One leaver still has access: **Pieter De Smet** (Finance) is disabled in Keycloak but still holds "
                  "laptop LT-1046 and an active Snipe-IT login. Revoking the login and collecting the laptop closes "
                  "it - both are listed under People > Leavers."),
    (("deadline", "overdue", "finding"), "Two findings are past their deadline: the Tomcat remote code execution on "
                                         "app-01 (critical, CVE-2025-24813) and the OpenSLP heap overflow on esx-01 "
                                         "(high). Both have a vendor fix; app-01 is the urgent one."),
]
DEFAULT_REPLY = "Nothing needs your attention right now: every data flow ran, and the approvals queue is up to date."


def email_of(login: str) -> str:
    return f"{login}@{DOMAIN}"


def stable_id(*parts: Any) -> str:
    return str(uuid.uuid5(NS, "/".join(map(str, parts))))


def iso(at: float) -> str:
    return datetime.fromtimestamp(at, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def person(login: str) -> tuple:
    return next(p for p in PEOPLE if p[0] == login)


# -- fake tool APIs --------------------------------------------------------------------------------------------------

Reply = tuple[int, Any]  # (status, JSON value or HTML text)


class _Handler(BaseHTTPRequestHandler):
    server_version = "demo"

    def log_message(self, *args: Any) -> None:  # quiet
        pass

    def _serve(self, method: str) -> None:
        parts = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        try:
            status, value = self.server.app(method, parts.path, parse_qs(parts.query), body, self.headers)  # type: ignore[attr-defined]
        except Exception as exc:  # a broken fake must say so, not hang the hub's request
            status, value = 500, {"detail": f"fake error: {exc.__class__.__name__}: {exc}"}
        if isinstance(value, str):
            data, ctype = value.encode(), "text/html; charset=utf-8"
        else:
            data, ctype = json.dumps(value).encode(), "application/json"
        self.send_response(status)
        if status != 204:
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if status != 204:
            self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802 - http.server's naming
        self._serve("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._serve("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._serve("PUT")

    def do_PATCH(self) -> None:  # noqa: N802
        self._serve("PATCH")

    def do_DELETE(self) -> None:  # noqa: N802
        self._serve("DELETE")


# OpenAPI documents the fakes serve at /openapi.json, so the hub reads each tool's API on import:
# (title, version, security scheme, [(method, path), ...])
SPECS: dict[str, tuple[str, str, dict[str, Any], list[tuple[str, str]]]] = {
    "snipeit": ("Snipe-IT API", "8.3.2", {"type": "http", "scheme": "bearer"},
                [("get", "/api/v1/hardware"), ("post", "/api/v1/hardware"), ("get", "/api/v1/hardware/{id}"),
                 ("patch", "/api/v1/hardware/{id}"), ("get", "/api/v1/users"), ("get", "/api/v1/users/me")]),
    "keycloak": ("Keycloak Admin REST API", "26.4", {"type": "openIdConnect", "openIdConnectUrl":
                                                    "/realms/company/.well-known/openid-configuration"},
                 [("get", "/admin/realms/{realm}/users"), ("post", "/admin/realms/{realm}/users"),
                  ("get", "/admin/realms/{realm}/users/{id}"), ("put", "/admin/realms/{realm}/users/{id}"),
                  ("get", "/admin/realms/{realm}/users/{id}/groups"), ("get", "/admin/realms/{realm}/clients")]),
    "ciso": ("CISO Assistant API", "2.7.1", {"type": "apiKey", "in": "header", "name": "Authorization"},
             [("get", "/api/assets/"), ("post", "/api/assets/"), ("get", "/api/applied-controls/"),
              ("post", "/api/applied-controls/"), ("get", "/api/risk-scenarios/"), ("get", "/api/vulnerabilities/"),
              ("post", "/api/vulnerabilities/"), ("get", "/api/frameworks/"), ("get", "/api/compliance-assessments/")]),
    "grafana": ("Grafana HTTP API", "12.2.0", {"type": "http", "scheme": "bearer"},
                [("get", "/api/search"), ("get", "/api/dashboards/uid/{uid}"), ("post", "/api/dashboards/db"),
                 ("get", "/api/v1/provisioning/alert-rules"), ("get", "/api/health")]),
    "wazuh": ("Wazuh API REST", "4.13.1", {"type": "http", "scheme": "bearer"},
              [("post", "/security/user/authenticate"), ("get", "/agents"), ("get", "/agents/{agent_id}"),
               ("get", "/syscheck/{agent_id}"), ("get", "/rules"), ("get", "/manager/status")]),
}


def openapi(key: str, base: str) -> dict[str, Any]:
    title, version, scheme, operations = SPECS[key]
    paths: dict[str, dict[str, Any]] = {}
    for method, path in operations:
        paths.setdefault(path, {})[method] = {"summary": f"{method.upper()} {path}", "responses": {"200": {
            "description": "OK"}}}
    if scheme.get("openIdConnectUrl", "").startswith("/"):
        scheme = {**scheme, "openIdConnectUrl": base + scheme["openIdConnectUrl"]}
    return {"openapi": "3.0.3", "info": {"title": title, "version": version, "description": f"{title} (demo)"},
            "servers": [{"url": base}], "paths": paths,
            "components": {"securitySchemes": {"auth": scheme}}, "security": [{"auth": []}]}


def web_page(title: str, spec: str | None = None) -> Callable[..., Reply]:
    """A tool's home page (enough for the hub's health check) and, with `spec`, its OpenAPI document."""
    def app(method: str, path: str, query: dict, body: bytes, headers: Any) -> Reply:
        if method == "GET" and path in ("", "/"):
            return 200, f"<!doctype html><title>{html.escape(title)}</title><h1>{html.escape(title)} (demo)</h1>"
        if method == "GET" and spec and path == "/openapi.json":
            return 200, openapi(spec, f"http://{headers.get('Host')}")
        return 404, {"detail": "Not found"}
    return app


def _page(items: list, query: dict, offset_key: str = "offset", limit_key: str = "limit") -> tuple[list, int]:
    offset = int((query.get(offset_key) or ["0"])[0])
    limit = int((query.get(limit_key) or ["50"])[0])
    return items[offset:offset + limit], len(items)


def snipeit_app(method: str, path: str, query: dict, body: bytes, headers: Any) -> Reply:
    """Snipe-IT's REST API v1 (the calls the hub's connector makes, read-only)."""
    if path in ("", "/", "/openapi.json"):
        return web_page("Snipe-IT", "snipeit")(method, path, query, body, headers)
    if headers.get("Authorization") != f"Bearer {SNIPEIT_TOKEN}":
        return 401, {"status": "error", "messages": "Unauthorized."}
    if method != "GET":
        return 405, {"status": "error", "messages": "This demo is read-only."}
    if path == "/api/v1/version":
        return 200, {"version": "v8.3.2", "build_version": "demo"}
    if path == "/api/v1/users/me":
        return 200, {"id": 1, "username": "atrium-sync", "name": "Atrium sync"}
    if path == "/api/v1/hardware":
        rows, total = _page([_hardware(i, h) for i, h in enumerate(HARDWARE, start=1)], query)
        return 200, {"total": total, "rows": rows}
    if path == "/api/v1/users":
        users = [{"id": i, "username": p[0], "email": email_of(p[0]), "name": f"{p[1]} {p[2]}", "first_name": p[1],
                  "last_name": p[2], "activated": True, "deleted_at": None,
                  "last_login": {"datetime": iso(time.time() - (3 + i) * 3600), "formatted": ""}}
                 for i, p in enumerate(PEOPLE, start=2)]
        rows, total = _page(users, query)
        return 200, {"total": total, "rows": rows}
    return 404, {"status": "error", "messages": "Not found."}


def _hardware(row_id: int, h: tuple) -> dict[str, Any]:
    tag, name, category, maker, model, ip, login, os_name = h
    assigned = None
    if login:
        p = person(login)
        assigned = {"id": PEOPLE.index(p) + 2, "type": "user", "name": f"{p[1]} {p[2]}", "username": login,
                    "email": email_of(login)}
    mac = "02:00:5e:%02x:%02x:%02x" % (row_id, len(name), sum(map(ord, tag)) % 256)
    return {"id": row_id, "name": name, "asset_tag": tag, "serial": f"DEMO{row_id:05d}{tag[-2:]}",
            "model": {"id": row_id, "name": model}, "manufacturer": {"id": 1, "name": maker},
            "category": {"id": 1, "name": category}, "status_label": {"id": 2, "name": "Deployed",
                                                                      "status_type": "deployable",
                                                                      "status_meta": "deployed"},
            "assigned_to": assigned, "location": {"id": 1, "name": "Ghent HQ" if not ip.startswith("10.0.10.") else
                                                   "Office"},
            "custom_fields": {"IP Address": {"field": "_snipeit_ip_address_1", "value": ip, "field_format": "IP"},
                              "MAC Address": {"field": "_snipeit_mac_address_2", "value": mac,
                                              "field_format": "MAC"},
                              "Operating System": {"field": "_snipeit_os_3", "value": os_name,
                                                   "field_format": "ANY"}},
            "purchase_date": {"date": "2024-03-1%d" % (row_id % 9), "formatted": ""},
            "updated_at": {"datetime": "2026-10-01 09:00:00", "formatted": ""}, "deleted_at": None}


def keycloak_app(realm: str) -> Callable[..., Reply]:
    users = [{"id": stable_id("kc", p[0]), "username": p[0], "email": email_of(p[0]), "firstName": p[1],
              "lastName": p[2], "enabled": p[6], "createdTimestamp": int((time.time() - 400 * DAY) * 1000),
              "attributes": {"title": [p[3]], "department": [p[4]], "location": [p[8]],
                             **({"manager": [stable_id("kc", p[5])]} if p[5] else {})}} for p in PEOPLE]
    groups = {stable_id("kc", p[0]): [{"id": stable_id("group", g), "name": g, "path": f"/{g}"} for g in p[7]]
              for p in PEOPLE}
    admin = f"/admin/realms/{realm}"

    def app(method: str, path: str, query: dict, body: bytes, headers: Any) -> Reply:
        if path in ("", "/", "/openapi.json"):
            return web_page("Keycloak", "keycloak")(method, path, query, body, headers)
        if path == f"/realms/{realm}/.well-known/openid-configuration":
            issuer = f"http://{headers.get('Host')}/realms/{realm}"
            return 200, {"issuer": issuer, "authorization_endpoint": f"{issuer}/protocol/openid-connect/auth",
                         "token_endpoint": f"{issuer}/protocol/openid-connect/token",
                         "userinfo_endpoint": f"{issuer}/protocol/openid-connect/userinfo",
                         "jwks_uri": f"{issuer}/protocol/openid-connect/certs"}
        if method == "POST" and path == f"/realms/{realm}/protocol/openid-connect/token":
            form = parse_qs(body.decode())
            if form.get("client_secret") != [KEYCLOAK_SECRET]:
                return 401, {"error": "unauthorized_client", "error_description": "Invalid client credentials"}
            return 200, {"access_token": "demo-access-token", "expires_in": 300, "token_type": "Bearer"}
        if not path.startswith(admin):
            return 404, {"error": "Not found"}
        if headers.get("Authorization") != "Bearer demo-access-token":
            return 401, {"error": "HTTP 401 Unauthorized"}
        rest = path[len(admin):]
        if rest == "/users/count":
            return 200, len(users)
        if rest == "/users":
            return 200, _page(users, query, "first", "max")[0]
        if rest.startswith("/users/") and rest.endswith("/groups"):
            return 200, groups.get(rest.split("/")[2], [])
        return 404, {"error": "Not found"}
    return app


class CisoAssistant:
    """CISO Assistant's REST API as a plain object store: lists page with limit / offset, POST creates, PATCH
    updates - enough for the connector's test, its pushes (assets, controls and evidence, findings) and its reads.
    Two accounts: Atrium's sync account (CISO_TOKEN) and the subsidiary team's read-only one (CISO_TEAM_TOKEN)."""

    COLLECTIONS = ("assets", "applied-controls", "evidences", "risk-scenarios", "vulnerabilities", "frameworks",
                   "compliance-assessments", "requirement-assessments", "folders", "risk-matrices")

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.store: dict[str, dict[str, dict[str, Any]]] = {c: {} for c in self.COLLECTIONS}
        root = stable_id("ciso", "global")
        self.store["folders"][root] = {"id": root, "name": "Global", "content_type": "GLOBAL", "parent_folder": None}

    def __call__(self, method: str, path: str, query: dict, body: bytes, headers: Any) -> Reply:
        if path in ("", "/", "/openapi.json"):
            return web_page("CISO Assistant", "ciso")(method, path, query, body, headers)
        if not path.startswith("/api/"):
            return 404, {"detail": "Not found."}
        team = headers.get("Authorization") == f"Token {CISO_TEAM_TOKEN}"
        if headers.get("Authorization") != f"Token {CISO_TOKEN}" and not team:
            return 401, {"detail": "Invalid token."}
        if team and method != "GET":
            return 403, {"detail": "You do not have permission to perform this action."}
        parts = [p for p in path[len("/api/"):].split("/") if p]
        if parts == ["iam", "current-user"]:
            login = "atrium-team" if team else "atrium-sync"
            return 200, {"id": stable_id("ciso", login), "email": f"{login}@example.com", "first_name": "Atrium"}
        if parts == ["build"]:
            return 200, {"version": "v2.7.1"}
        if parts == ["loaded-libraries"]:
            return 200, []
        if not parts or parts[0] not in self.store:
            return 404, {"detail": "Not found."}
        items = self.store[parts[0]]
        with self.lock:
            if len(parts) == 1 and method == "GET":
                rows, total = _page(list(items.values()), query)
                return 200, {"count": total, "next": None, "previous": None, "results": rows}
            if len(parts) == 1 and method == "POST":
                data = json.loads(body or b"{}")
                item = {**data, "id": str(uuid.uuid4())}
                items[item["id"]] = item
                return 201, item
            item = items.get(parts[1]) if len(parts) > 1 else None
            if item is None:
                return 404, {"detail": "No object matches the given query."}
            if method == "GET":
                return 200, item
            if method in ("PATCH", "PUT"):
                item.update(json.loads(body or b"{}"))
                return 200, item
            if method == "DELETE":
                items.pop(parts[1], None)
                return 204, None
        return 405, {"detail": "Method not allowed."}


def skeleton(schema: dict[str, Any]) -> Any:
    """The smallest value that fits a JSON schema: what the fake models answer to structured-output requests."""
    if schema.get("enum"):
        return schema["enum"][0]
    kind = schema.get("type")
    kind = kind[0] if isinstance(kind, list) else kind
    if kind == "object":
        required = set(schema.get("required") or [])
        return {k: skeleton(v) for k, v in (schema.get("properties") or {}).items() if k in required}
    return {"array": [], "string": "", "integer": 0, "number": 0, "boolean": False}.get(str(kind))


class ModelServer:
    """An AI model server with an OpenAI-compatible API (GET /v1/models, POST /v1/chat/completions), as Atrium's
    "openai_compatible" providers call it - with canned answers instead of a model: REPLIES by the words of the
    question, the subsidiary clerk's control (TEAM_CHANGE) as a tool call when it is offered the tool and asked about
    MFA, a tool it is told to call by name (Atrium's capability check), and the smallest valid JSON for structured
    output. Usage is counted from the characters, about 4 a token."""

    def __init__(self, models: list[str], key: str | None = None):
        self.models, self.key = models, key
        self.calls = 0

    def __call__(self, method: str, path: str, query: dict, body: bytes, headers: Any) -> Reply:
        if method == "GET" and path in ("", "/"):
            return 200, "<!doctype html><title>Model server</title><h1>Model server (demo)</h1>"
        if self.key and headers.get("Authorization") != f"Bearer {self.key}":
            return 401, {"error": {"message": "Invalid API key.", "type": "invalid_request_error"}}
        if method == "GET" and path == "/v1/models":
            return 200, {"object": "list", "data": [{"id": m, "object": "model", "owned_by": "demo"} for m in self.models]}
        if method == "POST" and path == "/v1/chat/completions":
            return 200, self.complete(json.loads(body or b"{}"))
        return 404, {"error": {"message": "Not found.", "type": "invalid_request_error"}}

    def complete(self, req: dict[str, Any]) -> dict[str, Any]:
        self.calls += 1
        messages = req.get("messages") or []
        last = messages[-1] if messages else {}
        asked = " ".join(str(m.get("content") or "") for m in messages if m.get("role") == "user")
        offered = {str(f.get("name")): f.get("parameters") or {} for f in
                   (t.get("function") or {} for t in req.get("tools") or [])}
        upsert = next((name for name in offered if name.endswith("controls-upsert")), None)
        told = next((name for name in offered if f"Call the {name} tool" in str(last.get("content") or "")), None)
        fmt = req.get("response_format") or {}
        message: dict[str, Any] = {"role": "assistant", "content": ""}
        if told:
            message["tool_calls"] = [{"id": f"call_{self.calls}", "type": "function",
                                      "function": {"name": told, "arguments": json.dumps(skeleton(offered[told]))}}]
        elif fmt.get("type") == "json_schema":
            message["content"] = json.dumps(skeleton((fmt.get("json_schema") or {}).get("schema") or {}))
        elif fmt.get("type") == "json_object":
            message["content"] = "{}"
        elif last.get("role") == "tool":
            message["content"] = ("I asked Atrium to record the control MFA for remote access in CISO Assistant; the "
                                  "change waits for a person's approval.")
        elif upsert and "MFA" in asked:
            message["content"] = TEAM_REASON
            message["tool_calls"] = [{"id": f"call_{self.calls}", "type": "function",
                                      "function": {"name": upsert, "arguments": json.dumps(TEAM_CHANGE)}}]
        else:
            question = str(last.get("content") or "").lower()
            message["content"] = next((text for words, text in REPLIES if any(w in question for w in words)),
                                      DEFAULT_REPLY)
        sent = len(json.dumps(messages)) + len(json.dumps(req.get("tools") or []))
        usage = {"prompt_tokens": sent // 4 + 1, "completion_tokens": len(json.dumps(message)) // 4 + 1}
        return {"id": f"chatcmpl-demo-{self.calls}", "object": "chat.completion", "created": int(time.time()),
                "model": req.get("model"), "usage": {**usage, "total_tokens": sum(usage.values())},
                "choices": [{"index": 0, "message": message,
                             "finish_reason": "tool_calls" if message.get("tool_calls") else "stop"}]}


class Greenbone:
    """gvmd, as far as the hub's OpenVAS connector needs it: login, the default scan config / scanner / port list,
    targets, tasks and results. A started scan finishes at once with the FINDINGS of the hosts it targeted."""

    CONFIG = "daba56c8-73ec-11df-a475-002264764cea"
    SCANNER = "08b69003-5fc2-4037-a479-93b440211c73"
    PORT_LIST = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.targets: dict[str, dict[str, Any]] = {}
        self.tasks: dict[str, dict[str, Any]] = {}
        self.results: list[dict[str, Any]] = []

    @staticmethod
    def reply(tag: str, body: str = "", status: str = "200", text: str = "OK", **attrs: str) -> str:
        extra = "".join(f" {k}={quoteattr(v)}" for k, v in attrs.items())
        return f'<{tag}_response status="{status}" status_text={quoteattr(text)}{extra}>{body}</{tag}_response>'

    def answer(self, el: ET.Element, authed: bool) -> tuple[str, bool]:
        tag = el.tag
        if tag == "get_version":
            return self.reply(tag, "<version>22.5</version>"), authed
        if tag == "authenticate":
            ok = el.findtext("credentials/password") == GREENBONE_PASSWORD
            return (self.reply(tag, "<role>User</role><timezone>UTC</timezone>") if ok else
                    self.reply(tag, status="400", text="Authentication failed")), ok
        if not authed:
            return self.reply(tag, status="401", text="Authenticate first"), authed
        with self.lock:
            return getattr(self, f"do_{tag}", self.bogus)(el), authed

    def bogus(self, el: ET.Element) -> str:
        return self.reply(el.tag, status="400", text=f"Bogus command name {el.tag}")

    @staticmethod
    def count(tag: str, total: int) -> str:
        return f"<{tag}_count>{total}<filtered>{total}</filtered><page>{total}</page></{tag}_count>"

    def do_get_configs(self, el: ET.Element) -> str:
        return self.reply(el.tag, f'<config id="{self.CONFIG}"><name>Full and fast</name><nvt_count>95841<growing>1'
                                  f'</growing></nvt_count><usage_type>scan</usage_type></config>' + self.count("config", 1))

    def do_get_scanners(self, el: ET.Element) -> str:
        return self.reply(el.tag, f'<scanner id="{self.SCANNER}"><name>OpenVAS Default</name><type>2</type></scanner>'
                          + self.count("scanner", 1))

    def do_get_port_lists(self, el: ET.Element) -> str:
        return self.reply(el.tag, f'<port_list id="{self.PORT_LIST}"><name>All IANA assigned TCP</name></port_list>'
                          + self.count("port_list", 1))

    def do_verify_scanner(self, el: ET.Element) -> str:
        return self.reply(el.tag, "<version>OSP 22.5</version>")

    def do_get_feeds(self, el: ET.Element) -> str:
        return self.reply(el.tag, "<feed><type>NVT</type><name>Greenbone Community Feed</name>"
                                  "<version>202610130705</version></feed>")

    def _task(self, task_id: str) -> str:
        t = self.tasks[task_id]
        last = (f'<last_report><report id="{t["report"]}"><timestamp>{iso(t["done_at"])}</timestamp>'
                f'<scan_end>{iso(t["done_at"])}</scan_end></report></last_report>' if t.get("report") else "")
        return (f'<task id="{task_id}"><name>{escape(t["name"])}</name><creation_time>{iso(t["created"])}'
                f'</creation_time><usage_type>scan</usage_type><config id="{self.CONFIG}"><name>Full and fast</name>'
                f'</config><target id="{t["target"]}"><name>target</name></target><scanner id="{self.SCANNER}"><name>'
                f'OpenVAS Default</name><type>2</type></scanner><status>{t["status"]}</status><progress>-1</progress>'
                f'{last}</task>')

    def do_get_tasks(self, el: ET.Element) -> str:
        wanted = el.get("task_id")
        if wanted:
            if wanted not in self.tasks:
                return self.reply(el.tag, status="404", text=f"Failed to find task '{wanted}'")
            return self.reply(el.tag, self._task(wanted))
        return self.reply(el.tag, "".join(self._task(i) for i in self.tasks) + self.count("task", len(self.tasks)))

    def do_get_targets(self, el: ET.Element) -> str:
        target = self.targets.get(el.get("target_id") or "")
        if target is None:
            return self.reply(el.tag, status="404", text="Failed to find target")
        return self.reply(el.tag, f'<target id="{el.get("target_id")}"><name>{escape(target["name"])}</name>'
                                  f'<hosts>{escape(target["hosts"])}</hosts></target>')

    def do_create_target(self, el: ET.Element) -> str:
        target_id = str(uuid.uuid4())
        self.targets[target_id] = {"name": el.findtext("name") or "", "hosts": el.findtext("hosts") or ""}
        return self.reply(el.tag, status="201", text="OK, resource created", id=target_id)

    def do_create_task(self, el: ET.Element) -> str:
        target = el.find("target")
        task_id = str(uuid.uuid4())
        self.tasks[task_id] = {"name": el.findtext("name") or "scan", "target": target.get("id") if target is not None
                               else "", "status": "New", "created": time.time()}
        return self.reply(el.tag, status="201", text="OK, resource created", id=task_id)

    def do_start_task(self, el: ET.Element) -> str:
        task = self.tasks.get(el.get("task_id") or "")
        if task is None:
            return self.reply(el.tag, status="404", text="Failed to find task")
        report = str(uuid.uuid4())
        now = time.time()
        hosts = [h.strip() for h in self.targets.get(task["target"], {}).get("hosts", "").split(",") if h.strip()]
        for host in hosts:
            for oid, name, score, port, cves, age, summary, solution in FINDINGS.get(host, []):
                self.results.append({"id": str(uuid.uuid4()), "report": report, "task": el.get("task_id"), "host": host,
                                     "oid": OID + oid, "name": name, "severity": score, "port": port, "cves": cves,
                                     "created": now - age * DAY, "summary": summary, "solution": solution})
        task.update(status="Done", report=report, done_at=now)
        return self.reply(el.tag, f"<report_id>{report}</report_id>")

    def do_delete_task(self, el: ET.Element) -> str:
        self.tasks.pop(el.get("task_id") or "", None)
        return self.reply(el.tag)

    def do_delete_target(self, el: ET.Element) -> str:
        self.targets.pop(el.get("target_id") or "", None)
        return self.reply(el.tag)

    def do_get_results(self, el: ET.Element) -> str:
        terms = dict(t.split("=", 1) for t in (el.get("filter") or "").split() if "=" in t)
        found = sorted((r for r in self.results if r["report"] == terms.get("report_id")), key=lambda r: -r["severity"])
        first, rows = int(terms.get("first", "1")), int(terms.get("rows", "100"))
        shown = found[first - 1:first - 1 + rows]
        body = "".join(self._result(r) for r in shown)
        return self.reply(el.tag, body + f"<result_count>{len(found)}<filtered>{len(found)}</filtered>"
                                         f"<page>{len(shown)}</page></result_count>")

    @staticmethod
    def _result(r: dict[str, Any]) -> str:
        refs = "".join(f'<ref type="cve" id="{c}"/>' for c in r["cves"])
        tags = escape(f"summary={r['summary']}|solution_type=VendorFix")
        return (f'<result id="{r["id"]}"><name>{escape(r["name"])}</name><creation_time>{iso(r["created"])}'
                f'</creation_time><modification_time>{iso(r["created"])}</modification_time><report id="{r["report"]}"/>'
                f'<task id="{r["task"]}"/><host>{r["host"]}<hostname></hostname></host><port>{r["port"]}</port>'
                f'<nvt oid="{r["oid"]}"><type>nvt</type><name>{escape(r["name"])}</name><family>General</family>'
                f'<cvss_base>{r["severity"]}</cvss_base><tags>{tags}</tags><solution type="VendorFix">'
                f'{escape(r["solution"])}</solution><refs>{refs}</refs></nvt><severity>{r["severity"]}</severity>'
                f'<qod><value>80</value><type>remote_banner</type></qod><description></description></result>')


class _GmpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        manager: Greenbone = self.server.manager  # type: ignore[attr-defined]
        authed = False
        while True:
            command = self._read()
            if command is None:
                return
            text, authed = manager.answer(command, authed)
            self.request.sendall(text.encode())

    def _read(self) -> ET.Element | None:
        parser = ET.XMLPullParser(events=("start", "end"))
        depth, root = 0, None
        while True:
            try:
                chunk = self.request.recv(65536)
            except OSError:
                return None
            if not chunk:
                return None
            parser.feed(chunk)
            for event, element in parser.read_events():
                if event == "start":
                    root = element if root is None else root
                    depth += 1
                else:
                    depth -= 1
                    if depth == 0:
                        return root


class _GmpServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def bind_port(preferred: int) -> int:
    """`preferred` when it is free on 127.0.0.1, else any free port."""
    for port in (preferred, 0):
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # like the servers: a port in TIME_WAIT is free
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                continue
            return s.getsockname()[1]
    raise OSError("no free port")


class DemoTools:
    """The fake tool APIs and model servers, each on its own port of 127.0.0.1: `first_port` and the 9 after it when
    they are free (the screenshots then show the same addresses every time), any free ports with 0. The subsidiary's
    sidecar, once seeding started it, stops with them."""

    def __init__(self, first_port: int = 8791):
        self.first_port = first_port
        self.servers: list[socketserver.BaseServer] = []
        self.urls: dict[str, str] = {}
        self.ciso = CisoAssistant()
        self.greenbone = Greenbone()
        self.models = {"cloud": ModelServer(MODEL_CLOUD[2], MODEL_CLOUD_KEY), "local": ModelServer(MODEL_LOCAL[2])}
        self.gmp_port = 0
        self.sidecar: FakeSidecar | None = None

    def _port(self, offset: int) -> int:
        return bind_port(self.first_port + offset) if self.first_port else 0  # 0: any free port

    def _http(self, key: str, offset: int, app: Callable[..., Reply]) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", self._port(offset)), _Handler)
        server.daemon_threads = True
        server.app = app  # type: ignore[attr-defined]
        self._run(server)
        self.urls[key] = f"http://127.0.0.1:{server.server_address[1]}"

    def _run(self, server: socketserver.BaseServer) -> None:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.servers.append(server)

    def start(self) -> "DemoTools":
        self._http("snipeit", 0, snipeit_app)
        self._http("keycloak", 1, keycloak_app("company"))
        self._http("greenbone", 2, web_page("Greenbone Security Assistant"))
        self._http("ciso", 3, self.ciso)
        self._http("grafana", 4, web_page("Grafana", "grafana"))
        self._http("wazuh", 5, web_page("Wazuh", "wazuh"))
        self._http("firewall", 7, web_page("fw-edge-01"))
        self._http("model_cloud", 8, self.models["cloud"])
        self._http("model_local", 9, self.models["local"])
        gmp = _GmpServer(("127.0.0.1", self._port(6)), _GmpHandler)
        gmp.manager = self.greenbone  # type: ignore[attr-defined]
        self._run(gmp)
        self.gmp_port = gmp.server_address[1]
        return self

    def stop(self) -> None:
        if self.sidecar is not None:
            self.sidecar.stop()
        for server in self.servers:
            server.shutdown()
            server.server_close()


# -- the subsidiary's sidecar ------------------------------------------------------------------------------------------


class FakeSidecar:
    """A scripted sidecar for an API-only subsidiary (docs/SUBSIDIARIES.md), speaking only Atrium's sidecar API
    (/api/subsidiary/v1/): it enrolls with the one-time code and its own Ed25519 key, sends a heartbeat every 20
    seconds (as a non-root container user), runs conformance check K1 - the connector's own test with the team's
    read-only credential, which Atrium hands it - and works on the runs Atrium sends: one turn through Atrium's model
    gateway, the change the model asks for as an action request (it waits for a person in Approvals), a closing turn,
    the reply and the end of the run. Everything else - the charter, the staff, budgets, approvals - is Atrium's."""

    BEAT = 20  # seconds between heartbeats (Atrium flags a sidecar offline after 90)

    def __init__(self, base: str, log: Callable[[str], None] = print):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        public = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.public_key = base64.urlsafe_b64encode(public).rstrip(b"=").decode()
        self.http = httpx.Client(base_url=f"{base}/api/subsidiary/v1/", headers={"X-Hub-Request": "1"}, timeout=60)
        self.log = log
        self.cursor = 0
        self.status = ""
        self.last_error = ""
        self.stopped = threading.Event()
        self.thread: threading.Thread | None = None

    def call(self, method: str, path: str, body: Any = None) -> Any:
        response = self.http.request(method, path, json=body)
        if response.status_code >= 400:
            raise SeedError(f"sidecar: {method} {path} -> {response.status_code} {response.text[:300]}")
        return response.json() if response.content else None

    def enroll(self, code: str) -> None:
        answer = self.call("POST", "enroll", {"code": code, "public_key": self.public_key, "version": "demo-0.1"})
        self.http.headers["Authorization"] = f"Bearer {answer['token']}"  # kept in memory only

    def start(self) -> "FakeSidecar":
        self.thread = threading.Thread(target=self._loop, name="fake-sidecar", daemon=True)
        self.thread.start()
        return self

    def stop(self) -> None:
        self.stopped.set()
        if self.thread is not None:
            self.thread.join(10)
        self.http.close()

    def _loop(self) -> None:
        beat = 0.0
        while not self.stopped.is_set():
            try:
                if time.monotonic() >= beat:
                    self.heartbeat()
                    beat = time.monotonic() + self.BEAT
                for message in self.call("GET", f"inbox?cursor={self.cursor}&wait=0")["messages"]:
                    self.cursor = max(self.cursor, message["seq"])
                    self.handle(message)
                self.last_error = ""
            except Exception as exc:  # said once; the next round tries again
                if str(exc) != self.last_error:
                    self.log(f"{exc}")
                self.last_error = str(exc)
            self.stopped.wait(2)

    def heartbeat(self) -> None:
        reply = self.call("POST", "heartbeat", {
            "version": "demo-0.1", "health": "ok", "clock": time.time(), "runs": [],
            "runtime": {"uid": 10001, "container": True, "hostname_hash": "5f0c2e9a4b17"}})
        self.status = reply["status"]

    def handle(self, message: dict[str, Any]) -> None:
        body = message.get("body") or {}
        if message["type"] == "conformance":
            self.conformance(body)
        elif message["type"] in ("run", "chat"):
            self.work(body)

    def conformance(self, body: dict[str, Any]) -> None:
        """K1, as the real sidecar runs it: the connector's own test with the credential Atrium gives it."""
        import asyncio

        from hub.connectors import build

        credential = self.call("GET", "credential")
        try:
            result = asyncio.run(build(credential["kind"], credential["config"], credential["secrets"]).test())
            ok, detail = bool(result.get("ok")), "the connector's test passed with the team's own credential"
        except Exception as exc:
            ok, detail = False, f"the connector's test failed ({exc.__class__.__name__})"
        rows = [{"id": vector["id"], "ok": ok, "detail": detail} for vector in body.get("vectors") or []]
        self.call("POST", "conformance", {"rows": rows, "built_at": body.get("built_at")})

    def work(self, run: dict[str, Any]) -> None:
        run_id, agent_id = run["run_id"], run["agent_id"]
        messages: list[dict[str, Any]] = [{"role": "user", "text": run.get("text") or "Do your standing task."}]
        outcome = "done"
        try:
            charter = self.call("GET", "charter")
            tools = {t["name"]: t.get("action_id") for t in (charter.get("tools") or {}).get("normal", [])}
            answer = self.call("POST", "model", {"run_id": run_id, "agent_id": agent_id, "messages": messages})
            reply = answer.get("text") or ""
            if answer.get("tool_calls"):
                messages.append({"role": "assistant", "text": answer.get("text") or "",
                                 "tool_calls": answer["tool_calls"], "ref": answer.get("ref")})
                for tool_call in answer["tool_calls"]:
                    action = tools.get(tool_call["name"])
                    asked = self.call("POST", "actions/request", {
                        "run_id": run_id, "agent_id": agent_id, "action_id": action, "params": tool_call["arguments"],
                        "reason": answer.get("text") or ""}) if action else {"status": "denied", "reason": "unknown"}
                    said = ("Atrium asked a person to approve it (approval " + str(asked.get("approval_id")) + ")."
                            if asked["status"] == "pending_approval" else f"{asked['status']}: {asked.get('reason')}")
                    messages.append({"role": "tool", "call_id": tool_call["id"], "text": said})
                answer = self.call("POST", "model", {"run_id": run_id, "agent_id": agent_id, "messages": messages})
                reply = answer.get("text") or reply
        except SeedError as exc:
            self.log(f"{exc}")
            outcome, reply = "failed", "The run failed."
        if run.get("correlation_id"):
            self.call("POST", "replies", {"correlation_id": run["correlation_id"], "reply": reply[:8000],
                                          "ok": outcome == "done"})
        self.call("POST", f"runs/{run_id}/end", {"outcome": outcome})


# -- the hub -----------------------------------------------------------------------------------------------------------


def start_hub(data_dir: Path, port: int, password: str, *, log: Path | None = None) -> subprocess.Popen:
    """`python -m hub serve` with the fake firewall, without Claude, with `ava` as the first administrator."""
    if port == 8710:
        raise SystemExit("use a port other than 8710")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ANTHROPIC_", "HUB_"))}
    env.update(HUB_LLM="off", HUB_SELF_PATCH="off", HUB_DEV_FAKE_DEVICES="1", HUB_FLOW_INTERVAL="5",
               HUB_ADMIN_USERNAME=USERS[0][0], HUB_ADMIN_PASSWORD=password)
    out = open(log, "ab") if log else subprocess.DEVNULL  # noqa: SIM115 - handed to the child
    hub = subprocess.Popen([sys.executable, "-m", "hub", "serve", "--port", str(port), "--data-dir", str(data_dir)],
                           env=env, cwd=ROOT, stdout=out, stderr=subprocess.STDOUT if log else subprocess.DEVNULL)
    deadline = time.monotonic() + 60
    while True:
        try:
            if httpx.get(f"http://127.0.0.1:{port}/api/health", timeout=2).status_code == 200:
                return hub
        except httpx.HTTPError:
            pass
        if hub.poll() is not None or time.monotonic() > deadline:
            stop_hub(hub)
            raise SystemExit("the hub did not start")
        time.sleep(0.3)


def stop_hub(hub: subprocess.Popen) -> None:
    if hub.poll() is None:
        os.kill(hub.pid, signal.SIGTERM)
        try:
            hub.wait(15)
        except subprocess.TimeoutExpired:
            os.kill(hub.pid, signal.SIGKILL)
            hub.wait()


# -- seeding through the REST API --------------------------------------------------------------------------------------


class SeedError(RuntimeError):
    pass


class Api:
    """A signed-in session of one account."""

    def __init__(self, base: str, username: str, password: str):
        self.username = username
        self.http = httpx.Client(base_url=base, headers={"X-Hub-Request": "1"}, timeout=120)
        self.call("POST", "/api/auth/login", {"username": username, "password": password})

    def call(self, method: str, path: str, body: Any = None, ok: tuple[int, ...] = ()) -> Any:
        response = self.http.request(method, path, json=body)
        if response.status_code >= 400 and response.status_code not in ok:
            raise SeedError(f"{self.username}: {method} {path} -> {response.status_code} {response.text[:400]}")
        return response.json() if response.content else None

    def get(self, path: str) -> Any:
        return self.call("GET", path)

    def post(self, path: str, body: Any = None, ok: tuple[int, ...] = ()) -> Any:
        return self.call("POST", path, {} if body is None else body, ok)

    def put(self, path: str, body: Any) -> Any:
        return self.call("PUT", path, body)

    def patch(self, path: str, body: Any) -> Any:
        return self.call("PATCH", path, body)


def wait(what: str, check: Callable[[], Any], timeout: float = 90) -> Any:
    deadline = time.monotonic() + timeout
    while True:
        value = check()
        if value:
            return value
        if time.monotonic() > deadline:
            raise SeedError(f"timed out waiting for {what}")
        time.sleep(0.5)


def pending(api: Api, kind: str | None = None) -> list[dict[str, Any]]:
    return [a for a in api.get("/api/approvals?status=pending") if kind is None or a["kind"] == kind]


def decide(api: Api, approval: dict[str, Any], approve: bool = True, note: str | None = None) -> None:
    api.post(f"/api/approvals/{approval['id']}", {"approve": approve, "note": note})


def seed(base: str, password: str, tools: DemoTools, log: Callable[[str], None] = print) -> dict[str, Any]:
    """Fill the hub through its API; returns ids the screenshots need (tools, the firewall change, a person, ...)."""
    admin = Api(base, USERS[0][0], password)
    me = admin.get("/api/auth/me")
    user_id = (me.get("user") or me).get("id")
    admin.patch(f"/api/users/{user_id}", {"display_name": USERS[0][2], "email": email_of("ava.martens")})
    for username, role, name in USERS[1:]:
        login = next(p[0] for p in PEOPLE if p[0].startswith(username + "."))
        admin.post("/api/users", {"username": username, "password": password, "role": role, "display_name": name,
                                  "email": email_of(login), "must_change_password": False})
    second_admin = Api(base, "noah", password)
    operator = Api(base, "jonas", password)
    log("accounts: ava (admin), noah (admin), jonas (operator), lena (viewer)")

    # -- tools ---------------------------------------------------------------------------------------------------------
    imports = [("Snipe-IT", "snipeit", True), ("Keycloak", "keycloak", True), ("OpenVAS", "greenbone", False),
               ("CISO Assistant", "ciso", True), ("Grafana", "grafana", True), ("Wazuh", "wazuh", True),
               ("Edge firewall", "firewall", False)]
    ids: dict[str, str] = {}
    for name, key, spec in imports:
        body = {"source_type": "saas", "source": tools.urls[key], "name": name}
        if spec:
            body["openapi_url"] = f"{tools.urls[key]}/openapi.json"
        ids[name] = admin.post("/api/tools/import", body)["id"]
    for name, tool_id in ids.items():
        wait(f"{name} to be analysed", lambda: admin.get(f"/api/tools/{tool_id}")["status"] not in
             ("importing", "analyzing", "cloning"), 120)
    log(f"imported {len(ids)} tools")

    connections = {
        "Snipe-IT": ("snipeit", {"base_url": tools.urls["snipeit"], "read_accounts": True, "verify_tls": True},
                     {"token": SNIPEIT_TOKEN}),
        "Keycloak": ("keycloak", {"base_url": tools.urls["keycloak"], "realm": "company", "client_id": "atrium-directory",
                                  "include_groups": True}, {"client_secret": KEYCLOAK_SECRET}),
        "OpenVAS": ("openvas", {"connection_type": "tcp", "host": "127.0.0.1", "port": tools.gmp_port,
                                "username": "atrium"}, {"password": GREENBONE_PASSWORD}),
        "CISO Assistant": ("ciso_assistant", {"base_url": tools.urls["ciso"]}, {"token": CISO_TOKEN}),
        "Edge firewall": ("fake_firewall", {"device": "fw-edge-01", "base_url": tools.urls["firewall"]},
                          {"api_key": FIREWALL_KEY}),
    }
    for name, (kind, config, secrets) in connections.items():
        admin.put(f"/api/tools/{ids[name]}/connection", {"kind": kind, "config": config, "secrets": secrets})
        result = admin.post(f"/api/tools/{ids[name]}/connection/test")
        if not result.get("ok"):
            raise SeedError(f"the {name} connection test failed: {result.get('detail')}")
    log("connections saved and tested")

    # -- data flows: approve what the planner proposed, except one push to CISO Assistant (stays in Approvals) ----------
    def flow_approvals() -> list[dict[str, Any]]:
        return pending(admin, "flow")

    wait("the planner's flow proposals", lambda: len({a["payload"].get("tool_id") for a in flow_approvals()}) >= 4)
    time.sleep(2)  # the planner proposes per tool; let it finish
    keep = None
    for approval in flow_approvals():
        p = approval["payload"]
        if p.get("tool_id") == ids["CISO Assistant"] and p.get("domain") == "controls" and keep is None:
            keep = approval
            continue
        decide(admin, approval, note="Demo: approved while seeding")
    log(f"approved the proposed data flows; left one pending: {keep['title'] if keep else 'none'}")

    def run_flow(tool: str, domain: str) -> dict[str, Any]:
        flow = wait(f"the {domain} flow of {tool}", lambda: next(
            (f for f in admin.get(f"/api/flows?tool_id={ids[tool]}") if f["domain"] == domain
             and f["status"] == "enabled" and f["direction"] != "scan"), None))
        result = admin.post(f"/api/flows/{flow['id']}/run")
        if not (result.get("ok") or (result.get("flow") or {}).get("last_result", {}).get("ok")):
            log(f"  {tool} {domain}: {json.dumps(result)[:300]}")
        return flow

    run_flow("Keycloak", "people")
    run_flow("Snipe-IT", "assets")
    run_flow("Snipe-IT", "accounts")
    run_flow("Edge firewall", "network")
    log("pulled people, assets, accounts and the firewall's configuration")

    # -- assets: owners, criticality, scan scope; a scan with OpenVAS ---------------------------------------------------
    people = {p["login"]: p for p in admin.get("/api/people")["people"] if p.get("login")}
    assets = {a["name"]: a for a in admin.get("/api/assets")}
    for name, login in SERVER_OWNERS.items():
        if name in assets and login in people:
            admin.patch(f"/api/assets/{assets[name]['id']}", {"owner_person_id": people[login]["id"],
                                                               "criticality": CRITICALITY.get(name, "medium")})
    scope = [assets[n]["id"] for n in SERVER_OWNERS if n in assets]
    admin.post("/api/assets/scan-scope", {"asset_ids": scope, "in_scope": True})
    admin.post("/api/vulnerabilities/scan", {"scanner_tool_id": ids["OpenVAS"]})
    scan = wait("the scan flow", lambda: next((f for f in admin.get(f"/api/flows?tool_id={ids['OpenVAS']}")
                                               if f["direction"] == "scan"), None))

    def scanned() -> bool:
        flow = next(f for f in admin.get(f"/api/flows?tool_id={ids['OpenVAS']}") if f["id"] == scan["id"])
        if flow.get("job"):
            admin.post(f"/api/flows/{scan['id']}/run", ok=(400, 409))
            return False
        return bool(admin.get("/api/vulnerabilities"))

    wait("the scan's findings", scanned, 120)
    log(f"scan finished: {len(admin.get('/api/vulnerabilities'))} findings")
    for flow in admin.get(f"/api/flows?tool_id={ids['CISO Assistant']}"):
        if flow["status"] == "enabled":
            admin.post(f"/api/flows/{flow['id']}/run")

    # -- compliance: a CyFun 2025 self-assessment, policies, a risk ------------------------------------------------------
    frameworks = admin.get("/api/frameworks")
    fw = frameworks["default"]
    assessment = operator.post(f"/api/frameworks/{fw}/assessments", {
        "name": "CyFun 2025 self-assessment 2026", "target_level": "B",
        "scope": "Example Company NV: all offices, the data centre and the cloud services"})
    detail = admin.get(f"/api/frameworks/{fw}")
    refs = _requirement_refs(detail, "B") + _requirement_refs(detail, "I")[:14]
    owners = [people[k]["id"] for k in ("noah.willems", "jonas.peeters", "lena.claes") if k in people]
    scored = 0
    for i, ref in enumerate(refs[:48]):
        implementation = (3, 4, 2, 3, 5, 1, 3, 4)[i % 8]
        body: dict[str, Any] = {"implementation": implementation, "documentation": max(1, implementation - (i % 2))}
        if owners and i % 3 == 0:
            body["owner_person_id"] = owners[i % len(owners)]
        operator.patch(f"/api/frameworks/{fw}/assessments/{assessment['id']}/requirements/{ref}", body)
        scored += 1
    log(f"CyFun self-assessment {assessment['id']}: {scored} requirements scored")

    templates = admin.get("/api/grc/policy-templates")
    template_list = templates if isinstance(templates, list) else list(templates.values()) if isinstance(templates, dict) \
        else []
    for t in template_list[:3]:
        if isinstance(t, dict) and t.get("title"):
            admin.post("/api/grc/policies", {"title": t["title"], "category": t.get("category", "security"),
                                             "body": t.get("body", ""), "version": "1.0", "status": "approved",
                                             "owner_person_id": people.get("lena.claes", {}).get("id"),
                                             "review_due": "2027-03-31"})
    admin.post("/api/grc/risks", {"title": "Ransomware encrypts the file server and its backups", "category": "security",
                                  "likelihood": 3, "impact": 5, "treatment": "mitigate",
                                  "owner_person_id": people.get("ava.martens", {}).get("id"),
                                  "asset_ids": [assets[n]["id"] for n in ("files-01", "backup-01") if n in assets]})
    admin.post("/api/grc/risks", {"title": "Single internet uplink at the Ghent office", "category": "operational",
                                  "likelihood": 2, "impact": 3, "treatment": "accept",
                                  "owner_person_id": people.get("jonas.peeters", {}).get("id")})

    # -- network: device changes on, a maintenance window, an operator's proposal waiting for a second admin -----------
    fw_id = ids["Edge firewall"]
    admin.patch("/api/settings/guardrails", {"device_changes": True})
    admin.post("/api/network/maintenance-windows", _window())
    admin.post(f"/api/network/devices/{fw_id}/backups", ok=(400,))
    seg = admin.get(f"/api/segmentation?firewall={fw_id}")
    zones = {str(z.get("name")).upper(): z["id"] for z in seg.get("zones", [])}
    request = {"firewall": fw_id, "op": "allow", "source_zone": zones.get("SERVERS"), "target_zone": zones.get("MGMT"),
               "services": [{"proto": "tcp", "ports": "6281"}], "log": True, "description": "Backups to backup-01",
               "justification": "The servers send their nightly Hyper Backup jobs to backup-01 in the management "
                                "network (CHG-2026-114)."}
    change = operator.post("/api/segmentation/changes", request)
    log(f"firewall change proposed by jonas: {change['change']['id']}")

    # -- the Patch Agent's patches, agent teams, an extension pack, operator activity -------------------------------
    for approval in pending(admin, "patch"):  # Wazuh's stay in Approvals
        if approval["payload"].get("tool_id") != ids["Wazuh"]:
            decide(admin, approval, note="Demo: approved while seeding")
    for approval in pending(admin, "agent_team"):  # two teams; the other proposals stay in Approvals
        if approval["payload"].get("tool_id") in (ids["Snipe-IT"], ids["OpenVAS"]):
            decide(second_admin, approval, note="Demo: approved while seeding")
    for approval in pending(admin, "extension"):
        decide(admin, approval, note="Demo: approved while seeding")
    if any(d.get("key") == "alerts" for d in admin.get("/api/x")):
        for title, severity, status, rule, host, user, age in ALERTS:
            operator.post("/api/x/alerts", {"fields": {
                "title": title, "severity": severity, "status": status, "rule": rule, "host": host, "user": user,
                "detected": iso(time.time() - age * 3600)}})
    admin.post("/api/commands", {"command": "uptime", "target": "local"}, ok=(400, 403, 409))

    # -- round 4: AI providers and agents on them, dashboards, a subsidiary inside CISO Assistant -------------------
    models = seed_models(admin, tools, ids, log)
    operator.post("/api/chat", {"text": "Which leavers still have access?"}, ok=(400, 409, 429, 503))
    if models.get("triage"):
        admin.post(f"/api/agents/{models['triage']}/chat", {"text": "Which findings are past their deadline?"},
                   ok=(400, 409, 429, 503))
    boards = seed_dashboards(admin, ids, log)
    team = seed_subsidiary(admin, second_admin, operator, tools, ids, base, log)
    admin.post("/api/integration/evaluate")
    leaver = people.get(LEAVER)
    return {"tools": ids, "firewall": fw_id, "change_id": change["change"]["id"], "framework": fw,
            "assessment_id": assessment["id"], "person_id": (people.get("emma.janssens") or {}).get("id"),
            "leaver_id": leaver["id"] if leaver else None, **models, **boards, **team}


def seed_models(admin: Api, tools: DemoTools, ids: dict[str, str], log: Callable[[str], None]) -> dict[str, Any]:
    """The two model servers as AI providers (the cloud one with its key, prices and supplier record), the suite's
    model choice - the GPU server by default, the cloud for code changes and as the fallback, the OpenVAS team
    local-only - two agents' own choices and the Hub Supervisor's settings."""
    cloud, cloud_name, cloud_models = MODEL_CLOUD
    local, local_name, local_models = MODEL_LOCAL
    admin.post("/api/llm/providers", {"id": cloud, "name": cloud_name, "base_url": f"{tools.urls['model_cloud']}/v1",
                                      "default_model": cloud_models[0], "api_key": MODEL_CLOUD_KEY,
                                      "location": "third_party"})  # a cloud service: it runs on loopback here
    admin.post("/api/llm/providers", {"id": local, "name": local_name, "base_url": f"{tools.urls['model_local']}/v1",
                                      "default_model": local_models[0]})
    for provider, models in ((cloud, cloud_models), (local, local_models)):
        result = admin.post(f"/api/llm/providers/{provider}/test")
        if not result.get("ok"):
            raise SeedError(f"the {provider} model server test failed: {result.get('detail')}")
        for model in models[:2]:  # "Check tools and JSON": two tiny calls each
            admin.post(f"/api/llm/providers/{provider}/probe", {"model": model})
    admin.patch(f"/api/llm/providers/{cloud}", {"supplier": {
        "owner": "Lena Claes", "reviewed_at": time.time() - 16 * DAY,
        "notes": "Data processing agreement signed; prompts are processed in the EU and not used for training."}})
    small = {k: round(v / 6, 3) for k, v in CLOUD_PRICE.items()}
    admin.put("/api/llm/prices", {"overrides": {f"{cloud}:{cloud_models[0]}": CLOUD_PRICE,
                                                f"{cloud}:{cloud_models[1]}": small}})
    version = admin.get("/api/llm/selection")["selection"]["version"]
    admin.patch("/api/llm/selection", {
        "version": version, "default": {"provider": local, "model": local_models[0]},
        "purposes": {"code": {"provider": cloud, "model": cloud_models[0]}}, "fallback": [cloud],
        "teams": {ids["OpenVAS"]: {"provider": local, "model": local_models[1], "local_only": True}}})

    agents = admin.get("/api/agents")
    triage = next((a["id"] for a in agents if a.get("team") == ids["OpenVAS"] and "triage" in a["id"]), None)
    reconciler = next((a["id"] for a in agents if a.get("team") == ids["Snipe-IT"] and "reconciler" in a["id"]), None)
    if reconciler:
        view = admin.get(f"/api/agents/{reconciler}/settings")
        admin.patch(f"/api/agents/{reconciler}/settings", {"version": view["version"],
                                                           "llm": {"provider": cloud, "model": cloud_models[1]}})
    view = admin.get("/api/agents/supervisor/settings")
    admin.patch("/api/agents/supervisor/settings", {"version": view["version"], "llm": {"provider": cloud,
                                                                                         "model": cloud_models[0]},
                                                    "config": {
        "extra_instructions": "Name the tool every fact comes from. When a change waits in Approvals, say who may "
                              "approve it.",
        "budget": {"daily_tokens": 2_000_000, "daily_cost_usd": 5, "monthly_cost_usd": 60, "hard_stop": True},
        "rate": {"calls_per_minute": 20, "runs_per_hour": 120},
        "memory": {"mode": "persisted", "max_turns": 40, "retention_days": 30},
        "escalation": {"tool": True, "rules": ["Someone asks to switch a guardrail off",
                                               "A data flow fails three times in a row"],
                       "failed_runs": 3, "pause_schedule": True, "max_per_day": 5}}})
    log(f"AI providers {cloud} (cloud) and {local} (self-hosted); agents on both; the Hub Supervisor configured")
    return {"triage": triage, "reconciler": reconciler}


def _widget(n: int, kind: str, x: int, y: int, w: int, h: int, config: dict[str, Any],
            title: str | None = None) -> dict[str, Any]:
    return {"id": f"w_demo{n:04d}", "type": kind, "x": x, "y": y, "w": w, "h": h, "title": title, "config": config}


def seed_dashboards(admin: Api, ids: dict[str, str], log: Callable[[str], None]) -> dict[str, Any]:
    """A shared "Security desk" of hub numbers and tool widgets (OpenVAS findings, Snipe-IT assets, Wazuh alerts, the
    firewall) that an administrator arranged and published, and ava's own "Settings & AI" from its template."""
    openvas, snipeit = (f"tool:{ids[n]}" for n in ("OpenVAS", "Snipe-IT"))
    still_open = [{"field": "status", "op": "in", "value": ["open", "in_progress"]}]
    widgets = [
        _widget(1, "metric", 0, 0, 3, 1, {"metric": "vulnerabilities_open"}),
        _widget(2, "metric", 3, 0, 3, 1, {"metric": "vulnerabilities_overdue"}),
        _widget(3, "metric", 6, 0, 3, 1, {"metric": "approvals_pending"}),
        _widget(4, "metric", 9, 0, 3, 1, {"metric": "llm_spend_today"}),
        _widget(5, "domain_count", 0, 1, 4, 4, {"domain": "vulnerabilities", "source": openvas, "filters": still_open,
                                                "group_by": "severity", "view": "bars"}, "OpenVAS: open findings"),
        _widget(6, "vuln_sla", 4, 1, 4, 4, {"source": openvas}, "OpenVAS: deadlines"),
        _widget(7, "tool_overview", 8, 1, 4, 4, {"tool_id": ids["Snipe-IT"]}, "Snipe-IT"),
        _widget(8, "domain_list", 0, 5, 6, 4, {"domain": "vulnerabilities", "source": openvas, "filters": still_open,
                                               "sort": "severity", "order": "desc", "limit": 8,
                                               "columns": ["title", "severity", "host", "due_at"]},
                "OpenVAS: worst open findings"),
        _widget(9, "domain_count", 6, 5, 3, 4, {"domain": "assets", "source": snipeit, "filters": [],
                                                "group_by": "type", "view": "bars"}, "Snipe-IT assets"),
        _widget(10, "network_overview", 0, 9, 6, 3, {"tools": [ids["Edge firewall"]]}, "Edge firewall"),
        _widget(11, "approvals_queue", 6, 9, 6, 3, {"kinds": [], "limit": 6}),
    ]
    if any(d.get("key") == "alerts" for d in admin.get("/api/x")):
        widgets.append(_widget(12, "domain_count", 9, 5, 3, 4, {"domain": "x:alerts", "source": "all", "filters": [],
                                                                "group_by": "severity", "view": "bars"},
                               "Wazuh alerts"))
    made = admin.post("/api/dashboards/shared", {"title": "Security desk", "icon": "shield",
                                                 "description": "Findings, deadlines, assets and alerts from the tools."})
    admin.put(f"/api/dashboards/shared/{made['id']}", {"title": made["title"], "icon": made["icon"],
                                                      "description": made["description"], "widgets": widgets,
                                                      "base_version": made["version"]})
    personal = admin.post("/api/dashboards/mine", {"title": "Settings & AI", "icon": "sliders",
                                                   "from": "template:settings_ai"})
    log(f"dashboards: shared Security desk ({len(widgets)} widgets), ava's Settings & AI")
    return {"dashboard": made["id"], "my_dashboard": personal["id"]}


def seed_subsidiary(admin: Api, second_admin: Api, operator: Api, tools: DemoTools, ids: dict[str, str], base: str,
                    log: Callable[[str], None]) -> dict[str, Any]:
    """An API-only subsidiary of CISO Assistant (docs/SUBSIDIARIES.md): jonas asks for the team, ava switches
    subsidiaries on and enters the team's read-only credential and an enrollment, the scripted sidecar enrolls and
    passes K1, noah approves the charter (never the person who asked), jonas gives the clerk a task - and the change
    the clerk asks for waits in Approvals for someone other than jonas."""
    tool = ids["CISO Assistant"]
    admin.patch("/api/settings/guardrails", {"allow_subsidiaries": True})
    operator.post(f"/api/tools/{tool}/subsidiary", {"mode": "sidecar_only", "designer": "templates",
                                                     "goals": TEAM_GOALS})
    admin.put(f"/api/subsidiaries/{tool}/credential", {"secrets": {"token": CISO_TEAM_TOKEN}})
    sidecar = FakeSidecar(base, lambda line: log(f"  sidecar: {line}"))
    sidecar.enroll(admin.post(f"/api/subsidiaries/{tool}/enrollment")["code"])
    tools.sidecar = sidecar.start()
    charter = wait("the charter approval", lambda: next(iter(pending(admin, "subsidiary_charter")), None), 60)
    decide(second_admin, charter, note="Demo: approved while seeding")
    wait("the subsidiary to be active", lambda: admin.get(f"/api/subsidiaries/{tool}")["status"] == "active", 60)
    staff = admin.get(f"/api/subsidiaries/{tool}")["charter"]["staff"]
    clerk = next(a for a, scope in staff.items() if "records.controls.upsert" in scope["actions"])
    operator.post(f"/api/subsidiaries/{tool}/tasks", {"agent_id": clerk, "text": TEAM_TASK})
    change = wait("the team's change request", lambda: next(iter(pending(admin, "subsidiary_action")), None), 90)
    log(f"subsidiary of CISO Assistant active, its sidecar enrolled; waiting for approval: {change['title']}")
    return {"subsidiary_tool": tool, "subsidiary_approval": change["id"], "subsidiary_clerk": clerk}


def _requirement_refs(detail: dict[str, Any], level: str) -> list[str]:
    """Refs of the catalog's requirements of one level ("B", "I" or "E"), in catalog order."""
    refs: list[str] = []
    for function in detail.get("tree") or []:
        for category in function.get("categories") or []:
            for subcategory in category.get("subcategories") or []:
                refs += [r["ref_id"] for r in subcategory.get("requirements") or [] if r.get("level") == level]
    return refs


def _window() -> dict[str, Any]:
    return {"name": "Nightly change window", "recurrence": "weekly", "days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
            "start_time": "22:00", "end_time": "23:59", "timezone": "Europe/Brussels", "enabled": True}


# -- running it by hand ------------------------------------------------------------------------------------------------


def _interrupt(signum: int, frame: Any) -> None:
    raise KeyboardInterrupt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8790, help="the hub's port (never 8710; default 8790)")
    parser.add_argument("--data-dir", help="the hub's data directory (default: a new temporary one, removed at exit)")
    parser.add_argument("--password", default="demo-password-2026", help="the password of every demo account")
    args = parser.parse_args()
    data_dir = Path(args.data_dir) if args.data_dir else Path(tempfile.mkdtemp(prefix="atrium-demo-"))
    signal.signal(signal.SIGTERM, _interrupt)  # `kill <pid>` cleans up like Ctrl+C: the hub is stopped too
    tools = DemoTools(args.port + 1).start()
    hub = start_hub(data_dir, args.port, args.password)
    print(f"demo pid {os.getpid()}, hub pid {hub.pid} on http://127.0.0.1:{args.port}, data {data_dir}", flush=True)
    try:
        seed(f"http://127.0.0.1:{args.port}", args.password, tools)
        print(f"Ready: sign in as ava / noah (admin), jonas (operator) or lena (viewer) with '{args.password}'. "
              "Ctrl+C stops.", flush=True)
        while hub.poll() is None:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        tools.stop()  # the sidecar first: it would only see a hub that is gone
        stop_hub(hub)
        if not args.data_dir:
            shutil.rmtree(data_dir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
