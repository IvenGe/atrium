"""The MikroTik RouterOS connector against a fake RouterOS REST API (httpx.MockTransport, no network). The fake follows
the RouterOS 7.26 manual: every value a string, PUT = add (201 + record, ``place-before``), PATCH = set, DELETE = remove
(204, 404 for an unknown id), group policies (``api`` + ``rest-api``, ``read``, ``write``, ``ftp``, ``test``) with the
documented errors, ``/export`` + ``/file/read`` in chunks, a router clock in local time and a scheduler that runs the
undo job's script when its start time comes (only the script forms the connector writes are understood)."""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest

from hub.connectors.base import normalize
from hub.connectors.mikrotik import MikrotikConnector, Router, parse_clock
from hub.connectors.netmodel import (Backup, ChangeError, inverse_ops, ops_applied, ops_reverted, parse_ops)
from hub.integration.connections import clean_config

PASSWORD = "mt-pass-7f3e9a1c5b2d"
BASE = "https://gw.example.net"
WG_KEY = "wg-private-key-GDcp0fMa3Sx2bNq8Y1uE5vKk="
START = datetime(2026, 10, 9, 10, 0, 0, tzinfo=timezone.utc).timestamp()
FULL = "local,telnet,ssh,ftp,reboot,read,write,policy,test,winbox,password,web,sniff,sensitive,api,romon,rest-api"
DO_REMOVE = re.compile(r'^:do \{ (/ip|/ipv6) firewall filter remove \[find comment="([^"\\$?\[\]{};]*)"\] \} '
                       r'on-error=\{\}$')
DO_SET = re.compile(r"^:do \{ (/ip|/ipv6) firewall filter set (\*[0-9A-F]+) disabled=(yes|no) \} on-error=\{\}$")
SELF_REMOVE = re.compile(r'^/system scheduler remove \[find name="(atrium-rb-[0-9a-f]{12})"\]$')


def run(coro):
    return asyncio.run(coro)


def rule(rid: str, chain: str, action: str, comment: str = "", **fields: str) -> dict[str, Any]:
    row = {".id": rid, "chain": chain, "action": action, "bytes": "1000", "packets": "10", "disabled": "false",
           "dynamic": "false", "invalid": "false", "log": "false", "log-prefix": ""}
    if comment:
        row["comment"] = comment
    row.update(fields)
    return row


class FakeRouterOS:
    """Just enough of RouterOS's REST API for the connector."""

    MENUS = {"/interface": "interfaces", "/interface/vlan": "vlans", "/ip/address": "addresses",
             "/ipv6/address": "addresses6", "/interface/list": "lists", "/interface/list/member": "members",
             "/ip/firewall/filter": "filter", "/ipv6/firewall/filter": "filter6",
             "/ip/firewall/address-list": "address_lists", "/ipv6/firewall/address-list": "address_lists6",
             "/system/scheduler": "scheduler", "/user": "users", "/user/group": "groups"}

    def __init__(self) -> None:
        self.now = [START]  # UTC epoch seconds (the hub's clock as well)
        self.gmt = 7200  # Europe/Brussels in summer
        self.version = "7.16.2 (stable)"
        self.date_style = "iso"
        self.calls: list[tuple[str, str, Any]] = []
        self.unreachable = self.tls_untrusted = self.no_certificate = self.rest_off = False
        self.lock_on_write = self.locked = False
        self.fail_add = False
        self.ignore_scheduler = False  # an add that does not schedule (next-run stays empty)
        self.groups_unreadable = False
        self.script_errors: list[str] = []
        self.ran: list[str] = []
        self.next_id = 0x40
        self.passwords = {"atrium": PASSWORD, "reader": PASSWORD, "noapi": PASSWORD, "admin": PASSWORD}
        self.groups = [{".id": "*1", "name": "atrium-rw", "policy": "read,write,api,rest-api,ftp,test,!local,!telnet,"
                                                                    "!ssh,!reboot,!policy,!winbox,!password,!web,"
                                                                    "!sniff,!sensitive,!romon"},
                       {".id": "*2", "name": "atrium-ro", "policy": "read,api,rest-api,!write,!ftp,!test"},
                       {".id": "*3", "name": "rest-only", "policy": "read,rest-api"},
                       {".id": "*4", "name": "full", "policy": FULL}]
        self.users = [{".id": "*1", "name": "atrium", "group": "atrium-rw", "address": "", "disabled": "false"},
                      {".id": "*2", "name": "reader", "group": "atrium-ro", "address": "", "disabled": "false"},
                      {".id": "*3", "name": "noapi", "group": "rest-only", "address": "", "disabled": "false"},
                      {".id": "*4", "name": "admin", "group": "full", "address": "", "disabled": "false"}]
        self.interfaces = [
            {".id": "*1", "name": "ether1", "type": "ether", "running": "true", "disabled": "false", "comment": "uplink"},
            *({".id": f"*{n}", "name": f"ether{n}", "type": "ether", "running": "true", "disabled": "false"}
              for n in range(2, 6)),
            {".id": "*A", "name": "bridge", "type": "bridge", "running": "true", "disabled": "false"},
            {".id": "*B", "name": "vlan20", "type": "vlan", "running": "true", "disabled": "false", "comment": "SERVERS"},
            {".id": "*C", "name": "vlan30", "type": "vlan", "running": "true", "disabled": "false", "comment": "GUEST"},
            {".id": "*D", "name": "vlan99", "type": "vlan", "running": "true", "disabled": "false", "comment": "MGMT"},
            {".id": "*E", "name": "wg0", "type": "wg", "running": "false", "disabled": "true"},
        ]
        self.vlans = [{".id": f"*{i}", "name": f"vlan{v}", "vlan-id": str(v), "interface": "bridge", "disabled": "false",
                       "running": "true"} for i, v in ((1, 20), (2, 30), (3, 99))]
        self.addresses = [
            {".id": "*1", "address": "203.0.113.7/24", "network": "203.0.113.0", "interface": "ether1",
             "actual-interface": "ether1", "disabled": "false", "dynamic": "true", "invalid": "false"},
            {".id": "*2", "address": "10.0.10.1/24", "network": "10.0.10.0", "interface": "bridge",
             "actual-interface": "bridge", "disabled": "false", "dynamic": "false", "invalid": "false"},
            {".id": "*3", "address": "10.0.20.1/24", "network": "10.0.20.0", "interface": "vlan20",
             "actual-interface": "vlan20", "disabled": "false", "dynamic": "false", "invalid": "false"},
            {".id": "*4", "address": "10.0.30.1/24", "network": "10.0.30.0", "interface": "vlan30",
             "actual-interface": "vlan30", "disabled": "false", "dynamic": "false", "invalid": "false"},
            {".id": "*5", "address": "10.0.99.1/24", "network": "10.0.99.0", "interface": "vlan99",
             "actual-interface": "vlan99", "disabled": "false", "dynamic": "false", "invalid": "false"},
        ]
        self.addresses6 = [
            {".id": "*1", "address": "fe80::1/64", "interface": "bridge", "disabled": "false", "dynamic": "true",
             "invalid": "false", "link-local": "true"},
            {".id": "*2", "address": "2001:db8:10::1/64", "interface": "bridge", "disabled": "false", "dynamic": "false",
             "invalid": "false"},
            {".id": "*3", "address": "2001:db8:20::1/64", "interface": "vlan20", "disabled": "false", "dynamic": "false",
             "invalid": "false"},
        ]
        self.lists = [{".id": "*2000010", "name": "all", "builtin": "true", "dynamic": "false"},
                      {".id": "*2000011", "name": "none", "builtin": "true", "dynamic": "false"},
                      {".id": "*1", "name": "WAN", "include": "", "exclude": "", "builtin": "false", "dynamic": "false"},
                      {".id": "*2", "name": "LAN", "include": "SERVERS", "exclude": "", "builtin": "false",
                       "dynamic": "false"},
                      {".id": "*3", "name": "SERVERS", "include": "", "exclude": "", "builtin": "false",
                       "dynamic": "false"}]
        self.members = [{".id": "*1", "list": "WAN", "interface": "ether1", "disabled": "false", "dynamic": "false"},
                        {".id": "*2", "list": "LAN", "interface": "bridge", "disabled": "false", "dynamic": "false"},
                        {".id": "*3", "list": "LAN", "interface": "vlan30", "disabled": "false", "dynamic": "false"},
                        {".id": "*4", "list": "LAN", "interface": "vlan99", "disabled": "false", "dynamic": "false"},
                        {".id": "*5", "list": "SERVERS", "interface": "vlan20", "disabled": "false", "dynamic": "false"}]
        self.address_lists = [
            {".id": "*1", "list": "MGMT", "address": "10.0.99.0/24", "disabled": "false", "dynamic": "false"},
            {".id": "*2", "list": "RFC1918", "address": "10.0.0.0/8", "disabled": "false", "dynamic": "false"},
            {".id": "*3", "list": "RFC1918", "address": "172.16.0.0/12", "disabled": "false", "dynamic": "false"},
            {".id": "*4", "list": "RFC1918", "address": "192.168.0.0/16", "disabled": "false", "dynamic": "false"},
            {".id": "*5", "list": "scanners", "address": "198.51.100.9", "disabled": "false", "dynamic": "true",
             "timeout": "23h59m50s"},
            {".id": "*6", "list": "updates", "address": "updates.example.net", "disabled": "false",
             "dynamic": "false"},
            {".id": "*7", "list": "ADMINS", "address": "10.0.10.5-10.0.10.6", "disabled": "false", "dynamic": "false"},
        ]
        self.address_lists6: list[dict[str, Any]] = []
        self.filter = [
            rule("*1", "forward", "passthrough", "special dummy rule to show fasttrack counters", dynamic="true"),
            rule("*2", "input", "accept", "defconf: accept established,related,untracked",
                 **{"connection-state": "established,related,untracked"}),
            rule("*3", "input", "drop", "defconf: drop invalid", **{"connection-state": "invalid"}),
            rule("*4", "input", "accept", "defconf: accept ICMP", protocol="icmp"),
            rule("*5", "input", "accept", "defconf: accept to local loopback (for CAPsMAN)", **{"dst-address": "127.0.0.1"}),
            rule("*6", "input", "accept", "REST from management", protocol="tcp", **{"dst-port": "443",
                 "src-address-list": "MGMT", "in-interface": "vlan99"}),
            rule("*7", "input", "drop", "defconf: drop all not coming from LAN", **{"in-interface-list": "!LAN"}),
            rule("*8", "forward", "accept", "defconf: accept in ipsec policy", **{"ipsec-policy": "in,ipsec"}),
            rule("*9", "forward", "fasttrack-connection", "defconf: fasttrack",
                 **{"connection-state": "established,related", "hw-offload": "true"}),
            rule("*A", "forward", "accept", "defconf: accept established,related, untracked",
                 **{"connection-state": "established,related,untracked"}),
            rule("*B", "forward", "drop", "defconf: drop invalid", **{"connection-state": "invalid"}),
            rule("*C", "forward", "drop", "defconf: drop all from WAN not DSTNATed",
                 **{"connection-state": "new", "connection-nat-state": "!dstnat", "in-interface-list": "WAN"}),
            rule("*D", "forward", "accept", "servers to internet", **{"in-interface": "vlan20",
                                                                      "out-interface-list": "WAN"}),
            rule("*E", "forward", "accept", "Users to web <b>app</b>", protocol="tcp", log="true",
                 **{"src-address": "10.0.10.0/24", "dst-address": "10.0.20.10", "dst-port": "443,8443",
                    "in-interface-list": "LAN", "packets": "15320"}),
            rule("*F", "forward", "jump", "guest rules", **{"jump-target": "guest", "in-interface": "vlan30"}),
            rule("*10", "guest", "accept", "guest to internet", **{"dst-address-list": "!RFC1918"}),
            rule("*11", "guest", "drop", "guest isolation"),
            rule("*12", "unused", "accept", "orphan chain"),
            rule("*13", "forward", "accept", "old guest access", disabled="true",
                 **{"src-address": "10.0.30.0/24", "dst-address": "10.0.20.0/24"}),
            rule("*14", "forward", "accept", "admins anywhere", **{"src-address-list": "ADMINS"}),
        ]
        self.filter6 = [
            rule("*1", "input", "accept", "defconf: accept ICMPv6", protocol="icmpv6"),
            rule("*2", "forward", "accept", "ssh to servers", protocol="tcp",
                 **{"src-address": "2001:db8:10::/64", "dst-address": "2001:db8:20::/64", "dst-port": "22"}),
            rule("*3", "forward", "drop", "defconf: drop everything else not coming from LAN",
                 **{"in-interface-list": "!LAN"}),
        ]
        self.scheduler: list[dict[str, Any]] = [
            {".id": "*1", "name": "nightly-script", "start-date": "2026-01-01", "start-time": "03:00:00",
             "interval": "1d", "on-event": f"/tool fetch password={PASSWORD}-other", "policy": "read,write",
             "disabled": "false", "owner": "admin", "run-count": "5", "next-run": "2026-10-10 03:00:00"}]
        self.files: dict[str, bytes] = {}

    # -- device behaviour ------------------------------------------------------------------

    def local(self) -> datetime:
        return datetime.fromtimestamp(self.now[0] + self.gmt, tz=timezone.utc).replace(tzinfo=None)

    def tick(self) -> None:
        for job in list(self.scheduler):
            start = job.get("_start")
            if start is None or job.get("_ran") or truthy(job.get("disabled")) or self.local() < start:
                continue
            job["_ran"] = True
            job["next-run"] = ""
            self.run_script(job["on-event"])

    def run_script(self, script: str) -> None:
        for line in script.split("\n"):
            if m := DO_REMOVE.match(line):
                table = self.filter if m.group(1) == "/ip" else self.filter6
                table[:] = [r for r in table if r.get("comment") != m.group(2)]
            elif m := DO_SET.match(line):
                table = self.filter if m.group(1) == "/ip" else self.filter6
                found = next((r for r in table if r[".id"] == m.group(2)), None)
                if found:
                    found["disabled"] = "true" if m.group(3) == "yes" else "false"
            elif m := SELF_REMOVE.match(line):
                self.scheduler[:] = [j for j in self.scheduler if j["name"] != m.group(1)]
            else:
                self.script_errors.append(line)
                return
        self.ran.append(script)
        self.locked = False

    # -- HTTP ------------------------------------------------------------------------------

    @staticmethod
    def error(code: int, detail: str) -> httpx.Response:
        message = {400: "Bad Request", 404: "Not Found", 500: "Internal Server Error"}.get(code, "Error")
        return httpx.Response(code, json={"detail": detail, "error": code, "message": message})

    def policies(self, user: str) -> set[str]:
        group = next(u["group"] for u in self.users if u["name"] == user)
        policy = next(g["policy"] for g in self.groups if g["name"] == group)
        return {p for p in policy.split(",") if not p.startswith("!")}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.tick()
        if self.unreachable or self.locked:
            raise httpx.ConnectTimeout("timed out", request=request)
        if self.tls_untrusted:
            raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed "
                                     "certificate in certificate chain (_ssl.c:1006)", request=request)
        if self.no_certificate:
            raise httpx.ConnectError("[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure "
                                     "(_ssl.c:1006)", request=request)
        if self.rest_off:
            return httpx.Response(403, html="<html><body>Forbidden</body></html>")
        raw_path = request.url.raw_path.decode()
        assert "%2A" not in raw_path.upper(), raw_path  # RouterOS: "no such command prefix"
        user, _, password = base64.b64decode(request.headers["Authorization"].split()[1]).decode().partition(":")
        if self.passwords.get(user) != password or "rest-api" not in self.policies(user):
            return httpx.Response(401, json={"error": 401, "message": "Unauthorized"})
        policies = self.policies(user)
        if "api" not in policies:
            return self.error(500, "std failure: not allowed (9)")
        if request.method != "GET" and request.headers.get("content-type") != "application/json" and request.content:
            return httpx.Response(415)
        path = request.url.path[len("/rest"):]
        body = json.loads(request.content) if request.content else None
        self.calls.append((request.method, path, body))
        need = {"GET": {"read"}, "PUT": {"write"}, "PATCH": {"write"}, "DELETE": {"write"}}.get(request.method, set())
        if path == "/export":
            need = {"ftp"}
        elif path == "/file/read":
            need = {"ftp", "test"}
        elif path.startswith("/file/"):
            need = {"ftp"}
        if not need <= policies or (path == "/user/group" and self.groups_unreadable):
            return self.error(500, "not enough permissions (9)")
        answer = self.route(request.method, path, dict(request.url.params), body)
        if isinstance(answer, httpx.Response):
            return answer
        if request.method in ("PATCH", "PUT", "DELETE") and "/firewall/filter" in path and self.lock_on_write:
            self.locked = True
        if answer is None:
            return httpx.Response(204)
        return httpx.Response(201 if request.method == "PUT" else 200, json=answer)

    def menu(self, path: str) -> tuple[list[dict[str, Any]] | None, str | None]:
        if path in self.MENUS:
            return getattr(self, self.MENUS[path]), None
        parent, _, item = path.rpartition("/")
        if parent in self.MENUS:
            return getattr(self, self.MENUS[parent]), item
        return None, None

    @staticmethod
    def text(value: Any) -> str:
        """Replies encode every value as a string; requests may send JSON types ("disabled": true)."""
        return ("true" if value else "false") if isinstance(value, bool) else str(value)

    @staticmethod
    def public(row: dict[str, Any], proplist: str | None = None) -> dict[str, Any]:
        out = {k: v for k, v in row.items() if not k.startswith("_")}
        if proplist:
            keys = set(proplist.split(",")) | {".id"}
            out = {k: v for k, v in out.items() if k in keys}
        return out

    def route(self, method: str, path: str, params: dict[str, str], body: Any) -> Any:
        local = self.local()
        if method == "GET" and path == "/system/resource":
            return {"uptime": "3d4h", "version": self.version, "build-time": "2026-09-01 10:00:00",
                    "board-name": "RB5009UG+S+", "architecture-name": "arm64", "cpu-load": "3",
                    "free-memory": "800000000", "platform": "MikroTik"}
        if method == "GET" and path == "/system/identity":
            return {"name": "edge-gw"}
        if method == "GET" and path == "/system/routerboard":
            return {"routerboard": "true", "model": "RB5009UG+S+", "serial-number": "HE10ABC123"}
        if method == "GET" and path == "/system/clock":
            date = local.strftime("%Y-%m-%d") if self.date_style == "iso" else local.strftime("%b/%d/%Y").lower()
            return {"time": local.strftime("%H:%M:%S"), "date": date, "time-zone-name": "Europe/Brussels",
                    "gmt-offset": "+02:00", "dst-active": "true", "time-zone-autodetect": "false"}
        if method == "POST" and path == "/export":
            text = self.export(sensitive="show-sensitive" in (body or {}))
            self.files[f"{body['file']}.rsc"] = text.encode()
            return []
        if method == "POST" and path == "/file/read":
            data = self.files.get(body["file"])
            if data is None:
                return self.error(400, "no such item")
            offset, size = int(body["offset"]), int(body["chunk-size"])
            return [{"data": data[offset:offset + size].decode()}]
        if path.startswith("/file/"):
            name = path[len("/file/"):]
            if method == "DELETE" and name in self.files:
                del self.files[name]
                return None
            return self.error(404, "no such item")
        rows, item = self.menu(path)
        if rows is None:
            return self.error(400, f"no such command or directory ({path.rsplit('/', 1)[-1]})")
        if method == "GET":
            if item is not None:
                found = next((r for r in rows if r.get(".id") == item), None)
                return self.public(found) if found else self.error(404, "no such item")
            matches = [r for r in rows if all(str(r.get(k)) == v for k, v in params.items() if k != ".proplist")]
            return [self.public(r, params.get(".proplist")) for r in matches]
        if method == "PUT" and item is None:
            return self.add(path, rows, dict(body))
        found = next((r for r in rows if r.get(".id") == item), None)
        if found is None:
            return self.error(404, "no such item")
        if method == "PATCH":
            found.update({k: self.text(v) for k, v in body.items()})
            return self.public(found)
        if method == "DELETE":
            rows.remove(found)
            return None
        return self.error(400, "no such command")

    def add(self, path: str, rows: list[dict[str, Any]], body: dict[str, Any]) -> Any:
        if path == "/system/scheduler":
            date, clock = body["start-date"], body["start-time"]
            fmt = "%Y-%m-%d" if self.date_style == "iso" else "%b/%d/%Y"
            start = datetime.strptime(f"{date.title() if self.date_style != 'iso' else date} {clock}", f"{fmt} %H:%M:%S")
            self.next_id += 1
            job = {".id": f"*{self.next_id:X}", **{k: str(v) for k, v in body.items()}, "disabled": "false",
                   "owner": "atrium", "run-count": "0",
                   "next-run": "" if self.ignore_scheduler else f"{start:%Y-%m-%d %H:%M:%S}",
                   "_start": None if self.ignore_scheduler else start}
            rows.append(job)
            return self.public(job)
        if self.fail_add:
            return self.error(400, "failure: invalid value for argument dst-port")
        place = body.pop("place-before", None)
        self.next_id += 1
        row = rule(f"*{self.next_id:X}", body.pop("chain"), body.pop("action"), bytes="0", packets="0",
                   **{k: self.text(v) for k, v in body.items()})
        if place:
            index = next(i for i, r in enumerate(rows) if r[".id"] == place)
            rows.insert(index, row)
        else:
            rows.append(row)
        return self.public(row)

    def export(self, sensitive: bool = False) -> str:
        lines = [f"# {self.local():%Y-%m-%d %H:%M:%S} by RouterOS {self.version.split()[0]}",
                 "# software id = ABCD-1234", "/interface bridge", "add name=bridge",
                 "/interface wireguard",
                 "add listen-port=13231 name=wg0" + (f" private-key=\"{WG_KEY}\"" if sensitive else ""),
                 "/ip firewall filter"]
        for row in self.filter:
            if row.get("dynamic") != "true":
                lines.append("add " + " ".join(f"{k}={v}" for k, v in row.items()
                                               if k not in (".id", "bytes", "packets", "dynamic", "invalid")))
        lines += [f"# padding line {n:05d} " + "x" * 60 for n in range(600)]  # > 32 KiB: read in several chunks
        return "\n".join(lines) + "\n"

    # -- helpers for tests -------------------------------------------------------------------

    def row(self, rid: str, table: str = "filter") -> dict[str, Any]:
        return next(r for r in getattr(self, table) if r[".id"] == rid)

    def jobs(self) -> list[dict[str, Any]]:
        return [j for j in self.scheduler if j["name"].startswith("atrium-rb-")]

    def methods(self, method: str, fragment: str = "") -> list[str]:
        return [p for m, p, _ in self.calls if m == method and fragment in p]


def truthy(value: Any) -> bool:
    return str(value).lower() in ("true", "yes")


@pytest.fixture
def fake(monkeypatch):
    device = FakeRouterOS()

    async def sleep(seconds: float) -> None:
        device.now[0] += seconds

    monkeypatch.setattr(MikrotikConnector, "clock", staticmethod(lambda: device.now[0]))
    monkeypatch.setattr(MikrotikConnector, "sleep", staticmethod(sleep))
    return device


def connector(fake: FakeRouterOS, user: str = "atrium", password: str = PASSWORD, **config: Any) -> MikrotikConnector:
    """A new instance (= a new connection), as the hub builds one per call. The hub manages the router from the
    management VLAN (10.0.99.10), so the management-path guard knows which rules carry its traffic."""
    config = {"hub_address": "10.0.99.10", "username": user, **config}
    return MikrotikConnector(clean_config(MikrotikConnector, {"base_url": BASE, **{k: v for k, v in config.items()
                                                                                  if v is not None}}),
                             {"password": password}, httpx.MockTransport(fake))


def snapshot(fake: FakeRouterOS, **config: Any) -> dict[str, Any]:
    records, errors = normalize("network", run(connector(fake, **config).pull("network")))
    assert errors == [] and records[0]["errors"] == [], errors or records[0]["errors"]
    return records[0]


def allow(marker: str = "atrium:chg_7", src: str = "10.0.10.0/24", dst: str = "10.0.20.0/24",
          services: list[dict[str, Any]] | None = None, src_zone: str = "bridge", dst_zone: str = "vlan20",
          description: str = "Users to intranet") -> list[dict[str, Any]]:
    return parse_ops([{"op": "allow", "source": {"zone": src_zone, "cidrs": [src]},
                       "destination": {"zone": dst_zone, "cidrs": [dst]},
                       "services": services or [{"proto": "tcp", "ports": "443"}], "log": True,
                       "description": description, "marker": marker}])


def disable(*refs: str, op: str = "disable_rules") -> list[dict[str, Any]]:
    return parse_ops([{"op": op, "rules": [{"id": r, "vendor_ref": r} for r in refs]}])


ALLOW = allow()


# --------------------------------------------------------------------------------------
# reading
# --------------------------------------------------------------------------------------


def test_reads_the_router_into_the_network_model(fake):
    record = snapshot(fake)
    assert record["external_id"] == "HE10ABC123" and record["kind"] == "router"
    assert record["device"] == {"vendor": "MikroTik", "model": "RB5009UG+S+", "version": "7.16.2",
                                "hostname": "edge-gw", "management_address": "gw.example.net", "serial": "HE10ABC123"}
    ifaces = {i["id"]: i for i in record["interfaces"]}
    assert set(ifaces) == {"ether1", "bridge", "vlan20", "vlan30", "vlan99"}  # bridge ports and unused wg0 skipped
    assert ifaces["ether1"]["role"] == "wan" and ifaces["ether1"]["subnets"] == ["203.0.113.0/24"]  # DHCP address
    assert ifaces["bridge"]["role"] == "lan" and ifaces["bridge"]["subnets"] == ["10.0.10.0/24", "2001:db8:10::/64"]
    assert ifaces["vlan20"]["vlan"] == 20 and ifaces["vlan20"]["role"] == "lan"  # LAN includes the SERVERS list
    assert ifaces["vlan20"]["description"] == "SERVERS" and ifaces["vlan99"]["vlan"] == 99
    assert "fe80::1" not in record["self_addresses"] and "10.0.99.1" in record["self_addresses"]
    assert record["zones"] == [] and record["default_policy"] == {"inbound": "pass", "forward": "pass",
                                                                  "outbound": "pass"}

    aliases = {a["name"]: a for a in record["aliases"]}
    assert aliases["MGMT"] == {"name": "MGMT", "kind": "network", "cidrs": ["10.0.99.0/24"], "ports": None,
                               "resolved": True}
    assert aliases["RFC1918"]["cidrs"] == ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    assert aliases["scanners"]["resolved"] is False and aliases["updates"]["resolved"] is False  # run-time / DNS
    assert aliases["ADMINS"]["cidrs"] == ["10.0.10.5/32", "10.0.10.6/32"] and aliases["ADMINS"]["kind"] == "host"

    by = {r["id"]: r for r in record["rules"]}
    # not listed: the dynamic counter rule, established/related accepts, the loopback accept, the IPsec accept,
    # fasttrack and jump rules, and the chain nothing jumps to
    assert set(by) == {"ip:*3", "ip:*4", "ip:*6", "ip:*7", "ip:*B", "ip:*C", "ip:*D", "ip:*E", "ip:*10", "ip:*11",
                       "ip:*13", "ip:*14", "ipv6:*1", "ipv6:*2", "ipv6:*3"}
    mgmt = by["ip:*6"]
    assert mgmt["destination"] == {"any": False, "cidrs": [], "aliases": [], "nets": [], "self": True, "negate": False}
    assert mgmt["source"]["aliases"] == ["MGMT"] and mgmt["interfaces"] == ["vlan99"]
    assert mgmt["services"] == [{"proto": "tcp", "ports": "443", "alias": None, "name": ""}]
    assert by["ip:*7"]["floating"] and by["ip:*7"]["action"] == "block"  # "!LAN": read wider, as floating
    web = by["ip:*E"]
    assert web["interfaces"] == ["bridge", "vlan30", "vlan99", "vlan20"] and web["log"] and web["hits"] == 15320
    assert web["source"]["cidrs"] == ["10.0.10.0/24"] and web["destination"]["cidrs"] == ["10.0.20.10/32"]
    assert web["services"][0]["ports"] == "443,8443"
    assert web["description"] == "Users to web <b>app</b>"  # device text stays text (never HTML)
    assert by["ip:*D"]["interfaces"] == ["vlan20"] and by["ip:*D"]["out_interfaces"] == ["ether1"]
    guest = by["ip:*10"]  # in the "guest" jump chain: read as a forward rule without the jump's conditions
    assert guest["floating"] and guest["destination"]["negate"] and guest["destination"]["aliases"] == ["RFC1918"]
    assert by["ip:*13"]["enabled"] is False
    assert by["ipv6:*2"]["source"]["cidrs"] == ["2001:db8:10::/64"] and by["ipv6:*1"]["services"][0]["proto"] == "icmpv6"
    assert by["ip:*E"]["order"] < by["ip:*10"]["order"] < by["ipv6:*1"]["order"]
    notes = " | ".join(record["notes"])
    for expected in ("established, related or untracked", "loopback", "no enabled rule jumps to", "jump, return",
                     "interface lists are read as their member interfaces", "accepts packets no rule drops"):
        assert expected in notes, expected
    text = json.dumps(record)
    assert PASSWORD not in text and "nightly-script" not in text


def test_revision_follows_the_configuration_not_counters(fake):
    first = snapshot(fake)
    fake.row("*E")["packets"] = "99999"  # counters, link state, dynamic entries and read times move all the time
    fake.interfaces[0]["running"] = "false"
    fake.address_lists.append({".id": "*9", "list": "scanners", "address": "198.51.100.77", "disabled": "false",
                               "dynamic": "true", "timeout": "1h"})
    fake.addresses[0]["address"] = "203.0.113.8/24"  # a new DHCP lease
    fake.now[0] += 500
    assert snapshot(fake)["revision"] == first["revision"]
    fake.row("*E")["dst-port"] = "443"
    assert snapshot(fake)["revision"] != first["revision"]


def test_an_unreadable_address_list_reads_wider(fake):
    original = fake.route

    def route(method, path, params, body):
        if path == "/ip/firewall/address-list":  # a block list too large for RouterOS's 60 s
            return fake.error(400, "Session closed")
        return original(method, path, params, body)

    fake.route = route
    record = snapshot(fake)
    assert any(n.startswith("address lists: not readable") and "60 s" in n for n in record["notes"])
    assert "MGMT" not in {a["name"] for a in record["aliases"]}
    mgmt = next(r for r in record["rules"] if r["id"] == "ip:*6")
    assert mgmt["source"]["aliases"] == ["MGMT"]  # unknown to the hub: "any address" (wider)
    # without the list the guard cannot tell the hub's traffic apart: disabling the rule is refused
    assert run(connector(fake, hub_address="192.0.2.50").preview_change(disable("ip:*6"), record))["problems"]


def test_router_helpers():
    assert parse_clock({"date": "2026-10-09", "time": "23:59:30"}) == (datetime(2026, 10, 9, 23, 59, 30), "iso")
    assert parse_clock({"date": "oct/09/2026", "time": "01:02:03"}) == (datetime(2026, 10, 9, 1, 2, 3), "legacy")
    with pytest.raises(ValueError):
        parse_clock({"date": "09.10.2026", "time": "01:02:03"})
    assert Router.cidrs("10.0.0.1-10.0.0.3") == ["10.0.0.1/32", "10.0.0.2/31"]
    assert Router.cidrs("updates.example.net") is None
    assert Router.services("tcp", "!22", "") == [{"proto": "tcp", "ports": None}]  # negated ports: any port
    assert Router.services("!tcp", "22", "") is None
    assert Router.services("udp", "53", "53") == [{"proto": "udp", "ports": None}]  # "port" matches either side


# --------------------------------------------------------------------------------------
# test()
# --------------------------------------------------------------------------------------


def names(result: dict[str, Any]) -> list[str]:
    return [c["name"] for c in result["checks"]]


def detail(result: dict[str, Any], name: str) -> str:
    return next(c["detail"] for c in result["checks"] if c["name"] == name)


def test_test_reports_each_step_and_the_write_capability(fake):
    result = run(connector(fake).test())
    assert result["ok"], result
    assert names(result)[:6] == ["reachability", "tls", "authentication", "privileges", "version", "api_features"]
    assert result["network_write"] == {"ops": ["allow", "disable_rules", "enable_rules"], "rollback": "deadman",
                                       "window_s": 120}
    assert "read-only one is recommended" in detail(result, "privileges")
    assert "group atrium-rw: api,ftp,read,rest-api,test,write" in detail(result, "privileges")
    assert "RouterOS 7.16.2 on RB5009UG+S+ - supported" in detail(result, "version")
    assert "no Safe Mode over REST" in detail(result, "api_features")
    assert "configuration exports: yes" in detail(result, "api_features")
    assert "router time 2026-10-09 12:00:00 (Europe/Brussels); in step with the hub" in detail(result, "clock")
    assert "10.0.99.10" in detail(result, "management_guard")
    assert not [m for m, _, _ in fake.calls if m != "GET"]  # every probe is a read
    assert not any("nightly" in json.dumps(b) for _, _, b in fake.calls)
    assert PASSWORD not in json.dumps(result) and "nightly-script" not in json.dumps(result)
    assert run(connector(fake, window_s=300).test())["network_write"]["window_s"] == 300


def test_test_read_only_group_and_settings(fake):
    result = run(connector(fake, user="reader").test())
    assert result["ok"] and result["network_write"] is None and result["detail"].endswith("(read only)")
    assert "read only (no 'write' policy)" in detail(result, "privileges")
    assert "need the 'ftp' and 'test' policies" in detail(result, "privileges")
    result = run(connector(fake, read_only=True).test())
    assert result["network_write"] is None and "set to read only" in detail(result, "privileges")
    assert connector(fake, read_only=True).write_capability() is None
    result = run(connector(fake, user="admin").test())
    assert "not needed by Atrium" in detail(result, "privileges") and "sensitive" in detail(result, "privileges")
    fake.groups_unreadable = True  # the group cannot be read: no changes without knowing the policies
    result = run(connector(fake).test())
    assert result["ok"] and result["network_write"] is None and "cannot read the user's group" in detail(result,
                                                                                                         "privileges")


def test_test_failures_say_what_to_fix(fake):
    fake.unreachable = True
    result = run(connector(fake).test())
    assert result["ok"] is False and names(result) == ["reachability"] and "did not answer in time" in result["detail"]
    fake.unreachable, fake.tls_untrusted = False, True
    result = run(connector(fake).test())
    assert names(result) == ["reachability", "tls"] and "CA certificate file" in detail(result, "tls")
    fake.tls_untrusted, fake.no_certificate = False, True
    result = run(connector(fake).test())
    assert "assign a certificate to the www-ssl service" in detail(result, "tls")
    fake.no_certificate, fake.rest_off = False, True
    result = run(connector(fake).test())
    assert not result["ok"] and "REST API is off" in detail(result, "authentication")
    fake.rest_off = False
    result = run(connector(fake, password="wrong-password-value").test())
    assert names(result)[-1] == "authentication" and "'rest-api' policy" in result["detail"]
    assert "wrong-password-value" not in json.dumps(result) and PASSWORD not in json.dumps(result)
    result = run(connector(fake, user="noapi").test())
    assert not result["ok"] and "lacks the 'api' policy" in detail(result, "privileges")
    result = run(connector(fake, verify_tls=False).test())
    assert not next(c for c in result["checks"] if c["name"] == "tls")["ok"]
    fake.version = "6.49.10 (long-term)"  # (a v6 router has no REST API; the version check says so)
    result = run(connector(fake).test())
    assert not result["ok"] and "7.1 or later" in detail(result, "version")


def test_config_validation_and_options(fake):
    assert clean_config(MikrotikConnector, {"base_url": "https://gw:8443/rest/"})["base_url"] == "https://gw:8443"
    for bad in ("http://gw", "https://user:pw@gw", "gw.example.net", "https://gw/?x=1"):
        with pytest.raises(ValueError):
            clean_config(MikrotikConnector, {"base_url": bad})
    with pytest.raises(ValueError, match="absolute"):
        clean_config(MikrotikConnector, {"base_url": BASE, "ca_file": "ca.pem"})
    with pytest.raises(ValueError, match="IP address"):
        clean_config(MikrotikConnector, {"base_url": BASE, "hub_address": "hub.local"})
    for bad in ({"window_s": 30}, {"username": "a b"}, {"wan_list": 'WAN"; /system reboot'}):
        with pytest.raises(ValueError):
            clean_config(MikrotikConnector, {"base_url": BASE, **bad})
    assert MikrotikConnector.endpoint({"base_url": BASE, "verify_tls": False}) != \
        MikrotikConnector.endpoint({"base_url": BASE, "verify_tls": True})
    assert run(connector(fake).options("wan_list")) == [{"value": "WAN", "label": "WAN"}, {"value": "LAN", "label": "LAN"},
                                                        {"value": "SERVERS", "label": "SERVERS"}]
    assert MikrotikConnector.actions == set() and MikrotikConnector.describe()["can_backup"]


# --------------------------------------------------------------------------------------
# changes: dead-man scheduler
# --------------------------------------------------------------------------------------


def test_apply_verify_confirm(fake):
    before = snapshot(fake)
    preview = run(connector(fake).preview_change(ALLOW, before))
    assert preview["problems"] == [], preview
    assert preview["steps"][0]["position"] == "forward chain, before rule #12"  # the first drop that is not "invalid"
    assert any("undoes the change by itself 120 s" in n for n in preview["notes"])
    assert not [m for m, _, _ in fake.calls if m != "GET"]  # a preview writes nothing

    applied = run(connector(fake).apply_change(ALLOW, before["revision"], None))
    writes = [(m, p) for m, p, _ in fake.calls if m in ("PUT", "PATCH", "DELETE")]
    assert writes[0] == ("PUT", "/system/scheduler") and writes[1] == ("PUT", "/ip/firewall/filter")  # armed first
    job = fake.jobs()[0]
    assert job["interval"] == "0s" and job["policy"] == "read,write"
    assert (job["start-date"], job["start-time"]) == ("2026-10-09", "12:02:00")  # router time + 120 s
    assert job["on-event"] == (':do { /ip firewall filter remove [find comment="atrium:chg_7 Users to intranet"] } '
                               'on-error={}\n/system scheduler remove [find name="' + job["name"] + '"]')
    added = next(b for m, p, b in fake.calls if (m, p) == ("PUT", "/ip/firewall/filter"))
    assert added == {"chain": "forward", "action": "accept", "in-interface": "bridge", "out-interface": "vlan20",
                     "src-address": "10.0.10.0/24", "dst-address": "10.0.20.0/24", "protocol": "tcp",
                     "dst-port": "443", "comment": "atrium:chg_7 Users to intranet", "log": True,
                     "place-before": "*C"}
    assert applied["rollback_until"] == START + 120 and applied["revision"] is None
    ref = applied["created"][0]["id"]
    assert applied["created"] == [{"op": 0, "id": ref, "vendor_ref": ref}] and ref.startswith("ip:*")
    token = json.loads(applied["token"])
    assert token["mode"] == "deadman" and len(applied["token"]) < 4096 and PASSWORD not in applied["token"]

    after = snapshot(fake)  # verification over a new connection
    assert ops_applied(after, ALLOW) == []
    new = next(r for r in after["rules"] if r["id"] == ref)
    drop = next(r for r in after["rules"] if r["id"] == "ip:*C")
    assert new["order"] < drop["order"] and new["interfaces"] == ["bridge"] and new["out_interfaces"] == ["vlan20"]
    fake.now[0] += 60
    result = run(connector(fake).confirm_change(applied["token"]))
    assert result["confirmed"] and fake.jobs() == []
    fake.now[0] += 600  # confirmed: nothing reverts it any more
    assert ops_applied(snapshot(fake), ALLOW) == [] and fake.script_errors == []

    revert = inverse_ops(ALLOW, applied)  # a revert is a new change: the created rule is disabled
    again = run(connector(fake).apply_change(revert, snapshot(fake)["revision"], None))
    assert again["disabled"] == [ref]
    assert ops_reverted(before, snapshot(fake), ALLOW) == []


def test_the_router_undoes_an_unconfirmed_change_by_itself(fake):
    before = snapshot(fake)
    ops = ALLOW + disable("ip:*E")
    applied = run(connector(fake).apply_change(ops, before["revision"], None))
    assert applied["disabled"] == ["ip:*E"] and fake.row("*E")["disabled"] == "true"
    assert next(b for m, p, b in fake.calls if (m, p) == ("PATCH", "/ip/firewall/filter/*E")) == {"disabled": True}
    assert 'set *E disabled=no' in fake.jobs()[0]["on-event"]
    fake.now[0] += 121  # the hub never confirmed: the router's own job runs
    after = snapshot(fake)
    assert ops_reverted(before, after, ops) == [] and fake.jobs() == [] and fake.script_errors == []
    with pytest.raises(ChangeError) as late:
        run(connector(fake).confirm_change(applied["token"]))
    assert late.value.state == "rolled_back"
    result = run(connector(fake).rollback_change(applied["token"], None))
    assert result["method"] == "deadman"


def test_confirm_too_close_to_the_window_lets_the_job_run(fake):
    before = snapshot(fake)
    applied = run(connector(fake).apply_change(ALLOW, before["revision"], None))
    fake.now[0] += 115  # five seconds left: deleting the job now could race it
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).confirm_change(applied["token"]))
    assert caught.value.state == "rolled_back" and not fake.methods("DELETE", "/system/scheduler")
    assert ops_reverted(before, snapshot(fake), ALLOW) == []


def test_rollback_over_rest_and_lockout(fake):
    before = snapshot(fake)
    ops = ALLOW + disable("ip:*E")
    applied = run(connector(fake).apply_change(ops, before["revision"], None))
    result = run(connector(fake).rollback_change(applied["token"], None))
    assert result == {"rolled_back": True, "method": "inverse_ops", "notes": []}
    assert ops_reverted(before, snapshot(fake), ops) == [] and fake.jobs() == []
    fake.now[0] += 600
    assert fake.ran == []  # the job was deleted: it never runs later against someone else's change

    fake.lock_on_write = True  # the new rule cuts the hub off (in a real network: a wrong interface, a route...)
    applied = run(connector(fake).apply_change(ALLOW, snapshot(fake)["revision"], None))
    fake.lock_on_write = False
    assert run(connector(fake).test())["ok"] is False  # the hub's check over a new connection fails
    with pytest.raises(ChangeError) as unreachable:
        run(connector(fake).rollback_change(applied["token"], None))
    assert unreachable.value.code == "unreachable" and unreachable.value.state == "unknown"
    fake.now[0] += 121  # the router's own job restores access
    assert run(connector(fake).test())["ok"] and ops_reverted(before, snapshot(fake), ALLOW) == []


def test_rollback_falls_back_to_the_backup(fake, monkeypatch):
    taken = run(connector(fake).backup())
    before = snapshot(fake)
    ops = ALLOW + disable("ip:*E")
    applied = run(connector(fake).apply_change(ops, before["revision"], None))

    async def stuck(self, client, info):  # the rule-by-rule undo "succeeds" but the router keeps the change
        return None

    monkeypatch.setattr(MikrotikConnector, "_inverse", stuck)
    result = run(connector(fake).rollback_change(applied["token"], as_backup(taken)))
    assert result["method"] == "backup_restore" and ops_reverted(before, snapshot(fake), ops) == []
    assert fake.jobs() == []
    applied = run(connector(fake).apply_change(ops, snapshot(fake)["revision"], None))
    with pytest.raises(ChangeError) as caught:  # no backup to fall back on
        run(connector(fake).rollback_change(applied["token"], None))
    assert caught.value.state == "applied"
    fake.row("*D")["comment"] = "edited in WinBox"  # the backup cannot be restored over the API either
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).rollback_change(applied["token"], as_backup(taken)))
    assert caught.value.code == "unsupported" and caught.value.state == "applied"


def test_a_failed_write_is_undone_and_the_job_removed(fake):
    before = snapshot(fake)
    fake.fail_add = True
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(disable("ip:*E") + ALLOW, before["revision"], None))
    assert caught.value.code == "invalid" and caught.value.state == "unchanged" and "undone" in caught.value.message
    assert "dst-port" in caught.value.message
    assert fake.row("*E")["disabled"] == "false" and fake.jobs() == []


def test_nothing_is_written_when_the_job_cannot_be_armed(fake):
    before = snapshot(fake)
    fake.ignore_scheduler = True  # the router keeps the job but will never run it
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(ALLOW, before["revision"], None))
    assert caught.value.state == "unchanged" and "did not schedule the undo job" in caught.value.message
    assert not fake.methods("PUT", "/ip/firewall/filter") and fake.jobs() == []


def test_scheduler_dates_follow_the_router(fake):
    fake.now[0] = datetime(2026, 10, 9, 21, 59, 30, tzinfo=timezone.utc).timestamp()  # 23:59:30 router time
    before = snapshot(fake)
    run(connector(fake).apply_change(ALLOW, before["revision"], None))
    assert (fake.jobs()[0]["start-date"], fake.jobs()[0]["start-time"]) == ("2026-10-10", "00:01:30")
    fake.scheduler[:] = [j for j in fake.scheduler if not j["name"].startswith("atrium-rb-")]
    fake.date_style = "legacy"  # RouterOS before 7.10
    run(connector(fake).apply_change(allow("atrium:chg_8"), snapshot(fake)["revision"], None))
    assert fake.jobs()[0]["start-date"] == "oct/10/2026"


def test_stale_lockout_and_invalid_changes(fake):
    before = snapshot(fake)
    with pytest.raises(ChangeError) as stale:
        run(connector(fake).apply_change(ALLOW, "h-0000000000000000", None))
    assert stale.value.code == "stale" and stale.value.state == "unchanged"

    mgmt = disable("ip:*6")  # the REST rule on the management VLAN carries the hub's own traffic (from 10.0.99.10)
    assert run(connector(fake).preview_change(mgmt, before))["problems"]
    with pytest.raises(ChangeError) as lockout:
        run(connector(fake).apply_change(mgmt, before["revision"], None))
    assert lockout.value.code == "lockout" and fake.jobs() == []
    assert run(connector(fake, hub_address="192.0.2.50").preview_change(mgmt, before))["problems"] == []
    assert run(connector(fake, hub_address=None).preview_change(disable("ip:*E"), before))["problems"] == []

    wide = parse_ops([
        {"op": "allow", "source": {"zone": "bridge", "cidrs": ["10.0.10.0/24", "10.0.11.0/24"]},
         "destination": {"zone": "vlan20", "cidrs": ["10.0.20.0/24"]},
         "services": [{"proto": "tcp", "ports": "80"}, {"proto": "udp", "ports": "53"}], "marker": "atrium:chg_9"},
        {"op": "allow", "source": {"zone": "ether9", "cidrs": ["10.0.10.0/24"]},
         "destination": {"zone": "vlan20", "cidrs": ["2001:db8:20::/64"]}, "services": [{"proto": "icmp"}],
         "marker": "atrium:chg_9"},
        {"op": "allow", "source": {"zone": "bridge", "cidrs": ["2001:db8:10::/64"]},
         "destination": {"zone": "vlan20", "cidrs": ["2001:db8:20::/64"]}, "services": [{"proto": "icmp"}],
         "marker": "atrium:chg_9"},
        {"op": "disable_rules", "rules": [{"id": "ip:*1"}, {"id": "ip:*99"}]}])
    problems = " | ".join(run(connector(fake).preview_change(wide, before))["problems"])
    for expected in ("one source network", "one protocol and one port list", "no interface 'ether9'",
                     "IPv4 and IPv6", "ICMP rules are IPv4 only", "is dynamic", "ip:_99 is not on the"):
        assert expected in problems, expected
    with pytest.raises(ChangeError) as invalid:
        run(connector(fake).apply_change(wide[:3], before["revision"], None))
    assert invalid.value.code == "invalid" and fake.jobs() == []

    with pytest.raises(ChangeError) as read_only:
        run(connector(fake, read_only=True).apply_change(ALLOW, before["revision"], None))
    assert read_only.value.code == "unsupported"

    applied = run(connector(fake).apply_change(ALLOW, before["revision"], None))
    current = snapshot(fake)
    problems = run(connector(fake).preview_change(allow("atrium:chg_7"), current))["problems"]
    assert any("already on the router" in p for p in problems) and any("waiting for confirmation" in p for p in problems)
    with pytest.raises(ChangeError, match="waiting for confirmation"):
        run(connector(fake).apply_change(allow("atrium:chg_8"), current["revision"], None))
    assert run(connector(fake).test())["checks"][-2]["name"] == "pending_change"
    run(connector(fake).confirm_change(applied["token"]))


def test_ipv6_changes_use_the_ipv6_table(fake):
    ops = allow("atrium:chg_6", src="2001:db8:10::/64", dst="2001:db8:20::/64", services=[{"proto": "tcp",
                                                                                          "ports": "80,443"}])
    before = snapshot(fake)
    applied = run(connector(fake).apply_change(ops, before["revision"], None))
    assert applied["created"][0]["id"].startswith("ipv6:*") and fake.methods("PUT", "/ipv6/firewall/filter")
    assert "/ipv6 firewall filter remove" in fake.jobs()[0]["on-event"]
    after = snapshot(fake)
    assert ops_applied(after, ops) == []
    new = next(r for r in after["rules"] if r["id"] == applied["created"][0]["id"])
    assert new["order"] < next(r for r in after["rules"] if r["id"] == "ipv6:*3")["order"]
    fake.now[0] += 121
    assert ops_reverted(before, snapshot(fake), ops) == [] and fake.script_errors == []


def test_descriptions_never_reach_the_script_unescaped(fake):
    ops = allow("atrium:chg_5", description='x" ] ; /system reboot ; $a [:put ?] {}\\')
    before = snapshot(fake)
    applied = run(connector(fake).apply_change(ops, before["revision"], None))
    comment = next(b for m, p, b in fake.calls if (m, p) == ("PUT", "/ip/firewall/filter"))["comment"]
    assert comment == "atrium:chg_5 x_ _ _ /system reboot _ _a _:put __ ___"
    assert "reboot ;" not in fake.jobs()[0]["on-event"]
    fake.now[0] += 121
    assert ops_reverted(before, snapshot(fake), ops) == [] and fake.script_errors == []
    assert json.loads(applied["token"])["comments"] == [["ip", comment]]


def test_tokens_are_validated(fake):
    good = {"v": 1, "mode": "deadman", "sched": "atrium-rb-0123456789ab", "sched_id": "*41", "created": [],
            "toggled": {}, "comments": [], "deadline": START}
    for bad in ({"sched": 'x"]; /system reboot'}, {"sched_id": "*41/../../user"},
                {"comments": [["ip", 'atrium:chg_1 a"] ; /system reboot']]}, {"toggled": {"ip:*1": "maybe"}},
                {"created": ["ip:1 or 1"]}, {"mode": "savepoint"}, {"comments": [["user", "atrium:chg_1"]]}):
        with pytest.raises(ChangeError, match="Not a change token"):
            run(connector(fake).rollback_change(json.dumps({**good, **bad}), None))
    with pytest.raises(ChangeError, match="Not a change token"):
        run(connector(fake).confirm_change("{}"))


# --------------------------------------------------------------------------------------
# backups
# --------------------------------------------------------------------------------------


def as_backup(taken: dict[str, Any]) -> Backup:
    content = taken["content"]
    return Backup("bk_1", content, hashlib.sha256(content).hexdigest(), 0.0, taken["format"],
                  taken["device_backup_id"], taken["revision"])


def test_backup_reads_the_export_in_chunks_and_cleans_up(fake):
    taken = run(connector(fake).backup())
    assert taken["format"] == "json" and taken["device_backup_id"] is None
    assert taken["sha256"] == hashlib.sha256(taken["content"]).hexdigest()
    saved = json.loads(taken["content"])
    assert saved["format"] == "atrium-routeros-backup" and saved["routeros"] == "7.16.2"
    assert saved["export"].startswith("# 2026-10-09 12:00:00 by RouterOS 7.16.2") and len(saved["export"]) > 32768
    assert saved["revision"] == snapshot(fake)["revision"]
    assert [r[".id"] for r in saved["filter"]["ip"]][:2] == ["*2", "*3"]  # static rows, without counters
    assert "packets" not in saved["filter"]["ip"][0]
    reads = [b for m, p, b in fake.calls if p == "/file/read"]
    assert len(reads) >= 3 and [r["offset"] for r in reads][:2] == ["0", "32768"]
    export = next(b for m, p, b in fake.calls if p == "/export")
    assert set(export) == {"file"} and fake.files == {}  # never "show-sensitive"; the file is deleted afterwards
    assert WG_KEY not in taken["content"].decode() and PASSWORD not in taken["content"].decode()
    with pytest.raises(Exception, match="'ftp'"):
        run(connector(fake, user="reader").backup())


def test_restore_puts_atrium_changes_back(fake):
    taken = run(connector(fake).backup())
    before = snapshot(fake)
    ops = ALLOW + disable("ip:*E")
    applied = run(connector(fake).apply_change(ops, before["revision"], None))
    run(connector(fake).confirm_change(applied["token"]))
    restored = run(connector(fake).restore_backup(as_backup(taken)))
    assert restored["restored"] and ops_reverted(before, snapshot(fake), ops) == []
    assert fake.methods("DELETE", "/ip/firewall/filter") and fake.row("*E")["disabled"] == "false"

    fake.row("*D")["comment"] = "edited in WinBox"  # a change Atrium did not make: refused before writing anything
    writes = len([m for m, _, _ in fake.calls if m != "GET"])
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).restore_backup(as_backup(taken)))
    assert caught.value.code == "unsupported" and caught.value.state == "unchanged"
    assert "edited" in caught.value.message and "edited in WinBox" not in caught.value.message
    assert len([m for m, _, _ in fake.calls if m != "GET"]) == writes

    with pytest.raises(ChangeError) as caught:
        run(connector(fake).restore_backup(Backup("bk_2", b"<config/>", "x", 0.0, "xml")))
    assert caught.value.code == "invalid"


def test_restore_refuses_to_cut_the_hub_off(fake):
    fake.row("*6")["disabled"] = "true"
    taken = run(connector(fake).backup())  # a backup in which the management rule was off
    fake.row("*6")["disabled"] = "false"
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).restore_backup(as_backup(taken)))
    assert caught.value.code == "lockout" and fake.row("*6")["disabled"] == "false"


def test_errors_never_carry_secrets(fake):
    before = snapshot(fake)
    with pytest.raises(ChangeError) as caught:
        run(connector(fake, user="reader", read_only=False).apply_change(ALLOW, before["revision"], None))
    text = json.dumps(caught.value.as_dict())
    assert "'write'" in text and PASSWORD not in text
    assert fake.jobs() == []


# --------------------------------------------------------------------------------------
# through the hub
# --------------------------------------------------------------------------------------


def test_through_the_hub(client, monkeypatch, wait_for):
    from hub.models import Manifest, Tool

    fake = FakeRouterOS()
    hub = client.app.state.hub
    monkeypatch.setattr(hub, "connector_transport", httpx.MockTransport(fake), raising=False)
    tool = Tool(id="mt1", name="MikroTik edge", source_type="saas", source="https://mikrotik.com", status="ready",
                manifest=Manifest(id="mt1", name="MikroTik edge", kind="saas"))
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    detected = client.get("/api/connectors").json()
    assert any(c["kind"] == "mikrotik" and c["network_write"]["rollback"] == "deadman" for c in detected)
    response = client.put("/api/tools/mt1/connection", json={"kind": "mikrotik", "config": {"base_url": BASE},
                                                             "secrets": {"password": PASSWORD}})
    assert response.status_code == 200, response.text
    tested = client.post("/api/tools/mt1/connection/test").json()
    assert tested["ok"] and tested["network_write"]["rollback"] == "deadman", tested
    assert PASSWORD not in json.dumps(tested)
    approval = wait_for(lambda: next((a for a in client.get("/api/approvals?status=pending").json()
                                      if a["kind"] == "flow" and a["payload"]["tool_id"] == "mt1"), None))
    assert client.post(f"/api/approvals/{approval['id']}", json={"approve": True}).status_code == 200
    wait_for(lambda: next((f for f in client.get("/api/flows?tool_id=mt1").json()
                           if f["domain"] == "network" and f["status"] == "enabled"), None))
    refreshed = client.post("/api/network/devices/mt1/refresh").json()
    assert refreshed["results"][0]["ok"], refreshed
    device = client.get("/api/network/devices/mt1").json()
    assert device["record"]["device"]["vendor"] == "MikroTik" and device["record"]["kind"] == "router"
    assert len(device["record"]["rules"]) == 15
    assert PASSWORD not in json.dumps(device) and "nightly-script" not in json.dumps(device)
    seg = client.get("/api/segmentation?firewall=mt1").json()
    zones = {z["native_id"] for z in seg["zones"] if z.get("native_id")}
    assert {"bridge", "vlan20", "vlan30", "vlan99"} <= zones
