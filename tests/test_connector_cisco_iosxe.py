"""The Cisco IOS-XE connector against a fake device (no network): RESTCONF through httpx.MockTransport with answers
shaped by RFC 7951 from Cisco's 17.15.1 YANG models (module-qualified top-level members, uint64 sequences as strings,
empty leaves as [null], port names such as "www"), and a NETCONF server speaking RFC 6242 framing (end-of-message for
the hello, then chunked - split into several chunks) over in-memory pipes, sharing one configuration with RESTCONF:
candidate / running datastores, locks, edit-config with create / remove, confirmed commit with persist, confirming
commit by persist-id, cancel-commit and the confirm timer. The NETCONF client is also run over real SSH (asyncssh) to
an in-process server with a ``netconf`` subsystem."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import copy
import json
import re
import xml.etree.ElementTree as ET
from typing import Any

import httpx
import pytest

from hub.connectors.base import normalize
from hub.connectors.cisco_iosxe import (CiscoIosXeConnector, Device, NetconfError, NetconfSession, parse_version,
                                        wildcard_cidr)
from hub.connectors.netmodel import Backup, ChangeError, inverse_ops, ops_applied, ops_reverted, parse_ops
from hub.integration.connections import clean_config

PASSWORD = "iosxe-pass-5b7d1e9f3a"
SECRET_HASH = "$9$fakeDeviceSecretHashXYZ"
BASE = "https://10.0.99.2"
NC = "urn:ietf:params:xml:ns:netconf:base:1.0"
EOM = b"]]>]]>"
START = 1_760_000_000.0
CAPS_WRITE = ["urn:ietf:params:netconf:base:1.0", "urn:ietf:params:netconf:base:1.1",
              "urn:ietf:params:netconf:capability:candidate:1.0",
              "urn:ietf:params:netconf:capability:confirmed-commit:1.0",
              "urn:ietf:params:netconf:capability:confirmed-commit:1.1",
              "urn:ietf:params:netconf:capability:validate:1.1",
              "urn:ietf:params:netconf:capability:rollback-on-error:1.0",
              "urn:ietf:params:netconf:capability:with-defaults:1.0?basic-mode=explicit&also-supported=report-all-tagged"]


def run(coro):
    return asyncio.run(coro)


def ace(seq: int, **fields: Any) -> dict[str, Any]:
    return {"sequence": str(seq), "ace-rule": fields}


def default_config() -> dict[str, Any]:
    return {
        "hostname": "sw-core-1",
        "interface": {
            "GigabitEthernet": [
                {"name": "0/0", "description": "out-of-band", "vrf": {"forwarding": "Mgmt-vrf"},
                 "ip": {"address": {"primary": {"address": "10.0.99.2", "mask": "255.255.255.0"}}}},
                {"name": "1/0/1", "description": "uplink to ISP",
                 "ip": {"address": {"primary": {"address": "203.0.113.2", "mask": "255.255.255.248"}},
                        "access-group": {"in": {"acl": {"acl-name": "WAN-IN", "in": [None]}}}}},
                {"name": "1/0/2", "switchport-conf": {"switchport": True}},
                {"name": "1/0/3", "switchport-conf": {"switchport": True}, "shutdown": [None]},
            ],
            "Vlan": [
                {"name": 10, "description": "Users <script>",
                 "ip": {"address": {"primary": {"address": "10.0.10.1", "mask": "255.255.255.0"}},
                        "access-group": {"in": {"acl": {"acl-name": "USERS-IN", "in": [None]}}}}},
                {"name": 20, "ip": {"address": {"primary": {"address": "10.0.20.1", "mask": "255.255.255.0"},
                                                "secondary": [{"address": "10.0.21.1", "mask": "255.255.255.0",
                                                               "secondary": [None]}]},
                                    "access-group": {"out": {"acl": {"acl-name": "SERVERS-OUT", "out": [None]}}}}},
                {"name": 30, "ip": {"address": {"primary": {"address": "10.0.30.1", "mask": "255.255.255.0"}}}},
            ],
            "Loopback": [{"name": 0, "ip": {"address": {"primary": {"address": "10.255.0.1",
                                                                    "mask": "255.255.255.255"}}}}],
        },
        "vlan": [{"id": 10, "name": "USERS"}, {"id": 20, "name": "SERVERS"}, {"id": 30, "name": "GUEST"},
                 {"id": 40, "name": "PRINTERS"}],
        "acl": {
            "extended": [
                {"name": "USERS-IN", "access-list-seq-rule": [
                    {"sequence": "10", "remark": "Users may reach the web servers"},
                    ace(20, action="permit", protocol="tcp", **{"ipv4-address": "10.0.10.0", "mask": "0.0.0.255",
                                                               "dst-host-address": "10.0.20.10", "dst-eq": "www",
                                                               "dst-eq-port2": 443, "log": [None]}),
                    ace(30, action="permit", protocol="udp", **{"ipv4-address": "10.0.10.0", "mask": "0.0.0.255",
                                                               "dst-object-group": "DNS_SERVERS", "dst-eq": "domain"}),
                    {"sequence": "35", "remark": "keep users out of the rest"},
                    ace(40, action="deny", protocol="ip", **{"ipv4-address": "10.0.10.0", "mask": "0.0.0.255",
                                                            "dest-ipv4-address": "10.0.0.0", "dest-mask": "0.255.255.255",
                                                            "log": [None]}),
                    ace(50, action="permit", protocol="ip", **{"any": [None], "dst-any": [None]}),
                ]},
                {"name": "WAN-IN", "access-list-seq-rule": [
                    ace(10, action="permit", protocol="tcp", **{"any": [None], "dst-host-address": "10.0.20.10",
                                                               "dst-eq": 443}),
                    ace(15, action="permit", protocol="tcp", **{"any": [None], "dest-ipv4-address": "10.0.20.0",
                                                               "dest-mask": "0.0.0.255", "dst-gt": 1023,
                                                               "established": [None]}),
                    ace(25, action="permit", protocol="udp", **{"any": [None], "dst-host-address": "10.0.20.10",
                                                               "dst-range1": 5000, "dst-range2": 5010}),
                    ace(35, action="permit", protocol="tcp", **{"ipv4-address": "192.0.2.0", "mask": "0.0.255.0",
                                                               "dst-any": [None], "src-eq": 179}),
                    ace(40, action="deny", protocol="ip", **{"any": [None], "dst-any": [None], "log": [None]}),
                ]},
                {"name": "SERVERS-OUT", "access-list-seq-rule": [
                    ace(10, action="permit", protocol="tcp", **{"any": [None], "dest-ipv4-address": "10.0.20.0",
                                                               "dest-mask": "0.0.0.255", "dst-neq": "telnet"}),
                    ace(20, action="deny", protocol="ip", **{"any": [None], "dst-any": [None]}),
                ]},
                {"name": "UNUSED-EXT", "access-list-seq-rule": [ace(10, action="permit", protocol="ip",
                                                                    **{"any": [None], "dst-any": [None]})]},
            ],
            "standard": [
                {"name": "VTY-MGMT", "access-list-seq-rule": [
                    {"sequence": "10", "permit": {"std-ace": {"ipv4-address-prefix": "10.0.99.0", "mask": "0.0.0.255"}}},
                    {"sequence": "20", "permit": {"std-ace": {"host-address": "10.0.10.5"}}},
                ]},
            ],
        },
        "object-group": [{"name": "DNS_SERVERS", "obj-Mode-config-network-group": {
            "host": [{"ipv4-host": "10.0.20.53"}],
            "network_address": [{"ipv4_addr": "10.0.21.0", "ipv4_mask": "255.255.255.0"}]}}],
        "line": {"vty": [{"first": 0, "last": 4, "access-class": {"acccess-list": [{"direction": "in",
                                                                                   "access-list": "VTY-MGMT"}]},
                          "transport": {"input": {"input": ["ssh"]}}},
                         {"first": 5, "last": 15, "access-class": {"acccess-list": [{"direction": "in",
                                                                                    "access-list": "VTY-MGMT"}]}}]},
        "http": {"server": False, "secure-server": True},
    }


class Pipe:
    """One direction of an in-memory byte stream (reader and writer side)."""

    def __init__(self) -> None:
        self.queue: asyncio.Queue[bytes] = asyncio.Queue()

    def write(self, data: bytes) -> None:
        self.queue.put_nowait(bytes(data))

    async def drain(self) -> None:
        return None

    async def read(self, n: int = -1) -> bytes:
        return await self.queue.get()

    def close(self) -> None:
        self.queue.put_nowait(b"")


def local(tag: str) -> str:
    return tag.rpartition("}")[2]


class FakeNetconf:
    """The fake's NETCONF transport: ``session(target)`` like AsyncsshNetconf, over in-memory pipes."""

    def __init__(self, device: "FakeIosXe"):
        self.device = device
        self.targets: list[Any] = []

    @contextlib.asynccontextmanager
    async def session(self, target):
        device = self.device
        if device.unreachable or device.netconf_fail:
            raise NetconfError(f"{target.label}: cannot connect to NETCONF (ConnectionRefusedError: refused)")
        self.targets.append(target)
        number = len(self.targets)
        to_server, to_client = Pipe(), Pipe()
        task = asyncio.create_task(device.serve(to_server, to_client, number))
        session = NetconfSession(to_client, to_server, label="fake")
        try:
            await session.hello()
            yield session
        finally:
            await session.close()
            to_server.close()
            with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
                await asyncio.wait_for(task, 2)
            device.end_session(number)


class FakeIosXe(httpx.MockTransport):
    """Just enough of an IOS-XE device for the connector (RESTCONF + NETCONF on one configuration)."""

    def __init__(self) -> None:
        super().__init__(self.route)
        self.running = default_config()
        self.candidate = copy.deepcopy(self.running)
        self.startup: dict[str, Any] | None = None
        self.software = ("Cisco IOS XE Software, Version 17.15.01\nCisco IOS Software [IOSXE], Catalyst L3 Switch "
                         "Software (CAT9K_IOSXE), Version 17.15.1, RELEASE SOFTWARE (fc3)")
        self.caps = list(CAPS_WRITE)
        self.netconf = FakeNetconf(self)
        self.now = START
        self.calls: list[tuple[str, str]] = []
        self.rpcs: list[tuple[int, str]] = []
        self.lock: int | None = None
        self.pending: dict[str, Any] | None = None  # {persist, before, deadline}
        self.flash: dict[str, dict[str, Any]] = {}
        self.counters = {("USERS-IN", "20"): 1532, ("WAN-IN", "40"): 77}
        self.unreachable = self.tls_untrusted = self.netconf_fail = self.fields_unsupported = False
        self.syncing = self.copy_fails = self.lose_session_on_commit = False
        self.refuse_edit: str | None = None
        self.chunk = 97  # split chunked replies into pieces of this size

    # -- the device's own behaviour ----------------------------------------------------------

    def tick(self) -> None:
        if self.pending and self.now >= self.pending["deadline"]:
            self.running = self.pending["before"]
            self.candidate = copy.deepcopy(self.running)
            self.pending = None

    def end_session(self, number: int) -> None:
        if self.lock == number:
            self.lock = None
            self.candidate = copy.deepcopy(self.running)  # RFC 6241: changes of the lock holder are discarded

    def acl(self, store: dict[str, Any], name: str) -> dict[str, Any] | None:
        return next((a for a in store["acl"]["extended"] if a["name"] == name), None)

    def rows(self, name: str) -> dict[str, dict[str, Any]]:
        return {r["sequence"]: r for r in self.acl(self.running, name)["access-list-seq-rule"]}

    # -- RESTCONF ----------------------------------------------------------------------------

    def route(self, request: httpx.Request) -> httpx.Response:
        self.tick()
        path = request.url.path
        self.calls.append((request.method, path + (f"?{request.url.query.decode()}" if request.url.query else "")))
        if self.unreachable:
            raise httpx.ConnectError("timed out", request=request)
        if self.tls_untrusted:
            raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed", request=request)
        auth = request.headers.get("authorization", "")
        user, _, password = base64.b64decode(auth.split(" ", 1)[1]).decode().partition(":") if " " in auth else ("", "", "")
        if password != PASSWORD or user not in ("atrium", "lowpriv"):
            return httpx.Response(401, json=error("access-denied", "access denied"))
        if not path.startswith("/restconf/"):
            return httpx.Response(404)
        path = path[len("/restconf"):]
        if request.method == "POST" and path.startswith("/operations/"):
            return self.operation(path, json.loads(request.content or b"{}"))
        if user == "lowpriv" and "native" in path:
            return httpx.Response(403, json=error("access-denied", "access denied"))
        if path.startswith("/data/Cisco-IOS-XE-interfaces-oper") and request.url.params.get("fields") \
                and self.fields_unsupported:
            return httpx.Response(400, json=error("invalid-value", "fields not supported"))
        answer = self.data(path)
        if answer is None:
            return httpx.Response(404, json=error("invalid-value", "uri keypath not found"))
        return httpx.Response(200, json=answer, headers={"Content-Type": "application/yang-data+json"})

    def data(self, path: str) -> Any:
        c = self.running
        native = "/data/Cisco-IOS-XE-native:native/"
        hw = "/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data/device-hardware/"
        if path == hw + "device-system-data":
            return {"Cisco-IOS-XE-device-hardware-oper:device-system-data": {
                "current-time": "2026-10-09T10:00:00+00:00", "software-version": self.software}}
        if path == hw + "device-inventory":
            return {"Cisco-IOS-XE-device-hardware-oper:device-inventory": [
                {"hw-type": "hw-type-dram", "hw-dev-index": 0, "part-number": "DRAM"},
                {"hw-type": "hw-type-chassis", "hw-dev-index": 0, "part-number": "C9300-24T",
                 "serial-number": "FOC1234X0AB"}]}
        if path == native + "hostname":
            return {"Cisco-IOS-XE-native:hostname": c["hostname"]}
        if path == native + "interface":
            return {"Cisco-IOS-XE-native:interface": copy.deepcopy(c["interface"])}
        if path == native + "vlan":
            return {"Cisco-IOS-XE-native:vlan": {"Cisco-IOS-XE-vlan:vlan-list": copy.deepcopy(c["vlan"])}}
        if path == native + "ip/access-list":
            acl = {f"Cisco-IOS-XE-acl:{k}": copy.deepcopy(v) for k, v in c["acl"].items() if v}
            return {"Cisco-IOS-XE-native:access-list": acl} if acl else None
        if path == native + "object-group":
            return {"Cisco-IOS-XE-native:object-group": {"Cisco-IOS-XE-object-group:network":
                                                         copy.deepcopy(c["object-group"])}} if c["object-group"] else None
        if path == native + "line":
            return {"Cisco-IOS-XE-native:line": copy.deepcopy(c["line"])}
        if path == native + "ip/http":
            return {"Cisco-IOS-XE-http:http": copy.deepcopy(c["http"])}
        if path == "/data/Cisco-IOS-XE-interfaces-oper:interfaces":
            out = []
            for kind, entries in c["interface"].items():
                for e in entries:
                    primary = e.get("ip", {}).get("address", {}).get("primary", {})
                    out.append({"name": f"{kind}{e['name']}", "admin-status": "if-state-up",
                                "oper-status": "if-oper-state-ready", "ipv4": primary.get("address", "0.0.0.0"),
                                "ipv4-subnet-mask": primary.get("mask", "0.0.0.0"),
                                "statistics": {"in-octets": str(int(self.now))}})
            return {"Cisco-IOS-XE-interfaces-oper:interfaces": {"interface": out}}
        if path == "/data/Cisco-IOS-XE-acl-oper:access-lists":
            lists: dict[str, list[dict[str, Any]]] = {}
            for (name, seq), count in self.counters.items():
                lists.setdefault(name, []).append({"rule-name": int(seq), "access-list-entries-oper-data": {
                    "match-counter": str(count)}})
            return {"Cisco-IOS-XE-acl-oper:access-lists": {"access-list": [
                {"access-control-list-name": n, "access-list-entries": {"access-list-entry": e}} for n, e in lists.items()]}}
        return None

    def operation(self, path: str, body: dict[str, Any]) -> httpx.Response:
        name = path.rsplit("/", 1)[1]
        module = name.split(":")[0]
        data = body.get(f"{module}:input") or {}

        def out(**fields: Any) -> httpx.Response:
            return httpx.Response(200, json={f"{module}:output": fields})

        if name == "cisco-ia:is-syncing":
            return out(result="ok", syncing=self.syncing, **{"syncs-pending": False,
                                                              "candidate-datastore-dirty": self.candidate != self.running})
        if name == "cisco-ia:save-config":
            self.startup = copy.deepcopy(self.running)
            return out(result="Save running-config successful")
        if name == "Cisco-IOS-XE-cli-rpc:get-modelled-config-clis":
            return out(result=f"hostname {self.running['hostname']}\nusername admin privilege 15 secret 9 {SECRET_HASH}\n"
                              + json.dumps(self.running["acl"]))
        if name == "Cisco-IOS-XE-rpc:copy":
            target = data.get("destination-drop-node-name", "")
            if data.get("source-drop-node-name") != "running-config" or not re.match(r"^(bootflash|flash):", target):
                return httpx.Response(400, json=error("invalid-value", "bad copy"))
            if self.copy_fails or target in self.flash:
                return httpx.Response(500, json=error("operation-failed", "%Error opening (File exists)"))
            self.flash[target] = copy.deepcopy(self.running)
            return out(result="Copy successful")
        if name == "Cisco-IOS-XE-rpc:delete":
            self.flash.pop(data.get("filename-drop-node-name"), None)
            return out(result="Delete successful")
        if name == "cisco-ia:rollback":
            target = data.get("target-url")
            if target not in self.flash:
                return httpx.Response(400, json=error("operation-failed", f"%Error opening {target} (No such file)"))
            self.running = copy.deepcopy(self.flash[target])
            self.candidate = copy.deepcopy(self.running)
            self.pending = None
            return out(result="Rollback Done")
        return httpx.Response(404, json=error("invalid-value", "unknown operation"))

    # -- NETCONF -----------------------------------------------------------------------------

    async def serve(self, inbox: Any, outbox: Any, number: int) -> None:
        buffer, chunked = b"", False

        async def more() -> bool:
            nonlocal buffer
            data = await inbox.read(65536)
            buffer += data
            return bool(data)

        async def receive() -> bytes | None:
            nonlocal buffer
            if not chunked:
                while EOM not in buffer:
                    if not await more():
                        return None
                message, _, buffer = buffer.partition(EOM)
                return message
            parts = []
            while True:
                if buffer.startswith(b"\n##\n"):
                    buffer = buffer[4:]
                    return b"".join(parts)
                match = re.match(rb"\n#(\d+)\n", buffer)
                if match and len(buffer) >= match.end() + int(match.group(1)):
                    size = int(match.group(1))
                    parts.append(buffer[match.end():match.end() + size])
                    buffer = buffer[match.end() + size:]
                    continue
                if not await more():
                    return None

        def send(text: str) -> None:
            data = text.encode()
            if not chunked:
                outbox.write(data + EOM)
                return
            pieces = [data[i:i + self.chunk] for i in range(0, len(data), self.chunk)]
            outbox.write(b"".join(b"\n#%d\n%s" % (len(p), p) for p in pieces) + b"\n##\n")

        caps = "".join(f"<capability>{c.replace('&', '&amp;')}</capability>" for c in self.caps)
        send(f'<?xml version="1.0" encoding="UTF-8"?><hello xmlns="{NC}"><capabilities>{caps}</capabilities>'
             f"<session-id>{number}</session-id></hello>")
        hello = await receive()
        if hello is None:
            return
        client = {c.text for c in ET.fromstring(hello).iter(f"{{{NC}}}capability")}
        chunked = "urn:ietf:params:netconf:base:1.1" in client and "urn:ietf:params:netconf:base:1.1" in self.caps
        while True:
            message = await receive()
            if message is None:
                return
            rpc = ET.fromstring(message)
            mid = rpc.get("message-id")
            op = rpc[0]
            self.rpcs.append((number, local(op.tag)))
            self.tick()
            if self.lose_session_on_commit and local(op.tag) == "commit":
                self.apply_commit(op, number)
                outbox.write(b"")
                inbox.close()
                return
            problem = self.handle(op, number)
            if local(op.tag) == "close-session":
                send(f'<rpc-reply message-id="{mid}" xmlns="{NC}"><ok/></rpc-reply>')
                return
            if problem:
                tag, text = problem
                send(f'<rpc-reply message-id="{mid}" xmlns="{NC}"><rpc-error><error-type>application</error-type>'
                     f"<error-tag>{tag}</error-tag><error-severity>error</error-severity>"
                     f'<error-message xml:lang="en">{text}</error-message></rpc-error></rpc-reply>')
            else:
                send(f'<rpc-reply message-id="{mid}" xmlns="{NC}"><ok/></rpc-reply>')

    def handle(self, op: ET.Element, number: int) -> tuple[str, str] | None:
        name = local(op.tag)
        if name == "lock":
            if self.lock not in (None, number):
                return "lock-denied", f"Lock failed, lock is already held by session {self.lock}"
            if self.candidate != self.running:  # RFC 6241 8.3.5.1
                return "lock-denied", "the candidate holds uncommitted changes"
            self.lock = number
        elif name == "unlock":
            if self.lock == number:
                self.lock = None
        elif name == "discard-changes":
            if self.lock not in (None, number):
                return "in-use", "the candidate is locked by another session"
            self.candidate = copy.deepcopy(self.running)
        elif name == "edit-config":
            if self.lock not in (None, number):
                return "in-use", "the candidate is locked by another session"
            if self.refuse_edit:
                return "invalid-value", self.refuse_edit
            return self.edit(op)
        elif name == "validate":
            return None
        elif name == "commit":
            return self.apply_commit(op, number)
        elif name == "cancel-commit":
            persist = next((c.text for c in op if local(c.tag) == "persist-id"), None)
            if not self.pending or self.pending["persist"] != persist:
                return "invalid-value", "no confirmed commit is pending"
            self.running = self.pending["before"]
            self.candidate = copy.deepcopy(self.running)
            self.pending = None
        elif name == "close-session":
            return None
        else:
            return "operation-not-supported", name
        return None

    def apply_commit(self, op: ET.Element, number: int) -> tuple[str, str] | None:
        fields = {local(c.tag): (c.text or "") for c in op}
        if "persist-id" in fields:
            if not self.pending or self.pending["persist"] != fields["persist-id"]:
                return "invalid-value", "no confirmed commit is pending"
            self.pending = None
            self.running = copy.deepcopy(self.candidate)
            return None
        if self.pending:
            return "in-use", "a confirmed commit is pending"
        if "confirmed" in fields:
            assert "persist" in fields and fields["persist"]
            self.pending = {"persist": fields["persist"], "before": copy.deepcopy(self.running),
                            "deadline": self.now + int(fields.get("confirm-timeout") or 600)}
        self.running = copy.deepcopy(self.candidate)
        return None

    def edit(self, op: ET.Element) -> tuple[str, str] | None:
        config = next(c for c in op if local(c.tag) == "config")
        assert next(c for c in op if local(c.tag) == "default-operation").text == "none"
        native = config[0]
        assert native.tag == "{http://cisco.com/ns/yang/Cisco-IOS-XE-native}native"
        for extended in native.iter("{http://cisco.com/ns/yang/Cisco-IOS-XE-acl}extended"):
            name = next(c.text for c in extended if local(c.tag) == "name")
            acl = self.acl(self.candidate, name)
            if acl is None:
                return "data-missing", f"access list {name} does not exist"
            rows = acl["access-list-seq-rule"]
            for entry in extended:
                if local(entry.tag) != "access-list-seq-rule":
                    continue
                operation = entry.get(f"{{{NC}}}operation")
                seq = next(c.text for c in entry if local(c.tag) == "sequence")
                existing = next((r for r in rows if r["sequence"] == seq), None)
                if operation == "create":
                    if existing:
                        return "data-exists", f"entry {seq} exists"
                    row: dict[str, Any] = {"sequence": seq}
                    for child in entry:
                        if local(child.tag) == "remark":
                            row["remark"] = child.text
                        elif local(child.tag) == "ace-rule":
                            row["ace-rule"] = {local(c.tag): ([None] if c.text is None else
                                                              int(c.text) if c.text.isdigit() and "port" in local(c.tag)
                                                              or local(c.tag).startswith(("dst-eq", "dst-range"))
                                                              else c.text) for c in child}
                    rows.append(row)
                    rows.sort(key=lambda r: int(r["sequence"]))
                elif operation in ("remove", "delete"):
                    if existing:
                        rows.remove(existing)
                    elif operation == "delete":
                        return "data-missing", f"entry {seq} does not exist"
        return None


def error(tag: str, message: str) -> dict[str, Any]:
    return {"ietf-restconf:errors": {"error": [{"error-type": "application", "error-tag": tag,
                                                "error-message": message}]}}


CONFIG = {"base_url": BASE, "username": "atrium", "wan_interface": "GigabitEthernet1/0/1", "hub_address": "10.0.99.10",
          "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"}


def connector(fake: FakeIosXe, **config: Any) -> CiscoIosXeConnector:
    """A new instance (= a new connection), as the hub builds one per call."""
    conn = CiscoIosXeConnector(clean_config(CiscoIosXeConnector, {**CONFIG, **config}), {"password": PASSWORD}, fake)
    conn.clock = lambda: fake.now
    return conn


@pytest.fixture
def fake() -> FakeIosXe:
    return FakeIosXe()


def snapshot(fake: FakeIosXe, **config: Any) -> dict[str, Any]:
    records, errors = normalize("network", run(connector(fake, **config).pull("network")))
    assert errors == [] and records[0]["errors"] == [], (errors, records[0]["errors"])
    return records[0]


def rule(record: dict[str, Any], rule_id: str) -> dict[str, Any]:
    return next(r for r in record["rules"] if r["id"] == rule_id)


def detail(result: dict[str, Any], name: str) -> str:
    return next(c["detail"] for c in result["checks"] if c["name"] == name)


def allow(src_zone="Vlan10", src="10.0.10.0/24", dst_zone="Vlan20", dst="10.0.20.0/24", services=None,
          change="chg_7", description="Users to app") -> dict[str, Any]:
    return {"op": "allow", "source": {"zone": src_zone, "cidrs": [src]}, "destination": {"zone": dst_zone, "cidrs": [dst]},
            "services": services or [{"proto": "tcp", "ports": "8443"}], "log": True, "description": description,
            "marker": f"atrium:{change}"}


# --------------------------------------------------------------------------------------
# reading
# --------------------------------------------------------------------------------------


def test_reads_svis_routed_interfaces_and_bound_acls(fake):
    record = snapshot(fake)
    assert record["kind"] == "switch" and record["external_id"] == "sw-core-1"
    assert record["device"] == {"vendor": "Cisco", "model": "C9300-24T", "version": "17.15.1", "hostname": "sw-core-1",
                                "management_address": "10.0.99.2", "serial": "FOC1234X0AB"}
    ifaces = {i["id"]: i for i in record["interfaces"]}
    assert set(ifaces) == {"GigabitEthernet0/0", "GigabitEthernet1/0/1", "Vlan10", "Vlan20", "Vlan30"}
    assert ifaces["Vlan20"]["name"] == "SERVERS" and ifaces["Vlan20"]["vlan"] == 20
    assert ifaces["Vlan20"]["subnets"] == ["10.0.20.0/24", "10.0.21.0/24"]
    assert ifaces["Vlan10"]["description"] == "Users <script>"  # device text kept as text (never HTML)
    assert ifaces["GigabitEthernet0/0"]["role"] == "mgmt" and ifaces["GigabitEthernet1/0/1"]["role"] == "wan"
    assert {"10.255.0.1", "10.0.99.2", "203.0.113.2"} <= set(record["self_addresses"])
    assert record["default_policy"] == {"inbound": "pass", "forward": "pass", "outbound": "pass"}

    web = rule(record, "USERS-IN:20")
    assert web["vendor_ref"] == "USERS-IN:20" and web["interfaces"] == ["Vlan10"] and web["direction"] == "in"
    assert web["source"]["cidrs"] == ["10.0.10.0/24"] and web["destination"]["cidrs"] == ["10.0.20.10/32"]
    assert {(s["proto"], s["ports"]) for s in web["services"]} == {("tcp", "80"), ("tcp", "443")}  # "www" is 80
    assert web["description"] == "Users may reach the web servers" and web["hits"] == 1532 and web["log"]
    dns = rule(record, "USERS-IN:30")
    assert dns["destination"]["aliases"] == ["DNS_SERVERS"] and dns["services"][0]["ports"] == "53"
    alias = next(a for a in record["aliases"] if a["name"] == "DNS_SERVERS")
    assert alias["resolved"] and sorted(alias["cidrs"]) == ["10.0.20.53/32", "10.0.21.0/24"]
    deny = rule(record, "USERS-IN:40")
    assert deny["action"] == "block" and deny["description"] == "keep users out of the rest"
    assert deny["destination"]["cidrs"] == ["10.0.0.0/8"]
    implicit = rule(record, "USERS-IN:implicit-deny")
    assert implicit["action"] == "block" and implicit["interfaces"] == ["Vlan10"]
    assert [r["id"] for r in record["rules"] if r["vendor_ref"].startswith("USERS-IN")] == [
        "USERS-IN:20", "USERS-IN:30", "USERS-IN:40", "USERS-IN:50", "USERS-IN:implicit-deny"]  # in sequence order

    assert rule(record, "WAN-IN:15")["services"] == [{"proto": "tcp", "ports": "1024-65535", "alias": None, "name": ""}]
    assert rule(record, "WAN-IN:25")["services"][0]["ports"] == "5000-5010"
    odd = rule(record, "WAN-IN:35")  # wildcard 0.0.255.0 is not a prefix: an unresolved alias (treated as any)
    assert odd["source"]["aliases"] == ["192.0.2.0 wildcard 0.0.255.0"]
    assert not next(a for a in record["aliases"] if a["name"] == odd["source"]["aliases"][0])["resolved"]
    out = rule(record, "SERVERS-OUT:10")
    assert out["interfaces"] == ["Vlan20"] and out["direction"] == "out"
    assert out["services"][0]["ports"] == "1-22,24-65535"  # neq telnet

    vty = rule(record, "VTY-MGMT:10")
    assert vty["destination"] == {**vty["destination"], "self": True} and vty["floating"]
    assert vty["source"]["cidrs"] == ["10.0.99.0/24"] and vty["services"][0]["ports"] == "22"
    https = rule(record, "http:no-access-class")  # no ip http access-class: any address reaches HTTPS
    assert https["source"]["any"] and https["services"] == [{"proto": "tcp", "ports": "443", "alias": None, "name": ""}]
    assert not any(r["id"].startswith("UNUSED-EXT") for r in record["rules"])
    notes = " | ".join(record["notes"])
    for expected in ("1 access list(s) are not bound", "2 interface(s) have no inbound ACL", "1 VLAN(s) have no SVI",
                     "source-port conditions", "TCP flag conditions ('established'", "IPv6 access lists are not read"):
        assert expected in notes, expected


def test_management_exposure_is_visible(fake):
    from hub.connectors.netmodel import exposes_management

    fake.running["line"]["vty"][1].pop("access-class")  # lines 5-15 accept SSH from anywhere
    fake.running["acl"]["extended"][1]["access-list-seq-rule"].insert(
        0, ace(5, action="permit", protocol="tcp", **{"any": [None], "dst-host-address": "203.0.113.2", "dst-eq": 22}))
    record = snapshot(fake)
    exposed = {r["id"] for r in record["rules"] if exposes_management(record, r)}
    assert {"vty:no-access-class", "http:no-access-class", "WAN-IN:5"} <= exposed
    assert "USERS-IN:20" not in exposed


def test_revision_follows_the_configuration_not_counters(fake):
    first = snapshot(fake)
    fake.counters[("USERS-IN", "20")] += 10
    fake.now += 60
    assert snapshot(fake)["revision"] == first["revision"]
    fake.running["acl"]["extended"][0]["access-list-seq-rule"][1]["ace-rule"]["dst-eq-port2"] = 8443
    assert snapshot(fake)["revision"] != first["revision"]


def test_router_kind_and_optional_reads(fake):
    fake.running["vlan"], fake.running["interface"]["Vlan"] = [], []
    fake.running["interface"]["GigabitEthernet"][1]["ip"]["access-group"]["in"]["acl"]["acl-name"] = "USERS-IN"
    fake.running["object-group"] = []
    fake.counters.clear()
    fake.fields_unsupported = True  # the oper read falls back to a plain GET
    record = snapshot(fake)
    assert record["kind"] == "router"
    assert next(a for a in record["aliases"] if a["name"] == "DNS_SERVERS")["resolved"] is False
    assert "hit counts are not available" in record["notes"]
    assert any("fields=" in path for _, path in fake.calls) and ("GET", "/restconf/data/Cisco-IOS-XE-interfaces-oper:"
                                                                         "interfaces") in fake.calls


def test_old_releases_are_refused(fake):
    fake.software = "Cisco IOS XE Software, Version 03.16.08.S"
    with pytest.raises(Exception) as caught:
        run(connector(fake).pull("network"))
    assert "IOS XE 16" in str(caught.value)


def test_helpers():
    assert parse_version("Cisco IOS XE Software, Version 17.09.04a") == (17, 9, 4)
    assert wildcard_cidr("10.1.2.3", "0.0.0.0") == "10.1.2.3/32"
    assert wildcard_cidr("10.1.2.0", "0.0.0.255") == "10.1.2.0/24"
    assert wildcard_cidr("10.0.0.0", "0.255.0.255") is None
    dev = Device({"interfaces": {}}, {}, "10.0.0.1")
    flags: set[str] = set()
    assert dev.services({"protocol": "tcp", "dst-lt": 1024}, flags) == [{"proto": "tcp", "ports": "1-1023"}]
    assert dev.services({"protocol": "tcp", "dst-eq": "no-such-name"}, flags)[0]["alias"] == "port no-such-name"
    assert dev.services({"protocol": "ip"}, flags) is None
    assert dev.services({"protocol": "ahp"}, flags) == [{"proto": "ah"}]


# --------------------------------------------------------------------------------------
# test()
# --------------------------------------------------------------------------------------


def test_test_reports_each_step_and_the_write_capability(fake):
    result = run(connector(fake).test())
    assert result["ok"], result
    names = [c["name"] for c in result["checks"]]
    assert names[:6] == ["reachability", "tls", "authentication", "privileges", "version", "api_features"]
    assert result["network_write"] == {"ops": ["allow"], "rollback": "commit_confirm", "window_s": 120}
    assert "privilege 15" in detail(result, "privileges") and "can write" in detail(result, "privileges")
    assert "17.15.1" in detail(result, "version") and "supported" in detail(result, "version")
    assert "confirmed commit 1.1" in detail(result, "api_features") and "hit counters: yes" in detail(result, "api_features")
    assert "in sync" in detail(result, "api_features")
    assert "access list(s) on the management path" in detail(result, "management_guard")
    assert PASSWORD not in json.dumps(result)
    assert fake.netconf.targets[0].port == 830 and fake.netconf.targets[0].host == "10.0.99.2"


@pytest.mark.parametrize("caps,expected", [
    ([c for c in CAPS_WRITE if "candidate" not in c], "candidate-datastore"),
    ([c for c in CAPS_WRITE if not c.endswith("confirmed-commit:1.1")], "confirmed commit 1.1"),
])
def test_test_without_safe_netconf_is_read_only(fake, caps, expected):
    fake.caps = caps
    result = run(connector(fake).test())
    assert result["ok"] and result["network_write"] is None
    assert expected in detail(result, "api_features") and "(read only)" in result["detail"]


def test_test_read_only_setting_and_failures(fake):
    result = run(connector(fake, read_only=True).test())
    assert result["ok"] and result["network_write"] is None and not fake.netconf.targets
    fake.netconf_fail = True
    result = run(connector(fake).test())
    assert result["ok"] and result["network_write"] is None and "cannot connect to NETCONF" in detail(result, "api_features")
    fake.netconf_fail = False
    fake.unreachable = True
    result = run(connector(fake).test())
    assert not result["ok"] and result["checks"][0]["name"] == "reachability" and not result["checks"][0]["ok"]
    fake.unreachable, fake.tls_untrusted = False, True
    result = run(connector(fake).test())
    assert not result["ok"] and detail(result, "tls").startswith("The device's TLS certificate is not trusted")
    fake.tls_untrusted = False
    bad = CiscoIosXeConnector(clean_config(CiscoIosXeConnector, CONFIG), {"password": "wrong-password"}, fake)
    result = run(bad.test())
    assert not result["ok"] and not next(c for c in result["checks"] if c["name"] == "authentication")["ok"]
    low = CiscoIosXeConnector(clean_config(CiscoIosXeConnector, {**CONFIG, "username": "lowpriv"}),
                              {"password": PASSWORD}, fake)
    result = run(low.test())
    assert not result["ok"] and "privilege-15" in detail(result, "privileges")
    assert not next(c for c in result["checks"] if c["name"] == "privileges")["ok"]
    fake.software = "Cisco IOS XE Software, Version 03.16.08.S"
    result = run(connector(fake).test())
    assert not result["ok"] and "IOS XE 16 or later" in detail(result, "version")


def test_a_missing_ca_file_is_a_tls_problem():
    conn = CiscoIosXeConnector({**CONFIG, "ca_file": "/nonexistent/iosxe-ca.pem"}, {"password": PASSWORD})
    result = run(conn.test())
    assert result["ok"] is False and result["checks"][0]["name"] == "tls"
    assert "/nonexistent/iosxe-ca.pem" in result["detail"]


def test_config_validation_and_detection():
    cleaned = clean_config(CiscoIosXeConnector, {"base_url": "https://sw1.example.net:8443/restconf/"})
    assert cleaned["base_url"] == "https://sw1.example.net:8443" and cleaned["netconf_port"] == 830
    for bad, message in (({"base_url": "http://10.0.0.1"}, "https://"),
                         ({"base_url": "https://admin:pw@10.0.0.1"}, "credentials"),
                         ({"base_url": "https://10.0.0.1/api"}, "device address only"),
                         ({"base_url": BASE, "hub_address": "hub.local"}, "IP address"),
                         ({"base_url": BASE, "confirm_timeout": 5}, "60-600"),
                         ({"base_url": BASE, "ca_file": "certs/ca.pem"}, "absolute"),
                         ({"base_url": BASE, "host_key": "not a key"}, "public key line"),
                         ({"base_url": BASE, "wan_interface": "eth0; reload"}, "interface name")):
        with pytest.raises(ValueError, match=message):
            clean_config(CiscoIosXeConnector, bad)
    assert CiscoIosXeConnector.endpoint({**CONFIG}) != CiscoIosXeConnector.endpoint({**CONFIG, "host_key": None})
    assert CiscoIosXeConnector.endpoint(CONFIG) != CiscoIosXeConnector.endpoint({**CONFIG, "verify_tls": False})
    from hub.models import Manifest, Tool

    tool = Tool(id="sw1", name="Core switch (IOS-XE)", source_type="saas", source="", status="ready",
                manifest=Manifest(id="sw1", name="Core switch", kind="saas"))
    assert CiscoIosXeConnector.detect(tool) == 90
    assert CiscoIosXeConnector.detect(tool.model_copy(update={"name": "Cisco Catalyst 9300", "id": "cat"})) == 60


def test_options_list_routed_interfaces(fake):
    choices = run(connector(fake).options("wan_interface"))
    assert {c["value"] for c in choices} == {"GigabitEthernet0/0", "GigabitEthernet1/0/1"}


# --------------------------------------------------------------------------------------
# changes
# --------------------------------------------------------------------------------------


def test_preview_places_the_entry_after_the_leading_permits(fake):
    record = snapshot(fake)
    preview = run(connector(fake).preview_change(parse_ops([allow()]), record))
    assert preview["problems"] == []
    step = preview["steps"][0]
    assert step["kind"] == "add_rule" and "sequence 32" in step["position"]  # 31 remark + 32, before remark 35
    assert "permit tcp 10.0.10.0 0.0.0.255 10.0.20.0 0.0.0.255 eq 8443 log" in step["detail"]
    assert any("reverts the change by itself after 120 s" in n for n in preview["notes"])
    assert fake.rpcs and all(op != "edit-config" for _, op in fake.rpcs)  # a preview changes nothing


@pytest.mark.parametrize("op,problem", [
    (allow(src_zone="Vlan30", src="10.0.30.0/24"), "no inbound ACL"),
    (allow(src_zone="GigabitEthernet0/0", src="10.0.99.0/24"), "management path"),
    (allow(src_zone="Vlan99"), "no routed interface or SVI"),
    (allow(services=[{"proto": "tcp", "ports": "443"}, {"proto": "udp", "ports": "53"}]), "one protocol"),
    (allow(services=[{"proto": "tcp", "ports": "80,443"}]), "up to 10 single ports"),
    ({**allow(), "source": {"zone": "Vlan10", "cidrs": ["10.0.10.0/25", "10.0.10.128/25"]}}, "one source"),
    ({"op": "disable_rules", "rules": [{"id": "USERS-IN:20"}]}, "cannot be disabled"),
])
def test_preview_problems(fake, op, problem):
    preview = run(connector(fake).preview_change(parse_ops([op]), snapshot(fake)))
    assert any(problem in p for p in preview["problems"]), preview["problems"]


def test_the_vty_acl_is_never_changed(fake):
    fake.running["interface"]["Vlan"][0]["ip"]["access-group"]["in"]["acl"]["acl-name"] = "MGMT-IN"
    fake.running["acl"]["extended"].append({"name": "MGMT-IN", "access-list-seq-rule": [
        ace(10, action="permit", protocol="ip", **{"any": [None], "dst-any": [None]})]})
    fake.running["line"]["vty"][0]["access-class"]["acccess-list"][0]["access-list"] = "MGMT-IN"
    record = snapshot(fake)
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(parse_ops([allow()]), record["revision"], None))
    assert caught.value.code == "lockout" and caught.value.state == "unchanged" and "VTY" in caught.value.message
    assert not any(op == "edit-config" for _, op in fake.rpcs)


def test_sequence_numbers_for_the_new_entries():
    position = CiscoIosXeConnector._position
    permit = {"ace-rule": {"action": "permit"}}
    assert position([], set()) == (10, 11)  # an empty ACL (it denies everything)
    rows = [{"sequence": "10", **permit}, {"sequence": "20", **permit}]
    assert position(rows, {10, 20}) == (21, 22)  # only permits: after them
    rows = [{"sequence": "10", "ace-rule": {"action": "deny"}}]
    assert position(rows, {10}) == (1, 2)
    rows = [{"sequence": "10", **permit}, {"sequence": "12", "ace-rule": {"action": "deny"}}]
    assert position(rows, {10, 12}) is None  # no room: resequence first
    rows = [{"sequence": "10", **permit}, {"sequence": "19", "remark": "the deny below"},
            {"sequence": "20", "ace-rule": {"action": "deny"}}]
    assert position(rows, {10, 19, 20}) == (11, 12)  # before the remark that describes the deny
    assert position(rows, {10, 11, 12, 19, 20}) == (13, 14)  # a second entry of the same change


def test_no_room_before_the_first_deny_is_a_problem(fake):
    rows = fake.acl(fake.running, "USERS-IN")["access-list-seq-rule"]
    rows.insert(3, {"sequence": "31", "remark": "taken"})
    preview = run(connector(fake).preview_change(parse_ops([allow()]), snapshot(fake)))
    assert any("resequence" in p for p in preview["problems"])


def test_apply_verify_confirm_saves_and_persists_across_connections(fake):
    record = snapshot(fake)
    ops = parse_ops([allow(description="Users <app> & co")])
    applied = run(connector(fake).apply_change(ops, record["revision"], None))
    assert applied["rollback_until"] == START + 120 and applied["created"] == [
        {"op": 0, "id": "USERS-IN:32", "vendor_ref": "USERS-IN:32"}]
    assert fake.pending and fake.lock is None and fake.startup is None
    assert [op for _, op in fake.rpcs] == ["lock", "discard-changes", "edit-config", "validate", "commit", "unlock",
                                           "close-session"]
    rows = fake.rows("USERS-IN")
    assert rows["31"] == {"sequence": "31", "remark": "atrium:chg_7 Users <app> & co"}  # escaped in the XML
    assert rows["32"]["ace-rule"] == {"action": "permit", "protocol": "tcp", "ipv4-address": "10.0.10.0",
                                      "mask": "0.0.0.255", "dest-ipv4-address": "10.0.20.0",
                                      "dest-mask": "0.0.0.255", "dst-eq": 8443, "log": [None]}
    after = snapshot(fake)  # the hub verifies over a new connection
    assert ops_applied(after, ops) == []
    created = rule(after, "USERS-IN:32")
    assert created["marker"] == "chg_7" and created["interfaces"] == ["Vlan10"]
    assert [r["id"] for r in after["rules"] if r["vendor_ref"].startswith("USERS-IN")][:3] == [
        "USERS-IN:20", "USERS-IN:30", "USERS-IN:32"]
    fake.now += 60
    confirmed = run(connector(fake).confirm_change(applied["token"]))
    assert confirmed["confirmed"] and "saved to startup-config" in confirmed["notes"]
    assert fake.pending is None and fake.startup == fake.running
    fake.now += 600
    assert ops_applied(snapshot(fake), ops) == []  # the timer no longer reverts it
    assert len(fake.netconf.targets) == 2  # apply and confirm: one NETCONF connection each


def test_unconfirmed_change_reverts_by_itself(fake):
    record = snapshot(fake)
    ops = parse_ops([allow()])
    applied = run(connector(fake).apply_change(ops, record["revision"], None))
    fake.now += 121
    assert ops_reverted(record, snapshot(fake), ops) == []
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).confirm_change(applied["token"]))
    assert caught.value.state == "rolled_back" and "reverted" in caught.value.message
    rolled = run(connector(fake).rollback_change(applied["token"], None))
    assert rolled["rolled_back"] and "already reverted" in rolled["notes"][0]


def test_rollback_cancels_the_pending_commit(fake):
    record = snapshot(fake)
    ops = parse_ops([allow()])
    applied = run(connector(fake).apply_change(ops, record["revision"], None))
    rolled = run(connector(fake).rollback_change(applied["token"], None))
    assert rolled == {"rolled_back": True, "method": "commit_confirm", "notes": ["the confirmed commit was cancelled"]}
    assert fake.pending is None and ops_reverted(record, snapshot(fake), ops) == []


def test_rollback_after_confirm_removes_exactly_the_created_entries(fake):
    record = snapshot(fake)
    ops = parse_ops([allow(), allow(services=[{"proto": "icmp"}], change="chg_7", dst="10.0.20.10/32")])
    applied = run(connector(fake).apply_change(ops, record["revision"], None))
    assert [c["id"] for c in applied["created"]] == ["USERS-IN:32", "USERS-IN:34"]
    run(connector(fake).confirm_change(applied["token"]))
    rolled = run(connector(fake).rollback_change(applied["token"], None))
    assert rolled["method"] == "inverse_ops"
    assert set(fake.rows("USERS-IN")) == {"10", "20", "30", "35", "40", "50"}
    assert ops_reverted(record, snapshot(fake), ops) == []


def test_a_revert_proposal_needs_disable_rules_which_ios_xe_does_not_offer(fake):
    """An ACE has no disabled state: the hub's generic revert (inverse_ops) cannot be applied here - a revert of an
    applied allow goes through restoring the pre-change backup instead (see the module docstring)."""
    record = snapshot(fake)
    ops = parse_ops([allow()])
    applied = run(connector(fake).apply_change(ops, record["revision"], None))
    run(connector(fake).confirm_change(applied["token"]))
    assert connector(fake).write_capability()["ops"] == ["allow"]
    inverse = inverse_ops(ops, applied)
    assert inverse == [{"op": "disable_rules", "rules": [{"id": "USERS-IN:32", "vendor_ref": "USERS-IN:32"}]}]
    preview = run(connector(fake).preview_change(inverse, snapshot(fake)))
    assert any("cannot be disabled" in p for p in preview["problems"])


def test_rollback_refuses_entries_that_lost_the_marker(fake):
    record = snapshot(fake)
    applied = run(connector(fake).apply_change(parse_ops([allow()]), record["revision"], None))
    run(connector(fake).confirm_change(applied["token"]))
    fake.rows("USERS-IN")["31"]["remark"] = "someone else's entry now"
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).rollback_change(applied["token"], None))
    assert caught.value.state == "applied" and "32" in fake.rows("USERS-IN")


def test_stale_locked_refused_and_broken_commits(fake):
    record = snapshot(fake)
    ops = parse_ops([allow()])
    fake.running["hostname"] = "renamed"
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(ops, record["revision"], None))
    assert caught.value.code == "stale" and caught.value.state == "unchanged" and fake.lock is None
    record = snapshot(fake)
    fake.lock = 99  # another NETCONF session holds the candidate
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(ops, record["revision"], None))
    assert caught.value.state == "unchanged" and "locked by another session" in caught.value.message
    fake.candidate["hostname"] = "left over"  # an earlier session ended without committing or discarding
    fake.lock = None
    fake.refuse_edit = "%Invalid ACE"
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(ops, record["revision"], None))
    assert caught.value.state == "unchanged" and "%Invalid ACE" in caught.value.message
    assert fake.candidate == fake.running and fake.lock is None and fake.pending is None
    fake.refuse_edit = None
    fake.candidate["hostname"] = "left over"
    applied = run(connector(fake).apply_change(ops, record["revision"], None))  # leftovers are discarded first
    assert fake.running["hostname"] == "renamed" and "32" in fake.rows("USERS-IN")
    run(connector(fake).rollback_change(applied["token"], None))
    fake.syncing = True
    with pytest.raises(ChangeError, match="syncing"):
        run(connector(fake).apply_change(ops, record["revision"], None))
    fake.syncing = False
    fake.caps = [c for c in CAPS_WRITE if "candidate" not in c]
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(ops, record["revision"], None))
    assert caught.value.code == "unsupported"
    fake.caps = list(CAPS_WRITE)
    fake.lose_session_on_commit = True
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(ops, record["revision"], None))
    assert caught.value.state == "unknown" and "reverts by itself within 120 s" in caught.value.message
    assert fake.pending is not None  # the commit went through: the device's timer protects it
    fake.now += 121
    fake.tick()
    assert fake.pending is None and "31" not in fake.rows("USERS-IN")
    with pytest.raises(ChangeError) as caught:
        run(connector(fake, read_only=True).apply_change(ops, record["revision"], None))
    assert caught.value.code == "unsupported"


def test_write_methods_are_not_actions(fake):
    from hub.connectors.base import ConnectorError

    assert CiscoIosXeConnector.actions == set()
    for name in ("backup", "apply_change", "confirm_change", "rollback_change", "restore_backup", "allow"):
        with pytest.raises(ConnectorError):
            run(connector(fake).action(name, {}))
    assert not fake.rpcs and not fake.flash


def test_tokens_are_validated(fake):
    for token in ("garbage", "iosxe1:" + base64.urlsafe_b64encode(b'{"persist": "x"}').decode(),
                  "iosxe1:" + base64.urlsafe_b64encode(json.dumps(
                      {"persist": "0" * 32, "until": 1, "entries": [["X; reload", 1, 2, "c"]]}).encode()).decode()):
        with pytest.raises(ChangeError) as caught:
            run(connector(fake).confirm_change(token))
        assert caught.value.code == "invalid"


# --------------------------------------------------------------------------------------
# backups
# --------------------------------------------------------------------------------------


def test_backup_keeps_the_full_configuration_on_the_device_and_restores_it(fake):
    backup = run(connector(fake).backup())
    assert backup["format"] == "text" and SECRET_HASH in backup["content"]
    assert re.fullmatch(r"bootflash:atrium-[0-9a-f]{16}\.cfg", backup["device_backup_id"])
    assert backup["device_backup_id"] in fake.flash and backup["revision"] == snapshot(fake)["revision"]
    again = run(connector(fake).backup())  # same configuration: same file, replaced
    assert again["device_backup_id"] == backup["device_backup_id"] and len(fake.flash) == 1
    record = snapshot(fake)
    applied = run(connector(fake).apply_change(parse_ops([allow()]), record["revision"], None))
    run(connector(fake).confirm_change(applied["token"]))
    content = backup["content"].encode()
    saved = Backup(backup_id="b1", content=content, sha256="x", taken_at=START, format="text",
                   device_backup_id=backup["device_backup_id"], revision=backup["revision"])
    restored = run(connector(fake).restore_backup(saved))
    assert restored["restored"] and "31" not in fake.rows("USERS-IN")
    assert snapshot(fake)["revision"] == record["revision"]
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).restore_backup(Backup(backup_id="b2", content=content, sha256="x", taken_at=START,
                                                  device_backup_id="flash:../../nvram:startup-config")))
    assert caught.value.code == "unsupported" and caught.value.state == "unchanged"
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).restore_backup(Backup(backup_id="b3", content=content, sha256="x", taken_at=START,
                                                  device_backup_id="bootflash:atrium-0000000000000000.cfg")))
    assert caught.value.state == "unchanged" and "No such file" in caught.value.message
    fake.copy_fails = True
    fake.running["hostname"] = "other"
    with pytest.raises(Exception, match="could not keep the full configuration"):
        run(connector(fake).backup())


def test_errors_never_carry_secrets(fake):
    fake.refuse_edit = f"bad {PASSWORD}"
    record = snapshot(fake)
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(parse_ops([allow()]), record["revision"], None))
    # the device's own text is passed on shortened; the connector masks its own secrets in what it raises
    text = json.dumps(caught.value.as_dict())
    assert "bad ***" in text and PASSWORD not in text
    result = run(connector(fake).test())
    assert PASSWORD not in json.dumps(result) and SECRET_HASH not in json.dumps(snapshot(fake))


# --------------------------------------------------------------------------------------
# NETCONF framing and the real SSH transport
# --------------------------------------------------------------------------------------


def test_framing_end_of_message_chunked_and_hostile_input():
    async def go(chunks: list[bytes], chunked: bool = True) -> Any:
        reader = Pipe()
        for c in chunks:
            reader.write(c)
        reader.close()
        session = NetconfSession(reader, Pipe(), label="t", timeout=2, max_message=1000)
        session.chunked = chunked
        return await session.receive()

    assert run(go([b"\n#4\nabcd\n#3\nefg\n##\n"])) == b"abcdefg"
    assert run(go([b"\n#4", b"\nab", b"cd\n##", b"\n"])) == b"abcd"  # split anywhere
    assert run(go([b"<x/>]]>", b"]]>rest"], chunked=False)) == b"<x/>"
    for bad, message in (([b"\n#0\n\n##\n"], "framing"), ([b"\n#x\nab\n##\n"], "framing"),
                         ([b"\n#5000\n" + b"a" * 5000 + b"\n##\n"], "larger than"), ([b"\n#4\nab"], "closed")):
        with pytest.raises(NetconfError, match=message):
            run(go(bad))
    with pytest.raises(NetconfError, match="DOCTYPE"):
        from hub.connectors.cisco_iosxe import parse_xml
        parse_xml(b'<!DOCTYPE x [<!ENTITY a "aaaa">]><rpc-reply>&a;</rpc-reply>')


asyncssh = pytest.importorskip("asyncssh")


class _Server(asyncssh.SSHServer):
    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username == "atrium" and password == PASSWORD


async def _with_ssh(fake: FakeIosXe, check, *, pin: str = "right"):
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    other = asyncssh.generate_private_key("ssh-ed25519")
    sessions = iter(range(100, 200))

    async def handle(process) -> None:
        if process.subsystem != "netconf":
            process.exit(1)
            return
        await fake.serve(process.stdin, process.stdout, next(sessions))
        process.exit(0)

    server = await asyncssh.create_server(_Server, "127.0.0.1", 0, server_host_keys=[host_key], process_factory=handle,
                                          encoding=None)
    try:
        port = server.sockets[0].getsockname()[1]
        pinned = {"right": host_key, "wrong": other}[pin]
        return await check(port, pinned.export_public_key().decode().strip())
    finally:
        server.close()


def test_real_ssh_netconf_session_applies_and_confirms(fake):
    class RestOnly(httpx.MockTransport):  # RESTCONF stays fake; NETCONF goes over real SSH to 127.0.0.1
        pass

    rest = RestOnly(fake.route)

    async def check(port: int, key: str):
        def make() -> CiscoIosXeConnector:
            conn = CiscoIosXeConnector(clean_config(CiscoIosXeConnector, {**CONFIG, "base_url": "https://127.0.0.1",
                                                                          "netconf_port": port, "host_key": key}),
                                       {"password": PASSWORD}, rest)
            conn.clock = lambda: fake.now
            return conn

        record = normalize("network", await make().pull("network"))[0][0]
        tested = await make().test()
        applied = await make().apply_change(parse_ops([allow()]), record["revision"], None)
        confirmed = await make().confirm_change(applied["token"])
        return tested, applied, confirmed

    tested, applied, confirmed = run(_with_ssh(fake, check))
    assert tested["network_write"]["rollback"] == "commit_confirm", tested
    assert applied["created"][0]["id"] == "USERS-IN:32" and confirmed["confirmed"]
    assert fake.pending is None and "32" in fake.rows("USERS-IN")


def test_real_ssh_refuses_an_unknown_host_key(fake):
    async def check(port: int, key: str):
        conn = CiscoIosXeConnector(clean_config(CiscoIosXeConnector, {**CONFIG, "base_url": "https://127.0.0.1",
                                                                      "netconf_port": port, "host_key": key}),
                                   {"password": PASSWORD}, httpx.MockTransport(fake.route))
        return await conn.test()

    result = run(_with_ssh(fake, check, pin="wrong"))
    assert result["ok"] and result["network_write"] is None
    assert "host key is not trusted" in detail(result, "api_features")


# --------------------------------------------------------------------------------------
# through the hub
# --------------------------------------------------------------------------------------


def test_through_the_hub(client, monkeypatch, wait_for):
    from hub.models import Manifest, Tool

    fake = FakeIosXe()
    hub = client.app.state.hub
    monkeypatch.setattr(hub, "connector_transport", fake, raising=False)
    tool = Tool(id="sw1", name="Core switch IOS-XE", source_type="saas", source="https://www.cisco.com", status="ready",
                manifest=Manifest(id="sw1", name="Core switch IOS-XE", kind="saas"))
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    described = next(c for c in client.get("/api/connectors").json() if c["kind"] == "cisco_iosxe")
    assert described["network_write"]["rollback"] == "commit_confirm" and described["can_backup"]
    response = client.put("/api/tools/sw1/connection", json={"kind": "cisco_iosxe", "config": {
        "base_url": BASE, "username": "atrium", "host_key": CONFIG["host_key"]}, "secrets": {"password": PASSWORD}})
    assert response.status_code == 200, response.text
    tested = client.post("/api/tools/sw1/connection/test").json()
    assert tested["ok"] and tested["network_write"]["rollback"] == "commit_confirm", tested
    assert PASSWORD not in json.dumps(tested)
    approval = wait_for(lambda: next((a for a in client.get("/api/approvals?status=pending").json()
                                      if a["kind"] == "flow" and a["payload"]["tool_id"] == "sw1"), None))
    assert client.post(f"/api/approvals/{approval['id']}", json={"approve": True}).status_code == 200
    wait_for(lambda: next((f for f in client.get("/api/flows?tool_id=sw1").json()
                           if f["domain"] == "network" and f["status"] == "enabled"), None))
    refreshed = client.post("/api/network/devices/sw1/refresh").json()
    assert refreshed["results"][0]["ok"], refreshed
    device = client.get("/api/network/devices/sw1").json()
    assert device["record"]["device"]["vendor"] == "Cisco" and device["record"]["kind"] == "switch"
    assert any(r["id"] == "USERS-IN:20" for r in device["record"]["rules"])
    assert PASSWORD not in json.dumps(device) and SECRET_HASH not in json.dumps(device)
    taken = client.post("/api/network/devices/sw1/backups")
    assert taken.status_code == 201, taken.text
    assert SECRET_HASH not in taken.text and fake.flash
