"""The OpenVAS / Greenbone connector against a fake gvmd that speaks GMP over plain TCP and TLS on 127.0.0.1 - no
real scanner and no outside network."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import socket
import ssl
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

import pytest

from hub.connectors import build, catalog
from hub.connectors.base import ConnectorError, normalize
from hub.connectors.openvas import ALL_IANA_TCP, FULL_AND_FAST, OPENVAS_DEFAULT, OpenVasConnector, pick_host
from hub.models import Manifest, Tool

PASSWORD = "gvm-p<a>&\"ss'word-42"
CVE_SCANNER = "6acd0832-df90-11e4-b9d5-28d24461215b"
EMPTY_CONFIG = "085569ce-73ed-11df-83c3-002264764cea"
POLICY = "c4b7c0cb-6502-4809-b034-8e635311b3e6"
NMAP_PORTS = "730ef368-57e2-11e1-a90f-406186ea4fc5"
OID = "1.3.6.1.4.1.25623.1.0."


def run(coro):
    return asyncio.run(coro)


def iso(at: float) -> str:
    return datetime.fromtimestamp(at, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_id() -> str:
    return str(uuid.uuid4())


def terms(text: str | None) -> dict[str, tuple[str, str]]:
    out = {}
    for token in (text or "").split():
        match = re.match(r"^([a-z_-]+)(=|>|<)(.*)$", token)
        if match:
            out[match.group(1)] = (match.group(2), match.group(3))
    return out


def answer(tag: str, body: str = "", status: str = "200", text: str = "OK", **attrs: str) -> str:
    extra = "".join(f" {k}={quoteattr(v)}" for k, v in attrs.items())
    return f'<{tag}_response status="{status}" status_text={quoteattr(text)}{extra}>{body}</{tag}_response>'


class FakeGmp:
    """A tiny gvmd: answers the GMP commands the connector sends from in-memory state, on a loop in its own thread."""

    def __init__(self, tls: ssl.SSLContext | None = None):
        self.tls = tls
        self.users = {"admin": PASSWORD}
        self.role = "Admin"
        self.version = "22.5"
        self.configs = [{"id": FULL_AND_FAST, "name": "Full and fast", "nvts": "95000", "usage": "scan"},
                        {"id": EMPTY_CONFIG, "name": "Empty", "nvts": "0", "usage": "scan"},
                        {"id": POLICY, "name": "IT-Grundschutz", "nvts": "300", "usage": "policy"}]
        self.scanners = [{"id": OPENVAS_DEFAULT, "name": "OpenVAS Default", "type": "2",
                           "host": "/run/ospd/ospd-openvas.sock", "port": "0"},
                         {"id": CVE_SCANNER, "name": "CVE", "type": "3", "host": "", "port": "0"}]
        self.port_lists = [{"id": ALL_IANA_TCP, "name": "All IANA assigned TCP"},
                           {"id": NMAP_PORTS, "name": "All TCP and Nmap top 100 UDP"}]
        self.feed_syncing = False
        self.scanner_online = True
        self.targets: dict[str, dict] = {}
        self.tasks: dict[str, dict] = {}
        self.results: list[dict] = []
        self.requests: list[ET.Element] = []
        self.fail: dict[str, tuple[str, str]] = {}
        self.max_rows = 1000  # gvmd's "Max Rows Per Page"
        self.raw_reply: bytes | None = None
        self.lie_about_count = 0

    # -- running ---------------------------------------------------------------------

    def __enter__(self) -> "FakeGmp":
        self.loop = asyncio.new_event_loop()
        ready = threading.Event()

        def serve():
            asyncio.set_event_loop(self.loop)
            self.server = self.loop.run_until_complete(asyncio.start_server(self.handle, "127.0.0.1", 0, ssl=self.tls))
            self.port = self.server.sockets[0].getsockname()[1]
            ready.set()
            self.loop.run_forever()

        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()
        assert ready.wait(5)
        return self

    def __exit__(self, *exc) -> None:
        async def stop():
            self.server.close()
            if hasattr(self.server, "close_clients"):
                self.server.close_clients()
            await asyncio.wait_for(self.server.wait_closed(), 3)

        try:
            asyncio.run_coroutine_threadsafe(stop(), self.loop).result(5)
        except Exception:
            pass
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        if not self.loop.is_running():
            self.loop.close()

    def config(self, **overrides) -> dict:
        return {"connection_type": "tcp", "host": "127.0.0.1", "port": self.port, "username": "admin", **overrides}

    def connector(self, password: str = PASSWORD, **overrides) -> OpenVasConnector:
        return build("openvas", self.config(**overrides), {"password": password})  # type: ignore[return-value]

    def sent(self, tag: str) -> list[ET.Element]:
        return [r for r in self.requests if r.tag == tag]

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        authed = False
        try:
            while True:
                command = await self.read_command(reader)
                if command is None:
                    break
                self.requests.append(command)
                if self.raw_reply is not None:
                    writer.write(self.raw_reply)
                    await writer.drain()
                    break
                reply = self.answer(command, authed)
                authed = authed or (command.tag == "authenticate" and 'status="200"' in reply)
                writer.write(reply.encode("utf-8"))
                await writer.drain()
        except (ConnectionError, OSError, ET.ParseError):
            pass
        finally:
            writer.close()

    @staticmethod
    async def read_command(reader: asyncio.StreamReader) -> ET.Element | None:
        parser = ET.XMLPullParser(events=("start", "end"))
        depth, root = 0, None
        while True:
            chunk = await reader.read(65536)
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

    # -- state helpers ---------------------------------------------------------------

    def add_task(self, name: str, hosts: str, *, at: float | None = None, created: float | None = None,
                 usage: str = "scan") -> tuple[str, str | None]:
        """A scan task, finished at `at` (when given) with its report; returns (task id, report id)."""
        target_id, task_id = new_id(), new_id()
        self.targets[target_id] = {"name": f"{name} target", "hosts": hosts, "port_list": ALL_IANA_TCP, "alive": None}
        report_id = new_id() if at is not None else None
        self.tasks[task_id] = {"name": name, "target": target_id, "config": FULL_AND_FAST, "scanner": OPENVAS_DEFAULT,
                               "status": "Done" if at is not None else "New", "progress": "-1", "usage": usage,
                               "last_report": report_id, "last_at": iso(at) if at is not None else None, "current": None,
                               "created": iso(created if created is not None else (at or time.time()) - 60)}
        return task_id, report_id

    def finish(self, task_id: str, results: list[dict], at: float | None = None) -> str:
        task = self.tasks[task_id]
        report_id = task["current"] or new_id()
        task.update(status="Done", progress="-1", last_report=report_id, last_at=iso(at or time.time()), current=None)
        for result in results:
            self.results.append({**result, "report_id": report_id, "task_id": task_id})
        return report_id

    def add_results(self, task_id: str, report_id: str, results: list[dict]) -> None:
        for result in results:
            self.results.append({**result, "report_id": report_id, "task_id": task_id})

    # -- answers ---------------------------------------------------------------------

    def page(self, items: list, filter_text: str | None) -> list:
        t = terms(filter_text)
        first = int(t.get("first", ("=", "1"))[1])
        rows = int(t.get("rows", ("=", "10"))[1])
        rows = self.max_rows if rows < 0 else min(rows, self.max_rows)
        return items[first - 1:first - 1 + rows]

    @staticmethod
    def count(tag: str, total: int, shown: int) -> str:
        return f"<{tag}_count>{total}<filtered>{total}</filtered><page>{shown}</page></{tag}_count>"

    def answer(self, el: ET.Element, authed: bool) -> str:
        tag = el.tag
        if tag in self.fail:
            status, text = self.fail[tag]
            return answer(tag, status=status, text=text)
        if tag == "get_version":
            return answer(tag, f"<version>{self.version}</version>")
        if tag == "authenticate":
            user, password = el.findtext("credentials/username"), el.findtext("credentials/password")
            if self.users.get(user or "") != password:
                return answer(tag, status="400", text="Authentication failed")
            return answer(tag, f"<role>{self.role}</role><timezone>UTC</timezone>")
        if not authed:
            return answer(tag, status="401", text="Authenticate first")
        handler = getattr(self, f"do_{tag}", None)
        if handler is None:
            return answer(tag, status="400", text=f"Bogus command name {tag}")
        return handler(el)

    def _listing(self, el: ET.Element, tag: str, items: list[dict], render, id_attr: str) -> str:
        wanted = el.get(id_attr)
        if wanted:
            found = [i for i in items if i["id"] == wanted]
            if not found:
                return answer(el.tag, status="404", text=f"Failed to find {tag} '{wanted}'")
            return answer(el.tag, render(found[0]))
        shown = self.page(items, el.get("filter"))
        return answer(el.tag, "".join(render(i) for i in shown) + self.count(tag, len(items), len(shown)))

    def do_get_configs(self, el):
        items = [c for c in self.configs if not el.get("usage_type") or c["usage"] == el.get("usage_type")]
        return self._listing(el, "config", items, lambda c: (
            f'<config id="{c["id"]}"><name>{escape(c["name"])}</name><nvt_count>{c["nvts"]}<growing>1</growing>'
            f'</nvt_count><usage_type>{c["usage"]}</usage_type></config>'), "config_id")

    def do_get_scanners(self, el):
        return self._listing(el, "scanner", self.scanners, lambda s: (
            f'<scanner id="{s["id"]}"><name>{escape(s["name"])}</name><type>{s["type"]}</type>'
            f'<host>{escape(s.get("host") or "")}</host><port>{s.get("port") or 0}</port></scanner>'), "scanner_id")

    def do_modify_scanner(self, el):
        scanner = next((s for s in self.scanners if s["id"] == el.get("scanner_id")), None)
        if scanner is None:
            return answer(el.tag, status="404", text="Failed to find scanner")
        host = el.findtext("host")
        if host is not None:
            scanner["host"] = host
        return answer(el.tag)

    def do_get_port_lists(self, el):
        return self._listing(el, "port_list", self.port_lists, lambda p: (
            f'<port_list id="{p["id"]}"><name>{escape(p["name"])}</name></port_list>'), "port_list_id")

    def do_verify_scanner(self, el):
        if not self.scanner_online:
            return answer(el.tag, status="503", text="Service unavailable")
        return answer(el.tag, "<version>OTP/2.0</version>")

    def do_get_feeds(self, el):
        syncing = "<currently_syncing><timestamp>now</timestamp></currently_syncing>" if self.feed_syncing else ""
        return answer(el.tag, f"<feed><type>NVT</type><name>Greenbone Community Feed</name><version>202610090601</version>"
                              f"<description>x</description>{syncing}</feed>")

    def task_xml(self, task_id: str) -> str:
        t = self.tasks[task_id]
        last = (f'<last_report><report id="{t["last_report"]}"><timestamp>{t["last_at"]}</timestamp>'
                f'<scan_end>{t["last_at"]}</scan_end></report></last_report>' if t["last_report"] else "")
        current = (f'<current_report><report id="{t["current"]}"><timestamp>{iso(time.time())}</timestamp></report>'
                   f'</current_report>' if t["current"] else "")
        return (f'<task id="{task_id}"><name>{escape(t["name"])}</name><creation_time>{t["created"]}</creation_time>'
                f'<usage_type>{t["usage"]}</usage_type>'
                f'<config id="{t["config"]}"><name>Full and fast</name></config>'
                f'<target id="{t["target"]}"><name>x</name></target>'
                f'<scanner id="{t["scanner"]}"><name>OpenVAS Default</name><type>2</type></scanner>'
                f'<status>{t["status"]}</status><progress>{t["progress"]}</progress>{current}{last}</task>')

    def do_get_tasks(self, el):
        wanted = el.get("task_id")
        if wanted:
            if wanted not in self.tasks:
                return answer(el.tag, status="404", text=f"Failed to find task '{wanted}'")
            return answer(el.tag, self.task_xml(wanted))
        ids = sorted(self.tasks, key=lambda i: self.tasks[i]["name"])
        shown = self.page(ids, el.get("filter"))
        return answer(el.tag, "".join(self.task_xml(i) for i in shown) + self.count("task", len(ids), len(shown)))

    def do_get_targets(self, el):
        target = self.targets.get(el.get("target_id") or "")
        if target is None:
            return answer(el.tag, status="404", text="Failed to find target")
        return answer(el.tag, f'<target id="{el.get("target_id")}"><name>{escape(target["name"])}</name>'
                              f'<hosts>{escape(target["hosts"])}</hosts></target>')

    def do_create_target(self, el):
        name = el.findtext("name") or ""
        if any(t["name"] == name for t in self.targets.values()):
            return answer(el.tag, status="400", text="Target exists already")
        port_list = el.find("port_list")
        if port_list is None or port_list.get("id") not in {p["id"] for p in self.port_lists}:
            return answer(el.tag, status="404", text="Failed to find port_list")
        target_id = new_id()
        self.targets[target_id] = {"name": name, "hosts": el.findtext("hosts") or "", "port_list": port_list.get("id"),
                                   "alive": el.findtext("alive_tests"), "comment": el.findtext("comment")}
        return answer(el.tag, status="201", text="OK, resource created", id=target_id)

    def do_create_task(self, el):
        config, target, scanner = (el.find(t).get("id") for t in ("config", "target", "scanner"))
        if config not in {c["id"] for c in self.configs}:
            return answer(el.tag, status="404", text=f"Failed to find config '{config}'")
        if target not in self.targets or scanner not in {s["id"] for s in self.scanners}:
            return answer(el.tag, status="404", text="Failed to find target or scanner")
        task_id = new_id()
        self.tasks[task_id] = {"name": el.findtext("name"), "target": target, "config": config, "scanner": scanner,
                               "status": "New", "progress": "-1", "usage": "scan", "last_report": None,
                               "last_at": None, "current": None, "comment": el.findtext("comment"),
                               "created": iso(time.time())}
        return answer(el.tag, status="201", text="OK, resource created", id=task_id)

    def do_start_task(self, el):
        task = self.tasks.get(el.get("task_id") or "")
        if task is None:
            return answer(el.tag, status="404", text="Failed to find task")
        task.update(status="Requested", progress="0", current=new_id())
        return answer(el.tag, f"<report_id>{task['current']}</report_id>")

    def do_delete_task(self, el):
        self.tasks.pop(el.get("task_id") or "", None)
        return answer(el.tag)

    def do_delete_target(self, el):
        self.targets.pop(el.get("target_id") or "", None)
        return answer(el.tag)

    def do_get_results(self, el):
        t = terms(el.get("filter"))
        selected = [r for r in self.results if r["report_id"] == t.get("report_id", ("=", ""))[1]]
        if "min_qod" in t:
            selected = [r for r in selected if r.get("qod", 80) >= int(t["min_qod"][1])]
        if t.get("severity", ("", ""))[0] == ">":
            selected = [r for r in selected if r["severity"] > float(t["severity"][1])]
        elif t.get("severity", ("", ""))[0] == "<":
            selected = [r for r in selected if r["severity"] < float(t["severity"][1])]
        selected.sort(key=lambda r: -r["severity"])
        shown = self.page(selected, el.get("filter"))
        total = len(selected) + self.lie_about_count
        return answer(el.tag, "".join(self.result_xml(r) for r in shown)
                      + f"<result_count>{total}<filtered>{total}</filtered><page>{len(shown)}</page></result_count>")

    @staticmethod
    def result_xml(r: dict) -> str:
        refs = "".join(f'<ref type="cve" id="{c}"/>' for c in r.get("cves", [])) + '<ref type="url" id="https://x.example"/>'
        solution = (f'<solution type="{r["solution_type"]}">{escape(r["solution"])}</solution>'
                    if r.get("solution") else "")
        return (f'<result id="{r.get("id") or new_id()}"><name>{escape(r["name"])}</name><owner><name>admin</name></owner>'
                f'<comment/><creation_time>{r.get("created", iso(time.time()))}</creation_time>'
                f'<modification_time>{r.get("created", iso(time.time()))}</modification_time>'
                f'<report id="{r["report_id"]}"/><task id="{r["task_id"]}"><name>t</name></task>'
                f'<host>{r["host"]}<asset asset_id=""/><hostname>{r.get("hostname", "")}</hostname></host>'
                f'<port>{r["port"]}</port><nvt oid="{r["oid"]}"><type>nvt</type><name>{escape(r["name"])}</name>'
                f'<family>General</family><cvss_base>{r["severity"]}</cvss_base><severities score="{r["severity"]}"/>'
                f'<tags>{escape(r.get("tags", ""))}</tags>{solution}<refs>{refs}</refs></nvt>'
                f'<scan_nvt_version/><threat>High</threat><severity>{r["severity"]}</severity>'
                f'<qod><value>{r.get("qod", 80)}</value><type>remote_banner</type></qod>'
                f'<description>{escape(r.get("description", ""))}</description></result>')


def result(oid: str, host: str, name: str, severity: float, port: str = "443/tcp", **extra) -> dict:
    return {"oid": OID + oid, "host": host, "name": name, "severity": severity, "port": port, **extra}


@pytest.fixture
def gmp():
    with FakeGmp() as server:
        yield server


# -- test() ------------------------------------------------------------------------------------


def test_test_walks_through_every_check_on_a_healthy_instance(gmp):
    outcome = run(gmp.connector().test())
    assert outcome["ok"], outcome
    assert [c["name"] for c in outcome["checks"]] == ["Connect", "GMP version", "Login", "Scan config", "Scanner",
                                                       "Port list", "Scanner online", "NVT feed", "Read scan results"]
    details = {c["name"]: c["detail"] for c in outcome["checks"]}
    assert "plain TCP" in details["Connect"] and details["GMP version"] == "GMP 22.5"
    assert details["Login"] == "Signed in as admin (role Admin)" and "95000 NVTs" in details["Scan config"]
    assert details["Scanner"] == "OpenVAS Default (OpenVAS Scanner)" and "OTP/2.0" in details["Scanner online"]
    assert "Full and fast" in outcome["detail"] and "All IANA assigned TCP" in outcome["detail"]
    assert outcome["domains"] == {"vulnerabilities": ["read"]}
    # the password went out XML-escaped and arrived intact; it is in nothing the connector answered
    assert gmp.sent("authenticate")[0].findtext("credentials/password") == PASSWORD
    assert PASSWORD not in repr(outcome)
    assert [r.tag for r in gmp.requests[:2]] == ["get_version", "authenticate"]


def test_test_explains_a_wrong_password_and_unusable_settings(gmp):
    outcome = run(gmp.connector(password="wrong-password-1").test())
    assert not outcome["ok"] and outcome["domains"] == {}
    login = outcome["checks"][-1]
    assert login["name"] == "Login" and not login["ok"] and "username and password" in login["detail"]
    assert "wrong-password-1" not in repr(outcome)

    gmp.role = "Observer"
    gmp.scanner_online = False
    gmp.feed_syncing = True
    outcome = run(gmp.connector(scan_config_id=EMPTY_CONFIG, port_list_id=new_id()).test())
    checks = {c["name"]: c for c in outcome["checks"]}
    assert not outcome["ok"] and outcome["detail"].startswith("Permissions:")
    assert not checks["Permissions"]["ok"] and "Observer" in checks["Permissions"]["detail"]
    assert not checks["Scan config"]["ok"] and "feed" in checks["Scan config"]["detail"]
    assert not checks["Port list"]["ok"] and "choose another" in checks["Port list"]["detail"]
    assert not checks["Scanner online"]["ok"] and "ospd-openvas" in checks["Scanner online"]["detail"]
    assert checks["NVT feed"]["ok"] and "update is running" in checks["NVT feed"]["detail"]

    outcome = run(gmp.connector(scan_config_id=POLICY).test())
    assert "compliance policy" in next(c for c in outcome["checks"] if c["name"] == "Scan config")["detail"]


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_test_explains_connection_problems(gmp):
    closed = run(build("openvas", {**gmp.config(), "port": free_port()}, {"password": PASSWORD}).test())
    assert not closed["ok"] and [c["name"] for c in closed["checks"]] == ["Connect"]
    assert "refused the connection" in closed["detail"] and "--listen" in closed["detail"]

    bad = run(build("openvas", {**gmp.config(), "host": "https://gvm.example.com"}, {"password": PASSWORD}).test())
    assert bad["checks"] == [{"name": "Settings", "ok": False, "detail": bad["checks"][0]["detail"]}]
    assert "without https://" in bad["detail"]

    gmp.raw_reply = b"HTTP/1.1 400 Bad Request\r\n\r\n<html>"
    garbage = run(gmp.connector().test())
    assert not garbage["ok"] and "did not answer with GMP XML" in garbage["detail"]

    gmp.raw_reply = b'<!DOCTYPE x [<!ENTITY a "aaaa">]><get_version_response status="200"/>'
    assert "document type declaration" in run(gmp.connector().test())["detail"]

    gmp.raw_reply = b""
    closing = run(gmp.connector().test())
    assert "closed the connection" in closing["detail"] and "connection type" in closing["detail"]


def self_signed(tmp_path: Path) -> tuple[Path, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    cert_file, key_file = tmp_path / "gvmd-cert.pem", tmp_path / "gvmd-key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_file, key_file


def test_tls_checks_the_certificate_unless_switched_off(tmp_path):
    cert_file, key_file = self_signed(tmp_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    with FakeGmp(tls=context) as server:
        untrusted = run(server.connector(connection_type="tls").test())
        assert not untrusted["ok"] and "not trusted" in untrusted["detail"] and "CA certificate file" in untrusted["detail"]

        trusted = run(server.connector(connection_type="tls", ca_file=str(cert_file)).test())
        assert trusted["ok"], trusted
        assert "TLS, certificate verified" in trusted["checks"][0]["detail"]

        lab = run(server.connector(connection_type="tls", verify_tls=False).test())
        assert lab["ok"] and "NOT verified" in lab["checks"][0]["detail"]

        missing = run(server.connector(connection_type="tls", ca_file=str(tmp_path / "nope.pem")).test())
        assert "Cannot load the CA certificate file" in missing["detail"]

        plain = run(server.connector(connection_type="tcp").test())  # plain TCP against a TLS port
        assert not plain["ok"] and plain["checks"][0]["ok"] and not plain["checks"][1]["ok"]


# -- settings ------------------------------------------------------------------------------------


def test_settings_are_validated_and_the_endpoint_covers_tls_verification():
    validate = OpenVasConnector.validate_config
    base = {**OpenVasConnector.defaults(), "username": "admin"}
    assert validate({**base, "host": "[2001:db8::1]", "port": "9390"})["host"] == "2001:db8::1"
    for bad, message in ((dict(host=""), "host name"), (dict(host="gvm.example.com/api"), "without https://"),
                         (dict(host="gvm.example.com", port=70000), "Port"), (dict(host="gvm", port=True), "Port"),
                         (dict(host="gvm", ca_file="certs/ca.pem"), "absolute path"),
                         (dict(host="gvm", scanner_id="OpenVAS Default"), "UUID"),
                         (dict(host="gvm", min_qod=101), "quality of detection"),
                         (dict(host="gvm", alive_test="Ping everything"), "alive test"),
                         (dict(host="gvm", connection_type="ssh"), "tls, unix or tcp")):
        with pytest.raises(ConnectorError, match=message):
            validate({**base, **bad})
    unix = {**base, "connection_type": "unix", "socket_path": "run/gvmd.sock"}
    if os.name == "posix":
        with pytest.raises(ConnectorError, match="absolute path"):
            validate(unix)
        assert validate({**unix, "socket_path": "/run/gvmd/gvmd.sock"})["socket_path"] == "/run/gvmd/gvmd.sock"
    else:
        with pytest.raises(ConnectorError, match="Linux or macOS"):
            validate({**unix, "socket_path": "/run/gvmd/gvmd.sock"})
    config = validate({**base, "host": "gvm.example.com"})
    assert OpenVasConnector.endpoint(config) != OpenVasConnector.endpoint({**config, "verify_tls": False})
    assert OpenVasConnector.endpoint(config) != OpenVasConnector.endpoint({**config, "connection_type": "tcp"})
    assert OpenVasConnector.endpoint(config) == OpenVasConnector.endpoint({**config, "min_qod": 50})

    entry = next(c for c in catalog() if c["kind"] == "openvas")
    fields = {f["name"]: f for f in entry["fields"]}
    assert fields["scan_config_id"]["default"] == FULL_AND_FAST and fields["scanner_id"]["default"] == OPENVAS_DEFAULT
    assert fields["port_list_id"]["default"] == ALL_IANA_TCP and fields["password"]["kind"] == "secret"
    assert entry["actions"] == ["retarget_scanner", "scan", "scan_status", "scanner_check"]
    assert entry["capabilities"] == {"vulnerabilities": ["read"]}
    tool = Tool(id="gvm", name="Greenbone", source_type="local", source="/x", manifest=Manifest(id="gvm", name="Greenbone"))
    assert OpenVasConnector.detect(tool) == 90


def test_options_list_scan_configs_scanners_and_port_lists(gmp):
    gmp.max_rows = 1  # gvmd caps pages: the listing still reads everything
    connector = gmp.connector()
    configs = run(connector.options("scan_config_id"))
    assert configs == [{"value": FULL_AND_FAST, "label": "Full and fast - default"}, {"value": EMPTY_CONFIG, "label": "Empty"}]
    assert gmp.sent("get_configs")[0].get("usage_type") == "scan"
    assert run(connector.options("scanner_id")) == [
        {"value": OPENVAS_DEFAULT, "label": "OpenVAS Default (OpenVAS Scanner) - default"},
        {"value": CVE_SCANNER, "label": "CVE (CVE Scanner)"}]
    assert [o["label"] for o in run(connector.options("port_list_id"))] == ["All IANA assigned TCP - default",
                                                                            "All TCP and Nmap top 100 UDP"]
    with pytest.raises(ConnectorError, match="no choices"):
        run(connector.options("username"))


# -- scans -----------------------------------------------------------------------------------------


def test_scan_creates_a_target_and_a_task_and_reports_their_status(gmp):
    connector = gmp.connector(alive_test="Consider Alive")
    job = run(connector.action("scan", {"hosts": ["10.0.0.5", "web-1.example.com", "10.0.1.0/24", "10.0.0.5"],
                                        "name": "Atrium <scan> & co"}))
    task = gmp.tasks[job["job_id"]]
    target = gmp.targets[task["target"]]
    assert target["hosts"] == "10.0.0.5,web-1.example.com,10.0.1.0/24" and target["port_list"] == ALL_IANA_TCP
    assert target["name"].startswith("Atrium <scan> & co - ") and target["alive"] == "Consider Alive"
    assert task["name"] == "Atrium <scan> & co" and task["config"] == FULL_AND_FAST and task["scanner"] == OPENVAS_DEFAULT
    assert "Atrium" in task["comment"] and job["report_id"] == task["current"] and job["hosts"] == 3

    status = lambda: run(connector.action("scan_status", {"job_id": job["job_id"]}))
    assert status() == {"status": "queued", "progress": 0, "done": False, "scanner_status": "Requested",
                        "report_id": task["current"]}
    task.update(status="Running", progress="42")
    assert (status()["status"], status()["progress"]) == ("running", 42)
    gmp.finish(job["job_id"], [])
    assert {k: status()[k] for k in ("status", "progress", "done")} == {"status": "done", "progress": 100, "done": True}
    for raw, mapped in (("Interrupted", "interrupted"), ("Stopped", "stopped"), ("Stop Requested", "stopped"),
                        ("Processing", "processing"), ("Queued", "queued")):
        task["status"] = raw
        assert status()["status"] == mapped and not status()["done"]
    del gmp.tasks[job["job_id"]]
    gone = status()
    assert gone["status"] == "failed" and "no longer exists" in gone["detail"]

    # the default alive test (the scan config's) sends no element of its own
    run(gmp.connector().action("scan", {"hosts": ["10.0.0.6"], "name": "Plain"}))
    assert gmp.sent("create_target")[-1].find("alive_tests") is None


def test_scan_refuses_odd_hosts_and_cleans_up_after_a_failed_start(gmp):
    connector = gmp.connector()
    for hosts in (["10.0.0.5</hosts><x>"], ["-iL /etc/passwd"], [], "a b", [7]):
        with pytest.raises(ConnectorError):
            run(connector.action("scan", {"hosts": hosts, "name": "x"}))
    assert gmp.requests == []  # refused before anything was sent
    with pytest.raises(ConnectorError, match="not a Greenbone task id"):
        run(connector.action("scan_status", {"job_id": "1 or 1=1"}))

    gmp.fail["start_task"] = ("503", "Service temporarily down")
    with pytest.raises(ConnectorError, match="busy or its scanner is not available") as failure:
        run(connector.action("scan", {"hosts": ["10.0.0.5"], "name": "x"}))
    assert failure.value.status == 503
    assert gmp.tasks == {} and gmp.targets == {}  # the half-made task and target went to the trashcan
    del gmp.fail["start_task"]

    gmp.fail["create_target"] = ("400", "Error in host specification")
    with pytest.raises(ConnectorError) as failure:
        run(connector.action("scan", {"hosts": ["10.0.0.5"], "name": "x"}))
    assert failure.value.status == 400 and failure.value.message.endswith("Error in host specification")


def _listen(path: Path) -> socket.socket:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(path))
    return sock


def test_a_failed_scan_includes_the_scanners_error(gmp):
    connector = gmp.connector()
    job = run(connector.action("scan", {"hosts": ["10.0.0.5"], "name": "Atrium scan"}))
    task = gmp.tasks[job["job_id"]]
    task["status"] = "Interrupted"
    gmp.results.append({"report_id": task["current"], "task_id": job["job_id"], "name": "Error Message", "host": "",
                        "port": "general", "oid": "0", "severity": -3, "qod": 0, "description": "Could not connect to Scanner",
                        "cves": []})
    status = run(connector.action("scan_status", {"job_id": job["job_id"]}))
    assert status["status"] == "interrupted" and status["detail"] == "Could not connect to Scanner"


def test_a_missing_scanner_socket_is_replaced_by_the_one_ospd_opened(gmp, tmp_path):
    missing, live = tmp_path / "ospd-openvas.sock", tmp_path / "ospd.sock"
    sock = _listen(live)
    try:
        gmp.scanners[0]["host"] = str(missing)
        gmp.scanner_online = False
        checked = run(gmp.connector().scanner_check())
        assert checked["online"] is False and checked["suggestion"]["host"] == str(live)
        assert checked["suggestion"]["previous"] == str(missing)
        assert checked["suggestion"]["scanner_id"] == OPENVAS_DEFAULT

        gmp.scanner_online = True
        moved = run(gmp.connector().retarget_scanner(OPENVAS_DEFAULT, str(live)))
        assert moved == {"scanner_id": OPENVAS_DEFAULT, "host": str(live), "previous": str(missing)}
        assert gmp.scanners[0]["host"] == str(missing)  # GMP will not store a socket path
        assert os.path.islink(missing) and os.path.realpath(missing) == os.path.realpath(live)
        assert gmp.sent("modify_scanner") == []
    finally:
        sock.close()


def test_retarget_restores_the_old_path_when_the_scanner_still_does_not_answer(gmp, tmp_path):
    missing, live = tmp_path / "ospd-openvas.sock", tmp_path / "ospd.sock"
    sock = _listen(live)
    try:
        gmp.scanners[0]["host"] = str(missing)
        gmp.scanner_online = False
        with pytest.raises(ConnectorError, match="link was removed") as failure:
            run(gmp.connector().retarget_scanner(OPENVAS_DEFAULT, str(live)))
        assert gmp.scanners[0]["host"] == str(missing) and not missing.exists()
        assert gmp.sent("modify_scanner") == []
        assert failure.value.status == 503
    finally:
        sock.close()


def test_retarget_refuses_a_socket_that_is_not_the_one_beside_the_missing_path(gmp, tmp_path):
    missing = tmp_path / "ospd-openvas.sock"
    elsewhere = tmp_path / "other"
    elsewhere.mkdir()
    sock = _listen(elsewhere / "ospd.sock")
    present = _listen(tmp_path / "ospd.sock")
    try:
        gmp.scanners[0]["host"] = str(missing)
        with pytest.raises(ConnectorError, match="beside the missing one"):
            run(gmp.connector().retarget_scanner(OPENVAS_DEFAULT, str(elsewhere / "ospd.sock")))
        gmp.scanners[0]["host"] = str(tmp_path / "ospd.sock")
        with pytest.raises(ConnectorError, match="already there"):
            run(gmp.connector().retarget_scanner(OPENVAS_DEFAULT, str(tmp_path / "ospd.sock")))
        assert gmp.sent("modify_scanner") == [] and not missing.exists()
    finally:
        sock.close()
        present.close()


# -- findings ---------------------------------------------------------------------------------------


def test_pull_after_a_scan_reads_that_scans_report_completely(gmp):
    now = time.time()
    old_task, old_report = gmp.add_task("Last month", "10.0.0.9", at=now - 30 * 86400)
    gmp.add_results(old_task, old_report, [result("10", "10.0.0.9", "Old finding", 5.0)])
    # someone's nightly task in Greenbone, made long ago, finished during the hub's scan: not part of that scan
    nightly, nightly_report = gmp.add_task("Nightly", "10.0.3.0/24", at=now - 30, created=now - 100 * 86400)
    gmp.add_results(nightly, nightly_report, [result("11", "10.0.3.4", "Nightly finding", 7.0)])
    job = run(gmp.connector().action("scan", {"hosts": ["web-1.example.com", "10.0.2.0/24"], "name": "Atrium scan"}))
    gmp.finish(job["job_id"], [
        result("1", "10.0.0.7", "OpenSSL remote code execution", 9.8, hostname="web-1.example.com",
               cves=["CVE-2024-0001", "CVE-2024-0002"], solution="Update to 3.0.14", solution_type="VendorFix",
               tags="cvss_base_vector=AV:N|summary=OpenSSL is prone to RCE.|insight=Heap overflow|solution_type=VendorFix",
               description="Installed version: 3.0.1", created=iso(now - 60)),
        result("2", "10.0.2.15", "SSH weak MAC algorithms", 5.3, port="22/tcp", hostname="build-2",
               tags="summary=Weak MACs.|solution=Disable the weak MAC algorithms.|solution_type=Mitigation"),
        result("3", "10.0.2.15", "Weak cipher suites", 7.5),
        result("4", "10.0.2.15", "Low-quality guess", 9.0, qod=30),
        result("5", "10.0.2.15", "OS Detection Consolidation", 0.0, port="general/tcp"),
        result("6", "10.0.2.15", "Overridden false positive", -1.0),
    ])
    gmp.max_rows = 2  # pages of two: the connector pages on and checks the total
    records = run(gmp.connector().pull("vulnerabilities", since=now - 300))
    valid, errors = normalize("vulnerabilities", records)
    assert errors == [] and len(valid) == 3
    by_title = {r["title"]: r for r in valid}
    rce = by_title["OpenSSL remote code execution"]
    assert rce["external_id"] == f"{OID}1|web-1.example.com|443/tcp"  # the host the hub asked to scan
    assert (rce["severity"], rce["cvss"], rce["cves"]) == ("critical", 9.8, ["CVE-2024-0001", "CVE-2024-0002"])
    assert rce["solution"] == "Update to 3.0.14 (VendorFix)" and rce["scanner"] == "OpenVAS / Greenbone"
    assert rce["description"].startswith("OpenSSL is prone to RCE.") and "Installed version: 3.0.1" in rce["description"]
    assert "Insight: Heap overflow" in rce["description"] and abs(rce["detected_at"] - (now - 60)) < 2
    ssh = by_title["SSH weak MAC algorithms"]
    assert ssh["host"] == "10.0.2.15" and ssh["port"] == "22/tcp" and ssh["severity"] == "medium"
    assert ssh["solution"] == "Disable the weak MAC algorithms. (Mitigation)"
    assert by_title["Weak cipher suites"]["severity"] == "high"
    filters = [r.get("filter") for r in gmp.sent("get_results")]
    assert all("apply_overrides=1" in f and "min_qod=70" in f and "severity>0" in f for f in filters)
    assert len(filters) == 2  # only the scan's own report (in two pages): the older tasks are not read

    # log results only on request; false positives (negative severities) never
    gmp.max_rows = 1000
    with_log = run(gmp.connector(import_log=True, min_qod=20).pull("vulnerabilities", since=now - 300))
    titles = {r["title"] for r in with_log}
    assert {"OS Detection Consolidation", "Low-quality guess"} <= titles and "Overridden false positive" not in titles
    info = next(r for r in normalize("vulnerabilities", with_log)[0] if r["title"] == "OS Detection Consolidation")
    assert info["severity"] == "info"


def test_full_pull_takes_each_hosts_findings_from_the_newest_scan_of_it(gmp):
    now = time.time()
    old_task, old_report = gmp.add_task("Old", "10.0.0.0/24", at=now - 10 * 86400)
    gmp.add_results(old_task, old_report, [result("1", "10.0.0.5", "Fixed since", 9.0),
                                           result("2", "10.0.0.5", "Still there", 6.0),
                                           result("3", "10.0.0.6", "Gone from six", 4.0),
                                           result("4", "10.0.0.7", "Only scanned once", 4.0)])
    new_task, new_report = gmp.add_task("New", "10.0.0.5", at=now - 86400)
    gmp.add_results(new_task, new_report, [result("2", "10.0.0.5", "Still there", 6.5)])
    _, newest_report = gmp.add_task("Newest", "10.0.0.6", at=now - 3600)  # scanned .6 again and found nothing
    audit, audit_report = gmp.add_task("Audit", "10.0.0.5", at=now, usage="audit")
    gmp.add_results(audit, audit_report, [result("9", "10.0.0.5", "Compliance check", 10.0)])
    gmp.add_task("Never run", "10.0.0.8")
    records = {r["title"]: r for r in run(gmp.connector().pull("vulnerabilities"))}
    assert set(records) == {"Still there", "Only scanned once"}
    assert records["Still there"]["cvss"] == 6.5  # the newer report's result
    read = {r.get("filter").split()[0] for r in gmp.sent("get_results")}
    assert read == {f"report_id={report}" for report in (old_report, new_report, newest_report)}  # not the audit


def test_incomplete_or_oversized_reads_are_refused(gmp):
    task, report = gmp.add_task("Scan", "10.0.0.5", at=time.time())
    gmp.add_results(task, report, [result(str(i), "10.0.0.5", f"Finding {i}", 5.0) for i in range(3)])
    gmp.lie_about_count = 1
    with pytest.raises(ConnectorError, match="counted 4 results"):
        run(gmp.connector().pull("vulnerabilities"))
    gmp.lie_about_count = 0
    with pytest.raises(ConnectorError, match="cannot read assets"):
        run(gmp.connector().pull("assets"))
    gmp.fail["get_results"] = ("403", "Permission denied")
    with pytest.raises(ConnectorError, match="lacks permission") as failure:
        run(gmp.connector().pull("vulnerabilities"))
    assert failure.value.status == 403


def test_host_choice_follows_the_scan_targets():
    assert pick_host("10.0.0.7", "web-1.example.com", ["web-1.example.com"]) == "web-1.example.com"
    assert pick_host("10.0.0.7", "web-1.example.com", ["10.0.0.0/24"]) == "10.0.0.7"
    assert pick_host("10.0.0.7", "WEB-1.example.com.", ["web-1.example.com", "10.0.0.7"]) == "10.0.0.7"
    assert pick_host("10.0.0.7", "", []) == "10.0.0.7"
    assert pick_host("", "db-1", ["10.0.0.0/24"]) == "db-1"


# -- through the hub ---------------------------------------------------------------------------------


def test_the_hub_scans_in_scope_assets_with_openvas_and_tracks_the_findings(client, wait_for):
    hub = client.app.state.hub
    web = client.post("/api/assets", json={"name": "web-1", "type": "server",
                                           "facts": {"addresses": ["web-1.example.com"]}}).json()
    assert client.post("/api/assets/scan-scope", json={"asset_ids": [web["id"]], "in_scope": True}).status_code == 200
    tool = Tool(id="greenbone", name="Greenbone", source_type="saas", source="https://greenbone.example.com",
                status="ready", manifest=Manifest(id="greenbone", name="Greenbone", kind="saas"))
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    seen: list[str] = []

    with FakeGmp() as gmp:
        connection = client.get("/api/tools/greenbone/connection").json()
        assert connection["detected"][0]["kind"] == "openvas"
        saved = client.put("/api/tools/greenbone/connection", json={
            "kind": "openvas", "config": {"connection_type": "tcp", "host": "127.0.0.1", "port": gmp.port,
                                          "username": "admin"}, "secrets": {"password": PASSWORD}})
        assert saved.status_code == 200, saved.text
        tested = client.post("/api/tools/greenbone/connection/test").json()
        assert tested["ok"], tested
        seen += [saved.text, repr(tested)]
        proposal = wait_for(lambda: [a for a in client.get("/api/approvals?status=pending").json()
                                     if a["kind"] == "flow" and a["payload"]["tool_id"] == "greenbone"])
        assert proposal[0]["payload"]["action"] == "scan"

        started = client.post("/api/vulnerabilities/scan", json={}).json()
        assert started["ok"] and started["pending"] and started["flow"]["job"]["status"] == "running"
        task_id = started["flow"]["job"]["job_id"]
        assert gmp.targets[gmp.tasks[task_id]["target"]]["hosts"] == "web-1.example.com"
        flow_id = started["flow"]["id"]
        gmp.tasks[task_id].update(status="Running", progress="40")
        polled = client.post(f"/api/flows/{flow_id}/run").json()
        assert polled["pending"] and "40%" in polled["detail"]

        gmp.finish(task_id, [
            result("1", "10.0.0.7", "OpenSSL remote code execution", 9.8, hostname="web-1.example.com",
                   cves=["CVE-2024-0001"]),
            result("2", "10.0.0.7", "Weak cipher suites", 5.0, hostname="web-1.example.com"),
        ])
        done = client.post(f"/api/flows/{flow_id}/run").json()
        assert done["ok"] and done["counts"]["new"] == 2 and done["flow"]["job"] is None, done
        vulns = client.get("/api/vulnerabilities").json()
        assert {v["asset_id"] for v in vulns} == {web["id"]} and {v["host"] for v in vulns} == {"web-1.example.com"}
        critical = next(v for v in vulns if v["severity"] == "critical")
        assert critical["cves"] == ["CVE-2024-0001"] and critical["source"] == "greenbone"

        # a rescan (a new task in Greenbone) no longer finds the critical one: it is fixed
        again = client.post("/api/vulnerabilities/scan", json={"asset_ids": [web["id"]]}).json()
        second = again["flow"]["job"]["job_id"]
        assert second != task_id
        gmp.finish(second, [result("2", "10.0.0.7", "Weak cipher suites", 5.0, hostname="web-1.example.com")],
                   at=time.time() + 2)  # a later scan (both started within seconds here)
        rescan = client.post(f"/api/flows/{flow_id}/run").json()
        assert rescan["counts"]["fixed"] == 1 and rescan["counts"]["updated"] == 1, rescan
        assert client.get(f"/api/vulnerabilities/{critical['id']}").json()["status"] == "fixed"
        seen += [repr(done), repr(rescan), client.get("/api/flows").text, client.get("/api/activity").text]

    assert all(PASSWORD not in text and escape(PASSWORD) not in text for text in seen)
