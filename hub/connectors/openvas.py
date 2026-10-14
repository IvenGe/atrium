"""OpenVAS / Greenbone connector: GMP, the Greenbone Management Protocol (XML), over TLS, a unix socket or plain TCP.

Checked against the GMP 22.5 reference (docs.greenbone.net/API/GMP/gmp-22.5.html), the gvmd sources
(src/manage_sql.h) and man page, the GSA sources (src/gmp/models/scanner.ts, scan-config.ts,
web/pages/targets/TargetDialog.tsx) and python-gvm (gvm/connections), October 2026:

- one connection carries one command after another; each answer is a single XML element "<command>_response" with
  a status (2xx OK, 400 bad request - a failed login too -, 403 permission denied, 404 not found, 5xx trouble in the
  manager) and a status_text. Only get_version works before authenticate. gvmd serves GMP on a unix socket
  (python-gvm's default: /run/gvmd/gvmd.sock; Community Containers share it through a volume, so the path varies) and
  on TLS only when started with --listen / --port (python-gvm's default port: 9390);
- a scan is create_target (hosts and a port list) -> create_task (scan config, target, scanner) -> start_task, which
  answers the report id. The job id is the task id: get_tasks gives its status (New, Requested, Queued, Running,
  Processing, Done, Stop Requested, Stopped, Interrupted, Delete Requested) and progress (-1 when not running), and
  last_report - the last finished report with its timestamp;
- defaults as gvmd / GSA define them: scan config "Full and fast" daba56c8-73ec-11df-a475-002264764cea, scanner
  "OpenVAS Default" 08b69003-5fc2-4037-a479-93b440211c73, port list "All IANA assigned TCP"
  33d0cd82-57c6-11e1-8ed1-406186ea4fc5;
- results come from get_results with a filter (report_id, apply_overrides, min_qod, severity, first, rows). A page
  is capped by the user's "Max Rows Per Page" setting, so paging advances by the rows received, and the number read
  is checked against result_count/filtered: an incomplete read is refused, because the hub marks findings missing
  from a scan's results as fixed. A result's severity is its CVSS-based score with overrides applied; negative
  scores are false positives (-1), debug (-2) and error (-3) results and are skipped, 0 is a log result (info).

pull("vulnerabilities", since) reads the last finished report of scan tasks (audits are left out). The hub only
passes `since` right after its own scan, and every hub scan creates its own task, so with `since` only tasks created
at or after it count (less CLOCK_SLACK) - scheduled tasks someone keeps in Greenbone cannot mix into that scan's
results. Without `since`, every scan task counts. Either way the reports are read newest first and a host's findings
come only from the newest report whose target covered it (or that has results for it): an older scan cannot bring
back what a newer one no longer finds. A finding's host is the address or host name its task's target listed (the
hub's scan targets), so findings land on the asset that was scanned; external_id is "<nvt oid>|<host>|<port>".

Assumptions (not verifiable without an instance): result filters accept "severity>0" and "sort-reverse=severity" as
GSA uses them; an NVT's solution is in <nvt><solution type=...> (GMP 20.08+) or else in its tags ("solution=...").
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import secrets as tokens
import socket
import ssl
import xml.etree.ElementTree as ET
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, AsyncIterator
from xml.sax.saxutils import escape, quoteattr

from .base import HOSTNAME_RE, Connector, ConnectorError, ConnectorField, check, severity_from_score, to_timestamp, \
    valid_scan_target

GMP_PORT = 9390
FULL_AND_FAST = "daba56c8-73ec-11df-a475-002264764cea"
OPENVAS_DEFAULT = "08b69003-5fc2-4037-a479-93b440211c73"
ALL_IANA_TCP = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
SCANNER_TYPES = {"2": "OpenVAS Scanner", "3": "CVE Scanner", "5": "Greenbone Sensor", "6": "OpenVASD Scanner",
                 "7": "Agent Controller", "8": "OpenVASD Sensor", "9": "Agent Sensor", "10": "Container Image Scanner",
                 "11": "Web Application Scanner"}
ALIVE_TESTS = ("Scan Config Default", "ICMP Ping", "TCP-ACK Service Ping", "TCP-SYN Service Ping", "ARP Ping",
               "ICMP & TCP-ACK Service Ping", "ICMP & ARP Ping", "TCP-ACK Service & ARP Ping",
               "ICMP, TCP-ACK Service & ARP Ping", "Consider Alive")
# task status -> (status for the hub, done); the hub treats failed / stopped / interrupted as a failed scan
TASK_STATES = {"new": ("queued", False), "requested": ("queued", False), "queued": ("queued", False),
               "running": ("running", False), "processing": ("processing", False), "done": ("done", True),
               "stop requested": ("stopped", False), "stopped": ("stopped", False),
               "interrupted": ("interrupted", False), "delete requested": ("failed", False),
               "ultimate delete requested": ("failed", False)}
COMMENT = "Created by Atrium for a scan of in-scope assets"
SCANNER_NAME = "OpenVAS / Greenbone"
PAGE = 500  # rows asked for per page (gvmd may cap it lower)
MAX_RECORDS = 100_000  # more is refused, never truncated: a partial read would mark the rest fixed
MAX_ITEMS = 20_000  # tasks, configs, ... in one listing
MAX_HOSTS = 4096
MAX_RESPONSE = 256 * 1024 * 1024
CHUNK = 256 * 1024
CONNECT_TIMEOUT = 15.0
READ_TIMEOUT = 300.0  # one answer: a page of detailed results can take a while on a large instance
CLOCK_SLACK = 900.0  # beyond the hub's own 5 minutes: a scanner clock further behind still finds the scan's task
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
XML_INVALID = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")


def x(value: Any) -> str:
    """Text for an XML element; GMP cannot carry control characters, so they are refused."""
    text = str(value)
    if XML_INVALID.search(text):
        raise ConnectorError("A value contains control characters that GMP cannot carry")
    return escape(text)


def attr(value: Any) -> str:
    """A quoted XML attribute value."""
    text = str(value)
    if XML_INVALID.search(text):
        raise ConnectorError("A value contains control characters that GMP cannot carry")
    return quoteattr(text)


def _clean(value: Any, limit: int = 200) -> str:
    return " ".join(XML_INVALID.sub(" ", str(value or "")).split())[:limit]


def _float(value: Any) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _time(value: Any) -> float | None:
    """POSIX seconds of a GMP time: ISO 8601, or the ctime form older managers used ("Mon Feb 1 19:11:20 2010")."""
    stamp = to_timestamp(value)
    if stamp is not None or not value:
        return stamp
    try:
        return datetime.strptime(" ".join(str(value).split()), "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def _count(root: ET.Element, name: str) -> int | None:
    """The filtered total of a "<name><filtered>N</filtered>...</name>" count element."""
    element = root.find(name)
    if element is None:
        return None
    for text in (element.findtext("filtered"), element.text):
        if text and text.strip().lstrip("-").isdigit():
            return int(text.strip())
    return None


def _tags(text: str | None) -> dict[str, str]:
    """An NVT's tags ("summary=...|insight=...|solution_type=VendorFix") as a dict."""
    out: dict[str, str] = {}
    for part in (text or "").split("|"):
        key, sep, value = part.partition("=")
        if sep and key.strip() and value.strip():
            out[key.strip()] = value.strip()
    return out


def _covers(targets: list[str], host: str) -> bool:
    """Whether a target list (addresses, host names, CIDRs) names `host`."""
    host = host.lower().rstrip(".")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    for target in targets:
        if target == host:
            return True
        if address is not None and "/" in target:
            try:
                if address in ipaddress.ip_network(target, strict=False):
                    return True
            except ValueError:
                continue
    return False


def pick_host(ip: str, hostname: str, targets: list[str]) -> str:
    """The name the hub scanned the host by: its address, or its host name when only that was a target."""
    for candidate in (ip, hostname):
        if candidate and targets and _covers(targets, candidate):
            return candidate.lower().rstrip(".") if candidate == hostname else candidate
    return ip or hostname


class Gmp:
    """One GMP connection: commands go out one at a time and each answer is read as one complete XML element."""

    def __init__(self, owner: "OpenVasConnector", reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.owner = owner
        self.reader = reader
        self.writer = writer
        self.broken: str | None = None  # after a transport failure the stream is out of step: no further commands

    async def command(self, xml: str, what: str) -> ET.Element:
        """Send one command and return its answer; ConnectorError when the manager does not answer OK."""
        name = self.owner.title
        if self.broken:
            raise self.owner.error(f"{self.broken} ({what})")
        try:
            self.writer.write(xml.encode("utf-8"))
            await asyncio.wait_for(self.writer.drain(), CONNECT_TIMEOUT)
            root = await self._read()
        except ConnectorError as exc:
            self.broken = exc.message
            raise
        except (asyncio.TimeoutError, TimeoutError) as exc:
            self.broken = f"{name} did not answer in time"
            raise self.owner.error(f"{self.broken} ({what})") from exc
        except OSError as exc:
            self.broken = f"The connection to {name} broke: {exc.__class__.__name__}"
            raise self.owner.error(f"{self.broken} ({what})") from exc
        status = root.get("status") or ""
        if not status.startswith("2"):
            raise self.owner.gmp_error(what, status, root.get("status_text") or "")
        return root

    async def _read(self) -> ET.Element:
        parser = ET.XMLPullParser(events=("start", "end"))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + READ_TIMEOUT
        root: ET.Element | None = None
        depth = size = 0
        tail = b""
        while True:
            chunk = await asyncio.wait_for(self.reader.read(CHUNK), max(0.1, deadline - loop.time()))
            if not chunk:
                raise self.owner.error(
                    f"{self.owner.title} closed the connection without a complete answer - check the connection type "
                    "(gvmd's TLS port needs 'TLS') and that the address is gvmd's GMP port")
            size += len(chunk)
            if size > MAX_RESPONSE:
                raise self.owner.error(f"{self.owner.title} sent an answer larger than {MAX_RESPONSE >> 20} MB")
            window = tail + chunk
            if b"<!DOCTYPE" in window or b"<!ENTITY" in window:  # GMP never declares a DTD; refuse entity tricks
                raise self.owner.error(f"{self.owner.title} sent an answer with a document type declaration - refused")
            tail = chunk[-16:]
            try:
                parser.feed(chunk)
                events = list(parser.read_events())
            except ET.ParseError as exc:
                raise self.owner.error(f"{self.owner.title} did not answer with GMP XML ({exc}) - is this gvmd's GMP "
                                       "port, and does the connection type match?") from exc
            for event, element in events:
                if event == "start":
                    root = element if root is None else root
                    depth += 1
                else:
                    depth -= 1
                    if depth == 0 and root is not None:
                        return root

    async def close(self) -> None:
        try:
            self.writer.close()
            await asyncio.wait_for(self.writer.wait_closed(), 3)
        except Exception:  # closing a broken connection may fail; nothing is left to clean up
            pass


class OpenVasConnector(Connector):
    kind = "openvas"
    title = "OpenVAS / Greenbone"
    description = ("Vulnerability scanner (Greenbone Management Protocol): scans the assets in scan scope and reports "
                   "its findings to Hub Vulnerabilities.")
    fields = [
        ConnectorField(name="connection_type", label="Connection", kind="select", default="tls", choices=[
            {"value": "tls", "label": "TLS (port 9390)"}, {"value": "unix", "label": "Unix socket (hub on Linux / macOS)"},
            {"value": "tcp", "label": "Plain TCP (insecure - labs and tests only)"}],
            help="How the hub reaches gvmd. gvmd only listens on a unix socket unless started with --listen and --port."),
        ConnectorField(name="host", label="Host", kind="text", placeholder="gvmd.example.com",
                       help="gvmd's host name or IP address (TLS and plain TCP)."),
        ConnectorField(name="port", label="Port", kind="number", default=GMP_PORT),
        ConnectorField(name="socket_path", label="Socket path", kind="text", placeholder="/run/gvmd/gvmd.sock",
                       help="Only for 'Unix socket': the hub's user needs access to it (usually the gvm group)."),
        ConnectorField(name="verify_tls", label="Verify TLS certificate", kind="bool", default=True,
                       help="Switch off only in a lab. Changing it means entering the password again."),
        ConnectorField(name="ca_file", label="CA certificate file", kind="text", placeholder="/etc/atrium/gvmd-ca.pem",
                       help="PEM file on the hub's machine that signed gvmd's certificate (gvmd's own CA is "
                            "/var/lib/gvm/CA/cacert.pem on the scanner). Empty: the system's trusted CAs."),
        ConnectorField(name="username", label="Username", kind="text", required=True,
                       help="A Greenbone user that may create targets and tasks (role User or Admin)."),
        ConnectorField(name="password", label="Password", kind="secret", required=True),
        ConnectorField(name="scan_config_id", label="Scan config", kind="select", options=True, default=FULL_AND_FAST,
                       help="Default: Full and fast."),
        ConnectorField(name="scanner_id", label="Scanner", kind="select", options=True, default=OPENVAS_DEFAULT,
                       help="Default: OpenVAS Default."),
        ConnectorField(name="port_list_id", label="Port list", kind="select", options=True, default=ALL_IANA_TCP,
                       help="Default: All IANA assigned TCP."),
        ConnectorField(name="alive_test", label="Alive test", kind="select", default="Scan Config Default",
                       choices=[{"value": t, "label": t} for t in ALIVE_TESTS],
                       help="'Consider Alive' scans hosts that do not answer pings (e.g. behind a firewall)."),
        ConnectorField(name="min_qod", label="Minimum quality of detection (%)", kind="number", default=70,
                       help="Results below this QoD are not imported (Greenbone's default is 70)."),
        ConnectorField(name="import_log", label="Import log results", kind="bool", default=False,
                       help="Also read informational (log) results; the scan flow's 'include info' option decides "
                            "whether the hub keeps them."),
    ]
    capabilities = {"vulnerabilities": {"read"}}
    actions = {"scan", "scan_status"}
    side_effect_actions = {"scan": "scan"}  # starting a scan loads the scanned systems: only via the scan approval path

    @classmethod
    def detect(cls, tool) -> int:
        return cls.name_score(tool, ("openvas", "greenbone", "gvm"), ("vuln.scanner",))

    @classmethod
    def endpoint(cls, config: dict[str, Any]) -> str:
        # switching certificate checks off would let a stored password go to whoever answers: enter it again
        return super().endpoint(config) + f"|verify_tls={str(bool(config.get('verify_tls', True))).lower()}"

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        config = dict(config)
        kind = config.get("connection_type") or "tls"
        if kind not in ("tls", "unix", "tcp"):
            raise ConnectorError("Connection must be tls, unix or tcp")
        if kind == "unix":
            if os.name != "posix":
                raise ConnectorError("A unix socket only works when the hub runs on Linux or macOS - use TLS")
            path = str(config.get("socket_path") or "").strip()
            if not path or not PurePosixPath(path).is_absolute():
                raise ConnectorError("Enter the absolute path of gvmd's socket, e.g. /run/gvmd/gvmd.sock")
            config["socket_path"] = path
        else:
            host = str(config.get("host") or "").strip().strip("[]").rstrip(".")
            if not host:
                raise ConnectorError("Enter gvmd's host name or IP address")
            if "://" in host or "/" in host or not _host_ok(host):
                raise ConnectorError("Host must be a host name or IP address, without https:// or a path")
            config["host"] = host
            port = _integer(config.get("port", GMP_PORT))
            if port is None or not 1 <= port <= 65535:
                raise ConnectorError("Port must be a number from 1 to 65535")
            config["port"] = port
        ca_file = str(config.get("ca_file") or "").strip()
        if ca_file and not (os.path.isabs(ca_file) or PurePosixPath(ca_file).is_absolute()):
            raise ConnectorError("CA certificate file must be an absolute path on the hub's machine")
        for name, label in (("scan_config_id", "Scan config"), ("scanner_id", "Scanner"), ("port_list_id", "Port list")):
            value = str(config.get(name) or "").strip()
            if value and not UUID_RE.match(value):
                raise ConnectorError(f"{label} must be a Greenbone id (a UUID) - pick one from the list")
        qod = _integer(config.get("min_qod", 70))
        if qod is None or not 0 <= qod <= 100:
            raise ConnectorError("Minimum quality of detection must be a whole number from 0 to 100")
        config["min_qod"] = qod
        if config.get("alive_test") and config["alive_test"] not in ALIVE_TESTS:
            raise ConnectorError("Unknown alive test")
        return config

    # -- connection --------------------------------------------------------------------

    def where(self) -> str:
        if self.config.get("connection_type") == "unix":
            return str(self.config.get("socket_path") or "the socket")
        host = str(self.config.get("host") or "")
        return f"{'[' + host + ']' if ':' in host else host}:{self.config.get('port') or GMP_PORT}"

    def ssl_context(self) -> ssl.SSLContext:
        ca_file = str(self.config.get("ca_file") or "").strip()
        if not ca_file:
            context = ssl.create_default_context()
        else:
            try:
                context = ssl.create_default_context(cafile=ca_file)
            except (OSError, ssl.SSLError) as exc:
                raise self.error(f"Cannot load the CA certificate file {ca_file}: {getattr(exc, 'strerror', None) or exc}") from exc
            # a private CA such as gvmd's own is often not RFC 5280-strict; the chain and host name are still checked
            context.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
        if not self.config.get("verify_tls", True):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context

    async def open(self) -> Gmp:
        kind = self.config.get("connection_type") or "tls"
        where = self.where()
        host = str(self.config.get("host") or "")
        try:
            if kind == "unix":
                if os.name != "posix" or not hasattr(asyncio, "open_unix_connection"):
                    raise ConnectorError("A unix socket only works when the hub runs on Linux or macOS - use TLS")
                opening = asyncio.open_unix_connection(str(self.config.get("socket_path") or ""), limit=CHUNK)
            elif kind == "tls":
                opening = asyncio.open_connection(host, int(self.config.get("port") or GMP_PORT), ssl=self.ssl_context(),
                                                  server_hostname=host, ssl_handshake_timeout=CONNECT_TIMEOUT, limit=CHUNK)
            elif kind == "tcp":
                opening = asyncio.open_connection(host, int(self.config.get("port") or GMP_PORT), limit=CHUNK)
            else:
                raise ConnectorError("Connection must be tls, unix or tcp")
            reader, writer = await asyncio.wait_for(opening, CONNECT_TIMEOUT)
        except ConnectorError:
            raise
        except (asyncio.TimeoutError, TimeoutError) as exc:
            raise self.error(f"{where} did not answer within {CONNECT_TIMEOUT:.0f} s - check the host, the port and "
                             "firewalls") from exc
        except ssl.SSLCertVerificationError as exc:
            raise self.error(
                f"The TLS certificate of {where} is not trusted ({exc.verify_message or exc.reason}) - set the CA "
                "certificate file to the CA that signed it (gvmd's own: /var/lib/gvm/CA/cacert.pem on the scanner), "
                "use the host name the certificate names, or, in a lab, switch off certificate verification") from exc
        except ssl.SSLError as exc:
            raise self.error(f"The TLS handshake with {where} failed ({exc.reason or exc.__class__.__name__}) - is this "
                             "gvmd's TLS port? For an unencrypted port choose 'Plain TCP'") from exc
        except socket.gaierror as exc:
            raise self.error(f"Cannot resolve the host name '{host}'") from exc
        except ConnectionRefusedError as exc:
            raise self.error(f"{where} refused the connection - is gvmd listening for GMP there? By default gvmd only "
                             "listens on a unix socket; TLS on port 9390 needs gvmd --listen and --port") from exc
        except FileNotFoundError as exc:
            raise self.error(f"There is no socket at {where} - check the socket path (often /run/gvmd/gvmd.sock)") from exc
        except PermissionError as exc:
            raise self.error(f"The hub may not open {where} - give the hub's user access (usually the gvm group)") from exc
        except OSError as exc:
            raise self.error(f"Cannot connect to {where}: {exc.strerror or exc.__class__.__name__}") from exc
        return Gmp(self, reader, writer)

    async def login(self, gmp: Gmp) -> str:
        """Authenticate; the user's role ("User", "Admin", "Observer", ...)."""
        username, password = str(self.config.get("username") or "").strip(), self.secrets.get("password", "")
        if not username or not password:
            raise ConnectorError("Enter the Greenbone username and password in the connection settings")
        root = await gmp.command(f"<authenticate><credentials><username>{x(username)}</username>"
                                 f"<password>{x(password)}</password></credentials></authenticate>", "login")
        return (root.findtext("role") or "").strip()

    @asynccontextmanager
    async def session(self) -> AsyncIterator[Gmp]:
        gmp = await self.open()
        try:
            await self.login(gmp)
            yield gmp
        finally:
            await gmp.close()

    def gmp_error(self, what: str, status: str, text: str) -> ConnectorError:
        """A failed GMP answer as a message for people; the status mirrors HTTP so repairs can diagnose it."""
        code = int(status) if status.isdigit() else None
        text = _clean(text, 300) or "no reason given"
        name = self.title
        if what == "login":
            return self.error(f"{name} rejected the login ({text}) - check the username and password", status=401)
        if code == 401:
            return self.error(f"{name} asks for a login again ({what}: {text})", status=401)
        if code == 403:
            return self.error(f"{name} refused {what} ({text}) - the account lacks permission", status=403)
        if code == 404:
            return self.error(f"{name} could not find what {what} needs ({text})", status=404)
        if code == 503:
            return self.error(f"{name} is busy or its scanner is not available ({what}: {text}) - try again later",
                              status=503)
        if code is not None and code >= 500:
            return self.error(f"{name} failed while {what} (GMP {code}: {text})", status=code)
        return self.error(f"{name} rejected {what} (GMP {status or '?'}): {text}", status=400)

    async def listing(self, gmp: Gmp, command: str, tag: str, terms: str = "", attrs: str = "") -> list[ET.Element]:
        """Every item of a GMP list, page by page."""
        items: list[ET.Element] = []
        first = 1
        while True:
            terms_page = f"{terms} first={first} rows={PAGE}".strip()
            root = await gmp.command(f"<{command}{attrs} filter={attr(terms_page)}/>", f"listing {tag.replace('_', ' ')}s")
            page = root.findall(tag)
            items += page
            total = _count(root, f"{tag}_count")
            if not page or (total is not None and len(items) >= total) or (total is None and len(page) < PAGE):
                return items
            if len(items) > MAX_ITEMS:
                raise self.error(f"{self.title} lists more than {MAX_ITEMS} {tag.replace('_', ' ')}s")
            first += len(page)

    # -- test --------------------------------------------------------------------------

    async def test(self) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []
        domains = self.domains()

        def result(detail: str) -> dict[str, Any]:
            ok = bool(checks) and all(c["ok"] for c in checks)
            failed = next((c for c in checks if not c["ok"]), None)
            return {"ok": ok, "detail": detail if ok else f"{failed['name']}: {failed['detail']}" if failed else detail,
                    "checks": checks, "domains": domains if ok else {}}

        try:
            self.config = self.validate_config(self.config)
        except ConnectorError as exc:
            checks.append(check("Settings", False, exc.message))
            return result(exc.message)
        kind = self.config.get("connection_type") or "tls"
        try:
            gmp = await self.open()
        except ConnectorError as exc:
            checks.append(check("Connect", False, exc.message))
            return result(exc.message)
        security = {"tls": "TLS, certificate verified" if self.config.get("verify_tls", True) else
                           "TLS, certificate NOT verified", "unix": "unix socket",
                    "tcp": "plain TCP - unencrypted, labs only"}[kind]
        checks.append(check("Connect", True, f"{self.where()} ({security})"))
        try:
            version = ""
            try:
                version = _clean((await gmp.command("<get_version/>", "reading the GMP version")).findtext("version"), 40)
                old = version.split(".")[0].isdigit() and int(version.split(".")[0]) < 20
                checks.append(check("GMP version", True, f"GMP {version}" + (" - older than 20.08, untested" if old else "")))
            except ConnectorError as exc:
                checks.append(check("GMP version", False, exc.message))
                return result(exc.message)
            try:
                role = await self.login(gmp)
            except ConnectorError as exc:
                checks.append(check("Login", False, exc.message))
                return result(exc.message)
            username = str(self.config.get("username"))
            checks.append(check("Login", True, f"Signed in as {username}" + (f" (role {role})" if role else "")))
            if role.lower() == "observer":
                checks.append(check("Permissions", False, "The Observer role can read results but cannot create "
                                                          "targets or start scans - use a User or Admin account"))
            names: dict[str, str] = {}
            for field, command, tag, label in (("scan_config_id", "get_configs", "config", "Scan config"),
                                               ("scanner_id", "get_scanners", "scanner", "Scanner"),
                                               ("port_list_id", "get_port_lists", "port_list", "Port list")):
                names[field] = await self._check_item(gmp, checks, field, command, tag, label)
            await self._check_scanner_online(gmp, checks)
            await self._check_feed(gmp, checks)
            try:
                root = await gmp.command(f"<get_tasks filter={attr('first=1 rows=1')}/>", "listing scan tasks")
                count = _count(root, "task_count")
                checks.append(check("Read scan results", True, f"{count if count is not None else 'Some'} scan task(s) "
                                                                "visible to this account"))
            except ConnectorError as exc:
                checks.append(check("Read scan results", False, exc.message))
        finally:
            await gmp.close()
        return result(f"Connected to Greenbone (GMP {version}) as {username}; scans use '{names['scan_config_id']}' "
                      f"on '{names['scanner_id']}' with port list '{names['port_list_id']}'.")

    async def _check_item(self, gmp: Gmp, checks: list[dict[str, Any]], field: str, command: str, tag: str,
                          label: str) -> str:
        item_id = str(self.config.get(field) or "")
        try:
            root = await gmp.command(f"<{command} {tag}_id={attr(item_id)}/>", f"reading the {label.lower()}")
            item = root.find(tag)
            if item is None:
                raise self.error(f"{self.title} could not find the {label.lower()} {item_id}", status=404)
        except ConnectorError as exc:
            hint = " - choose another one" + (" (the feed's scan configs may not be loaded yet)" if tag == "config" else "")
            checks.append(check(label, False, exc.message + (hint if exc.status == 404 else "")))
            return item_id
        name = _clean(item.findtext("name")) or item_id
        detail = name
        if tag == "config":
            nvts = (item.findtext("nvt_count") or "").strip()
            if nvts == "0":
                checks.append(check(label, False, f"'{name}' has no vulnerability tests (NVTs) yet - wait until "
                                                  "Greenbone has loaded its feed"))
                return name
            detail += f" ({nvts} NVTs)" if nvts.isdigit() else ""
            if (item.findtext("usage_type") or "scan") != "scan":
                checks.append(check(label, False, f"'{name}' is a compliance policy, not a scan config"))
                return name
        if tag == "scanner":
            kind = (item.findtext("type") or "").strip()
            detail += f" ({SCANNER_TYPES.get(kind, f'type {kind}')})" if kind else ""
        checks.append(check(label, True, detail))
        return name

    async def _check_scanner_online(self, gmp: Gmp, checks: list[dict[str, Any]]) -> None:
        scanner_id = str(self.config.get("scanner_id") or "")
        try:
            root = await gmp.command(f"<verify_scanner scanner_id={attr(scanner_id)}/>", "verifying the scanner")
            version = _clean(root.findtext("version"))
            checks.append(check("Scanner online", True, f"The scanner answers{f' ({version})' if version else ''}"))
        except ConnectorError as exc:
            if exc.status in (401, 403):
                checks.append(check("Scanner online", True, "Not checked: this account may not verify scanners"))
            else:
                checks.append(check("Scanner online", False, exc.message + " - scans would stay 'Requested'; check "
                                                                          "that ospd-openvas / openvasd is running"))

    async def _check_feed(self, gmp: Gmp, checks: list[dict[str, Any]]) -> None:
        try:
            root = await gmp.command('<get_feeds type="NVT"/>', "reading the feed status")
        except ConnectorError:
            return  # older managers or restricted accounts: the scan config check already shows a missing feed
        feed = root.find("feed")
        if feed is None:
            return
        version = _clean(feed.findtext("version"))
        if feed.find("currently_syncing") is not None:
            checks.append(check("NVT feed", True, f"Version {version or '?'} - a feed update is running, scans may "
                                                  "miss tests until it finishes"))
        elif feed.find("sync_not_available") is not None:
            checks.append(check("NVT feed", False, _clean(feed.findtext("sync_not_available/error"), 300)
                                or "The feed is not available"))
        else:
            checks.append(check("NVT feed", True, f"Version {version}" if version else "Available"))

    # -- options ---------------------------------------------------------------------

    async def options(self, field_name: str) -> list[dict[str, str]]:
        specs = {"scan_config_id": ("get_configs", "config", "sort=name", ' usage_type="scan"', FULL_AND_FAST),
                 "scanner_id": ("get_scanners", "scanner", "sort=name", "", OPENVAS_DEFAULT),
                 "port_list_id": ("get_port_lists", "port_list", "sort=name", "", ALL_IANA_TCP)}
        if field_name not in specs:
            return await super().options(field_name)
        command, tag, terms, attrs, default = specs[field_name]
        async with self.session() as gmp:
            items = await self.listing(gmp, command, tag, terms, attrs)
        out = []
        for item in items:
            item_id = item.get("id") or ""
            if not UUID_RE.match(item_id) or (tag == "config" and (item.findtext("usage_type") or "scan") != "scan"):
                continue
            label = _clean(item.findtext("name")) or item_id
            if tag == "scanner" and (kind := (item.findtext("type") or "").strip()):
                label += f" ({SCANNER_TYPES.get(kind, f'type {kind}')})"
            out.append({"value": item_id, "label": label + (" - default" if item_id == default else "")})
        return out

    # -- scans -----------------------------------------------------------------------

    async def action(self, name: str, params: dict[str, Any]) -> dict[str, Any]:
        if name == "scan":
            return await self.scan(params.get("hosts"), params.get("name"))
        if name == "scan_status":
            return await self.scan_status(params.get("job_id"))
        return await super().action(name, params)

    async def scan(self, hosts: Any, name: Any = None) -> dict[str, Any]:
        """Create a target and a task for `hosts` and start it; the job id is the task id."""
        if isinstance(hosts, str):
            hosts = [hosts]
        if not isinstance(hosts, (list, tuple)) or not hosts:
            raise ConnectorError("No hosts to scan")
        clean = []
        for host in hosts:
            if not isinstance(host, str) or not valid_scan_target(host):
                raise ConnectorError(f"Refusing to scan '{_clean(host, 80)}': only IP addresses, networks (CIDR) and "
                                     "host names can be scanned")
            host = host.strip()
            if host not in clean:
                clean.append(host)
        if len(clean) > MAX_HOSTS:
            raise ConnectorError(f"Too many hosts for one scan ({len(clean)}; at most {MAX_HOSTS})")
        title = _clean(name, 150) or "Atrium scan"
        alive = str(self.config.get("alive_test") or "")
        alive_xml = f"<alive_tests>{x(alive)}</alive_tests>" if alive in ALIVE_TESTS and alive != ALIVE_TESTS[0] else ""
        async with self.session() as gmp:
            target = await gmp.command(
                f"<create_target><name>{x(f'{title} - {tokens.token_hex(3)}')}</name><comment>{x(COMMENT)}</comment>"
                f"<hosts>{x(','.join(clean))}</hosts><port_list id={attr(self.config.get('port_list_id') or ALL_IANA_TCP)}/>"
                f"{alive_xml}</create_target>", "creating the scan target")
            target_id = target.get("id") or ""
            try:
                task = await gmp.command(
                    f"<create_task><name>{x(title)}</name><comment>{x(COMMENT)}</comment>"
                    f"<config id={attr(self.config.get('scan_config_id') or FULL_AND_FAST)}/><target id={attr(target_id)}/>"
                    f"<scanner id={attr(self.config.get('scanner_id') or OPENVAS_DEFAULT)}/></create_task>",
                    "creating the scan task")
                task_id = task.get("id") or ""
                if not UUID_RE.match(task_id):
                    raise self.error(f"{self.title} created no scan task (its answer has no task id)")
                try:
                    started = await gmp.command(f"<start_task task_id={attr(task_id)}/>", "starting the scan")
                except ConnectorError:
                    await self._discard(gmp, f"<delete_task task_id={attr(task_id)}/>")
                    raise
            except ConnectorError:
                if UUID_RE.match(target_id):
                    await self._discard(gmp, f"<delete_target target_id={attr(target_id)}/>")
                raise
        return {"job_id": task_id, "report_id": (started.findtext("report_id") or "").strip() or None,
                "target_id": target_id, "hosts": len(clean)}

    @staticmethod
    async def _discard(gmp: Gmp, command: str) -> None:
        """Move what a failed scan start created to the trashcan; a failure here changes nothing for the caller."""
        try:
            await gmp.command(command, "cleaning up")
        except ConnectorError:
            pass

    async def scan_status(self, job_id: Any) -> dict[str, Any]:
        job_id = str(job_id or "").strip()
        if not UUID_RE.match(job_id):
            raise ConnectorError("The scan job id is not a Greenbone task id")
        async with self.session() as gmp:
            try:
                root = await gmp.command(f"<get_tasks task_id={attr(job_id)}/>", "reading the scan status")
            except ConnectorError as exc:
                if exc.status != 404:
                    raise
                root = ET.Element("get_tasks_response")
        task = root.find("task")
        if task is None:
            return {"status": "failed", "progress": 0, "done": False,
                    "detail": f"The scan task {job_id} no longer exists in {self.title}"}
        raw = _clean(task.findtext("status"), 60)
        state, done = TASK_STATES.get(raw.lower(), (raw.lower() or "unknown", False))
        progress = _float(task.findtext("progress"))
        progress = 100 if done else max(0, min(99, int(progress or 0)))
        report = task.find("current_report/report")
        if report is None:
            report = task.find("last_report/report")
        return {"status": state, "progress": progress, "done": done, "scanner_status": raw,
                "report_id": report.get("id") if report is not None else None}

    # -- findings --------------------------------------------------------------------

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        if domain != "vulnerabilities":
            return await super().pull(domain, since)
        async with self.session() as gmp:
            reports = []
            for task in await self.listing(gmp, "get_tasks", "task", "apply_overrides=0 sort=name"):
                if (task.findtext("usage_type") or "scan").strip() != "scan":
                    continue
                report = task.find("last_report/report")
                if report is None or not UUID_RE.match(report.get("id") or "") or not UUID_RE.match(task.get("id") or ""):
                    continue
                at, created = _time(report.findtext("timestamp")), _time(task.findtext("creation_time"))
                if since is not None:  # the hub's scans create their task: older tasks are someone else's
                    stamp = created if created is not None else at
                    if stamp is not None and stamp < since - CLOCK_SLACK:
                        continue  # an unreadable time is kept: leaving a report out could mark its findings fixed
                target = task.find("target")
                reports.append({"id": report.get("id"), "task_id": task.get("id"), "at": (at or 0.0, created or 0.0),
                                "target_id": target.get("id") if target is not None else ""})
            reports.sort(key=lambda r: r["at"], reverse=True)  # by report time, then task creation (same second)
            records: dict[str, dict[str, Any]] = {}
            newer_targets: list[list[str]] = []
            newer_hosts: set[str] = set()
            count = 0
            for report in reports:  # newest first: a newer scan of a host decides what is still there
                targets = await self._target_hosts(gmp, report["target_id"])
                found = await self._results(gmp, report["id"], report["task_id"], targets)
                count += len(found)
                if count > MAX_RECORDS:
                    raise self.error(f"{self.title} reports more than {MAX_RECORDS} results - raise the minimum "
                                     "quality of detection or scan fewer hosts per task")
                for record, names in found:
                    if names & newer_hosts or any(_covers(t, n) for t in newer_targets for n in names):
                        continue
                    records.setdefault(record["external_id"], record)
                newer_targets.append(targets)
                newer_hosts |= {n for _, names in found for n in names}
        return list(records.values())

    async def _target_hosts(self, gmp: Gmp, target_id: str) -> list[str]:
        if not UUID_RE.match(target_id or ""):
            return []  # a container task (imported reports) has no target
        try:
            root = await gmp.command(f"<get_targets target_id={attr(target_id)}/>", "reading the scan target")
        except ConnectorError as exc:
            if exc.status in (403, 404):
                return []  # the target was deleted or is not ours: findings keep their scanned address
            raise
        hosts = root.findtext("target/hosts") or ""
        return [h.strip().lower().rstrip(".") for h in hosts.split(",") if h.strip()]

    async def _results(self, gmp: Gmp, report_id: str, task_id: str,
                       targets: list[str]) -> list[tuple[dict[str, Any], set[str]]]:
        """Every result of one report as canonical findings with the host's address and name - all of them or an
        error, never part of them."""
        terms = f"report_id={report_id} apply_overrides=1 min_qod={int(self.config.get('min_qod', 70))}"
        terms += "" if self.config.get("import_log") else " severity>0"
        terms += " sort-reverse=severity"
        seen: dict[str, tuple[dict[str, Any], set[str]] | None] = {}
        first, total = 1, None
        while True:
            root = await gmp.command(
                f'<get_results task_id={attr(task_id)} details="1" get_counts="1" '
                f"filter={attr(f'{terms} first={first} rows={PAGE}')}/>", "reading scan results")
            page = root.findall("result")
            total = _count(root, "result_count")
            for index, element in enumerate(page):
                record = self.finding(element, targets)
                names = {n.lower().rstrip(".") for n in ((element.findtext("host") or "").strip(),
                                                         (element.findtext("host/hostname") or "").strip()) if n}
                seen[element.get("id") or f"#{first + index}"] = (record, names) if record else None
            if not page or (total is not None and first - 1 + len(page) >= total) or (total is None and len(page) < PAGE):
                break
            if len(seen) > MAX_RECORDS:
                raise self.error(f"{self.title} reports more than {MAX_RECORDS} results for one scan")
            first += len(page)
        if total is not None and len(seen) < total:
            raise self.error(f"{self.title} counted {total} results for report {report_id} but sent {len(seen)} - the "
                             "report changed while it was read; try again")
        return [record for record in seen.values() if record is not None]

    def finding(self, result: ET.Element, targets: list[str]) -> dict[str, Any] | None:
        """One GMP result as a canonical vulnerability record (None for false positives, debug and error results)."""
        nvt = result.find("nvt")
        if nvt is None:
            nvt = ET.Element("nvt")
        score = _float(result.findtext("severity"))
        if score is None:
            fallback = _float(nvt.find("severities").get("score")) if nvt.find("severities") is not None else None
            fallback = fallback if fallback is not None else _float(nvt.findtext("cvss_base"))
            score = fallback / 10 if fallback is not None and fallback > 10 else fallback  # some managers give 0-100
        if score is not None and score < 0:
            return None
        host_element = result.find("host")
        ip = ((host_element.text if host_element is not None else "") or "").strip()
        hostname = (result.findtext("host/hostname") or "").strip()
        host = pick_host(ip, hostname, targets)
        if not host:
            return None
        port = (result.findtext("port") or "").strip() or "general"
        oid = (nvt.get("oid") or "").strip() or _clean(result.findtext("name"), 100) or "unknown"
        tags = _tags(nvt.findtext("tags"))
        cves = [ref.get("id", "") for ref in nvt.iter("ref") if (ref.get("type") or "").lower() == "cve"]
        cves += re.findall(r"CVE-\d{4}-\d{4,}", nvt.findtext("cve") or "", re.IGNORECASE)  # managers before GMP 8
        solution_element = nvt.find("solution")
        solution = ((solution_element.text if solution_element is not None else "") or "").strip() or tags.get("solution", "")
        solution_type = (solution_element.get("type") if solution_element is not None else None) or tags.get("solution_type")
        if solution_type:
            solution = f"{solution} ({solution_type})" if solution else solution_type
        parts = [tags.get("summary", "")]
        detection = (result.findtext("description") or "").strip()
        if detection:
            parts.append(f"Detection result:\n{detection}")
        parts += [f"{label}: {tags[key]}" for key, label in (("insight", "Insight"), ("impact", "Impact"),
                                                              ("affected", "Affected")) if tags.get(key)]
        qod = (result.findtext("qod/value") or "").strip()
        parts.append(f"OpenVAS NVT {oid}" + (f", quality of detection {qod}%" if qod else ""))
        return {
            "external_id": f"{oid}|{host}|{port}",
            "title": (result.findtext("name") or nvt.findtext("name") or oid).strip(),
            "severity": severity_from_score(score),
            "cvss": score,
            "cves": cves,
            "host": host,
            "port": port,
            "description": "\n\n".join(p for p in parts if p),
            "solution": solution,
            "detected_at": _time(result.findtext("creation_time")) or _time(result.findtext("modification_time")),
            "scanner": SCANNER_NAME,
        }


def _host_ok(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOSTNAME_RE.match(host))


def _integer(value: Any) -> int | None:
    """A whole number from a setting (numbers or numeric text; never a bool)."""
    if isinstance(value, bool):
        return None
    try:
        number = float(str(value).strip())
    except ValueError:
        return None
    return int(number) if number.is_integer() else None
