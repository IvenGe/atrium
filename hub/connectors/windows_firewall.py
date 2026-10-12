"""Windows Defender Firewall over OpenSSH and PowerShell (``kind`` ``windows_firewall``).

There is no sudoers file and this connector never accepts a password (no sudo password, no account password,
no ``SshTarget.password``). The SSH user is a key-only account. Writes need an elevated token: ``whoami /groups``
contains the High Mandatory Level SID ``S-1-16-12288``.

# UNVERIFIED: that SID means the OpenSSH session is elevated (fw-hosts 4.1). Whether Win32-OpenSSH sets
# UNVERIFIED: ``SSH_CONNECTION`` was not verified (fw-hosts 0.1); the read script still prints it when it is set.

The dead-man switch is a Scheduled Task (not systemd). ``arm-revert`` exports the current store with
``netsh advfirewall export`` and registers task ``atrium-fw-revert-<change id>`` to import that file after the
window. ``apply`` then adds or disables rules. Windows persists rules immediately, so a reboot does not roll
them back; the task does, until ``confirm`` unregisters it. ``revert-now`` imports the export and unregisters
the task.

The five verbs (``snapshot``, ``arm-revert``, ``apply``, ``confirm``, ``revert-now``) are the actions of one
fixed PowerShell script. The script is ``powershell.exe -NoProfile -NonInteractive -Command -`` with the body
on stdin. The change itself is base64 inside that script so device text is data, not shell text. Rule names
passed to a cmdlet must match ``^[A-Za-z0-9_.:-]{1,200}$``. ``OpenSSH-Server-In-TCP`` is never disabled.

Linux sudoers for the same verbs live in ``hub/connectors/hostfw.py``. Do not add a sudo password there either.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import time
from typing import Any

from ..execution.runner import SshError, SshTarget, parse_ssh_connection, posix_command
from .base import HOSTNAME_RE, Connector, ConnectorError, ConnectorField, check
from .hostfw import _SAFE_ARG, merge_by_marker
from .netmodel import (
    LEAST_PRIVILEGE_NOTE,
    Backup,
    ChangeError,
    derived_revision,
    find_marker,
    management_guard,
    normalize_record,
    parse_ops,
    parse_ports,
    untrusted_text,
    validate_write_spec,
)

PS_ARGV = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "-"]
_WINDOW = 180
_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,200}$")
_CHANGE_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_PASSWORD_KEYS = {"password", "sudo_password", "sudo_pass", "root_password"}
OPENSSH_RULE = "OpenSSH-Server-In-TCP"
_TRUE = {"true", "1", "enabled", "yes"}
_FALSE = {"false", "2", "disabled", "no"}
_ACTION = {"allow": "pass", "2": "pass", "allowbypass": "pass", "3": "pass", "block": "block", "4": "block",
           "deny": "block"}
_DIRECTION = {"inbound": "in", "1": "in", "outbound": "out", "2": "out"}
_POLICY = {"block": "block", "deny": "block", "allow": "pass", "permit": "pass", "notconfigured": "unknown"}

READ_SCRIPT = r"""$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
  $ssh = [string]$env:SSH_CONNECTION
  $os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
  $groups = (whoami /groups) -join "`n"
  $elevated = $groups -match 'S-1-16-12288'
  $profiles = @(Get-NetFirewallProfile | ForEach-Object {
    [pscustomobject]@{ name = [string]$_.Name; enabled = [string]$_.Enabled
      inbound = [string]$_.DefaultInboundAction; outbound = [string]$_.DefaultOutboundAction
      allow_local = [string]$_.AllowLocalFirewallRules }
  })
  $addrs = @(Get-NetIPAddress | ForEach-Object {
    [pscustomobject]@{ alias = [string]$_.InterfaceAlias; address = [string]$_.IPAddress
      prefix = [int]$_.PrefixLength; family = [string]$_.AddressFamily }
  })
  $store = 'ActiveStore'
  # UNVERIFIED: port and address filters join to rules on InstanceID (fw-hosts 4.2).
  $pf = @{}; Get-NetFirewallPortFilter -All -PolicyStore $store | ForEach-Object { $pf[$_.InstanceID] = $_ }
  $af = @{}; Get-NetFirewallAddressFilter -All -PolicyStore $store | ForEach-Object { $af[$_.InstanceID] = $_ }
  $rules = @(foreach ($r in Get-NetFirewallRule -PolicyStore $store) {
    $p = $pf[$r.InstanceID]; $a = $af[$r.InstanceID]
    [pscustomobject]@{ name = [string]$r.Name; display_name = [string]$r.DisplayName
      description = [string]$r.Description; group = [string]$r.Group; enabled = [string]$r.Enabled
      direction = [string]$r.Direction; action = [string]$r.Action; profile = [string]$r.Profile
      enforcement = @($r.EnforcementStatus)
      protocol = $(if ($p) { [string]$p.Protocol } else { '' })
      local_port = $(if ($p) { @($p.LocalPort) } else { @() })
      remote_port = $(if ($p) { @($p.RemotePort) } else { @() })
      local_address = $(if ($a) { @($a.LocalAddress) } else { @() })
      remote_address = $(if ($a) { @($a.RemoteAddress) } else { @() }) }
  })
  ConvertTo-Json -InputObject ([pscustomobject]@{ ok = $true; hostname = [string]$env:COMPUTERNAME
    ssh_connection = $ssh; elevated = [bool]$elevated; os = $os; profiles = $profiles
    addresses = $addrs; rules = $rules }) -Depth 6 -Compress
  exit 0
} catch {
  ConvertTo-Json -InputObject ([pscustomobject]@{ ok = $false; error = [string]$_.Exception.Message }) -Compress
  exit 1
}
"""

# Arm (Register-ScheduledTask) is a separate verb from apply (New-NetFirewallRule). The connector calls arm first.
WRITE_SCRIPT = r"""$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$b64 = @'
__PAYLOAD_B64__
'@
try {
  $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64.Trim()))
  $payload = $json | ConvertFrom-Json
  $id = [string]$payload.change_id
  if ($id -notmatch '^[A-Za-z0-9_-]{1,64}$') { throw 'bad change id' }
  $dir = 'C:\ProgramData\Atrium\fw'
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $file = Join-Path $dir ($id + '.wfw')
  $task = 'atrium-fw-revert-' + $id
  $verb = [string]$payload.verb
  if ($verb -eq 'confirm') {
    Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
    ConvertTo-Json -InputObject ([pscustomobject]@{ ok = $true; confirmed = $true }) -Compress
    exit 0
  }
  if ($verb -eq 'revert-now') {
    if (Test-Path -LiteralPath $file) { & netsh.exe advfirewall import $file | Out-Null }
    Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
    ConvertTo-Json -InputObject ([pscustomobject]@{ ok = $true; rolled_back = $true }) -Compress
    exit 0
  }
  if ($verb -eq 'snapshot') {
    & netsh.exe advfirewall export $file | Out-Null
    # UNVERIFIED: netsh export is a complete store and is readable as soon as the command returns (fw-hosts 4.4).
    $wfw = [Convert]::ToBase64String([IO.File]::ReadAllBytes($file))
    ConvertTo-Json -InputObject ([pscustomobject]@{ ok = $true; path = $file; wfw_b64 = $wfw }) -Compress
    exit 0
  }
  if ($verb -eq 'import') {
    $raw = [string]$payload.wfw_b64
    if ($raw -notmatch '^[A-Za-z0-9+/=]+$') { throw 'unsafe export' }
    [IO.File]::WriteAllBytes($file, [Convert]::FromBase64String($raw))
    & netsh.exe advfirewall import $file | Out-Null
    ConvertTo-Json -InputObject ([pscustomobject]@{ ok = $true; restored = $true }) -Compress
    exit 0
  }
  if ($verb -eq 'arm-revert') {
    & netsh.exe advfirewall export $file | Out-Null
    $act = New-ScheduledTaskAction -Execute 'netsh.exe' -Argument ('advfirewall import "' + $file + '"')
    $seconds = [int]$payload.window_s
    if ($seconds -lt 10) { $seconds = 10 }
    $trg = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddSeconds($seconds))
    # UNVERIFIED: New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest (fw-hosts 4.4).
    $prn = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $task -Action $act -Trigger $trg -Principal $prn -Force | Out-Null
    ConvertTo-Json -InputObject ([pscustomobject]@{ ok = $true; task = $task; armed = $true }) -Compress
    exit 0
  }
  if ($verb -eq 'apply') {
    foreach ($rule in @($payload.rules)) {
      $name = [string]$rule.name
      if ($name -notmatch '^[A-Za-z0-9_.:-]{1,200}$') { throw 'unsafe rule name' }
      if ($name -eq 'OpenSSH-Server-In-TCP') { throw 'refusing to change the OpenSSH rule' }
      $op = [string]$rule.op
      if ($op -eq 'disable') { Disable-NetFirewallRule -Name $name }
      elseif ($op -eq 'enable') { Enable-NetFirewallRule -Name $name }
      else {
        $params = @{ Name = $name; DisplayName = [string]$rule.display_name; Group = 'Atrium'
          Direction = 'Inbound'; Action = 'Allow'; Protocol = [string]$rule.protocol; Profile = 'Any'
          Enabled = 'True'; Description = [string]$rule.description }
        $remote = @($rule.remote); $local = @($rule.local)
        if ($remote) { $params.RemoteAddress = $remote }
        if ($local) { $params.LocalAddress = $local }
        $proto = [string]$params.Protocol
        if ($proto -eq 'TCP' -or $proto -eq 'UDP') { $params.LocalPort = @($rule.ports) }
        New-NetFirewallRule @params | Out-Null
      }
    }
    ConvertTo-Json -InputObject ([pscustomobject]@{ ok = $true; applied = $true }) -Compress
    exit 0
  }
  throw 'unknown verb'
} catch {
  ConvertTo-Json -InputObject ([pscustomobject]@{ ok = $false; error = [string]$_.Exception.Message }) -Compress
  exit 1
}
"""


def _refuse_password(config: dict[str, Any], secrets: dict[str, str]) -> None:
    if any(key.lower() in _PASSWORD_KEYS for key in secrets) or config.get("password") or config.get("sudo_password"):
        raise ConnectorError("This connector never accepts a sudo or account password. Use an SSH key; "
                             "Windows writes need an elevated token, not a password")


def _ps_command() -> str:
    if any(not _SAFE_ARG.fullmatch(part) for part in PS_ARGV):
        raise ConnectorError("the PowerShell command is not a fixed token list")
    return posix_command(PS_ARGV)


def _as_list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    return [value]


def _enabled(value: Any) -> bool:
    text = str(value if value is not None else "true").strip().lower()
    if text in _FALSE:
        return False
    if text in _TRUE:
        return True
    return True


def _cidrs(values: list[Any]) -> tuple[list[str], bool]:
    """Return (cidrs, is_any). 'Any' and the other Windows address keywords are any, not a network."""
    cidrs: list[str] = []
    any_ = False
    for value in values:
        text = str(value or "").strip()
        if not text or text.lower() in {"any", "localsubnet", "internet", "intranet", "dns", "dhcp", "wins",
                                        "defaultgateway", "playtodevice", "captiveportal"}:
            any_ = True
            continue
        if text.lower().endswith(("4", "6")) and text.lower()[:-1] in {"any", "localsubnet", "internet"}:
            any_ = True
            continue
        try:
            cidrs.append(str(ipaddress.ip_network(text, strict=False)))
        except ValueError:
            any_ = True
    return list(dict.fromkeys(cidrs)), any_ and not cidrs


def _ports(values: list[Any]) -> str | None:
    parts: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text.lower() == "any":
            return None
        parts.append(text)
    if not parts:
        return None
    try:
        return parse_ports(",".join(parts))
    except ValueError:
        return None


def parse_windows(document: dict[str, Any]) -> dict[str, Any]:
    """The read script's JSON (or the research sample's rule list) into record pieces."""
    raw_rules = document.get("rules") if isinstance(document, dict) else document
    if isinstance(raw_rules, dict):
        raw_rules = [raw_rules]
    rules = []
    gpo = False
    for order, item in enumerate(raw_rules or [], start=1):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("Name") or "")
        if not name:
            continue
        action = _ACTION.get(str(item.get("action") or item.get("Action") or "allow").strip().lower(), "pass")
        direction = _DIRECTION.get(str(item.get("direction") or "inbound").strip().lower(), "in")
        proto = str(item.get("protocol") or "").strip().lower()
        ports = _ports(_as_list(item.get("local_port")))
        services = None
        if proto in {"tcp", "udp"}:
            services = [{"proto": proto, "ports": ports}] if ports else [{"proto": proto}]
        elif proto in {"icmpv4", "icmpv6", "icmp"}:
            services = [{"proto": "icmp"}]
        elif proto in {"", "any", "256"}:
            services = None
        remote, remote_any = _cidrs(_as_list(item.get("remote_address")))
        local, local_any = _cidrs(_as_list(item.get("local_address")))
        source = {"any": True} if remote_any or not remote else {"cidrs": remote}
        destination = {"any": True} if local_any or not local else {"cidrs": local}
        description = item.get("description") or item.get("display_name") or ""
        rule: dict[str, Any] = {
            "id": name, "vendor_ref": name, "order": order, "enabled": _enabled(item.get("enabled")),
            "action": action, "direction": direction, "source": source, "destination": destination,
            "services": services, "description": untrusted_text(description), "log": False,
        }
        profile = str(item.get("profile") or "")
        if profile and profile.lower() not in {"", "any", "0"}:
            rule["source_zones"] = [profile.lower()]
        rules.append(rule)
        enforcement = " ".join(str(v) for v in _as_list(item.get("enforcement")))
        if "LocalFirewallRulesDisallowed" in enforcement or "16" == enforcement:
            gpo = True
    interfaces: dict[str, dict[str, Any]] = {}
    addresses: list[str] = []
    for item in _as_list(document.get("addresses") if isinstance(document, dict) else None):
        if not isinstance(item, dict):
            continue
        alias = str(item.get("alias") or "")
        address = str(item.get("address") or "").split("%", 1)[0]
        if not alias or not address:
            continue
        try:
            ip = ipaddress.ip_address(address)
            prefix = int(item.get("prefix") or (128 if ip.version == 6 else 32))
            network = str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))
        except (TypeError, ValueError):
            continue
        slot = interfaces.setdefault(alias, {"id": alias, "name": alias, "role": "lan", "subnets": [],
                                             "addresses": [], "enabled": True})
        if ip.is_loopback or alias.lower().startswith("loopback"):
            slot["role"] = "other"
        if address not in slot["addresses"]:
            slot["addresses"].append(address)
        if network not in slot["subnets"]:
            slot["subnets"].append(network)
        if address not in addresses:
            addresses.append(address)
    profiles = _as_list(document.get("profiles") if isinstance(document, dict) else None)
    inbound, outbound, allow_local = [], [], True
    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        inbound.append(_POLICY.get(str(profile.get("inbound") or "").strip().lower(), "unknown"))
        outbound.append(_POLICY.get(str(profile.get("outbound") or "").strip().lower(), "unknown"))
        if str(profile.get("allow_local") or "true").strip().lower() in _FALSE:
            allow_local = False
    policy: dict[str, str] = {}
    if inbound:
        policy["inbound"] = inbound[0] if len(set(inbound)) == 1 else "unknown"
    if outbound:
        policy["outbound"] = outbound[0] if len(set(outbound)) == 1 else "unknown"
    zones = [{"id": name, "name": name, "interfaces": [name]} for name in interfaces]
    for profile_name in ("domain", "private", "public"):
        zones.append({"id": profile_name, "name": profile_name, "interfaces": [],
                      "description": "Windows firewall profile"})
    os_info = document.get("os") if isinstance(document, dict) and isinstance(document.get("os"), dict) else {}
    return {"rules": merge_by_marker(rules), "interfaces": list(interfaces.values()), "zones": zones,
            "addresses": addresses, "policy": policy, "allow_local": allow_local, "gpo": gpo,
            "elevated": bool(document.get("elevated")) if isinstance(document, dict) else False,
            "hostname": str(document.get("hostname") or "") if isinstance(document, dict) else "",
            "ssh_connection": str(document.get("ssh_connection") or "") if isinstance(document, dict) else "",
            "os": os_info}


class WindowsFirewallConnector(Connector):
    kind = "windows_firewall"
    title = "Windows Defender Firewall"
    description = ("Windows Defender Firewall over OpenSSH and PowerShell. A Scheduled Task reverts the change "
                   "unless it is confirmed. No sudo password is stored or sent.")
    fields = [
        ConnectorField(name="host", label="Host", required=True, placeholder="10.0.99.20"),
        ConnectorField(name="port", label="SSH port", kind="number", default=22),
        ConnectorField(name="username", label="SSH user", required=True, placeholder="atrium"),
        ConnectorField(name="private_key", label="Private key", kind="secret", required=True,
                       help="OpenSSH private key. A key passphrase is not a password for the firewall."),
        ConnectorField(name="passphrase", label="Key passphrase", kind="secret",
                       help="Passphrase for the private key only. An account password is never accepted."),
        ConnectorField(name="host_key", label="Pinned host key", placeholder="ssh-ed25519 AAAA..."),
        ConnectorField(name="strict_host_keys", label="Strict host key checking", kind="bool", default=True),
        ConnectorField(name="window_s", label="Revert window (seconds)", kind="number", default=_WINDOW),
        ConnectorField(name="read_only", label="Read-only credential", kind="bool", default=False,
                       help="When on, device changes are not offered even if the token is elevated."),
    ]
    capabilities = {"network": {"read"}}
    network_write = {"ops": ["allow", "disable_rules", "enable_rules"], "rollback": "deadman", "window_s": _WINDOW}

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        host = str(config.get("host") or "").strip()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not HOSTNAME_RE.match(host):
                raise ConnectorError("The host must be an IP address or a hostname")
        user = str(config.get("username") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9._\\-]{1,64}", user):
            raise ConnectorError("The SSH user must be letters, digits, '.', '_', '-' or a domain backslash")
        try:
            port = int(config.get("port") or 22)
            window = int(config.get("window_s") or _WINDOW)
        except (TypeError, ValueError) as exc:
            raise ConnectorError("The SSH port and the revert window must be numbers") from exc
        if not 1 <= port <= 65535:
            raise ConnectorError("The SSH port is 1-65535")
        if not 10 <= window <= 3600:
            raise ConnectorError("The revert window is 10-3600 seconds")
        if config.get("password") or config.get("sudo_password"):
            raise ConnectorError("A password is not accepted. Use an SSH key")
        pinned = str(config.get("host_key") or "").strip()
        if pinned and not re.match(r"^ssh-(ed25519|rsa|ecdsa)(\s+\S+){1,2}$", pinned):
            raise ConnectorError("The pinned host key must look like 'ssh-ed25519 AAAA...'")
        return {**config, "host": host, "username": user, "port": port, "window_s": window, "host_key": pinned or None}

    @classmethod
    def detect(cls, tool) -> int:
        return cls.name_score(tool, ("windows firewall", "windows defender", "defender firewall", "windows_firewall"))

    def write_capability(self) -> dict[str, Any] | None:
        if self.config.get("read_only"):
            return None
        return validate_write_spec({**self.network_write, "window_s": int(self.config.get("window_s") or _WINDOW)})

    def _target(self) -> SshTarget:
        _refuse_password(self.config, self.secrets)
        key = self.secrets.get("private_key")
        if not key:
            raise ConnectorError("The SSH private key is missing")
        host = str(self.config.get("host") or "").strip()
        user = str(self.config.get("username") or "").strip()
        if not host or not user:
            raise ConnectorError("Host and SSH user are required")
        return SshTarget(host=host, username=user, port=int(self.config.get("port") or 22), private_key=key,
                         passphrase=self.secrets.get("passphrase"),
                         strict_host_keys=bool(self.config.get("strict_host_keys", True)),
                         host_key=(self.config.get("host_key") or None))

    def _script(self, payload: dict[str, Any]) -> str:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        blob = base64.b64encode(raw).decode("ascii")
        if not re.fullmatch(r"[A-Za-z0-9+/=]+", blob):
            raise ChangeError("the change payload could not be encoded", code="failed", state="unchanged")
        return WRITE_SCRIPT.replace("__PAYLOAD_B64__", blob, 1)

    async def _powershell(self, session: Any, script: str, *, state: str | None) -> dict[str, Any]:
        result = await session.run(_ps_command(), input=script)
        if result.truncated:
            message = "PowerShell output was truncated; refusing to parse a partial result"
            if state is None:
                raise ConnectorError(message)
            raise ChangeError(message, code="failed", state=state)
        text = result.stdout.strip()
        try:
            data = json.loads(text or "{}")
        except ValueError as exc:
            message = f"PowerShell did not return JSON ({result.exit_status})"
            if state is None:
                raise ConnectorError(message) from exc
            raise ChangeError(message, code="failed", state=state) from exc
        if not isinstance(data, dict) or not data.get("ok", result.ok):
            message = str((data or {}).get("error") if isinstance(data, dict) else "") or "PowerShell failed"
            if state is None:
                raise ConnectorError(message)
            raise ChangeError(message, code="failed", state=state)
        return data

    async def _read(self, session: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        data = await self._powershell(session, READ_SCRIPT, state=None)
        parsed = parse_windows(data)
        return data, parsed

    def _record(self, parsed: dict[str, Any]) -> dict[str, Any]:
        os_info = parsed.get("os") or {}
        hostname = parsed.get("hostname") or str(self.config.get("host") or "windows")
        version = " ".join(str(os_info.get(key) or "") for key in ("Caption", "Version", "BuildNumber")).strip()
        ssh = parse_ssh_connection(parsed.get("ssh_connection") or "")
        addresses = list(parsed.get("addresses") or [])
        if ssh and ssh.get("server_ip") and ssh["server_ip"] not in addresses:
            addresses.append(ssh["server_ip"])
        notes = [
            "Windows Firewall has no administrator rule order; an explicit block beats this allow",
            "rules persist immediately; the Scheduled Task is what reverts them until confirm",
            "per-rule hit counts are not available",
        ]
        # UNVERIFIED: Win32_OperatingSystem Caption/Version/BuildNumber (fw-hosts 4.2).
        if not parsed.get("allow_local", True) or parsed.get("gpo"):
            notes.append("Group Policy disallows local firewall rules; a rule Atrium adds would not apply")
        if not parsed.get("ssh_connection"):
            notes.append("SSH_CONNECTION was empty; the hub source address was not learned from the host")
        rules = [{k: v for k, v in rule.items() if k != "hits"} for rule in parsed["rules"]]
        revision = derived_revision("windows_firewall", rules, parsed["interfaces"], parsed["policy"], hostname)
        return {
            "external_id": hostname, "revision": revision, "read_at": time.time(), "kind": "host",
            "device": {"vendor": "Microsoft", "model": "Windows Defender Firewall", "version": version,
                       "hostname": hostname, "management_address": (ssh or {}).get("server_ip") or "", "serial": ""},
            "interfaces": parsed["interfaces"], "zones": parsed["zones"], "aliases": [],
            "self_addresses": addresses, "rules": parsed["rules"], "default_policy": parsed["policy"],
            "nat_evaluated": False, "notes": [untrusted_text(note, 300) for note in notes],
        }

    def _zone_ids(self, record: dict[str, Any]) -> set[str]:
        return {z["id"] for z in record.get("zones") or []} | {i["id"] for i in record.get("interfaces") or []}

    def _problems(self, record: dict[str, Any], ops: list[dict[str, Any]]) -> list[str]:
        problems = list(management_guard(record, ops))
        zones = self._zone_ids(record)
        by_ref = {rule["vendor_ref"]: rule for rule in record.get("rules") or []}
        by_id = {rule["id"]: rule for rule in record.get("rules") or []}
        for op in ops:
            if op["op"] == "allow":
                for side in ("source", "destination"):
                    zone = op[side]["zone"]
                    if zones and zone not in zones:
                        problems.append(f"the device has no interface or profile '{zone}'")
                continue
            for ref in op["rules"]:
                for part in str(ref.get("vendor_ref") or ref["id"]).split(","):
                    if part == OPENSSH_RULE or part.startswith(OPENSSH_RULE):
                        problems.append(f"rule {OPENSSH_RULE} is the host's SSH allow; disabling it could cut the "
                                        "hub off from the device")
                    rule = by_ref.get(part) or by_id.get(ref.get("id"))
                    if rule is None:
                        problems.append(f"rule {part} is not on the device (re-read it first)")
                    elif not _NAME_RE.fullmatch(part):
                        problems.append(f"rule {untrusted_text(part, 40)} has a name this connector will not pass "
                                        "to a firewall cmdlet")
        return list(dict.fromkeys(problems))

    def _change_id(self, ops: list[dict[str, Any]]) -> str:
        for op in ops:
            if op["op"] == "allow":
                found = find_marker(op["marker"])
                if found:
                    return found
        return "dis-" + derived_revision(ops)[2:18]

    def _rules_for(self, ops: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rendered = []
        for index, op in enumerate(ops):
            if op["op"] == "allow":
                description = f"{op['marker']} op{index} {op.get('description') or ''}".strip()
                description = "".join(ch if ch.isalnum() or ch in " _.:/=+-" else " " for ch in description)
                for slice_index, service in enumerate(op["services"]):
                    proto = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMPv4"}[service["proto"]]
                    # UNVERIFIED: ICMPv4 as New-NetFirewallRule -Protocol (fw-hosts 4.3).
                    name = f"atrium-{find_marker(op['marker'])}-{index}-{slice_index}"
                    if not _NAME_RE.fullmatch(name):
                        raise ChangeError("the generated rule name is not a safe token", code="invalid",
                                          state="unchanged")
                    item: dict[str, Any] = {
                        "op": "add", "name": name, "display_name": f"Atrium {find_marker(op['marker'])}",
                        "protocol": proto, "remote": list(op["source"]["cidrs"]),
                        "local": list(op["destination"]["cidrs"]), "description": " ".join(description.split()),
                    }
                    if service["proto"] != "icmp":
                        item["ports"] = str(service["ports"]).split(",")
                    rendered.append(item)
            else:
                verb = "enable" if op["op"] == "enable_rules" else "disable"
                for ref in op["rules"]:
                    for part in str(ref.get("vendor_ref") or ref["id"]).split(","):
                        if not _NAME_RE.fullmatch(part):
                            raise ChangeError(f"rule {untrusted_text(part, 40)} has a name this connector will not "
                                              "pass to a firewall cmdlet", code="invalid", state="unchanged")
                        if part == OPENSSH_RULE:
                            raise ChangeError(f"rule {OPENSSH_RULE} is the host's SSH allow; disabling it could cut "
                                              "the hub off from the device", code="lockout", state="unchanged")
                        rendered.append({"op": verb, "name": part})
        return rendered

    def _spec(self, parsed: dict[str, Any] | None = None) -> dict[str, Any] | None:
        if self.config.get("read_only"):
            return None
        if parsed is not None and (not parsed.get("elevated") or not parsed.get("allow_local", True) or parsed.get("gpo")):
            return None
        return validate_write_spec({**self.network_write, "window_s": int(self.config.get("window_s") or _WINDOW)})

    async def test(self) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []
        try:
            target = self._target()
        except ConnectorError as exc:
            return {"ok": False, "detail": exc.message, "checks": [check("reachability", False, exc.message)],
                    "domains": {}, "network_write": None}
        try:
            async with self.ssh(target) as session:
                checks.append(check("reachability", True, f"{self.config['host']} answered SSH"))
                strict = bool(self.config.get("strict_host_keys", True))
                checks.append(check("tls", strict, "SSH host-key checking is on (SSH is the transport; there is no TLS)"
                                    if strict else "strict host-key checking is off"))
                checks.append(check("authentication", True,
                                    f"SSH key accepted for {self.config['username']}@{self.config['host']}"))
                _raw, parsed = await self._read(session)
        except SshError as exc:
            message = str(exc)
            if "authentication failed" in message:
                checks.extend((check("reachability", True, "the host answered SSH"),
                               check("authentication", False, message)))
            elif "host key" in message:
                checks.extend((check("reachability", True, "the host answered SSH"),
                               check("tls", False, message),
                               check("authentication", False, "the host key was not accepted")))
            else:
                checks.append(check("reachability", False, message))
            return {"ok": False, "detail": message, "checks": checks, "domains": {}, "network_write": None}
        except ConnectorError as exc:
            checks.append(check("privileges", False, exc.message))
            return {"ok": False, "detail": exc.message, "checks": checks, "domains": {}, "network_write": None}
        spec = self._spec(parsed)
        if parsed.get("elevated") and self.config.get("read_only"):
            detail = LEAST_PRIVILEGE_NOTE + "; this connection is marked read-only"
        elif parsed.get("elevated") and not parsed.get("allow_local", True):
            detail = "the token is elevated, but Group Policy disallows local firewall rules"
        elif parsed.get("elevated"):
            detail = LEAST_PRIVILEGE_NOTE
        else:
            detail = ("the SSH token is not elevated (High Mandatory Level S-1-16-12288 was absent); "
                      "device changes are unavailable")
        checks.append(check("privileges", True, detail))
        os_info = parsed.get("os") or {}
        version = " ".join(str(os_info.get(key) or "") for key in ("Caption", "Version")).strip() or "Windows"
        checks.append(check("version", True, f"Windows Defender Firewall on {version} (supported)"))
        feature = (f"deadman via Scheduled Task; window {spec['window_s']}s; confirm unregisters the task"
                   if spec else "reads the active store; writes off")
        checks.append(check("api_features", True, feature))
        ok = strict
        return {"ok": ok, "detail": f"Windows Defender Firewall on {parsed.get('hostname') or self.config['host']}",
                "checks": checks, "domains": self.domains() if ok else {}, "network_write": spec}

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        if domain != "network":
            raise ConnectorError(f"{self.title} cannot read {domain}")
        async with self.ssh(self._target()) as session:
            _raw, parsed = await self._read(session)
        return [normalize_record(self._record(parsed))]

    async def backup(self) -> dict[str, Any]:
        async with self.ssh(self._target()) as session:
            raw, parsed = await self._read(session)
            record = normalize_record(self._record(parsed))
            extra: dict[str, Any] = {}
            if parsed.get("elevated") and not self.config.get("read_only"):
                try:
                    snap = await self._powershell(session, self._script({"verb": "snapshot", "change_id": "backup",
                                                                          "window_s": int(self.config.get("window_s") or _WINDOW)}),
                                                  state=None)
                    extra = {key: snap.get(key) for key in ("path", "wfw_b64") if snap.get(key)}
                except ConnectorError:
                    extra = {}
        content = json.dumps({"manager": "windows_firewall", "read": raw, **extra}, sort_keys=True, default=str)
        return {"content": content, "format": "json", "device_backup_id": extra.get("path"), "revision": record["revision"]}

    async def preview_change(self, ops: list[dict[str, Any]], snapshot: dict[str, Any]) -> dict[str, Any]:
        try:
            parsed_ops = parse_ops(ops)
        except ValueError as exc:
            return {"steps": [], "notes": [], "problems": [str(exc)]}
        async with self.ssh(self._target()) as session:
            _raw, parsed = await self._read(session)
        record = normalize_record(self._record(parsed))
        problems = self._problems(record, parsed_ops)
        if snapshot and snapshot.get("revision") and snapshot.get("revision") != record["revision"]:
            problems.append("the device revision moved since this snapshot; re-read it and preview again")
        steps = []
        for index, op in enumerate(parsed_ops):
            if op["op"] == "allow":
                steps.append({"op": index, "kind": "add_rule",
                              "position": "Windows Firewall has no administrator order; a block would beat this allow",
                              "detail": "one inbound allow, marked " + op["marker"]})
            else:
                kind = "disable_rule" if op["op"] == "disable_rules" else "enable_rule"
                steps.extend({"op": index, "kind": kind, "position": "in place",
                              "detail": f"{op['op'].replace('_', ' ')} {ref['vendor_ref']}"} for ref in op["rules"])
        return {"steps": steps, "notes": ["dead-man timer is a Scheduled Task",
                                          "Windows persists the rule immediately; confirm only cancels the task"],
                "problems": problems}

    async def apply_change(self, ops: list[dict[str, Any]], base_revision: str, backup: Backup | None) -> dict[str, Any]:
        try:
            parsed_ops = parse_ops(ops)
        except ValueError as exc:
            raise ChangeError(str(exc), code="invalid", state="unchanged") from exc
        try:
            target = self._target()
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unsupported", state="unchanged") from exc
        try:
            async with self.ssh(target) as session:
                return await self._apply_in(session, parsed_ops, base_revision)
        except SshError as exc:
            raise ChangeError(str(exc), code="unreachable", state="unchanged") from exc

    async def _apply_in(self, session: Any, ops: list[dict[str, Any]], base_revision: str) -> dict[str, Any]:
        raw, parsed = await self._read(session)
        if not parsed.get("elevated") or self.config.get("read_only"):
            raise ChangeError("this credential cannot write the Windows firewall", code="unsupported", state="unchanged")
        if not parsed.get("allow_local", True) or parsed.get("gpo"):
            raise ChangeError("Group Policy disallows local firewall rules", code="unsupported", state="unchanged")
        record = normalize_record(self._record(parsed))
        if record["revision"] != base_revision:
            raise ChangeError(f"the device is at revision {record['revision']}, not {base_revision}: re-read it and "
                              "preview again", code="stale", state="unchanged")
        problems = self._problems(record, ops)
        if problems:
            code = "lockout" if any("could cut the hub" in item for item in problems) else "invalid"
            raise ChangeError("Refused: " + "; ".join(problems), code=code, state="unchanged")
        for op in ops:
            if op["op"] == "allow" and any(rule.get("marker") == find_marker(op["marker"]) and _op_index(rule) == ops.index(op)
                                           for rule in record.get("rules") or []):
                raise ChangeError(f"a rule marked {op['marker']} is already on the device", code="failed",
                                  state="unchanged")
        change_id = self._change_id(ops)
        if not _CHANGE_RE.fullmatch(change_id):
            raise ChangeError("the change id is not safe to put in a task name", code="invalid", state="unchanged")
        window = int(self.config.get("window_s") or _WINDOW)
        rules = self._rules_for(ops)
        await self._verb(session, "snapshot", change_id, window, state="unchanged")
        await self._verb(session, "arm-revert", change_id, window, state="unchanged")
        try:
            await self._verb(session, "apply", change_id, window, state="unknown", rules=rules)
            _raw2, parsed2 = await self._read(session)
            after = normalize_record(self._record(parsed2))
            self._assert_applied(after, ops)
        except (ChangeError, ConnectorError, SshError) as exc:
            reverted = await self._try_revert(session, change_id, window)
            message = exc.message if isinstance(exc, ConnectorError) else str(exc)
            raise ChangeError(message, code=getattr(exc, "code", "failed"),
                              state="rolled_back" if reverted else "unknown") from exc
        created, disabled = [], []
        for index, op in enumerate(ops):
            if op["op"] == "allow":
                mid = find_marker(op["marker"])
                rule = next(rule for rule in after.get("rules") or []
                            if rule.get("marker") == mid and _op_index(rule) == index)
                created.append({"op": index, "id": rule["id"], "vendor_ref": rule["vendor_ref"]})
            elif op["op"] == "disable_rules":
                disabled.extend(str(ref.get("vendor_ref") or ref["id"]) for ref in op["rules"])
        token = json.dumps({"v": 1, "host": self.config["host"], "port": int(self.config.get("port") or 22),
                            "manager": "windows_firewall", "change_id": change_id, "revision": after["revision"]},
                           separators=(",", ":"))
        return {"token": token, "rollback_until": time.time() + window, "revision": after["revision"],
                "created": created, "disabled": disabled,
                "notes": ["Scheduled Task armed before the rule was written",
                          "Windows persisted the rule immediately; confirm only cancels the task"]}

    async def _verb(self, session: Any, verb: str, change_id: str, window: int, *, state: str,
                    rules: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"verb": verb, "change_id": change_id, "window_s": window}
        if rules is not None:
            payload["rules"] = rules
        return await self._powershell(session, self._script(payload), state=state)

    def _assert_applied(self, record: dict[str, Any], ops: list[dict[str, Any]]) -> None:
        from .netmodel import rule_matches_allow

        for index, op in enumerate(ops):
            if op["op"] == "allow":
                mid = find_marker(op["marker"])
                found = [rule for rule in record.get("rules") or [] if rule.get("marker") == mid and _op_index(rule) == index]
                if not found:
                    found = [rule for rule in record.get("rules") or [] if rule.get("marker") == mid]
                if not any(rule_matches_allow(rule, op) for rule in found):
                    raise ChangeError(f"the rule marked {op['marker']} is not on the device as proposed",
                                      code="failed", state="unknown")
            else:
                want = op["op"] == "enable_rules"
                for ref in op["rules"]:
                    rule = _find(record, ref)
                    if rule is None or bool(rule.get("enabled", True)) != want:
                        raise ChangeError(f"rule {ref.get('id')} is not {'enabled' if want else 'disabled'}",
                                          code="failed", state="unknown")

    async def _try_revert(self, session: Any, change_id: str, window: int) -> bool:
        try:
            await self._verb(session, "revert-now", change_id, window, state="unknown")
        except (ChangeError, ConnectorError, SshError):
            return False
        return True

    def _token(self, token: str) -> dict[str, Any]:
        try:
            data = json.loads(token)
        except ValueError as exc:
            raise ChangeError("the change token is not valid", code="invalid", state="unknown") from exc
        if not isinstance(data, dict) or data.get("host") != self.config.get("host"):
            raise ChangeError("the change token is for a different host", code="invalid", state="unknown")
        if data.get("manager") != "windows_firewall" or not _CHANGE_RE.fullmatch(str(data.get("change_id") or "")):
            raise ChangeError("the change token is not valid", code="invalid", state="unknown")
        return data

    async def confirm_change(self, token: str) -> dict[str, Any]:
        data = self._token(token)
        window = int(self.config.get("window_s") or _WINDOW)
        try:
            async with self.ssh(self._target()) as session:
                await self._verb(session, "confirm", data["change_id"], window, state="unknown")
        except SshError as exc:
            raise ChangeError(str(exc), code="unreachable", state="unknown") from exc
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="failed", state="unknown") from exc
        return {"confirmed": True, "revision": data.get("revision"),
                "notes": ["Scheduled Task unregistered", "the rule was already persistent"]}

    async def rollback_change(self, token: str, backup: Backup | None) -> dict[str, Any]:
        data = self._token(token)
        window = int(self.config.get("window_s") or _WINDOW)
        try:
            async with self.ssh(self._target()) as session:
                await self._verb(session, "revert-now", data["change_id"], window, state="unknown")
        except SshError as exc:
            raise ChangeError(str(exc), code="unreachable", state="unknown") from exc
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="failed", state="unknown") from exc
        return {"rolled_back": True, "method": "deadman", "notes": ["netsh import restored the export"]}

    async def restore_backup(self, backup: Backup) -> dict[str, Any]:
        try:
            saved = json.loads(backup.text())
        except (ValueError, UnicodeError) as exc:
            raise ChangeError("the backup is not a Windows firewall export", code="invalid", state="unchanged") from exc
        if not isinstance(saved, dict) or saved.get("manager") != "windows_firewall":
            raise ChangeError("the backup is not a Windows firewall export", code="invalid", state="unchanged")
        if not saved.get("wfw_b64"):
            raise ChangeError("this backup has no netsh export to restore", code="invalid", state="unchanged")
        change_id = "restore-" + derived_revision(saved.get("wfw_b64"))[2:10]
        window = int(self.config.get("window_s") or _WINDOW)
        try:
            async with self.ssh(self._target()) as session:
                await self._verb(session, "arm-revert", change_id, window, state="unchanged")
                try:
                    await self._powershell(session, self._script({"verb": "import", "change_id": change_id,
                                                                  "window_s": window, "wfw_b64": saved["wfw_b64"]}),
                                           state="unknown")
                    await self._verb(session, "confirm", change_id, window, state="unknown")
                except (ChangeError, ConnectorError) as exc:
                    reverted = await self._try_revert(session, change_id, window)
                    raise ChangeError(exc.message, code="failed", state="rolled_back" if reverted else "unknown") from exc
                _raw, parsed = await self._read(session)
        except SshError as exc:
            raise ChangeError(str(exc), code="unreachable", state="unchanged") from exc
        return {"restored": True, "revision": normalize_record(self._record(parsed))["revision"],
                "notes": ["netsh import replaced the store from the backup"]}


def _op_index(rule: dict[str, Any]) -> int | None:
    found = re.search(r"\bop(\d+)\b", str(rule.get("description") or ""))
    return int(found.group(1)) if found else None


def _find(record: dict[str, Any], ref: dict[str, Any]) -> dict[str, Any] | None:
    wanted = set(str(ref.get("vendor_ref") or ref.get("id") or "").split(","))
    wanted.add(str(ref.get("id") or ""))
    for rule in record.get("rules") or []:
        names = set(str(rule.get("vendor_ref") or "").split(","))
        names.add(rule.get("id"))
        if wanted & names:
            return rule
    return None
