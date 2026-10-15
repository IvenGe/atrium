"""Windows Defender Firewall over OpenSSH and PowerShell (device kind ``host``).

Research: docs/research/fw-hosts-linux-windows.md sections 0 and 4-5. One SSH session per call
(``Connector.ssh``). The command line is always the same fixed text, ``powershell.exe -NoProfile -NonInteractive
-NoLogo -EncodedCommand <BOOT>`` (Base64 of UTF-16LE, about_PowerShell_exe), where BOOT reads the real script from
stdin and runs it - so nothing variable is ever on a command line, scripts of any size fit, and the default shell
(cmd.exe for OpenSSH on Windows, or PowerShell) does not matter. Values go into scripts only as Base64 JSON data.
Every script prints one ``ATRIUM-RESULT:<json>`` line; errors are caught and reported as codes.

Reading (verified on Microsoft Learn unless marked):
- ``Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore`` (without -PolicyStore only the PersistentStore
  is read; ActiveStore includes Group Policy). Conditions live in filter objects, read in bulk with
  ``Get-NetFirewallPortFilter -All``, ``Get-NetFirewallAddressFilter -All`` and ``Get-NetFirewallInterfaceFilter -All``
  and joined to rules by InstanceID; a rule whose filters do not join is read with the per-rule cmdlets.
- Enum values are cast to strings in PowerShell (Windows PowerShell 5.1's ConvertTo-Json has no -EnumsAsStrings).
- Windows has no rule order (explicit block wins over allow); the order shown is block rules first.
- Profiles (Domain, Private, Public) are the zones: ``Get-NetFirewallProfile`` (Enabled, DefaultInboundAction,
  AllowInboundRules, AllowLocalFirewallRules) and the profile of each interface from ``Get-NetConnectionProfile``.
- Interfaces: ``Get-NetIPAddress``, ``Get-NetAdapter`` (VlanID), default route ``Get-NetRoute``; listening ports
  ``Get-NetTCPConnection -State Listen``.

Changes (rollback ``deadman``; research 4.3-4.4 - Windows has no commit-confirm):
- Before writing, the arm script records the change as "armed" under HKLM:\\SOFTWARE\\Atrium\\FirewallChanges and
  registers a one-time Scheduled Task (``\\Atrium\\atrium-fw-revert-<id>``, SYSTEM, highest run level, trigger
  ``(Get-Date).AddSeconds(window)`` computed on the host) that runs the inverse of the change: remove the rules it
  created, set toggled rules back. The revert, the confirm and an explicit rollback take the same named mutex
  (``Global\\atrium-fw-<id>``) and only act on an "armed" change, so the timer and a confirm cannot both win. The
  revert script travels inside the task as -EncodedCommand: no file on disk can be swapped.
- allow: ``New-NetFirewallRule -Name atrium-<change>-<n>`` (Group "Atrium", Inbound, Allow, -Profile from the zone
  or -InterfaceAlias escaped with [WildcardPattern]::Escape, -Enabled "True" as a string). disable_rules /
  enable_rules: ``Disable-`` / ``Enable-NetFirewallRule`` on the rule object found by its exact name (-Name accepts
  wildcards), for local rules only (Group Policy rules are changed in the GPO). Windows has a real disabled state.
- The OpenSSH rule ``OpenSSH-Server-In-TCP`` is never disabled, and a block rule that could match the hub's SSH path
  is never enabled (block rules always win).
- Backups: ``netsh advfirewall export`` to a temporary file of the signed-in account; restore: ``netsh advfirewall
  import`` (replaces the whole store without asking - only for an approved restore change).

Least privilege: Windows has no read-only firewall role for these cmdlets that was verified, and SSH sessions of
administrators must be elevated to change anything (checked with WindowsPrincipal.IsInRole(Administrator)). Use a
dedicated local account with a key in %ProgramData%\\ssh\\administrators_authorized_keys (ACL: SYSTEM and
Administrators only), allowed by sshd's AllowUsers from the hub's address.

UNVERIFIED (no Windows host was used. The connector was tested against a fake host; every script was parsed, and the
read / arm / apply / rollback / confirm scripts were run, by PowerShell 7.4.6 on Linux over stub cmdlets - the
NetSecurity and ScheduledTasks cmdlets and Windows PowerShell 5.1 itself were not available): that BOOT's ``[Console]::In.ReadToEnd()`` reads the script OpenSSH passes
on stdin in Windows PowerShell 5.1; that a filter's InstanceID equals its rule's (fallback per rule); whether
Win32-OpenSSH sets SSH_CONNECTION (fallback: established connections to the SSH port); whether administrators'
SSH sessions get an elevated token; ``New-ScheduledTaskPrincipal -UserId 'SYSTEM'`` (Microsoft's example uses
LOCALSERVICE); whether standard users can run the read cmdlets; the address text the filters return for subnets
(mask or prefix form - both are read); that a .wfw export is a full backup of the local store.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import ipaddress
import json
import re
import secrets as secrets_module
import time
from typing import Any, AsyncIterator, Callable

from ..execution.runner import SshError, parse_ssh_connection
from .base import Connector, ConnectorError, ConnectorField, check
from .netmodel import (LEAST_PRIVILEGE_NOTE, Backup, ChangeError, derived_revision, display_id, management_guard,
                       normalise_cidr, normalize_record, parse_ops, port_ranges, ssh_fields, ssh_target, untrusted_text,
                       validate_ssh_config)

OPS = ["allow", "disable_rules", "enable_rules"]
WINDOW = 180
WINDOW_BOUNDS = (60, 600)
RESULT = "ATRIUM-RESULT:"
OPENSSH_RULE = "OpenSSH-Server-In-TCP"
PROFILES = ("domain", "private", "public")
SID_RE = re.compile(r"^[0-9a-f]{16}$")
CREATED_RE = re.compile(r"^atrium-[A-Za-z0-9_-]{1,64}-\d{1,2}$")
DESCRIPTION_DROP = re.compile(r"[^A-Za-z0-9 _.,:/()+=-]")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# address space that never faces the internet: RFC 1918, CGNAT, link-local, ULA
INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                   "169.254.0.0/16", "127.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128")]
PROTOCOLS = {"tcp": "tcp", "6": "tcp", "udp": "udp", "17": "udp", "icmpv4": "icmp", "1": "icmp", "icmpv6": "icmpv6",
             "58": "icmpv6", "any": "any", "": "any"}
CATEGORIES = {"domainauthenticated": "domain", "domain": "domain", "private": "private", "public": "public"}

# Reads the script from stdin and runs it (the command line never changes).
BOOT = "$s=[Console]::In.ReadToEnd(); & ([scriptblock]::Create($s))"
COMMAND = ("powershell.exe -NoProfile -NonInteractive -NoLogo -EncodedCommand "
           + base64.b64encode(BOOT.encode("utf-16-le")).decode("ascii"))

OUTPUT = r"""try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }
function Out-Atrium($o) { [Console]::Out.Write("`nATRIUM-RESULT:" + (ConvertTo-Json -InputObject $o -Depth 8 -Compress) + "`n") }
"""
PRELUDE = r"""# atrium:@@NAME@@
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
""" + OUTPUT + r"""$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('@@PAYLOAD@@')) | ConvertFrom-Json
$key = 'HKLM:\SOFTWARE\Atrium\FirewallChanges'
try {
@@BODY@@
} catch {
  Out-Atrium @{ ok = $false; error = 'exception'; fqid = [string]$_.FullyQualifiedErrorId; detail = [string]$_.Exception.Message }
}
"""

READ = r"""
$s = 'ActiveStore'
$rules = @(Get-NetFirewallRule -PolicyStore $s -TracePolicyStore)
$pf = @{}; foreach ($f in @(Get-NetFirewallPortFilter -All -PolicyStore $s)) { $pf[[string]$f.InstanceID] = $f }
$af = @{}; foreach ($f in @(Get-NetFirewallAddressFilter -All -PolicyStore $s)) { $af[[string]$f.InstanceID] = $f }
$xf = @{}; foreach ($f in @(Get-NetFirewallInterfaceFilter -All -PolicyStore $s)) { $xf[[string]$f.InstanceID] = $f }
$joined = 0; $piped = 0
$out = foreach ($r in $rules) {
  $id = [string]$r.InstanceID; $pr = $pf[$id]; $ad = $af[$id]; $ix = $xf[$id]
  if ($pr -and $ad -and $ix) { $joined++ } else {
    # UNVERIFIED that a filter's InstanceID is its rule's: read this rule's filters one by one
    $piped++; $pr = $r | Get-NetFirewallPortFilter; $ad = $r | Get-NetFirewallAddressFilter; $ix = $r | Get-NetFirewallInterfaceFilter
  }
  [pscustomobject]@{ name = [string]$r.Name; display = [string]$r.DisplayName; description = [string]$r.Description
    group = [string]$r.Group; enabled = [string]$r.Enabled; direction = [string]$r.Direction; action = [string]$r.Action
    profile = [string]$r.Profile; status = [string]$r.PrimaryStatus; store_type = [string]$r.PolicyStoreSourceType
    enforcement = @($r.EnforcementStatus | ForEach-Object { [string]$_ }); protocol = [string]$pr.Protocol
    local_port = @($pr.LocalPort | ForEach-Object { [string]$_ }); remote_port = @($pr.RemotePort | ForEach-Object { [string]$_ })
    local_address = @($ad.LocalAddress | ForEach-Object { [string]$_ }); remote_address = @($ad.RemoteAddress | ForEach-Object { [string]$_ })
    interface = @($ix.InterfaceAlias | ForEach-Object { [string]$_ }) }
}
$profiles = @(Get-NetFirewallProfile -PolicyStore $s | ForEach-Object { [pscustomobject]@{ name = [string]$_.Name
  enabled = [string]$_.Enabled; inbound = [string]$_.DefaultInboundAction; outbound = [string]$_.DefaultOutboundAction
  allow_inbound = [string]$_.AllowInboundRules; allow_local = [string]$_.AllowLocalFirewallRules
  log_allowed = [string]$_.LogAllowed; log_blocked = [string]$_.LogBlocked } })
$ips = @(Get-NetIPAddress -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ alias = [string]$_.InterfaceAlias
  address = [string]$_.IPAddress; prefix = [int]$_.PrefixLength } })
$adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ alias = [string]$_.Name
  status = [string]$_.Status; vlan = [string]$_.VlanID } })
$categories = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{
  alias = [string]$_.InterfaceAlias; category = [string]$_.NetworkCategory } })
$routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.InterfaceAlias })
$listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{
  address = [string]$_.LocalAddress; port = [int]$_.LocalPort } })
$peers = @()
if (-not $env:SSH_CONNECTION) { $peers = @(Get-NetTCPConnection -State Established -LocalPort ([int]$p.port) -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.RemoteAddress }) }
$os = Get-CimInstance Win32_OperatingSystem
$admin = $false
try { $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
Out-Atrium @{ ok = $true; rules = @($out); joined = $joined; piped = $piped; profiles = $profiles; ips = $ips
  adapters = $adapters; categories = $categories; routes = $routes; listen = $listen; peers = $peers
  ssh = [string]$env:SSH_CONNECTION; host = [string]$env:COMPUTERNAME; ps = [string]$PSVersionTable.PSVersion
  os = @{ caption = [string]$os.Caption; version = [string]$os.Version; build = [string]$os.BuildNumber }
  admin = [bool]$admin; tasks = [bool](Get-Command Register-ScheduledTask -ErrorAction SilentlyContinue) }
"""

ARM = r"""
if ($p.sid -notmatch '^[0-9a-f]{16}$') { throw 'bad session id' }
if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
foreach ($t in @(Get-ScheduledTask -TaskPath '\Atrium\' -ErrorAction SilentlyContinue)) {
  $old = $t.TaskName -replace '^atrium-fw-revert-', ''
  if ((Get-ItemProperty -Path $key -Name $old -ErrorAction SilentlyContinue).$old -ne 'armed') {
    Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath '\Atrium\' -Confirm:$false
  }
}
New-ItemProperty -Path $key -Name $p.sid -Value 'armed' -PropertyType String -Force | Out-Null
$act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -NoLogo -EncodedCommand ' + $p.revert)
$trg = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddSeconds([int]$p.window))
# UNVERIFIED: -UserId 'SYSTEM' (Microsoft's example uses LOCALSERVICE); registering fails loudly if it is wrong
$prn = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
Register-ScheduledTask -TaskName ('atrium-fw-revert-' + $p.sid) -TaskPath '\Atrium\' -Action $act -Trigger $trg -Principal $prn -Settings $set -Force | Out-Null
$t = Get-ScheduledTask -TaskName ('atrium-fw-revert-' + $p.sid) -TaskPath '\Atrium\'
Out-Atrium @{ ok = ([string]$t.State -eq 'Ready'); state = [string]$t.State }
"""

APPLY = r"""
if ((Get-ItemProperty -Path $key -Name $p.sid -ErrorAction SilentlyContinue).($p.sid) -ne 'armed') {
  Out-Atrium @{ ok = $false; error = 'not_armed' }; return
}
$all = @{}; foreach ($r in @(Get-NetFirewallRule -PolicyStore PersistentStore)) { $all[[string]$r.Name] = $r }
$done = @()
foreach ($o in @($p.ops)) {
  if ($o.kind -eq 'add') {
    if ($all.ContainsKey([string]$o.name)) { Out-Atrium @{ ok = $false; error = 'exists'; done = $done }; return }
    $a = @{ Name = [string]$o.name; DisplayName = [string]$o.display; Description = [string]$o.description; Group = 'Atrium'
      Direction = 'Inbound'; Action = 'Allow'; Protocol = [string]$o.protocol; RemoteAddress = @($o.remote_address)
      LocalAddress = @($o.local_address); Enabled = 'True'; PolicyStore = 'PersistentStore'; Profile = 'Any' }
    if ($o.local_port) { $a.LocalPort = @($o.local_port) }
    if ($o.profile) { $a.Profile = [string]$o.profile }
    if ($o.interface) { $a.InterfaceAlias = [WildcardPattern]::Escape([string]$o.interface) }
    New-NetFirewallRule @a | Out-Null
  } else {
    $r = $all[[string]$o.name]
    if (-not $r) { Out-Atrium @{ ok = $false; error = 'missing'; done = $done }; return }
    if ($o.enabled) { $r | Enable-NetFirewallRule } else { $r | Disable-NetFirewallRule }
  }
  $done += [string]$o.name
}
Out-Atrium @{ ok = $true; done = $done }
"""

# The inverse of a change, run by the Scheduled Task (mode "fired") or by a rollback (mode "rolled").
REVERT = r"""# atrium:revert
$ErrorActionPreference = 'Continue'
$d = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('@@DATA@@')) | ConvertFrom-Json
$k = 'HKLM:\SOFTWARE\Atrium\FirewallChanges'
$m = New-Object System.Threading.Mutex($false, ('Global\atrium-fw-' + $d.sid))
[void]$m.WaitOne(60000)
try {
  $state = (Get-ItemProperty -Path $k -Name $d.sid -ErrorAction SilentlyContinue).($d.sid)
  if ($state -eq 'armed') {
    Set-ItemProperty -Path $k -Name $d.sid -Value $d.mode
    $all = @{}; foreach ($r in @(Get-NetFirewallRule -PolicyStore PersistentStore)) { $all[[string]$r.Name] = $r }
    foreach ($n in @($d.created)) { if ($all.ContainsKey([string]$n)) { $all[[string]$n] | Remove-NetFirewallRule } }
    foreach ($e in @($d.toggled)) {
      $r = $all[[string]$e.name]
      if ($r) { if ($e.enabled) { $r | Enable-NetFirewallRule } else { $r | Disable-NetFirewallRule } }
    }
    $state = 'reverted'
  }
} finally { $m.ReleaseMutex() }
"""

ROLLBACK = REVERT.replace("# atrium:revert\n", "# atrium:rollback\n" + OUTPUT) + r"""Unregister-ScheduledTask -TaskName ('atrium-fw-revert-' + $d.sid) -TaskPath '\Atrium\' -Confirm:$false -ErrorAction SilentlyContinue
Out-Atrium @{ ok = $true; state = [string]$state }
"""

CONFIRM = r"""
if ($p.sid -notmatch '^[0-9a-f]{16}$') { throw 'bad session id' }
$m = New-Object System.Threading.Mutex($false, ('Global\atrium-fw-' + $p.sid))
[void]$m.WaitOne(60000)
try {
  $state = [string](Get-ItemProperty -Path $key -Name $p.sid -ErrorAction SilentlyContinue).($p.sid)
  if ($state -eq 'armed') { Set-ItemProperty -Path $key -Name $p.sid -Value 'confirmed'; $state = 'confirmed' }
  elseif (-not $state) { $state = 'missing' }
} finally { $m.ReleaseMutex() }
if ($state -eq 'confirmed') {
  Unregister-ScheduledTask -TaskName ('atrium-fw-revert-' + $p.sid) -TaskPath '\Atrium\' -Confirm:$false -ErrorAction SilentlyContinue
}
Out-Atrium @{ ok = $true; state = $state }
"""

BACKUP = r"""
$f = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'atrium-' + [Guid]::NewGuid().ToString('N') + '.wfw')
$o = & netsh.exe advfirewall export $f 2>&1
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $f)) { Out-Atrium @{ ok = $false; error = 'export' }; return }
try { $b = [IO.File]::ReadAllBytes($f) } finally { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
Out-Atrium @{ ok = $true; content = [Convert]::ToBase64String($b) }
"""

RESTORE = r"""
$b = [Convert]::FromBase64String([string]$p.content)
$h = -join ([Security.Cryptography.SHA256]::Create().ComputeHash($b) | ForEach-Object { $_.ToString('x2') })
if ($h -ne [string]$p.sha256) { Out-Atrium @{ ok = $false; error = 'content' }; return }
$f = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'atrium-' + [Guid]::NewGuid().ToString('N') + '.wfw')
[IO.File]::WriteAllBytes($f, $b)
try { $o = & netsh.exe advfirewall import $f 2>&1; $rc = $LASTEXITCODE } finally { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
Out-Atrium @{ ok = ($rc -eq 0); error = $(if ($rc -eq 0) { $null } else { 'import' }) }
"""


def script(name: str, body: str, payload: dict[str, Any]) -> str:
    """One script: the prelude with `payload` as Base64 JSON data and `body`."""
    data = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    return PRELUDE.replace("@@NAME@@", name).replace("@@PAYLOAD@@", data).replace("@@BODY@@", body.strip("\n"))


def revert_script(sid: str, created: list[str], toggled: list[dict[str, Any]], mode: str) -> str:
    data = base64.b64encode(json.dumps({"sid": sid, "created": created, "toggled": toggled, "mode": mode})
                            .encode("utf-8")).decode("ascii")
    return (ROLLBACK if mode == "rolled" else REVERT).replace("@@DATA@@", data)


def encoded(text: str) -> str:
    """-EncodedCommand form of a script: Base64 of its UTF-16LE text."""
    return base64.b64encode(text.encode("utf-16-le")).decode("ascii")


class SshUnavailable(ConnectorError):
    """The SSH connection could not be opened or broke off."""


# --------------------------------------------------------------------------------------
# reading
# --------------------------------------------------------------------------------------


def _strings(value: Any) -> list[str]:
    items = value if isinstance(value, list) else [value] if value not in (None, "") else []
    return [str(v) for v in items if v not in (None, "")]


def addresses(values: list[str], local_subnets: list[str]) -> tuple[dict[str, Any] | None, list[str]]:
    """(endpoint or None for "any", keyword aliases used) of a filter's LocalAddress / RemoteAddress list."""
    cidrs, aliases = [], []
    for value in values:
        text = value.strip()
        if text.lower() in ("any", "*", ""):
            return None, []
        if re.fullmatch(r"(LocalSubnet|DNS|DHCP|WINS|DefaultGateway|Internet|Intranet|IntranetRemoteAccess|PlayToDevice|"
                        r"CaptivePortal|Ply2Renderers)[46]?", text, re.IGNORECASE):
            name = text.lower()
            if name.startswith("localsubnet"):
                cidrs += [c for c in local_subnets if c not in cidrs]
            else:
                aliases.append(f"keyword:{name}")
            continue
        if "-" in text:  # a range a-b
            low, _, high = text.partition("-")
            try:
                cidrs += [str(n) for n in ipaddress.summarize_address_range(ipaddress.ip_address(low.strip()),
                                                                           ipaddress.ip_address(high.strip()))]
            except (ValueError, TypeError):
                aliases.append(f"unreadable:{display_id(text, 40)}")
            continue
        cidr = normalise_cidr(text)  # 1.2.3.4, 1.2.3.0/24 and 1.2.3.0/255.255.255.0
        if cidr is None:
            aliases.append(f"unreadable:{display_id(text, 40)}")
        elif cidr not in cidrs:
            cidrs.append(cidr)
    return {"cidrs": cidrs, "aliases": aliases}, aliases


def ports_text(values: list[str]) -> tuple[str | None, str | None]:
    """(ports, unresolved keyword) of a LocalPort / RemotePort list; (None, None) for any."""
    ranges, keyword = [], None
    for value in values:
        text = value.strip()
        if text.lower() in ("any", ""):
            return None, None
        match = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", text)
        if match:
            low, high = int(match.group(1)), int(match.group(2) or match.group(1))
            if 0 < low <= high <= 65535:
                ranges.append((low, high))
                continue
        keyword = display_id(text, 40)
    if not ranges:
        return None, keyword
    parts = sorted(set(ranges))
    return ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in parts), keyword


def win_rule(raw: dict[str, Any], local_subnets: list[str]) -> dict[str, Any] | None:
    """A rule from the read script in the normalised shape."""
    name = str(raw.get("name") or "")
    if not name or CONTROL.search(name):
        return None
    action = {"allow": "pass", "allowbypass": "pass", "block": "block"}.get(str(raw.get("action") or "").lower())
    direction = {"inbound": "in", "outbound": "out"}.get(str(raw.get("direction") or "").lower())
    if action is None or direction is None:
        return None
    local, _ = addresses(_strings(raw.get("local_address")), local_subnets)
    remote, _ = addresses(_strings(raw.get("remote_address")), local_subnets)
    protocol = PROTOCOLS.get(str(raw.get("protocol") or "").lower(), str(raw.get("protocol") or "any").lower())
    ports, keyword = ports_text(_strings(raw.get("local_port" if direction == "in" else "remote_port")))
    if protocol == "any":
        services = None
    elif protocol in ("tcp", "udp") and keyword and not ports:
        services = [{"proto": protocol, "alias": f"port:{keyword}"}]
    else:
        services = [{"proto": protocol, "ports": ports if protocol in ("tcp", "udp") else None}]
    profile = [p.strip().lower() for p in str(raw.get("profile") or "Any").split(",")]
    zones = [] if "any" in profile or not profile else [p for p in profile if p in PROFILES]
    interfaces = [i for i in _strings(raw.get("interface")) if i.lower() != "any"]
    host_side = local or {"self": True}
    other_side = remote or {"any": True}
    description = str(raw.get("description") or "")
    if not description.startswith("atrium:"):
        description = str(raw.get("display") or name) + (f" - {description}" if description else "")
    store = str(raw.get("store_type") or "")
    if store and store.lower() != "local":
        description += f" [{store}]"
    return {"id": name, "vendor_ref": name, "order": 0, "enabled": str(raw.get("enabled")).lower() == "true",
            "action": action, "direction": direction, "interfaces": interfaces if direction == "in" else [],
            "out_interfaces": interfaces if direction == "out" else [],
            "source_zones": zones if direction == "in" else [], "destination_zones": zones if direction == "out" else [],
            "source": other_side if direction == "in" else host_side,
            "destination": host_side if direction == "in" else other_side,
            "services": services, "log": False, "description": description, "hits": None}


def read_model(data: dict[str, Any], host: str) -> dict[str, Any]:
    """The read script's answer as {"record": network record, "facts": ...}."""
    ips = [i for i in data.get("ips") or [] if isinstance(i, dict)]
    adapters = {str(a.get("alias")): a for a in data.get("adapters") or [] if isinstance(a, dict)}
    categories = {str(c.get("alias")): CATEGORIES.get(str(c.get("category") or "").lower(), "public")
                  for c in data.get("categories") or [] if isinstance(c, dict)}
    default = {str(r) for r in data.get("routes") or []}
    interfaces: dict[str, dict[str, Any]] = {}
    for item in ips:
        alias = str(item.get("alias") or "")
        try:
            iface = ipaddress.ip_interface(f"{item.get('address')}/{int(item.get('prefix'))}")
        except (ValueError, TypeError):
            continue
        if not alias or CONTROL.search(alias) or iface.ip.is_loopback or iface.ip.is_link_local:
            continue
        entry = interfaces.setdefault(alias, {"id": alias, "name": alias, "subnets": [], "addresses": [], "vlan": None,
                                              "enabled": True, "role": "lan", "description": ""})
        entry["addresses"].append(str(iface.ip))
        if str(iface.network) not in entry["subnets"]:
            entry["subnets"].append(str(iface.network))
    for alias, entry in interfaces.items():
        adapter = adapters.get(alias) or {}
        vlan = str(adapter.get("vlan") or "")
        entry["vlan"] = int(vlan) if vlan.isdigit() and 1 <= int(vlan) <= 4094 else None
        entry["enabled"] = str(adapter.get("status") or "Up").lower() == "up"
        public = any(not any(ipaddress.ip_address(a) in n for n in INTERNAL_NETS
                             if n.version == ipaddress.ip_address(a).version) for a in entry["addresses"])
        entry["role"] = "wan" if alias in default and public else "lan"
        if alias in categories:
            entry["description"] = f"{categories[alias]} network"
    local_subnets = [s for i in interfaces.values() for s in i["subnets"]]
    rules = [r for r in (win_rule(raw, local_subnets) for raw in data.get("rules") or [] if isinstance(raw, dict)) if r]
    rules.sort(key=lambda r: (r["action"] == "pass", r["direction"], r["id"].lower()))  # block wins: shown first
    for index, rule in enumerate(rules, 1):
        rule["order"] = index
    keyword_aliases = sorted({a for r in rules for side in ("source", "destination") for a in r[side].get("aliases") or []})
    aliases = [{"name": a, "kind": "other", "resolved": False} for a in keyword_aliases]
    aliases += [{"name": f"port:{k}", "kind": "port", "resolved": False} for k in
                sorted({s["alias"][5:] for r in rules for s in r["services"] or [] if s.get("alias")})]
    profiles = {str(p.get("name") or "").lower(): p for p in data.get("profiles") or [] if isinstance(p, dict)}
    zones = [{"id": z, "name": z.capitalize(), "interfaces": sorted(a for a, c in categories.items() if c == z),
              "description": "firewall " + ("on" if str((profiles.get(z) or {}).get("enabled")).lower() != "false"
                                            else "OFF")} for z in PROFILES]
    active = {categories[a] for a in interfaces if a in categories} or set(PROFILES)
    off = sorted(z for z in PROFILES if str((profiles.get(z) or {}).get("enabled")).lower() == "false")
    open_in = sorted(z for z in PROFILES if str((profiles.get(z) or {}).get("inbound")).lower() == "allow")
    inbound = "pass" if (set(off) | set(open_in)) & active else "block"
    outbound = "block" if all(str((profiles.get(z) or {}).get("outbound")).lower() == "block" for z in active) else "pass"
    notes = ["Windows Firewall has no rule order: block rules win over allow rules (shown first)"]
    if off:
        notes.append("the firewall is OFF for the " + ", ".join(off) + " profile")
    shields = sorted(z for z in PROFILES if str((profiles.get(z) or {}).get("allow_inbound")).lower() == "false")
    if shields:
        notes.append("inbound allow rules are ignored (Shields Up) on the " + ", ".join(shields) + " profile")
    no_local = sorted(z for z in PROFILES if str((profiles.get(z) or {}).get("allow_local")).lower() == "false")
    if no_local:
        notes.append("Group Policy ignores local rules on the " + ", ".join(no_local) + " profile")
    gpo = sum(1 for r in data.get("rules") or [] if isinstance(r, dict)
              and str(r.get("store_type") or "local").lower() not in ("local", ""))
    if gpo:
        notes.append(f"{gpo} rules come from Group Policy or other stores and cannot be changed here")
    logged = sorted(z for z in PROFILES if str((profiles.get(z) or {}).get("log_allowed")).lower() == "true")
    notes.append("logging is per profile, not per rule" + (": allowed connections are logged on the "
                                                           + ", ".join(logged) + " profile" if logged else ""))
    if data.get("piped"):
        notes.append(f"{data['piped']} rules were read filter by filter (the bulk join did not match them)")
    listening = sorted({f"tcp/{int(item.get('port'))}" for item in data.get("listen") or [] if isinstance(item, dict)
                        and str(item.get("address")) in ("0.0.0.0", "::") and str(item.get("port") or "").isdigit()},
                       key=lambda s: int(s[4:]))
    if listening:
        notes.append("listening on every address: " + ", ".join(listening[:40]))
    os_info = data.get("os") if isinstance(data.get("os"), dict) else {}
    revision = derived_revision("windows", sorted(
        ([r.get(k) for k in ("name", "enabled", "direction", "action", "profile", "protocol", "local_port", "remote_port",
                             "local_address", "remote_address", "interface", "store_type")]
         for r in data.get("rules") or [] if isinstance(r, dict)), key=lambda x: str(x[0])),
        [[p.get(k) for k in ("name", "enabled", "inbound", "outbound", "allow_inbound", "allow_local")]
         for p in profiles.values()])
    connection = parse_ssh_connection(str(data.get("ssh") or ""))
    record = {"external_id": str(data.get("host") or host), "revision": revision, "read_at": None, "kind": "host",
              "device": {"vendor": "Microsoft", "model": str(os_info.get("caption") or "Windows"),
                         "version": f"{os_info.get('version') or ''} (build {os_info.get('build') or '?'}), "
                                    f"PowerShell {data.get('ps') or '?'}",
                         "hostname": str(data.get("host") or host),
                         "management_address": (connection or {}).get("server_ip") or host, "serial": ""},
              "interfaces": list(interfaces.values()), "zones": zones, "aliases": aliases,
              "self_addresses": [a for i in interfaces.values() for a in i["addresses"]], "rules": rules,
              "default_policy": {"inbound": inbound, "outbound": outbound}, "nat_evaluated": False, "notes": notes}
    peers = [p for p in (str(x) for x in data.get("peers") or []) if normalise_cidr(p)]
    facts = {"admin": bool(data.get("admin")), "tasks": bool(data.get("tasks")), "ps": str(data.get("ps") or ""),
             "connection": connection, "peers": peers, "profiles": profiles, "off": off, "no_local": no_local,
             "shields": shields, "rules": {str(r.get("name")): r for r in data.get("rules") or [] if isinstance(r, dict)}}
    return {"record": record, "facts": facts}


# --------------------------------------------------------------------------------------
# the connector
# --------------------------------------------------------------------------------------


class WindowsFirewallConnector(Connector):
    kind = "windows_firewall"
    title = "Windows Defender Firewall"
    description = ("Reads a Windows host's firewall rules, profiles, interfaces and listening ports over OpenSSH and "
                   "PowerShell into the Network app. With device changes enabled and an elevated account, adds one "
                   "allow rule or disables / enables local rules under a dead-man Scheduled Task on the host.")
    fields = [
        *ssh_fields(default_user="atrium"),
        ConnectorField(name="rollback_window_s", label="Automatic revert after (seconds)", kind="number",
                       default=WINDOW, help="A change reverts by itself unless Atrium confirms it in time (60-600)."),
        ConnectorField(name="read_only", label="Read only", kind="bool", default=False,
                       help="Never change this host through this connection, even with device changes on."),
    ]
    capabilities = {"network": {"read"}}
    network_write = {"ops": OPS, "rollback": "deadman", "window_s": WINDOW}
    clock: Callable[[], float] = staticmethod(time.time)

    @classmethod
    def detect(cls, tool) -> int:
        return cls.name_score(tool, ("windows firewall", "windows defender firewall", "defender firewall", "wfas",
                                     "windows-firewall"))

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        try:
            config = validate_ssh_config(config)
        except ValueError as exc:
            raise ConnectorError(str(exc)) from exc
        window = int(config.get("rollback_window_s") or WINDOW)
        if not WINDOW_BOUNDS[0] <= window <= WINDOW_BOUNDS[1]:
            raise ConnectorError(f"The automatic revert window is {WINDOW_BOUNDS[0]}-{WINDOW_BOUNDS[1]} seconds")
        return {**config, "rollback_window_s": window}

    @property
    def window(self) -> int:
        return int(self.config.get("rollback_window_s") or WINDOW)

    def write_capability(self) -> dict[str, Any] | None:
        if self.config.get("read_only"):
            return None
        spec = super().write_capability()
        return {**spec, "window_s": self.window} if spec else None

    # -- SSH and PowerShell --------------------------------------------------------------------

    @contextlib.asynccontextmanager
    async def session(self) -> AsyncIterator[Any]:
        try:
            target = ssh_target(self.config, self.secrets)
        except ConnectorError as exc:
            raise self.error(exc.message) from exc
        try:
            async with self.ssh(target) as session:
                yield session
        except SshError as exc:
            raise SshUnavailable(self.redact(f"Windows over SSH: {exc}")) from exc

    async def ps(self, session: Any, name: str, body: str, payload: dict[str, Any] | None = None, *,
                 what: str, text: str | None = None) -> dict[str, Any]:
        """Run one script (``text`` as is, or the prelude + `body`); its ATRIUM-RESULT object."""
        source = text if text is not None else script(name, body, payload or {})
        try:
            result = await session.run(COMMAND, input=source)
        except SshError as exc:
            raise SshUnavailable(self.redact(f"Windows over SSH ({what}): {exc}")) from exc
        if result.truncated:
            raise self.error(f"Windows' answer was larger than the read limit ({what}) - refusing a partial read")
        line = next((l for l in reversed(result.stdout.splitlines()) if l.startswith(RESULT)), None)
        try:
            answer = json.loads(line[len(RESULT):]) if line else None
        except ValueError:
            answer = None
        if not isinstance(answer, dict):
            hint = "is powershell.exe the shell's PowerShell?" if result.exit_status in (1, 9009, 127) else \
                "the script did not finish"
            raise self.error(f"Windows did not answer the {what} script (exit status {result.exit_status}; {hint})"
                             + (f": {untrusted_text(result.stderr, 160)}" if result.stderr.strip() else ""))
        return answer

    def _failed(self, answer: dict[str, Any], what: str) -> ConnectorError:
        fqid = display_id(answer.get("fqid") or answer.get("error"), 80)
        if "UnauthorizedAccess" in fqid or "access is denied" in str(answer.get("detail") or "").lower():
            return self.error(f"Windows refused to {what}: access denied - the account must be an elevated "
                              "administrator")
        return self.error(f"Windows could not {what} ({fqid})"
                          + (f": {untrusted_text(answer.get('detail'), 160)}" if answer.get("detail") else ""))

    async def read(self, session: Any) -> dict[str, Any]:
        answer = await self.ps(session, "read", READ, {"port": int(self.config.get("port") or 22)},
                               what="read the firewall")
        if not answer.get("ok"):
            raise self._failed(answer, "read the firewall")
        model = read_model(answer, str(self.config.get("host") or ""))
        model["record"]["read_at"] = self.clock()
        return model

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        if domain != "network":
            raise self.error(f"Windows Firewall cannot read {domain}")
        async with self.session() as session:
            model = await self.read(session)
        return [model["record"]]

    # -- test --------------------------------------------------------------------------------------

    def _result(self, checks: list[dict[str, Any]], ok: bool, detail: str,
                write: dict[str, Any] | None = None) -> dict[str, Any]:
        return {"ok": ok, "detail": detail, "checks": checks, "domains": self.domains() if ok else {},
                "network_write": write if ok else None}

    def writes(self, model: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
        facts, reasons = model["facts"], []
        if self.config.get("read_only"):
            reasons.append("this connection is set to read only")
        if not facts["admin"]:
            reasons.append("the SSH session is not an elevated administrator")
        if not facts["tasks"]:
            reasons.append("the ScheduledTasks cmdlets are missing: there is no dead-man timer")
        if facts["no_local"]:
            reasons.append("Group Policy ignores local rules on the " + ", ".join(facts["no_local"]) + " profile")
        write = None if reasons or self.write_capability() is None else \
            {"ops": OPS, "rollback": "deadman", "window_s": self.window}
        return write, reasons

    def hub_path(self, model: dict[str, Any]) -> tuple[list[str] | None, int]:
        """(the hub's addresses as the host sees them, the SSH port) for the management-path guard."""
        connection = model["facts"]["connection"]
        if connection:
            return [connection["client_ip"]], connection["server_port"]
        peers = model["facts"]["peers"]
        return (peers if len(peers) == 1 else None), int(self.config.get("port") or 22)

    async def test(self) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []
        where = f"{self.config.get('host')}:{self.config.get('port') or 22}"
        pinned = "pinned host key" if self.config.get("host_key") else \
            f"host key in {self.config.get('known_hosts') or '~/.ssh/known_hosts'}"
        try:
            async with self.session() as session:
                checks += [check("reachability", True, f"SSH answers on {where}"),
                           check("tls", True, f"SSH {pinned} verified"),
                           check("authentication", True, f"signed in as {self.config.get('username')}")]
                model = await self.read(session)
        except ConnectorError as exc:
            if checks:
                checks.append(check("privileges" if "denied" in exc.message else "ruleset", False, exc.message))
                return self._result(checks, False, exc.message)
            text = exc.message.lower()
            if "host key" in text or "known_hosts" in text:
                checks += [check("reachability", True, f"SSH answers on {where}"), check("tls", False, exc.message)]
            elif "authentication" in text or "private key" in text or "password" in text:
                checks += [check("reachability", True, f"SSH answers on {where}"), check("tls", True, pinned),
                           check("authentication", False, exc.message)]
            else:
                checks.append(check("reachability", False, exc.message))
            return self._result(checks, False, exc.message)
        record, facts = normalize_record(model["record"]), model["facts"]
        write, reasons = self.writes(model)
        checks.append(check("privileges", True, f"elevated administrator - {LEAST_PRIVILEGE_NOTE}" if facts["admin"]
                            else "not elevated: the firewall is read, changes are unavailable (an administrator's "
                                 "session must be elevated to change it)"))
        checks.append(check("version", True, f"{record['device']['model']} {record['device']['version']} - supported"))
        checks.append(check("api_features", True, f"NetSecurity cmdlets ({len(record['rules'])} rules); changes: "
                            + (f"dead-man revert by a Scheduled Task (SYSTEM) after {self.window} s; backups with "
                               "netsh advfirewall export" if write else "unavailable - " + "; ".join(reasons))))
        profiles = facts["profiles"]
        state = ", ".join(f"{z.capitalize()} " + ("OFF" if z in facts["off"] else
                                                  f"on (inbound {str((profiles.get(z) or {}).get('inbound') or '?').lower()})")
                          for z in PROFILES)
        checks.append(check("profiles", not facts["off"], state))
        ssh_rule = facts["rules"].get(OPENSSH_RULE)
        checks.append(check("openssh_rule", bool(ssh_rule and str(ssh_rule.get("enabled")).lower() == "true"),
                            f"{OPENSSH_RULE} is enabled - Atrium never disables it" if ssh_rule and
                            str(ssh_rule.get("enabled")).lower() == "true" else
                            f"{OPENSSH_RULE} is missing or disabled - another rule must let the hub reach sshd"))
        addresses_, port = self.hub_path(model)
        checks.append(check("management_guard", True,
                            f"the hub reaches sshd from {', '.join(addresses_)} to port {port}: rules carrying that "
                            "path are never disabled" if addresses_ else
                            "the hub's address is unknown (SSH_CONNECTION not set): every rule that can reach the "
                            "host is protected"))
        if record["errors"]:
            checks.append(check("ruleset", True, f"{len(record['errors'])} entries could not be read and were skipped"))
        detail = (f"Connected to {record['device']['hostname']} ({record['device']['model']}): "
                  f"{len(record['rules'])} rules" + ("" if write else " (read only)"))
        return self._result(checks, True, detail, write)

    # -- backups --------------------------------------------------------------------------------

    async def backup(self) -> dict[str, Any]:
        async with self.session() as session:
            model = await self.read(session)
            answer = await self.ps(session, "backup", BACKUP, {}, what="export the firewall")
        if not answer.get("ok"):
            raise ChangeError("netsh advfirewall export failed (an elevated administrator is needed)", code="failed",
                              state="unchanged")
        try:
            content = base64.b64decode(str(answer.get("content") or ""), validate=True)
        except ValueError as exc:
            raise ChangeError("The firewall export could not be read", code="failed", state="unchanged") from exc
        if not content:
            raise ChangeError("The firewall export was empty", code="failed", state="unchanged")
        return {"content": content, "format": "wfw", "device_backup_id": None,
                "revision": model["record"]["revision"], "sha256": hashlib.sha256(content).hexdigest()}

    # -- changes ----------------------------------------------------------------------------------

    def _plan(self, model: dict[str, Any], ops: list[dict[str, Any]]) -> dict[str, Any]:
        record, facts = normalize_record(model["record"]), model["facts"]
        rules = {r["id"]: r for r in record["rules"]}
        zones = {z["id"] for z in record["zones"]}
        interfaces = {i["id"] for i in record["interfaces"]}
        hub, port = self.hub_path(model)
        problems, steps, notes, payload, created, toggled, disabled, enabled = [], [], [], [], [], [], [], []
        for index, op in enumerate(ops):
            if op["op"] == "allow":
                name = f"atrium-{op['marker'].split(':', 1)[1]}-{index}"
                zone = op["source"]["zone"]
                if zone not in zones | interfaces:
                    problems.append(f"operation {index + 1}: Windows has no profile or interface '{display_id(zone)}'")
                if op["destination"]["zone"] not in zones | interfaces:
                    problems.append(f"operation {index + 1}: Windows has no profile or interface "
                                    f"'{display_id(op['destination']['zone'])}'")
                if len(op["services"]) != 1:
                    problems.append(f"operation {index + 1}: one service per Windows rule - combine the ports into "
                                    "one entry or split the change")
                service = op["services"][0]
                ports = service.get("ports")
                if ports and ports != ",".join(str(lo) if lo == hi else f"{lo}-{hi}"
                                               for lo, hi in sorted(set(port_ranges(ports)))):
                    problems.append(f"operation {index + 1}: list the ports in ascending order")
                families = {ipaddress.ip_network(c).version for side in ("source", "destination")
                            for c in op[side]["cidrs"]}
                if service["proto"] == "icmp" and 6 in families:
                    problems.append(f"operation {index + 1}: ICMP rules are IPv4 only (ICMPv6 is not an Atrium service)")
                own = [a for a in record["self_addresses"]
                       if any(ipaddress.ip_address(a) in ipaddress.ip_network(c) for c in op["destination"]["cidrs"]
                              if ipaddress.ip_network(c).version == ipaddress.ip_address(a).version)]
                if not own:
                    problems.append(f"operation {index + 1}: the destination networks hold none of this host's "
                                    "addresses - a host firewall only filters traffic to the host itself")
                if name in rules:
                    problems.append(f"operation {index + 1}: a rule named {name} is already on the host")
                if facts["shields"]:
                    problems.append("inbound allow rules are ignored (Shields Up) on the " + ", ".join(facts["shields"])
                                    + " profile")
                description = " ".join(DESCRIPTION_DROP.sub(" ", op.get("description") or "").split())
                payload.append({"kind": "add", "name": name, "display": f"Atrium {name[7:]}"[:120],
                                "description": f"{op['marker']}.{index} {description}".strip()[:200],
                                "protocol": {"tcp": "TCP", "udp": "UDP", "icmp": "ICMPv4"}[service["proto"]],
                                "local_port": ports.split(",") if ports else None,
                                "remote_address": op["source"]["cidrs"], "local_address": op["destination"]["cidrs"],
                                "profile": zone.capitalize() if zone in PROFILES else None,
                                "interface": None if zone in PROFILES else zone})
                created.append({"op": index, "id": name, "vendor_ref": name})
                steps.append({"op": index, "kind": "add_rule", "position": "Windows has no rule order (allow rule)",
                              "detail": f"allow {service['proto']}{'/' + ports if ports else ''} on {display_id(zone)}, "
                                        f"named {name}"})
                continue
            verb = "disable" if op["op"] == "disable_rules" else "enable"
            for ref in op["rules"]:
                rule = rules.get(ref["id"]) or rules.get(ref["vendor_ref"])
                raw = facts["rules"].get(rule["id"]) if rule else None
                if rule is None or raw is None:
                    problems.append(f"rule {display_id(ref['id'])} is not on the host (re-read it first)")
                    continue
                steps.append({"op": index, "kind": f"{verb}_rule", "position": "in place",
                              "detail": f"{verb} {display_id(rule['id'])}"})
                if str(raw.get("store_type") or "Local").lower() != "local":
                    problems.append(f"rule {display_id(rule['id'])} comes from {display_id(raw.get('store_type'))} "
                                    "(Group Policy): change it there")
                    continue
                if verb == "disable" and rule["id"].lower() == OPENSSH_RULE.lower():
                    problems.append(f"{OPENSSH_RULE} keeps sshd reachable: Atrium never disables it")
                if verb == "enable" and rule["action"] != "pass" and rule["direction"] == "in" \
                        and self._blocks_hub(rule, hub, port):
                    problems.append(f"rule {display_id(rule['id'])} blocks traffic that can include the hub's SSH "
                                    "connection - enabling it could cut the hub off (block rules always win)")
                if rule["enabled"] == (verb == "enable") or any(t["name"] == rule["id"] for t in toggled):
                    notes.append(f"rule {display_id(rule['id'])} is already {verb}d")
                    continue
                toggled.append({"name": rule["id"], "enabled": rule["enabled"]})
                (disabled if verb == "disable" else enabled).append(rule["id"])
                payload.append({"kind": "set", "name": rule["id"], "enabled": verb == "enable"})
        guard = management_guard(record, ops, hub_addresses=hub, management_ports=[port])
        if not payload and not problems:
            problems.append("nothing to change: the rules are already as asked")
        return {"guard": guard, "problems": problems, "steps": steps, "notes": notes, "payload": payload,
                "created": created, "toggled": toggled, "disabled": disabled, "enabled": enabled}

    @staticmethod
    def _blocks_hub(rule: dict[str, Any], hub: list[str] | None, port: int) -> bool:
        source = rule.get("source") or {}
        if hub and not source.get("any") and not source.get("negate"):
            cidrs = source.get("cidrs") or []
            if not source.get("aliases") and not any(ipaddress.ip_address(h) in ipaddress.ip_network(c) for h in hub
                                                     for c in cidrs if ipaddress.ip_network(c).version ==
                                                     ipaddress.ip_address(h).version):
                return False
        services = rule.get("services")
        return not services or any(s["proto"] in ("tcp", "any") and (s.get("alias") or not s.get("ports") or any(
            lo <= port <= hi for lo, hi in port_ranges(s["ports"]))) for s in services)

    async def preview_change(self, ops: list[dict[str, Any]], snapshot: dict[str, Any]) -> dict[str, Any]:
        ops = parse_ops(ops)
        async with self.session() as session:
            model = await self.read(session)
        plan = self._plan(model, ops)
        write, reasons = self.writes(model)
        problems = plan["guard"] + plan["problems"] + [f"changes are unavailable on this host: {r}" for r in
                                                       (reasons if write is None else [])]
        notes = plan["notes"] + [f"Windows Firewall has no commit-confirm: Atrium registers a Scheduled Task that "
                                 f"undoes the change {self.window} s after it unless Atrium confirms it",
                                 "Windows saves rule changes at once: a reboot does not undo them"]
        if model["record"]["revision"] != snapshot.get("revision"):
            notes.append("the host changed since the snapshot: refresh before approving")
        return {"steps": plan["steps"], "notes": notes, "problems": problems}

    @staticmethod
    def _parse_token(token: str) -> dict[str, Any]:
        try:
            info = json.loads(token)
            assert isinstance(info, dict) and info.get("v") == 1 and SID_RE.match(str(info.get("sid") or ""))
            assert all(isinstance(n, str) and CREATED_RE.match(n) for n in info.get("created") or [])
            assert all(isinstance(t, dict) and isinstance(t.get("name"), str) and 0 < len(t["name"]) <= 300
                       and not CONTROL.search(t["name"]) and isinstance(t.get("enabled"), bool)
                       for t in info.get("toggled") or [])
        except (ValueError, AssertionError, AttributeError, TypeError) as exc:
            raise ChangeError("Not a change token of this Windows Firewall connector", code="invalid",
                              state="unknown") from exc
        return info

    @staticmethod
    def _state(record: dict[str, Any], info: dict[str, Any]) -> str:
        rules = {r["id"]: r for r in record.get("rules") or []}
        applied, reverted = [], []
        for name in info.get("created") or []:
            present = name in rules and rules[name].get("enabled", True)
            applied.append(present)
            reverted.append(not present)
        for entry in info.get("toggled") or []:
            now = (rules.get(entry["name"]) or {}).get("enabled", entry["enabled"])
            applied.append(now != entry["enabled"])
            reverted.append(now == entry["enabled"])
        if not applied:
            return "partial"
        return "applied" if all(applied) else "reverted" if all(reverted) else "partial"

    async def apply_change(self, ops: list[dict[str, Any]], base_revision: str, backup: Backup | None) -> dict[str, Any]:
        ops = parse_ops(ops)
        if self.write_capability() is None:
            raise ChangeError("This connection is read only", code="unsupported", state="unchanged")
        progress = {"armed": False}
        try:
            async with self.session() as session:
                return await self._apply(session, ops, base_revision, progress)
        except ChangeError:
            raise
        except ConnectorError as exc:
            raise ChangeError(exc.message + (f" - the Scheduled Task undoes the change within {self.window} s"
                                             if progress["armed"] else ""),
                              code="unreachable" if isinstance(exc, SshUnavailable) else "failed",
                              state="unknown" if progress["armed"] else "unchanged") from exc

    async def _apply(self, session: Any, ops: list[dict[str, Any]], base_revision: str,
                     progress: dict[str, bool]) -> dict[str, Any]:
        model = await self.read(session)
        if normalize_record(model["record"])["revision"] != base_revision:
            raise ChangeError("The host's rules changed since the preview - re-read it and preview again", code="stale",
                              state="unchanged")
        write, reasons = self.writes(model)
        if write is None:
            raise ChangeError("Changes are unavailable on this host: " + "; ".join(reasons), code="unsupported",
                              state="unchanged")
        plan = self._plan(model, ops)
        if plan["guard"]:
            raise ChangeError("Refused by the management-path guard: " + "; ".join(plan["guard"]), code="lockout",
                              state="unchanged")
        if plan["problems"]:
            raise ChangeError("; ".join(plan["problems"]), code="invalid", state="unchanged")
        sid = secrets_module.token_hex(8)
        info: dict[str, Any] = {"v": 1, "sid": sid, "created": [c["id"] for c in plan["created"]],
                                "toggled": plan["toggled"]}
        if len(json.dumps(info)) > 3800:
            raise ChangeError("Too many rules in one change - split it", code="invalid", state="unchanged")
        # 1. arm the Scheduled Task that undoes the change BEFORE writing
        armed_at = self.clock()
        revert = encoded(revert_script(sid, info["created"], info["toggled"], "fired"))
        arm = await self.ps(session, "arm", ARM, {"sid": sid, "window": self.window, "revert": revert},
                            what="arm the automatic revert")
        if not arm.get("ok"):
            await self._rollback(session, info)  # clears the registry entry and any half-registered task
            raise ChangeError("Windows could not register the automatic revert task - nothing was changed",
                              code="failed", state="unchanged")
        progress["armed"] = True
        info["deadline"] = armed_at + self.window
        # 2. write
        answer = await self.ps(session, "apply", APPLY, {"sid": sid, "ops": plan["payload"]}, what="apply the change")
        if not answer.get("ok"):
            reason = {"exists": "a rule with Atrium's name already exists", "missing": "a rule to change is gone",
                      "not_armed": "the automatic revert was not armed"}.get(str(answer.get("error")),
                                                                            self._failed(answer, "apply the change").message)
            raise await self._undone(session, info, f"Windows refused the change: {reason}")
        after = normalize_record((await self.read(session))["record"])
        if self._state(after, info) != "applied":
            raise await self._undone(session, info, "Windows accepted the change but its rules do not show it")
        return {"token": json.dumps(info, separators=(",", ":"), sort_keys=True), "rollback_until": info["deadline"],
                "revision": after["revision"], "created": plan["created"], "disabled": plan["disabled"],
                "enabled": plan["enabled"], "notes": [f"Scheduled Task armed: the change is undone after "
                                                      f"{self.window} s unless confirmed (session {sid})"]}

    async def _rollback(self, session: Any, info: dict[str, Any]) -> str:
        answer = await self.ps(session, "rollback", "", what="roll the change back",
                               text=revert_script(info["sid"], info["created"], info["toggled"], "rolled"))
        return str(answer.get("state") or "")

    async def _undone(self, session: Any, info: dict[str, Any], message: str) -> ChangeError:
        try:
            await self._rollback(session, info)
            after = normalize_record((await self.read(session))["record"])
            if self._state(after, info) == "reverted":
                return ChangeError(message + " - Atrium rolled it back", code="failed", state="rolled_back")
        except ConnectorError:
            pass
        return ChangeError(message + f" - the Scheduled Task undoes the change within {self.window} s", code="failed",
                           state="unknown")

    async def confirm_change(self, token: str) -> dict[str, Any]:
        info = self._parse_token(token)
        try:
            async with self.session() as session:
                answer = await self.ps(session, "confirm", CONFIRM, {"sid": info["sid"]}, what="confirm the change")
                record = normalize_record((await self.read(session))["record"])
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable" if isinstance(exc, SshUnavailable) else "failed",
                              state="unknown") from exc
        state, now = str(answer.get("state") or ""), self._state(record, info)
        if state == "confirmed" and now == "applied":
            return {"confirmed": True, "revision": record["revision"],
                    "notes": ["the Scheduled Task was removed; Windows had saved the rules when they were made"]}
        if state in ("fired", "rolled") or now == "reverted":
            raise ChangeError("Too late to confirm: Windows undid the change", code="failed",
                              state="rolled_back" if now == "reverted" else "unknown")
        raise ChangeError("No armed change with this id on the host", code="failed", state="unknown")

    async def rollback_change(self, token: str, backup: Backup | None) -> dict[str, Any]:
        info = self._parse_token(token)
        try:
            async with self.session() as session:
                state = await self._rollback(session, info)
                record = normalize_record((await self.read(session))["record"])
        except ConnectorError as exc:
            raise ChangeError(exc.message + " - if the host is unreachable, its Scheduled Task undoes the change "
                              f"within {self.window} s of it", code="unreachable" if isinstance(exc, SshUnavailable)
                              else "failed", state="unknown") from exc
        if self._state(record, info) == "reverted":
            return {"rolled_back": True, "method": "deadman",
                    "notes": ["the Scheduled Task had already undone the change"] if state == "fired" else []}
        if state == "confirmed":
            raise ChangeError("The change was already confirmed: revert it with a new change", code="failed",
                              state="applied")
        raise ChangeError("The change is still on the host after rolling it back", code="failed", state="applied")

    async def restore_backup(self, backup: Backup) -> dict[str, Any]:
        if backup.format != "wfw" or not backup.content:
            raise ChangeError("The backup is not a Windows Firewall export", code="invalid", state="unchanged")
        try:
            async with self.session() as session:
                answer = await self.ps(session, "restore", RESTORE, {
                    "content": base64.b64encode(backup.content).decode("ascii"),
                    "sha256": hashlib.sha256(backup.content).hexdigest()}, what="import the backup")
                if not answer.get("ok"):
                    raise ChangeError("netsh advfirewall import refused the backup"
                                      if answer.get("error") == "import" else "The backup did not arrive intact",
                                      code="failed" if answer.get("error") == "import" else "invalid",
                                      state="unknown" if answer.get("error") == "import" else "unchanged")
                record = normalize_record((await self.read(session))["record"])
        except ChangeError:
            raise
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable" if isinstance(exc, SshUnavailable) else "failed",
                              state="unknown") from exc
        return {"restored": True, "revision": record["revision"],
                "notes": ["netsh advfirewall import replaced the whole local firewall store with the backup"]}
