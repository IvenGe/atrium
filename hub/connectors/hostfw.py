"""Linux host firewalls over SSH: nftables, ufw and firewalld (device kind ``host``).

Research: docs/research/fw-hosts-linux-windows.md (sections 0-3 and 5). Every call uses ONE SSH session
(``Connector.ssh``): stdout, stderr and the exit status stay apart, scripts go on stdin, nothing is cut silently.
Commands are fixed text; nothing read from the host (rule comments, interface or zone names) is ever put into a
command line - values Atrium sends are validated against strict patterns and passed as separate arguments or as
data lines on stdin.

Which firewall ("manager", setting ``auto`` = research 0.3): firewalld when ``systemctl is-active firewalld`` says
active; else ufw when /etc/ufw/ufw.conf says ``ENABLED=yes``; else raw nftables when ``nft`` exists; legacy iptables
alone is not supported (the host is shown without rules, with a note).

Reading (all managers: ``ip -j -d addr show``, ``ip -j route show default``, ``ss -H -tuln``, /etc/os-release):

- nftables: ``nft -j list ruleset``. Base chains of type filter on the input / forward / output hooks of the ip,
  ip6 and inet families, in hook and priority order; rules reached through jump / goto are read in place. Checked
  against nft 1.0.9 (JSON schema 1) in a network namespace: payload ``saddr`` / ``daddr`` matches, ``ct state`` as
  ``{"op": "in", "right": [...]}``, anonymous sets with ``{"range": [lo, hi]}``, ``{"prefix": {...}}``, named sets
  as ``"@name"``, ``{"jump": {"target": ...}}`` (libnftables-json(5)). Return-traffic rules (``ct state
  established,related``, ``ct state invalid``) are left out (they never allow a new connection); matches Atrium
  cannot represent make the rule look wider, never narrower (noted). nftables has no disabled state: rules Atrium
  disabled are kept in the regular chain ``parked`` of ``table inet atrium`` (never jumped to) and read as disabled.
- ufw: the ``### tuple ###`` lines of /etc/ufw/user.rules and user6.rules (machine readable; field order action
  proto dport dst sport src [dapp sapp] direction[_iface], comments hex-encoded - verified in ufw's
  backend_iptables.py / util.py, upstream main October 2026), defaults from /etc/default/ufw, and
  ``ufw status verbose`` for the running state. Rules in before.rules / after.rules are not shown (``ufw status``
  does not show them either). IPv4 rules are numbered before IPv6 rules (``get_status``).
- firewalld: ``firewall-cmd --list-all-zones`` (runtime), ``--permanent --list-all-zones`` (only to report a
  difference), ``--list-all-policies`` and the service definitions in /usr/lib/firewalld/services (world readable).
  Output format, rich-rule rendering (``rule priority=.. family=.. source .. destination .. element log action``)
  and priority semantics (``priority < 0`` runs in the zone's _pre chain, before deny rules) checked against
  firewalld main (command.py, rich.py) and firewalld.richlanguage(5). Inactive zones are not shown.

Least privilege - a dedicated account with a key and ``sudo -n`` (never a stored sudo password). The connector runs
the tools by the absolute path it finds (/usr/sbin, /sbin, /usr/bin, /bin, /usr/local/sbin); use the paths
``command -v`` shows as root::

    # reads - keep the lines of the manager in use
    Cmnd_Alias ATRIUM_FW_READ = /usr/sbin/nft -j list ruleset, /usr/sbin/nft list ruleset, \\
        /usr/sbin/ufw status verbose, /usr/sbin/ufw version, \\
        /usr/bin/cat /etc/ufw/user.rules, /usr/bin/cat /etc/ufw/user6.rules, \\
        /usr/bin/cat /etc/ufw/before.rules, /usr/bin/cat /etc/ufw/after.rules, \\
        /usr/bin/cat /etc/ufw/before6.rules, /usr/bin/cat /etc/ufw/after6.rules, \\
        /usr/bin/firewall-cmd --state, /usr/bin/firewall-cmd --version, \\
        /usr/bin/firewall-cmd --list-all-zones, /usr/bin/firewall-cmd --permanent --list-all-zones, \\
        /usr/bin/firewall-cmd --list-all-policies
    # changes - leave this out for a read-only connection
    Cmnd_Alias ATRIUM_FW_WRITE = /usr/local/sbin/atrium-fw
    atrium ALL=(root) NOPASSWD: ATRIUM_FW_READ, ATRIUM_FW_WRITE

Changes (rollback ``deadman``; research 0.4-0.5, 1.3-1.4, 2.3-2.4, 3.3-3.4): only through ``atrium-fw``, a root-owned
wrapper with fixed verbs that Atrium ships (``python -m hub.connectors.hostfw wrapper > /usr/local/sbin/atrium-fw``,
root:root 0755). It refuses to change anything until ``arm`` has saved the current state and started a transient
systemd timer (``systemd-run --on-active=<window> --timer-property=AccuracySec=1s``) that restores it; ``confirm``
renames the arm file atomically (so the timer and a confirm cannot both win), stops the timer and only then persists.
It validates its input again: nftables - the text must be exactly one ``table inet atrium { ... }`` block (no other
table, include, define, comment, variable or backslash; checked with ``nft -c`` before ``nft -f``), applied as one
transaction (``table inet atrium {}``, ``delete table inet atrium``, the new table); ufw / firewalld - one data line
per step, every field matched against a strict pattern, run as separate arguments (no shell evaluation).

- nftables: Atrium only writes inside ``table inet atrium``, which an administrator creates once with an input chain
  whose policy is drop (``python -m hub.connectors.hostfw nft-table`` prints a starting point). An accept in one table
  cannot override a drop in another (every base chain runs; a drop is final), so an allow is refused while another
  table's input chain drops by default. New rules go to the top of the input chain; persisted after confirm to
  /etc/atrium/atrium.nft (include it from the distribution's nftables configuration).
- One allow can be several native rules carrying the same key ``<marker>.<n>``: one per address family on nftables,
  one per source / destination network pair on ufw and firewalld (their rules take one network each). They are read
  back as one rule with the networks joined, so a dual-stack or multi-subnet zone works and the hub still verifies
  exactly what was asked; a half-applied or half-parked allow reads as two rules and never looks complete. A family
  present on one side only cannot be expressed (no rule could match it) and is refused.
- ufw: ``ufw prepend allow in on <if> [log] proto <p> from <src> to <dst> port <ports> comment '<marker>.<n> ...'``;
  the timer copies user.rules / user6.rules back and runs ``ufw reload``. ufw writes are persistent at once: a reboot is no extra rollback. Disabling an Atrium rule deletes
  it and keeps it in the wrapper's registry (/var/lib/atrium/fw/parked), read back as disabled.
- firewalld: ``--add-rich-rule`` at runtime only (``rule priority="-1" family=.. source address=.. destination
  address=.. port port=.. protocol=.. log prefix="<marker>.<n> " level="info" accept``); the timer runs
  ``firewall-cmd --reload`` (permanent configuration back to runtime - this also drops other runtime-only changes);
  confirm repeats the change with ``--permanent``. Rich rules have no comment, so the marker is the log prefix: an
  allow on firewalld must log.
- disable_rules / enable_rules: only rules Atrium created (marker ``atrium:<change>.<n>``) - none of the three has a
  disabled state, and Atrium never rewrites rules it does not own.
- Backups: ``nft list ruleset`` / the ufw rules files / the firewalld listings, read with the read lines above.
  Restore puts back ``table inet atrium`` (nftables) or user.rules / user6.rules (ufw; only the filter table, ufw's
  own chains and, in each rule, the options and targets ufw itself writes are accepted); firewalld is not restored.
  A restore runs like a change: ``restore SID SECONDS MANAGER`` validates the content, arms the automatic revert,
  then writes; Atrium confirms it (nftables: saves it) only after a new connection reached the host.

nftables keeps anonymous sets collapsed (adjacent networks merged; adjacent ports merged once a set holds a range,
seen with nft 1.0.9), so an allow is refused unless written in that form - otherwise it would read back different.

UNVERIFIED (no real host was used; nft 1.0.9 ran in a network namespace, the wrapper ran under dash with stub tools):
the ``ip -j`` key ``ifname`` (research S37 lists the others); ``ss -H -tuln`` columns; that a rule's ufw tuple dport
keeps the order it was given in; ufw ``prepend`` needing ufw 0.35 or later; that /etc/ufw/*.rules need root to read;
the polkit side of firewalld (sudo is used instead); firewalld service definitions outside /usr/lib/firewalld/services
and /etc/firewalld/services; the persistence include paths (/etc/nftables.conf, /etc/sysconfig/nftables.conf); that
the ufw restore check (``check_ufw``, written from ufw's source) accepts every rule form a real ufw writes.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import ipaddress
import json
import re
import secrets as secrets_module
import sys
import time
import xml.etree.ElementTree as ET
from itertools import product
from typing import Any, AsyncIterator, Callable

from ..execution.runner import SshError, SshResult, parse_ssh_connection, posix_command
from .base import Connector, ConnectorError, ConnectorField, check
from .netmodel import (LEAST_PRIVILEGE_NOTE, Backup, ChangeError, UnsafeXml, derived_revision, display_id,
                       management_guard, normalise_cidr, normalize_record, parse_ops, parse_ports, parse_untrusted_xml,
                       port_ranges, ssh_fields, ssh_target, untrusted_text, validate_ssh_config)

OPS = ["allow", "disable_rules", "enable_rules"]
WINDOW = 180
WINDOW_BOUNDS = (60, 600)
WRAPPER = "/usr/local/sbin/atrium-fw"
WRAPPER_VERSION = "1"
MANAGERS = ("auto", "nftables", "ufw", "firewalld")
SID_RE = re.compile(r"^[0-9a-f]{16}$")
KEY_AT_START = re.compile(r"^(atrium:[A-Za-z0-9_-]{1,64}\.\d{1,2})(?:\s|$)")
KEY_FULL = re.compile(r"^atrium:[A-Za-z0-9_-]{1,64}\.\d{1,2}$")
IFNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$")
ZONE_RE = re.compile(r"^[A-Za-z0-9_+-]{1,32}$")
NAME_RE = re.compile(r"^[A-Za-z0-9_.+-]{1,64}$")
PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]{1,200}$")
COMMENT_DROP = re.compile(r"[^A-Za-z0-9 _.,:/()+=-]")
UFW_FILES = ("user.rules", "user6.rules", "before.rules", "after.rules", "before6.rules", "after6.rules")
NFT_HOOKS = {"input": 0, "forward": 1, "output": 2}
# address space that never faces the internet: RFC 1918, CGNAT, link-local, ULA
INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                   "169.254.0.0/16", "127.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128")]
PROTOS = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6", "132": "sctp", "ipv6-icmp": "icmpv6"}
# firewalld's own definitions (config/services/*.xml, firewalld main) - used when the host's files cannot be read
FIREWALLD_SERVICES = {
    "ssh": [("tcp", "22")], "http": [("tcp", "80")], "https": [("tcp", "443")], "dhcpv6-client": [("udp", "546")],
    "cockpit": [("tcp", "9090")], "mdns": [("udp", "5353")], "dns": [("tcp", "53"), ("udp", "53")],
}

# The host facts every session starts with: tool paths (fixed candidates), account, kernel, how the host sees the
# hub (SSH_CONNECTION), whether firewalld / ufw are on, the OS. Output: key=value lines (untrusted).
PROBE = r"""for t in nft ufw firewall-cmd systemd-run ip ss; do
  for d in /usr/sbin /sbin /usr/bin /bin /usr/local/sbin /usr/local/bin; do
    if [ -x "$d/$t" ]; then echo "path.$t=$d/$t"; break; fi
  done
done
echo "uid=$(id -u)"
echo "host=$(uname -n)"
echo "kernel=$(uname -r)"
echo "ssh=${SSH_CONNECTION:-}"
if command -v systemctl >/dev/null 2>&1; then echo "firewalld=$(systemctl is-active firewalld 2>/dev/null)"; fi
if [ -r /etc/ufw/ufw.conf ]; then grep -E '^ENABLED=' /etc/ufw/ufw.conf | sed 's/^/ufw./'; fi
if [ -r /etc/os-release ]; then grep -E '^(ID|VERSION_ID|PRETTY_NAME)=' /etc/os-release | sed 's/^/os./'; fi
if [ -e /sys/class/net/docker0 ]; then echo "docker=yes"; fi
"""
SERVICES = r"""for f in /usr/lib/firewalld/services/*.xml /etc/firewalld/services/*.xml; do
  if [ -r "$f" ]; then echo "### atrium-service ${f##*/}"; cat "$f"; echo; fi
done
"""
NFT_TABLE_TEMPLATE = """table inet atrium {
\tchain input {
\t\ttype filter hook input priority filter; policy drop;
\t\tct state established,related accept
\t\tct state invalid drop
\t\tiifname "lo" accept
\t\tmeta l4proto { icmp, ipv6-icmp } accept
\t\ttcp dport 22 accept comment "ssh - keep the management path open"
\t}

\tchain parked {
\t}
}
"""

WRAPPER_SCRIPT = r'''#!/bin/sh
# atrium-fw 1 - the only command Atrium's SSH account runs as root to CHANGE a host firewall (sudo -n, NOPASSWD).
# Generated by Atrium: python -m hub.connectors.hostfw wrapper > /usr/local/sbin/atrium-fw (root:root, 0755).
#
# Verbs: version | check | parked | table | arm SID SECONDS MANAGER | apply SID (change on stdin) | confirm SID |
#        rollback SID | revert-now SID (the timer) | status SID | restore SID SECONDS MANAGER (content on stdin)
# A change is refused unless the automatic revert (a systemd timer) was armed first; a restore arms it itself and is
# saved only by confirm. Input is validated here again: nftables - only table inet atrium is ever replaced; ufw -
# only rules commented "atrium:<change>.<n>" (a restore: ufw's own chains and rule options); firewalld - only rich
# rules whose log prefix is "atrium:<change>.<n> ".
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
VERSION=1
SELF=/usr/local/sbin/atrium-fw
SPOOL=/var/lib/atrium/fw
PERSIST=/etc/atrium/atrium.nft
UFW_DIR=/etc/ufw
TAB=$(printf '\t')

die() { printf 'atrium-fw: %s\n' "$*" >&2; exit 2; }
matches() { printf '%s\n' "$2" | grep -Eqx -- "$1"; }
need_sid() { matches '[0-9a-f]{16}' "$1" || die "bad session id"; D="$SPOOL/$1"; }
need_manager() { case "$1" in nftables|ufw|firewalld) ;; *) die "bad manager";; esac; }
KEY_RE='atrium:[A-Za-z0-9_-]{1,64}[.][0-9]{1,2}'
ADDR_RE='[0-9A-Fa-f][0-9A-Fa-f.:]{1,38}(/[0-9]{1,3})?'

# -- nftables: the text must be exactly one "table inet atrium { ... }" block -------------------------------------
check_table() {  # FILE
  [ "$(tr -d '\011\012\040-\176' < "$1" | wc -c)" -eq 0 ] || { echo "atrium-fw: non-printable characters" >&2; return 1; }
  awk '
  function fail(why) { bad = why; exit 1 }
  BEGIN { depth = 0; started = 0; ended = 0; bad = "" }
  {
    raw = $0
    if (raw ~ /\\/) fail("backslashes are not accepted")
    q = raw; if (gsub(/"/, "", q) % 2) fail("unbalanced quotes")
    line = raw; gsub(/"[^"]*"/, "\"\"", line)
    if (index(line, "#") || index(line, "$")) fail("comments and variables are not accepted")
    if (!started) {
      if (line ~ /^[ \t]*$/) next
      if (line !~ /^table inet atrium \{[ \t]*$/) fail("the text must start with: table inet atrium {")
      started = 1; depth = 1; next
    }
    if (line ~ /(^|[^A-Za-z0-9_-])(table|include|define|redefine|undefine|flush|destroy)([^A-Za-z0-9_-]|$)/)
      fail("only the content of table inet atrium is accepted")
    n = length(line)
    for (i = 1; i <= n; i++) {
      c = substr(line, i, 1)
      if (ended) { if (c != " " && c != "\t") fail("text after the table"); continue }
      if (c == "{") depth++
      else if (c == "}") { depth--; if (depth == 0) ended = 1 }
    }
  }
  END {
    if (bad == "" && !(started && ended)) bad = "the table is not complete"
    if (bad != "") { print "atrium-fw: " bad > "/dev/stderr"; exit 1 }
  }' "$1"
}

# -- ufw restore: a user rules file as ufw writes it - the filter table, ufw's own chains, and in every rule only
# the options and targets ufw itself writes there (format_rule, the logging and the rate-limiting rules of ufw's
# backend_iptables.py); every value is matched against a strict pattern ---------------------------------------
check_ufw() {  # FILE
  [ "$(tr -d '\011\012\040-\176' < "$1" | wc -c)" -eq 0 ] || return 1
  awk '
  function value(o, v) {
    if (o == "-p") return v ~ /^(tcp|udp|ipv6|esp|ah|gre|igmp|vrrp|all)$/
    if (o == "-i" || o == "-o") return v ~ /^[A-Za-z0-9][A-Za-z0-9_.+-]*$/ && length(v) <= 15
    if (o == "-s" || o == "-d") return v ~ /^[0-9A-Fa-f.:]+(\/[0-9]+)?$/ && length(v) <= 43
    if (o == "--dport" || o == "--sport") return v ~ /^[0-9]+(:[0-9]+)?$/
    if (o == "--dports" || o == "--sports") return v ~ /^[0-9]+(:[0-9]+)?(,[0-9]+(:[0-9]+)?)*$/
    if (o == "--ctstate") return v ~ /^(NEW|INVALID|RELATED|ESTABLISHED)(,(NEW|INVALID|RELATED|ESTABLISHED))*$/
    if (o == "--seconds" || o == "--hitcount" || o == "--limit-burst") return v ~ /^[0-9]+$/
    if (o == "--limit") return v ~ /^[0-9]+\/(second|minute|hour|day|sec|min|s|m|h|d)$/
    if (o == "--reject-with") return v ~ /^(tcp-reset|icmp-port-unreachable|icmp6-port-unreachable)$/
    if (o == "-j") return v ~ /^(ACCEPT|DROP|REJECT|RETURN|LOG|ufw6?-[a-z-]+)$/
    if (o == "--log-prefix") return v == "@P"
    if (o == "--comment") return v == "@C"
    return 0
  }
  function rule(line,   q, n, w, i, o) {
    if (index(line, "@")) return 0
    # the quoted values ufw writes: a log prefix in double quotes, an application comment in single quotes
    while (match(line, /"[^"]*"/)) {
      q = substr(line, RSTART, RLENGTH)
      if (q !~ /^"\[UFW [A-Z]+( [A-Z]+)*\] "$/) return 0
      line = substr(line, 1, RSTART - 1) "@P" substr(line, RSTART + RLENGTH)
    }
    while (match(line, sq "[^" sq "]*" sq)) {
      q = substr(line, RSTART + 1, RLENGTH - 2)
      if (q !~ /^[ds]app_[A-Za-z0-9_%.+-]+(,[ds]app_[A-Za-z0-9_%.+-]+)?$/) return 0
      line = substr(line, 1, RSTART - 1) "@C" substr(line, RSTART + RLENGTH)
    }
    if (index(line, "\"") || index(line, sq)) return 0
    n = split(line, w, /[ \t]+/)
    if (w[1] !~ /^-[AI]$/ || w[2] !~ /^ufw6?-[a-z-]+$/) return 0
    for (i = 3; i <= n; i++) {
      o = w[i]
      if (o == "--set" || o == "--update" || o == "--rsource") continue
      if (o == "-m") { if (w[++i] !~ /^(multiport|conntrack|recent|limit|comment)$/) return 0; continue }
      if (i == n || !value(o, w[++i])) return 0
    }
    return 1
  }
  BEGIN { state = 0; bad = 0; sq = sprintf("%c", 39) }
  /^[ \t]*$/ || /^#/ { next }
  state == 0 && $0 == "*filter" { state = 1; next }
  state == 1 && $0 == "COMMIT" { state = 2; next }
  state == 1 && /^:ufw6?-[a-z-]+ - \[0:0\]$/ { next }
  state == 1 && rule($0) { next }
  { bad = 1; exit 1 }
  END { if (bad || state != 2) exit 1 }' "$1"
}

replace_table() {  # TABLE_FILE OUT_FILE - one nft transaction: (re)create table inet atrium from the file
  { printf 'table inet atrium {}\ndelete table inet atrium\n'; cat "$1"; } > "$2" &&
  nft -c -f "$2" && nft -f "$2"
}

persist_table() {
  mkdir -p "${PERSIST%/*}" && nft list table inet atrium > "$PERSIST.tmp" && mv "$PERSIST.tmp" "$PERSIST"
}

# -- ufw / firewalld: one tab-separated line per step ------------------------------------------------------------
# ufw:       VERB KEY IFACE LOG(0|1) PROTO SRC DST PORTS COMMENT     VERB: add | park | unpark
# firewalld: VERB KEY ZONE RICH_RULE
valid_line() {  # MANAGER LINE
  case "$1" in
    ufw)
      printf '%s\n' "$2" | {
        IFS="$TAB" read -r verb key iface log proto src dst ports comment rest || true
        case "$verb" in add|park|unpark) ;; *) exit 1;; esac
        [ -z "${rest:-}" ] && matches "$KEY_RE" "$key" && matches '[A-Za-z0-9][A-Za-z0-9_.-]{0,14}' "$iface" &&
          matches '[01]' "$log" && matches 'tcp|udp' "$proto" && matches "$ADDR_RE" "$src" && matches "$ADDR_RE" "$dst" &&
          matches '[0-9]{1,5}([,:][0-9]{1,5}){0,29}' "$ports" && matches '[A-Za-z0-9 _.,:/()+=-]{1,200}' "$comment" &&
          case "$comment" in "$key"|"$key "*) true;; *) false;; esac
      } ;;
    firewalld)
      printf '%s\n' "$2" | {
        IFS="$TAB" read -r verb key zone rule rest || true
        case "$verb" in add|park|unpark) ;; *) exit 1;; esac
        [ -z "${rest:-}" ] && matches "$KEY_RE" "$key" && matches '[A-Za-z0-9_+-]{1,32}' "$zone" &&
          matches "rule priority=\"-1\" family=\"ipv[46]\" source address=\"$ADDR_RE\" destination address=\"$ADDR_RE\" (port port=\"[0-9]{1,5}(-[0-9]{1,5})?\" protocol=\"(tcp|udp)\"|protocol value=\"icmp\") log prefix=\"$KEY_RE \" level=\"info\" accept" "$rule" &&
          case "$rule" in *"log prefix=\"$key \""*) true;; *) false;; esac
      } ;;
    *) return 1 ;;
  esac
}

ufw_rule() {  # prepend|delete IFACE LOG PROTO SRC DST PORTS COMMENT
  if [ "$3" = 1 ]; then
    ufw "$1" allow in on "$2" log proto "$4" from "$5" to "$6" port "$7" comment "$8"
  else
    ufw "$1" allow in on "$2" proto "$4" from "$5" to "$6" port "$7" comment "$8"
  fi
}

unregister() {  # KEY - drop a parked rule from the registry
  if [ -f "$SPOOL/parked" ]; then
    awk -F "$TAB" -v k="$1" '$2 != k' "$SPOOL/parked" > "$SPOOL/parked.tmp" && mv "$SPOOL/parked.tmp" "$SPOOL/parked"
  fi
}

run_line() {  # MANAGER LINE MODE(runtime|permanent)
  case "$1" in
    ufw)
      IFS="$TAB" read -r verb key iface log proto src dst ports comment <<EOF
$2
EOF
      case "$verb" in
        add) ufw_rule prepend "$iface" "$log" "$proto" "$src" "$dst" "$ports" "$comment" ;;
        park) ufw_rule delete "$iface" "$log" "$proto" "$src" "$dst" "$ports" "$comment" &&
                printf 'ufw\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$key" "$iface" "$log" "$proto" "$src" "$dst" "$ports" "$comment" >> "$SPOOL/parked" ;;
        unpark) ufw_rule prepend "$iface" "$log" "$proto" "$src" "$dst" "$ports" "$comment" && unregister "$key" ;;
      esac ;;
    firewalld)
      IFS="$TAB" read -r verb key zone rule <<EOF
$2
EOF
      if [ "$3" = permanent ]; then
        case "$verb" in
          add|unpark) firewall-cmd --permanent --zone="$zone" --add-rich-rule="$rule" ;;
          park) firewall-cmd --permanent --zone="$zone" --remove-rich-rule="$rule" ;;
        esac
        return
      fi
      case "$verb" in
        add) firewall-cmd --zone="$zone" --add-rich-rule="$rule" ;;
        park) firewall-cmd --zone="$zone" --remove-rich-rule="$rule" &&
                printf 'firewalld\t%s\t%s\t%s\n' "$key" "$zone" "$rule" >> "$SPOOL/parked" ;;
        unpark) firewall-cmd --zone="$zone" --add-rich-rule="$rule" && unregister "$key" ;;
      esac ;;
  esac
}

# -- the automatic revert -----------------------------------------------------------------------------------------
restore_pre() {  # put back what "arm" saved (the timer, or a rollback)
  m=$(cat "$D/manager") ok=0
  case "$m" in
    nftables) replace_table "$D/pre.nft" "$D/revert.nft" >/dev/null && ok=1 ;;
    ufw) cp "$D/user.rules" "$UFW_DIR/user.rules" && cp "$D/user6.rules" "$UFW_DIR/user6.rules" &&
           ufw reload >/dev/null && ok=1 ;;
    firewalld) firewall-cmd --reload >/dev/null && ok=1 ;;
  esac
  cp "$D/parked" "$SPOOL/parked" 2>/dev/null || true
  [ "$ok" = 1 ]
}

state_of() {
  for s in armed confirmed fired rolled; do [ -e "$D/$s" ] && { echo "$s"; return; }; done
  echo missing
}

arm_session() {  # SID SECONDS MANAGER - save the current state and start the automatic revert (or die)
  need_sid "$1"; need_manager "$3"
  matches '[0-9]{2,4}' "$2" && [ "$2" -ge 10 ] && [ "$2" -le 3600 ] || die "the window is 10-3600 seconds"
  command -v systemd-run >/dev/null 2>&1 || die "systemd-run is missing: changes need the automatic revert"
  mkdir -p "$SPOOL" || die "cannot create $SPOOL"
  find "$SPOOL" -mindepth 1 -maxdepth 1 -type d -mtime +30 -exec rm -rf {} + 2>/dev/null || true  # old sessions
  mkdir "$D" 2>/dev/null || die "session $1 exists"
  case "$3" in
    nftables) nft list table inet atrium > "$D/pre.nft" || { rm -rf "$D"; die "table inet atrium is missing"; } ;;
    ufw) { cp -p "$UFW_DIR/user.rules" "$D/user.rules" && cp -p "$UFW_DIR/user6.rules" "$D/user6.rules"; } ||
           { rm -rf "$D"; die "cannot copy the ufw rules"; } ;;
    firewalld) firewall-cmd --state >/dev/null 2>&1 || { rm -rf "$D"; die "firewalld is not running"; } ;;
  esac
  if [ -f "$SPOOL/parked" ]; then cp -p "$SPOOL/parked" "$D/parked"; else : > "$D/parked"; fi
  printf '%s\n' "$3" > "$D/manager"
  : > "$D/armed"
  if ! systemd-run --unit="atrium-fw-revert-$1" --on-active="$2" --timer-property=AccuracySec=1s \
      "$SELF" revert-now "$1" >/dev/null 2>&1; then
    rm -rf "$D"; die "systemd-run could not arm the automatic revert"
  fi
}

undo_now() {  # SID - roll an armed session back at once (a write that failed half-way)
  if mv "$D/armed" "$D/rolled" 2>/dev/null; then
    systemctl stop "atrium-fw-revert-$1.timer" >/dev/null 2>&1 || true
    restore_pre >/dev/null 2>&1 || true
  fi
}

cmd=${1:-}
[ $# -gt 0 ] && shift
case "$cmd" in
  version) echo "atrium-fw $VERSION" ;;
  check)
    echo "version=$VERSION"
    if command -v systemd-run >/dev/null 2>&1 && [ -d /run/systemd/system ]; then echo systemd_run=yes; else echo systemd_run=no; fi
    if command -v nft >/dev/null 2>&1; then
      echo nft=yes
      if nft list table inet atrium >/dev/null 2>&1; then echo atrium_table=yes; else echo atrium_table=no; fi
      if grep -qsF "$PERSIST" /etc/nftables.conf /etc/sysconfig/nftables.conf; then echo persist=yes; else echo persist=no; fi
    else echo nft=no; fi
    if command -v ufw >/dev/null 2>&1; then echo ufw=yes; else echo ufw=no; fi
    if command -v firewall-cmd >/dev/null 2>&1; then echo firewalld=yes; else echo firewalld=no; fi
    if mkdir -p "$SPOOL" 2>/dev/null && [ -w "$SPOOL" ]; then echo spool=ok; else echo spool=failed; fi ;;
  parked) cat "$SPOOL/parked" 2>/dev/null || true ;;
  table) nft list table inet atrium ;;
  arm)
    [ $# -eq 3 ] || die "usage: arm SID SECONDS MANAGER"
    arm_session "$1" "$2" "$3"
    echo armed ;;
  apply)
    [ $# -eq 1 ] || die "usage: apply SID < change"
    need_sid "$1"
    [ -e "$D/armed" ] || die "not armed: the automatic revert must be armed first"
    m=$(cat "$D/manager")
    cat > "$D/change" || die "cannot read the change"
    case "$m" in
      nftables)
        check_table "$D/change" || die "the table text was refused"
        replace_table "$D/change" "$D/change.nft" || die "nft refused the table" ;;
      *)
        [ -s "$D/change" ] || die "empty change"
        while IFS= read -r line; do valid_line "$m" "$line" || die "a step was refused"; done < "$D/change"
        while IFS= read -r line; do run_line "$m" "$line" runtime >/dev/null || die "a step failed"; done < "$D/change" ;;
    esac
    echo applied ;;
  confirm)
    [ $# -eq 1 ] || die "usage: confirm SID"
    need_sid "$1"
    [ -d "$D" ] || { echo missing; exit 0; }
    if mv "$D/armed" "$D/confirmed" 2>/dev/null; then
      systemctl stop "atrium-fw-revert-$1.timer" >/dev/null 2>&1 || true
      echo confirmed
      m=$(cat "$D/manager")
      case "$m" in
        nftables) if persist_table; then echo persist=ok; else echo persist=failed; fi ;;
        firewalld)
          ok=1
          while IFS= read -r line; do run_line firewalld "$line" permanent >/dev/null || ok=0; done < "$D/change"
          if [ "$ok" = 1 ]; then echo persist=ok; else echo persist=failed; fi ;;
        ufw) echo persist=immediate ;;
      esac
      rm -f "$D/pre.nft" "$D/user.rules" "$D/user6.rules"
    else
      state_of
    fi ;;
  rollback|revert-now)
    [ $# -eq 1 ] || die "usage: $cmd SID"
    need_sid "$1"
    [ -d "$D" ] || { echo missing; exit 0; }
    to=rolled; [ "$cmd" = revert-now ] && to=fired
    if mv "$D/armed" "$D/$to" 2>/dev/null; then
      [ "$cmd" = rollback ] && { systemctl stop "atrium-fw-revert-$1.timer" >/dev/null 2>&1 || true; }
      if restore_pre; then echo reverted; else echo revert-failed; exit 1; fi
    else
      state_of
    fi ;;
  status)
    [ $# -eq 1 ] || die "usage: status SID"
    need_sid "$1"; state_of ;;
  restore)
    # like a change: validated first, then armed (the timer puts the current rules back), then written; saved only
    # by "confirm SID", which Atrium sends after reaching the host again over a new connection
    [ $# -eq 3 ] || die "usage: restore SID SECONDS MANAGER < content"
    need_sid "$1"; need_manager "$3"
    [ "$3" != firewalld ] || die "restoring firewalld is not supported: restore /etc/firewalld from the backup by hand"
    mkdir -p "$SPOOL" || die "cannot create $SPOOL"
    T=$(mktemp -d "$SPOOL/restore.XXXXXX") || die "cannot create a work directory"
    trap 'rm -rf "$T"' EXIT
    case "$3" in
      nftables)
        cat > "$T/table" || die "cannot read the content"
        check_table "$T/table" || die "the table text was refused" ;;
      ufw)
        awk -v dir="$T" '
          /^### atrium-fw file (user|user6)\.rules$/ { out = dir "/" $4; printf "" > out; next }
          /^### atrium-fw / { out = ""; next }
          out != "" { print > out }' || die "cannot read the content"
        for f in user.rules user6.rules; do
          [ -s "$T/$f" ] && check_ufw "$T/$f" ||
            die "$f is missing or not a ufw user rules file (only rules in the form ufw writes are restored)"
        done ;;
    esac
    arm_session "$1" "$2" "$3"
    case "$3" in
      nftables) replace_table "$T/table" "$T/restore.nft" >/dev/null || { undo_now "$1"; die "nft refused the table"; } ;;
      ufw) { cp "$T/user.rules" "$UFW_DIR/user.rules" && cp "$T/user6.rules" "$UFW_DIR/user6.rules" &&
               ufw reload >/dev/null; } || { undo_now "$1"; die "ufw could not reload the restored rules"; } ;;
    esac
    echo restored ;;
  *) die "unknown verb (version, check, parked, table, arm, apply, confirm, rollback, revert-now, status, restore)" ;;
esac
'''


class SshUnavailable(ConnectorError):
    """The SSH connection could not be opened or broke off."""


class SudoRefused(ConnectorError):
    """sudo -n refused a command (the sudoers lines are missing)."""


# --------------------------------------------------------------------------------------
# small parsers (all input is untrusted text from the host)
# --------------------------------------------------------------------------------------


def parse_probe(text: str) -> dict[str, Any]:
    facts: dict[str, Any] = {"paths": {}, "os": {}}
    for line in (text or "").splitlines():
        key, sep, value = line.partition("=")
        if not sep:
            continue
        value = value.strip()
        if key.startswith("path.") and key[5:] in ("nft", "ufw", "firewall-cmd", "systemd-run", "ip", "ss"):
            if PATH_RE.match(value) and ".." not in value:
                facts["paths"].setdefault(key[5:], value)
        elif key.startswith("os.") and key[3:] in ("ID", "VERSION_ID", "PRETTY_NAME"):
            facts["os"][key[3:]] = untrusted_text(value.strip('"').strip("'"), 80)
        elif key in ("uid", "host", "kernel", "firewalld", "docker", "ufw.ENABLED"):
            facts[key] = untrusted_text(value.strip('"'), 120)
        elif key == "ssh":
            facts["ssh"] = parse_ssh_connection(value)
    return facts


def canonical_ports(ranges: list[tuple[int, int]]) -> str | None:
    """Ports as text, ascending ("80,443,8000-8080"); None for an empty list."""
    parts = sorted(set(ranges))
    if not parts:
        return None
    return parse_ports(",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in parts))


def sorted_ports(text: str | None) -> bool:
    """Whether a ports text is already in the order the host firewalls list them (ascending)."""
    return not text or canonical_ports(port_ranges(text)) == text


def parse_ip_addr(data: Any, default_devs: set[str]) -> list[dict[str, Any]]:
    """Interfaces from ``ip -j -d addr show`` (loopback and veth pairs left out; link-local addresses ignored)."""
    out = []
    for link in data if isinstance(data, list) else []:
        if not isinstance(link, dict):
            continue
        name = str(link.get("ifname") or "")
        if not IFNAME_RE.match(name) or link.get("link_type") == "loopback" or name.startswith("veth"):
            continue
        addresses, subnets = [], []
        for info in link.get("addr_info") or []:
            if not isinstance(info, dict) or info.get("scope") not in ("global", "site", None):
                continue
            try:
                iface = ipaddress.ip_interface(f"{info.get('local')}/{int(info.get('prefixlen'))}")
            except (ValueError, TypeError):
                continue
            addresses.append(str(iface.ip))
            if str(iface.network) not in subnets:
                subnets.append(str(iface.network))
        kind = link.get("linkinfo") if isinstance(link.get("linkinfo"), dict) else {}
        vlan = (kind.get("info_data") or {}).get("id") if kind.get("info_kind") == "vlan" else None
        flags = link.get("flags") if isinstance(link.get("flags"), list) else []
        public = any(not any(ipaddress.ip_address(a) in net for net in INTERNAL_NETS
                             if net.version == ipaddress.ip_address(a).version) for a in addresses)
        out.append({"id": name, "name": name, "vlan": vlan if isinstance(vlan, int) else None, "subnets": subnets,
                    "addresses": addresses, "role": "wan" if name in default_devs and public else "lan",
                    "enabled": "UP" in flags and link.get("operstate") != "DOWN",
                    "description": f"VLAN {vlan} on {display_id(link.get('link'))}" if isinstance(vlan, int) else ""})
    return out


def parse_default_devs(data: Any) -> set[str]:
    return {str(r.get("dev")) for r in data if isinstance(r, dict) and r.get("dst") == "default" and r.get("dev")} \
        if isinstance(data, list) else set()


def parse_ss(text: str) -> dict[str, list[str]]:
    """Listening sockets from ``ss -H -tuln``: {"all": [...], "specific": [...], "local": [...]} of "tcp/22"."""
    out: dict[str, list[str]] = {"all": [], "specific": [], "local": []}
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 5 or not parts[0].startswith(("tcp", "udp")):
            continue
        address, _, port = parts[4].rpartition(":")
        if not port.isdigit():
            continue
        address = address.strip("[]").split("%")[0]
        item = f"{parts[0][:3]}/{int(port)}"
        if address in ("*", "0.0.0.0", "::", ""):
            where = "all"
        else:
            try:
                where = "local" if ipaddress.ip_address(address).is_loopback else "specific"
            except ValueError:
                continue
        if item not in out[where]:
            out[where].append(item)
    return out


def _hex_comment(value: str) -> str:
    """A ufw tuple comment (hex-encoded UTF-8, ufw.util.hex_decode; an odd length drops the last digit)."""
    value = value.strip()
    try:
        return bytes.fromhex(value[:-1] if len(value) % 2 else value).decode("utf-8", "replace")
    except ValueError:
        return value


def _int(value: Any, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _key(text: Any) -> str | None:
    match = KEY_AT_START.match(str(text or ""))
    return match.group(1) if match else None


def _short_hash(*parts: Any) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()[:12]


def _endpoint(cidrs: list[str] | None = None, aliases: list[str] | None = None, negate: bool = False,
              default: str = "any") -> dict[str, Any]:
    if cidrs or aliases:
        return {"cidrs": cidrs or [], "aliases": aliases or [], "negate": negate}
    return {"self": True} if default == "self" else {"any": True}


def _rule(rid: str, ref: str, order: int, action: str, *, interfaces: list[str] | None = None,
          out_interfaces: list[str] | None = None, direction: str = "in", source: dict[str, Any] | None = None,
          destination: dict[str, Any] | None = None, services: list[dict[str, Any]] | None = None, log: bool = False,
          description: str = "", hits: int | None = None, enabled: bool = True,
          source_zones: list[str] | None = None, destination_zones: list[str] | None = None) -> dict[str, Any]:
    return {"id": rid, "vendor_ref": ref, "order": order, "enabled": enabled, "action": action,
            "interfaces": interfaces or [], "out_interfaces": out_interfaces or [], "direction": direction,
            "source_zones": source_zones or [], "destination_zones": destination_zones or [],
            "source": source or {"any": True}, "destination": destination or {"any": True}, "services": services,
            "log": log, "description": description, "hits": hits}


def merge_parts(rules: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, dict[str, int]]]:
    """Atrium writes an allow as one native rule per address family (nftables) or per source / destination pair
    (ufw, firewalld), all carrying the same key; they are read back as ONE rule with the networks joined, so the hub
    verifies the change as it was asked. Enabled and parked parts stay apart (``<key>~parked``): a half-applied
    change never looks complete. Also returns {key: {"on": enabled parts, "off": parked parts}}."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for rule in rules:
        if KEY_FULL.match(rule["id"]):
            groups.setdefault(rule["id"], []).append(rule)
    parts = {k: {"on": sum(1 for r in g if r["enabled"]), "off": sum(1 for r in g if not r["enabled"])}
             for k, g in groups.items()}
    out, done = [], set()
    for rule in rules:
        key = rule["id"]
        if key not in groups:
            out.append(rule)
            continue
        if key in done:
            continue
        done.add(key)
        for enabled in (True, False):
            members = [r for r in groups[key] if r["enabled"] == enabled]
            if not members:
                continue
            merged = copy.deepcopy(members[0])
            for side in ("source", "destination"):
                if all(m[side].get("cidrs") for m in members):
                    merged[side]["cidrs"] = list(dict.fromkeys(c for m in members for c in m[side]["cidrs"]))
            merged["interfaces"] = list(dict.fromkeys(i for m in members for i in m["interfaces"]))
            hits = [m["hits"] for m in members if m.get("hits") is not None]
            merged["hits"] = sum(hits) if hits else None
            if not enabled and parts[key]["on"]:
                merged["id"] = merged["vendor_ref"] = f"{key}~parked"
            out.append(merged)
    return out, parts


def family_pairs(op: dict[str, Any]) -> tuple[list[tuple[list[str], list[str]]], list[int]]:
    """([(source networks, destination networks) per address family], families found on one side only)."""
    families: dict[int, dict[str, list[str]]] = {}
    for side in ("source", "destination"):
        for cidr in op[side]["cidrs"]:
            families.setdefault(ipaddress.ip_network(cidr).version, {"source": [], "destination": []})[side].append(cidr)
    pairs = [(g["source"], g["destination"]) for _, g in sorted(families.items()) if g["source"] and g["destination"]]
    return pairs, sorted(v for v, g in families.items() if not (g["source"] and g["destination"]))


def safe_comment(key: str, description: str) -> str:
    """The comment / description Atrium writes: its key, then the change's description reduced to safe characters."""
    rest = " ".join(COMMENT_DROP.sub(" ", description or "").split())
    return f"{key} {rest}".strip()[:180]


# --------------------------------------------------------------------------------------
# nftables
# --------------------------------------------------------------------------------------


def _scrub(value: Any) -> Any:
    """`value` without counters, element expiry and other runtime state - what a revision must not depend on."""
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items() if k not in ("packets", "bytes", "expires", "used")}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value


def _flags(obj: dict[str, Any]) -> set[str]:
    value = obj.get("flags")
    return set(value if isinstance(value, list) else [value] if value else [])


def _values(right: Any) -> list[Any]:
    """The values on the right side of an nft match, sets flattened."""
    if isinstance(right, dict) and "set" in right:
        inner = right["set"]
        items = inner if isinstance(inner, list) else [inner]
    elif isinstance(right, list):
        items = right
    else:
        items = [right]
    out = []
    for item in items:
        if isinstance(item, dict) and "elem" in item:
            item = (item.get("elem") or {}).get("val")
        out.append(item)
    return out


def _cidrs(values: list[Any]) -> list[str] | None:
    out: list[str] = []
    for value in values:
        cidrs: list[str] = []
        if isinstance(value, str):
            cidr = normalise_cidr(value)
            cidrs = [cidr] if cidr else []
        elif isinstance(value, dict) and isinstance(value.get("prefix"), dict):
            cidr = normalise_cidr(f"{value['prefix'].get('addr')}/{value['prefix'].get('len')}")
            cidrs = [cidr] if cidr else []
        elif isinstance(value, dict) and isinstance(value.get("range"), list) and len(value["range"]) == 2:
            try:
                low, high = (ipaddress.ip_address(str(v)) for v in value["range"])
                cidrs = [str(n) for n in ipaddress.summarize_address_range(low, high)]
            except (ValueError, TypeError):
                cidrs = []
        if not cidrs:
            return None
        out += [c for c in cidrs if c not in out]
    return out


def _port_ranges(values: list[Any]) -> list[tuple[int, int]] | None:
    out = []
    for value in values:
        if isinstance(value, bool):
            return None
        if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
            out.append((int(value), int(value)))
        elif isinstance(value, dict) and isinstance(value.get("range"), list) and len(value["range"]) == 2:
            try:
                out.append((int(value["range"][0]), int(value["range"][1])))
            except (TypeError, ValueError):
                return None
        else:
            return None
    return out if all(0 < lo <= hi <= 65535 for lo, hi in out) else None


def _protos(values: list[Any]) -> list[str] | None:
    out = []
    for value in values:
        text = str(value).lower()
        text = PROTOS.get(text, text)
        if not re.fullmatch(r"[a-z0-9][a-z0-9.+-]{0,23}", text):
            return None
        out.append(text)
    return out


class NftRuleset:
    """``nft -j list ruleset`` read into the network model."""

    def __init__(self, data: Any):
        items = data.get("nftables") if isinstance(data, dict) else None
        if not isinstance(items, list):
            raise ValueError("not an nft JSON listing ({\"nftables\": [...]})")
        self.version, self.schema = "", None
        self.chains: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.rules: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
        self.sets: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.tables: list[tuple[str, str]] = []
        self.compat = False
        body = []
        for item in items:
            if not isinstance(item, dict) or len(item) != 1:
                continue
            kind, obj = next(iter(item.items()))
            if not isinstance(obj, dict):
                continue
            if kind == "metainfo":
                self.version, self.schema = untrusted_text(obj.get("version"), 40), obj.get("json_schema_version")
                continue
            key = (str(obj.get("family") or ""), str(obj.get("table") or ""), str(obj.get("name") or ""))
            if kind == "table":
                self.tables.append((key[0], key[2]))
            elif kind == "chain":
                self.chains[key] = obj
                self.rules.setdefault(key, [])
            elif kind in ("set", "map"):
                self.sets[key] = {**obj, "_map": kind == "map"}
                if self._volatile(obj):  # dynamic sets (fail2ban, rate limits) change on their own
                    obj = {k: v for k, v in obj.items() if k != "elem"}
            elif kind == "rule":
                self.rules.setdefault((key[0], key[1], str(obj.get("chain") or "")), []).append(obj)
                self.compat = self.compat or any(isinstance(s, dict) and "xt" in s for s in obj.get("expr") or [])
            body.append({kind: _scrub(obj)})
        self.revision = derived_revision("nftables", body)

    @staticmethod
    def _volatile(obj: dict[str, Any]) -> bool:
        return bool(_flags(obj) & {"dynamic", "timeout"}) or "timeout" in obj

    # -- sets ------------------------------------------------------------------------------

    def aliases(self) -> list[dict[str, Any]]:
        out = []
        for (family, table, name), obj in self.sets.items():
            if obj.get("_map") or family not in ("inet", "ip", "ip6"):
                continue
            kind = str(obj.get("type") or "")
            alias = {"name": f"{family}/{table}/{name}", "kind": "other", "cidrs": [], "ports": None, "resolved": False}
            values = _values({"set": obj.get("elem") or []})
            if kind in ("ipv4_addr", "ipv6_addr"):
                alias["kind"] = "network"
                cidrs = _cidrs(values) if values else []
                if cidrs is not None and not self._volatile(obj):
                    alias.update(cidrs=cidrs, resolved=True)
            elif kind == "inet_service":
                alias["kind"] = "port"
                ranges = _port_ranges(values) if values else []
                if ranges and not self._volatile(obj):
                    alias.update(ports=canonical_ports(ranges), resolved=True)
            out.append(alias)
        return out

    # -- rules -----------------------------------------------------------------------------

    def _translate(self, rule: dict[str, Any], family: str, table: str) -> dict[str, Any] | None:
        """One rule's matches and verdict; None for a rule without a filtering verdict."""
        cond: dict[str, Any] = {"interfaces": [], "out_interfaces": [], "saddr": None, "daddr": None, "protos": None,
                                "l4": None, "ports": None, "port_alias": None}
        verdict, target, log, hits, exact, new_ok = None, None, False, None, True, True
        for stmt in rule.get("expr") or []:
            if not isinstance(stmt, dict) or len(stmt) != 1:
                exact = False
                continue
            name, value = next(iter(stmt.items()))
            if name == "match" and isinstance(value, dict):
                left, right, op = value.get("left"), value.get("right"), value.get("op", "==")
                negate = op == "!="
                if op not in ("==", "!=", "in"):
                    exact = False
                    continue
                values = _values(right)
                if isinstance(left, dict) and isinstance(left.get("meta"), dict):
                    meta = left["meta"].get("key")
                    if meta in ("iifname", "iif", "oifname", "oif") and not negate and all(isinstance(v, str) for v in values):
                        cond["interfaces" if meta.startswith("i") else "out_interfaces"] = [str(v) for v in values]
                    elif meta == "l4proto" and not negate and _protos(values):
                        cond["protos"] = _protos(values)
                    elif meta != "nfproto":
                        exact = False
                elif isinstance(left, dict) and isinstance(left.get("payload"), dict):
                    proto, field = left["payload"].get("protocol"), left["payload"].get("field")
                    if proto in ("ip", "ip6") and field in ("saddr", "daddr"):
                        # UNVERIFIED in libnftables-json(5) (no example); seen from nft 1.0.9 in a namespace
                        if isinstance(right, str) and right.startswith("@"):
                            entry = {"cidrs": [], "aliases": [f"{family}/{table}/{right[1:]}"], "negate": negate}
                        else:
                            cidrs = _cidrs(values)
                            if cidrs is None:
                                exact = False
                                continue
                            entry = {"cidrs": cidrs, "aliases": [], "negate": negate}
                        cond["saddr" if field == "saddr" else "daddr"] = entry
                    elif (proto, field) in (("ip", "protocol"), ("ip6", "nexthdr")) and not negate and _protos(values):
                        cond["protos"] = _protos(values)
                    elif field == "dport" and not negate:
                        cond["l4"] = ["tcp", "udp"] if proto == "th" else [str(proto)]
                        if isinstance(right, str) and right.startswith("@"):
                            cond["port_alias"] = f"{family}/{table}/{right[1:]}"
                        else:
                            ranges = _port_ranges(values)
                            if ranges is None:
                                exact = False
                                continue
                            cond["ports"] = canonical_ports(ranges)
                    elif proto in ("icmp", "icmpv6") and field == "type":
                        cond["protos"] = cond["protos"] or [proto]
                    else:
                        exact = False
                elif isinstance(left, dict) and isinstance(left.get("ct"), dict) and left["ct"].get("key") == "state":
                    states = {str(v) for v in values}
                    new_ok = ("new" in states) != negate  # only rules that can match a NEW connection count
                else:
                    exact = False
            elif name == "counter" and isinstance(value, dict):
                hits = value.get("packets") if isinstance(value.get("packets"), int) else hits
            elif name == "log":
                log = True
            elif name in ("accept", "drop", "reject"):
                verdict = name
            elif name in ("jump", "goto") and isinstance(value, dict):
                verdict, target = name, str(value.get("target") or "")
            elif name in ("return", "vmap", "queue"):
                verdict = verdict or name
            elif name == "xt":
                exact = False
        if verdict is None or verdict in ("return", "queue"):
            return None
        return {"cond": cond, "verdict": verdict, "target": target, "log": log, "hits": hits, "exact": exact,
                "new_ok": new_ok}

    @staticmethod
    def _merge(outer: dict[str, Any], inner: dict[str, Any]) -> dict[str, Any]:
        return {k: inner.get(k) if inner.get(k) not in (None, []) else outer.get(k) for k in set(outer) | set(inner)}

    def _base_chains(self, hooks: tuple[str, ...] = tuple(NFT_HOOKS)) -> list[tuple[str, str, str]]:
        keys = [k for k, c in self.chains.items() if c.get("hook") in hooks and c.get("type", "filter") == "filter"
                and k[0] in ("inet", "ip", "ip6")]
        return sorted(keys, key=lambda k: (NFT_HOOKS[self.chains[k]["hook"]], self.chains[k].get("prio") or 0, k))

    def rule_id(self, key: tuple[str, str, str], rule: dict[str, Any]) -> str:
        family, table, chain = key
        if (family, table) == ("inet", "atrium"):  # Atrium replaces this table as a whole: handles change
            return _key(rule.get("comment")) or f"inet/atrium/{chain}/c-{_short_hash(_scrub(rule.get('expr')), rule.get('comment'))}"
        return f"{family}/{table}/{chain}/{rule.get('handle')}"

    def _emit(self, key: tuple[str, str, str], rule: dict[str, Any], hook: str, cond: dict[str, Any],
              t: dict[str, Any], order: int, enabled: bool = True) -> dict[str, Any]:
        src, dst = cond.get("saddr"), cond.get("daddr")
        source = _endpoint(**src) if src else _endpoint(default="self" if hook == "output" else "any")
        destination = _endpoint(**dst) if dst else _endpoint(default="self" if hook == "input" else "any")
        services = None
        if cond.get("ports") or cond.get("port_alias"):
            protos = cond.get("l4") or cond.get("protos") or ["tcp", "udp"]
            services = [{"proto": p, "ports": cond.get("ports"), "alias": cond.get("port_alias")} for p in protos]
        elif cond.get("protos"):
            services = [{"proto": p} for p in cond["protos"]]
        rid = self.rule_id(key, rule)
        action = {"accept": "pass", "drop": "block", "reject": "reject"}.get(t["verdict"], "block")
        return _rule(rid, rid, order, action, interfaces=cond.get("interfaces"), out_interfaces=cond.get("out_interfaces"),
                     direction="out" if hook == "output" else "in", source=source, destination=destination,
                     services=services, log=t["log"], description=str(rule.get("comment") or ""), hits=t["hits"],
                     enabled=enabled)

    def read_rules(self) -> tuple[list[dict[str, Any]], list[str]]:
        out: list[dict[str, Any]] = []
        stats = {"stateful": 0, "inexact": 0, "vmap": 0}

        def walk(key: tuple[str, str, str], hook: str, inherited: dict[str, Any], depth: int, seen: set) -> None:
            for rule in self.rules.get(key, []):
                t = self._translate(rule, key[0], key[1])
                if t is None:
                    continue
                if not t["new_ok"]:
                    stats["stateful"] += 1
                    continue
                if t["verdict"] == "vmap":
                    stats["vmap"] += 1
                    continue
                stats["inexact"] += 0 if t["exact"] else 1
                cond = self._merge(inherited, t["cond"])
                if t["verdict"] in ("jump", "goto"):
                    target = (key[0], key[1], t["target"])
                    if target in self.chains and target not in seen and depth < 8:
                        walk(target, hook, cond, depth + 1, seen | {target})
                    continue
                out.append(self._emit(key, rule, hook, cond, t, len(out) + 1))

        for key in self._base_chains():
            walk(key, self.chains[key]["hook"], {}, 0, {key})
        for rule in self.rules.get(("inet", "atrium", "parked"), []):  # Atrium's disabled rules (never jumped to)
            t = self._translate(rule, "inet", "atrium")
            if t is not None and t["verdict"] in ("accept", "drop", "reject"):
                out.append(self._emit(("inet", "atrium", "parked"), rule, "input", t["cond"], t, len(out) + 1, False))
        seen: dict[str, int] = {}
        for rule in out:  # a chain reached from two places is read twice (Atrium's own parts are merged later)
            if KEY_FULL.match(rule["id"]):
                continue
            count = seen[rule["id"]] = seen.get(rule["id"], 0) + 1
            if count > 1:
                rule["id"] = rule["vendor_ref"] = f"{rule['id']}@{count}"
        notes = []
        if stats["stateful"]:
            notes.append(f"{stats['stateful']} return-traffic rules (ct state established/related/invalid) are not "
                         "shown: they never allow a new connection")
        if stats["inexact"]:
            notes.append(f"{stats['inexact']} rules have matches Atrium cannot show; they are shown wider than they are")
        if stats["vmap"]:
            notes.append(f"{stats['vmap']} verdict-map rules are not shown")
        nat = sum(1 for c in self.chains.values() if c.get("type") == "nat")
        if nat:
            notes.append(f"{nat} NAT chains are not evaluated")
        skipped = sorted({k[0] for k in self.chains if k[0] not in ("inet", "ip", "ip6")})
        if skipped:
            notes.append("tables of the families " + ", ".join(display_id(f) for f in skipped) + " are not read")
        if self.compat:
            notes.append("tables managed by iptables-nft (Docker, Kubernetes, iptables tools) are read approximately")
        return out, notes

    def default_policy(self) -> dict[str, str]:
        policy = {}
        for hook, name in (("input", "inbound"), ("forward", "forward"), ("output", "outbound")):
            chains = [self.chains[k] for k in self._base_chains((hook,))]
            policy[name] = "block" if any(c.get("policy") == "drop" for c in chains) else "pass"
        return policy

    def atrium_status(self) -> dict[str, Any]:
        """What changes need: table inet atrium with a base input chain (policy drop), and no other table whose
        input chain drops by default (an accept is not final across base chains)."""
        chain = self.chains.get(("inet", "atrium", "input"))
        others = [k for k in self._base_chains(("input",)) if k[:2] != ("inet", "atrium")]
        return {"table": ("inet", "atrium") in self.tables,
                "input": bool(chain and chain.get("hook") == "input"),
                "policy": str((chain or {}).get("policy") or "accept"),
                "other_drop": sorted({f"{display_id(k[0])} {display_id(k[1])}" for k in others
                                      if self.chains[k].get("policy") == "drop"}),
                "other_rules_drop": sorted({f"{display_id(k[0])} {display_id(k[1])}" for k in others if any(
                    any(isinstance(s, dict) and ("drop" in s or "reject" in s) for s in r.get("expr") or [])
                    for r in self.rules.get(k, []))})}


class AtriumTable:
    """The text of ``nft list table inet atrium`` (one tab per level, one rule per line - nft 1.0.9), edited by
    lines: Atrium adds rules at the top of chain input and moves its own rules between input and parked."""

    def __init__(self, text: str):
        self.lines = (text or "").rstrip("\n").split("\n")
        if not self.lines or self.lines[0].strip() != "table inet atrium {" or self.lines[-1] != "}":
            raise ValueError("not the listing of table inet atrium")
        if not self._chain("input"):
            raise ValueError("table inet atrium has no chain input")
        if not self._chain("parked"):
            self.lines[-1:] = ["", "\tchain parked {", "\t}", "}"]

    def _chain(self, name: str) -> tuple[int, int] | None:
        """(index of the "chain <name> {" line, index of its closing line)."""
        for index, line in enumerate(self.lines):
            if line == f"\tchain {name} {{":
                end = next((i for i in range(index + 1, len(self.lines)) if self.lines[i] == "\t}"), None)
                return (index, end) if end is not None else None
        return None

    def _rules(self, name: str) -> tuple[int, list[int]]:
        """(index where rules start, indexes of the rule lines) of a chain; spec lines (type/policy/comment) skipped."""
        start, end = self._chain(name) or (0, 0)
        first = start + 1
        while first < end and re.match(r"^\t\t(type |policy |comment |devices |flags )", self.lines[first]):
            first += 1
        return first, [i for i in range(first, end) if self.lines[i].startswith("\t\t")]

    def find(self, key: str) -> list[tuple[str, int]]:
        """(chain, line index) of every rule carrying `key` (an allow may be several rules)."""
        pattern = re.compile(r'comment "' + re.escape(key) + r'(?: [^"]*)?"')
        return [(chain, index) for chain in ("input", "parked") for index in self._rules(chain)[1]
                if pattern.search(self.lines[index])]

    def add_top(self, line: str) -> None:
        first, _ = self._rules("input")
        self.lines.insert(first, "\t\t" + line)

    def move(self, key: str, to: str) -> int:
        """Move every rule carrying `key` that is not in chain `to` there (top of input / end of parked)."""
        moving = [index for chain, index in self.find(key) if chain != to]
        lines = [self.lines[i] for i in moving]
        for index in sorted(moving, reverse=True):
            self.lines.pop(index)
        for line in reversed(lines):
            if to == "input":
                self.lines.insert(self._rules("input")[0], line)
            else:
                self.lines.insert(self._chain("parked")[1], line)
        return len(lines)

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def nft_form(op: dict[str, Any], ports: str | None) -> list[str]:
    """Problems with an allow's form on nftables: nft keeps anonymous sets of networks collapsed (adjacent or
    overlapping networks merged) and, once a set holds a range, merges adjacent ports (checked with nft 1.0.9); a
    rule written in another form would read back different from the change and fail verification."""
    problems = []
    for side in ("source", "destination"):
        try:
            collapsed = [str(n) for n in ipaddress.collapse_addresses(ipaddress.ip_network(c) for c in op[side]["cidrs"])]
        except TypeError:  # IPv4 and IPv6 mixed (reported separately)
            continue
        if sorted(collapsed) != sorted(op[side]["cidrs"]):
            problems.append(f"nftables keeps these {side} networks as {', '.join(collapsed)} - use that")
    if ports:
        ranges = sorted(set(port_ranges(ports)))
        if any(lo != hi for lo, hi in ranges):
            merged: list[list[int]] = []
            for lo, hi in ranges:
                if merged and lo <= merged[-1][1] + 1:
                    merged[-1][1] = max(merged[-1][1], hi)
                else:
                    merged.append([lo, hi])
            ranges = [(lo, hi) for lo, hi in merged]
        expected = canonical_ports(ranges)
        if expected != ports:
            problems.append(f"nftables keeps these ports as {expected} - use that")
    return problems


def nft_rule_line(op: dict[str, Any], key: str, proto: str, ports: str | None) -> str:
    """The nft rule an allow becomes (one line of ``table inet atrium``, chain input)."""
    family = "ip" if ipaddress.ip_network(op["source"]["cidrs"][0]).version == 4 else "ip6"

    def group(items: list[str]) -> str:
        return items[0] if len(items) == 1 else "{ " + ", ".join(items) + " }"

    parts = [f'iifname "{op["source"]["zone"]}"', f"{family} saddr {group(op['source']['cidrs'])}",
             f"{family} daddr {group(op['destination']['cidrs'])}"]
    parts.append("meta l4proto icmp" if proto == "icmp" else f"{proto} dport {group((ports or '').split(','))}")
    parts.append("counter")
    if op.get("log", True):
        parts.append(f'log prefix "{key} "')
    parts += ["accept", f'comment "{safe_comment(key, op.get("description") or "")}"']
    return " ".join(parts)


# --------------------------------------------------------------------------------------
# ufw
# --------------------------------------------------------------------------------------

UFW_TUPLE = re.compile(r"^### tuple ### (.+)$")


def parse_ufw_tuples(text: str, v6: bool) -> list[dict[str, Any]]:
    """The ``### tuple ###`` lines of user.rules / user6.rules, in file order."""
    out = []
    for line in (text or "").splitlines():
        match = UFW_TUPLE.match(line.strip())
        if not match:
            continue
        body, comment = match.group(1), ""
        if " comment=" in body:  # comment= is always last (backend_iptables.py)
            body, _, raw = body.partition(" comment=")
            comment = _hex_comment(raw)
        fields = body.split()
        if 6 <= len(fields) <= 9:
            out.append({"body": " ".join(fields), "fields": fields, "comment": comment, "v6": v6})
    return out


def ufw_parts(t: dict[str, Any]) -> dict[str, Any]:
    """A tuple's fields by name (route rules, log type, interfaces split out)."""
    f = t["fields"]
    action = f[0]
    route = action.startswith("route:")
    action = action.split(":", 1)[1] if route else action
    base, _, logtype = action.partition("_")
    direction, iface_in, iface_out = "in", "", ""
    if len(f) in (7, 9):
        last = f[-1]
        direction = last.split("_")[0]
        if "!" in last:
            iface_in, iface_out = last.split("!")[0].partition("_")[2], last.split("!")[1].partition("_")[2]
        elif last.startswith("in_"):
            iface_in = last.partition("_")[2]
        elif last.startswith("out_"):
            iface_out = last.partition("_")[2]
    app = f[6].replace("%20", " ") if len(f) >= 8 and f[6] != "-" else None
    return {"route": route, "action": base, "log": logtype, "proto": f[1], "dport": f[2], "dst": f[3],
            "sport": f[4], "src": f[5], "app": app, "direction": direction, "in": iface_in, "out": iface_out,
            "comment": t["comment"], "v6": t["v6"]}


def _ufw_address(value: str) -> list[str] | None:
    if value in ("0.0.0.0/0", "::/0", "any"):
        return []
    cidr = normalise_cidr(value)
    return [cidr] if cidr else None


def _ufw_services(proto: str, dport: str, app: str | None) -> list[dict[str, Any]] | None:
    ports = None
    if dport != "any":
        ranges = [(int(lo), int(hi or lo)) for lo, _, hi in (p.partition(":") for p in dport.split(","))
                  if lo.isdigit() and (not hi or hi.isdigit())]
        ports = canonical_ports(ranges) if ranges else None
    if proto == "any":
        return [{"proto": p, "ports": ports, "name": app or ""} for p in ("tcp", "udp")] if ports else None
    return [{"proto": proto, "ports": ports, "name": app or ""}]


def ufw_rule(t: dict[str, Any], number: int) -> dict[str, Any] | None:
    p = ufw_parts(t)
    action = {"allow": "pass", "limit": "pass", "deny": "block", "reject": "reject"}.get(p["action"])
    src, dst = _ufw_address(p["src"]), _ufw_address(p["dst"])
    if action is None or src is None or dst is None:
        return None
    if p["route"]:
        source, destination, direction = _endpoint(src), _endpoint(dst), "in"
    elif p["direction"] == "out":
        source, destination, direction = _endpoint(src, default="self"), _endpoint(dst), "out"
    else:
        source, destination, direction = _endpoint(src), _endpoint(dst, default="self"), "in"
    rid = _key(p["comment"]) or f"ufw/{'v6' if p['v6'] else 'v4'}/{_short_hash(t['body'])}"
    description = p["comment"] or (f"app {p['app']}" if p["app"] else "")
    if p["action"] == "limit":
        description = (description + " (rate limited)").strip()
    return _rule(rid, f"{number}|{t['body']}", number, action, interfaces=[p["in"]] if p["in"] else [],
                 out_interfaces=[p["out"]] if p["out"] else [], direction=direction, source=source,
                 destination=destination, services=_ufw_services(p["proto"], p["dport"], p["app"]),
                 log=p["log"] in ("log", "log-all"), description=description)


def ufw_fields(p: dict[str, Any], key: str) -> list[str] | None:
    """The wrapper's fields for an Atrium ufw rule (iface log proto src dst ports comment), or None when the rule is
    not one Atrium could have written."""
    fields = [key, p["in"], "1" if p["log"] == "log" else "0", p["proto"], p["src"], p["dst"], p["dport"],
              p["comment"]]
    if (p["route"] or p["action"] != "allow" or p["direction"] != "in" or p["out"] or p["app"] or p["sport"] != "any"
            or not IFNAME_RE.match(p["in"]) or p["proto"] not in ("tcp", "udp")
            or not re.fullmatch(r"[0-9]{1,5}([,:][0-9]{1,5}){0,29}", p["dport"]) or _key(p["comment"]) != key
            or COMMENT_DROP.search(p["comment"]) or any(_ufw_address(a) in (None, []) for a in (p["src"], p["dst"]))):
        return None
    return fields


def parse_ufw_defaults(text: str) -> dict[str, str]:
    """/etc/default/ufw DEFAULT_*_POLICY -> {"inbound", "outbound", "forward"}."""
    policy = {}
    for line in (text or "").splitlines():
        match = re.match(r'^DEFAULT_(INPUT|OUTPUT|FORWARD)_POLICY="?([A-Z]+)"?', line.strip())
        if match:
            name = {"INPUT": "inbound", "OUTPUT": "outbound", "FORWARD": "forward"}[match.group(1)]
            policy[name] = {"ACCEPT": "pass", "DROP": "block", "REJECT": "reject"}.get(match.group(2), "unknown")
    return policy


def parse_parked(text: str) -> list[dict[str, Any]]:
    """The wrapper's registry of disabled Atrium rules (ufw and firewalld): tab-separated lines."""
    out = []
    for line in (text or "").splitlines():
        parts = line.split("\t")
        if len(parts) == 9 and parts[0] == "ufw" and KEY_FULL.match(parts[1]):
            out.append({"manager": "ufw", "key": parts[1], "fields": parts[1:]})
        elif len(parts) == 4 and parts[0] == "firewalld" and KEY_FULL.match(parts[1]) and ZONE_RE.match(parts[2]):
            out.append({"manager": "firewalld", "key": parts[1], "zone": parts[2], "rule": parts[3]})
    return out


def ufw_parked_rule(entry: dict[str, Any], order: int) -> dict[str, Any] | None:
    key, iface, log, proto, src, dst, ports, comment = entry["fields"]
    t = {"fields": [f"allow{'_log' if log == '1' else ''}", proto, ports, dst, "any", src, f"in_{iface}"],
         "comment": comment, "v6": ":" in src, "body": ""}
    rule = ufw_rule(t, order)
    if rule is not None:
        rule.update(id=key, vendor_ref=key, enabled=False)
    return rule


# --------------------------------------------------------------------------------------
# firewalld
# --------------------------------------------------------------------------------------

RICH_TOKEN = re.compile(r'\s*([A-Za-z][A-Za-z0-9_-]*)(?:="([^"]*)"|=(\S+))?')
RICH_ELEMENTS = ("service", "port", "protocol", "icmp-block", "icmp-type", "masquerade", "forward-port",
                 "source-port", "tcp-mss-clamp")


def parse_fw_listing(text: str) -> list[dict[str, Any]]:
    """``firewall-cmd --list-all-zones`` / ``--list-all-policies``: blocks of "name (attrs)" and "  key: value"
    lines; rich rules and forward ports continue on tab-indented lines (command.py print_zone_policy_info)."""
    blocks: list[dict[str, Any]] = []
    current, key = None, None
    for raw in (text or "").splitlines():
        if not raw.strip():
            continue
        if not raw[0].isspace():
            match = re.match(r"^(\S+)(?:\s+\(([^)]*)\))?\s*$", raw)
            current, key = None, None
            if match and ZONE_RE.match(match.group(1)):
                current = {"name": match.group(1), "fields": {}, "rich": [], "forward_ports": [],
                           "attrs": {a.strip() for a in (match.group(2) or "").split(",") if a.strip()}}
                blocks.append(current)
            continue
        if current is None:
            continue
        if raw.startswith("\t") or raw.startswith("    "):
            if key == "rich rules":
                current["rich"].append(raw.strip())
            elif key == "forward-ports":
                current["forward_ports"].append(raw.strip())
            continue
        name, sep, value = raw.strip().partition(":")
        if sep:
            key = name.strip()
            current["fields"][key] = value.strip()
    return blocks


def parse_rich_rule(text: str) -> dict[str, Any] | None:
    """A rich rule as firewalld renders it (rich.py Rich_Rule.__str__); None when it cannot be read."""
    tokens, pos = [], 0
    text = text.strip()
    while pos < len(text):
        match = RICH_TOKEN.match(text, pos)
        if not match or match.end() == pos:
            return None
        tokens.append((match.group(1), match.group(2) if match.group(2) is not None else match.group(3)))
        pos = match.end()
        while pos < len(text) and text[pos].isspace():
            pos += 1
    if not tokens or tokens[0] != ("rule", None):
        return None
    rule: dict[str, Any] = {"priority": 0, "family": None, "source": None, "destination": None, "element": None,
                            "log": None, "action": None, "text": text}
    i = 1
    while i < len(tokens):
        name, value = tokens[i]
        if name in ("priority", "family") and value is not None:
            if name == "priority":
                try:
                    rule["priority"] = int(value)
                except ValueError:
                    return None
            else:
                rule["family"] = value
            i += 1
        elif name in ("source", "destination") and value is None:
            i += 1
            negate = i < len(tokens) and tokens[i] in (("NOT", None), ("not", None))
            i += 1 if negate else 0
            if i >= len(tokens) or tokens[i][1] is None:
                return None
            rule[name] = {"kind": tokens[i][0], "value": tokens[i][1], "negate": negate}
            i += 1
        elif name in RICH_ELEMENTS and value is None:
            element: dict[str, Any] = {"type": name}
            i += 1
            while i < len(tokens) and tokens[i][1] is not None and tokens[i][0] in ("name", "port", "protocol",
                                                                                     "value", "to-port", "to-addr"):
                element[tokens[i][0]] = tokens[i][1]
                i += 1
            rule["element"] = element
        elif name in ("log", "nflog", "audit") and value is None:
            entry: dict[str, Any] = {}
            i += 1
            while i < len(tokens) and (tokens[i][1] is not None or tokens[i][0] == "limit"):
                if tokens[i][0] != "limit":
                    entry[tokens[i][0]] = tokens[i][1]
                i += 1
            if name == "log":
                rule["log"] = entry
        elif name in ("accept", "reject", "drop", "mark") and value is None:
            rule["action"] = name
            i += 1
            while i < len(tokens) and (tokens[i][1] is not None or tokens[i][0] == "limit"):
                i += 1
        else:
            return None
    return rule


def parse_services(text: str) -> dict[str, list[tuple[str, str | None]]]:
    """firewalld service definitions (``### atrium-service <file>`` sections of XML), includes resolved."""
    raw: dict[str, tuple[list[tuple[str, str | None]], list[str]]] = {}
    for section in (text or "").split("### atrium-service ")[1:]:
        name, _, body = section.partition("\n")
        name = name.strip().removesuffix(".xml")
        if not NAME_RE.match(name):
            continue
        try:
            root = parse_untrusted_xml(body.strip())
        except (UnsafeXml, ET.ParseError):  # a service file with a DOCTYPE or entities is skipped
            continue
        ports: list[tuple[str, str | None]] = []
        for el in root.findall("port"):
            proto, port = str(el.get("protocol") or "").lower(), str(el.get("port") or "")
            if proto and re.fullmatch(r"\d{1,5}(-\d{1,5})?", port):
                ports.append((proto, port))
        ports += [(str(el.get("value") or "").lower(), None) for el in root.findall("protocol") if el.get("value")]
        raw[name] = (ports, [str(el.get("service") or "") for el in root.findall("include")])

    def resolve(name: str, depth: int = 0) -> list[tuple[str, str | None]]:
        if name not in raw or depth > 4:
            return list(FIREWALLD_SERVICES.get(name, []))
        ports, includes = raw[name]
        return ports + [p for inc in includes for p in resolve(inc, depth + 1)]

    return {name: resolve(name) for name in raw}


def _rich_endpoint(part: dict[str, Any] | None) -> tuple[dict[str, Any] | None, bool]:
    """(endpoint, exact) of a rich rule's source / destination (None: not given)."""
    if part is None:
        return None, True
    if part["kind"] == "address":
        cidr = normalise_cidr(part["value"])
        return (_endpoint([cidr], negate=part["negate"]), True) if cidr else (None, False)
    if part["kind"] == "ipset" and NAME_RE.match(part["value"] or ""):
        return _endpoint(aliases=[f"ipset:{part['value']}"], negate=part["negate"]), True
    return {"any": True}, False


def _services_of(name: str, services: dict[str, list[tuple[str, str | None]]]) -> list[dict[str, Any]] | None:
    known = services.get(name) or FIREWALLD_SERVICES.get(name)
    if not known:
        return [{"proto": "any", "alias": f"service:{name}", "name": name}]
    return [{"proto": proto, "ports": port.replace(":", "-") if port else None, "name": name} for proto, port in known]


def firewalld_rules(zone: dict[str, Any], services: dict[str, list[tuple[str, str | None]]], start: int,
                    policy: bool = False) -> tuple[list[dict[str, Any]], int]:
    """A zone's (or policy's) settings as rules, in firewalld's order: rich rules with priority < 0, deny rich rules,
    services / ports / protocols / ICMP and accept rich rules, rich rules with priority > 0, then the target."""
    fields, name = zone["fields"], zone["name"]
    prefix = f"policy/{name}" if policy else name
    extra: dict[str, Any] = {}
    if policy:
        ingress = fields.get("ingress-zones", "").split()
        egress = fields.get("egress-zones", "").split()
        extra["source_zones"] = [z for z in ingress if z not in ("ANY", "HOST")]
        extra["destination_zones"] = [z for z in egress if z not in ("ANY", "HOST")]
        default_source = _endpoint(default="self") if "HOST" in ingress else {"any": True}
        default_destination = _endpoint(default="self") if "HOST" in egress else {"any": True}
    else:
        interfaces = fields.get("interfaces", "").split()
        sources = fields.get("sources", "").split()
        cidrs = [c for c in (normalise_cidr(s) for s in sources) if c]
        if sources and not interfaces:  # bound by source address
            default_source = _endpoint(cidrs) if len(cidrs) == len(sources) else {"any": True}
        else:
            default_source = {"any": True}
            extra["interfaces"] = interfaces if not sources else []
        default_destination = _endpoint(default="self")
    pre, deny, allow, post = [], [], [], []
    for text in zone["rich"]:
        rich = parse_rich_rule(text)
        action = {"accept": "pass", "reject": "reject", "drop": "block"}.get((rich or {}).get("action"))
        element = (rich or {}).get("element") or {}
        if rich is None or action is None or element.get("type") in ("masquerade", "forward-port", "icmp-block",
                                                                       "tcp-mss-clamp"):
            continue
        source, ok_s = _rich_endpoint(rich["source"])
        destination, ok_d = _rich_endpoint(rich["destination"])
        kind = element.get("type")
        if kind == "service":
            rule_services = _services_of(element.get("name") or "", services)
        elif kind == "port" and re.fullmatch(r"\d{1,5}(-\d{1,5})?", element.get("port") or ""):
            rule_services = [{"proto": element.get("protocol") or "tcp", "ports": element["port"]}]
        elif kind == "protocol":
            rule_services = [{"proto": element.get("value") or "any"}]
        elif kind == "icmp-type":
            rule_services = [{"proto": "icmp"}]
        else:
            rule_services = None
        log = rich.get("log")
        key = _key((log or {}).get("prefix"))
        rid = key or f"{prefix}/rich/{_short_hash(text)}"
        rule = _rule(rid, key or f"{name}|{text}", 0, action, source=source or default_source,
                     destination=destination or default_destination, services=rule_services, log=log is not None,
                     description=((log or {}).get("prefix") or "").strip(), **extra)
        rule["_rich"] = text
        if not (ok_s and ok_d):
            rule["_inexact"] = 1
        bucket = pre if rich["priority"] < 0 else post if rich["priority"] > 0 else deny if action != "pass" else allow
        bucket.append((rich["priority"], rule))
    plain = []
    for service in fields.get("services", "").split():
        plain.append(_rule(f"{prefix}/service/{service}", f"{name}|service={service}", 0, "pass",
                           source=default_source, destination=default_destination,
                           services=_services_of(service, services), description=f"service {service}", **extra))
    for port in fields.get("ports", "").split():
        number, _, proto = port.partition("/")
        if re.fullmatch(r"\d{1,5}(-\d{1,5})?", number) and proto:
            plain.append(_rule(f"{prefix}/port/{number}-{proto}", f"{name}|port={port}", 0, "pass",
                               source=default_source, destination=default_destination,
                               services=[{"proto": proto, "ports": number}], description=f"port {port}", **extra))
    for proto in fields.get("protocols", "").split():
        plain.append(_rule(f"{prefix}/protocol/{proto}", f"{name}|protocol={proto}", 0, "pass", source=default_source,
                           destination=default_destination, services=[{"proto": proto}],
                           description=f"protocol {proto}", **extra))
    if not policy and fields.get("icmp-block-inversion", "no") == "no" and not fields.get("icmp-blocks"):
        plain.append(_rule(f"{prefix}/icmp", f"{name}|icmp", 0, "pass", source=default_source,
                           destination=default_destination, services=[{"proto": "icmp"}, {"proto": "icmpv6"}],
                           description="ICMP (firewalld allows it unless blocked)", **extra))
    ordered = ([r for _, r in sorted(pre, key=lambda x: x[0])] + [r for _, r in deny] + plain + [r for _, r in allow]
               + [r for _, r in sorted(post, key=lambda x: x[0])])
    target = fields.get("target", "default").upper()
    if target == "ACCEPT":
        ordered.append(_rule(f"{prefix}/target", f"{name}|target", 0, "pass", source=default_source,
                             destination=default_destination, description="target ACCEPT: everything else is allowed",
                             **extra))
    elif policy and target in ("DROP", "REJECT", "%%REJECT%%"):
        ordered.append(_rule(f"{prefix}/target", f"{name}|target", 0, "reject" if "REJECT" in target else "block",
                             source=default_source, destination=default_destination,
                             description=f"target {target.strip('%')}", **extra))
    for rule in ordered:
        start += 1
        rule["order"] = start
    return ordered, start


def rich_rule_text(op: dict[str, Any], key: str, proto: str, ports: str | None) -> str:
    """The rich rule an allow becomes, rendered the way firewalld lists it (rich.py)."""
    family = "ipv4" if ipaddress.ip_network(op["source"]["cidrs"][0]).version == 4 else "ipv6"
    element = 'protocol value="icmp"' if proto == "icmp" else f'port port="{ports}" protocol="{proto}"'
    return (f'rule priority="-1" family="{family}" source address="{op["source"]["cidrs"][0]}" destination address='
            f'"{op["destination"]["cidrs"][0]}" {element} log prefix="{key} " level="info" accept')


def firewalld_parked_rule(entry: dict[str, Any], order: int) -> dict[str, Any] | None:
    zone = {"name": entry["zone"], "fields": {"icmp-block-inversion": "yes"}, "rich": [entry["rule"]]}
    rules, _ = firewalld_rules(zone, {}, order - 1)
    if not rules:
        return None
    rules[0].update(id=entry["key"], vendor_ref=entry["key"], enabled=False, interfaces=[])
    return rules[0]


# --------------------------------------------------------------------------------------
# the connector
# --------------------------------------------------------------------------------------


class HostFirewallConnector(Connector):
    kind = "hostfw"
    title = "Linux host firewall (nftables, ufw, firewalld)"
    description = ("Reads a Linux host's firewall (nftables, ufw or firewalld), interfaces and listening ports over SSH "
                   "into the Network app. With device changes enabled and the atrium-fw wrapper installed, adds one "
                   "allow rule or disables rules Atrium created, under a dead-man timer on the host.")
    fields = [
        *ssh_fields(default_user="atrium"),
        ConnectorField(name="manager", label="Firewall", kind="select", default="auto", choices=[
            {"value": "auto", "label": "Detect (firewalld, then ufw, then nftables)"},
            {"value": "nftables", "label": "nftables"}, {"value": "ufw", "label": "ufw"},
            {"value": "firewalld", "label": "firewalld"}]),
        ConnectorField(name="wrapper", label="Change wrapper", default=WRAPPER,
                       help="Path of atrium-fw on the host (python -m hub.connectors.hostfw wrapper prints it)."),
        ConnectorField(name="rollback_window_s", label="Automatic revert after (seconds)", kind="number",
                       default=WINDOW, help="A change reverts by itself unless Atrium confirms it in time (60-600)."),
        ConnectorField(name="read_only", label="Read only", kind="bool", default=False,
                       help="Never change this host through this connection, even with device changes on; the change "
                            "wrapper is then never called (set it for a read-only account)."),
    ]
    capabilities = {"network": {"read"}}
    network_write = {"ops": OPS, "rollback": "deadman", "window_s": WINDOW}
    clock: Callable[[], float] = staticmethod(time.time)

    @classmethod
    def detect(cls, tool) -> int:
        return cls.name_score(tool, ("nftables", "ufw", "firewalld", "host firewall", "hostfw", "iptables"))

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        try:
            config = validate_ssh_config(config)
        except ValueError as exc:
            raise ConnectorError(str(exc)) from exc
        if str(config.get("manager") or "auto") not in MANAGERS:
            raise ConnectorError("Firewall: auto, nftables, ufw or firewalld")
        wrapper = str(config.get("wrapper") or WRAPPER)
        if not PATH_RE.match(wrapper) or ".." in wrapper:
            raise ConnectorError("Change wrapper must be an absolute path such as /usr/local/sbin/atrium-fw")
        window = int(config.get("rollback_window_s") or WINDOW)
        if not WINDOW_BOUNDS[0] <= window <= WINDOW_BOUNDS[1]:
            raise ConnectorError(f"The automatic revert window is {WINDOW_BOUNDS[0]}-{WINDOW_BOUNDS[1]} seconds")
        return {**config, "manager": str(config.get("manager") or "auto"), "wrapper": wrapper,
                "rollback_window_s": window}

    @property
    def window(self) -> int:
        return int(self.config.get("rollback_window_s") or WINDOW)

    @property
    def wrapper(self) -> str:
        return str(self.config.get("wrapper") or WRAPPER)

    def write_capability(self) -> dict[str, Any] | None:
        if self.config.get("read_only"):
            return None
        spec = super().write_capability()
        return {**spec, "window_s": self.window} if spec else None

    # -- SSH ---------------------------------------------------------------------------------

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
            raise SshUnavailable(self.redact(f"Host over SSH: {exc}")) from exc

    async def _exec(self, session: Any, command: str, *, what: str, input: str | None = None) -> SshResult:
        try:
            result = await session.run(command, input=input)
        except SshError as exc:
            raise SshUnavailable(self.redact(f"Host over SSH ({what}): {exc}")) from exc
        if result.truncated:
            raise self.error(f"The host's answer was larger than the read limit ({what}) - refusing a partial read")
        return result

    async def _run(self, session: Any, command: str, *, what: str, input: str | None = None,
                   ok_codes: tuple[int, ...] = (0,)) -> SshResult:
        result = await self._exec(session, command, what=what, input=input)
        if result.timed_out or result.exit_status not in ok_codes:
            if result.stderr.lstrip().startswith("sudo:"):
                raise SudoRefused(self.error(f"sudo -n refused to {what} - add the sudoers lines from "
                                             "docs/NETWORK.md (Atrium never stores a sudo password)").message)
            raise self.error(f"The host could not {what} (exit status {result.exit_status}"
                             + (", timed out" if result.timed_out else "") + ")"
                             + (f": {untrusted_text(result.stderr, 160)}" if result.stderr.strip() else ""))
        return result

    async def _sudo(self, session: Any, path: str, *args: str, what: str, input: str | None = None,
                    ok_codes: tuple[int, ...] = (0,)) -> SshResult:
        return await self._run(session, posix_command(["sudo", "-n", path, *args]), what=what, input=input,
                               ok_codes=ok_codes)

    async def _wrapper(self, session: Any, *args: str, what: str, input: str | None = None) -> SshResult:
        """The wrapper's answer (any exit status); SudoRefused when sudo does not allow it."""
        result = await self._exec(session, posix_command(["sudo", "-n", self.wrapper, *args]), what=what, input=input)
        if result.exit_status != 0 and result.stderr.lstrip().startswith("sudo:"):
            missing = "not found" in result.stderr
            raise SudoRefused(self.error(
                f"{self.wrapper} is not installed (python -m hub.connectors.hostfw wrapper prints it)" if missing else
                f"sudo does not allow {self.wrapper} (read-only account; the ATRIUM_FW_WRITE sudoers line adds "
                "changes)").message)
        return result

    # -- reading -------------------------------------------------------------------------------

    async def probe(self, session: Any) -> dict[str, Any]:
        facts = parse_probe((await self._run(session, "/bin/sh -s", what="read the host facts", input=PROBE)).stdout)
        configured = str(self.config.get("manager") or "auto")
        paths = facts["paths"]
        if configured != "auto":
            manager = configured
        elif facts.get("firewalld") == "active" and "firewall-cmd" in paths:
            manager = "firewalld"
        elif facts.get("ufw.ENABLED", "").lower() == "yes" and "ufw" in paths:
            manager = "ufw"
        elif "nft" in paths:
            manager = "nftables"
        else:
            manager = "none"
        tool = {"nftables": "nft", "ufw": "ufw", "firewalld": "firewall-cmd"}.get(manager)
        if tool and tool not in paths:
            raise self.error(f"{manager} is selected but {tool} was not found on the host")
        facts["manager"] = manager
        return facts

    async def _network(self, session: Any, facts: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
        ip, notes = facts["paths"].get("ip"), []
        if not ip:
            return [], ["ip (iproute2) was not found: interfaces are unknown"]
        try:
            routes = json.loads((await self._run(session, posix_command([ip, "-j", "route", "show", "default"]),
                                                 what="read the default route")).stdout or "[]")
            links = json.loads((await self._run(session, posix_command([ip, "-j", "-d", "addr", "show"]),
                                                what="read the interfaces")).stdout or "[]")
        except ValueError as exc:
            raise self.error("ip -j did not print JSON - iproute2 is too old (needs JSON output)") from exc
        interfaces = parse_ip_addr(links, parse_default_devs(routes))
        if facts["paths"].get("ss"):
            listening = parse_ss((await self._exec(session, posix_command([facts["paths"]["ss"], "-H", "-tuln"]),
                                                   what="read the listening ports")).stdout)
            if listening["all"]:
                notes.append("listening on every address: " + ", ".join(listening["all"][:40]))
            if listening["specific"]:
                notes.append("listening on specific addresses: " + ", ".join(listening["specific"][:40]))
        return interfaces, notes

    async def read(self, session: Any, facts: dict[str, Any] | None = None) -> dict[str, Any]:
        """The host read in one session: facts, interfaces, the manager's rules (Atrium's parked rules included)."""
        facts = facts or await self.probe(session)
        interfaces, notes = await self._network(session, facts)
        state: dict[str, Any] = {"facts": facts, "manager": facts["manager"], "interfaces": interfaces, "zones": [],
                                 "aliases": [], "rules": [], "default_policy": {}, "notes": notes,
                                 "manager_version": "", "read_at": self.clock()}
        reader = {"nftables": self._read_nft, "ufw": self._read_ufw, "firewalld": self._read_firewalld}.get(
            state["manager"])
        if reader is None:
            state["notes"].append("no supported firewall manager was found (firewalld, ufw or nftables): legacy "
                                  "iptables is not read")
            state["revision"] = derived_revision("none")
        else:
            await reader(session, state)
        state["rules"], state["parts"] = merge_parts(state["rules"])
        if facts.get("docker") == "yes":
            state["notes"].append("Docker is installed: ports it publishes bypass ufw and firewalld rules")
        return state

    async def _read_nft(self, session: Any, state: dict[str, Any]) -> None:
        nft = state["facts"]["paths"]["nft"]
        try:
            data = (await self._sudo(session, nft, "-j", "list", "ruleset", what="list the nftables ruleset")).json()
            ruleset = NftRuleset(data)
        except (SshError, ValueError) as exc:
            raise self.error(f"nft -j list ruleset could not be read ({exc}) - nft versions before 1.0 may fail on "
                             "tables managed by iptables-nft") from exc
        rules, notes = ruleset.read_rules()
        state.update(rules=rules, aliases=ruleset.aliases(), default_policy=ruleset.default_policy(),
                     manager_version=ruleset.version, revision=ruleset.revision, nft=ruleset)
        state["notes"] += notes

    async def _read_ufw(self, session: Any, state: dict[str, Any]) -> None:
        ufw = state["facts"]["paths"]["ufw"]
        status = (await self._sudo(session, ufw, "status", "verbose", what="read ufw's status")).stdout
        version = (await self._sudo(session, ufw, "version", what="read ufw's version")).stdout
        files = {}
        for name in ("user.rules", "user6.rules"):
            files[name] = (await self._run(session, posix_command(["sudo", "-n", "cat", f"/etc/ufw/{name}"]),
                                           what=f"read /etc/ufw/{name}")).stdout
        defaults = (await self._run(session, "cat /etc/default/ufw", what="read /etc/default/ufw",
                                    ok_codes=(0, 1))).stdout
        tuples = parse_ufw_tuples(files["user.rules"], False) + parse_ufw_tuples(files["user6.rules"], True)
        rules = [r for r in (ufw_rule(t, n) for n, t in enumerate(tuples, 1)) if r is not None]
        parked = await self._parked(session, state, "ufw")
        rules += [r for r in (ufw_parked_rule(p, len(tuples) + n) for n, p in enumerate(parked, 1)) if r]
        first = status.strip().splitlines()[0] if status.strip() else ""
        active = first == "Status: active"
        if not active:
            state["notes"].append("ufw reports it is not active: its rules are not enforced" if first ==
                                  "Status: inactive" else "ufw's status could not be read (translated output?)")
        if len(rules) < len(tuples) + len(parked):
            state["notes"].append(f"{len(tuples) + len(parked) - len(rules)} ufw rules could not be read")
        state["notes"].append("rules in /etc/ufw/before.rules and after.rules are not shown (ufw status does not "
                              "show them either)")
        match = re.search(r"\bufw (\d+(?:\.\d+)+)", version)
        state.update(rules=rules, default_policy=parse_ufw_defaults(defaults) if active else {"inbound": "pass"},
                     manager_version=match.group(1) if match else "", ufw_active=active, ufw_tuples=tuples,
                     revision=derived_revision("ufw", files, defaults, [p["fields"] for p in parked]))

    async def _read_firewalld(self, session: Any, state: dict[str, Any]) -> None:
        fc = state["facts"]["paths"]["firewall-cmd"]
        running = (await self._sudo(session, fc, "--state", what="read firewalld's state", ok_codes=(0, 252))).stdout
        if running.strip() != "running":
            state["notes"].append("firewalld is not running")
        version = (await self._sudo(session, fc, "--version", what="read firewalld's version")).stdout.strip()
        zones_text = (await self._sudo(session, fc, "--list-all-zones", what="list firewalld's zones")).stdout
        permanent = (await self._sudo(session, fc, "--permanent", "--list-all-zones",
                                      what="list firewalld's permanent zones")).stdout
        try:
            policies_text = (await self._sudo(session, fc, "--list-all-policies", what="list firewalld's policies")).stdout
        except SudoRefused:
            raise
        except ConnectorError:  # firewalld before 0.9 has no policies
            policies_text = ""
        services = parse_services((await self._exec(session, "/bin/sh -s", what="read firewalld's services",
                                                    input=SERVICES)).stdout)
        zones = parse_fw_listing(zones_text)
        active = [z for z in zones if "active" in z["attrs"]]
        default = next((z["name"] for z in zones if "default" in z["attrs"]), "")
        rules: list[dict[str, Any]] = []
        order = 0
        policies = [p for p in parse_fw_listing(policies_text) if p["fields"].get("disable", "no") != "yes"]
        early = [p for p in policies if _int(p["fields"].get("priority"), -1) < 0]
        for policy in early:
            more, order = firewalld_rules(policy, services, order, policy=True)
            rules += more
        for zone in active:
            more, order = firewalld_rules(zone, services, order)
            rules += more
        for policy in policies:
            if policy not in early:
                more, order = firewalld_rules(policy, services, order, policy=True)
                rules += more
        parked = await self._parked(session, state, "firewalld")
        rules += [r for r in (firewalld_parked_rule(p, order + n) for n, p in enumerate(parked, 1)) if r]
        inexact = sum(1 for r in rules if r.pop("_inexact", 0))
        for rule in rules:
            rule.pop("_rich", None)
        default_zone = next((z for z in zones if z["name"] == default), None)
        target = ((default_zone or {}).get("fields") or {}).get("target", "default").upper()
        notes = [f"zone {z['name']}: target {z['fields'].get('target', 'default')}" for z in active
                 if z["fields"].get("target", "default") not in ("default", "%%REJECT%%")]
        if permanent and self._zone_settings(permanent) != self._zone_settings(zones_text):
            notes.append("the runtime configuration differs from the permanent one (unsaved runtime changes, or an "
                         "Atrium change waiting for confirmation)")
        if any(z["fields"].get("masquerade") == "yes" or z["forward_ports"]
               or any(re.search(r"\b(masquerade|forward-port)\b", r) for r in z["rich"]) for z in zones):
            notes.append("NAT (masquerade, forward ports) is not evaluated")
        if inexact:
            notes.append(f"{inexact} rich rules use MAC sources or similar matches Atrium cannot show exactly")
        if len(zones) > len(active):
            notes.append(f"{len(zones) - len(active)} inactive zones are not shown")
        state["notes"] += notes
        state.update(rules=rules, zones=[{"id": z["name"], "name": z["name"],
                                          "interfaces": z["fields"].get("interfaces", "").split(),
                                          "description": "default zone" if z["name"] == default else ""} for z in active],
                     default_policy={"inbound": "pass" if target == "ACCEPT" else "block"},
                     manager_version=untrusted_text(version, 40), fw_zones=zones, fw_running=running.strip() == "running",
                     revision=derived_revision("firewalld", zones_text, policies_text,
                                               [[p["zone"], p["rule"]] for p in parked]))

    @staticmethod
    def _zone_settings(text: str) -> list[Any]:
        """A listing without the runtime-only "active" marks (to compare runtime and permanent)."""
        return [[z["name"], sorted((k, v) for k, v in z["fields"].items() if k != "interfaces"), sorted(z["rich"])]
                for z in parse_fw_listing(text)]

    async def _parked(self, session: Any, state: dict[str, Any], manager: str) -> list[dict[str, Any]]:
        """Atrium's disabled rules from the wrapper's registry (empty when the wrapper is not allowed; never asked on
        a read-only connection, so a read-only account does not log a refused sudo on every read)."""
        if self.config.get("read_only"):
            state["parked_readable"] = False
            state.setdefault("parked_entries", {})[manager] = []
            return []
        try:
            result = await self._wrapper(session, "parked", what="read Atrium's disabled rules")
        except SudoRefused:
            state["parked_readable"] = False
            return []
        state["parked_readable"] = result.ok
        entries = [p for p in parse_parked(result.stdout) if p["manager"] == manager] if result.ok else []
        state.setdefault("parked_entries", {})[manager] = entries
        return entries

    def to_record(self, state: dict[str, Any]) -> dict[str, Any]:
        facts = state["facts"]
        host = str(self.config.get("host") or "")
        os_name = facts["os"].get("PRETTY_NAME") or " ".join(filter(None, (facts["os"].get("ID"),
                                                                            facts["os"].get("VERSION_ID"))))
        connection = facts.get("ssh") or {}
        management = connection.get("server_ip") or host
        manager = {"nftables": "nftables", "ufw": "ufw", "firewalld": "firewalld"}.get(state["manager"], "no manager")
        return {"external_id": facts.get("host") or host, "revision": state["revision"], "read_at": state["read_at"],
                "kind": "host",
                "device": {"vendor": "Linux", "model": os_name, "hostname": facts.get("host") or host,
                           "version": " ".join(filter(None, (manager, state["manager_version"])))
                           + (f", kernel {facts['kernel']}" if facts.get("kernel") else ""),
                           "management_address": management, "serial": ""},
                "interfaces": state["interfaces"], "zones": state["zones"], "aliases": state["aliases"],
                "self_addresses": [a for i in state["interfaces"] for a in i["addresses"]],
                "rules": state["rules"], "default_policy": state["default_policy"], "nat_evaluated": False,
                "notes": state["notes"]}

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        if domain != "network":
            raise self.error(f"A host firewall cannot read {domain}")
        async with self.session() as session:
            state = await self.read(session)
        return [self.to_record(state)]

    # -- test ------------------------------------------------------------------------------------

    def _result(self, checks: list[dict[str, Any]], ok: bool, detail: str,
                write: dict[str, Any] | None = None) -> dict[str, Any]:
        return {"ok": ok, "detail": detail, "checks": checks, "domains": self.domains() if ok else {},
                "network_write": write if ok else None}

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
                return await self._test_session(session, checks)
        except ConnectorError as exc:
            if checks:  # failed after signing in
                name = "privileges" if isinstance(exc, SudoRefused) else "ruleset"
                checks.append(check(name, False, exc.message))
                return self._result(checks, False, exc.message)
            text = exc.message.lower()
            if "host key" in text or "known_hosts" in text:
                checks += [check("reachability", True, f"SSH answers on {where}"), check("tls", False, exc.message)]
            elif "authentication" in text or "private key" in text or "password" in text:
                checks += [check("reachability", True, f"SSH answers on {where}"), check("tls", True, pinned),
                           check("authentication", False, exc.message + " (repeated failures can make sshd's "
                                                                        "PerSourcePenalties block the hub for a while)")]
            else:
                checks.append(check("reachability", False, exc.message))
            return self._result(checks, False, exc.message)

    async def writes(self, session: Any, state: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str], dict[str, Any]]:
        """(write capability, why not, wrapper facts) for this host and connection."""
        reasons: list[str] = []
        info: dict[str, Any] = {}
        if self.config.get("read_only"):
            return None, ["this connection is set to read only"], info
        try:
            answer = await self._wrapper(session, "check", what="check the change wrapper")
            info = dict(line.split("=", 1) for line in answer.stdout.splitlines() if "=" in line) if answer.ok else {}
            if not answer.ok:
                reasons.append(f"{self.wrapper} is not installed or does not run")
        except SudoRefused as exc:
            reasons.append(exc.message)
        if info and info.get("version") != WRAPPER_VERSION:
            reasons.append(f"{self.wrapper} is version {display_id(info.get('version'))}, Atrium needs "
                           f"{WRAPPER_VERSION}: install it again")
        if info and info.get("systemd_run") != "yes":
            reasons.append("systemd-run is not available: there is no dead-man timer")
        manager = state["manager"]
        if manager == "none":
            reasons.append("no supported firewall manager")
        elif manager == "nftables":
            status = state["nft"].atrium_status()
            if not (status["table"] and status["input"]):
                reasons.append("table inet atrium with an input chain does not exist (python -m hub.connectors.hostfw "
                               "nft-table prints a starting point)")
            elif status["policy"] != "drop":
                reasons.append("table inet atrium's input chain accepts by default, so an allow there changes nothing")
        elif manager == "ufw":
            version = tuple(int(x) for x in re.findall(r"\d+", state["manager_version"])[:2]) or (0,)
            if not state.get("ufw_active"):
                reasons.append("ufw is not active")
            if version < (0, 35):
                reasons.append("ufw before 0.35 has no 'prepend'")  # UNVERIFIED: the version prepend appeared in
        elif manager == "firewalld" and not state.get("fw_running"):
            reasons.append("firewalld is not running")
        write = None if reasons else {"ops": OPS, "rollback": "deadman", "window_s": self.window}
        if write is not None and self.write_capability() is None:
            write = None
        return write, reasons, info

    async def _test_session(self, session: Any, checks: list[dict[str, Any]]) -> dict[str, Any]:
        facts = await self.probe(session)
        state = await self.read(session, facts)
        record = normalize_record(self.to_record(state))
        write, reasons, info = await self.writes(session, state)
        root = facts.get("uid") == "0"
        if root:
            privilege = ("signed in as root - use a dedicated account with the sudoers lines from docs/NETWORK.md "
                         "(sudo -n, exact command lines)")
        elif self.config.get("read_only"):
            privilege = (f"uid {display_id(facts.get('uid'))}: reads through sudo -n with exact command lines; this "
                         "connection is read only (the change wrapper is never called)")
        elif any("sudo does not allow" in r or "is not installed" in r for r in reasons):
            privilege = (f"uid {display_id(facts.get('uid'))}: reads through sudo -n with exact command lines; "
                         "read-only account (the change wrapper is not allowed or not installed)")
        else:
            privilege = (f"uid {display_id(facts.get('uid'))}: reads through sudo -n with exact command lines; "
                         f"{self.wrapper} allowed - {LEAST_PRIVILEGE_NOTE}")
        checks.append(check("privileges", True, privilege))
        os_name = record["device"]["model"] or "Linux"
        checks.append(check("version", state["manager"] != "none",
                            f"{os_name}, kernel {display_id(facts.get('kernel'))}; "
                            + (f"{state['manager']} {state['manager_version']} - supported" if state["manager"] != "none"
                               else "no supported firewall manager (firewalld, ufw or nftables) was found")))
        features = {"nftables": f"nft JSON listing (schema {display_id(getattr(state.get('nft'), 'schema', ''))})",
                    "ufw": "ufw rule tuples (user.rules, user6.rules)",
                    "firewalld": "firewall-cmd zone, policy and rich-rule listings"}.get(state["manager"], "none")
        features += "; changes: " + (f"atrium-fw {WRAPPER_VERSION}, dead-man revert after {self.window} s via "
                                     "systemd-run" if write else "unavailable - " + "; ".join(reasons))
        checks.append(check("api_features", True, features))
        checks.append(check("manager", state["manager"] != "none",
                            f"{state['manager']} ({'set in the connection' if self.config.get('manager') != 'auto' else 'detected'})"))
        if state["manager"] == "nftables":
            status = state["nft"].atrium_status()
            text = ("table inet atrium: " + ("present, input policy " + status["policy"] if status["table"] else
                                             "missing (Atrium only writes inside its own table)"))
            if status["other_drop"]:
                text += "; input also dropped by default in " + ", ".join(status["other_drop"]) \
                        + ": an allow in Atrium's table cannot override that"
            if info.get("persist") == "no" and status["table"]:
                text += "; not persisted - include /etc/atrium/atrium.nft from the nftables service configuration"
            checks.append(check("atrium_table", status["table"], text))
        connection = facts.get("ssh")
        checks.append(check("management_guard", True,
                            f"the hub reaches sshd from {connection['client_ip']} to port {connection['server_port']}: "
                            "rules carrying that path are never disabled" if connection else
                            "the hub's address is unknown (SSH_CONNECTION not set): every rule that can reach the host "
                            "is protected"))
        if record["errors"]:
            checks.append(check("ruleset", True, f"{len(record['errors'])} entries could not be read and were skipped"))
        detail = (f"Connected to {record['device']['hostname'] or self.config['host']} ({os_name}, {state['manager']}): "
                  f"{len(record['rules'])} rules" + ("" if write else " (read only)"))
        return self._result(checks, True, detail, write)

    # -- backups ---------------------------------------------------------------------------------

    async def backup(self) -> dict[str, Any]:
        async with self.session() as session:
            facts = await self.probe(session)
            state = await self.read(session, facts)
            manager, parts = state["manager"], [f"### atrium-fw backup v1 manager={state['manager']}"]
            if manager == "nftables":
                text = (await self._sudo(session, facts["paths"]["nft"], "list", "ruleset",
                                         what="list the nftables ruleset")).stdout
                parts += ["### atrium-fw file nft-ruleset", text.rstrip("\n")]
            elif manager == "ufw":
                for name in UFW_FILES:
                    result = await self._exec(session, posix_command(["sudo", "-n", "cat", f"/etc/ufw/{name}"]),
                                              what=f"read /etc/ufw/{name}")
                    if result.ok:
                        parts += [f"### atrium-fw file {name}", result.stdout.rstrip("\n")]
                    elif name in ("user.rules", "user6.rules"):
                        raise self.error(f"/etc/ufw/{name} could not be read for the backup")
                    else:
                        parts.append(f"### atrium-fw missing {name}")
                defaults = await self._exec(session, "cat /etc/default/ufw", what="read /etc/default/ufw")
                parts += ["### atrium-fw file default-ufw", defaults.stdout.rstrip("\n")]
            elif manager == "firewalld":
                fc = facts["paths"]["firewall-cmd"]
                for name, args in (("zones", ("--list-all-zones",)), ("permanent-zones", ("--permanent", "--list-all-zones")),
                                   ("policies", ("--list-all-policies",))):
                    result = await self._exec(session, posix_command(["sudo", "-n", fc, *args]), what=f"list {name}")
                    parts += [f"### atrium-fw file {name}", result.stdout.rstrip("\n") if result.ok else "(not readable)"]
            else:
                raise ChangeError("No supported firewall manager on this host: nothing to back up", code="unsupported",
                                  state="unchanged")
        content = ("\n".join(parts) + "\n").encode("utf-8")
        return {"content": content, "format": "text", "device_backup_id": None, "revision": state["revision"],
                "sha256": hashlib.sha256(content).hexdigest()}

    # -- changes ---------------------------------------------------------------------------------

    @staticmethod
    def _service(op: dict[str, Any]) -> tuple[str, str | None]:
        """The one (protocol, ports) an allow carries on a host firewall; ValueError otherwise."""
        if len(op["services"]) != 1:
            raise ValueError("one service per rule on a host firewall - combine the ports into one entry or split "
                             "the change")
        service = op["services"][0]
        if not sorted_ports(service.get("ports")):
            raise ValueError("list the ports in ascending order (the host firewall lists them that way)")
        return service["proto"], service.get("ports")

    def _plan(self, state: dict[str, Any], ops: list[dict[str, Any]], record: dict[str, Any],
              connection: dict[str, Any] | None, table_text: str | None = None) -> dict[str, Any]:
        """What ``ops`` would do here: {"guard", "problems", "steps", "notes", "lines" | "table", "created",
        "toggled", "parts", "disabled", "enabled"} (nothing is changed)."""
        manager = state["manager"]
        rules = {r["id"]: r for r in record["rules"]}
        counts = state.get("parts") or {}
        interfaces = {i["id"]: i for i in record["interfaces"]}
        zones = {z["id"] for z in record["zones"]}
        problems, steps, notes, lines, created = [], [], [], [], []
        toggled: dict[str, str] = {}
        parts: dict[str, int] = {}
        disabled, enabled = [], []
        table = None
        if manager == "nftables" and table_text is not None:
            try:
                table = AtriumTable(table_text)
            except ValueError as exc:
                problems.append(f"table inet atrium cannot be edited: {exc}")
        if manager == "nftables":
            status = state["nft"].atrium_status()
            if status["other_drop"] and any(op["op"] == "allow" for op in ops):
                problems.append("the host's own nftables table (" + ", ".join(status["other_drop"])
                                + ") drops incoming traffic by default: an accept in Atrium's table cannot override "
                                  "that (every base chain runs and a drop is final)")
            elif status["other_rules_drop"] and any(op["op"] == "allow" for op in ops):
                notes.append("other tables have drop or reject rules on the input hook; they still apply")
        if manager == "none":
            problems.append("no supported firewall manager on this host")
        for index, op in enumerate(ops):
            if op["op"] == "allow":
                self._plan_allow(state, record, op, index, table, problems, steps, lines, created, parts)
                continue
            verb = "disable" if op["op"] == "disable_rules" else "enable"
            for ref in op["rules"]:
                key = next((r for r in (ref["id"], ref["vendor_ref"]) if KEY_FULL.match(r)), None)
                if key is None:
                    problems.append(f"rule {display_id(ref['id'])}: {manager} has no disabled state, so Atrium only "
                                    "disables rules it created itself (marked atrium:<change>.<n>)")
                    continue
                count = counts.get(key)
                if count is None or (key not in rules and f"{key}~parked" not in rules):
                    problems.append(f"rule {display_id(key)} is not on the host (re-read it first)")
                    continue
                steps.append({"op": index, "kind": f"{verb}_rule", "position": "in place" if manager != "nftables" else
                              ("chain parked" if verb == "disable" else "top of chain input"),
                              "detail": f"{verb} {display_id(key)}"})
                moving = count["on"] if verb == "disable" else count["off"]
                if not moving or key in toggled:
                    notes.append(f"rule {display_id(key)} is already {verb}d")
                    continue
                toggled[key] = "0" if verb == "disable" else "1"
                parts[key] = count["on"] + count["off"]
                (disabled if verb == "disable" else enabled).append(key)
                if manager == "nftables" and table is not None:
                    if table.move(key, "parked" if verb == "disable" else "input") != moving:
                        problems.append(f"rule {display_id(key)} does not match table inet atrium (re-read it first)")
                elif manager in ("ufw", "firewalld"):
                    entries = self._parts_on_host(state, key) if verb == "disable" else self._parked_parts(state, key)
                    if entries is None or len(entries) != moving:
                        problems.append(f"rule {display_id(key)} is not a rule Atrium wrote (edited by hand?)")
                    else:
                        lines += ["\t".join(["park" if verb == "disable" else "unpark", *e]) for e in entries]
        guard = management_guard(record, ops,
                                 hub_addresses=[connection["client_ip"]] if connection else None,
                                 management_ports=[connection["server_port"] if connection
                                                   else int(self.config.get("port") or 22)])
        if manager == "nftables" and table is None and not problems:
            problems.append("table inet atrium could not be read through the change wrapper")
        if not created and not toggled and not problems:
            problems.append("nothing to change: the rules are already as asked")
        return {"guard": guard, "problems": problems, "steps": steps, "notes": notes, "lines": lines,
                "table": table.text() if table is not None else None, "created": created, "toggled": toggled,
                "parts": parts, "disabled": disabled, "enabled": enabled}

    def _plan_allow(self, state: dict[str, Any], record: dict[str, Any], op: dict[str, Any], index: int,
                    table: AtriumTable | None, problems: list[str], steps: list[dict[str, Any]], lines: list[str],
                    created: list[dict[str, Any]], parts: dict[str, int]) -> None:
        """One allow: checks, and the native rules it becomes - one per address family (nftables) or per source /
        destination pair (ufw and firewalld rules take one network each), all carrying the same key."""
        manager, key, zone = state["manager"], f"{op['marker']}.{index}", op["source"]["zone"]
        where = f"operation {index + 1}"
        interfaces = {i["id"] for i in record["interfaces"]}
        zones = {z["id"] for z in record["zones"]}
        if manager == "firewalld":
            if zone not in zones or not ZONE_RE.match(zone):
                problems.append(f"{where}: firewalld has no active zone '{display_id(zone)}'")
        elif zone not in interfaces or not IFNAME_RE.match(zone):
            problems.append(f"{where}: the host has no interface '{display_id(zone)}'")
        if op["destination"]["zone"] not in zones | interfaces:
            problems.append(f"{where}: the host has no interface or zone '{display_id(op['destination']['zone'])}'")
        pairs, one_sided = family_pairs(op)
        for version in one_sided:
            problems.append(f"{where}: IPv{version} networks are on one side only - the rule could never match them")
        own = [a for a in record["self_addresses"]
               if any(ipaddress.ip_address(a) in ipaddress.ip_network(c) for c in op["destination"]["cidrs"]
                      if ipaddress.ip_network(c).version == ipaddress.ip_address(a).version)]
        if not own:
            problems.append(f"{where}: the destination networks hold none of this host's addresses - a host firewall "
                            "only filters traffic to the host itself")
        if key in (state.get("parts") or {}):
            problems.append(f"{where}: a rule marked {key} is already on the host")
        try:
            proto, ports = self._service(op)
        except ValueError as exc:
            problems.append(f"{where}: {exc}")
            proto, ports = "tcp", None
        if proto == "icmp" and any(ipaddress.ip_network(s[0]).version == 6 for s, _ in pairs):
            problems.append(f"{where}: ICMP rules are IPv4 only (ICMPv6 is not an Atrium service)")
        if manager == "ufw" and proto == "icmp":
            problems.append(f"{where}: ufw cannot express ICMP rules (they live in before.rules)")
        if manager == "ufw" and sum(2 if lo != hi else 1 for lo, hi in port_ranges(ports)) > 15:
            problems.append(f"{where}: ufw takes at most 15 ports per rule")
        if manager == "firewalld" and ports and "," in ports:
            problems.append(f"{where}: a firewalld rich rule takes one port or one range")
        if manager == "firewalld" and not op.get("log", True):
            problems.append(f"{where}: firewalld rich rules have no comment, so Atrium marks its rules with a log "
                            "prefix - this change must log")
        native = []
        for sources, destinations in pairs:
            if manager == "nftables":
                part = {**op, "source": {**op["source"], "cidrs": sources},
                        "destination": {**op["destination"], "cidrs": destinations}}
                problems.extend(f"{where}: {p}" for p in nft_form(part, ports))
                native.append(nft_rule_line(part, key, proto, ports))
            elif manager in ("ufw", "firewalld"):
                native += [(src, dst) for src, dst in product(sources, destinations)]
        if len(native) > 32:
            problems.append(f"{where}: {len(native)} {manager} rules would be needed (at most 32) - split the change")
            return
        for item in native:
            if manager == "nftables" and table is not None:
                table.add_top(item)
            elif manager == "ufw":
                lines.append("\t".join(["add", key, zone, "1" if op.get("log", True) else "0", proto, item[0], item[1],
                                         (ports or "").replace("-", ":"), safe_comment(key, op.get("description") or "")]))
            elif manager == "firewalld":
                part = {**op, "source": {**op["source"], "cidrs": [item[0]]},
                        "destination": {**op["destination"], "cidrs": [item[1]]}}
                lines.append("\t".join(["add", key, zone, rich_rule_text(part, key, proto, ports)]))
        created.append({"op": index, "id": key, "vendor_ref": key})
        parts[key] = len(native)
        position = {"nftables": "top of chain input in table inet atrium", "ufw": "top of ufw's rules (prepend)",
                    "firewalld": f"zone {display_id(zone)}, priority -1 (before its deny rules)"}.get(manager, "-")
        steps.append({"op": index, "kind": "add_rule", "position": position,
                      "detail": f"pass {proto}{'/' + ports if ports else ''} on {display_id(zone)}, marked {key}"
                                + (f" ({len(native)} {manager} rules)" if len(native) > 1 else "")})

    @staticmethod
    def _parked_parts(state: dict[str, Any], key: str) -> list[list[str]]:
        """The wrapper-registry entries of a parked key, as fields for "unpark" lines."""
        out = []
        for entry in state.get("parked_entries", {}).get(state["manager"], []):
            if entry["key"] == key:
                out.append(entry["fields"] if entry["manager"] == "ufw" else [key, entry["zone"], entry["rule"]])
        return out

    @staticmethod
    def _parts_on_host(state: dict[str, Any], key: str) -> list[list[str]] | None:
        """The fields of every active native rule carrying `key` ("park" lines); None if one is not Atrium's form."""
        out: list[list[str]] = []
        if state["manager"] == "ufw":
            for t in state.get("ufw_tuples") or []:
                parts = ufw_parts(t)
                if _key(parts["comment"]) == key:
                    fields = ufw_fields(parts, key)
                    if fields is None:
                        return None
                    out.append(fields)
        else:
            for zone in state.get("fw_zones") or []:
                for text in zone["rich"]:
                    rich = parse_rich_rule(text)
                    if rich and _key(((rich.get("log") or {}).get("prefix")) or "") == key:
                        out.append([key, zone["name"], text])
        return out

    async def _read_for_change(self, session: Any) -> tuple[dict[str, Any], dict[str, Any], str | None]:
        """(state, normalised record, table inet atrium text) read for a preview or an apply."""
        facts = await self.probe(session)
        state = await self.read(session, facts)
        table_text = None
        if state["manager"] == "nftables" and state["nft"].atrium_status()["table"]:
            try:
                answer = await self._wrapper(session, "table", what="read table inet atrium")
                table_text = answer.stdout if answer.ok else None
            except SudoRefused:
                table_text = None
        return state, normalize_record(self.to_record(state)), table_text

    async def preview_change(self, ops: list[dict[str, Any]], snapshot: dict[str, Any]) -> dict[str, Any]:
        ops = parse_ops(ops)
        async with self.session() as session:
            state, record, table_text = await self._read_for_change(session)
            write, reasons, _ = await self.writes(session, state)
        plan = self._plan(state, ops, record, state["facts"].get("ssh"), table_text)
        problems = plan["guard"] + plan["problems"]
        if write is None:
            problems += [f"changes are unavailable on this host: {r}" for r in reasons]
        notes = plan["notes"] + [f"none of these firewalls has a commit-confirm: Atrium arms a revert on the host "
                                 f"(systemd timer) that restores the previous rules {self.window} s after the change "
                                 "unless Atrium confirms it"]
        if state["manager"] == "ufw":
            notes.append("ufw saves every change at once: a reboot does not undo it")
        if state["manager"] == "firewalld":
            notes.append("the change is made at runtime and saved (--permanent) only after confirmation; the "
                         "automatic revert reloads firewalld, which also drops other unsaved runtime changes")
        if record["revision"] != snapshot.get("revision"):
            notes.append("the host changed since the snapshot: refresh before approving")
        return {"steps": plan["steps"], "notes": notes, "problems": problems}

    @staticmethod
    def _parse_token(token: str) -> dict[str, Any]:
        try:
            info = json.loads(token)
            assert isinstance(info, dict) and info.get("v") == 1 and SID_RE.match(str(info.get("sid") or ""))
            assert info.get("mgr") in ("nftables", "ufw", "firewalld")
            assert all(KEY_FULL.match(str(k)) for k in info.get("created") or [])
            assert all(KEY_FULL.match(str(k)) and v in ("0", "1") for k, v in (info.get("toggled") or {}).items())
            assert all(KEY_FULL.match(str(k)) and isinstance(n, int) and 0 < n <= 64
                       for k, n in (info.get("parts") or {}).items())
        except (ValueError, AssertionError, AttributeError, TypeError) as exc:
            raise ChangeError("Not a change token of this host firewall connector", code="invalid",
                              state="unknown") from exc
        return info

    @staticmethod
    def _state(state: dict[str, Any], info: dict[str, Any]) -> str:
        """"applied", "reverted" or "partial": what the host shows of the change now, counted in native rules (every
        part of every rule the change created or toggled)."""
        counts, expected = state.get("parts") or {}, info.get("parts") or {}
        applied, reverted = [], []
        for key in info.get("created") or []:
            count = counts.get(key, {"on": 0, "off": 0})
            applied.append(count["on"] == expected.get(key, 1) and count["off"] == 0)
            reverted.append(count["on"] == 0)
        for key, previous in (info.get("toggled") or {}).items():
            count, total = counts.get(key, {"on": 0, "off": 0}), expected.get(key, 1)
            on, off = (count["on"], count["off"]) if previous == "0" else (count["off"], count["on"])
            applied.append(on == 0 and off == total)  # all moved away from the previous state
            reverted.append(on == total and off == 0)
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
        except ConnectorError as exc:  # before arming nothing changed; after it the host's timer reverts
            raise ChangeError(exc.message + (f" - the automatic revert restores the previous rules within "
                                             f"{self.window} s" if progress["armed"] else ""),
                              code="unreachable" if isinstance(exc, SshUnavailable) else "failed",
                              state="unknown" if progress["armed"] else "unchanged") from exc

    async def _apply(self, session: Any, ops: list[dict[str, Any]], base_revision: str,
                     progress: dict[str, bool]) -> dict[str, Any]:
        state, record, table_text = await self._read_for_change(session)
        if record["revision"] != base_revision:
            raise ChangeError("The host's rules changed since the preview - re-read it and preview again", code="stale",
                              state="unchanged")
        write, reasons, _ = await self.writes(session, state)
        if write is None:
            raise ChangeError("Changes are unavailable on this host: " + "; ".join(reasons), code="unsupported",
                              state="unchanged")
        plan = self._plan(state, ops, record, state["facts"].get("ssh"), table_text)
        if plan["guard"]:
            raise ChangeError("Refused by the management-path guard: " + "; ".join(plan["guard"]), code="lockout",
                              state="unchanged")
        if plan["problems"]:
            raise ChangeError("; ".join(plan["problems"]), code="invalid", state="unchanged")
        manager = state["manager"]
        change = plan["table"] if manager == "nftables" else "".join(f"{line}\n" for line in plan["lines"])
        info: dict[str, Any] = {"v": 1, "sid": secrets_module.token_hex(8), "mgr": manager,
                                "created": [c["id"] for c in plan["created"]], "toggled": plan["toggled"],
                                "parts": plan["parts"]}
        if not change or len(json.dumps(info)) > 4000:
            raise ChangeError("Nothing to change" if not change else "Too many rules in one change - split it",
                              code="invalid", state="unchanged")
        # 1. arm the revert timer BEFORE writing (the wrapper refuses to apply otherwise)
        armed_at = self.clock()
        arm = await self._wrapper(session, "arm", info["sid"], str(self.window), manager, what="arm the automatic revert")
        if not arm.ok or arm.stdout.strip() != "armed":
            raise ChangeError("The host could not arm the automatic revert - nothing was changed"
                              + (f" ({untrusted_text(arm.stderr, 160)})" if arm.stderr.strip() else ""),
                              code="failed", state="unchanged")
        progress["armed"] = True
        info["deadline"] = armed_at + self.window
        # 2. write
        answer = await self._wrapper(session, "apply", info["sid"], what="apply the change", input=change)
        if not answer.ok or answer.stdout.strip() != "applied":
            raise await self._undone(session, info, "The host refused the change"
                                     + (f" ({untrusted_text(answer.stderr, 200)})" if answer.stderr.strip() else ""))
        # 3. the host now shows the change (the hub re-reads it over a new connection before confirming)
        after = await self.read(session)
        if self._state(after, info) != "applied":
            raise await self._undone(session, info, "The host accepted the change but its rules do not show it")
        return {"token": json.dumps(info, separators=(",", ":"), sort_keys=True), "rollback_until": info["deadline"],
                "revision": after["revision"], "created": plan["created"], "disabled": plan["disabled"],
                "enabled": plan["enabled"], "notes": [f"dead-man revert armed for {self.window} s (session {info['sid']})"]}

    async def _undone(self, session: Any, info: dict[str, Any], message: str) -> ChangeError:
        """Roll a failed change back at once; the error to raise."""
        try:
            answer = await self._wrapper(session, "rollback", info["sid"], what="roll the change back")
            after = await self.read(session)
            if answer.stdout.strip() == "reverted" and self._state(after, info) == "reverted":
                return ChangeError(message + " - Atrium rolled it back", code="failed", state="rolled_back")
        except ConnectorError:
            pass
        return ChangeError(message + f" - the automatic revert restores the previous rules within {self.window} s",
                           code="failed", state="unknown")

    async def confirm_change(self, token: str) -> dict[str, Any]:
        info = self._parse_token(token)
        try:
            async with self.session() as session:
                answer = (await self._wrapper(session, "confirm", info["sid"], what="confirm the change")).stdout
                record = await self.read(session)
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable" if isinstance(exc, SshUnavailable) else "failed",
                              state="unknown") from exc
        lines = answer.strip().splitlines()
        state = self._state(record, info)
        if lines[:1] == ["confirmed"] and state == "applied":
            persist = next((l.split("=", 1)[1] for l in lines if l.startswith("persist=")), "")
            notes = ["the automatic revert was stopped"]
            notes.append({"ok": "the change was saved", "immediate": "ufw saved the change when it was made",
                          "failed": "the change could NOT be saved: it is lost at the next reboot or reload"}.get(
                persist, "saving the change was not reported"))
            return {"confirmed": True, "revision": record["revision"], "notes": notes}
        if lines[:1] in (["fired"], ["rolled"]) or state == "reverted":
            raise ChangeError("Too late to confirm: the host restored the previous rules", code="failed",
                              state="rolled_back" if state == "reverted" else "unknown")
        raise ChangeError("No armed change with this id on the host", code="failed", state="unknown")

    async def rollback_change(self, token: str, backup: Backup | None) -> dict[str, Any]:
        info = self._parse_token(token)
        try:
            async with self.session() as session:
                answer = (await self._wrapper(session, "rollback", info["sid"], what="roll the change back")).stdout
                record = await self.read(session)
        except ConnectorError as exc:
            raise ChangeError(exc.message + " - if the host is unreachable, its timer restores the previous rules "
                              f"within {self.window} s of the change", code="unreachable" if isinstance(exc, SshUnavailable)
                              else "failed", state="unknown") from exc
        word = answer.strip().splitlines()[:1]
        if self._state(record, info) == "reverted":
            notes = [] if word == ["reverted"] else ["the automatic revert had already run"] if word == ["fired"] else []
            return {"rolled_back": True, "method": "deadman", "notes": notes}
        if word == ["confirmed"]:
            raise ChangeError("The change was already confirmed: revert it with a new change", code="failed",
                              state="applied")
        raise ChangeError("The change is still on the host after rolling it back", code="failed", state="applied")

    async def restore_backup(self, backup: Backup) -> dict[str, Any]:
        sections: dict[str, str] = {}
        name = None
        try:
            text = backup.text()
        except UnicodeError as exc:
            raise ChangeError("The backup is not a host firewall backup of Atrium", code="invalid",
                              state="unchanged") from exc
        lines = text.splitlines()
        header = re.match(r"^### atrium-fw backup v1 manager=(\w+)$", lines[0]) if lines else None
        for line in lines[1:]:
            match = re.match(r"^### atrium-fw file ([\w.-]+)$", line)
            if match:
                name = match.group(1)
                sections[name] = ""
            elif line.startswith("### atrium-fw "):
                name = None
            elif name:
                sections[name] += line + "\n"
        manager = header.group(1) if header else ""
        if manager == "nftables":
            table = self._extract_table(sections.get("nft-ruleset", ""))
            if table is None:
                raise ChangeError("The backup holds no table inet atrium: Atrium only restores its own table",
                                  code="invalid", state="unchanged")
            content = table
        elif manager == "ufw" and sections.get("user.rules") and sections.get("user6.rules"):
            content = "".join(f"### atrium-fw file {n}\n{sections[n]}" for n in ("user.rules", "user6.rules"))
        elif manager == "firewalld":
            raise ChangeError("firewalld backups are listings: restore /etc/firewalld by hand", code="unsupported",
                              state="unchanged")
        else:
            raise ChangeError("The backup is not a host firewall backup of Atrium", code="invalid", state="unchanged")
        # like a change (review F36): the wrapper arms the automatic revert before it writes, and the restore is
        # confirmed (and saved) only after a NEW connection reached the host - a backup that cuts Atrium off is
        # put back by the host's own timer
        sid = secrets_module.token_hex(8)
        sent = False
        try:
            async with self.session() as session:
                facts = await self.probe(session)
                if facts["manager"] != manager:
                    raise ChangeError(f"The backup is of {manager}, the host now runs {facts['manager']}",
                                      code="invalid", state="unchanged")
                sent = True
                answer = await self._wrapper(session, "restore", sid, str(self.window), manager,
                                             what="restore the backup", input=content)
                if not answer.ok or answer.stdout.strip() != "restored":
                    raise ChangeError("The host refused the backup"
                                      + (f" ({untrusted_text(answer.stderr, 200)})" if answer.stderr.strip() else ""),
                                      code="failed", state="unknown")
        except ChangeError:
            raise
        except ConnectorError as exc:
            raise ChangeError(exc.message + (f" - the automatic revert restores the previous rules within "
                                             f"{self.window} s" if sent else ""),
                              code="unreachable" if isinstance(exc, SshUnavailable) else "failed",
                              state="unknown" if sent else "unchanged") from exc
        try:
            async with self.session() as session:
                record = normalize_record(self.to_record(await self.read(session)))
                confirmed = (await self._wrapper(session, "confirm", sid, what="confirm the restore")).stdout
        except ConnectorError as exc:
            raise ChangeError(f"After the restore Atrium could not reach the host again ({exc.message}) - the "
                              f"automatic revert restores the previous rules within {self.window} s",
                              code="unreachable" if isinstance(exc, SshUnavailable) else "failed",
                              state="unknown") from exc
        lines = confirmed.strip().splitlines()
        if lines[:1] != ["confirmed"]:
            raise ChangeError("Too late to confirm the restore: the host put the previous rules back", code="failed",
                              state="rolled_back" if lines[:1] in (["fired"], ["rolled"]) else "unknown")
        persist = next((l.split("=", 1)[1] for l in lines if l.startswith("persist=")), "")
        notes = ["table inet atrium was restored; other tables were not touched" if manager == "nftables"
                 else "user.rules and user6.rules were restored and ufw reloaded; before/after rules were not touched",
                 f"the automatic revert ({self.window} s) was armed first and stopped once a new connection reached "
                 "the host"]
        if persist == "failed":
            notes.append("the restored table could NOT be saved: it is lost at the next reboot or reload")
        return {"restored": True, "revision": record["revision"], "notes": notes}

    @staticmethod
    def _extract_table(text: str) -> str | None:
        """``table inet atrium { ... }`` out of an ``nft list ruleset`` listing."""
        lines = text.splitlines()
        start = next((i for i, l in enumerate(lines) if l == "table inet atrium {"), None)
        if start is None:
            return None
        end = next((i for i in range(start + 1, len(lines)) if lines[i] == "}"), None)
        return "\n".join(lines[start:end + 1]) + "\n" if end is not None else None


if __name__ == "__main__":  # python -m hub.connectors.hostfw wrapper | nft-table
    what = sys.argv[1] if len(sys.argv) > 1 else ""
    if what == "wrapper":
        sys.stdout.write(WRAPPER_SCRIPT)
    elif what == "nft-table":
        sys.stdout.write(NFT_TABLE_TEMPLATE)
    else:
        sys.stderr.write("usage: python -m hub.connectors.hostfw wrapper | nft-table\n")
        sys.exit(2)
