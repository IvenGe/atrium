"""Command policy: decides whether a command runs, waits for a human, or is refused.

Three autonomy levels control agent-originated commands:

* ``manual``     - every agent command needs approval.
* ``assisted``   - read-only commands run, anything that changes state needs approval.
* ``autonomous`` - agents may run anything that is not blocked.

Commands typed by a person in the Operator console run directly (the person is
the approval), but blocked commands are refused for everyone - unless an admin
switched the ``block_catastrophic_commands`` guardrail off: blocked patterns are
then ordinary ``change`` commands (people run them, agents follow the autonomy level).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

Risk = Literal["read_only", "change", "blocked"]
Action = Literal["run", "approve", "deny"]

# Patterns that are refused outright, whoever asks.
BLOCKED = [
    (re.compile(r"\brm\s+(-[a-zA-Z]*\s+)*-[a-zA-Z]*[rR][a-zA-Z]*\s+(-[a-zA-Z]+\s+)*(/|~|\*|/\*|\$HOME)(\s|$)"), "recursive delete of a root, home or wildcard path"),
    (re.compile(r"\bmkfs(\.\w+)?\b"), "formats a filesystem"),
    (re.compile(r"\bdd\b.*\bof=/dev/"), "writes raw data to a device"),
    (re.compile(r">\s*/dev/(sd|nvme|hd|xvd)"), "overwrites a block device"),
    (re.compile(r":\(\)\s*\{\s*:\|:&\s*\};:"), "fork bomb"),
    (re.compile(r"\b(shutdown|poweroff|halt|reboot)\b"), "powers off or restarts the machine"),
    (re.compile(r"\binit\s+[06]\b"), "powers off or restarts the machine"),
    (re.compile(r"\bformat\s+[a-zA-Z]:", re.IGNORECASE), "formats a Windows drive"),
    (re.compile(r"\b(del|erase)\s+.*(/s|/q).*[a-zA-Z]:\\\s*$", re.IGNORECASE), "deletes a Windows drive"),
    (re.compile(r"Remove-Item\b.*-Recurse\b.*\s[a-zA-Z]:\\?\s*$", re.IGNORECASE), "deletes a Windows drive"),
    (re.compile(r"\bchmod\s+-R\s+0?777\s+/(\s|$)"), "opens permissions on the whole filesystem"),
    (re.compile(r"\bchown\s+-R\s+\S+\s+/(\s|$)"), "changes ownership of the whole filesystem"),
    (re.compile(r"\b(curl|wget|iwr|Invoke-WebRequest)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", re.IGNORECASE), "pipes a download straight into a shell"),
    (re.compile(r"\bhistory\s+-c\b|\bshred\b.*\.(bash_|zsh_)history"), "erases audit history"),
]

# Read-only commands that may run without approval in "assisted" mode.
READ_ONLY = [
    re.compile(p)
    for p in (
        r"^(ls|dir|pwd|whoami|hostname|uname|uptime|id|date|df|free|nproc|lscpu|lsblk|lsb_release|ver|systeminfo|ipconfig|ifconfig)(\s+-{0,2}[\w=/.-]+)*$",
        r"^ip\s+(a|addr|address|r|route|link)(\s+show)?$",
        r"^cat\s+/(etc/os-release|etc/hostname|proc/cpuinfo|proc/meminfo|proc/loadavg|proc/version)$",
        r"^git\s+(status|log|diff|show|rev-parse|describe)(\s+[\w=./:@^~-]+)*$",
        r"^git\s+remote\s+-v$",
        r"^git\s+branch(\s+(-a|-r|-v|-vv|--list))*(\s+[\w./-]+)?$",
        r"^git\s+tag(\s+(-l|-n|--list))*(\s+[\w./@-]+)?$",
        r"^docker\s+(ps|images|version|info|stats\s+--no-stream)(\s+-{1,2}[\w=-]+)*$",
        r"^docker\s+compose\s+(ps|ls|config\s+--services)(\s+-{1,2}[\w=-]+)*$",
        r"^(systemctl|service)\s+status(\s+[\w@.-]+)*$",
        r"^systemctl\s+(is-active|is-enabled|list-units)(\s+[\w@.=-]+)*$",
        r"^kubectl\s+(get|describe|version|top)(\s+[\w/.=,:-]+)*$",
        r"^(python3?|node|npm|go|java|docker|git|pip3?|uv|cargo|rustc|dotnet|php|ruby)\s+(--version|-V|version)$",
        r"^(which|where|type)\s+[\w.-]+$",
        r"^(Get-ComputerInfo|Get-Service|Get-Process|Get-Volume|Get-NetIPAddress)(\s+[\w-]+)*$",
    )
]

# Shell metacharacters that can chain or redirect - never "read-only".
METACHARS = re.compile(r"[;&|`<>]|\$\(|\r|\n")

# The hub's own database and key. A command that names them is refused for everyone: the Operator console
# runs as the hub user, so a "read-only" or person-typed command must not be a way to read or edit them.
HUB_PRIVATE = re.compile(r"(secret\.key|hub\.db(?:-wal|-shm)?|(?:^|[\s/'\"])\.hub(?:/|\b)|HUB_DATA_DIR|HUB_SECRET_KEY)", re.IGNORECASE)


@dataclass
class Decision:
    action: Action
    risk: Risk
    reason: str


def classify(command: str, *, block_catastrophic: bool = True) -> tuple[Risk, str]:
    cmd = command.strip()
    if not cmd:
        return "blocked", "empty command"
    for pattern, why in BLOCKED:
        if pattern.search(cmd):
            if block_catastrophic:
                return "blocked", why
            return "change", f"{why} - not blocked because the block_catastrophic_commands guardrail is off"
    if HUB_PRIVATE.search(cmd):
        return "blocked", "names the hub's own database or encryption key"
    if METACHARS.search(cmd):
        return "change", "uses shell chaining or redirection"
    if any(p.match(cmd) for p in READ_ONLY):
        return "read_only", "known read-only command"
    return "change", "may change state"


def decide(command: str, autonomy: str, *, from_person: bool, trusted: bool = False,
           block_catastrophic: bool = True, person_may_change: bool = True) -> Decision:
    """``trusted`` marks hub-defined commands (e.g. the built-in discovery script); ``block_catastrophic`` is the
    guardrail of that name. ``person_may_change`` is false for a non-admin's command on this machine: that command
    can read the hub's files, so a state-changing one waits for an administrator."""
    risk, why = classify(command, block_catastrophic=block_catastrophic)
    if risk == "blocked":
        return Decision("deny", risk, f"Blocked: {why}. Run it yourself if you really mean it.")
    if trusted and risk == "change":
        risk, why = "read_only", "built-in hub read-only script"
    if from_person:
        if not person_may_change and risk == "change":
            return Decision("approve", risk, "A state-changing command on this machine needs an administrator. "
                            "The Operator console runs as the hub user.")
        return Decision("run", risk, "Requested by a person in the Operator console.")
    if autonomy == "autonomous":
        return Decision("run", risk, f"Autonomous mode ({why}).")
    if autonomy == "assisted" and risk == "read_only":
        return Decision("run", risk, f"Assisted mode allows read-only commands ({why}).")
    return Decision("approve", risk, f"Needs approval: {why} ({autonomy} mode).")
