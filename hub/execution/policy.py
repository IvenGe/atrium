"""Command policy: decides whether a command runs, waits for a human, or is refused.

Three autonomy levels control agent-originated commands:

* ``manual``     - every agent command needs approval.
* ``assisted``   - read-only commands run, anything that changes state needs approval.
* ``autonomous`` - agents may run anything that is not blocked.

Commands typed by a person in the Operator console run directly (the person is
the approval), but blocked commands are refused for everyone - unless an admin
switched the ``block_catastrophic_commands`` guardrail off: blocked patterns are
then ordinary ``change`` commands (people run them, agents follow the autonomy level).
On the hub machine the Operator Agent adds one rule on top of this policy: an
operator's commands there that are not read-only wait for an administrator
(``OperatorAgent.on_run`` in ``hub/agents/operator.py``).
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Callable, Literal

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

# Read-only commands that may run without approval in "assisted" mode. They run without a person looking, so they
# must not change the machine, write a file or show the content of a file outside a repository (F1, F4, F5):
# commands that print a name, a clock or an interface take only their display options (with other arguments
# `hostname`, `date`, `ifconfig` and `ipconfig` set the name, the clock or an interface, and `date -f FILE` prints
# the file's lines in its error messages); `git` and `kubectl` take only the options in GIT_OPTION / KUBECTL_*
# below (checked in _read_only); `type` is left out (on Windows it prints a file).
READ_ONLY = [
    re.compile(p)
    for p in (
        r"^(ls|dir|pwd|whoami|uname|uptime|id|df|free|nproc|lscpu|lsblk|lsb_release|ver|systeminfo)(\s+-{0,2}[\w=/.-]+)*$",
        r"^hostname(\s+(-[fsdiIA]|--(fqdn|long|short|domain|ip-addresses?|all-ip-addresses|all-fqdns)))*$",
        r"^date(\s+(-u|-R|-I\w*|--utc|--universal|--rfc-email|--rfc-3339=\w+|--iso-8601(=\w+)?))*$",
        r"^ifconfig(\s+-[aslv])*(\s+[\w.:-]+)?$",  # at most one interface name: anything after it configures it
        r"^ipconfig(\s+/(?i:all|displaydns|allcompartments))*$",
        r"^ip\s+(a|addr|address|r|route|link)(\s+show)?$",
        r"^cat\s+/(etc/os-release|etc/hostname|proc/cpuinfo|proc/meminfo|proc/loadavg|proc/version)$",
        r"^git\s+(status|log|diff|branch|show|rev-parse|describe|tag)(\s+[\w=./:@^~-]+)*$",
        r"^docker\s+(ps|images|version|info|stats\s+--no-stream)(\s+-{1,2}[\w=-]+)*$",
        r"^docker\s+compose\s+(ps|ls|config\s+--services)(\s+-{1,2}[\w=-]+)*$",
        r"^(systemctl|service)\s+status(\s+[\w@.-]+)*$",
        r"^systemctl\s+(is-active|is-enabled|list-units)(\s+[\w@.=-]+)*$",
        r"^kubectl\s+(get|describe|top)(\s+[\w/.=,:-]+)*$",
        r"^kubectl\s+version(\s+--client)?$",
        r"^(python3?|node|npm|go|java|docker|git|pip3?|uv|cargo|rustc|dotnet|php|ruby)\s+(--version|-V|version)$",
        r"^(which|where)\s+[\w.-]+$",
        r"^(Get-ComputerInfo|Get-Service|Get-Process|Get-Volume|Get-NetIPAddress)(\s+[\w-]+)*$",
    )
]

# Arguments that make a command from the list above a "change" whatever else it says: kubectl on secrets reads the
# credentials the hub's own kubeconfig can reach; docker compose config --output writes a file.
NOT_READ_ONLY = [
    re.compile(r"^kubectl\s.*\bsecrets?\b"),
    re.compile(r"^docker\s.*\s(-o|--ou)"),
]
# The hub's own files, and other files that hold credentials, named in any argument: never read without approval.
SENSITIVE = re.compile(r"(?i)(^|[\s=:/\\])(\.env([.\s/\\]|$)|secret\.key|hub\.db|\.hub([\s/\\]|$)|\.ssh([\s/\\]|$)"
                       r"|id_(rsa|dsa|ecdsa|ed25519)|\.kube([\s/\\]|$)|\.git-credentials|\.netrc)")

# git: the display options of status, log, diff, show, rev-parse and describe. Anything else - --output (writes a
# file), --no-index (compares any two files), --ext-diff / --textconv (run programs), -O / --pathspec-from-file
# (read a file), ... - is not read-only. A non-option word is a revision or a path in the repository; "<rev>:<path>"
# is refused (it names a file's content, e.g. HEAD:.env).
GIT_OPTION = re.compile(
    r"-\d+|-n\d*|-U\d+|-[pusvbawzcq]+|-uno|-unormal|-uall|--|"
    r"--(oneline|graph|all|stat|shortstat|numstat|name-only|name-status|summary|patch|no-patch|cached|staged|merges|"
    r"no-merges|first-parent|reverse|abbrev-commit|no-abbrev-commit|decorate|no-decorate|short|long|branch|porcelain|"
    r"ignored|verbose|show-stash|ahead-behind|no-ahead-behind|follow|tags|always|dirty|contains|show-toplevel|"
    r"show-prefix|show-cdup|git-dir|absolute-git-dir|is-inside-work-tree|is-inside-git-dir|is-bare-repository|"
    r"abbrev-ref|symbolic-full-name|verify|quiet|no-color|ignore-space-change|ignore-all-space|word-diff|minimal|"
    r"full-history|no-renames|find-renames|relative-date|left-right|cherry-pick|cherry-mark|boundary|exit-code|check|"
    r"no-ext-diff|no-textconv|text|date-order|topo-order|author-date-order)|"
    r"--(max-count|skip|since|until|after|before|author|committer|grep|date|pretty|format|decorate|abbrev|"
    r"untracked-files|porcelain|color|unified|stat|word-diff|diff-filter|find-renames|ignore-submodules|match|"
    r"short)=[\w.:@/-]+")
GIT_WORD = re.compile(r"[\w./@^~-]+")
# git branch and git tag only list with these options; with a name they create, move or delete a branch or tag.
GIT_LIST_OPTIONS = {"-a", "-r", "-v", "-vv", "-l", "--list", "--all", "--remotes", "--verbose", "--show-current"}
# kubectl get / describe / top: names, the namespace and label selection and the built-in output formats. Anything
# else - --server (sends the request elsewhere), --raw, --kubeconfig / -f / -k (read a file), template outputs
# (read a template file), --token, ... - is not read-only.
KUBECTL_FLAGS = {"-A", "--all-namespaces", "--show-labels", "--no-headers", "-w", "--watch", "--containers"}
KUBECTL_VALUE = {"-n": r"[\w.-]+", "--namespace": r"[\w.-]+", "--context": r"[\w.@-]+", "-l": r"[\w./=,-]+",
                 "--selector": r"[\w./=,-]+", "--field-selector": r"[\w./=,-]+", "-o": r"wide|name|json|yaml",
                 "--output": r"wide|name|json|yaml"}
KUBECTL_WORD = re.compile(r"[\w.-]+(/[\w.-]+)?")

# Shell metacharacters that can chain or redirect - never "read-only".
METACHARS = re.compile(r"[;&|`<>]|\$\(|\r|\n")

# A command an AI model proposes (a launch or setup command read from a README a stranger may have written) runs on
# the hub machine with Atrium's privileges once an administrator approves it: it starts a program of the tool's own
# folder or one of these build tools and runtimes - nothing that fetches from the network, runs inline code, raises
# privileges or reaches out of a container (proposed_command_problem).
PROPOSED_PROGRAMS = frozenset({
    "mvn", "mvnw", "gradle", "gradlew", "sbt", "lein", "npm", "yarn", "pnpm", "bun", "deno", "node", "python",
    "python3", "py", "pip", "pip3", "uv", "poetry", "pipenv", "pdm", "hatch", "uvicorn", "gunicorn", "hypercorn",
    "daphne", "flask", "django-admin", "streamlit", "java", "go", "cargo", "make", "dotnet", "php", "composer", "ruby",
    "bundle", "rails", "rake", "mix", "elixir", "docker", "podman", "docker-compose", "podman-compose", "sh", "bash",
})
NETWORK_TOOLS = frozenset({"curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "sftp", "ftp", "tftp",
                           "rsync", "iwr", "invoke-webrequest", "invoke-restmethod", "certutil", "bitsadmin", "npx"})
ELEVATE = frozenset({"sudo", "su", "doas", "pkexec", "runas"})
INLINE_CODE = {"python": ("-c",), "python3": ("-c",), "py": ("-c",), "node": ("-e", "--eval", "-p", "--print"),
               "bun": ("-e", "--eval"), "deno": ("eval",), "ruby": ("-e",), "php": ("-r",), "sh": ("-c",),
               "bash": ("-c",)}
CONTAINER_SUBCOMMANDS = {"docker": ("run", "compose"), "podman": ("run", "compose"), "docker-compose": ("up",),
                         "podman-compose": ("up",)}
CONTAINER_ESCAPE = re.compile(
    r"^(--privileged|--cap-add|--device|--security-opt|--pid|--ipc|--uts|--userns|--cgroupns)(=|$)"
    r"|^--(net|network)(=host$|$)")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def proposed_command_problem(command: str, program: Callable[[str], bool] | None = None) -> str | None:
    """Why a command an AI model proposed may not become a launch or setup command, in a few words (None: it may be
    proposed - an administrator still approves it). Stricter than ``classify``, which judges what a person typed:
    no chaining, pipe, redirection, background job or command substitution; no network fetcher (curl, wget, nc, ...)
    or inline interpreter code (python -c, node -e, sh -c, ...); no sudo; a container only through docker/podman run
    or compose, never privileged, on the host's network or with a host folder mounted by absolute path. It starts a
    file of the tool's own folder (`program(path)` says whether a path is one) or a known build tool or runtime
    (PROPOSED_PROGRAMS); leading KEY=value assignments are allowed."""
    if METACHARS.search(command):
        return "it chains commands, pipes, redirects or substitutes (; & | > < ` $( ) - one plain command only"
    try:
        words = shlex.split(command)
    except ValueError:
        return "it cannot be read as one command (unbalanced quotes)"
    while words and ASSIGNMENT.match(words[0]):
        words = words[1:]
    if not words:
        return "it holds no command"
    lowered = [w.lower() for w in words]
    names = [re.sub(r"\.(exe|cmd|bat)$", "", w.replace("\\", "/").rsplit("/", 1)[-1]) for w in lowered]
    if ELEVATE & set(names):
        return "it raises privileges (sudo)"
    if NETWORK_TOOLS & set(names):
        return "it fetches from or connects to the network (" + ", ".join(sorted(NETWORK_TOOLS & set(names))) + ")"
    first, name = words[0], names[0]
    local = "/" in first or "\\" in first or first.startswith(".")
    if local or name not in PROPOSED_PROGRAMS:
        if program is None or not program(first):
            return (f"{first} is neither a file of the tool's folder nor a known build tool or runtime"
                    if local else f"{first} is not a known build tool or runtime")
    flags = INLINE_CODE.get(name, ())
    for word in lowered[1:]:  # the interpreter's own options, up to the script or module it runs
        if word in flags:
            return f"it runs inline code ({name} {word})"
        if not word.startswith("-") or word == "-m":
            break
    if name in ("sh", "bash") and not (len(words) > 1 and program is not None and program(words[1])):
        return f"{name} runs a script of the tool's folder only"
    if name in CONTAINER_SUBCOMMANDS:
        if len(lowered) < 2 or lowered[1] not in CONTAINER_SUBCOMMANDS[name]:
            return f"only {name} {' or '.join(CONTAINER_SUBCOMMANDS[name])} starts a container"
        for index, word in enumerate(lowered):
            if CONTAINER_ESCAPE.match(word) or (word in ("--net", "--network") and lowered[index + 1:index + 2] == ["host"]):
                return f"the container would reach out of its isolation ({word})"
            if word in ("-v", "--volume") and words[index + 1:index + 2] and words[index + 1].startswith(("/", "~")):
                return "the container would mount a folder of the hub machine"
            if word.startswith(("--volume=/", "-v=/", "--mount")) and ("source=/" in word or "src=/" in word
                                                                      or word.startswith(("--volume=/", "-v=/"))):
                return "the container would mount a folder of the hub machine"
    return None


def _git_read_only(sub: str, args: list[str]) -> bool:
    if sub in ("branch", "tag"):
        return all(w in GIT_LIST_OPTIONS for w in args)
    expect_count = False
    for w in args:
        if expect_count:  # -n <number>
            if not w.isdigit():
                return False
            expect_count = False
        elif w.startswith("-"):
            if not GIT_OPTION.fullmatch(w):
                return False
            expect_count = w == "-n"
        elif not GIT_WORD.fullmatch(w):
            return False
    if sub == "diff":
        # with two paths git diff compares any two files on the machine even without --no-index (outside a work
        # tree, which the caller picks with cwd, or for a path outside it): at most one argument that is not an
        # option - one revision ("a..b" for two) or one path in the repository
        return sum(1 for w in args if not w.startswith("-")) <= 1
    return True


def _kubectl_read_only(args: list[str]) -> bool:
    value_of: str | None = None
    for w in args:
        if value_of is not None:
            if not re.fullmatch(KUBECTL_VALUE[value_of], w):
                return False
            value_of = None
        elif w.startswith("-"):
            name, eq, value = w.partition("=")
            if eq:
                if name not in KUBECTL_VALUE or not re.fullmatch(KUBECTL_VALUE[name], value):
                    return False
            elif w in KUBECTL_VALUE:
                value_of = w
            elif w not in KUBECTL_FLAGS:
                return False
        elif not KUBECTL_WORD.fullmatch(w):
            return False
    return value_of is None


def _protected(word: str, protected: tuple[str, ...]) -> bool:
    """Whether `word` (or the value of an --option=value) names one of the `protected` directories or a path in it."""
    for candidate in (word, word.partition("=")[2]):
        path = candidate.replace("\\", "/").rstrip("/")
        if path and any(path == p or path.startswith(p + "/") for p in protected):
            return True
    return False


def _read_only(cmd: str, protected: tuple[str, ...] = ()) -> bool:
    if not any(p.match(cmd) for p in READ_ONLY) or any(p.search(cmd) for p in NOT_READ_ONLY) or SENSITIVE.search(cmd):
        return False
    words = cmd.split()
    roots = tuple(p.replace("\\", "/").rstrip("/") for p in protected if p and p.strip("/\\"))
    if roots and any(_protected(w, roots) for w in words[1:]):
        return False
    if words[0] == "git" and len(words) > 1:
        return _git_read_only(words[1], words[2:])
    if words[0] == "kubectl" and len(words) > 1 and words[1] in ("get", "describe", "top"):
        return _kubectl_read_only(words[2:])
    return True


@dataclass
class Decision:
    action: Action
    risk: Risk
    reason: str


def classify(command: str, *, block_catastrophic: bool = True, protected: tuple[str, ...] = ()) -> tuple[Risk, str]:
    """``protected``: directories no read-only command may name (the hub's data directory)."""
    cmd = command.strip()
    if not cmd:
        return "blocked", "empty command"
    for pattern, why in BLOCKED:
        if pattern.search(cmd):
            if block_catastrophic:
                return "blocked", why
            return "change", f"{why} - not blocked because the block_catastrophic_commands guardrail is off"
    if METACHARS.search(cmd):
        return "change", "uses shell chaining or redirection"
    if _read_only(cmd, protected):
        return "read_only", "known read-only command"
    return "change", "may change state"


def decide(command: str, autonomy: str, *, from_person: bool, trusted: bool = False,
           block_catastrophic: bool = True, protected: tuple[str, ...] = ()) -> Decision:
    """``trusted`` marks hub-defined commands (e.g. the built-in discovery script); ``block_catastrophic`` is the
    guardrail of that name; ``protected`` lists directories no read-only command may name (the data directory)."""
    risk, why = classify(command, block_catastrophic=block_catastrophic, protected=protected)
    if risk == "blocked":
        return Decision("deny", risk, f"Blocked: {why}. Run it yourself if you really mean it.")
    if trusted and risk == "change":
        risk, why = "read_only", "built-in hub read-only script"
    if from_person:
        return Decision("run", risk, "Requested by a person in the Operator console.")
    if autonomy == "autonomous":
        return Decision("run", risk, f"Autonomous mode ({why}).")
    if autonomy == "assisted" and risk == "read_only":
        return Decision("run", risk, f"Assisted mode allows read-only commands ({why}).")
    return Decision("approve", risk, f"Needs approval: {why} ({autonomy} mode).")
