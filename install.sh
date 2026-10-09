#!/usr/bin/env bash
# Installs Atrium on Linux or macOS (also in Git Bash on Windows): a Python virtual environment, ./start-atrium.sh
# and, with --service, a systemd user unit. Run it from a clone of the repository:
#
#     bash install.sh [--install-dir DIR] [--port PORT] [--dev] [--service]
#
# Safe to run again, e.g. after git pull: it reuses .venv, updates the installed package, rewrites the start script
# (and the unit) and never touches an existing .env or the hub's data (.hub). Works with the bash 3.2 of macOS.
if [ -z "${BASH_VERSION:-}" ]; then
    echo "error: run this installer with bash: bash install.sh" >&2
    exit 2
fi
set -euo pipefail

MIN_PYTHON="3.11"
PYTHON_DOWNLOAD="https://www.python.org/downloads/"
GIT_DOWNLOAD="https://git-scm.com/downloads"

usage() {
    cat <<'EOF'
Usage: bash install.sh [options]

Installs Atrium: finds Python 3.11 or newer, checks for git, creates .venv, installs Atrium with the
ai and ssh extras, copies .env.example to .env when there is no .env yet and writes ./start-atrium.sh.
Safe to run again; an existing .env and the hub's data are never touched.

Options:
  --install-dir DIR  copy the program to DIR and install it there (default: this folder)
  --port PORT        port the start script passes to the hub (default: HUB_PORT from .env, 8710)
  --dev              also install the development extras (pytest)
  --service          also write a systemd user unit (Linux) and print how to enable it; it is not enabled
  -h, --help         show this help

Set ATRIUM_PYTHON to choose the Python, e.g. ATRIUM_PYTHON=/usr/bin/python3.12 bash install.sh
EOF
}

quiet_exit=0
finish() {
    local status=$?
    if [ "$status" -ne 0 ] && [ "$quiet_exit" -eq 0 ]; then
        printf '\nInstallation failed. Fix the problem and run the installer again; it is safe to rerun.\n' >&2
        printf 'If Atrium is running from the install folder, stop it first.\n' >&2
    fi
}
trap finish EXIT

step() { printf '==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
bad_usage() {
    quiet_exit=1
    printf 'error: %s\n\n' "$*" >&2
    usage >&2
    exit 2
}

# Paths handed to a Windows Python from Git Bash must be Windows paths; elsewhere they pass through unchanged.
native() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -w -- "$1"; else printf '%s' "$1"; fi
}

# probe CMD [ARGS...]: prints "VERSION|EXECUTABLE" when CMD runs Python 3.11 or newer, fails otherwise.
probe() {
    local out
    out="$("$@" -c 'import sys
if sys.version_info < (3, 11): sys.exit(1)
print("%d.%d.%d|%s" % (sys.version_info[:3] + (sys.executable,)))' 2>/dev/null)" || return 1
    out="${out//$'\r'/}"
    [ -n "$out" ] || return 1
    printf '%s' "$out"
}

PYTHON=()
python_info=""
find_python() {
    local name
    if [ -n "${ATRIUM_PYTHON:-}" ]; then
        python_info="$(probe "$ATRIUM_PYTHON")" || die "ATRIUM_PYTHON ($ATRIUM_PYTHON) is not a working Python $MIN_PYTHON or newer."
        PYTHON=("$ATRIUM_PYTHON")
        return 0
    fi
    for name in python3 python3.16 python3.15 python3.14 python3.13 python3.12 python3.11 python; do
        command -v "$name" >/dev/null 2>&1 || continue
        # Assumption: on macOS /usr/bin/python3 is a stub that opens an installer dialog while the Command Line
        # Tools are missing; skip it then instead of popping that up.
        if [ "$(command -v "$name")" = /usr/bin/python3 ] && [ "$(uname -s)" = Darwin ] \
            && ! xcode-select -p >/dev/null 2>&1; then
            continue
        fi
        if python_info="$(probe "$name")"; then
            PYTHON=("$name")
            return 0
        fi
    done
    # The py launcher of Windows (Git Bash). Assumption, as in install.ps1: this setting keeps the Python install
    # manager from downloading a runtime when none is installed (docs.python.org, "Python install manager").
    if command -v py >/dev/null 2>&1 && python_info="$(PYTHON_MANAGER_AUTOMATIC_INSTALL=false probe py -3)"; then
        PYTHON=(py -3)
        return 0
    fi
    return 1
}

# Escapes a path for a systemd unit (systemd.syntax(7), systemd.unit(5) "Specifiers"): % is always doubled; inside a
# double-quoted ExecStart= word, backslashes and double quotes are escaped as well.
unit_path() { printf '%s' "$1" | sed -e 's/%/%%/g'; }
unit_quoted() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/%/%%/g'; }

install_dir=""
port=""
dev=0
service=0
while [ $# -gt 0 ]; do
    case "$1" in
        --install-dir)
            [ $# -ge 2 ] && [ -n "$2" ] || bad_usage "--install-dir needs a folder"
            install_dir="$2"
            shift 2
            ;;
        --install-dir=*)
            install_dir="${1#*=}"
            [ -n "$install_dir" ] || bad_usage "--install-dir needs a folder"
            shift
            ;;
        --port)
            [ $# -ge 2 ] && [ -n "$2" ] || bad_usage "--port needs a number"
            port="$2"
            shift 2
            ;;
        --port=*)
            port="${1#*=}"
            [ -n "$port" ] || bad_usage "--port needs a number"
            shift
            ;;
        --dev) dev=1; shift ;;
        --service) service=1; shift ;;
        -h | --help) usage; exit 0 ;;
        *) bad_usage "unknown option: $1" ;;
    esac
done

if [ -n "$port" ]; then
    case "$port" in
        *[!0-9]*) bad_usage "--port must be a number from 1 to 65535, not $port" ;;
    esac
    if [ "${#port}" -gt 5 ] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        bad_usage "--port must be a number from 1 to 65535, not $port"
    fi
fi
if [ "$service" -eq 1 ] && [ "$(uname -s)" != "Linux" ]; then
    bad_usage "--service writes a systemd user unit, which needs Linux (this is $(uname -s))"
fi

extras="ai,ssh"
if [ "$dev" -eq 1 ]; then extras="ai,ssh,dev"; fi
port_args=""
if [ -n "$port" ]; then port_args=" --port $port"; fi
repo="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

step "Looking for Python $MIN_PYTHON or newer"
if ! find_python; then
    die "Python $MIN_PYTHON or newer was not found (tried python3, python3.11 to python3.16 and python). Install it with your package manager or from $PYTHON_DOWNLOAD, or set ATRIUM_PYTHON, then run this installer again."
fi
printf '    Python %s: %s\n' "${python_info%%|*}" "${python_info#*|}"

step "Checking for git"
if command -v git >/dev/null 2>&1; then
    printf '    %s\n' "$(command -v git)"
else
    warn "git was not found. Atrium starts without it, but importing tools from GitHub and code patches need git: install it ($GIT_DOWNLOAD), then restart Atrium."
fi

target="$repo"
if [ -n "$install_dir" ]; then
    step "Copying Atrium to $install_dir"
    "${PYTHON[@]}" -I "$(native "$repo/scripts/install_copy.py")" "$(native "$repo")" "$(native "$install_dir")" \
        || die "could not copy Atrium to $install_dir"
    target="$(cd -- "$install_dir" && pwd -P)"
fi

venv="$target/.venv"
# A venv made by a Windows Python (Git Bash) has Scripts/*.exe, everywhere else bin/.
venv_paths() {
    if [ -d "$venv/Scripts" ] && [ ! -d "$venv/bin" ]; then
        venv_rel=".venv/Scripts"
        exe=".exe"
    else
        venv_rel=".venv/bin"
        exe=""
    fi
    venv_python="$target/$venv_rel/python$exe"
    venv_atrium="$target/$venv_rel/atrium$exe"
}
venv_paths
if [ -e "$venv_python" ] && existing="$(probe "$venv_python")" && "$venv_python" -m pip --version >/dev/null 2>&1; then
    step "Reusing the virtual environment in $venv (Python ${existing%%|*})"
else
    venv_hint="(on Debian or Ubuntu, install the python3-venv package for your Python first, e.g. sudo apt install python3-venv)"
    if [ -d "$venv" ]; then
        step "Recreating the virtual environment in $venv (it does not run Python $MIN_PYTHON or newer with pip)"
        "${PYTHON[@]}" -m venv --clear "$(native "$venv")" || die "could not recreate the virtual environment $venv_hint"
    else
        step "Creating the virtual environment in $venv"
        "${PYTHON[@]}" -m venv "$(native "$venv")" || die "could not create the virtual environment $venv_hint"
    fi
    venv_paths
    [ -e "$venv_python" ] || die "the virtual environment has no Python at $venv_python"
fi

step "Upgrading pip"
"$venv_python" -m pip install --upgrade pip || die "could not upgrade pip"
step "Installing Atrium with the $extras extras"
# Install from inside the folder so no path has to be converted between Git Bash and a Windows Python.
(cd -- "$target" && "$venv_python" -m pip install --editable ".[$extras]") || die "could not install Atrium"

step "Checking the installation"
check="$("$venv_atrium" --help 2>&1)" || die "atrium --help failed:
$check"

env_file="$target/.env"
if [ -e "$env_file" ]; then
    step "Keeping your settings in $env_file"
elif [ -f "$target/.env.example" ]; then
    step "Creating $env_file from .env.example"
    (umask 077 && cp -- "$target/.env.example" "$env_file")
else
    warn ".env.example is missing, so no .env was created."
fi

start="$target/start-atrium.sh"
step "Writing $start"
cat >"$start" <<EOF
#!/usr/bin/env bash
# Starts Atrium. Written by install.sh - run the installer again to rewrite it.
# Settings live in .env next to this file; extra arguments are passed on (e.g. --port 8711).
set -euo pipefail
cd -- "\$(dirname -- "\${BASH_SOURCE[0]}")"
exec ./$venv_rel/atrium$exe$port_args "\$@"
EOF
chmod +x "$start"

unit=""
if [ "$service" -eq 1 ]; then
    case "$target" in
        *'$'* | *$'\n'* | *$'\t'*) die "the systemd unit cannot be written for a folder whose path contains \$, a tab or a line break: $target" ;;
    esac
    unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
    unit="$unit_dir/atrium.service"
    step "Writing the systemd user unit $unit (not enabled)"
    mkdir -p -- "$unit_dir"
    cat >"$unit" <<EOF
# Atrium as a systemd user service. Written by install.sh - run the installer again with --service to rewrite it.
[Unit]
Description=Atrium - the agent-run tool hub

[Service]
Type=simple
WorkingDirectory=$(unit_path "$target")
ExecStart="$(unit_quoted "$target/$venv_rel/atrium$exe")" serve$port_args
Environment=PYTHONUNBUFFERED=1
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF
fi

address="http://127.0.0.1:${port:-8710}"
printf '\nAtrium is installed in %s\n\n' "$target"
printf 'Next steps:\n'
if [ -n "$unit" ]; then
    printf '  1. Start Atrium in this terminal:\n'
    printf '       "%s"\n' "$start"
    printf '     or as a service that also starts when you log in:\n'
    printf '       systemctl --user daemon-reload\n'
    printf '       systemctl --user enable --now atrium.service\n'
    printf '       systemctl --user status atrium.service    # its log shows the setup link of step 2\n'
    printf '     Optional, to keep it running while you are logged out: loginctl enable-linger "%s"\n' "${USER:-$(id -un)}"
else
    printf '  1. Start Atrium:\n'
    printf '       "%s"\n' "$start"
fi
printf '  2. The first start prints a one-time setup link like this one:\n'
printf '       First run: create the administrator at %s/#/setup?token=...\n' "$address"
printf '     Open that link in your browser and create the administrator account.\n'
printf '  3. Later, sign in at %s. Optional: put an Anthropic API key in\n' "$address"
printf '     %s (ANTHROPIC_API_KEY) so the agents can use Claude.\n' "$env_file"
