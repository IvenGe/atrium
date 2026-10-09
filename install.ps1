#Requires -Version 5.1
<#
.SYNOPSIS
    Installs Atrium on Windows: a Python virtual environment, start scripts and a desktop shortcut.

.DESCRIPTION
    Run it from a clone of the repository:

        powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1

    It finds Python 3.11 or newer (the py launcher or python on PATH; set ATRIUM_PYTHON to the full path of a
    python.exe to choose one), checks for git, creates .venv, installs Atrium with the ai and ssh extras, copies
    .env.example to .env when there is no .env yet and writes start-atrium.cmd and start-atrium.ps1.

    Safe to run again, e.g. after git pull: it reuses .venv, updates the installed package, rewrites the start
    scripts and the shortcut, and never touches an existing .env or the hub's data (.hub).

.PARAMETER InstallDir
    Copy the program to this folder and install it there. Default: this repository folder.

.PARAMETER Port
    Port the start scripts pass to the hub. Without it the hub uses HUB_PORT from .env (8710).

.PARAMETER NoShortcut
    Do not put an "Atrium" shortcut on the desktop.

.PARAMETER Dev
    Also install the development extras (pytest).

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -InstallDir "$env:LOCALAPPDATA\Atrium" -Port 8711
#>
[CmdletBinding()]
param(
    [string]$InstallDir = '',
    [ValidateRange(1, 65535)]
    [int]$Port,
    [switch]$NoShortcut,
    [switch]$Dev
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$PythonDownload = 'https://www.python.org/downloads/windows/'
$GitDownload = 'https://git-scm.com/downloads/win'
$MinimumPython = [version]'3.11'
$PortGiven = $PSBoundParameters.ContainsKey('Port')
$Extras = if ($Dev) { 'ai,ssh,dev' } else { 'ai,ssh' }

function Write-Step([string]$Message) {
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Invoke-Checked([string]$FilePath, [string[]]$Arguments) {
    # Native programs fail through their exit code; what they write to stderr (pip notices) is not an error.
    $ErrorActionPreference = 'Continue'
    & $FilePath @Arguments 2>&1 | ForEach-Object { Write-Host "$_" }
    if ($LASTEXITCODE -ne 0) {
        throw "$(Split-Path -Leaf $FilePath) $($Arguments -join ' ') failed (exit code $LASTEXITCODE)."
    }
}

function Get-PythonInfo([string]$Command, [string[]]$Arguments = @()) {
    # Version and full path of a working Python, or $null (missing, the Microsoft Store alias, Python 2, ...).
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) { return $null }
    $ErrorActionPreference = 'Continue'
    $probe = 'import sys; print(*sys.version_info[:3]); print(sys.executable)'
    try {
        $lines = @(& $Command @Arguments -c $probe 2>$null)
    } catch {
        return $null
    }
    if ($LASTEXITCODE -ne 0 -or $lines.Count -lt 2) { return $null }
    $version = $null
    if (-not [version]::TryParse(("$($lines[0])".Trim() -replace '\s+', '.'), [ref]$version)) { return $null }
    New-Object psobject -Property @{ Version = $version; Path = "$($lines[1])".Trim() }
}

function Find-Python {
    if ($env:ATRIUM_PYTHON) {
        $info = Get-PythonInfo $env:ATRIUM_PYTHON
        if ($info -and $info.Version -ge $MinimumPython) { return $info }
        throw "ATRIUM_PYTHON ($env:ATRIUM_PYTHON) is not a working Python $MinimumPython or newer."
    }
    # Assumption (docs.python.org, "Python install manager"): while no runtime is installed, the new py command
    # installs one on any launch. This setting keeps the probe from downloading anything.
    $previous = $env:PYTHON_MANAGER_AUTOMATIC_INSTALL
    $env:PYTHON_MANAGER_AUTOMATIC_INSTALL = 'false'
    try {
        foreach ($candidate in 'py -3', 'python', 'python3', 'py -3.14', 'py -3.13', 'py -3.12', 'py -3.11') {
            $words = @($candidate -split ' ')
            $info = Get-PythonInfo -Command $words[0] -Arguments @($words | Select-Object -Skip 1)
            if ($info -and $info.Version -ge $MinimumPython) { return $info }
        }
    } finally {
        $env:PYTHON_MANAGER_AUTOMATIC_INSTALL = $previous
    }
    return $null
}

function Test-Pip([string]$Python) {
    $ErrorActionPreference = 'Continue'
    & $Python -m pip --version *> $null
    $LASTEXITCODE -eq 0
}

function Test-Program([string]$FilePath, [string[]]$Arguments) {
    $ErrorActionPreference = 'Continue'
    $output = & $FilePath @Arguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "$(Split-Path -Leaf $FilePath) $($Arguments -join ' ') failed:`n$output"
    }
}

function New-DesktopShortcut([string]$Folder, [string]$Target, [string]$WorkingDirectory) {
    $path = Join-Path $Folder 'Atrium.lnk'
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut($path)
    $link.TargetPath = $Target
    $link.WorkingDirectory = $WorkingDirectory
    $link.Description = 'Start Atrium'
    $link.Save()
    $path
}

function Install-Atrium {
    $repo = $PSScriptRoot
    $target = $repo
    if ($InstallDir) {
        $target = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InstallDir)
        if ($target -notmatch '^[A-Za-z]:\\$') { $target = $target.TrimEnd('\', '/') }
    }

    Write-Step "Looking for Python $MinimumPython or newer"
    $python = Find-Python
    if (-not $python) {
        throw ("Python $MinimumPython or newer was not found (tried the py launcher, python and python3). Install it " +
               "from $PythonDownload (tick 'Add python.exe to PATH'), then run this installer again.")
    }
    Write-Host "    Python $($python.Version): $($python.Path)"

    Write-Step 'Checking for git'
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($git) {
        Write-Host "    $($git.Path)"
    } else {
        Write-Warning ("git was not found. Atrium starts without it, but importing tools from GitHub and code " +
                       "patches need git: install it from $GitDownload, then restart Atrium.")
    }

    if ($target -ne $repo) {
        Write-Step "Copying Atrium to $target"
        Invoke-Checked $python.Path @('-I', (Join-Path $repo 'scripts\install_copy.py'), $repo, $target)
    }

    $venv = Join-Path $target '.venv'
    $venvPython = Join-Path $venv 'Scripts\python.exe'
    $existing = $null
    if (Test-Path -LiteralPath $venvPython) { $existing = Get-PythonInfo $venvPython }
    if ($existing -and $existing.Version -ge $MinimumPython -and (Test-Pip $venvPython)) {
        Write-Step "Reusing the virtual environment in $venv (Python $($existing.Version))"
    } elseif (Test-Path -LiteralPath $venv) {
        Write-Step "Recreating the virtual environment in $venv (it does not run Python $MinimumPython or newer with pip)"
        Invoke-Checked $python.Path @('-m', 'venv', '--clear', $venv)
    } else {
        Write-Step "Creating the virtual environment in $venv"
        Invoke-Checked $python.Path @('-m', 'venv', $venv)
    }

    Write-Step 'Upgrading pip'
    Invoke-Checked $venvPython @('-m', 'pip', 'install', '--upgrade', 'pip')
    Write-Step "Installing Atrium with the $Extras extras"
    Invoke-Checked $venvPython @('-m', 'pip', 'install', '--editable', ('{0}[{1}]' -f $target, $Extras))

    Write-Step 'Checking the installation'
    Test-Program (Join-Path $venv 'Scripts\atrium.exe') @('--help')

    $envFile = Join-Path $target '.env'
    $envExample = Join-Path $target '.env.example'
    if (Test-Path -LiteralPath $envFile) {
        Write-Step "Keeping your settings in $envFile"
    } elseif (Test-Path -LiteralPath $envExample) {
        Write-Step "Creating $envFile from .env.example"
        Copy-Item -LiteralPath $envExample -Destination $envFile
    } else {
        Write-Warning '.env.example is missing, so no .env was created.'
    }

    $portArgument = ''
    if ($PortGiven) { $portArgument = " --port $Port" }
    $startCmd = Join-Path $target 'start-atrium.cmd'
    $startPs1 = Join-Path $target 'start-atrium.ps1'
    Write-Step "Writing $startCmd and start-atrium.ps1"
    Set-Content -LiteralPath $startCmd -Encoding Ascii -Value @(
        '@echo off'
        'rem Starts Atrium. Written by install.ps1 - run the installer again to rewrite it.'
        'rem Settings live in .env next to this file; extra arguments are passed on (e.g. --port 8711).'
        'setlocal'
        'cd /d "%~dp0"'
        ('".venv\Scripts\atrium.exe"{0} %*' -f $portArgument)
        'set "ATRIUM_EXIT=%ERRORLEVEL%"'
        'if not "%ATRIUM_EXIT%"=="0" pause'
        'exit /b %ATRIUM_EXIT%'
    )
    Set-Content -LiteralPath $startPs1 -Encoding Ascii -Value @(
        '# Starts Atrium. Written by install.ps1 - run the installer again to rewrite it.'
        '# Settings live in .env next to this file; extra arguments are passed on (e.g. --port 8711).'
        '$code = 1'
        'Push-Location -LiteralPath $PSScriptRoot'
        'try {'
        ('    & (Join-Path $PSScriptRoot ''.venv\Scripts\atrium.exe''){0} @args' -f $portArgument)
        '    $code = $LASTEXITCODE'
        '} finally {'
        '    Pop-Location'
        '}'
        'exit $code'
    )

    $shortcut = $null
    if ($NoShortcut) {
        Write-Step 'Skipping the desktop shortcut (-NoShortcut)'
    } else {
        $desktop = [Environment]::GetFolderPath('Desktop')
        if ($desktop -and (Test-Path -LiteralPath $desktop)) {
            $shortcut = New-DesktopShortcut $desktop $startCmd $target
            Write-Step "Desktop shortcut: $shortcut"
        } else {
            Write-Warning 'No desktop folder was found, so no shortcut was created.'
        }
    }

    $address = 'http://127.0.0.1:8710'
    if ($PortGiven) { $address = "http://127.0.0.1:$Port" }
    Write-Host ''
    Write-Host "Atrium is installed in $target" -ForegroundColor Green
    Write-Host ''
    Write-Host 'Next steps:'
    if ($shortcut) {
        Write-Host '  1. Start Atrium with the Atrium shortcut on your desktop, or run:'
    } else {
        Write-Host '  1. Start Atrium:'
    }
    Write-Host "       `"$startCmd`""
    Write-Host '  2. The first start prints a one-time setup link like this one:'
    Write-Host "       First run: create the administrator at $address/#/setup?token=..."
    Write-Host '     Open that link in your browser and create the administrator account.'
    Write-Host "  3. Later, sign in at $address. Optional: put an Anthropic API key in"
    Write-Host "     $envFile (ANTHROPIC_API_KEY) so the agents can use Claude."
}

try {
    Install-Atrium
} catch {
    Write-Host ''
    Write-Host "Installation failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'Fix the problem and run the installer again; it is safe to rerun. If Atrium is running from the install folder, stop it first.'
    exit 1
}
