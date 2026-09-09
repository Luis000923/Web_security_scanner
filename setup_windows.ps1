<#
.SYNOPSIS
    Quick-start bootstrapper for Web_security_scanner on Windows.

.DESCRIPTION
    Zero-touch setup for a fresh Windows machine (e.g. a university lab box):

        1. Git (Git Bash)      via winget  Git.Git
        2. Python 3.11         via winget  Python.Python.3.11
        3. uv                  via https://astral.sh/uv/install.ps1
        4. git clone + git checkout ai-agent
        5. runs `bash run_pipeline.sh` through Git Bash, automatically

    Everything is idempotent: already-installed tools are detected and skipped,
    and an existing clone is reused (fetch + checkout) instead of re-cloned.

    No administrator rights are required — winget installs per-user by default,
    and uv installs into %USERPROFILE%\.local\bin.

.PARAMETER InstallDir
    Parent directory that will contain the clone. Defaults to the directory the
    script is run from. Ignored when the script already lives inside the repo.

.PARAMETER Branch
    Branch to check out. Default: ai-agent.

.PARAMETER RepoUrl
    Clone URL. Default: https://github.com/Luis000923/Web_security_scanner.git

.PARAMETER SkipPipeline
    Do the setup but stop before launching run_pipeline.sh.

.PARAMETER PipelineArgs
    Extra arguments forwarded verbatim to run_pipeline.sh,
    e.g. -PipelineArgs '--regen-data','--epochs','2'

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1

.EXAMPLE
    .\setup_windows.ps1 -PipelineArgs '--skip-train'
#>

[CmdletBinding()]
param(
    [string]   $InstallDir    = $PSScriptRoot,
    [string]   $Branch        = 'ai-agent',
    [string]   $RepoUrl       = 'https://github.com/Luis000923/Web_security_scanner.git',
    [switch]   $SkipPipeline,
    [string[]] $PipelineArgs  = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'   # keeps Invoke-WebRequest fast

if (-not $InstallDir) { $InstallDir = (Get-Location).Path }

# ---------------------------------------------------------------------------
# presentation helpers
# ---------------------------------------------------------------------------
$script:Step = 0
function Write-Step($msg) {
    $script:Step++
    Write-Host ''
    Write-Host ("== [{0}] {1}" -f $script:Step, $msg) -ForegroundColor Cyan
}
function Write-Info($msg) { Write-Host "   $msg" }
function Write-Ok  ($msg) { Write-Host "   [OK] $msg"   -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "   [!]  $msg"   -ForegroundColor Yellow }
function Stop-Setup($msg) {
    Write-Host ''
    Write-Host "X SETUP ABORTED  $msg" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# environment helpers
# ---------------------------------------------------------------------------

# winget and the uv installer edit the *persisted* PATH, which does not reach an
# already-running process. Re-read Machine + User PATH so freshly installed
# tools become callable without reopening the terminal.
function Update-SessionPath {
    $parts = @()
    foreach ($scope in 'Machine', 'User') {
        $v = [Environment]::GetEnvironmentVariable('Path', $scope)
        if ($v) { $parts += $v }
    }
    # keep anything this session added that is not persisted (e.g. our own hints)
    $parts += $env:Path
    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $merged = foreach ($p in ($parts -join ';').Split(';')) {
        $p = $p.Trim()
        if ($p -and $seen.Add($p)) { $p }
    }
    $env:Path = ($merged -join ';')
}

function Test-Command($name) {
    $null -ne (Get-Command $name -ErrorAction SilentlyContinue)
}

# `bash.exe` in System32 is the WSL launcher, not Git Bash — it would run the
# pipeline inside a Linux distro (or fail outright), so it is always rejected.
function Resolve-GitBash {
    $candidates = New-Object System.Collections.Generic.List[string]

    foreach ($cmd in @(Get-Command bash.exe -All -ErrorAction SilentlyContinue)) {
        $candidates.Add($cmd.Source)
    }

    # git.exe lives in <git>\cmd or <git>\bin; bash.exe is in <git>\bin
    $git = Get-Command git.exe -ErrorAction SilentlyContinue
    if ($git) {
        $gitRoot = Split-Path (Split-Path $git.Source -Parent) -Parent
        $candidates.Add((Join-Path $gitRoot 'bin\bash.exe'))
        $candidates.Add((Join-Path $gitRoot 'usr\bin\bash.exe'))
    }

    foreach ($root in @(
        "$env:ProgramFiles\Git",
        "${env:ProgramFiles(x86)}\Git",
        "$env:LOCALAPPDATA\Programs\Git",
        "$env:ProgramW6432\Git",
        'C:\Program Files\Git')) {
        if ($root) {
            $candidates.Add((Join-Path $root 'bin\bash.exe'))
            $candidates.Add((Join-Path $root 'usr\bin\bash.exe'))
        }
    }

    foreach ($c in $candidates) {
        if (-not $c) { continue }
        if (-not (Test-Path -LiteralPath $c -PathType Leaf)) { continue }
        $full = (Resolve-Path -LiteralPath $c).Path
        if ($full -like "$env:SystemRoot\System32\*") { continue }   # WSL
        if ($full -like "$env:SystemRoot\SysWOW64\*") { continue }   # WSL (32-bit view)
        return $full
    }
    return $null
}

function Invoke-Winget([string]$Id, [string]$Label) {
    Write-Info "installing $Label via winget ($Id) ..."
    & winget install --id $Id -e --source winget `
        --accept-package-agreements --accept-source-agreements
    $rc = $LASTEXITCODE
    # winget has a whole family of non-zero "nothing to do" codes (already
    # installed, no applicable upgrade, ...) that differ between versions, so a
    # non-zero exit is only a warning here: the caller decides by checking
    # whether the tool actually became callable.
    if ($rc -ne 0) {
        Write-Warn "winget returned exit code $rc for $Label - verifying anyway"
    }
    Update-SessionPath
}

Write-Host ''
Write-Host 'Web_security_scanner - Windows quick start' -ForegroundColor Cyan
Write-Host ("  branch : {0}" -f $Branch)
Write-Host ("  target : {0}" -f $InstallDir)

$startedAt = Get-Date
Update-SessionPath

# ---------------------------------------------------------------------------
# 0. winget availability
# ---------------------------------------------------------------------------
Write-Step 'Checking winget (App Installer)'
if (Test-Command 'winget') {
    Write-Ok "winget present: $(& winget --version)"
} else {
    Stop-Setup @'
winget was not found. Install "App Installer" from the Microsoft Store
(https://apps.microsoft.com/detail/9NBLGGH4NNS1), then re-run this script.
'@
}

# ---------------------------------------------------------------------------
# 1. Git (Git Bash)
# ---------------------------------------------------------------------------
Write-Step 'Git / Git Bash'
if (Test-Command 'git') {
    Write-Ok "git already installed: $(& git --version)"
} else {
    Invoke-Winget -Id 'Git.Git' -Label 'Git'
    if (-not (Test-Command 'git')) {
        # winget put git on the persisted PATH but the shim may lag; add it by hand
        foreach ($root in @("$env:ProgramFiles\Git", "$env:LOCALAPPDATA\Programs\Git")) {
            $cmd = Join-Path $root 'cmd'
            if (Test-Path -LiteralPath (Join-Path $cmd 'git.exe')) {
                $env:Path = "$cmd;$env:Path"
            }
        }
    }
    if (Test-Command 'git') { Write-Ok "git installed: $(& git --version)" }
    else { Stop-Setup 'git is still not callable after installation - open a new terminal and re-run.' }
}

# ---------------------------------------------------------------------------
# 2. Python 3.11
# ---------------------------------------------------------------------------
Write-Step 'Python 3.11'
$pythonOk = $false
if (Test-Command 'py') {
    # the launcher is the reliable way to ask "is a 3.11/3.12 present?"
    & py -3.11 --version *> $null
    if ($LASTEXITCODE -eq 0) { $pythonOk = $true; Write-Ok "python 3.11 present: $(& py -3.11 --version)" }
    else {
        & py -3.12 --version *> $null
        if ($LASTEXITCODE -eq 0) { $pythonOk = $true; Write-Ok "python 3.12 present: $(& py -3.12 --version)" }
    }
}
if (-not $pythonOk -and (Test-Command 'python')) {
    $v = (& python --version 2>&1) -join ''
    if ($v -match '3\.(11|12)\.') { $pythonOk = $true; Write-Ok "python present: $v" }
    else { Write-Warn "found $v - 3.11/3.12 is preferred, installing it alongside" }
}
if (-not $pythonOk) {
    Invoke-Winget -Id 'Python.Python.3.11' -Label 'Python 3.11'
    if (Test-Command 'py') {
        & py -3.11 --version *> $null
        if ($LASTEXITCODE -eq 0) { Write-Ok "python 3.11 installed: $(& py -3.11 --version)" }
        else { Write-Warn 'python 3.11 not visible yet - uv will download its own interpreter' }
    } else {
        Write-Warn 'python launcher not on PATH yet - uv will download its own interpreter'
    }
    Write-Info 'uv resolves the interpreter itself when creating .venv'
}

# ---------------------------------------------------------------------------
# 3. uv
# ---------------------------------------------------------------------------
Write-Step 'uv package manager'
if (Test-Command 'uv') {
    Write-Ok "uv already installed: $(& uv --version)"
} else {
    Write-Info 'installing uv from https://astral.sh/uv/install.ps1 ...'
    try {
        # .Content is required: piping the response *object* straight into
        # Invoke-Expression stringifies the object, not the script body.
        (Invoke-WebRequest -Uri 'https://astral.sh/uv/install.ps1' -UseBasicParsing).Content |
            Invoke-Expression
    } catch {
        Stop-Setup "could not install uv: $($_.Exception.Message)"
    }
    Update-SessionPath
    $uvBin = Join-Path $env:USERPROFILE '.local\bin'
    if ((Test-Path -LiteralPath (Join-Path $uvBin 'uv.exe')) -and ($env:Path -notlike "*$uvBin*")) {
        $env:Path = "$uvBin;$env:Path"
    }
    if (Test-Command 'uv') { Write-Ok "uv installed: $(& uv --version)" }
    else { Stop-Setup 'uv is still not callable after installation - open a new terminal and re-run.' }
}

# ---------------------------------------------------------------------------
# 4. clone / update the repository
# ---------------------------------------------------------------------------
Write-Step "Repository (branch: $Branch)"

# If this script is already sitting inside the checkout, work in place.
if ($PSScriptRoot -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'run_pipeline.sh'))) {
    $repo = $PSScriptRoot
    Write-Ok "running from inside the checkout: $repo"
} else {
    if (-not (Test-Path -LiteralPath $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }
    $repo = Join-Path $InstallDir 'Web_security_scanner'
    if (Test-Path -LiteralPath (Join-Path $repo '.git')) {
        Write-Ok "existing clone found: $repo"
    } else {
        if (Test-Path -LiteralPath $repo) {
            Stop-Setup "$repo exists but is not a git checkout - move it aside and re-run."
        }
        Write-Info "cloning $RepoUrl ..."
        Push-Location $InstallDir
        try   { & git clone $RepoUrl; if ($LASTEXITCODE -ne 0) { Stop-Setup 'git clone failed' } }
        finally { Pop-Location }
        Write-Ok "cloned into $repo"
    }
}

Set-Location -LiteralPath $repo

& git fetch origin $Branch --quiet
if ($LASTEXITCODE -ne 0) { Write-Warn "could not fetch origin/$Branch - using whatever is local" }

& git checkout $Branch
if ($LASTEXITCODE -ne 0) { Stop-Setup "git checkout $Branch failed" }
Write-Ok "on branch $(& git rev-parse --abbrev-ref HEAD) @ $(& git rev-parse --short HEAD)"

# ---------------------------------------------------------------------------
# 5. locate Git Bash and launch the pipeline
# ---------------------------------------------------------------------------
Write-Step 'Launching run_pipeline.sh through Git Bash'

$bash = Resolve-GitBash
if (-not $bash) {
    Stop-Setup @'
Git Bash (bash.exe) was not found. Expected it at
"C:\Program Files\Git\bin\bash.exe" after the Git install. Open a new terminal
so the PATH refreshes and re-run this script.
'@
}
Write-Ok "bash: $bash"

if (-not (Test-Path -LiteralPath (Join-Path $repo 'run_pipeline.sh'))) {
    Stop-Setup "run_pipeline.sh not found in $repo"
}

if ($SkipPipeline) {
    Write-Warn 'skipping the pipeline (-SkipPipeline)'
    Write-Info "run it later with:  & '$bash' run_pipeline.sh"
} else {
    if ($PipelineArgs.Count) { Write-Info "extra args: $($PipelineArgs -join ' ')" }
    Write-Info 'handing over to run_pipeline.sh - this can take a long while'
    Write-Host ''

    # MSYS2_ARG_CONV_EXCL stops Git Bash from mangling "--flag=/value" style
    # arguments into Windows paths on their way to the script.
    $env:MSYS2_ARG_CONV_EXCL = '*'
    $env:MSYS_NO_PATHCONV    = '1'

    & $bash 'run_pipeline.sh' @PipelineArgs
    $rc = $LASTEXITCODE
    if ($rc -ne 0) { Stop-Setup "run_pipeline.sh exited with code $rc" }
}

$took = (Get-Date) - $startedAt
Write-Host ''
Write-Host ("OK  SETUP COMPLETE  total time: {0:hh\:mm\:ss}" -f $took) -ForegroundColor Green
Write-Host ("    repo: {0}" -f $repo)
