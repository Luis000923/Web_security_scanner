<#
.SYNOPSIS
    One-shot bootstrapper for Web_security_scanner on Windows: pre-flight check,
    toolchain install, clone, and an unattended pipeline run.

.DESCRIPTION
    Designed to be the only file you need on a bare Windows machine (e.g. a
    university lab PC). Two phases, one command:

    PHASE 1 - pre-flight (Invoke-PreflightCheck)
        Cheap, read-only checks that run BEFORE anything is downloaded, so a
        machine that cannot possibly succeed fails in seconds instead of after
        a 6 GB torch download: 64-bit OS, PowerShell version, winget, disk
        space, write access, and reachability of github.com / huggingface.co.
        Blocking failures abort in red. Warnings print in yellow and continue.

    PHASE 2 - setup + run (fully unattended)
        1. Git (Git Bash)      via winget  Git.Git
        2. Python 3.11         via winget  Python.Python.3.11
        3. uv                  via https://astral.sh/uv/install.ps1
        4. git clone + git checkout ai-agent
        5. bash run_pipeline.sh   through Git Bash

    Everything is idempotent: installed tools are detected and skipped, and an
    existing clone is reused (fetch + checkout) instead of re-cloned. No
    administrator rights are required - winget installs per-user by default and
    uv installs into %USERPROFILE%\.local\bin.

    check_windows_env.ps1 is the standalone entry point to phase 1; it delegates
    here so the checks have exactly one implementation.

.PARAMETER InstallDir
    Parent directory that will contain the clone. Defaults to the directory the
    script is run from. Ignored when the script already lives inside the repo.

.PARAMETER Branch
    Branch to check out. Default: ai-agent.

.PARAMETER RepoUrl
    Clone URL. Default: https://github.com/Luis000923/Web_security_scanner.git

.PARAMETER CheckOnly
    Run the pre-flight check and exit. Exit code 0 = ready (warnings allowed),
    1 = at least one blocking problem.

.PARAMETER SkipPreflight
    Jump straight to phase 2 without checking anything.

.PARAMETER Force
    Continue even when the pre-flight reports blocking problems. At your own
    risk: these are the checks that predict a failed install.

.PARAMETER SkipPipeline
    Do the setup but stop before launching run_pipeline.sh.

.PARAMETER PipelineArgs
    Extra arguments forwarded verbatim to run_pipeline.sh,
    e.g. -PipelineArgs '--regen-data','--epochs','2'

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1

.EXAMPLE
    .\setup_windows.ps1 -CheckOnly

.EXAMPLE
    .\setup_windows.ps1 -PipelineArgs '--skip-train'
#>

[CmdletBinding()]
param(
    [string]   $InstallDir    = $PSScriptRoot,
    [string]   $Branch        = 'ai-agent',
    [string]   $RepoUrl       = 'https://github.com/Luis000923/Web_security_scanner.git',
    [switch]   $CheckOnly,
    [switch]   $SkipPreflight,
    [switch]   $Force,
    [switch]   $SkipPipeline,
    [string[]] $PipelineArgs  = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'   # keeps Invoke-WebRequest fast

# Windows PowerShell 5.1 still negotiates TLS 1.0 by default on older images,
# which huggingface.co and astral.sh both refuse. Opt in before any web call.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    Write-Verbose "could not raise the TLS floor: $($_.Exception.Message)"
}

if (-not $InstallDir) { $InstallDir = (Get-Location).Path }

# Disk budget, in GB. A tier-3 run pulls a 14B 4-bit checkpoint (~9 GB), the
# CUDA torch wheels (~6 GB), and writes a merged fp16 adapter (~28 GB).
$script:DiskBlockGB = 15
$script:DiskWarnGB  = 50

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

# ===========================================================================
# PHASE 1 - pre-flight check
# ===========================================================================

# Every check returns one of these. Status is Pass | Warn | Block.
function New-CheckResult {
    param(
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][ValidateSet('Pass', 'Warn', 'Block')][string] $Status,
        [string] $Detail = '',
        [string] $Remedy = ''
    )
    [pscustomobject]@{
        Name   = $Name
        Status = $Status
        Detail = $Detail
        Remedy = $Remedy
    }
}

function Test-Endpoint {
    <#
      Reachability, not correctness: any HTTP response - including a 403 or 405
      from a host that rejects HEAD - proves we got through DNS, TLS and any
      proxy, which is all the pre-flight needs to know.
    #>
    param([Parameter(Mandatory)][string] $Url, [int] $TimeoutSec = 15)
    try {
        $r = Invoke-WebRequest -Uri $Url -Method Head -UseBasicParsing `
                               -TimeoutSec $TimeoutSec -ErrorAction Stop
        return [pscustomobject]@{ Ok = $true; Detail = "HTTP $([int]$r.StatusCode)" }
    } catch {
        $status = $null
        try {
            $resp = $_.Exception.Response
            if ($resp) { $status = [int]$resp.StatusCode }
        } catch { $status = $null }
        if ($status) {
            return [pscustomobject]@{ Ok = $true; Detail = "HTTP $status" }
        }
        return [pscustomobject]@{ Ok = $false; Detail = $_.Exception.Message }
    }
}

function Test-Command($name) {
    $null -ne (Get-Command $name -ErrorAction SilentlyContinue)
}

function Get-FreeSpaceGB {
    <# Free GB on the volume that holds $Path, or $null if it cannot be read. #>
    param([Parameter(Mandatory)][string] $Path)
    try {
        $probe = $Path
        while ($probe -and -not (Test-Path -LiteralPath $probe)) {
            $parent = Split-Path $probe -Parent
            if ($parent -eq $probe) { break }
            $probe = $parent
        }
        if (-not $probe) { return $null }
        $root = [System.IO.Path]::GetPathRoot((Resolve-Path -LiteralPath $probe).Path)
        if (-not $root) { return $null }
        return [math]::Round(([System.IO.DriveInfo]::new($root)).AvailableFreeSpace / 1GB, 1)
    } catch {
        return $null
    }
}

function Get-GpuProfile {
    <#
      Reads VRAM through nvidia-smi and mirrors the tier table in
      ai_module/auto_select_model.py so the operator sees, before anything is
      downloaded, which model the pipeline will pick. That Python module stays
      authoritative - this is a preview, not the decision.
    #>
    if (-not (Test-Command 'nvidia-smi')) { return $null }
    try {
        $raw = & nvidia-smi --query-gpu=name,memory.total --format=csv,noheader,nounits 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $raw) { return $null }
        $first = @($raw)[0]
        $parts = $first -split ',', 2
        if ($parts.Count -lt 2) { return $null }
        $name   = $parts[0].Trim()
        $vramGB = [math]::Round([double]($parts[1].Trim()) / 1024, 1)
        $tier = if ($vramGB -le 7)  { '1 (1.5B)' }
                elseif ($vramGB -le 16) { '2 (7B)' }
                else                    { '3 (14B)' }
        return [pscustomobject]@{ Name = $name; VramGB = $vramGB; Tier = $tier }
    } catch {
        return $null
    }
}

function Invoke-PreflightCheck {
    <#
      Read-only. Returns every result plus the Blocking/Warning subsets, so both
      -CheckOnly and the installer can decide what to do with them.
    #>
    param([Parameter(Mandatory)][string] $TargetDir)

    $results = New-Object System.Collections.Generic.List[object]

    # --- platform ----------------------------------------------------------
    $psv = $PSVersionTable.PSVersion
    if ($psv.Major -gt 5 -or ($psv.Major -eq 5 -and $psv.Minor -ge 1)) {
        $results.Add((New-CheckResult 'PowerShell' 'Pass' "v$psv"))
    } else {
        $results.Add((New-CheckResult 'PowerShell' 'Block' "v$psv is too old" `
            'Windows Management Framework 5.1+ is required (Windows 10 ships it).'))
    }

    # NB: must not be called $isWindows - PowerShell variable names are
    # case-insensitive, and $IsWindows is a read-only automatic variable in
    # PS 7, so assigning to it throws. Absent in 5.1, where "Windows" is implied.
    $onWindows = $true
    $isWinVar = Get-Variable -Name IsWindows -ErrorAction SilentlyContinue
    if ($isWinVar) { $onWindows = [bool]$isWinVar.Value }
    if (-not $onWindows) {
        $results.Add((New-CheckResult 'Operating system' 'Block' 'not Windows' `
            'This bootstrapper targets Windows. On Linux/macOS run ./run_pipeline.sh directly.'))
    } elseif ([Environment]::Is64BitOperatingSystem) {
        $results.Add((New-CheckResult 'Architecture' 'Pass' '64-bit Windows'))
    } else {
        $results.Add((New-CheckResult 'Architecture' 'Block' '32-bit Windows' `
            'torch and bitsandbytes publish no 32-bit wheels; a 64-bit OS is required.'))
    }

    # --- package manager ---------------------------------------------------
    # winget is only load-bearing when something still has to be installed:
    # a machine that already has git+python+uv does not need it at all.
    $hasGit    = Test-Command 'git'
    $hasUv     = Test-Command 'uv'
    $hasPython = (Test-Command 'python') -or (Test-Command 'py')
    $hasWinget = Test-Command 'winget'
    $needsInstall = -not ($hasGit -and $hasUv -and $hasPython)

    if ($hasWinget) {
        $wv = try { (& winget --version) -join '' } catch { 'unknown' }
        $results.Add((New-CheckResult 'winget' 'Pass' $wv))
    } elseif ($needsInstall) {
        $results.Add((New-CheckResult 'winget' 'Block' 'not found, and tools are missing' `
            'Install "App Installer" from the Microsoft Store: https://apps.microsoft.com/detail/9NBLGGH4NNS1'))
    } else {
        $results.Add((New-CheckResult 'winget' 'Warn' 'not found (nothing left to install)' `
            'Only needed to install Git/Python; both are already present.'))
    }

    # --- toolchain ---------------------------------------------------------
    # git is the one hard requirement the installer itself can satisfy, so it
    # blocks only when winget is ALSO missing - i.e. nothing can install it.
    if ($hasGit) {
        $gv = try { (& git --version) -join '' } catch { 'present' }
        $results.Add((New-CheckResult 'git' 'Pass' $gv))
    } elseif ($hasWinget) {
        $results.Add((New-CheckResult 'git' 'Warn' 'not installed' `
            'Will be installed via winget in phase 2.'))
    } else {
        $results.Add((New-CheckResult 'git' 'Block' 'not installed and no winget to install it' `
            'Install Git for Windows manually: https://git-scm.com/download/win'))
    }

    if ($hasPython) {
        $pv = try { (& python --version 2>&1) -join '' } catch { 'present' }
        $results.Add((New-CheckResult 'Python' 'Pass' $pv))
    } else {
        $results.Add((New-CheckResult 'Python' 'Warn' 'not installed' `
            'Will be installed via winget; uv can also provision its own interpreter.'))
    }

    if ($hasUv) {
        $uvv = try { (& uv --version) -join '' } catch { 'present' }
        $results.Add((New-CheckResult 'uv' 'Pass' $uvv))
    } else {
        $results.Add((New-CheckResult 'uv' 'Warn' 'not installed' `
            'Will be installed from https://astral.sh/uv/install.ps1 in phase 2.'))
    }

    # --- storage -----------------------------------------------------------
    $freeGB = Get-FreeSpaceGB -Path $TargetDir
    if ($null -eq $freeGB) {
        $results.Add((New-CheckResult 'Disk space' 'Warn' "could not read free space for $TargetDir"))
    } elseif ($freeGB -lt $script:DiskBlockGB) {
        $results.Add((New-CheckResult 'Disk space' 'Block' "$freeGB GB free at $TargetDir" `
            "At least $($script:DiskBlockGB) GB is needed for the CUDA wheels and one base model."))
    } elseif ($freeGB -lt $script:DiskWarnGB) {
        $results.Add((New-CheckResult 'Disk space' 'Warn' "$freeGB GB free at $TargetDir" `
            "A full tier-3 run (14B + merged fp16 adapter) wants ~$($script:DiskWarnGB) GB; a smaller model or --skip-train will still fit."))
    } else {
        $results.Add((New-CheckResult 'Disk space' 'Pass' "$freeGB GB free at $TargetDir"))
    }

    # The Hugging Face cache lands under the profile, which is often a different
    # (and smaller) volume than the checkout on a managed lab image.
    # Join-Path throws on a null parent, and USERPROFILE is absent in some
    # service/CI contexts, so fall back to the target volume rather than dying.
    $hfHome = if ($env:HF_HOME)     { $env:HF_HOME }
              elseif ($env:USERPROFILE) { Join-Path $env:USERPROFILE '.cache\huggingface' }
              else                  { $TargetDir }
    $hfFree = Get-FreeSpaceGB -Path $hfHome
    if ($null -ne $hfFree -and $null -ne $freeGB -and $hfFree -ne $freeGB) {
        if ($hfFree -lt $script:DiskBlockGB) {
            $results.Add((New-CheckResult 'HF cache space' 'Block' "$hfFree GB free at $hfHome" `
                'Point HF_HOME at a roomier volume, e.g. $env:HF_HOME="D:\hf-cache".'))
        } else {
            $results.Add((New-CheckResult 'HF cache space' 'Pass' "$hfFree GB free at $hfHome"))
        }
    }

    # --- write access ------------------------------------------------------
    try {
        if (-not (Test-Path -LiteralPath $TargetDir)) {
            New-Item -ItemType Directory -Path $TargetDir -Force -ErrorAction Stop | Out-Null
        }
        $probeFile = Join-Path $TargetDir ".preflight-$PID.tmp"
        [System.IO.File]::WriteAllText($probeFile, 'x')
        Remove-Item -LiteralPath $probeFile -Force -ErrorAction SilentlyContinue
        $results.Add((New-CheckResult 'Write access' 'Pass' $TargetDir))
    } catch {
        $results.Add((New-CheckResult 'Write access' 'Block' "cannot write to $TargetDir" `
            'Pick a writable -InstallDir, e.g. -InstallDir "$env:USERPROFILE\Documents".'))
    }

    # --- connectivity ------------------------------------------------------
    # github.com and huggingface.co are non-negotiable: without them there is no
    # clone and no model. The wheel mirrors only warn - a partial cache or a
    # local mirror can still carry the run.
    foreach ($ep in @(
        @{ Name = 'github.com';       Url = 'https://github.com';                Blocking = $true  },
        @{ Name = 'huggingface.co';   Url = 'https://huggingface.co';            Blocking = $true  },
        @{ Name = 'astral.sh (uv)';   Url = 'https://astral.sh/uv/install.ps1';  Blocking = $false },
        @{ Name = 'pypi.org';         Url = 'https://pypi.org/simple/';          Blocking = $false },
        @{ Name = 'pytorch wheels';   Url = 'https://download.pytorch.org/whl/cu128'; Blocking = $false }
    )) {
        $probe = Test-Endpoint -Url $ep.Url
        if ($probe.Ok) {
            $results.Add((New-CheckResult "Network: $($ep.Name)" 'Pass' $probe.Detail))
        } elseif ($ep.Blocking) {
            $results.Add((New-CheckResult "Network: $($ep.Name)" 'Block' $probe.Detail `
                'Check the connection, the campus proxy (HTTPS_PROXY), or a content filter.'))
        } else {
            $results.Add((New-CheckResult "Network: $($ep.Name)" 'Warn' $probe.Detail `
                'Non-fatal, but the dependency install will likely fail without it.'))
        }
    }

    if ($env:HTTPS_PROXY -or $env:HTTP_PROXY) {
        $results.Add((New-CheckResult 'Proxy' 'Warn' "HTTPS_PROXY=$($env:HTTPS_PROXY) HTTP_PROXY=$($env:HTTP_PROXY)" `
            'Git and uv honour these; make sure Git Bash inherits them too.'))
    }

    # --- GPU ---------------------------------------------------------------
    $gpu = Get-GpuProfile
    if ($gpu) {
        $results.Add((New-CheckResult 'GPU' 'Pass' `
            "$($gpu.Name), $($gpu.VramGB) GB VRAM -> auto-select tier $($gpu.Tier)"))
    } else {
        $results.Add((New-CheckResult 'GPU' 'Warn' 'no NVIDIA GPU detected (nvidia-smi absent or failed)' `
            'The pipeline will auto-select a CPU-sized model; training will be very slow.'))
    }

    # --- Windows quirks that bite later ------------------------------------
    try {
        $lp = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' `
                               -Name 'LongPathsEnabled' -ErrorAction Stop
        if ($lp.LongPathsEnabled -eq 1) {
            $results.Add((New-CheckResult 'Long paths' 'Pass' 'enabled'))
        } else {
            $results.Add((New-CheckResult 'Long paths' 'Warn' 'disabled (MAX_PATH = 260)' `
                'Deep Hugging Face cache paths can fail. Enable with: git config --system core.longpaths true'))
        }
    } catch {
        $results.Add((New-CheckResult 'Long paths' 'Warn' 'could not read the policy'))
    }

    try {
        $ram = [math]::Round((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory / 1GB, 1)
        if ($ram -ge 16) {
            $results.Add((New-CheckResult 'System RAM' 'Pass' "$ram GB"))
        } else {
            $results.Add((New-CheckResult 'System RAM' 'Warn' "$ram GB" `
                'QLoRA loads the checkpoint through host RAM; 16 GB+ is recommended.'))
        }
    } catch {
        $results.Add((New-CheckResult 'System RAM' 'Warn' 'could not be read'))
    }

    [pscustomobject]@{
        Results  = $results
        Blocking = @($results | Where-Object { $_.Status -eq 'Block' })
        Warnings = @($results | Where-Object { $_.Status -eq 'Warn'  })
    }
}

function Show-PreflightReport {
    param([Parameter(Mandatory)][object] $Report)

    foreach ($r in $Report.Results) {
        switch ($r.Status) {
            'Pass'  { Write-Host ("   [OK]    {0,-24} {1}" -f $r.Name, $r.Detail) -ForegroundColor Green }
            'Warn'  { Write-Host ("   [WARN]  {0,-24} {1}" -f $r.Name, $r.Detail) -ForegroundColor Yellow }
            'Block' { Write-Host ("   [BLOCK] {0,-24} {1}" -f $r.Name, $r.Detail) -ForegroundColor Red }
        }
    }

    if ($Report.Warnings.Count) {
        Write-Host ''
        Write-Host "   $($Report.Warnings.Count) warning(s) - continuing:" -ForegroundColor Yellow
        foreach ($w in $Report.Warnings) {
            if ($w.Remedy) { Write-Host "     - $($w.Name): $($w.Remedy)" -ForegroundColor Yellow }
        }
    }

    if ($Report.Blocking.Count) {
        Write-Host ''
        Write-Host "   $($Report.Blocking.Count) blocking problem(s):" -ForegroundColor Red
        foreach ($b in $Report.Blocking) {
            Write-Host "     - $($b.Name): $($b.Detail)" -ForegroundColor Red
            if ($b.Remedy) { Write-Host "       -> $($b.Remedy)" -ForegroundColor Red }
        }
    }
}

# ===========================================================================
# PHASE 2 - install helpers
# ===========================================================================

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

# `bash.exe` in System32 is the WSL launcher, not Git Bash - it would run the
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

# ===========================================================================
# main
# ===========================================================================

Write-Host ''
Write-Host 'Web_security_scanner - Windows one-shot setup' -ForegroundColor Cyan
Write-Host ("  branch : {0}" -f $Branch)
Write-Host ("  target : {0}" -f $InstallDir)

$startedAt = Get-Date
Update-SessionPath

# ---------------------------------------------------------------------------
# phase 1
# ---------------------------------------------------------------------------
if ($SkipPreflight) {
    Write-Step 'Pre-flight check'
    Write-Warn 'skipped (-SkipPreflight)'
    if ($CheckOnly) { Stop-Setup '-CheckOnly and -SkipPreflight are contradictory.' }
} else {
    Write-Step 'Pre-flight check'
    $report = Invoke-PreflightCheck -TargetDir $InstallDir
    Show-PreflightReport -Report $report

    if ($report.Blocking.Count -gt 0) {
        if ($Force) {
            Write-Host ''
            Write-Warn "$($report.Blocking.Count) blocking problem(s) overridden by -Force - continuing at your own risk"
        } elseif ($CheckOnly) {
            Write-Host ''
            Write-Host 'X NOT READY' -ForegroundColor Red
            exit 1
        } else {
            Stop-Setup @"
the pre-flight check found $($report.Blocking.Count) blocking problem(s) - see the
red lines above. Nothing was installed and nothing was downloaded.
Fix them and re-run, or pass -Force to proceed anyway.
"@
        }
    }

    if ($CheckOnly) {
        Write-Host ''
        Write-Host 'OK  READY - re-run without -CheckOnly to install and start the pipeline' -ForegroundColor Green
        exit 0
    }
}

# ---------------------------------------------------------------------------
# phase 2.1 Git (Git Bash)
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
# phase 2.2 Python 3.11
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
# phase 2.3 uv
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
# phase 2.4 clone / update the repository
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
# phase 2.5 locate Git Bash and launch the pipeline
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
