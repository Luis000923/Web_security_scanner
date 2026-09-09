<#
.SYNOPSIS
    Stand-alone pre-flight check for Web_security_scanner on Windows.

.DESCRIPTION
    Read-only. Answers "will setup_windows.ps1 succeed on this machine?" in a
    few seconds, before anything is installed, cloned or downloaded:

        * 64-bit Windows, PowerShell 5.1+
        * winget / git / Python / uv availability
        * disk space on the checkout volume and on the Hugging Face cache volume
        * write access to the target directory
        * reachability of github.com, huggingface.co, astral.sh, PyPI and the
          PyTorch wheel index
        * NVIDIA GPU and the model tier the pipeline will auto-select for it
        * Windows quirks that bite later: long-path policy, host RAM, proxies

    The checks themselves live in setup_windows.ps1 (which must be able to run
    them with no other file present, since on a bare machine it is the only file
    downloaded). This script is the stand-alone front end to that same code, so
    there is exactly one implementation to keep correct.

.PARAMETER InstallDir
    Directory the checkout would go into - the volume whose free space and write
    access are checked. Defaults to the directory this script is run from.

.PARAMETER SetupScript
    Path to setup_windows.ps1. Defaults to the copy next to this script.

.OUTPUTS
    Exit code 0 = ready (warnings are allowed), 1 = at least one blocking problem.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\check_windows_env.ps1

.EXAMPLE
    .\check_windows_env.ps1 -InstallDir D:\proyectos
#>

[CmdletBinding()]
param(
    [string] $InstallDir  = $PSScriptRoot,
    [string] $SetupScript = (Join-Path $PSScriptRoot 'setup_windows.ps1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $InstallDir) { $InstallDir = (Get-Location).Path }

if (-not (Test-Path -LiteralPath $SetupScript)) {
    Write-Host ''
    Write-Host "X setup_windows.ps1 not found at: $SetupScript" -ForegroundColor Red
    Write-Host ''
    Write-Host '  This script is a front end for the checks implemented there.' -ForegroundColor Red
    Write-Host '  Download both files side by side, or point at it explicitly:' -ForegroundColor Red
    Write-Host '      .\check_windows_env.ps1 -SetupScript C:\path\to\setup_windows.ps1' -ForegroundColor Red
    exit 1
}

# -CheckOnly runs phase 1 and exits: 0 = ready, 1 = blocking problems found.
& $SetupScript -InstallDir $InstallDir -CheckOnly
exit $LASTEXITCODE
