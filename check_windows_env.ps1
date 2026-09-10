<#
.SYNOPSIS
    Stand-alone pre-flight check for Web_security_scanner on Windows.

.DESCRIPTION
    Read-only. Answers "will setup_windows.ps1 succeed on this machine?" in a
    few seconds, before anything is installed, cloned or downloaded:

        * 64-bit Windows, PowerShell 5.1+
        * winget / git / uv availability, and a Python version torch has wheels
          for (3.10-3.13; a 3.14-only machine is reported as a problem here
          rather than twenty minutes into a dependency resolution)
        * disk space on the checkout volume and on the Hugging Face cache volume
        * write access to the target directory
        * reachability of github.com, huggingface.co, astral.sh, PyPI, python.org
          and the PyTorch wheel index - each failure classified (DNS / TLS /
          proxy / timeout) and paired with the remedy for that classification
        * NVIDIA GPU: VRAM, compute capability and driver, and the model, the
          precision and the batch/sequence budget the pipeline will pick for them
        * Windows quirks that bite later: long-path policy, host RAM, proxies

    Nothing is blocking on its own. A campus network that filters github.com but
    leaves PyPI and Hugging Face reachable is a warning plus instructions, not an
    abort: the repository can arrive as a zip instead.

    The checks themselves live in setup_windows.ps1 (which must be able to run
    them with no other file present, since on a bare machine it is the only file
    downloaded). This script is the stand-alone front end to that same code, so
    there is exactly one implementation to keep correct.

.PARAMETER InstallDir
    Directory the checkout would go into - the volume whose free space and write
    access are checked. Defaults to the directory this script is run from.

.PARAMETER SetupScript
    Path to setup_windows.ps1. Defaults to the copy next to this script.

.PARAMETER Proxy
    Proxy to test through, e.g. http://proxy.campus.edu:8080. Without it the
    system (WinINET) proxy is used when one is configured.

.PARAMETER SourceZip
    A local repository zip. Its presence is what makes an unreachable GitHub a
    warning rather than a blocking problem, so pass it here if you intend to
    pass it to setup_windows.ps1.

.PARAMETER TorchIndexUrl
    Check this wheel index instead of the one derived from the detected GPU.

.OUTPUTS
    Exit code 0 = ready (warnings are allowed), 1 = at least one blocking problem.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\check_windows_env.ps1

.EXAMPLE
    .\check_windows_env.ps1 -InstallDir D:\proyectos

.EXAMPLE
    # behind a campus proxy, with the repo already downloaded elsewhere
    .\check_windows_env.ps1 -Proxy http://proxy.campus.edu:8080 -SourceZip D:\repo.zip
#>

[CmdletBinding()]
param(
    [string] $InstallDir    = $PSScriptRoot,
    [string] $SetupScript   = (Join-Path $PSScriptRoot 'setup_windows.ps1'),
    [string] $Proxy,
    [string] $SourceZip,
    [string] $TorchIndexUrl
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
# Only forward the optional arguments that were actually given, so the setup
# script's own defaults still apply to the rest.
$forward = @{ InstallDir = $InstallDir; CheckOnly = $true }
if ($Proxy)         { $forward['Proxy']         = $Proxy }
if ($SourceZip)     { $forward['SourceZip']     = $SourceZip }
if ($TorchIndexUrl) { $forward['TorchIndexUrl'] = $TorchIndexUrl }

& $SetupScript @forward
exit $LASTEXITCODE
