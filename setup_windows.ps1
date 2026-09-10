<#
.SYNOPSIS
    One-shot bootstrapper for Web_security_scanner on Windows: pre-flight check,
    toolchain install, source acquisition, and an unattended pipeline run that is
    tuned to the GPU the machine actually has.

.DESCRIPTION
    Designed to be the only file you need on a bare Windows machine (e.g. a
    university lab PC). Two phases, one command:

    PHASE 1 - pre-flight (Invoke-PreflightCheck)
        Cheap, read-only checks that run BEFORE anything is downloaded, so a
        machine that cannot possibly succeed fails in seconds instead of after
        a 6 GB torch download: 64-bit OS, PowerShell version, winget, disk
        space, write access, a *usable* Python version, reachability of every
        host the install actually touches, and a preview of the model and the
        training knobs the detected GPU will get.

        A failure is only fatal when nothing can work around it. Every network
        probe is classified (DNS / TLS / proxy / timeout / HTTP status) and the
        report says which of the three source-acquisition routes survive, so a
        campus filter that blocks github.com but leaves PyPI and Hugging Face
        alone degrades to a warning plus instructions, not an abort.

    PHASE 2 - setup + run (fully unattended, every step idempotent)
        1. Git (Git Bash)   via winget  Git.Git                    [optional]
        2. Python 3.11      via winget  Python.Python.3.11         [if needed]
        3. uv               astral.sh -> pip -> winget             [3 routes]
        4. source           git clone -> HTTPS zip -> -SourceZip   [3 routes]
        5. GPU profiling    -> CUDA wheel index + training recipe
        6. run_pipeline.sh  through Git Bash, or the native PowerShell
                            equivalent when Git Bash is not available

    Hardware adaptation
        The GPU is profiled for VRAM *and* compute capability, because the two
        answer different questions: VRAM picks the model size, capability picks
        the numeric format. A 4 GB Turing card (GTX 1650, sm_75) has no bf16 at
        all, so it needs 4-bit NF4 weights, fp16 compute and a micro-batch --
        settings under which a 1.5B model fine-tunes fine, and without which the
        run aborts inside the trainer. The capability also selects the CUDA
        wheel index, so an older driver gets wheels it can actually load.

        ai_module/auto_select_model.py stays authoritative: the table mirrored
        here is a preview printed before anything is installed.

    Error handling
        Every network operation is retried with backoff. Every install route has
        at least one fallback. The whole run is transcribed to a log file, and a
        failure prints what was tried, what the machine looked like, and the
        exact command to resume.

    check_windows_env.ps1 is the standalone entry point to phase 1; it delegates
    here so the checks have exactly one implementation.

.PARAMETER InstallDir
    Parent directory that will contain the clone. Defaults to the directory the
    script is run from. Ignored when the script already lives inside the repo.

.PARAMETER Branch
    Branch to check out. Default: ai-agent.

.PARAMETER RepoUrl
    Clone URL. Default: https://github.com/Luis000923/Web_security_scanner.git

.PARAMETER ArchiveUrl
    HTTPS zip of the branch, used when `git clone` is impossible (no git, or the
    git transport is filtered). Defaults to the codeload URL for -RepoUrl.

.PARAMETER SourceZip
    Path to a local .zip of the repository - the offline route, for a machine
    where GitHub is unreachable entirely. Download it elsewhere and bring it in.

.PARAMETER Proxy
    Explicit proxy, e.g. http://proxy.campus.edu:8080. When omitted the script
    reads the system (WinINET) proxy and uses that if one is configured.

.PARAMETER TorchIndexUrl
    Override the auto-detected PyTorch wheel index (cu128 / cu126 / cu118 /
    cpu). Only needed when the driver reports a CUDA version that does not match
    the wheels you actually want.

.PARAMETER TorchSpec
    The torch requirement to install, default "torch" (latest on the index).
    Pin it when the newest build has dropped your GPU's architecture - PyTorch
    retires old compute capabilities over time, and the symptom is "no kernel
    image is available for execution on the device" at the first kernel launch.
    The setup detects exactly that and tells you which pin to try, e.g.
    -TorchSpec "torch==2.7.1".

.PARAMETER Task
    triage | payload - which adapter to fine-tune. Default: triage.

.PARAMETER Epochs
    Fine-tune epochs. Default: 3.

.PARAMETER CheckOnly
    Run the pre-flight check and exit. Exit code 0 = ready (warnings allowed),
    1 = at least one blocking problem.

.PARAMETER SkipPreflight
    Skip phase 1 entirely.

.PARAMETER SkipPipeline
    Install everything, then stop without training.

.PARAMETER SkipTrain
    Run the environment install and the smoke test, but not the full fine-tune.

.PARAMETER NativeRun
    Force the PowerShell pipeline path instead of run_pipeline.sh, even when
    Git Bash is present.

.PARAMETER Force
    Continue despite blocking pre-flight problems.

.PARAMETER LogFile
    Transcript path. Default: setup_windows_<timestamp>.log next to -InstallDir.

.PARAMETER PipelineArgs
    Extra arguments forwarded verbatim to run_pipeline.sh.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1

.EXAMPLE
    # campus network: GitHub blocked, repo brought in on a USB stick
    .\setup_windows.ps1 -SourceZip D:\Web_security_scanner.zip

.EXAMPLE
    # check the machine without touching it
    .\setup_windows.ps1 -CheckOnly
#>

[CmdletBinding()]
param(
    [string]   $InstallDir,
    [string]   $Branch        = 'ai-agent',
    [string]   $RepoUrl       = 'https://github.com/Luis000923/Web_security_scanner.git',
    [string]   $ArchiveUrl,
    [string]   $SourceZip,
    [string]   $Proxy,
    [string]   $TorchIndexUrl,
    [string]   $TorchSpec     = 'torch',
    [ValidateSet('triage', 'payload')]
    [string]   $Task          = 'triage',
    [int]      $Epochs        = 3,
    [switch]   $CheckOnly,
    [switch]   $SkipPreflight,
    [switch]   $SkipPipeline,
    [switch]   $SkipTrain,
    [switch]   $NativeRun,
    [switch]   $Force,
    [string]   $LogFile,
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
if (-not $ArchiveUrl) {
    # https://github.com/<owner>/<repo>.git -> codeload zip for the branch
    if ($RepoUrl -match '^https://github\.com/([^/]+)/([^/]+?)(\.git)?/?$') {
        $ArchiveUrl = "https://codeload.github.com/$($Matches[1])/$($Matches[2])/zip/refs/heads/$Branch"
    }
}

# Disk budget, in GB. A tier-3 run pulls a 14B 4-bit checkpoint (~9 GB), the
# CUDA torch wheels (~6 GB), and writes a merged fp16 adapter (~28 GB).
$script:DiskBlockGB = 15
$script:DiskWarnGB  = 50

# Python versions that have torch / bitsandbytes wheels. 3.14 is deliberately
# excluded: it installs and runs, and then `uv pip install torch` fails to
# resolve because no cp314 wheel exists yet - a failure that surfaces twenty
# minutes into the run instead of here.
$script:PythonOkVersions      = @('3.10', '3.11', '3.12', '3.13')
$script:PythonPreferredWinget = 'Python.Python.3.11'
$script:PythonPreferred       = '3.11'

$script:Warnings = New-Object System.Collections.Generic.List[string]

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
function Write-Warn($msg) {
    Write-Host "   [!]  $msg" -ForegroundColor Yellow
    $script:Warnings.Add($msg)
}
function Write-Err ($msg) { Write-Host "   [X]  $msg"   -ForegroundColor Red }

function Stop-Setup($msg) {
    Write-Host ''
    Write-Host "X SETUP ABORTED  $msg" -ForegroundColor Red
    if ($script:LogPath) {
        Write-Host ''
        Write-Host "   full log: $($script:LogPath)" -ForegroundColor Red
    }
    try { Stop-Transcript | Out-Null } catch { }
    exit 1
}

# ---------------------------------------------------------------------------
# retry
# ---------------------------------------------------------------------------
function Invoke-WithRetry {
    <#
      Run a scriptblock until it stops throwing. Network work on a campus link
      fails transiently often enough that a single attempt is not evidence of
      anything; three attempts with a growing gap are.

      Returns whatever the block returns. Rethrows the LAST exception when every
      attempt failed, so the caller still sees the real error.
    #>
    param(
        [Parameter(Mandatory)][scriptblock] $ScriptBlock,
        [Parameter(Mandatory)][string]      $Label,
        [int] $Attempts     = 3,
        [int] $DelaySeconds = 3
    )
    $delay = $DelaySeconds
    for ($i = 1; $i -le $Attempts; $i++) {
        try {
            return & $ScriptBlock
        } catch {
            if ($i -eq $Attempts) {
                Write-Err "$Label failed after $Attempts attempt(s): $($_.Exception.Message)"
                throw
            }
            Write-Warn "$Label failed (attempt $i/$Attempts): $($_.Exception.Message) - retrying in ${delay}s"
            Start-Sleep -Seconds $delay
            $delay = $delay * 2
        }
    }
}

# ---------------------------------------------------------------------------
# proxy
# ---------------------------------------------------------------------------
function Get-SystemProxy {
    <#
      The WinINET proxy that Internet Explorer / Edge / winget already use. A
      managed lab image usually has one configured here and nowhere else, which
      is why a bare Invoke-WebRequest times out while the browser works fine.
      Returns "http://host:port" or $null.
    #>
    try {
        $key = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' `
                                -ErrorAction Stop
        if (-not $key.ProxyEnable) { return $null }
        $server = $key.ProxyServer
        if (-not $server) { return $null }
        # "http=host:port;https=host:port" or a bare "host:port"
        if ($server -match 'https?=([^;]+)') { $server = $Matches[1] }
        elseif ($server -match ';')          { $server = ($server -split ';')[0] }
        if ($server -notmatch '^https?://')  { $server = "http://$server" }
        return $server
    } catch {
        return $null
    }
}

function Initialize-Proxy {
    <#
      Make one proxy decision and apply it everywhere: .NET (Invoke-WebRequest),
      the environment variables git / uv / pip / huggingface_hub read, and the
      Git Bash child process that inherits them. Returns the proxy in use, or
      $null when going direct.
    #>
    param([string] $Explicit)

    $proxy = $Explicit
    if (-not $proxy) { $proxy = $env:HTTPS_PROXY }
    if (-not $proxy) { $proxy = $env:HTTP_PROXY }
    $fromSystem = $false
    if (-not $proxy) {
        $proxy = Get-SystemProxy
        if ($proxy) { $fromSystem = $true }
    }
    if (-not $proxy) {
        # No proxy anywhere: still let .NET use the machine's default
        # credentials, which is what makes an authenticating proxy work at all.
        try {
            [Net.WebRequest]::DefaultWebProxy = [Net.WebRequest]::GetSystemWebProxy()
            [Net.WebRequest]::DefaultWebProxy.Credentials =
                [Net.CredentialCache]::DefaultNetworkCredentials
        } catch { }
        return $null
    }

    $env:HTTPS_PROXY = $proxy
    $env:HTTP_PROXY  = $proxy
    if (-not $env:NO_PROXY) { $env:NO_PROXY = 'localhost,127.0.0.1' }
    try {
        $webProxy = New-Object System.Net.WebProxy($proxy, $true)
        $webProxy.Credentials = [Net.CredentialCache]::DefaultNetworkCredentials
        [Net.WebRequest]::DefaultWebProxy = $webProxy
    } catch { }
    $script:ProxyFromSystem = $fromSystem
    return $proxy
}

# ---------------------------------------------------------------------------
# network probes
# ---------------------------------------------------------------------------
function Test-Dns {
    <#
      Split "the name does not resolve" from "the name resolves but the
      connection is refused" - a distinction that decides whether the operator
      should look at DNS/content filtering or at the proxy.

      Also asks a public resolver: when the campus resolver returns NXDOMAIN and
      1.1.1.1 answers, the block is a DNS filter and setting a different DNS
      server (or using the proxy) is the fix.
    #>
    param([Parameter(Mandatory)][string] $HostName)

    $result = [pscustomobject]@{ Local = $false; Public = $false; Detail = '' }
    if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
        try {
            $null = Resolve-DnsName -Name $HostName -Type A -ErrorAction Stop
            $result.Local = $true
        } catch {
            $result.Detail = $_.Exception.Message
        }
        if (-not $result.Local) {
            foreach ($server in @('1.1.1.1', '8.8.8.8')) {
                try {
                    $null = Resolve-DnsName -Name $HostName -Type A -Server $server `
                                            -DnsOnly -ErrorAction Stop
                    $result.Public = $true
                    break
                } catch { }
            }
        }
    } else {
        # PowerShell without the DnsClient module (Server Core, some images)
        try {
            $null = [System.Net.Dns]::GetHostEntry($HostName)
            $result.Local = $true
        } catch {
            $result.Detail = $_.Exception.Message
        }
    }
    return $result
}

function Test-Endpoint {
    <#
      Reachability, not correctness: any HTTP response - including a 403 or 405
      from a host that rejects HEAD - proves we got through DNS, TLS and any
      proxy, which is all the pre-flight needs to know.

      HEAD first, then GET: content filters and some CDNs answer HEAD with a
      connection reset while serving GET normally, so a HEAD-only probe reports
      an outage that is not there.

      Returns Ok / Detail / Kind, where Kind is one of
      dns | timeout | tls | proxy | refused | http | unknown - the classification
      the report turns into a remedy.
    #>
    param([Parameter(Mandatory)][string] $Url, [int] $TimeoutSec = 15)

    $lastError = $null
    foreach ($method in @('Head', 'Get')) {
        try {
            $r = Invoke-WebRequest -Uri $Url -Method $method -UseBasicParsing `
                                   -TimeoutSec $TimeoutSec -MaximumRedirection 5 `
                                   -ErrorAction Stop
            return [pscustomobject]@{ Ok = $true; Detail = "HTTP $([int]$r.StatusCode)"; Kind = 'http' }
        } catch {
            $lastError = $_
            $status = $null
            try {
                $resp = $_.Exception.Response
                if ($resp) { $status = [int]$resp.StatusCode }
            } catch { $status = $null }
            if ($status) {
                # An HTTP status - even 403/405 - means the path is open.
                return [pscustomobject]@{ Ok = $true; Detail = "HTTP $status"; Kind = 'http' }
            }
        }
    }

    $msg = if ($lastError) { $lastError.Exception.Message } else { 'unknown failure' }
    $kind = 'unknown'
    switch -Regex ($msg) {
        'remote name|resolver|resolve|No such host|host is known|NXDOMAIN' { $kind = 'dns'; break }
        'timed out|sobrepas|time.?out|espera'                              { $kind = 'timeout'; break }
        'SSL|TLS|secure channel|certificat|confianza'                      { $kind = 'tls'; break }
        'proxy|407'                                                        { $kind = 'proxy'; break }
        'refused|actively refused|rechaz'                                  { $kind = 'refused'; break }
    }
    return [pscustomobject]@{ Ok = $false; Detail = $msg; Kind = $kind }
}

function Get-EndpointRemedy {
    <#
      One sentence of "do this next", chosen from how the probe failed rather
      than from a generic template - the difference between a useful message and
      "check your connection".
    #>
    param(
        [Parameter(Mandatory)][string] $HostName,
        [Parameter(Mandatory)][string] $Kind,
        [bool] $ResolvesPublicly = $false
    )
    switch ($Kind) {
        'dns' {
            if ($ResolvesPublicly) {
                return "$HostName is filtered by this network's DNS (a public resolver answers, yours does not). " +
                       "Use the campus proxy (-Proxy http://host:port), a different DNS server, or bring the " +
                       "repository in with -SourceZip."
            }
            return "$HostName does not resolve. Check the connection, or set the proxy explicitly with " +
                   "-Proxy http://host:port."
        }
        'timeout'  { return "$HostName accepted no connection before the timeout - usually a proxy that must be set explicitly (-Proxy http://host:port)." }
        'tls'      { return "TLS to $HostName failed - a TLS-inspecting appliance whose root certificate this machine does not trust, or an outdated TLS stack." }
        'proxy'    { return "The proxy refused the request (407). Run in a session that has your credentials, or set -Proxy with them embedded." }
        'refused'  { return "$HostName refused the connection - a local firewall or content filter." }
        default    { return "Could not reach $HostName. Check the connection, the campus proxy (-Proxy), or a content filter." }
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

# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------
function Get-PythonProfile {
    <#
      Find an interpreter the ML stack can actually be installed into.

      "python is present" is not the question - Windows 11 ships a Store stub,
      and a fresh python.org install may be 3.14, which has no torch wheels. We
      want a 3.10-3.13, and we want to know how to invoke it.

      Returns: Found (bool), Command (string[] launcher+args), Version, All
      (every version seen), StubOnly (the Store alias that only opens the Store).
    #>
    $seen = New-Object System.Collections.Generic.List[string]
    $best = $null
    $bestCmd = $null

    # The py launcher is the reliable enumerator when it exists.
    if (Test-Command 'py') {
        foreach ($v in $script:PythonOkVersions) {
            try {
                $out = & py "-$v" --version 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $seen.Add($v)
                    if (-not $best) { $best = ($out -join '').Trim(); $bestCmd = @('py', "-$v") }
                }
            } catch { }
        }
    }

    # A bare `python` may be a different install than anything py knows about.
    $stubOnly = $false
    if (Test-Command 'python') {
        try {
            $raw = (& python --version 2>&1) -join ''
            if ($raw -match '(\d+\.\d+)\.\d+') {
                $ver = $Matches[1]
                if ($seen -notcontains $ver) { $seen.Add($ver) }
                if (-not $best -and ($script:PythonOkVersions -contains $ver)) {
                    $best = $raw.Trim(); $bestCmd = @('python')
                }
            } elseif ($raw -match 'Microsoft Store|was not found') {
                # The App Execution Alias: on PATH, but it only opens the Store.
                $stubOnly = $true
            }
        } catch { }
    }

    return [pscustomobject]@{
        Found    = [bool]$best
        Command  = $bestCmd
        Version  = $best
        All      = @($seen)
        StubOnly = $stubOnly
    }
}

# ---------------------------------------------------------------------------
# GPU
# ---------------------------------------------------------------------------
function Get-GpuProfile {
    <#
      Two independent facts about the GPU, because they answer different
      questions:

        VRAM       -> how big a model fits            (tier / batch / seq len)
        capability -> which numeric formats exist     (bf16 vs fp16, TF32)

      A 4 GB GTX 1650 is sm_75 (Turing): it has no bf16 unit at all. Training it
      with the workstation's bf16 defaults does not run slowly, it aborts. The
      driver's maximum CUDA version is read too, since that is what decides
      which torch wheel index can be loaded.

      Mirrors ai_module/auto_select_model.py, which stays authoritative - this
      runs before anything is installed, so the operator sees the plan first.
    #>
    if (-not (Test-Command 'nvidia-smi')) { return $null }

    $name = $null; $vramGB = $null; $cap = $null; $driver = $null
    try {
        # compute_cap needs a reasonably modern driver; fall back without it.
        $raw = & nvidia-smi --query-gpu=name,memory.total,compute_cap,driver_version `
                            --format=csv,noheader,nounits 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $raw) {
            $raw = & nvidia-smi --query-gpu=name,memory.total,driver_version `
                                --format=csv,noheader,nounits 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $raw) { return $null }
            $parts = (@($raw)[0] -split ',')
            if ($parts.Count -lt 3) { return $null }
            $name = $parts[0].Trim()
            $vramGB = [math]::Round([double]($parts[1].Trim()) / 1024, 1)
            $driver = $parts[2].Trim()
        } else {
            $parts = (@($raw)[0] -split ',')
            if ($parts.Count -lt 4) { return $null }
            $name = $parts[0].Trim()
            $vramGB = [math]::Round([double]($parts[1].Trim()) / 1024, 1)
            $cap = $parts[2].Trim()
            $driver = $parts[3].Trim()
        }
    } catch {
        return $null
    }

    # The driver's maximum CUDA runtime, from the nvidia-smi banner. Both
    # spellings occur: older drivers print "CUDA Version", newer ones
    # "CUDA UMD Version".
    $cudaMax = $null
    try {
        $banner = (& nvidia-smi 2>$null) -join "`n"
        if ($banner -match 'CUDA(?:\s+UMD)?\s+Version:\s*(\d+\.\d+)') { $cudaMax = [double]$Matches[1] }
    } catch { }
    if ($null -eq $cudaMax -and $driver -match '^(\d+)') {
        # No banner to parse - infer from the driver branch instead. Each of
        # these is the first branch that shipped the corresponding runtime.
        $branch = [int]$Matches[1]
        $cudaMax = if     ($branch -ge 570) { 12.8 }
                   elseif ($branch -ge 525) { 12.0 }
                   elseif ($branch -ge 452) { 11.8 }
                   else                     { $null }
    }

    # Keep the capability in both forms. The double is for comparisons; the
    # text is for display, because [string][double]8.0 is "8" - which would
    # print "sm_8" for an A100 and "sm_12" for a 5090.
    $capValue = $null
    $capText  = ''
    if ($cap -and $cap -match '^\d+\.\d+$') {
        $capValue = [double]$cap
        $capText  = 'sm_' + ($cap -replace '\.', '')
    }

    $tier = if ($vramGB -le 7) { 1 } elseif ($vramGB -le 16) { 2 } else { 3 }

    return [pscustomobject]@{
        Name           = $name
        VramGB         = $vramGB
        Capability     = $capValue      # 7.5, 8.6, 12.0 ... or $null
        CapabilityText = $capText       # "sm_75" ... or ""
        Driver         = $driver
        CudaMax        = $cudaMax       # 12.4 ... or $null
        Tier           = $tier
        Bf16           = ($null -ne $capValue -and $capValue -ge 8.0)
    }
}

function Resolve-TorchIndexUrl {
    <#
      Pick the torch wheel index the *driver* can load.

      torch wheels refuse to initialise on a driver older than the CUDA major
      series they were built against - the classic "CUDA driver version is
      insufficient for CUDA runtime version", which surfaces only when the first
      kernel launches, long after a 3 GB download. nvidia-smi reports the newest
      runtime the driver supports, so match against that.

      Only three indexes are candidates, because pyproject.toml requires
      torch >= 2.6 and the older channels (cu121, cu124) stopped publishing
      before or at that version. Within CUDA 12, minor-version compatibility
      means any 12.x driver (all of which are 525+) can load the cu126 runtime
      that ships inside the wheel, so one index covers the whole 12.0-12.7 range.

      Blackwell (sm_120) is the exception in the other direction: its kernels
      exist only in the CUDA 12.8 builds, so it pins cu128 regardless of what
      the driver advertises.
    #>
    param($Gpu)

    if (-not $Gpu) { return 'https://download.pytorch.org/whl/cpu' }
    if ($null -ne $Gpu.Capability -and $Gpu.Capability -ge 12.0) {
        return 'https://download.pytorch.org/whl/cu128'
    }
    $cuda = $Gpu.CudaMax
    if ($null -eq $cuda) {
        # No banner and no usable driver number: cu126 is the widest CUDA 12
        # build that still publishes a torch the project accepts.
        return 'https://download.pytorch.org/whl/cu126'
    }
    if ($cuda -ge 12.8) { return 'https://download.pytorch.org/whl/cu128' }
    if ($cuda -ge 12.0) { return 'https://download.pytorch.org/whl/cu126' }
    if ($cuda -ge 11.8) { return 'https://download.pytorch.org/whl/cu118' }
    return 'https://download.pytorch.org/whl/cpu'
}

function Get-TrainingPreview {
    <#
      What ai_module.auto_select_model will decide, previewed before the ML
      stack exists. Mirrors TIER_TABLE + RECIPE_TABLE there; that module stays
      the authority, and the pipeline re-derives all of this from the real torch
      probe once it is installed.
    #>
    param($Gpu)

    if (-not $Gpu) {
        return [pscustomobject]@{
            Model = 'unsloth/Qwen2.5-0.5B-Instruct-bnb-4bit'; Tier = 0
            Precision = 'fp32'; FourBit = $true
            BatchSize = 1; GradAccum = 8; SeqLen = 512; LoraR = 8
            Note = 'no NVIDIA GPU - CPU fallback, hours per epoch'
        }
    }

    $v = $Gpu.VramGB
    $model = if ($v -le 7) { 'unsloth/Qwen2.5-1.5B-Instruct-bnb-4bit' }
             elseif ($v -le 16) { 'unsloth/Qwen2.5-7B-Instruct-bnb-4bit' }
             else { 'unsloth/Qwen2.5-14B-Instruct-bnb-4bit' }

    if ($v -le 5.0) {
        $fourBit = $true;  $batch = 1; $accum = 16; $seq = 512;  $r = 16
        $note = 'micro-batch - the display also draws on this VRAM'
    } elseif ($v -le 7.0) {
        $fourBit = $true;  $batch = 2; $accum = 8;  $seq = 768;  $r = 16
        $note = 'laptop-GPU budget'
    } elseif ($v -le 16.0) {
        $fourBit = $true;  $batch = 4; $accum = 4;  $seq = 1024; $r = 32
        $note = '4-bit NF4 base'
    } else {
        $fourBit = $false; $batch = 8; $accum = 2;  $seq = 2048; $r = 32
        $note = 'native precision, no quantisation floor'
    }

    return [pscustomobject]@{
        Model = $model; Tier = $Gpu.Tier
        Precision = $(if ($Gpu.Bf16) { 'bf16' } else { 'fp16' })
        FourBit = $fourBit
        BatchSize = $batch; GradAccum = $accum; SeqLen = $seq; LoraR = $r
        Note = $note
    }
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

function Invoke-PreflightCheck {
    <#
      Read-only. Returns every result plus the Blocking/Warning subsets and the
      hardware profile, so -CheckOnly, the installer and the report all work off
      one evaluation.
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

    # --- can we already see the source? ------------------------------------
    # Decided first, because it is what makes a GitHub outage survivable: with
    # the repo already on disk (or in a -SourceZip) nothing needs github.com.
    $inRepo = $PSScriptRoot -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'run_pipeline.sh'))
    $existingClone = Test-Path -LiteralPath (Join-Path (Join-Path $TargetDir 'Web_security_scanner') '.git')
    $haveZip = $SourceZip -and (Test-Path -LiteralPath $SourceZip)
    $script:HaveLocalSource = [bool]($inRepo -or $existingClone -or $haveZip)

    if ($inRepo) {
        $results.Add((New-CheckResult 'Source' 'Pass' "running from inside a checkout: $PSScriptRoot"))
    } elseif ($existingClone) {
        $results.Add((New-CheckResult 'Source' 'Pass' "existing clone in $TargetDir"))
    } elseif ($haveZip) {
        $results.Add((New-CheckResult 'Source' 'Pass' "local archive: $SourceZip"))
    } else {
        $results.Add((New-CheckResult 'Source' 'Warn' 'not present locally - will be fetched from GitHub' `
            'If GitHub is unreachable, download the repo zip elsewhere and pass -SourceZip C:\path\repo.zip.'))
    }

    # --- package manager ---------------------------------------------------
    $python = Get-PythonProfile
    $hasGit    = Test-Command 'git'
    $hasUv     = Test-Command 'uv'
    $hasWinget = Test-Command 'winget'
    $needsInstall = -not ($hasGit -and $hasUv -and $python.Found)

    if ($hasWinget) {
        $wv = try { (& winget --version) -join '' } catch { 'unknown' }
        $results.Add((New-CheckResult 'winget' 'Pass' $wv))
    } elseif ($needsInstall) {
        # Not blocking any more: uv installs from PyPI without winget, and the
        # source can arrive as a zip. Only the *combination* of missing pieces
        # is fatal, and that is decided at the bottom of this function.
        $results.Add((New-CheckResult 'winget' 'Warn' 'not found, and tools are missing' `
            'Install "App Installer" from the Microsoft Store: https://apps.microsoft.com/detail/9NBLGGH4NNS1'))
    } else {
        $results.Add((New-CheckResult 'winget' 'Warn' 'not found (nothing left to install)' `
            'Only needed to install Git/Python; both are already present.'))
    }

    # --- toolchain ---------------------------------------------------------
    # git is convenient, not essential: the zip route needs neither git nor Git
    # Bash, because the pipeline can also be driven natively from PowerShell.
    if ($hasGit) {
        $gv = try { (& git --version) -join '' } catch { 'present' }
        $results.Add((New-CheckResult 'git' 'Pass' $gv))
    } elseif ($hasWinget) {
        $results.Add((New-CheckResult 'git' 'Warn' 'not installed' `
            'Will be installed via winget in phase 2 (its installer is hosted on GitHub, so this needs github.com).'))
    } else {
        $results.Add((New-CheckResult 'git' 'Warn' 'not installed and no winget to install it' `
            'Optional: with -SourceZip the pipeline runs natively from PowerShell. Otherwise: https://git-scm.com/download/win'))
    }

    # Python is where a lab image most often disagrees with the ML stack.
    if ($python.Found) {
        $results.Add((New-CheckResult 'Python' 'Pass' "$($python.Version) (usable for torch)"))
    } elseif ($python.All.Count -gt 0) {
        $results.Add((New-CheckResult 'Python' 'Warn' `
            "found $($python.All -join ', ') - none has torch wheels" `
            ("torch/bitsandbytes publish wheels for $($script:PythonOkVersions -join '/') only. " +
             "Python $($script:PythonPreferred) will be installed alongside; nothing already on this machine is removed or changed.")))
    } elseif ($python.StubOnly) {
        $results.Add((New-CheckResult 'Python' 'Warn' 'only the Microsoft Store alias is on PATH' `
            "Python $($script:PythonPreferred) will be installed via winget."))
    } else {
        $results.Add((New-CheckResult 'Python' 'Warn' 'not installed' `
            "Python $($script:PythonPreferred) will be installed via winget."))
    }

    if ($hasUv) {
        $uvv = try { (& uv --version) -join '' } catch { 'present' }
        $results.Add((New-CheckResult 'uv' 'Pass' $uvv))
    } else {
        $results.Add((New-CheckResult 'uv' 'Warn' 'not installed' `
            'Will be installed in phase 2: astral.sh installer, then "pip install uv", then winget - whichever answers first.'))
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
            "A full tier-3 run (14B + merged fp16 adapter) wants ~$($script:DiskWarnGB) GB; a smaller GPU needs far less."))
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
            $results.Add((New-CheckResult 'HF cache space' 'Warn' "$hfFree GB free at $hfHome" `
                "Phase 2 will redirect HF_HOME onto the roomier volume under $TargetDir."))
            $script:RedirectHfHome = $true
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

    # --- GPU (before the network block: it selects the wheel index) ---------
    $gpu = Get-GpuProfile
    $script:Gpu = $gpu
    $preview = Get-TrainingPreview -Gpu $gpu
    $script:Preview = $preview
    $torchIndex = if ($TorchIndexUrl) { $TorchIndexUrl } else { Resolve-TorchIndexUrl -Gpu $gpu }
    $script:TorchIndex = $torchIndex

    if ($gpu) {
        $capText = if ($gpu.CapabilityText) { ", $($gpu.CapabilityText)" } else { '' }
        $results.Add((New-CheckResult 'GPU' 'Pass' `
            "$($gpu.Name), $($gpu.VramGB) GB VRAM$capText, driver $($gpu.Driver)"))

        if ($null -eq $gpu.Capability) {
            $results.Add((New-CheckResult 'GPU capability' 'Warn' 'compute capability unreadable' `
                'Assuming no bf16 (the safe answer). Update the NVIDIA driver for an exact reading.'))
        } elseif (-not $gpu.Bf16) {
            $results.Add((New-CheckResult 'GPU capability' 'Pass' `
                "$($gpu.CapabilityText) has no bf16 -> training in fp16 (handled automatically)"))
        } else {
            $results.Add((New-CheckResult 'GPU capability' 'Pass' `
                "$($gpu.CapabilityText) supports bf16 + TF32"))
        }

        if ($null -ne $gpu.Capability -and $gpu.Capability -lt 8.0) {
            # PyTorch retires compute capabilities over time and the current
            # build on this index may already have dropped this one. It is not
            # knowable from here - but it is detectable in one second after the
            # install, which is what Test-TorchCuda does.
            $results.Add((New-CheckResult 'GPU arch support' 'Warn' `
                "$($gpu.CapabilityText) is an older architecture" `
                ('The newest torch on this index may no longer ship kernels for it. The install ' +
                 'launches a test kernel and, if it fails, prints the exact -TorchSpec pin to retry with.')))
        }
        if ($gpu.VramGB -le 4.5) {
            $results.Add((New-CheckResult 'VRAM budget' 'Warn' "$($gpu.VramGB) GB is the tight end" `
                "A 1.5B model in 4-bit fits, but the desktop compositor holds a few hundred MB. Close other GPU apps; the trainer halves the batch and retries automatically on OOM."))
        }
        if ($null -ne $gpu.CudaMax) {
            $results.Add((New-CheckResult 'CUDA (driver)' 'Pass' "up to CUDA $($gpu.CudaMax) -> $torchIndex"))
        } else {
            $results.Add((New-CheckResult 'CUDA (driver)' 'Warn' 'driver CUDA version unreadable' `
                "Defaulting to $torchIndex; override with -TorchIndexUrl if torch fails to initialise."))
        }
    } else {
        $results.Add((New-CheckResult 'GPU' 'Warn' 'no NVIDIA GPU detected (nvidia-smi absent or failed)' `
            'The pipeline will auto-select a CPU-sized model; training will be very slow.'))
    }

    # --- connectivity ------------------------------------------------------
    # Nothing here blocks on its own. github.com only matters when the source is
    # not already local, and even then there are three routes to it; the verdict
    # is computed after all the probes have run.
    $endpoints = @(
        @{ Name = 'github.com';      Url = 'https://github.com';                     Group = 'github' },
        @{ Name = 'codeload.github'; Url = "https://codeload.github.com";            Group = 'github' },
        @{ Name = 'huggingface.co';  Url = 'https://huggingface.co';                 Group = 'models' },
        @{ Name = 'pypi.org';        Url = 'https://pypi.org/simple/';               Group = 'pypi'   },
        @{ Name = 'files.pythonhosted'; Url = 'https://files.pythonhosted.org';      Group = 'pypi'   },
        @{ Name = 'astral.sh (uv)';  Url = 'https://astral.sh/uv/install.ps1';       Group = 'uv'     },
        @{ Name = 'python.org';      Url = 'https://www.python.org';                 Group = 'python' },
        @{ Name = 'pytorch wheels';  Url = $torchIndex;                              Group = 'torch'  }
    )
    $reach = @{}
    foreach ($ep in $endpoints) {
        $probe = Test-Endpoint -Url $ep.Url
        if (-not $reach.ContainsKey($ep.Group)) { $reach[$ep.Group] = $false }
        if ($probe.Ok) {
            $reach[$ep.Group] = $true
            $results.Add((New-CheckResult "Network: $($ep.Name)" 'Pass' $probe.Detail))
            continue
        }

        $hostName = ([Uri]$ep.Url).Host
        $publicOnly = $false
        if ($probe.Kind -eq 'dns') {
            $dns = Test-Dns -HostName $hostName
            $publicOnly = ($dns.Public -and -not $dns.Local)
        }
        $remedy = Get-EndpointRemedy -HostName $hostName -Kind $probe.Kind -ResolvesPublicly $publicOnly
        $results.Add((New-CheckResult "Network: $($ep.Name)" 'Warn' $probe.Detail $remedy))
    }
    $script:Reach = $reach

    # --- the verdicts that actually stop the run ---------------------------
    # 1. There must be some way to obtain the source.
    if (-not $script:HaveLocalSource -and -not $reach['github']) {
        $results.Add((New-CheckResult 'Source availability' 'Block' `
            'GitHub is unreachable and there is no local checkout or -SourceZip' `
            ("Three ways forward: (a) set the proxy: -Proxy http://host:port; (b) download " +
             "$ArchiveUrl on another machine and pass -SourceZip C:\path\to.zip; (c) copy an " +
             "existing checkout onto this machine and run setup_windows.ps1 from inside it.")))
    }
    # 2. The ML stack comes from PyPI + the torch index; without them there is
    #    nothing to install into the venv, whatever else works.
    if (-not $reach['pypi']) {
        $results.Add((New-CheckResult 'Dependency availability' 'Block' `
            'PyPI is unreachable - the Python dependencies cannot be installed' `
            'Set the proxy (-Proxy http://host:port) or point pip at a local mirror via PIP_INDEX_URL.'))
    }
    if (-not $reach['torch']) {
        $results.Add((New-CheckResult 'torch wheels' 'Warn' `
            "$torchIndex is unreachable" `
            'The install will fall back to the PyPI build of torch, which on Windows is CPU-only. Fix the proxy for a CUDA build.'))
    }
    # 3. A model has to be downloadable, or there is nothing to fine-tune.
    if (-not $reach['models']) {
        $results.Add((New-CheckResult 'Model availability' 'Block' `
            'huggingface.co is unreachable - no base model can be downloaded' `
            'Set the proxy (-Proxy http://host:port), or pre-populate the cache and point HF_HOME at it with HF_HUB_OFFLINE=1.'))
    }
    # 4. Python: either one is usable, or one can be installed.
    if (-not $python.Found -and -not $hasWinget -and -not $reach['python']) {
        $results.Add((New-CheckResult 'Python availability' 'Block' `
            "no Python $($script:PythonOkVersions -join '/') and no way to install one" `
            "Install Python $($script:PythonPreferred) manually from https://www.python.org/downloads/"))
    }

    if ($env:HTTPS_PROXY -or $env:HTTP_PROXY) {
        $detail = "HTTPS_PROXY=$($env:HTTPS_PROXY)"
        if ($script:ProxyFromSystem) { $detail += ' (read from the system settings)' }
        $results.Add((New-CheckResult 'Proxy' 'Pass' $detail))
    }

    # --- Windows quirks that bite later ------------------------------------
    try {
        $lp = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' `
                               -Name 'LongPathsEnabled' -ErrorAction Stop
        if ($lp.LongPathsEnabled -eq 1) {
            $results.Add((New-CheckResult 'Long paths' 'Pass' 'enabled'))
        } else {
            $results.Add((New-CheckResult 'Long paths' 'Warn' 'disabled (MAX_PATH = 260)' `
                'Deep Hugging Face cache paths can fail. Phase 2 shortens HF_HOME to work around it.'))
            $script:RedirectHfHome = $true
        }
    } catch {
        $results.Add((New-CheckResult 'Long paths' 'Warn' 'could not read the policy'))
    }

    try {
        $ram = [math]::Round((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory / 1GB, 1)
        # The requirement scales with the checkpoint: a 1.5B 4-bit model is
        # staged through ~2 GB of host RAM, a 14B through ~10 GB.
        $ramNeeded = if ($preview.Tier -ge 3) { 32 } elseif ($preview.Tier -eq 2) { 16 } else { 8 }
        if ($ram -ge $ramNeeded) {
            $results.Add((New-CheckResult 'System RAM' 'Pass' "$ram GB (tier $($preview.Tier) wants ${ramNeeded}+)"))
        } else {
            $results.Add((New-CheckResult 'System RAM' 'Warn' "$ram GB, tier $($preview.Tier) wants ${ramNeeded}+" `
                'QLoRA stages the checkpoint through host RAM; expect swapping while the model loads.'))
        }
    } catch {
        $results.Add((New-CheckResult 'System RAM' 'Warn' 'could not be read'))
    }

    [pscustomobject]@{
        Results  = $results
        Blocking = @($results | Where-Object { $_.Status -eq 'Block' })
        Warnings = @($results | Where-Object { $_.Status -eq 'Warn'  })
        Gpu      = $gpu
        Preview  = $preview
        Python   = $python
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

    # The plan, in the same breath as the hardware it was derived from - so the
    # operator can object before a multi-GB download rather than after.
    $p = $Report.Preview
    Write-Host ''
    Write-Host '   planned fine-tune (previewed from the hardware above):' -ForegroundColor Cyan
    Write-Host ("     model      {0}" -f $p.Model)
    Write-Host ("     precision  {0}{1}" -f $p.Precision, $(if ($p.FourBit) { ' + 4-bit NF4 weights' } else { '' }))
    Write-Host ("     batch      {0} x {1} grad-accum, {2}-token sequences, LoRA r={3}" -f `
        $p.BatchSize, $p.GradAccum, $p.SeqLen, $p.LoraR)
    Write-Host ("     wheels     {0}" -f $script:TorchIndex)
    Write-Host ("     note       {0}" -f $p.Note)
    Write-Host '     (ai_module/auto_select_model.py re-derives this from torch once installed)' -ForegroundColor DarkGray

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
    & winget install --id $Id -e --source winget --disable-interactivity `
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

function Invoke-Native {
    <#
      Run an external command, echo it, and turn a non-zero exit into a throw so
      Invoke-WithRetry can see it. PowerShell does not do this for native
      executables on its own - $ErrorActionPreference has no effect on them.
    #>
    param(
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(Mandatory)][string[]] $Arguments,
        [string] $WorkingDirectory
    )
    $previous = $null
    if ($WorkingDirectory) { $previous = (Get-Location).Path; Set-Location -LiteralPath $WorkingDirectory }
    try {
        Write-Info "> $Exe $($Arguments -join ' ')"
        & $Exe @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "$Exe exited with code $LASTEXITCODE"
        }
    } finally {
        if ($previous) { Set-Location -LiteralPath $previous }
    }
}

# ---------------------------------------------------------------------------
# uv - three independent routes, because each one fails on a different network
# ---------------------------------------------------------------------------
function Install-Uv {
    <#
      Route 1: the official astral.sh installer (needs astral.sh + GitHub releases)
      Route 2: pip install uv from PyPI  (needs only PyPI - the route that works
               on a campus link where GitHub is filtered)
      Route 3: winget astral-sh.uv

      Returns $true once `uv` is callable.
    #>
    param($Python)

    if (Test-Command 'uv') {
        Write-Ok "uv already installed: $(& uv --version)"
        return $true
    }

    # --- route 1 -----------------------------------------------------------
    try {
        Write-Info 'installing uv from https://astral.sh/uv/install.ps1 ...'
        Invoke-WithRetry -Label 'astral.sh uv installer' -Attempts 2 -ScriptBlock {
            # .Content is required: piping the response *object* straight into
            # Invoke-Expression stringifies the object, not the script body.
            (Invoke-WebRequest -Uri 'https://astral.sh/uv/install.ps1' -UseBasicParsing -TimeoutSec 60).Content |
                Invoke-Expression
        } | Out-Null
    } catch {
        Write-Warn "astral.sh route failed: $($_.Exception.Message)"
    }
    Update-SessionPath
    $uvBin = if ($env:USERPROFILE) { Join-Path $env:USERPROFILE '.local\bin' } else { $null }
    if ($uvBin -and (Test-Path -LiteralPath (Join-Path $uvBin 'uv.exe')) -and ($env:Path -notlike "*$uvBin*")) {
        $env:Path = "$uvBin;$env:Path"
    }
    if (Test-Command 'uv') { Write-Ok "uv installed via astral.sh: $(& uv --version)"; return $true }

    # --- route 2: PyPI -----------------------------------------------------
    # uv ships as a self-contained binary in its wheel, so the interpreter it is
    # installed into does not have to be the one the project will use - which is
    # why this works even on a machine whose only Python is 3.14.
    if ($Python -and $Python.Command) {
        $pyExe  = $Python.Command[0]
        $pyArgs = @()
        if ($Python.Command.Count -gt 1) { $pyArgs = $Python.Command[1..($Python.Command.Count - 1)] }
    } elseif (Test-Command 'python') {
        $pyExe = 'python'; $pyArgs = @()
    } elseif (Test-Command 'py') {
        $pyExe = 'py'; $pyArgs = @()
    } else {
        $pyExe = $null; $pyArgs = @()
    }

    if ($pyExe) {
        try {
            Write-Info "installing uv from PyPI via $pyExe ..."
            Invoke-WithRetry -Label 'pip install uv' -Attempts 3 -ScriptBlock {
                Invoke-Native -Exe $pyExe -Arguments ($pyArgs + @('-m', 'pip', 'install', '--user', '--upgrade', 'uv'))
            } | Out-Null
            Update-SessionPath
            # --user installs land in %APPDATA%\Python\PythonXY\Scripts, which is
            # not always on PATH yet in this process.
            if ($env:APPDATA) {
                foreach ($dir in (Get-ChildItem -Path (Join-Path $env:APPDATA 'Python') -Directory -ErrorAction SilentlyContinue)) {
                    $scripts = Join-Path $dir.FullName 'Scripts'
                    if (Test-Path -LiteralPath (Join-Path $scripts 'uv.exe')) {
                        $env:Path = "$scripts;$env:Path"
                    }
                }
            }
        } catch {
            Write-Warn "PyPI route failed: $($_.Exception.Message)"
        }
        if (Test-Command 'uv') { Write-Ok "uv installed from PyPI: $(& uv --version)"; return $true }
    }

    # --- route 3: winget ---------------------------------------------------
    if (Test-Command 'winget') {
        try { Invoke-Winget -Id 'astral-sh.uv' -Label 'uv' } catch { Write-Warn "winget route failed: $($_.Exception.Message)" }
        if (Test-Command 'uv') { Write-Ok "uv installed via winget: $(& uv --version)"; return $true }
    }

    return $false
}

# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------
function Install-Python {
    <#
      Ensure a torch-compatible interpreter exists. Never touches an existing
      one: a lab image's Python 3.14 stays exactly where it is, and 3.11 is
      installed alongside it.
    #>
    $python = Get-PythonProfile
    if ($python.Found) {
        Write-Ok "usable Python present: $($python.Version)"
        return $python
    }

    if ($python.All.Count -gt 0) {
        Write-Warn "Python $($python.All -join ', ') found, but torch publishes no wheels for it - installing $($script:PythonPreferred) alongside"
    } else {
        Write-Info "no usable Python found - installing $($script:PythonPreferred)"
    }

    if (Test-Command 'winget') {
        try {
            Invoke-Winget -Id $script:PythonPreferredWinget -Label "Python $($script:PythonPreferred)"
        } catch {
            Write-Warn "winget could not install Python: $($_.Exception.Message)"
        }
    } else {
        Write-Warn 'winget is not available to install Python'
    }

    $python = Get-PythonProfile
    if ($python.Found) {
        Write-Ok "Python installed: $($python.Version)"
        return $python
    }

    # uv can provision its own interpreter, but it downloads it from GitHub
    # releases - the one host most likely to be blocked on the networks this
    # fallback exists for. Try it, but do not depend on it.
    if (Test-Command 'uv') {
        Write-Info "asking uv to provision Python $($script:PythonPreferred) ..."
        try {
            Invoke-WithRetry -Label 'uv python install' -Attempts 2 -ScriptBlock {
                Invoke-Native -Exe 'uv' -Arguments @('python', 'install', $script:PythonPreferred)
            } | Out-Null
            Write-Ok "uv provisioned Python $($script:PythonPreferred)"
            # uv-managed interpreters are not on PATH; uv venv --python finds them.
            return [pscustomobject]@{
                Found = $true; Command = @('uv', 'run', 'python')
                Version = "uv-managed $($script:PythonPreferred)"; All = @(); StubOnly = $false
            }
        } catch {
            Write-Warn "uv could not provision an interpreter: $($_.Exception.Message)"
        }
    }

    return $python
}

# ---------------------------------------------------------------------------
# source acquisition
# ---------------------------------------------------------------------------
function Expand-RepoArchive {
    <#
      Unpack a GitHub zip into $Destination. GitHub archives wrap everything in
      a "<repo>-<branch>/" directory; strip it so the layout matches a clone.
    #>
    param(
        [Parameter(Mandatory)][string] $ZipPath,
        [Parameter(Mandatory)][string] $Destination
    )
    $staging = Join-Path ([System.IO.Path]::GetTempPath()) ("wss-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    try {
        Expand-Archive -LiteralPath $ZipPath -DestinationPath $staging -Force
        $roots = @(Get-ChildItem -LiteralPath $staging)
        $source = if ($roots.Count -eq 1 -and $roots[0].PSIsContainer) { $roots[0].FullName } else { $staging }
        if (-not (Test-Path -LiteralPath (Join-Path $source 'run_pipeline.sh'))) {
            throw "the archive does not look like this repository (no run_pipeline.sh at its root)"
        }
        if (-not (Test-Path -LiteralPath $Destination)) {
            New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        }
        Copy-Item -Path (Join-Path $source '*') -Destination $Destination -Recurse -Force
    } finally {
        Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-RepoSource {
    <#
      Put the repository on disk and return its path, trying every route in
      order of fidelity:

        0. we are already inside a checkout          (nothing to do)
        1. an existing clone in -InstallDir          (fetch + checkout)
        2. git clone                                 (needs git + github)
        3. HTTPS zip from codeload                   (needs github, not git)
        4. -SourceZip from disk                      (needs nothing)

      Routes 3 and 4 produce a directory that is not a git repository. That is
      fine for running the pipeline; it is called out so nobody is surprised
      when `git status` fails there later.
    #>
    param([Parameter(Mandatory)][string] $TargetDir)

    if ($PSScriptRoot -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'run_pipeline.sh'))) {
        Write-Ok "running from inside the checkout: $PSScriptRoot"
        return [pscustomobject]@{ Path = $PSScriptRoot; IsGit = (Test-Path -LiteralPath (Join-Path $PSScriptRoot '.git')) }
    }

    if (-not (Test-Path -LiteralPath $TargetDir)) {
        New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    }
    $repo = Join-Path $TargetDir 'Web_security_scanner'

    # --- route 1: existing clone ------------------------------------------
    if (Test-Path -LiteralPath (Join-Path $repo '.git')) {
        Write-Ok "existing clone found: $repo"
        if (Test-Command 'git') {
            try {
                Invoke-WithRetry -Label "git fetch origin $Branch" -Attempts 2 -ScriptBlock {
                    Invoke-Native -Exe 'git' -Arguments @('fetch', 'origin', $Branch, '--quiet') -WorkingDirectory $repo
                } | Out-Null
            } catch {
                Write-Warn "could not fetch origin/$Branch - using whatever is local"
            }
            try {
                Invoke-Native -Exe 'git' -Arguments @('checkout', $Branch) -WorkingDirectory $repo
            } catch {
                Write-Warn "git checkout $Branch failed - staying on the current branch"
            }
        }
        return [pscustomobject]@{ Path = $repo; IsGit = $true }
    }

    if ((Test-Path -LiteralPath $repo) -and @(Get-ChildItem -LiteralPath $repo -Force).Count -gt 0) {
        if (Test-Path -LiteralPath (Join-Path $repo 'run_pipeline.sh')) {
            Write-Ok "existing (non-git) copy found: $repo"
            return [pscustomobject]@{ Path = $repo; IsGit = $false }
        }
        Stop-Setup "$repo exists but is neither a checkout nor an unpacked copy - move it aside and re-run."
    }

    # --- route 2: git clone ------------------------------------------------
    if ((Test-Command 'git') -and $script:Reach['github']) {
        try {
            Write-Info "cloning $RepoUrl (branch $Branch) ..."
            Invoke-WithRetry -Label 'git clone' -Attempts 3 -ScriptBlock {
                Invoke-Native -Exe 'git' -Arguments @('clone', '--branch', $Branch, $RepoUrl, $repo)
            } | Out-Null
            Write-Ok "cloned into $repo"
            return [pscustomobject]@{ Path = $repo; IsGit = $true }
        } catch {
            Write-Warn "git clone failed - falling back to the HTTPS archive"
            Remove-Item -LiteralPath $repo -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # --- route 3: HTTPS zip ------------------------------------------------
    if ($ArchiveUrl -and $script:Reach['github']) {
        $zip = Join-Path ([System.IO.Path]::GetTempPath()) "Web_security_scanner-$Branch.zip"
        try {
            Write-Info "downloading $ArchiveUrl ..."
            Invoke-WithRetry -Label 'archive download' -Attempts 3 -ScriptBlock {
                Invoke-WebRequest -Uri $ArchiveUrl -OutFile $zip -UseBasicParsing -TimeoutSec 300
            } | Out-Null
            Expand-RepoArchive -ZipPath $zip -Destination $repo
            Write-Ok "unpacked into $repo (not a git checkout)"
            return [pscustomobject]@{ Path = $repo; IsGit = $false }
        } catch {
            Write-Warn "archive route failed: $($_.Exception.Message)"
        } finally {
            Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
        }
    }

    # --- route 4: local zip ------------------------------------------------
    if ($SourceZip) {
        if (-not (Test-Path -LiteralPath $SourceZip)) {
            Stop-Setup "-SourceZip does not exist: $SourceZip"
        }
        Write-Info "unpacking $SourceZip ..."
        try {
            Expand-RepoArchive -ZipPath $SourceZip -Destination $repo
            Write-Ok "unpacked into $repo (not a git checkout)"
            return [pscustomobject]@{ Path = $repo; IsGit = $false }
        } catch {
            Stop-Setup "could not unpack -SourceZip: $($_.Exception.Message)"
        }
    }

    Stop-Setup @"
could not obtain the source. Every route failed:
  - not running from inside a checkout
  - no existing clone in $TargetDir
  - git clone: $(if (Test-Command 'git') { 'github.com unreachable' } else { 'git is not installed' })
  - HTTPS archive: github.com unreachable
  - -SourceZip: not provided
Download $ArchiveUrl on a machine that can reach GitHub, copy it over, and re-run:
    .\setup_windows.ps1 -SourceZip C:\path\to\archive.zip
"@
}

# ---------------------------------------------------------------------------
# native pipeline - the no-Git-Bash fallback
# ---------------------------------------------------------------------------
function Get-Recipe {
    <#
      Ask ai_module.auto_select_model for the real, torch-measured recipe and
      return it as a hashtable. This is the authoritative version of the preview
      the pre-flight printed: it runs after torch is installed, so it sees the
      actual device rather than nvidia-smi's summary.
    #>
    param([Parameter(Mandatory)][string] $Repo)

    $out = & uv run python -m ai_module.auto_select_model --format recipe --quiet 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $out) { return $null }
    $recipe = @{}
    foreach ($line in $out) {
        if ($line -match '^([A-Z_]+)=(.*)$') { $recipe[$Matches[1]] = $Matches[2] }
    }
    if (-not $recipe.ContainsKey('MODEL')) { return $null }
    return $recipe
}

function Test-TorchCuda {
    <#
      Launch one real kernel.

      torch.cuda.is_available() only checks that a driver and a device exist; it
      says nothing about whether the wheel contains code for this GPU. A build
      that has retired the architecture imports fine, reports the device
      correctly, and then fails at the first launch with "no kernel image is
      available for execution on the device" - twenty minutes and one model
      download later. One 8-element tensor answers it up front.

      Returns Ok / Detail / ArchMissing.
    #>
    param([Parameter(Mandatory)][string] $Repo)

    $probe = @'
import sys, torch
if not torch.cuda.is_available():
    print("NOCUDA " + torch.__version__); sys.exit(0)
try:
    torch.zeros(8, device="cuda").sum().item()
    cap = torch.cuda.get_device_capability()
    print("OK %s sm_%d%d" % (torch.__version__, cap[0], cap[1]))
except Exception as exc:
    print("FAIL %s %s: %s" % (torch.__version__, type(exc).__name__, exc))
'@
    $probeFile = Join-Path ([System.IO.Path]::GetTempPath()) "torch_probe_$PID.py"
    [System.IO.File]::WriteAllText($probeFile, $probe)
    $lines = @()
    try {
        # --quiet keeps uv's own build/install chatter out of the capture.
        $lines = @(& uv run --quiet python $probeFile 2>&1 | ForEach-Object { "$_" })
    } catch {
        $lines = @("FAIL could not run the probe: $($_.Exception.Message)")
    } finally {
        Remove-Item -LiteralPath $probeFile -Force -ErrorAction SilentlyContinue
    }

    # The probe prints exactly one line with a known prefix; a traceback prints
    # none, in which case the whole output is the diagnosis.
    $verdict = @($lines | Where-Object { $_ -match '^(OK|NOCUDA|FAIL) ' } | Select-Object -Last 1)
    $out = if ($verdict.Count) { $verdict[0] } else { ($lines -join ' ') }

    $archMissing = $out -match 'no kernel image|not compatible with the current PyTorch'
    return [pscustomobject]@{
        Ok          = ($out -match '^OK ')
        Detail      = $out.Trim()
        ArchMissing = [bool]$archMissing
        NoCuda      = ($out -match '^NOCUDA ')
    }
}

function Assert-TorchUsable {
    <# Turn a failed kernel launch into an instruction, not a stack trace. #>
    param([Parameter(Mandatory)][string] $Repo)

    $probe = Test-TorchCuda -Repo $Repo
    if ($probe.Ok) {
        Write-Ok "torch can launch kernels on this GPU ($($probe.Detail))"
        return
    }
    if ($probe.NoCuda) {
        Write-Warn "torch was installed without CUDA support ($($probe.Detail)) - training will run on the CPU and take hours"
        Write-Info "re-run with -TorchIndexUrl $($script:TorchIndex) once the network allows it"
        return
    }
    if ($probe.ArchMissing) {
        $arch = if ($script:Gpu -and $script:Gpu.CapabilityText) { $script:Gpu.CapabilityText } else { 'this GPU' }
        Stop-Setup @"
torch installed correctly but has no kernels for ${arch}:
    $($probe.Detail)
PyTorch drops old compute capabilities as it moves on. Install the last build
that still had them:
    .\setup_windows.ps1 -SkipPreflight -TorchSpec "torch==2.7.1"
(then, if that build is also too new, step back another minor version). The
existing venv is reused, so only the torch wheel is re-downloaded.
"@
    }
    Write-Warn "the torch CUDA probe did not succeed: $($probe.Detail)"
    Write-Info 'continuing - the smoke test below will show whether training actually works'
}

function Invoke-PipelineNative {
    <#
      run_pipeline.sh without bash. Same steps, same order, same knobs - kept
      deliberately thin, because run_pipeline.sh remains the reference
      implementation and this exists only for a machine where Git Bash could not
      be installed (which, on a network that filters GitHub, is exactly the
      machine that most needs a way through).
    #>
    param(
        [Parameter(Mandatory)][string] $Repo,
        [Parameter(Mandatory)][string] $TorchIndex
    )

    Write-Step 'Python environment (native path)'
    $venvPython = Join-Path $Repo '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $venvPython)) {
        Invoke-WithRetry -Label 'uv venv' -Attempts 2 -ScriptBlock {
            Invoke-Native -Exe 'uv' -Arguments @('venv', '--python', $script:PythonPreferred) -WorkingDirectory $Repo
        } | Out-Null
    }
    if (-not (Test-Path -LiteralPath $venvPython)) {
        Stop-Setup "uv venv did not produce $venvPython"
    }
    Write-Ok "venv: $venvPython"

    Write-Step 'AI stack'
    # torch first and from its own index: installed as part of ".[ai]" it comes
    # from PyPI, which on Windows means the CPU-only build.
    Invoke-WithRetry -Label 'uv pip install torch' -Attempts 3 -DelaySeconds 5 -ScriptBlock {
        Invoke-Native -Exe 'uv' -Arguments @('pip', 'install', $TorchSpec, '--index-url', $TorchIndex) -WorkingDirectory $Repo
    } | Out-Null
    Invoke-WithRetry -Label 'uv pip install .[ai]' -Attempts 3 -DelaySeconds 5 -ScriptBlock {
        Invoke-Native -Exe 'uv' -Arguments @('pip', 'install', '-e', '.[ai]') -WorkingDirectory $Repo
    } | Out-Null
    Write-Ok 'AI stack installed'

    Set-Location -LiteralPath $Repo
    Assert-TorchUsable -Repo $Repo

    Set-Location -LiteralPath $Repo

    Write-Step 'Hardware profiling & training recipe'
    $recipe = Get-Recipe -Repo $Repo
    if (-not $recipe) {
        Stop-Setup 'ai_module.auto_select_model could not profile the GPU - is torch installed correctly?'
    }
    Write-Ok ("model      {0} (tier {1})" -f $recipe['MODEL'], $recipe['TIER'])
    Write-Ok ("hardware   {0} GB VRAM{1}" -f $recipe['VRAM_GB'],
        $(if ($recipe['CAPABILITY']) { ", sm_$($recipe['CAPABILITY'] -replace '\.', '')" } else { '' }))
    Write-Ok ("knobs      precision={0} 4bit={1} batch={2} accum={3} seq={4} lora_r={5}" -f `
        $recipe['PRECISION'], $recipe['LOAD_IN_4BIT'], $recipe['BATCH_SIZE'],
        $recipe['GRAD_ACCUM'], $recipe['MAX_SEQ_LEN'], $recipe['LORA_R'])
    if ($recipe['PRECISION'] -eq 'fp16') {
        Write-Info 'this GPU predates Ampere: bf16 and TF32 are off, fp16 is used instead'
    }

    # The knobs, as train_qlora.py flags.
    $knobs = @(
        '--precision',   $recipe['PRECISION']
        '--batch-size',  $recipe['BATCH_SIZE']
        '--grad-accum',  $recipe['GRAD_ACCUM']
        '--max-seq-len', $recipe['MAX_SEQ_LEN']
        '--lora-r',      $recipe['LORA_R']
        '--optim',       $recipe['OPTIM']
        '--num-workers', $recipe['NUM_WORKERS']
        '--attn-impl',   $recipe['ATTN_IMPL']
    )
    if ($recipe['LOAD_IN_4BIT'] -eq '1') { $knobs += '--load-in-4bit' }
    if ($recipe['TF32'] -ne '1')         { $knobs += '--no-tf32' }

    Write-Step 'Dataset'
    $train = $null; $val = $null
    foreach ($stem in @("data/sft.$Task", "data/$Task")) {
        if ((Test-Path -LiteralPath "$stem.train.jsonl") -and (Test-Path -LiteralPath "$stem.val.jsonl")) {
            $train = "$stem.train.jsonl"; $val = "$stem.val.jsonl"; break
        }
    }
    if (-not $train) {
        Stop-Setup "no dataset for task '$Task' under data/ - regenerate it with run_pipeline.sh --regen-data"
    }
    Write-Ok "train: $train"
    Write-Ok "eval : $val"

    Write-Step 'Base-model download'
    Invoke-WithRetry -Label 'ensure_base_model' -Attempts 2 -DelaySeconds 10 -ScriptBlock {
        Invoke-Native -Exe 'uv' -Arguments @('run', 'python', '-m', 'ai_module.ensure_base_model',
                                             $recipe['MODEL'], '--retries', '3') -WorkingDirectory $Repo
    } | Out-Null
    Write-Ok 'base model cached'

    Write-Step 'QLoRA smoke test (5 steps)'
    Remove-Item -LiteralPath (Join-Path $Repo 'runs\_smoke') -Recurse -Force -ErrorAction SilentlyContinue
    Invoke-Native -Exe 'uv' -Arguments (@('run', 'python', '-m', 'ai_module.train_qlora',
        '--base-model', $recipe['MODEL'], '--dataset', $train,
        '--output-dir', 'runs/_smoke', '--max-steps', '5') + $knobs) -WorkingDirectory $Repo
    Write-Ok 'smoke test OK - CUDA, bitsandbytes and the data pipeline all respond'

    if ($SkipTrain) {
        Write-Warn 'full fine-tune skipped (-SkipTrain)'
        return
    }

    Write-Step 'Full QLoRA fine-tune'
    $outDir = "runs/$Task-qlora"
    $full = @('run', 'python', '-m', 'ai_module.train_qlora',
              '--base-model', $recipe['MODEL'],
              '--dataset', $train, '--eval', $val,
              '--output-dir', $outDir,
              '--epochs', "$Epochs") + $knobs
    if ($recipe['MERGE_ADAPTER'] -eq '1') { $full += '--merge-adapter' }
    Invoke-Native -Exe 'uv' -Arguments $full -WorkingDirectory $Repo
    Write-Ok "fine-tune complete -> $outDir/adapter/"
    if ($recipe['MERGE_ADAPTER'] -ne '1') {
        Write-Info 'no merged model: a LoRA cannot be merged losslessly into 4-bit NF4 weights - serve the adapter on top of the base'
    }
}

# ===========================================================================
# main
# ===========================================================================

# Transcribe everything. A failure twenty minutes into a wheel download is not
# reproducible by scrolling a lab PC's console buffer.
if (-not $LogFile) {
    $LogFile = Join-Path $InstallDir ("setup_windows_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
}
$script:LogPath = $LogFile
try {
    if (-not (Test-Path -LiteralPath (Split-Path $LogFile -Parent))) {
        New-Item -ItemType Directory -Path (Split-Path $LogFile -Parent) -Force | Out-Null
    }
    Start-Transcript -Path $LogFile -Force | Out-Null
} catch {
    $script:LogPath = $null
    Write-Warning "could not start the transcript ($($_.Exception.Message)) - continuing without a log file"
}

Write-Host ''
Write-Host 'Web_security_scanner - Windows one-shot setup' -ForegroundColor Cyan
Write-Host ("  branch : {0}" -f $Branch)
Write-Host ("  target : {0}" -f $InstallDir)
Write-Host ("  task   : {0} ({1} epochs)" -f $Task, $Epochs)
if ($script:LogPath) { Write-Host ("  log    : {0}" -f $script:LogPath) }

$startedAt = Get-Date
Update-SessionPath

$activeProxy = Initialize-Proxy -Explicit $Proxy
if ($activeProxy) {
    Write-Host ("  proxy  : {0}{1}" -f $activeProxy,
        $(if ($script:ProxyFromSystem) { ' (from the system settings)' } else { '' }))
}

# ---------------------------------------------------------------------------
# phase 1
# ---------------------------------------------------------------------------
if ($SkipPreflight) {
    Write-Step 'Pre-flight check'
    Write-Warn 'skipped (-SkipPreflight)'
    if ($CheckOnly) { Stop-Setup '-CheckOnly and -SkipPreflight are contradictory.' }
    # The installers below read these; without the check they are unset.
    $script:Gpu        = Get-GpuProfile
    $script:Preview    = Get-TrainingPreview -Gpu $script:Gpu
    $script:TorchIndex = if ($TorchIndexUrl) { $TorchIndexUrl } else { Resolve-TorchIndexUrl -Gpu $script:Gpu }
    $script:Reach      = @{ github = $true; pypi = $true; models = $true; uv = $true; python = $true; torch = $true }
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
            try { Stop-Transcript | Out-Null } catch { }
            exit 1
        } else {
            Stop-Setup @"
the pre-flight check found $($report.Blocking.Count) blocking problem(s) - see the
red lines above. Nothing was installed and nothing was downloaded.
Each one lists what to do; the usual answers are -Proxy http://host:port for a
filtered network and -SourceZip C:\path\repo.zip for a blocked GitHub.
Fix them and re-run, or pass -Force to proceed anyway.
"@
        }
    }

    if ($CheckOnly) {
        Write-Host ''
        Write-Host 'OK  READY - re-run without -CheckOnly to install and start the pipeline' -ForegroundColor Green
        try { Stop-Transcript | Out-Null } catch { }
        exit 0
    }
}

# ---------------------------------------------------------------------------
# phase 2.1 Git (Git Bash) - optional
# ---------------------------------------------------------------------------
Write-Step 'Git / Git Bash'
if (Test-Command 'git') {
    Write-Ok "git already installed: $(& git --version)"
} elseif (Test-Command 'winget') {
    try {
        Invoke-Winget -Id 'Git.Git' -Label 'Git'
    } catch {
        Write-Warn "winget could not install Git: $($_.Exception.Message)"
    }
    if (-not (Test-Command 'git')) {
        # winget put git on the persisted PATH but the shim may lag; add it by hand
        foreach ($root in @("$env:ProgramFiles\Git", "$env:LOCALAPPDATA\Programs\Git")) {
            $cmd = Join-Path $root 'cmd'
            if (Test-Path -LiteralPath (Join-Path $cmd 'git.exe')) {
                $env:Path = "$cmd;$env:Path"
            }
        }
    }
    if (Test-Command 'git') {
        Write-Ok "git installed: $(& git --version)"
    } else {
        # Not fatal: Git's installer is hosted on GitHub, so this is the expected
        # outcome on precisely the networks where the zip route is needed.
        Write-Warn 'git could not be installed - continuing without it (the pipeline will run natively from PowerShell)'
    }
} else {
    Write-Warn 'no git and no winget - continuing without them'
}

# ---------------------------------------------------------------------------
# phase 2.2 Python
# ---------------------------------------------------------------------------
Write-Step "Python (torch needs $($script:PythonOkVersions -join ' / '))"
$python = Install-Python
if (-not $python.Found) {
    Stop-Setup @"
no interpreter that torch has wheels for.
Install Python $($script:PythonPreferred) from https://www.python.org/downloads/windows/
(tick "Add python.exe to PATH"), then re-run this script.
"@
}

# ---------------------------------------------------------------------------
# phase 2.3 uv
# ---------------------------------------------------------------------------
Write-Step 'uv package manager'
if (-not (Install-Uv -Python $python)) {
    Stop-Setup @"
uv could not be installed by any route (astral.sh, PyPI, winget).
Install it by hand and re-run:
    $($python.Command -join ' ') -m pip install --user uv
or download it from https://github.com/astral-sh/uv/releases
"@
}

# ---------------------------------------------------------------------------
# phase 2.4 source
# ---------------------------------------------------------------------------
Write-Step "Repository (branch: $Branch)"
$source = Get-RepoSource -TargetDir $InstallDir
$repo = $source.Path
Set-Location -LiteralPath $repo
if ($source.IsGit -and (Test-Command 'git')) {
    Write-Ok "on branch $(& git rev-parse --abbrev-ref HEAD) @ $(& git rev-parse --short HEAD)"
} else {
    Write-Warn 'this copy is not a git checkout - `git pull` will not work here'
}

# ---------------------------------------------------------------------------
# phase 2.5 environment tuning for this machine
# ---------------------------------------------------------------------------
Write-Step 'Environment tuning'

# Keep the Hugging Face cache on the roomy volume, and keep its path short:
# HF cache paths nest deeply, and this image may not have long paths enabled.
if ($script:RedirectHfHome -and -not $env:HF_HOME) {
    $hfHome = Join-Path $InstallDir '.hf'
    New-Item -ItemType Directory -Path $hfHome -Force | Out-Null
    $env:HF_HOME = $hfHome
    Write-Ok "HF_HOME -> $hfHome"
}
# Fragmentation is what turns a run that fits into an OOM on a small card.
if (-not $env:PYTORCH_CUDA_ALLOC_CONF) {
    $env:PYTORCH_CUDA_ALLOC_CONF = 'expandable_segments:True'
}
$env:TORCH_INDEX_URL = $script:TorchIndex
$env:TORCH_SPEC      = $TorchSpec
Write-Ok "torch wheel index: $($script:TorchIndex)"
if ($TorchSpec -ne 'torch') { Write-Ok "torch pinned to: $TorchSpec" }
if ($script:Gpu) {
    Write-Ok ("GPU: {0}, {1} GB VRAM, driver {2}" -f $script:Gpu.Name, $script:Gpu.VramGB, $script:Gpu.Driver)
} else {
    Write-Warn 'no NVIDIA GPU - the pipeline will pick a CPU-sized model and train slowly'
}

# ---------------------------------------------------------------------------
# phase 2.6 run
# ---------------------------------------------------------------------------
if ($SkipPipeline) {
    Write-Step 'Pipeline'
    Write-Warn 'skipping the pipeline (-SkipPipeline)'
    $bash = Resolve-GitBash
    if ($bash) { Write-Info "run it later with:  & '$bash' run_pipeline.sh" }
    else       { Write-Info "run it later with:  .\setup_windows.ps1 -SkipPreflight" }
} else {
    $bash = if ($NativeRun) { $null } else { Resolve-GitBash }

    if ($bash) {
        Write-Step 'Launching run_pipeline.sh through Git Bash'
        Write-Ok "bash: $bash"
        if (-not (Test-Path -LiteralPath (Join-Path $repo 'run_pipeline.sh'))) {
            Stop-Setup "run_pipeline.sh not found in $repo"
        }

        $args = @('run_pipeline.sh', '--task', $Task, '--epochs', "$Epochs")
        if ($SkipTrain) { $args += '--skip-train' }
        $args += $PipelineArgs
        if ($PipelineArgs.Count) { Write-Info "extra args: $($PipelineArgs -join ' ')" }
        Write-Info 'handing over to run_pipeline.sh - this can take a long while'
        Write-Host ''

        # MSYS2_ARG_CONV_EXCL stops Git Bash from mangling "--flag=/value" style
        # arguments into Windows paths on their way to the script.
        $env:MSYS2_ARG_CONV_EXCL = '*'
        $env:MSYS_NO_PATHCONV    = '1'

        & $bash @args
        $rc = $LASTEXITCODE
        if ($rc -ne 0) {
            Stop-Setup @"
run_pipeline.sh exited with code $rc.
The step that failed is the last one printed above. Common causes on this kind
of machine, in order of likelihood:
  - a wheel download interrupted   -> just re-run; everything is idempotent
  - CUDA out of memory             -> the trainer already retried with a smaller
                                      batch; if it still fails, try
                                      -PipelineArgs '--base-model','unsloth/Qwen2.5-0.5B-Instruct-bnb-4bit'
  - torch cannot see the GPU       -> the driver is older than the wheels; re-run
                                      with -TorchIndexUrl https://download.pytorch.org/whl/cu118
"@
        }
    } else {
        Write-Step 'Running the pipeline natively (no Git Bash available)'
        if ($NativeRun) { Write-Info 'forced by -NativeRun' }
        else { Write-Warn 'Git Bash was not found - using the PowerShell equivalent of run_pipeline.sh' }
        if ($PipelineArgs.Count) {
            Write-Warn "-PipelineArgs is only forwarded to run_pipeline.sh; ignored on the native path: $($PipelineArgs -join ' ')"
        }
        Invoke-PipelineNative -Repo $repo -TorchIndex $script:TorchIndex
    }
}

# ---------------------------------------------------------------------------
# done
# ---------------------------------------------------------------------------
$took = (Get-Date) - $startedAt
Write-Host ''
Write-Host ("OK  SETUP COMPLETE  total time: {0:hh\:mm\:ss}" -f $took) -ForegroundColor Green
Write-Host ("    repo: {0}" -f $repo)
if (-not $SkipPipeline -and -not $SkipTrain) {
    Write-Host ("    adapter: {0}" -f (Join-Path $repo "runs\$Task-qlora\adapter"))
}
if ($script:Warnings.Count) {
    Write-Host ''
    Write-Host ("    {0} warning(s) along the way:" -f $script:Warnings.Count) -ForegroundColor Yellow
    foreach ($w in $script:Warnings) { Write-Host "      - $w" -ForegroundColor Yellow }
}
if ($script:LogPath) { Write-Host ("    log : {0}" -f $script:LogPath) }
try { Stop-Transcript | Out-Null } catch { }
