# install-windows.ps1 — one-line installer for the Ankayma headless Windows client
# (CLI mesh.exe + daemon agent.exe, no GUI/WebView2) — for Windows Server, not desktop use.
#
# Registers `AnkaymaHeadless` as a real Windows Service (LocalSystem, auto-start) that spawns
# `agent up` on its own at boot — crates/agent-daemon/src/win_service_headless.rs. This is
# a DIFFERENT service from the GUI's `Ankayma` (win_service.rs, waits for a GUI Connect
# over a named pipe) — the two can coexist, they serve different use cases.
#
# Usage (elevated PowerShell):
#   iwr https://get.ankayma.com/windows-headless/install.ps1 -UseBasicParsing | iex
#
# First-time enrollment needs a node join-token (E-3 — same mechanism the GUI's
# QR-scan/paste-invite flow redeems; get one from the control plane / an admin):
#   $env:ANKAYMA_JOIN_TOKEN = "<token>"
#   iwr https://get.ankayma.com/windows-headless/install.ps1 -UseBasicParsing | iex
# Re-running later (upgrade) with no token is fine — the daemon reuses the identity
# already persisted under C:\ProgramData\Ankayma from the first run.
#
# Overridable via environment before running:
#   ANKAYMA_BASE_URL       download host        (default https://get.ankayma.com/windows-headless)
#   ANKAYMA_VERSION        version dir to fetch  (default "latest")
#   ANKAYMA_PREFIX         install dir           (default C:\Program Files\Ankayma)
#   ANKAYMA_CONTROL_PLANE  control-plane URL     (default https://cp.ankayma.com)
#   ANKAYMA_JOIN_TOKEN     node join-token (E-3) — first run only
#   ANKAYMA_NO_COSIGN      set =1 to skip the Cosign step when cosign is unavailable

$ErrorActionPreference = "Stop"

function Say($msg) { Write-Host $msg }
function Die($msg) { Write-Error $msg; exit 1 }

# ── 1. Platform + privilege check ────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Die "Run this from an elevated (Administrator) PowerShell — needs to install a service." }

$BaseUrl = if ($env:ANKAYMA_BASE_URL) { $env:ANKAYMA_BASE_URL } else { "https://get.ankayma.com/windows-headless" }
$Version = if ($env:ANKAYMA_VERSION) { $env:ANKAYMA_VERSION } else { "latest" }
$Prefix = if ($env:ANKAYMA_PREFIX) { $env:ANKAYMA_PREFIX } else { "C:\Program Files\Ankayma" }
$ControlPlane = if ($env:ANKAYMA_CONTROL_PLANE) { $env:ANKAYMA_CONTROL_PLANE } else { "https://cp.ankayma.com" }
$StateDir = "C:\ProgramData\Ankayma"
$ServiceName = "AnkaymaHeadless"

$dl = "$BaseUrl/$Version"
$tmp = Join-Path $env:TEMP ("ankayma-install-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    function Fetch($name) {
        try {
            Invoke-WebRequest -Uri "$dl/$name" -OutFile (Join-Path $tmp $name) -UseBasicParsing
            return $true
        }
        catch { return $false }
    }

    Say "-> Downloading Ankayma headless client ($Version, windows-amd64) from $BaseUrl ..."
    if (-not (Fetch "agent-windows-amd64.exe")) { Die "Download failed: $dl/agent-windows-amd64.exe" }
    if (-not (Fetch "mesh-windows-amd64.exe")) { Die "Download failed: $dl/mesh-windows-amd64.exe" }
    if (-not (Fetch "SHA256SUMS")) { Die "Download failed: $dl/SHA256SUMS" }
    $haveSig = Fetch "SHA256SUMS.sig"
    $havePub = Fetch "cosign.pub"

    # ── 2. Integrity: SHA-256 against the checksum manifest ─────────────────
    Say "-> Verifying SHA-256 checksums ..."
    Push-Location $tmp
    try {
        $ok = $true
        Get-Content "SHA256SUMS" | ForEach-Object {
            if ($_ -match '^([0-9a-f]{64})\s+(\S+)$') {
                $want = $Matches[1]; $file = $Matches[2]
                if (Test-Path $file) {
                    $got = (Get-FileHash -Algorithm SHA256 $file).Hash.ToLower()
                    if ($got -ne $want) { Say "  MISMATCH: $file"; $ok = $false }
                }
            }
        }
        if (-not $ok) { Die "Checksum mismatch - refusing to install." }
    }
    finally { Pop-Location }
    Say "  OK checksums match"

    # ── 3. Authenticity: Cosign signature of the checksum manifest ──────────
    $cosign = Get-Command cosign -ErrorAction SilentlyContinue
    if ($cosign) {
        if (-not $haveSig -or -not $havePub) {
            Die "cosign is installed but the host has no SHA256SUMS.sig/cosign.pub - cannot verify. Refusing to install."
        }
        Say "-> Verifying Cosign signature ..."
        Push-Location $tmp
        try {
            cosign verify-blob --insecure-ignore-tlog --key cosign.pub --signature SHA256SUMS.sig SHA256SUMS
            if ($LASTEXITCODE -ne 0) { Die "Cosign signature INVALID - refusing to install. Report this." }
        }
        finally { Pop-Location }
        Say "  OK signature valid (key: cosign.pub)"
    }
    elseif ($env:ANKAYMA_NO_COSIGN -eq "1") {
        Write-Warning "cosign not installed - skipping signature check (ANKAYMA_NO_COSIGN=1)."
        Write-Warning "  Integrity is still enforced via HTTPS + SHA-256, but authenticity is not."
    }
    else {
        Write-Error "cosign is not installed - cannot verify the publisher signature."
        Write-Error "  Install it (https://docs.sigstore.dev/cosign/installation) then re-run, or"
        Write-Error "  set `$env:ANKAYMA_NO_COSIGN='1' to proceed on HTTPS+checksum integrity alone."
        exit 1
    }

    # ── 4. Install binaries ──────────────────────────────────────────────────
    Say "-> Installing to $Prefix (agent.exe, mesh.exe) ..."
    New-Item -ItemType Directory -Force -Path $Prefix | Out-Null
    Copy-Item (Join-Path $tmp "agent-windows-amd64.exe") (Join-Path $Prefix "agent.exe") -Force
    Copy-Item (Join-Path $tmp "mesh-windows-amd64.exe") (Join-Path $Prefix "mesh.exe") -Force
    $agentExe = Join-Path $Prefix "agent.exe"

    # ── 5. First-run enrollment (only when a join-token was given) ──────────
    # `agent up --join-token <T>` is the intended "headless server path" (up.rs's own
    # comment: a golden image / MOTD never redeems a full-power secret - the join
    # token is single-use + short-TTL and enrolls this node directly). `agent up` has
    # no one-shot enroll-then-exit mode, so run it in the background just long enough
    # for AgentState to land at $StateDir\agent.json, then stop it - the Windows
    # Service registered below starts the real, persistent run with no token (see
    # win_service_headless.rs::spawn_agent_up, which never passes one). The token is
    # deliberately never given to `sc.exe create`/stored in the service config: service
    # binPath is readable by any local admin tool and shows up in event logs - it is
    # only ever live on this short-lived foreground process's command line.
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    $agentJson = Join-Path $StateDir "agent.json"
    if ($env:ANKAYMA_JOIN_TOKEN) {
        Say "-> Enrolling this node (join-token given) ..."
        $enrollLog = Join-Path $tmp "enroll.log"
        $proc = Start-Process -FilePath $agentExe -ArgumentList @(
            "up", "--join-token", $env:ANKAYMA_JOIN_TOKEN,
            "--control-plane", $ControlPlane,
            "--state-dir", $StateDir
        ) -PassThru -WindowStyle Hidden -RedirectStandardOutput $enrollLog -RedirectStandardError "$enrollLog.err"

        $deadline = (Get-Date).AddSeconds(30)
        while (-not (Test-Path $agentJson) -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 500
        }
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path $agentJson)) {
            Say "Enrollment did not complete within 30s:"
            Get-Content $enrollLog, "$enrollLog.err" -ErrorAction SilentlyContinue | Write-Host
            Die "Refusing to install the service without a persisted identity."
        }
        Say "  OK enrolled, identity persisted to $agentJson"
    }
    elseif (-not (Test-Path $agentJson)) {
        Write-Warning "No `$env:ANKAYMA_JOIN_TOKEN given and no existing identity in $StateDir - the"
        Write-Warning "service will start but has nothing to enroll with. Get a node join-token from"
        Write-Warning "your admin / control plane and re-run with `$env:ANKAYMA_JOIN_TOKEN set."
    }

    # ── 6. Windows Service: always up, restart on crash, survives reboot ────
    Say "-> Registering $ServiceName service ..."
    & sc.exe query $ServiceName 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        sc.exe stop $ServiceName 2>$null | Out-Null
        Start-Sleep -Seconds 1
        sc.exe delete $ServiceName | Out-Null
    }
    sc.exe create $ServiceName binPath= "`"$agentExe`" service-headless" start= auto obj= LocalSystem DisplayName= "Ankayma (headless)"
    if ($LASTEXITCODE -ne 0) { Die "sc.exe create failed" }
    # Mirror packaging/ankayma-agent.service's Restart=on-failure/RestartSec=2: retry
    # every 2s, reset the failure counter after a day of healthy uptime.
    sc.exe failure $ServiceName reset= 86400 actions= restart/2000/restart/2000/restart/2000 | Out-Null
    sc.exe description $ServiceName "Ankayma mesh agent (headless/server data-plane daemon)" | Out-Null
    sc.exe start $ServiceName
    if ($LASTEXITCODE -ne 0) { Die "sc.exe start failed" }

    Say ""
    Say "OK Installed and started:"
    Say "    $Prefix\agent.exe, $Prefix\mesh.exe"
    Say "    Service $ServiceName (auto-start, LocalSystem, restarts on crash)"
    Say ""
    Say "Check status:"
    Say "    Get-Service $ServiceName"
    Say "    Get-Content $StateDir\agent-status.json"
    Say ""
    Say "The agent is open source - audit it: https://github.com/ankayma/open-client"
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
