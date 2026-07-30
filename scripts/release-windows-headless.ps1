# release-windows-headless.ps1 — build unsigned headless Windows binaries (mesh + agent),
# checksum, cosign-sign, stage for R2 publish under get.ankayma.com/windows-headless/.
#
# Native build on windows-latest (no cross-compile). Mirrors scripts/release-linux.sh's
# structure (build -> stage -> checksum -> cosign), minus the apt/yum/nfpm packaging layer:
# this ships as raw binaries + install-windows.ps1, the same curl|sh-style model Linux uses,
# not an installer package (deliberately no MSI infra).
#
# Authenticode: NOT wired here. docs/windows-signing-setup.md's Azure Trusted Signing is a
# separate, still-open TODO for the GUI installer too — this pipeline does not block on it.
# Ships unsigned + cosign-signed SHA256SUMS, the same integrity posture as today's GUI .exe.
#
# Required env to sign (optional — script builds unsigned artifacts without them):
#   COSIGN_PASSWORD   password for cosign.key
#   cosign.key        repo-root private key (git-ignored / provided out of band)
#   cosign.pub        repo-root public key (committed)
#
# Run from repo root: pwsh scripts/release-windows-headless.ps1
# Output: dist/<version>/ — agent-windows-amd64.exe, mesh-windows-amd64.exe, SHA256SUMS(.sig),
# cosign.pub, install-windows.ps1.

$ErrorActionPreference = "Stop"

Set-Location (Join-Path $PSScriptRoot "..")

# Same version source as every other release artifact. The workspace Cargo.toml version is
# a crate version and does not track releases - it read 1.1.8 while the tag being built was
# v1.1.33, which would publish under a number matching nothing a user can see.
# tauri.conf.json is what the DMG, the updater manifest and the tag all derive from.
$versionMatch = Select-String -Path "gui/src-tauri/tauri.conf.json" -Pattern '"version" *: *"(.*)"' | Select-Object -First 1
if (-not $versionMatch) { throw "could not read version from gui/src-tauri/tauri.conf.json" }
$Version = $versionMatch.Matches[0].Groups[1].Value
$Out = "dist/$Version"

Write-Host "-> Building agent + mesh (release, native x86_64-pc-windows-msvc) ..."
cargo build --release --locked --bin agent --bin mesh
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

New-Item -ItemType Directory -Force -Path $Out | Out-Null
Copy-Item "target/release/agent.exe" "$Out/agent-windows-amd64.exe" -Force
Copy-Item "target/release/mesh.exe" "$Out/mesh-windows-amd64.exe" -Force
Copy-Item "cosign.pub" "$Out/cosign.pub" -Force
Copy-Item "scripts/install-windows.ps1" "$Out/install-windows.ps1" -Force

Write-Host "-> Checksums ..."
Push-Location $Out
try {
    $hashes = Get-FileHash -Algorithm SHA256 "agent-windows-amd64.exe", "mesh-windows-amd64.exe"
    $lines = $hashes | ForEach-Object { "{0}  {1}" -f $_.Hash.ToLower(), (Split-Path $_.Path -Leaf) }
    Set-Content -Path "SHA256SUMS" -Value $lines -Encoding ascii -NoNewline:$false
}
finally {
    Pop-Location
}

if (Test-Path "cosign.key") {
    if (-not $env:COSIGN_PASSWORD) {
        throw "set COSIGN_PASSWORD to sign (or remove cosign.key to skip signing)"
    }
    if (-not (Get-Command cosign -ErrorAction SilentlyContinue)) {
        throw "cosign not installed — see https://docs.sigstore.dev/cosign/installation"
    }
    Write-Host "-> Signing SHA256SUMS with cosign ..."
    cosign sign-blob --yes --tlog-upload=false --key cosign.key `
        --output-signature "$Out/SHA256SUMS.sig" "$Out/SHA256SUMS"
    if ($LASTEXITCODE -ne 0) { throw "cosign sign-blob failed" }
    cosign verify-blob --insecure-ignore-tlog --key cosign.pub `
        --signature "$Out/SHA256SUMS.sig" "$Out/SHA256SUMS"
    if ($LASTEXITCODE -ne 0) { throw "cosign verify-blob failed" }
    Write-Host "  OK signature verified"
}
else {
    Write-Warning "cosign.key not found - skipping signature (unsigned artifacts; do NOT publish as release)."
}

Write-Host ""
Write-Host "OK Built $Out :"
Get-ChildItem $Out | Format-Table Name, Length
