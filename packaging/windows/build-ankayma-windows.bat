@echo off
:: build-ankayma-windows.bat — Windows build script for the Ankayma GUI installer.
::
:: Invoked by Tauri beforeBuildCommand on a Windows CI runner (or dev machine).
:: Produces:
::   target\release\agent.exe          — unprivileged daemon (bundled by Tauri)
::   target\release\ankayma-service.exe — Windows Service (bundled by Tauri)
::   gui\src-tauri\wix\wintun.dll       — Wintun TUN driver DLL (from wintun.net)
::
:: Prerequisites (installed on the build machine):
::   - Rust (msvc toolchain, x86_64-pc-windows-msvc)
::   - cargo
::   - PowerShell (for wintun.dll download)
::   - NSIS or WiX (managed by tauri-cli)
::
:: [A verified-on-windows] — requires a Windows host; not runnable on macOS.

setlocal ENABLEEXTENSIONS
set SCRIPT_DIR=%~dp0
:: Resolve workspace root (2 levels up from packaging\windows\)
:: packaging\windows\ → packaging\ → workspace-root\
pushd "%SCRIPT_DIR%..\..\"
set WORKSPACE_ROOT=%CD%\
popd

echo [build] Building frontend...
cd /d "%WORKSPACE_ROOT%gui\frontend\app-gui"
call npm run build
if ERRORLEVEL 1 ( echo [FAIL] frontend build && exit /b 1 )

echo [build] Building agent.exe (release)...
cd /d "%WORKSPACE_ROOT%"
cargo build --release --bin agent --target x86_64-pc-windows-msvc
if ERRORLEVEL 1 ( echo [FAIL] agent build && exit /b 1 )

echo [build] Building ankayma-service.exe (release)...
cargo build --release --bin ankayma-service --target x86_64-pc-windows-msvc
if ERRORLEVEL 1 ( echo [FAIL] ankayma-service build && exit /b 1 )

:: Copy binaries to target\release\ so Tauri's externalBin path resolves.
copy /Y "%WORKSPACE_ROOT%target\x86_64-pc-windows-msvc\release\agent.exe" "%WORKSPACE_ROOT%target\release\agent.exe"
copy /Y "%WORKSPACE_ROOT%target\x86_64-pc-windows-msvc\release\ankayma-service.exe" "%WORKSPACE_ROOT%target\release\ankayma-service.exe"

:: Download wintun.dll (Microsoft-signed, from wintun.net) if not already cached.
:: We use the amd64 build. SHA-256 should be verified in CI. [A verified-on-windows]
set WINTUN_VERSION=0.14.1
set WINTUN_ZIP=%TEMP%\wintun-%WINTUN_VERSION%.zip
set WINTUN_DIR=%TEMP%\wintun-%WINTUN_VERSION%
set WINTUN_DLL_DST=%WORKSPACE_ROOT%gui\src-tauri\wix\wintun.dll

if not exist "%WINTUN_DLL_DST%" (
    echo [build] Downloading wintun %WINTUN_VERSION%...
    powershell -Command "Invoke-WebRequest -Uri 'https://www.wintun.net/builds/wintun-%WINTUN_VERSION%.zip' -OutFile '%WINTUN_ZIP%'"
    if ERRORLEVEL 1 ( echo [FAIL] wintun download && exit /b 1 )
    powershell -Command "Expand-Archive -Path '%WINTUN_ZIP%' -DestinationPath '%WINTUN_DIR%' -Force"
    copy /Y "%WINTUN_DIR%\wintun\bin\amd64\wintun.dll" "%WINTUN_DLL_DST%"
    if ERRORLEVEL 1 ( echo [FAIL] wintun extract && exit /b 1 )
    echo [build] wintun.dll ready at %WINTUN_DLL_DST%
) else (
    echo [build] wintun.dll already cached, skipping download.
)

echo [build] All pre-steps complete — tauri-cli will now package the MSI.
endlocal
