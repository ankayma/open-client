@echo off
:: build-ankayma-windows.bat — one-shot local build of the Ankayma Windows GUI
:: installer (NSIS). Produces target\release\bundle\nsis\Ankayma_<ver>_x64-setup.exe.
::
:: Prerequisites on PATH:
::   - Rust (x86_64-pc-windows-msvc) + the MSVC C++ build tools (link.exe)
::   - Node.js / npm
::   - Tauri CLI  (npm i -g @tauri-apps/cli@^2)  or  cargo install tauri-cli
:: WebView2 runtime ships with Windows 11 / modern Edge.
::
:: The agent daemon is bundled as a Tauri sidecar (externalBin) and needs
:: wintun.dll beside it at runtime; this script downloads the Microsoft-signed
:: DLL from wintun.net (not vendored — see .gitignore). [T:part-d-infrastructure]
setlocal ENABLEEXTENSIONS
set "SCRIPT_DIR=%~dp0"
:: packaging\windows\ -> repo root (two levels up), resolved from this script's path.
:: Separate lines: %CD% expands at parse time, so reading it on the same line as
:: pushd would capture the OLD directory (classic batch gotcha).
pushd "%SCRIPT_DIR%..\.."
set "ROOT=%CD%"
popd

echo [1/4] frontend (SvelteKit static)...
cd /d "%ROOT%\frontend\app-gui" || exit /b 1
:: Install deps only on a fresh checkout; skip the registry round-trip otherwise.
if not exist "node_modules" ( call npm ci --no-fund --no-audit || exit /b 1 )
call npm run build || exit /b 1

echo [2/4] agent daemon (release, msvc)...
cd /d "%ROOT%" || exit /b 1
cargo build --release --bin agent || exit /b 1
:: Tauri resolves the sidecar by target triple; give it the expected name.
copy /Y "%ROOT%\target\release\agent.exe" "%ROOT%\target\release\agent-x86_64-pc-windows-msvc.exe" >nul || exit /b 1

echo [3/4] wintun.dll (Microsoft-signed, from wintun.net)...
set "WINTUN=%ROOT%\gui\src-tauri\wintun.dll"
if not exist "%WINTUN%" (
  powershell -NoProfile -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile \"$env:TEMP\wintun.zip\"; Expand-Archive \"$env:TEMP\wintun.zip\" \"$env:TEMP\wintun\" -Force; Copy-Item \"$env:TEMP\wintun\wintun\bin\amd64\wintun.dll\" \"%WINTUN%\" -Force" || exit /b 1
)

echo [4/4] Tauri NSIS bundle...
cd /d "%ROOT%\gui" || exit /b 1
tauri build --config "%ROOT%\gui\src-tauri\tauri.windows.conf.json" || exit /b 1

echo.
echo [done] installer: %ROOT%\target\release\bundle\nsis\
endlocal
