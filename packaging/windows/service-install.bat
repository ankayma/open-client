@echo off
:: ankayma-service install — run as Administrator.
:: Called by the NSIS/WiX installer after placing ankayma-service.exe + wintun.dll.

setlocal
set SVC_NAME=AnkaymaHelper
set SVC_BIN="%ProgramFiles%\Ankayma\ankayma-service.exe"

:: Stop + delete any previous installation (idempotent).
sc query %SVC_NAME% >nul 2>&1 && (
    sc stop %SVC_NAME% >nul 2>&1
    sc delete %SVC_NAME% >nul 2>&1
)

:: Install and start.
%SVC_BIN% --install
if %errorlevel% neq 0 (
    echo ERROR: service install failed
    exit /b 1
)
sc start %SVC_NAME%
if %errorlevel% neq 0 (
    echo ERROR: service start failed
    exit /b 1
)
echo Ankayma Helper Service installed and started.
endlocal
