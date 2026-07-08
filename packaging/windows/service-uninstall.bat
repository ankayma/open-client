@echo off
:: ankayma-service uninstall — run as Administrator.
:: Called by the NSIS/WiX installer uninstall path.

setlocal
set SVC_NAME=AnkaymaHelper
set SVC_BIN="%ProgramFiles%\Ankayma\ankayma-service.exe"

sc query %SVC_NAME% >nul 2>&1 && (
    sc stop %SVC_NAME% >nul 2>&1
    %SVC_BIN% --uninstall
    if %errorlevel% neq 0 (
        echo WARN: --uninstall returned error, forcing sc delete
        sc delete %SVC_NAME% >nul 2>&1
    )
)
echo Ankayma Helper Service removed.
endlocal
