@echo off
REM ScanPay local startup (Windows)
setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

if "%SCANPAY_PORT%"=="" set SCANPAY_PORT=8484
if "%SCANPAY_PAYMENT_MODE%"=="" set SCANPAY_PAYMENT_MODE=disabled

if not exist ".run" mkdir .run
if not exist "logs" mkdir logs

if exist ".run\scanpay.pid" (
    for /f %%P in (.run\scanpay.pid) do (
        tasklist /FI "PID eq %%P" 2>nul | find "%%P" >nul
        if !errorlevel! equ 0 (
            echo ScanPay already running PID %%P on port %SCANPAY_PORT%
            exit /b 0
        )
    )
    echo Stale PID file found. Removing.
    del .run\scanpay.pid
)

echo Starting ScanPay on port %SCANPAY_PORT% payment_mode=%SCANPAY_PAYMENT_MODE%

start /b python -m uvicorn main:app --host 0.0.0.0 --port %SCANPAY_PORT% >> logs\scanpay.log 2>&1

REM Wait for the process to get a PID
timeout /t 2 /nobreak >nul

REM Get the PID of the most recent python process running uvicorn
for /f "tokens=2" %%P in ('tasklist /FI "IMAGENAME eq python.exe" /FO CSV /NH ^| findstr uvicorn') do (
    echo %%P> .run\scanpay.pid
    goto :healthwait
)

:healthwait
echo Waiting for health check...
for /L %%i in (1,1,15) do (
    curl -sf http://127.0.0.1:%SCANPAY_PORT%/api/v1/health >nul 2>&1
    if !errorlevel! equ 0 (
        echo ScanPay is healthy on port %SCANPAY_PORT%
        exit /b 0
    )
    timeout /t 1 /nobreak >nul
)
echo ERROR: ScanPay did not become healthy within 15 seconds.
exit /b 1