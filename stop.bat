@echo off
REM ScanPay graceful stop (Windows)
setlocal enabledelayedexpansion
set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

if not exist ".run\scanpay.pid" (
    echo No PID file found. ScanPay may not be running.
    exit /b 0
)

for /f %%P in (.run\scanpay.pid) do (
    tasklist /FI "PID eq %%P" 2>nul | find "%%P" >nul
    if !errorlevel! equ 0 (
        echo Stopping ScanPay PID %%P
        taskkill /PID %%P /T
        del .run\scanpay.pid
        echo ScanPay stopped.
    ) else (
        echo PID %%P not alive. Removing stale PID file.
        del .run\scanpay.pid
    )
)