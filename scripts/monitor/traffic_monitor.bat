@echo off
setlocal EnableExtensions
chcp 65001 >nul
set "ROOT=%~dp0..\.."
cd /d "%ROOT%" || exit /b 1

set "PYTHON=%ROOT%\.venv\Scripts\python.exe"
if not exist "%PYTHON%" set "PYTHON=python"

if "%~1"=="" (
    powershell.exe -NoProfile -Command "try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 http://127.0.0.1:9091/api/status | Out-Null; exit 0 } catch { exit 1 }"
    if not errorlevel 1 (
        start "" "http://127.0.0.1:9091"
        exit /b 0
    )
    start "" "http://127.0.0.1:9091"
)
"%PYTHON%" "%ROOT%\scripts\monitor\traffic_monitor.py" %*
exit /b %ERRORLEVEL%
