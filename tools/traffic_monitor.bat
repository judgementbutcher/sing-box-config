@echo off
setlocal EnableExtensions
chcp 65001 >nul
set "ROOT=%~dp0.."
cd /d "%ROOT%" || exit /b 1

set "PYTHON=%ROOT%\.venv\Scripts\python.exe"
if not exist "%PYTHON%" set "PYTHON=python"
start "" "http://127.0.0.1:9091"
"%PYTHON%" "%ROOT%\traffic_monitor.py"
exit /b %ERRORLEVEL%
