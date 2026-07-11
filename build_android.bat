@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0" || exit /b 1

set "INTERACTIVE="
if "%~1"=="" set "INTERACTIVE=1"

if not exist "%~dp0subscriptions.yaml" (
    echo [ERROR] This checkout has not been initialized.
    echo Run setup.bat and paste your subscription URL first.
    if defined INTERACTIVE pause
    exit /b 1
)

if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" "%~dp0generate_config.py" android %*
) else (
    py -3 "%~dp0generate_config.py" android %*
)
set "EXIT_CODE=%ERRORLEVEL%"

if defined INTERACTIVE pause
exit /b %EXIT_CODE%
