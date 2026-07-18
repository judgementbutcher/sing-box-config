@echo off
setlocal EnableExtensions
chcp 65001 >nul
set "ROOT=%~dp0.."
cd /d "%ROOT%" || exit /b 1

set "INTERACTIVE="
if "%~1"=="" set "INTERACTIVE=1"

if not exist "%ROOT%\subscriptions.yaml" (
    echo [ERROR] This checkout has not been initialized.
    echo Run setup.bat and paste your subscription URL first.
    if defined INTERACTIVE pause
    exit /b 1
)

if exist "%ROOT%\.venv\Scripts\python.exe" (
    "%ROOT%\.venv\Scripts\python.exe" "%ROOT%\generate_config.py" android %*
) else (
    py -3 "%ROOT%\generate_config.py" android %*
)
set "EXIT_CODE=%ERRORLEVEL%"

if defined INTERACTIVE pause
exit /b %EXIT_CODE%
