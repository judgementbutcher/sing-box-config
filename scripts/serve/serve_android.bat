@echo off
setlocal EnableExtensions
chcp 65001 >nul
set "ROOT=%~dp0..\.."
cd /d "%ROOT%" || exit /b 1

set "INTERACTIVE="
if "%~1"=="" set "INTERACTIVE=1"

if not exist "%ROOT%\dist\android\config.json" (
    echo [ERROR] dist\android\config.json not found.
    echo Generate the Android config first: scripts\manage\build_android.bat
    if defined INTERACTIVE pause
    exit /b 1
)

if exist "%ROOT%\.venv\Scripts\python.exe" (
    "%ROOT%\.venv\Scripts\python.exe" "%ROOT%\scripts\serve\serve_config.py" %*
) else (
    py -3 "%ROOT%\scripts\serve\serve_config.py" %*
)
set "EXIT_CODE=%ERRORLEVEL%"

if defined INTERACTIVE pause
exit /b %EXIT_CODE%
