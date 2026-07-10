@echo off
setlocal EnableExtensions DisableDelayedExpansion
chcp 65001 >nul
cd /d "%~dp0" || exit /b 1

rem Daily entry point: no menu, deployment, or profile selection.
rem Double-click builds both configurations.  Optional: desktop / android / all.
set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=all"
if /I "%TARGET%"=="quick" set "TARGET=desktop"

if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" "%~dp0generate_config.py" %TARGET% %2 %3 %4 %5 %6 %7 %8 %9
) else (
    py -3 "%~dp0generate_config.py" %TARGET% %2 %3 %4 %5 %6 %7 %8 %9
)
set "EXIT_CODE=%ERRORLEVEL%"

if "%~1"=="" pause
exit /b %EXIT_CODE%
