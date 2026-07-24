@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0" || exit /b 1

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0manage.ps1"
set "EXIT_CODE=%ERRORLEVEL%"
if not "%EXIT_CODE%"=="0" (
    echo.
    echo [ERROR] sing-box manager exited with code %EXIT_CODE%.
    pause
)
exit /b %EXIT_CODE%
