@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0..\.." || exit /b 1

where powershell.exe >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Windows PowerShell was not found.
    pause
    exit /b 1
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0manage.ps1" %*
set "EXIT_CODE=%ERRORLEVEL%"
if not "%EXIT_CODE%"=="0" (
    echo.
    echo [ERROR] sing-box manager exited with code %EXIT_CODE%.
)
if "%~1"=="" pause
exit /b %EXIT_CODE%
