@echo off
setlocal EnableExtensions
chcp 65001 >nul
set "ACTION=android"
if /I "%~1"=="--offline" set "ACTION=offline-android"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0manage.ps1" -Action "%ACTION%"
set "EXIT_CODE=%ERRORLEVEL%"
if "%~1"=="" pause
exit /b %EXIT_CODE%
