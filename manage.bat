@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0" || exit /b 1

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0manage.ps1"
exit /b %ERRORLEVEL%
