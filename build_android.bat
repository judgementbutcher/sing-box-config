@echo off
setlocal EnableExtensions
cd /d "%~dp0" || exit /b 1

call "%~dp0reload.bat" android %*
exit /b %ERRORLEVEL%
