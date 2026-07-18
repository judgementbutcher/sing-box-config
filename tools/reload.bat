@echo off
setlocal EnableExtensions
chcp 65001 >nul
set "ROOT=%~dp0.."
cd /d "%ROOT%" || exit /b 1

set "INTERACTIVE="
if "%~1"=="" set "INTERACTIVE=1"
if /I "%~1"=="--help" goto :help
if /I "%~1"=="-h" goto :help
if not exist "%ROOT%\subscriptions.yaml" (
    echo [ERROR] This checkout has not been initialized.
    echo Run setup.bat and paste your subscription URL first.
    goto :fail
)

echo === [1/2] Generate desktop config ===
if exist "%ROOT%\.venv\Scripts\python.exe" (
    "%ROOT%\.venv\Scripts\python.exe" "%ROOT%\generate_config.py" desktop %*
) else (
    py -3 "%ROOT%\generate_config.py" desktop %*
)
if errorlevel 1 (
    echo.
    echo [ERROR] Desktop config generation failed. Service restart skipped.
    goto :fail
)

echo.
echo === [2/2] Restart sing-box service ===
if not exist "%ROOT%\runtime\logs" mkdir "%ROOT%\runtime\logs"
set "RESTART_LOG=%ROOT%\runtime\logs\reload-restart.log"
set "RESTART_FAILED="
"%ROOT%\singbox-service.exe" restart > "%RESTART_LOG%" 2>&1
if errorlevel 1 set "RESTART_FAILED=1"
type "%RESTART_LOG%"
findstr /I /C:"FATAL" /C:"Unknown error" "%RESTART_LOG%" >nul 2>nul
if not errorlevel 1 set "RESTART_FAILED=1"

if defined RESTART_FAILED (
    echo.
    echo [WARN] Normal restart failed. Requesting administrator privileges.
    powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $exe=Join-Path (Get-Location) 'singbox-service.exe'; $process=Start-Process -FilePath $exe -ArgumentList 'restart' -WorkingDirectory (Get-Location) -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $process.ExitCode"
    if errorlevel 1 (
        echo.
        echo [ERROR] sing-box service restart failed. See %RESTART_LOG%.
        goto :fail
    )
)

echo.
echo [OK] Desktop config generated and sing-box service restarted.
if defined INTERACTIVE pause
exit /b 0

:fail
if defined INTERACTIVE pause
exit /b 1

:help
if exist "%ROOT%\.venv\Scripts\python.exe" (
    "%ROOT%\.venv\Scripts\python.exe" "%ROOT%\generate_config.py" desktop %*
) else (
    py -3 "%ROOT%\generate_config.py" desktop %*
)
exit /b %ERRORLEVEL%
