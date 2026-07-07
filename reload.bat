@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul
set "PYTHONIOENCODING=utf-8"
set "ROOT=%~dp0"
set "ROOT=%ROOT:~0,-1%"
cd /d "%ROOT%" || (
    echo [ERROR] Cannot enter script directory: %ROOT%
    pause
    exit /b 1
)

if not exist "logs" mkdir "logs"

set "PYTHON_RUN="
if exist ".venv\Scripts\python.exe" call :try_python ".venv\Scripts\python.exe"
if not defined PYTHON_RUN (
    where py >nul 2>nul
    if not errorlevel 1 call :try_python "py -3"
)
if not defined PYTHON_RUN (
    where python >nul 2>nul
    if not errorlevel 1 call :try_python "python"
)
if not defined PYTHON_RUN (
    echo [ERROR] Python not found. Install Python or create .venv\Scripts\python.exe.
    pause
    exit /b 1
)

echo === [1/3] Generate config.json ===
set "NEXT_CONFIG=config.next.json"
set "CHECK_CONFIG=%NEXT_CONFIG%"
del "%NEXT_CONFIG%" >nul 2>nul
%PYTHON_RUN% build_singbox.py --template template.json --output "%NEXT_CONFIG%" --fetch-proxy http://127.0.0.1:7890 --discard-info-nodes

if errorlevel 1 (
    echo.
    echo [WARN] Config generation failed. Falling back to existing config.json.
    if not exist "config.json" (
        echo [ERROR] Existing config.json not found.
        pause
        exit /b 1
    )
    set "CHECK_CONFIG=config.json"
)

echo.
echo === [2/3] Check sing-box config ===
sing-box.exe check -c "%CHECK_CONFIG%"

if errorlevel 1 (
    echo.
    echo [ERROR] Config check failed. Restart skipped.
    pause
    exit /b 1
)

if /I not "%CHECK_CONFIG%"=="config.json" (
    if not exist "backups" mkdir "backups"
    if exist "config.json" (
        set "BACKUP_STAMP="
        for /f %%I in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd-HHmmss"') do set "BACKUP_STAMP=%%I"
        if not defined BACKUP_STAMP set "BACKUP_STAMP=unknown"
        set "BACKUP_CONFIG=backups\config.!BACKUP_STAMP!.json"
        copy /Y "config.json" "!BACKUP_CONFIG!" >nul
        if errorlevel 1 (
            echo.
            echo [ERROR] Failed to backup config.json. Restart skipped.
            pause
            exit /b 1
        )
        echo [INFO] Backup saved: !BACKUP_CONFIG!
    )
    copy /Y "%CHECK_CONFIG%" "config.json" >nul
    if errorlevel 1 (
        echo.
        echo [ERROR] Failed to replace config.json. Restart skipped.
        pause
        exit /b 1
    )
)

echo.
echo === [3/3] Restart sing-box service ===
set "RESTART_LOG=logs\reload-restart.log"
set "RESTART_FAILED="
singbox-service.exe restart > "%RESTART_LOG%" 2>&1
if errorlevel 1 set "RESTART_FAILED=1"
type "%RESTART_LOG%"
findstr /I /C:"FATAL" /C:"Unknown error" "%RESTART_LOG%" >nul 2>nul
if not errorlevel 1 set "RESTART_FAILED=1"

if defined RESTART_FAILED (
    echo.
    echo [WARN] Normal restart failed. Trying elevated restart.
    powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $exe=Join-Path (Get-Location) 'singbox-service.exe'; $p=Start-Process -FilePath $exe -ArgumentList 'restart' -WorkingDirectory (Get-Location) -Verb RunAs -Wait -PassThru; exit $p.ExitCode" >> "%RESTART_LOG%" 2>&1
    if errorlevel 1 (
        echo.
        echo [ERROR] sing-box service restart failed. Check %RESTART_LOG% and logs\singbox-service.*.log.
        pause
        exit /b 1
    )
)

echo.
echo [OK] Done. Dashboard: http://127.0.0.1:9090/ui/
pause
exit /b 0

:try_python
%~1 -c "import sys" >nul 2>nul
if not errorlevel 1 set "PYTHON_RUN=%~1"
exit /b 0
