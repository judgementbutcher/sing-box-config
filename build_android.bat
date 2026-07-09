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

set "TEMPLATE=templates\mobile-android-sing-box-1.13.14.json"
set "FINAL_CONFIG=config.android.json"
set "NEXT_CONFIG=config.android.next.json"
set "REPORT=nodes-report.android.json"
set "CHECK_EXE=sing-box.exe"
set "CHECK_113=.downloads\sing-box-1.13.14-windows-amd64\sing-box-1.13.14-windows-amd64\sing-box.exe"

if exist "%CHECK_113%" set "CHECK_EXE=%CHECK_113%"

if not exist "%TEMPLATE%" (
    echo [ERROR] Android template not found: %TEMPLATE%
    pause
    exit /b 1
)

echo === [1/3] Generate Android config ===
del "%NEXT_CONFIG%" >nul 2>nul
%PYTHON_RUN% build_singbox.py --template "%TEMPLATE%" --output "%NEXT_CONFIG%" --report "%REPORT%" --fetch-proxy http://127.0.0.1:7890 --keep-info-nodes

if errorlevel 1 (
    echo.
    echo [ERROR] Android config generation failed. Existing %FINAL_CONFIG% was not changed.
    pause
    exit /b 1
)

echo.
echo === [2/3] Check with sing-box core ===
if exist "%CHECK_EXE%" (
    "%CHECK_EXE%" check -c "%NEXT_CONFIG%"
    if errorlevel 1 (
        echo.
        echo [ERROR] Config check failed. Existing %FINAL_CONFIG% was not changed.
        pause
        exit /b 1
    )
) else (
    echo [WARN] sing-box.exe not found. Skipping local check.
)

echo.
echo === [3/3] Publish Android config ===
if not exist "backups" mkdir "backups"
if exist "%FINAL_CONFIG%" (
    set "BACKUP_STAMP="
    for /f %%I in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd-HHmmss"') do set "BACKUP_STAMP=%%I"
    if not defined BACKUP_STAMP set "BACKUP_STAMP=unknown"
    set "BACKUP_CONFIG=backups\config.android.!BACKUP_STAMP!.json"
    copy /Y "%FINAL_CONFIG%" "!BACKUP_CONFIG!" >nul
    if errorlevel 1 (
        echo.
        echo [ERROR] Failed to backup %FINAL_CONFIG%. Publish skipped.
        pause
        exit /b 1
    )
    echo [INFO] Backup saved: !BACKUP_CONFIG!
)

copy /Y "%NEXT_CONFIG%" "%FINAL_CONFIG%" >nul
if errorlevel 1 (
    echo.
    echo [ERROR] Failed to replace %FINAL_CONFIG%.
    pause
    exit /b 1
)

echo.
echo [OK] Android config ready: %FINAL_CONFIG%
echo Import %FINAL_CONFIG% into sing-box for Android.
pause
exit /b 0

:try_python
%~1 -c "import sys" >nul 2>nul
if not errorlevel 1 set "PYTHON_RUN=%~1"
exit /b 0
