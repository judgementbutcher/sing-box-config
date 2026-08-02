[CmdletBinding()]
param(
    [ValidateSet("menu", "reload", "offline-reload", "desktop", "android", "offline-android", "publish", "offline-publish", "stop-publish", "all", "check", "status")]
    [string]$Action = "menu"
)

# 交互式 sing-box 管理菜单。用自然语言选项管理配置生成与 Windows 服务。
# 双击 manage.bat 即可运行；细分批处理通过 -Action 复用这里的操作。

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$ProjectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
Set-Location -LiteralPath $ProjectRoot
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch {}

$ServiceName = "sing-box"
$ServiceExe = Join-Path $ProjectRoot "runtime\services\singbox-service.exe"
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$Generator = Join-Path $ProjectRoot "scripts\config\generate_config.py"
$LogDirectory = Join-Path $ProjectRoot "runtime\logs"
$DashboardUrl = "http://127.0.0.1:9090/ui/"
$TrafficDashboardUrl = "http://127.0.0.1:9091"
$TrafficMonitor = Join-Path $ProjectRoot "scripts\monitor\traffic_monitor.py"
$TrafficServiceName = "sing-box-traffic"
$TrafficServiceExe = Join-Path $ProjectRoot "runtime\services\singbox-traffic-service.exe"
$ProxyEndpoint = "127.0.0.1:7890"
$AndroidPublisherPort = 8888
$AndroidPublisherDirectory = Join-Path $ProjectRoot "runtime\publish"
$AndroidPublisherReadyFile = Join-Path $AndroidPublisherDirectory "android-publisher.url"
$AndroidPublisherPidFile = Join-Path $AndroidPublisherDirectory "android-publisher.pid"
$AndroidPublisherScript = Join-Path $ProjectRoot "scripts\serve\serve_config.py"

function Get-PythonCommand {
    if (Test-Path -LiteralPath $VenvPython) {
        return @($VenvPython)
    }
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) {
        return @($launcher.Source, "-3")
    }
    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($python) {
        return @($python.Source)
    }
    throw "找不到 Python。请先运行 scripts\bootstrap\setup.bat 初始化环境。"
}

function Test-Initialized {
    return Test-Path -LiteralPath (Join-Path $ProjectRoot "config\local\subscriptions.yaml")
}

function Get-ServiceStateText {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        return "未安装"
    }
    switch ($service.Status) {
        "Running" { return "运行中" }
        "Stopped" { return "已停止" }
        default   { return [string]$service.Status }
    }
}

function Invoke-Generator {
    param(
        [string]$Target,
        [switch]$Offline,
        [string]$OutputDirectory
    )

    if (-not (Test-Initialized)) {
        Write-Host "[错误] 尚未初始化。请先运行 scripts\bootstrap\setup.bat 并粘贴订阅链接。" -ForegroundColor Red
        return $false
    }
    # Force an array here: PowerShell unwraps a single returned string, and
    # indexing that scalar would execute only the first character of the path.
    $python = @(Get-PythonCommand)
    $arguments = @($Generator, $Target)
    if ($Offline) {
        $arguments += "--offline"
    }
    if ($OutputDirectory) {
        $arguments += @("--output-dir", $OutputDirectory)
    }
    $executable = $python[0]
    $prefix = @($python | Select-Object -Skip 1)
    & $executable @prefix @arguments | Out-Host
    $generatorExitCode = $LASTEXITCODE
    if ($generatorExitCode -ne 0) {
        Write-Host "[错误] 配置生成失败 (退出码 $generatorExitCode)。" -ForegroundColor Red
        return $false
    }
    Write-Host "[完成] 配置已生成。" -ForegroundColor Green
    return $true
}

function Invoke-ServiceAction {
    param(
        [ValidateSet("install", "uninstall", "start", "stop", "restart")]
        [string]$Action
    )

    if (-not (Test-Path -LiteralPath $ServiceExe)) {
        Write-Host "[错误] 找不到 runtime\services\singbox-service.exe。请先运行 scripts\bootstrap\setup.bat。" -ForegroundColor Red
        return $false
    }
    if ($Action -ne "install") {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $service) {
            Write-Host "[错误] 服务尚未安装。请先运行 scripts\bootstrap\setup.bat 安装服务。" -ForegroundColor Red
            return $false
        }
    }
    # 操作 Windows 服务需要管理员权限，请求提权后隐藏窗口执行。
    Write-Host "正在请求管理员权限执行：$Action ..." -ForegroundColor Yellow
    try {
        $process = Start-Process -FilePath $ServiceExe -ArgumentList $Action `
            -WorkingDirectory $ProjectRoot -Verb RunAs -WindowStyle Hidden -Wait -PassThru
    } catch {
        Write-Host "[错误] 提权被拒绝或失败：$($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
    if ($process.ExitCode -ne 0) {
        Write-Host "[错误] 服务操作 '$Action' 失败 (退出码 $($process.ExitCode))。查看 $LogDirectory。" -ForegroundColor Red
        return $false
    }
    Write-Host "[完成] 服务操作 '$Action' 成功。当前状态：$(Get-ServiceStateText)" -ForegroundColor Green
    return $true
}

function Sync-ServiceDefinition {
    # manage 的 reload 不会重装服务；若 config\services 里的 XML 更新过（例如核心
    # 版本升级）而 runtime\services 副本没同步，重启后服务仍然跑旧核心。
    $sourceXml = Join-Path $ProjectRoot "config\services\singbox-service.xml"
    $runtimeXml = Join-Path $ProjectRoot "runtime\services\singbox-service.xml"
    if (-not (Test-Path -LiteralPath $sourceXml)) {
        return
    }
    if ((Test-Path -LiteralPath $runtimeXml) -and
        (Get-FileHash -LiteralPath $sourceXml).Hash -eq (Get-FileHash -LiteralPath $runtimeXml).Hash) {
        return
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $runtimeXml) -Force | Out-Null
    Copy-Item -LiteralPath $sourceXml -Destination $runtimeXml -Force
    Write-Host "[同步] 服务定义已更新：config\services\singbox-service.xml -> runtime\services\" -ForegroundColor Yellow
}

function Get-ServiceCoreExecutable {
    param([string]$DefinitionPath)

    # 用服务 XML 里声明的核心跑校验，保证「check 的核心」就是「服务将要跑的核心」。
    if (-not $DefinitionPath) {
        $DefinitionPath = Join-Path $ProjectRoot "runtime\services\singbox-service.xml"
    }
    if (Test-Path -LiteralPath $DefinitionPath) {
        $match = [regex]::Match((Get-Content -LiteralPath $DefinitionPath -Raw), 'cores\\([^\\]+)\\sing-box\.exe')
        if ($match.Success) {
            $exe = Join-Path $ProjectRoot ("runtime\cores\{0}\sing-box.exe" -f $match.Groups[1].Value)
            if (Test-Path -LiteralPath $exe) {
                return $exe
            }
            # XML 已明确指定核心时不猜测其他版本，否则可能用 A 版本校验、
            # 重启后却让服务尝试运行缺失的 B 版本。
            return $null
        }
    }
    $latest = Get-ChildItem -LiteralPath (Join-Path $ProjectRoot "runtime\cores") -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($latest) {
        $exe = Join-Path $latest.FullName "sing-box.exe"
        if (Test-Path -LiteralPath $exe) {
            return $exe
        }
    }
    return $null
}

function Test-DesktopConfig {
    param(
        [string]$ConfigPath = (Join-Path $ProjectRoot "dist\desktop\config.json"),
        [string]$CoreExecutable
    )

    $configPath = $ConfigPath
    if (-not (Test-Path -LiteralPath $configPath)) {
        Write-Host "[错误] 找不到桌面配置：$configPath" -ForegroundColor Red
        return $false
    }
    $coreExe = $CoreExecutable
    if (-not $coreExe) {
        $coreExe = Get-ServiceCoreExecutable
    }
    if (-not $coreExe) {
        Write-Host "[错误] 服务定义引用的 sing-box 核心不存在；拒绝跳过校验。" -ForegroundColor Red
        return $false
    }
    & $coreExe check -c $configPath 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[错误] sing-box check 未通过，已中止重启，当前服务保持原配置运行。" -ForegroundColor Red
        return $false
    }
    Write-Host "[校验] sing-box check 通过（$([IO.Path]::GetFileName([IO.Path]::GetDirectoryName($coreExe)))）。" -ForegroundColor Green
    return $true
}

function Test-AndroidConfig {
    param([string]$ConfigPath = (Join-Path $ProjectRoot "dist\android\config.json"))

    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        Write-Host "[错误] 找不到安卓配置：$ConfigPath" -ForegroundColor Red
        return $false
    }
    $coreExe = Get-ServiceCoreExecutable
    if (-not $coreExe) {
        Write-Host "[错误] 找不到与当前配置版本匹配的 sing-box 核心，无法校验安卓配置。" -ForegroundColor Red
        return $false
    }
    & $coreExe check -c $ConfigPath 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[错误] 安卓配置未通过 sing-box check，旧配置保持不变。" -ForegroundColor Red
        return $false
    }
    Write-Host "[校验] 安卓配置通过 sing-box check。" -ForegroundColor Green
    return $true
}

function Invoke-BuildAndroid {
    param([switch]$Offline)

    $stagingRoot = Join-Path $ProjectRoot "runtime\staging"
    $stagingDirectory = Join-Path $stagingRoot ("android-build-{0}" -f [Guid]::NewGuid().ToString("N"))
    $stagedConfig = Join-Path $stagingDirectory "android\config.json"
    $liveConfig = Join-Path $ProjectRoot "dist\android\config.json"
    $previousConfig = Join-Path $stagingDirectory "previous-config.json"

    New-Item -ItemType Directory -Path $stagingDirectory -Force | Out-Null
    try {
        if (-not (Invoke-Generator -Target "android" -Offline:$Offline -OutputDirectory $stagingDirectory)) {
            return $false
        }
        if (-not (Test-AndroidConfig -ConfigPath $stagedConfig)) {
            return $false
        }

        New-Item -ItemType Directory -Path (Split-Path -Parent $liveConfig) -Force | Out-Null
        if (Test-Path -LiteralPath $liveConfig) {
            [IO.File]::Replace($stagedConfig, $liveConfig, $previousConfig, $true)
        } else {
            Move-Item -LiteralPath $stagedConfig -Destination $liveConfig
        }
        Write-Host "[完成] 安卓配置已校验并发布：$liveConfig" -ForegroundColor Green
        return $true
    } finally {
        if (Test-Path -LiteralPath $stagingDirectory) {
            Remove-Item -LiteralPath $stagingDirectory -Recurse -Force
        }
        if ((Test-Path -LiteralPath $stagingRoot) -and -not (Get-ChildItem -LiteralPath $stagingRoot -Force)) {
            Remove-Item -LiteralPath $stagingRoot -Force
        }
    }
}

function Test-ServiceHealthy {
    param([int]$TimeoutSeconds = 10)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            try {
                Invoke-WebRequest -Uri "http://127.0.0.1:9090/version" -UseBasicParsing -TimeoutSec 1 | Out-Null
                return $true
            } catch {
                # 服务已启动但控制接口还在初始化，继续等待。
            }
        }
        Start-Sleep -Milliseconds 300
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Invoke-ReloadDesktop {
    param([switch]$Offline)

    $stagingRoot = Join-Path $ProjectRoot "runtime\staging"
    $stagingDirectory = Join-Path $stagingRoot ("desktop-reload-{0}" -f [Guid]::NewGuid().ToString("N"))
    $stagedConfig = Join-Path $stagingDirectory "desktop\config.json"
    $liveConfig = Join-Path $ProjectRoot "dist\desktop\config.json"
    $previousConfig = Join-Path $stagingDirectory "previous-config.json"
    $sourceXml = Join-Path $ProjectRoot "config\services\singbox-service.xml"
    $runtimeXml = Join-Path $ProjectRoot "runtime\services\singbox-service.xml"
    $previousXml = Join-Path $stagingDirectory "previous-service.xml"
    $hadLiveConfig = Test-Path -LiteralPath $liveConfig
    $hadRuntimeXml = Test-Path -LiteralPath $runtimeXml
    $published = $false
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    New-Item -ItemType Directory -Path $stagingDirectory -Force | Out-Null
    try {
        Write-Host "=== [1/4] 临时生成桌面配置 ===" -ForegroundColor Cyan
        if (-not (Invoke-Generator -Target "desktop" -Offline:$Offline -OutputDirectory $stagingDirectory)) {
            Write-Host "服务重启已跳过，正式配置未改动。" -ForegroundColor Yellow
            return $false
        }

        Write-Host ""
        Write-Host "=== [2/4] 使用目标核心校验临时配置 ===" -ForegroundColor Cyan
        $coreExe = Get-ServiceCoreExecutable -DefinitionPath $sourceXml
        if (-not $coreExe) {
            Write-Host "[错误] config\services\singbox-service.xml 引用的核心不存在。" -ForegroundColor Red
            return $false
        }
        if (-not (Test-DesktopConfig -ConfigPath $stagedConfig -CoreExecutable $coreExe)) {
            Write-Host "正式配置未改动。" -ForegroundColor Yellow
            return $false
        }

        Write-Host ""
        Write-Host "=== [3/4] 原子发布配置并同步服务定义 ===" -ForegroundColor Cyan
        New-Item -ItemType Directory -Path (Split-Path -Parent $liveConfig) -Force | Out-Null
        if ($hadLiveConfig) {
            [IO.File]::Replace($stagedConfig, $liveConfig, $previousConfig, $true)
        } else {
            Move-Item -LiteralPath $stagedConfig -Destination $liveConfig
        }
        $published = $true
        if ($hadRuntimeXml) {
            Copy-Item -LiteralPath $runtimeXml -Destination $previousXml -Force
        }
        Sync-ServiceDefinition

        if (-not $service) {
            Write-Host "[提示] 配置已校验并发布；服务尚未安装。运行 scripts\bootstrap\setup.bat 可安装服务。" -ForegroundColor Yellow
            return $true
        }

        Write-Host ""
        Write-Host "=== [4/4] 重启并确认 sing-box 健康 ===" -ForegroundColor Cyan
        if ((Invoke-ServiceAction -Action "restart") -and (Test-ServiceHealthy)) {
            Write-Host "[完成] 新配置已生效，控制接口健康。" -ForegroundColor Green
            return $true
        }
        throw "服务未能在重启后通过健康检查"
    } catch {
        $failure = $_.Exception.Message
        Write-Host "[错误] 刷新失败：$failure" -ForegroundColor Red
        if ($published) {
            Write-Host "正在回滚上一份配置和服务定义..." -ForegroundColor Yellow
            if ($hadLiveConfig -and (Test-Path -LiteralPath $previousConfig)) {
                Move-Item -LiteralPath $previousConfig -Destination $liveConfig -Force
            } elseif (-not $hadLiveConfig -and (Test-Path -LiteralPath $liveConfig)) {
                Remove-Item -LiteralPath $liveConfig -Force
            }
            if ($hadRuntimeXml -and (Test-Path -LiteralPath $previousXml)) {
                Copy-Item -LiteralPath $previousXml -Destination $runtimeXml -Force
            } elseif (-not $hadRuntimeXml -and (Test-Path -LiteralPath $runtimeXml)) {
                Remove-Item -LiteralPath $runtimeXml -Force
            }
            if ($service) {
                if ((Invoke-ServiceAction -Action "restart") -and (Test-ServiceHealthy)) {
                    Write-Host "[回滚] 旧配置已恢复，服务健康。" -ForegroundColor Green
                } else {
                    Write-Host "[严重] 旧配置已恢复，但服务未通过健康检查；请查看 runtime\logs。" -ForegroundColor Red
                }
            }
        }
        return $false
    } finally {
        if (Test-Path -LiteralPath $stagingDirectory) {
            Remove-Item -LiteralPath $stagingDirectory -Recurse -Force
        }
        if ((Test-Path -LiteralPath $stagingRoot) -and -not (Get-ChildItem -LiteralPath $stagingRoot -Force)) {
            Remove-Item -LiteralPath $stagingRoot -Force
        }
    }
}

function Get-AndroidPublisherUrl {
    $candidates = @()
    if (Test-Path -LiteralPath $AndroidPublisherReadyFile) {
        try {
            $readyUrl = (Get-Content -LiteralPath $AndroidPublisherReadyFile -Raw).Trim()
            if ($readyUrl) { $candidates += $readyUrl }
        } catch {}
    }
    # A prior manager may have been interrupted before it wrote the ready file.
    # Probe the fixed loopback endpoint so the existing publisher can still be
    # reused instead of failing on an occupied port.
    $candidates += "http://127.0.0.1:$AndroidPublisherPort/android/config.json"

    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        try {
            $response = Invoke-WebRequest -Uri $candidate -Method Head -UseBasicParsing -TimeoutSec 1
            if ($response.Headers["X-Sing-Box-Config-Publisher"] -ne "1") { continue }
            $reportedUrl = [string]$response.Headers["X-Sing-Box-Config-Url"]
            if ($reportedUrl) {
                New-Item -ItemType Directory -Path $AndroidPublisherDirectory -Force | Out-Null
                [IO.File]::WriteAllText($AndroidPublisherReadyFile, $reportedUrl.Trim() + [Environment]::NewLine)
                $reportedPid = [string]$response.Headers["X-Sing-Box-Config-Pid"]
                if ($reportedPid -match "^\d+$") {
                    [IO.File]::WriteAllText($AndroidPublisherPidFile, $reportedPid + [Environment]::NewLine)
                }
                return $reportedUrl.Trim()
            }
            return $candidate
        } catch {}
    }

    Remove-Item -LiteralPath $AndroidPublisherReadyFile -Force -ErrorAction SilentlyContinue
    return $null
}

function Stop-AndroidPublisher {
    # Refresh the PID from the listener itself.  Virtual-environment Python
    # launchers can have a different PID from the long-running interpreter.
    [void](Get-AndroidPublisherUrl)
    $stopped = $false
    if (Test-Path -LiteralPath $AndroidPublisherPidFile) {
        try {
            $processId = [int](Get-Content -LiteralPath $AndroidPublisherPidFile -Raw).Trim()
            $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
            if ($process) {
                Stop-Process -Id $processId -Force -ErrorAction Stop
                $stopped = $true
            }
        } catch {
            Write-Host "[提示] 发布器进程已退出或无法停止：$($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    Remove-Item -LiteralPath $AndroidPublisherReadyFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $AndroidPublisherPidFile -Force -ErrorAction SilentlyContinue
    if ($stopped) {
        Write-Host "[完成] 安卓局域网发布已停止。" -ForegroundColor Green
    } else {
        Write-Host "[提示] 没有由当前管理脚本启动的安卓发布器。" -ForegroundColor Yellow
    }
    return $true
}

function Invoke-PublishAndroid {
    param([switch]$Offline)

    Write-Host "=== [1/2] 生成安卓配置 ===" -ForegroundColor Cyan
    if (-not (Invoke-BuildAndroid -Offline:$Offline)) {
        Write-Host "局域网发布已跳过。" -ForegroundColor Yellow
        return $false
    }
    Write-Host ""
    Write-Host "=== [2/2] 局域网发布（手机 SFA 远程订阅） ===" -ForegroundColor Cyan
    if (-not (Test-Path -LiteralPath $AndroidPublisherScript)) {
        Write-Host "[错误] 找不到 scripts\serve\serve_config.py。" -ForegroundColor Red
        return $false
    }
    $publisherUrl = Get-AndroidPublisherUrl
    if ($publisherUrl) {
        Write-Host "[复用] 局域网发布器已在运行，本次生成的配置已可供手机更新。" -ForegroundColor Green
    } else {
        New-Item -ItemType Directory -Path $AndroidPublisherDirectory -Force | Out-Null
        Remove-Item -LiteralPath $AndroidPublisherReadyFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $AndroidPublisherPidFile -Force -ErrorAction SilentlyContinue
        $python = @(Get-PythonCommand)
        $executable = $python[0]
        $arguments = @($python | Select-Object -Skip 1) + @(
            "-X", "utf8",
            "-u",
            "`"$AndroidPublisherScript`"",
            "--port", "$AndroidPublisherPort",
            "--ready-file", "`"$AndroidPublisherReadyFile`"",
            "--pid-file", "`"$AndroidPublisherPidFile`""
        )
        $stdoutLog = Join-Path $LogDirectory "android-publisher.out.log"
        $stderrLog = Join-Path $LogDirectory "android-publisher.err.log"
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
        try {
            $process = Start-Process -FilePath $executable -ArgumentList $arguments -WorkingDirectory $ProjectRoot `
                -WindowStyle Hidden -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru
        } catch {
            Write-Host "[错误] 无法启动局域网发布器：$($_.Exception.Message)" -ForegroundColor Red
            return $false
        }

        $deadline = (Get-Date).AddSeconds(15)
        do {
            Start-Sleep -Milliseconds 150
            $publisherUrl = Get-AndroidPublisherUrl
            if ($publisherUrl) { break }
            if ($process.HasExited) { break }
        } while ((Get-Date) -lt $deadline)
        if (-not $publisherUrl) {
            if (-not $process.HasExited) {
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            }
            Remove-Item -LiteralPath $AndroidPublisherReadyFile -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $AndroidPublisherPidFile -Force -ErrorAction SilentlyContinue
            Write-Host "[错误] 发布器未能监听固定端口 $AndroidPublisherPort。查看 $stderrLog；如端口被其他程序占用，请释放该端口后重试。" -ForegroundColor Red
            return $false
        }
        Write-Host "[完成] 已在后台启动局域网发布（固定端口 $AndroidPublisherPort）。" -ForegroundColor Green
    }
    Write-Host "安卓远程配置 URL：$publisherUrl" -ForegroundColor Cyan
    Write-Host "首次：手机 SFA 新建「远程」配置并粘贴该 URL；日后刷新只需在 SFA 点「更新」。" -ForegroundColor DarkGray
    Write-Host "停止发布：管理菜单选择 [x]，或执行 manage.ps1 -Action stop-publish。" -ForegroundColor DarkGray
    return $true
}

function Show-Log {
    if (-not (Test-Path -LiteralPath $LogDirectory)) {
        Write-Host "[提示] 还没有日志目录。服务运行后才会产生日志。" -ForegroundColor Yellow
        return
    }
    # sing-box 的结构化运行日志写到 stderr；stdout 通常是空文件。
    # 优先跟随当前核心日志，再退回到任意最近且非空的服务日志。
    $log = Get-ChildItem -LiteralPath $LogDirectory -Filter "singbox-service.err.log*" -File -ErrorAction SilentlyContinue |
        Where-Object Length -gt 0 |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $log) {
        $log = Get-ChildItem -LiteralPath $LogDirectory -Filter "*.log" -File -ErrorAction SilentlyContinue |
            Where-Object Length -gt 0 |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
    }
    if (-not $log) {
        Write-Host "[提示] 日志目录里还没有非空日志。" -ForegroundColor Yellow
        return
    }
    Write-Host "正在跟随日志：$($log.FullName)" -ForegroundColor Cyan
    Write-Host "按 Ctrl+C 停止跟随并返回菜单。" -ForegroundColor DarkGray
    Write-Host ""
    try {
        Get-Content -LiteralPath $log.FullName -Tail 40 -Wait
    } catch [System.Management.Automation.PipelineStoppedException] {
        # 用户按 Ctrl+C，正常返回菜单。
    } catch {
        Write-Host "[提示] 已停止跟随日志。" -ForegroundColor DarkGray
    }
}

function Show-Status {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    Write-Host "服务：$(Get-ServiceStateText)" -ForegroundColor Cyan

    $coreExe = Get-ServiceCoreExecutable
    if ($coreExe) {
        $versionLine = (& $coreExe version 2>$null | Select-Object -First 1)
        Write-Host "核心：$versionLine" -ForegroundColor Cyan
        Write-Host "路径：$coreExe" -ForegroundColor DarkGray
    } else {
        Write-Host "核心：服务定义引用的文件不存在" -ForegroundColor Red
    }

    $configValid = Test-DesktopConfig -CoreExecutable $coreExe
    if ($service -and $service.Status -eq "Running") {
        try {
            $api = Invoke-RestMethod -Uri "http://127.0.0.1:9090/proxies" -TimeoutSec 2
            foreach ($name in @("Available", "DNS-Out", "AI", "Emby")) {
                $property = $api.proxies.PSObject.Properties[$name]
                if ($property) {
                    Write-Host ("选择：{0} -> {1}" -f $name, $property.Value.now) -ForegroundColor DarkGray
                }
            }
            Write-Host "控制接口：健康" -ForegroundColor Green
        } catch {
            Write-Host "控制接口：不可用（http://127.0.0.1:9090）" -ForegroundColor Red
            return $false
        }
    }
    return $configValid
}

function Open-Dashboard {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service -or $service.Status -ne "Running") {
        Write-Host "[提示] 服务未运行，仪表板可能打不开。可先启动服务。" -ForegroundColor Yellow
    }
    Write-Host "正在打开仪表板：$DashboardUrl" -ForegroundColor Cyan
    Start-Process $DashboardUrl
}

function Test-TrafficDashboard {
    try {
        Invoke-WebRequest -Uri "$TrafficDashboardUrl/api/status" -UseBasicParsing -TimeoutSec 2 | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Open-TrafficDashboard {
    if (-not (Test-Path -LiteralPath $TrafficMonitor)) {
        Write-Host "[错误] 找不到 scripts\monitor\traffic_monitor.py。" -ForegroundColor Red
        return
    }
    if (-not (Test-TrafficDashboard)) {
        $trafficService = Get-Service -Name $TrafficServiceName -ErrorAction SilentlyContinue
        if ($trafficService) {
            if ($trafficService.Status -ne "Running") {
                Write-Host "正在请求管理员权限启动流量统计服务..." -ForegroundColor Yellow
                try {
                    $process = Start-Process -FilePath $TrafficServiceExe -ArgumentList "start" `
                        -WorkingDirectory $ProjectRoot -Verb RunAs -WindowStyle Hidden -Wait -PassThru
                    if ($process.ExitCode -ne 0) {
                        Write-Host "[错误] 流量统计服务启动失败。" -ForegroundColor Red
                        return
                    }
                } catch {
                    Write-Host "[错误] 提权被拒绝或失败：$($_.Exception.Message)" -ForegroundColor Red
                    return
                }
            }
        } else {
            $python = @(Get-PythonCommand)
            $executable = $python[0]
            $arguments = @($python | Select-Object -Skip 1) + @("`"$TrafficMonitor`"")
            Write-Host "流量统计服务尚未安装，正在以当前用户启动统计器..." -ForegroundColor Yellow
            Start-Process -FilePath $executable -ArgumentList $arguments -WorkingDirectory $ProjectRoot -WindowStyle Hidden
        }
        for ($attempt = 0; $attempt -lt 15; $attempt++) {
            Start-Sleep -Milliseconds 300
            if (Test-TrafficDashboard) { break }
        }
    }
    if (-not (Test-TrafficDashboard)) {
        Write-Host "[错误] 流量统计面板未能启动。请检查 runtime\logs。" -ForegroundColor Red
        return
    }
    Write-Host "正在打开流量去向面板：$TrafficDashboardUrl" -ForegroundColor Cyan
    Start-Process $TrafficDashboardUrl
}

function Show-Menu {
    Write-Host ""
    Write-Host "==================== sing-box 管理 ====================" -ForegroundColor White
    Write-Host ("  服务状态：{0}    代理：{1}    仪表板：{2}" -f (Get-ServiceStateText), $ProxyEndpoint, $DashboardUrl) -ForegroundColor DarkGray
    Write-Host "-------------------------------------------------------"
    Write-Host "  [1] 刷新桌面配置并重启服务（日常一键）"
    Write-Host "  [2] 仅生成桌面配置"
    Write-Host "  [3] 生成安卓配置"
    Write-Host "  [a] 安卓配置：生成并局域网发布（手机远程订阅一键更新）"
    Write-Host "  [4] 生成全部配置（桌面 + 安卓）"
    Write-Host "  [5] 离线刷新桌面配置（不联网，只用缓存）"
    Write-Host "  ---------------------------------------------------"
    Write-Host "  [6] 启动服务"
    Write-Host "  [7] 停止服务"
    Write-Host "  [8] 重启服务"
    Write-Host "  [9] 检查核心、配置、服务和当前分组选择"
    Write-Host "  ---------------------------------------------------"
    Write-Host "  [d] 打开实时连接仪表板"
    Write-Host "  [t] 打开流量去向统计（域名 / 应用 / 规则 / 出口）"
    Write-Host "  [l] 查看实时日志"
    Write-Host "  [x] 停止安卓局域网发布"
    Write-Host "  [q] 退出"
    Write-Host "======================================================="
}

if (-not (Test-Initialized)) {
    Write-Host "[警告] 尚未初始化：找不到 config\local\subscriptions.yaml。" -ForegroundColor Yellow
    Write-Host "生成类操作会失败，请先运行 scripts\bootstrap\setup.bat 粘贴订阅链接。" -ForegroundColor Yellow
}

if ($Action -ne "menu") {
    $succeeded = switch ($Action) {
        "reload" { Invoke-ReloadDesktop }
        "offline-reload" { Invoke-ReloadDesktop -Offline }
        "desktop" { Invoke-Generator -Target "desktop" }
        "android" { Invoke-BuildAndroid }
        "offline-android" { Invoke-BuildAndroid -Offline }
        "publish" { Invoke-PublishAndroid }
        "offline-publish" { Invoke-PublishAndroid -Offline }
        "stop-publish" { Stop-AndroidPublisher }
        "all" { Invoke-Generator -Target "all" }
        "check" { Test-DesktopConfig }
        "status" { Show-Status }
    }
    if ($succeeded -eq $false) { exit 1 }
    exit 0
}

while ($true) {
    Show-Menu
    $raw = Read-Host "请选择"
    if ($null -eq $raw) { break }  # 输入流结束（EOF），退出循环。
    $choice = $raw.Trim().ToLower()
    Write-Host ""
    try {
        switch ($choice) {
            "1" { [void](Invoke-ReloadDesktop) }
            "2" { [void](Invoke-Generator -Target "desktop") }
            "3" { [void](Invoke-BuildAndroid) }
            "a" { [void](Invoke-PublishAndroid) }
            "4" { [void](Invoke-Generator -Target "all") }
            "5" { [void](Invoke-ReloadDesktop -Offline) }
            "6" { [void](Invoke-ServiceAction -Action "start") }
            "7" { [void](Invoke-ServiceAction -Action "stop") }
            "8" { [void](Invoke-ServiceAction -Action "restart") }
            "9" { [void](Show-Status) }
            "d" { Open-Dashboard }
            "t" { Open-TrafficDashboard }
            "l" { Show-Log }
            "x" { [void](Stop-AndroidPublisher) }
            "q" { break }
            ""  { }
            default { Write-Host "无效选项：$choice" -ForegroundColor Yellow }
        }
    } catch {
        Write-Host "[错误] 操作失败：$($_.Exception.Message)" -ForegroundColor Red
    }
    if ($choice -eq "q") { break }
    Write-Host ""
    [void](Read-Host "按回车返回菜单")
}

Write-Host "已退出 sing-box 管理。" -ForegroundColor DarkGray
