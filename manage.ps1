[CmdletBinding()]
param()

# 交互式 sing-box 管理菜单。用自然语言选项管理配置生成与 Windows 服务。
# 双击 manage.bat 即可运行；也可直接 powershell -File manage.ps1。

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
Set-Location -LiteralPath $PSScriptRoot
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch {}

$ServiceName = "sing-box"
$ServiceExe = Join-Path $PSScriptRoot "singbox-service.exe"
$VenvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$Generator = Join-Path $PSScriptRoot "generate_config.py"
$LogDirectory = Join-Path $PSScriptRoot "runtime\logs"
$DashboardUrl = "http://127.0.0.1:9090"
$TrafficDashboardUrl = "http://127.0.0.1:9091"
$TrafficMonitor = Join-Path $PSScriptRoot "traffic_monitor.py"
$TrafficServiceName = "sing-box-traffic"
$TrafficServiceExe = Join-Path $PSScriptRoot "singbox-traffic-service.exe"
$ProxyEndpoint = "127.0.0.1:7890"

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
    throw "找不到 Python。请先运行 setup.bat 初始化环境。"
}

function Test-Initialized {
    return Test-Path -LiteralPath (Join-Path $PSScriptRoot "subscriptions.yaml")
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
    param([string]$Target, [switch]$Offline)

    if (-not (Test-Initialized)) {
        Write-Host "[错误] 尚未初始化。请先运行 setup.bat 并粘贴订阅链接。" -ForegroundColor Red
        return $false
    }
    $python = Get-PythonCommand
    $arguments = @($Generator, $Target)
    if ($Offline) {
        $arguments += "--offline"
    }
    $executable = $python[0]
    $prefix = @($python | Select-Object -Skip 1)
    & $executable @prefix @arguments
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[错误] 配置生成失败 (退出码 $LASTEXITCODE)。" -ForegroundColor Red
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
        Write-Host "[错误] 找不到 singbox-service.exe。请先运行 setup.bat。" -ForegroundColor Red
        return $false
    }
    if ($Action -ne "install") {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $service) {
            Write-Host "[错误] 服务尚未安装。请先运行 setup.bat 安装服务。" -ForegroundColor Red
            return $false
        }
    }
    # 操作 Windows 服务需要管理员权限，请求提权后隐藏窗口执行。
    Write-Host "正在请求管理员权限执行：$Action ..." -ForegroundColor Yellow
    try {
        $process = Start-Process -FilePath $ServiceExe -ArgumentList $Action `
            -WorkingDirectory $PSScriptRoot -Verb RunAs -WindowStyle Hidden -Wait -PassThru
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

function Invoke-ReloadDesktop {
    param([switch]$Offline)

    Write-Host "=== [1/2] 生成桌面配置 ===" -ForegroundColor Cyan
    if (-not (Invoke-Generator -Target "desktop" -Offline:$Offline)) {
        Write-Host "服务重启已跳过。" -ForegroundColor Yellow
        return
    }
    Write-Host ""
    Write-Host "=== [2/2] 重启 sing-box 服务 ===" -ForegroundColor Cyan
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Host "[提示] 服务尚未安装，仅生成了配置。运行 setup.bat 可安装服务。" -ForegroundColor Yellow
        return
    }
    [void](Invoke-ServiceAction -Action "restart")
}

function Invoke-PublishAndroid {
    param([switch]$Offline)

    Write-Host "=== [1/2] 生成安卓配置 ===" -ForegroundColor Cyan
    if (-not (Invoke-Generator -Target "android" -Offline:$Offline)) {
        Write-Host "局域网发布已跳过。" -ForegroundColor Yellow
        return
    }
    Write-Host ""
    Write-Host "=== [2/2] 局域网发布（手机 SFA 远程订阅） ===" -ForegroundColor Cyan
    $serveBat = Join-Path $PSScriptRoot "tools\serve_android.bat"
    if (-not (Test-Path -LiteralPath $serveBat)) {
        Write-Host "[错误] 找不到 tools\serve_android.bat。" -ForegroundColor Red
        return
    }
    # 在新窗口常驻发布，保持本菜单可用；新窗口里会打印手机要用的远程配置 URL。
    Start-Process -FilePath $serveBat -WorkingDirectory $PSScriptRoot
    Write-Host "[完成] 已在新窗口启动局域网发布，窗口内显示手机 SFA 要用的远程配置 URL。" -ForegroundColor Green
    Write-Host "首次：手机 SFA 新建「远程」配置并粘贴该 URL；日后刷新只需在 SFA 点「更新」。" -ForegroundColor DarkGray
    Write-Host "停止发布：关闭那个新窗口，或在其中按 Ctrl+C。" -ForegroundColor DarkGray
}

function Show-Log {
    if (-not (Test-Path -LiteralPath $LogDirectory)) {
        Write-Host "[提示] 还没有日志目录。服务运行后才会产生日志。" -ForegroundColor Yellow
        return
    }
    $log = Get-ChildItem -LiteralPath $LogDirectory -Filter "*.out.log" -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $log) {
        Write-Host "[提示] 日志目录里还没有输出日志。" -ForegroundColor Yellow
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
        Write-Host "[错误] 找不到 traffic_monitor.py。" -ForegroundColor Red
        return
    }
    if (-not (Test-TrafficDashboard)) {
        $trafficService = Get-Service -Name $TrafficServiceName -ErrorAction SilentlyContinue
        if ($trafficService) {
            if ($trafficService.Status -ne "Running") {
                Write-Host "正在请求管理员权限启动流量统计服务..." -ForegroundColor Yellow
                try {
                    $process = Start-Process -FilePath $TrafficServiceExe -ArgumentList "start" `
                        -WorkingDirectory $PSScriptRoot -Verb RunAs -WindowStyle Hidden -Wait -PassThru
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
            $python = Get-PythonCommand
            $executable = $python[0]
            $arguments = @($python | Select-Object -Skip 1) + @("`"$TrafficMonitor`"")
            Write-Host "流量统计服务尚未安装，正在以当前用户启动统计器..." -ForegroundColor Yellow
            Start-Process -FilePath $executable -ArgumentList $arguments -WorkingDirectory $PSScriptRoot -WindowStyle Hidden
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
    Write-Host "  [9] 查看服务状态"
    Write-Host "  ---------------------------------------------------"
    Write-Host "  [d] 打开实时连接仪表板"
    Write-Host "  [t] 打开流量去向统计（域名 / 应用 / 规则 / 出口）"
    Write-Host "  [l] 查看实时日志"
    Write-Host "  [q] 退出"
    Write-Host "======================================================="
}

if (-not (Test-Initialized)) {
    Write-Host "[警告] 尚未初始化：找不到 subscriptions.yaml。" -ForegroundColor Yellow
    Write-Host "生成类操作会失败，请先运行 setup.bat 粘贴订阅链接。" -ForegroundColor Yellow
}

while ($true) {
    Show-Menu
    $raw = Read-Host "请选择"
    if ($null -eq $raw) { break }  # 输入流结束（EOF），退出循环。
    $choice = $raw.Trim().ToLower()
    Write-Host ""
    switch ($choice) {
        "1" { Invoke-ReloadDesktop }
        "2" { [void](Invoke-Generator -Target "desktop") }
        "3" { [void](Invoke-Generator -Target "android") }
        "a" { Invoke-PublishAndroid }
        "4" { [void](Invoke-Generator -Target "all") }
        "5" { Invoke-ReloadDesktop -Offline }
        "6" { [void](Invoke-ServiceAction -Action "start") }
        "7" { [void](Invoke-ServiceAction -Action "stop") }
        "8" { [void](Invoke-ServiceAction -Action "restart") }
        "9" { Write-Host "服务状态：$(Get-ServiceStateText)" -ForegroundColor Cyan }
        "d" { Open-Dashboard }
        "t" { Open-TrafficDashboard }
        "l" { Show-Log }
        "q" { break }
        ""  { }
        default { Write-Host "无效选项：$choice" -ForegroundColor Yellow }
    }
    if ($choice -eq "q") { break }
    Write-Host ""
    [void](Read-Host "按回车返回菜单")
}

Write-Host "已退出 sing-box 管理。" -ForegroundColor DarkGray
