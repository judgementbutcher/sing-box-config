[CmdletBinding()]
param(
    [string]$Action = "menu",
    [switch]$Offline,
    [string]$Name,
    [string]$Link,
    [string]$AdvertiseHost,
    [string]$BuildId,
    [switch]$Legacy,
    [string]$ConfigRoot,
    [string]$RuntimeRoot,
    [string]$OutputRoot,
    [switch]$NonInteractive,
    [switch]$Json,
    [string]$Domain,
    [string]$Platform = "desktop"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$ProjectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
Set-Location -LiteralPath $ProjectRoot
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch {}
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = "1"
$env:PYTHONDONTWRITEBYTECODE = "1"
$env:PYTHONUNBUFFERED = "1"
if (-not $ConfigRoot) { $ConfigRoot = Join-Path $ProjectRoot "config" }
if (-not $RuntimeRoot) { $RuntimeRoot = Join-Path $ProjectRoot "runtime" }
if (-not $OutputRoot) { $OutputRoot = Join-Path $ProjectRoot "dist" }
$PreferredCoreVersion = "1.15.0-alpha.11-reF1nd"
$ReadOnlyActions = @("status", "doctor", "sources", "history", "explain", "lint", "help")
$Actions = @("menu", "all", "check", "add", "remove", "disable", "enable", "maintain", "rollback", "recover", "publisher", "show-info", "rotate-credentials") + $ReadOnlyActions

function Stop-Usage {
    param([string]$Message)
    $errorObject = [ArgumentException]::new($Message)
    $errorObject.Data["ExitCode"] = 2
    throw $errorObject
}

function Get-PythonCommand {
    $venv = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $venv -PathType Leaf) { return @($venv) }
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) { return @($launcher.Source, "-3") }
    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($python) { return @($python.Source) }
    throw "找不到 Python。请先运行 scripts\bootstrap\setup.bat。"
}

function ConvertTo-NativeArgument {
    param([AllowEmptyString()][string]$Value)
    # Windows argv escaping, including quotes and trailing backslashes.
    return '"' + [regex]::Replace([regex]::Replace($Value, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
}

function Invoke-Python {
    param([string[]]$Arguments, [switch]$Capture, [switch]$Foreground)
    $python = @(Get-PythonCommand)
    $prefix = @($python | Select-Object -Skip 1)
    if ($Foreground) {
        & $python[0] @prefix @Arguments | Out-Host
        $code = $LASTEXITCODE
    } else {
        $start = New-Object System.Diagnostics.ProcessStartInfo
        $start.FileName = $python[0]
        $start.Arguments = (($prefix + $Arguments | ForEach-Object { ConvertTo-NativeArgument $_ }) -join " ")
        $start.WorkingDirectory = $ProjectRoot
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.StandardOutputEncoding = [Text.Encoding]::UTF8
        $start.StandardErrorEncoding = [Text.Encoding]::UTF8
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $start
        $started = $false
        try {
            [void]$process.Start()
            $started = $true
            if ($Capture) {
                $stdoutTask = $process.StandardOutput.ReadToEndAsync()
                $stderrTask = $process.StandardError.ReadToEndAsync()
                $process.WaitForExit()
                $stdout = $stdoutTask.GetAwaiter().GetResult()
                $stderr = $stderrTask.GetAwaiter().GetResult()
                if ($stderr) { [Console]::Error.Write($stderr) }
            } else {
                # Drain both streams concurrently; stderr must remain data in PS 5.1.
                $stdoutTask = $process.StandardOutput.ReadLineAsync()
                $stderrTask = $process.StandardError.ReadLineAsync()
                while ($null -ne $stdoutTask -or $null -ne $stderrTask) {
                    if ($null -ne $stdoutTask -and $stdoutTask.IsCompleted) {
                        $line = $stdoutTask.GetAwaiter().GetResult()
                        if ($null -eq $line) { $stdoutTask = $null }
                        else { Write-Host $line; $stdoutTask = $process.StandardOutput.ReadLineAsync() }
                    }
                    if ($null -ne $stderrTask -and $stderrTask.IsCompleted) {
                        $line = $stderrTask.GetAwaiter().GetResult()
                        if ($null -eq $line) { $stderrTask = $null }
                        else { [Console]::Error.WriteLine($line); $stderrTask = $process.StandardError.ReadLineAsync() }
                    }
                    $pending = @()
                    if ($null -ne $stdoutTask) { $pending += $stdoutTask }
                    if ($null -ne $stderrTask) { $pending += $stderrTask }
                    if ($pending.Count) { [void][Threading.Tasks.Task]::WaitAny([Threading.Tasks.Task[]]$pending, 250) }
                }
            }
            $process.WaitForExit()
            $code = $process.ExitCode
        } finally {
            if ($started -and -not $process.HasExited) {
                try { $process.Kill(); $process.WaitForExit() } catch {}
            }
            $process.Dispose()
        }
    }
    if ($code -ne 0) {
        $message = "操作失败（退出码 $code）；未收到成功结果，请勿假定已更新。"
        if ($code -eq 10) { $message = "活动版本已提交，但导出或清单同步未完成。请进入「诊断与修复 → 完成同步恢复」；成功前勿导入 dist。" }
        elseif ($code -eq 2) { $message = "命令参数有误；尚不能据此判断发生了配置提交。请检查参数或运行 -Action help。" }
        $errorObject = [InvalidOperationException]::new($message)
        $errorObject.Data["ExitCode"] = $code
        throw $errorObject
    }
    if ($Capture) { return $stdout }
}

function Get-CoreExecutable {
    param([switch]$Optional)
    if ($env:SING_BOX_CORE) { return $env:SING_BOX_CORE }
    $directory = Join-Path $ProjectRoot "runtime\cores\$PreferredCoreVersion"
    $candidate = Get-ChildItem -LiteralPath $directory -Filter "sing-box.exe" -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($candidate) { return $candidate.FullName }
    if (-not $Optional) { throw "未找到指定版本 CLI 核心。请安装到 runtime\cores\$PreferredCoreVersion 或用 SING_BOX_CORE 指定。不会自动下载或替换核心。" }
}

function Invoke-Query {
    param([string]$Command, [switch]$AsObject)
    $arguments = @("-m", "singbox_config.management", $Command,
        "--config-root", $ConfigRoot, "--runtime-root", $RuntimeRoot, "--output-root", $OutputRoot)
    $core = Get-CoreExecutable -Optional
    if ($core) { $arguments += @("--core", $core) }
    if ($Command -eq "explain") {
        $selectedDomain = $Domain
        if (-not $selectedDomain) {
            if ($NonInteractive) { Stop-Usage "explain 需要 -Domain；-NonInteractive 不会询问输入。" }
            $selectedDomain = (Read-Host "查询域名（回车取消）").Trim()
            if (-not $selectedDomain) { return }
        }
        $arguments += @("--domain=$selectedDomain", "--platform", $Platform)
    }
    $arguments += "--json"
    $text = Invoke-Python -Arguments $arguments -Capture
    if ($AsObject) { return ($text | ConvertFrom-Json) }
    if ($Json) { Write-Output $text.TrimEnd(); return }
    Show-QueryResult -Command $Command -Data ($text | ConvertFrom-Json)
}

function Format-State {
    param([string]$State)
    $labels = @{ valid="有效"; invalid="无效"; missing="缺失"; unknown="未知"; same="与发布版一致";
        changed="有未发布修改"; synced="已同步"; stale="不同步"; matches_active="匹配活动版";
        present_unverified="已找到/未执行校验"; unreadable="无法读取"; fresh="有效"; expired="已过期";
        local_input="本地输入"; input_missing="输入缺失" }
    if ($labels.ContainsKey($State)) { return $labels[$State] }
    return $State
}

function Show-QueryResult {
    param([string]$Command, $Data)
    switch ($Command) {
        "status" {
            $build = if ($Data.active.build_id) { $Data.active.build_id } else { "无" }
            Write-Host ("活动版本：{0}（{1}）    导出：{2}    工作配置：{3}" -f $build, (Format-State $Data.active.state), (Format-State $Data.exports.state), (Format-State $Data.working_config.state))
            Write-Host ("订阅：{0} 启用 / {1} 停用    核心：{2} {3}" -f $Data.sources.enabled, $Data.sources.disabled, (Format-State $Data.core.state), $Data.core.version)
            if ($Data.pending_recovery) { Write-Host "待恢复事务：有。请选 6 → 3 完成同步恢复；暂勿手动导入 dist。" -ForegroundColor Yellow }
            Write-Host "发布/客户端状态：只读查询不探测网络；客户端当前版本与节点选择未知。"
        }
        "sources" {
            $index = 0
            foreach ($item in $Data.items) {
                $index++
                $state = if ($item.enabled) { "启用" } else { "停用" }
                $count = if ($null -eq $item.node_count) { "未知" } else { "$($item.node_count)（活动快照）" }
                Write-Host ("  [{0}] {1} | {2} | 节点 {3} | 缓存 {4}" -f $index, $item.name, $state, $count, (Format-State $item.cache_status))
                if (@($item.required_by).Count) { Write-Host ("      依赖分组：" + ($item.required_by -join "、")) -ForegroundColor Yellow }
            }
            if (-not $index) { Write-Host "暂无订阅。" }
        }
        "history" {
            $index = 0
            foreach ($item in $Data.items) {
                $index++
                $state = if ($item.valid) { "有效" } else { "无效/不完整" }
                $current = if ($item.active) { "当前" } else { "历史" }
                $kind = if ($item.legacy) { "旧快照" } else { "release" }
                Write-Host ("  [{0}] {1} | {2}/{3}/{4} | {5} {6}" -f $index, $item.build_id, $state, $current, $kind, $item.created_at, $item.origin)
            }
            if (-not $index) { Write-Host "暂无历史版本。" }
        }
        "lint" {
            Write-Host ("规则结构检查：错误 {0} / 警告 {1} / 提示 {2}" -f $Data.counts.error, $Data.counts.warning, $Data.counts.info)
            $messages = @{ required_source_unavailable="依赖的订阅不存在或已停用"; invalid_domain_suffix="请检查域名后缀格式";
                duplicate_suffix="同一名单中重复"; cross_list_overlap="跨名单重叠，按规则顺序决定优先级";
                suffix_covered="已被更宽的本地后缀覆盖"; unresolved_rule_set="规则集定义缺失或无法解析";
                unresolved_dns_reference="DNS 引用了未知目标"; unresolved_final="默认目标不存在"; unresolved_reference="规则引用的目标不存在" }
            foreach ($item in $Data.issues) {
                $message = $messages[$item.code]
                if (-not $message) { $message = $item.message }
                $details = @($item.platform, $item.section, $item.domain, $item.file, $item.source, $item.target, $item.server) | Where-Object { $_ }
                Write-Host ("  [{0}] {1}：{2}" -f $item.severity, $message, ($details -join " / "))
            }
            Write-Host "仅静态结构检查；重叠可能是有意设计，不代表业务不可用，也不是实际连通性测试。"
        }
        "explain" {
            Write-Host ("域名：{0}    平台：{1}    依据：{2}" -f $Data.domain, $Data.platform, $Data.basis)
            foreach ($kind in @("route", "A", "AAAA", "HTTPS")) {
                $result = if ($kind -eq "route") { $Data.route } else { $Data.dns.$kind }
                $certainty = if ($result.certainty -eq "conditional") { "条件分流，前序条件未确认" } else { "静态输入可确定（非实际出口）" }
                Write-Host "  $kind：$certainty"
                foreach ($candidate in $result.candidates) {
                    $target = @($candidate.outbound, $candidate.server, $candidate.rcode, $candidate.target) | Where-Object { $null -ne $_ }
                    Write-Host ("    候选规则 {0}：{1} → {2}" -f $candidate.rule_index, $candidate.action, ($target -join "/"))
                }
                if ($result.candidate) {
                    $target = @($result.candidate.outbound, $result.candidate.server, $result.candidate.rcode, $result.candidate.target) | Where-Object { $null -ne $_ }
                    Write-Host ("    静态候选：规则 {0} / {1} / {2}" -f $result.candidate.rule_index, $result.candidate.action, ($target -join "/"))
                }
            }
            Write-Host "客户端实际选择与远端出口未知；不执行 DNS 查询、协议探测或自动切换节点。"
        }
    }
    foreach ($warning in $Data.warnings) { Write-Host "提示：$warning" -ForegroundColor Yellow }
}

function Invoke-Release {
    param([string]$Command, [string[]]$Extra = @(), [switch]$UseOffline)
    $arguments = @("-m", "singbox_config.release_manager", $Command,
        "--config-root", $ConfigRoot, "--runtime-root", $RuntimeRoot, "--output-root", $OutputRoot)
    if ($Command -notin @("list", "recover", "sources")) { $arguments += @("--core", (Get-CoreExecutable)) }
    $offlineMode = $Offline
    if ($PSBoundParameters.ContainsKey("UseOffline")) { $offlineMode = $UseOffline }
    if ($offlineMode) { $arguments += "--offline" }
    Write-Host "执行：$Command。生成/维护/回退会校验并激活两端；失败时请以提交状态为准。" -ForegroundColor Cyan
    Write-Host "执行前可取消；执行中中断不能保证未提交。若关闭窗口或 Ctrl+C，请先查 -Action status，有待恢复事务再运行 recover。" -ForegroundColor Yellow
    Invoke-Python -Arguments ($arguments + $Extra)
    if ($Command -notin @("list", "sources", "check")) {
        Write-Host "操作完成。配置发布成功不等于客户端已刷新；请分别在 SFW / SFA 刷新并核对。" -ForegroundColor Green
    }
}

function Confirm-Change {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Yellow
    return ((Read-Host "输入 y 确认；回车或其他输入取消").Trim().ToLowerInvariant() -eq "y")
}

function Show-HomeStatus {
    try {
        $status = Invoke-Query -Command status -AsObject
        Show-QueryResult -Command status -Data $status
    } catch { Write-Host "首页状态读取失败：$($_.Exception.Message)；仍可查看帮助或诊断。" -ForegroundColor Yellow }
}

function Show-Sources {
    $data = Invoke-Query -Command sources -AsObject
    $items = @($data.items)
    Show-QueryResult -Command sources -Data $data
    return $items
}

function Invoke-Add {
    param([switch]$Confirm)
    $selectedName = $Name
    $selectedLink = $Link
    if ($NonInteractive -and (-not $selectedName -or -not $selectedLink)) { Stop-Usage "add 需要 -Name 与 -Link。" }
    if (-not $selectedName -or -not $selectedLink) { $Confirm = $true }
    if (-not $selectedName) { $selectedName = (Read-Host "订阅名称（回车取消）").Trim() }
    if (-not $selectedName) { return }
    if (-not $selectedLink) { $selectedLink = (Read-Host "订阅链接或单节点 URI（敏感信息，回车取消）").Trim() }
    if (-not $selectedLink) { return }
    if ($Confirm -and -not (Confirm-Change "添加「$selectedName」将立即重新生成并激活两端配置；不会替你刷新客户端。")) { return }
    Invoke-Release -Command add -Extra @("--name=$selectedName", "--link=$selectedLink")
}

function Invoke-Maintenance {
    param([string]$Mode, [string]$SelectedName, [switch]$Confirm)
    if (-not $SelectedName) {
        if ($NonInteractive) { Stop-Usage "$Mode 需要 -Name。" }
        $SelectedName = (Read-Host "订阅名称（回车取消）").Trim()
        if (-not $SelectedName) { return }
        $Confirm = $true
    }
    if ($Confirm -and -not (Confirm-Change "对「$SelectedName」执行 $Mode，会立即重新生成并激活两端。依赖它的固定分组可能阻止发布；删除仅移除清单，不删除输入文件。")) { return }
    Invoke-Release -Command $Mode -Extra @("--name=$SelectedName")
}

function Show-MaintenanceMenu {
    if ($NonInteractive) { Stop-Usage "maintain 是交互菜单；请改用 add/remove/disable/enable 并提供必要参数。" }
    $items = @(Show-Sources)
    $selection = (Read-Host "输入编号或完整订阅名；a 添加；回车返回").Trim()
    if (-not $selection) { return }
    if ($selection -eq "a") { Invoke-Add -Confirm; return }
    $number = 0
    if ([int]::TryParse($selection, [ref]$number) -and $number -ge 1 -and $number -le $items.Count) { $selection = $items[$number - 1].name }
    if (-not ($items | Where-Object name -EQ $selection)) { Write-Host "没有找到该订阅。" -ForegroundColor Yellow; return }
    $mode = @{ "1" = "remove"; "2" = "disable"; "3" = "enable" }[(Read-Host "1 删除  2 停用  3 启用（回车返回）").Trim()]
    if ($mode) { Invoke-Maintenance -Mode $mode -SelectedName $selection -Confirm }
}

function Invoke-Rollback {
    param([switch]$Confirm)
    $target = $BuildId
    $isLegacy = [bool]$Legacy
    if (-not $target) {
        if ($NonInteractive) { Stop-Usage "rollback 需要 -BuildId。" }
        $data = Invoke-Query -Command history -AsObject
        $items = @($data.items)
        Show-QueryResult -Command history -Data $data
        if (-not $items.Count) { Write-Host "没有可列出的历史版本；仍可输入完整 ID。" }
        $target = (Read-Host "输入编号或完整 build_id（旧快照 backups:名称；回车返回）").Trim()
        if (-not $target) { return }
        $number = 0
        if ([int]::TryParse($target, [ref]$number) -and $number -ge 1 -and $number -le $items.Count) {
            $item = $items[$number - 1]
            if (-not $item.valid) { Write-Host "该版本无效或不完整，不能回退。" -ForegroundColor Yellow; return }
            $target = $item.build_id
            $isLegacy = [bool]$item.legacy
        }
        $Confirm = $true
    }
    if ($target.StartsWith("backups:")) { $isLegacy = $true; $target = $target.Substring(8) }
    if ($Confirm -and -not (Confirm-Change "回退到 $target：只恢复发布配置及版本缓存，不恢复工作策略、订阅清单或客户端节点选择；完成后需刷新客户端。")) { return }
    $extra = @("--build-id=$target")
    if ($isLegacy) { $extra += "--legacy" }
    Invoke-Release -Command rollback -Extra $extra
}

function Invoke-Publisher {
    param([string[]]$Extra = @())
    foreach ($entry in @(@($ConfigRoot, "config"), @($RuntimeRoot, "runtime"), @($OutputRoot, "dist"))) {
        $actual = [IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($entry[0])).TrimEnd('\', '/')
        $expected = [IO.Path]::GetFullPath((Join-Path $ProjectRoot $entry[1])).TrimEnd('\', '/')
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals($actual, $expected)) {
            Stop-Usage "自定义根目录下禁止发布、查看或轮换凭据，避免使用生产凭据/日志。隔离测试请直接调用 python -m singbox_config.publisher，并显式提供 --credentials、--access-log 及全部配置/运行目录参数。"
        }
    }
    $arguments = @("-m", "singbox_config.publisher", "--runtime-root", $RuntimeRoot,
        "--desktop-config", (Join-Path $OutputRoot "desktop\config.json"), "--desktop-stamp", (Join-Path $OutputRoot "desktop\config.validated.json"),
        "--android-config", (Join-Path $OutputRoot "android\config.json"), "--android-stamp", (Join-Path $OutputRoot "android\config.validated.json"))
    if ($AdvertiseHost) { $arguments += @("--advertise-host=$AdvertiseHost") }
    if (-not $Extra.Count) { Write-Host "发布器在当前窗口前台运行；Ctrl+C 停止。发布期间请另开管理窗口更新配置。不会修改防火墙或客户端；导入链接请另选「查看敏感导入信息」。" -ForegroundColor Cyan }
    Invoke-Python -Arguments ($arguments + $Extra) -Foreground:($Extra.Count -eq 0)
}

function Show-Help {
    $helpData = [ordered]@{
        description = "中文终端管理；菜单确认后执行，完整 CLI 参数保持直接执行。"
        readonly = $ReadOnlyActions
        commands = @("all [-Offline]", "add -Name 名称 -Link 链接", "remove/disable/enable -Name 名称", "rollback -BuildId ID [-Legacy]", "recover", "check", "publisher", "show-info", "rotate-credentials")
        examples = @("-Action status -Json -NonInteractive", "-Action explain -Domain example.com -Platform android -Json -NonInteractive", "-Action all -Offline -NonInteractive")
        exit_codes = @{ success = 0; failure = 1; arguments = 2; committed_pending_recovery = 10 }
        notes = @("-Json 仅支持只读查询；缺少必要参数时 -NonInteractive 返回 2。", "check 可能完成待恢复同步，并非只读；doctor/status/lint 不修改发布状态。", "更新/订阅维护/回退立即发布两端配置，但不刷新客户端、不控制核心。", "发布保持前台运行；启动不显示敏感信息，show-info 和轮换结果会显示完整导入信息。", "自定义根目录禁止 publisher/show-info/rotate-credentials，避免误用生产凭据或日志。")
    }
    if ($Json) { $helpData | ConvertTo-Json -Depth 6; return }
    Write-Host "用法：.\scripts\manage\manage.ps1 -Action <动作> [参数]"
    Write-Host ("只读：" + ($ReadOnlyActions -join " / "))
    foreach ($command in $helpData.commands) { Write-Host "  $command" }
    foreach ($note in $helpData.notes) { Write-Host "提示：$note" }
    Write-Host "查询和发布事务可用 -ConfigRoot/-RuntimeRoot/-OutputRoot 指定隔离目录；自定义根目录禁止 publisher/show-info/rotate-credentials，避免误用生产凭据。"
    Write-Host "退出码 0 成功、1 失败、2 参数错误、10 已提交待同步。"
}

function Invoke-Action {
    param([string]$ActionName)
    switch ($ActionName) {
        "all"                { Invoke-Release -Command all }
        "check"              { Invoke-Release -Command check }
        "recover"            { Invoke-Release -Command recover }
        "add"                { Invoke-Add }
        "remove"             { Invoke-Maintenance -Mode remove -SelectedName $Name }
        "disable"            { Invoke-Maintenance -Mode disable -SelectedName $Name }
        "enable"             { Invoke-Maintenance -Mode enable -SelectedName $Name }
        "maintain"           { Show-MaintenanceMenu }
        "rollback"           { Invoke-Rollback }
        "publisher"          { Invoke-Publisher }
        "show-info"          { Invoke-Publisher -Extra @("--show-info") }
        "rotate-credentials" { Invoke-Publisher -Extra @("--rotate-credentials") }
        "help"               { Show-Help }
        "doctor"             {
            if ($Json) {
                $result = [ordered]@{ status = (Invoke-Query -Command status -AsObject); lint = (Invoke-Query -Command lint -AsObject) }
                $result | ConvertTo-Json -Depth 30
            } else { Invoke-Query -Command status; Invoke-Query -Command lint }
        }
        default { Invoke-Query -Command $ActionName }
    }
}

try {
    $Action = $Action.ToLowerInvariant()
    $Platform = $Platform.ToLowerInvariant()
    if ($Action -notin $Actions) { Stop-Usage "未知动作：$Action。请运行 -Action help。" }
    if ($Platform -notin @("desktop", "android")) { Stop-Usage "-Platform 仅支持 desktop 或 android。" }
    if ($Json -and $Action -notin $ReadOnlyActions) { Stop-Usage "-Json 仅支持 status/doctor/sources/history/explain/lint/help。" }
    if ($Json) { $NonInteractive = $true }
    if ($NonInteractive -and $Action -in @("menu", "maintain")) { Stop-Usage "-NonInteractive 需要明确的非菜单 -Action。" }
    if ($Action -ne "menu") { Invoke-Action -ActionName $Action; exit 0 }
    while ($true) {
        Write-Host "`n============ sing-box 配置与发布 ============" -ForegroundColor Cyan
        Show-HomeStatus
        Write-Host "  [1] 更新配置        [2] 订阅管理        [3] 分流查询与检查"
        Write-Host "  [4] 发布与设备导入  [5] 历史版本与回退  [6] 诊断与修复"
        Write-Host "  [0/q] 退出         [h] 命令行帮助"
        $choice = (Read-Host "请选择").Trim().ToLowerInvariant()
        if ($choice -in @("0", "q")) { break }
        try {
            switch ($choice) {
                "1" {
                    $mode = (Read-Host "1 在线更新  2 离线复用完整缓存（回车返回）").Trim()
                    if ($mode -in @("1", "2") -and (Confirm-Change "将生成、校验并立即激活桌面和安卓配置。离线不延长缓存有效期；完成后请在 SFW/SFA 各自刷新。")) { Invoke-Release -Command all -UseOffline:($mode -eq "2") }
                }
                "2" { Show-MaintenanceMenu }
                "3" {
                    $mode = (Read-Host "1 查询域名分流（静态解释，非实际出口）  2 检查规则（回车返回）").Trim()
                    if ($mode -eq "1") { Invoke-Query -Command explain }
                    elseif ($mode -eq "2") { Invoke-Query -Command lint }
                }
                "4" {
                    $mode = (Read-Host "1 启动前台发布  2 查看敏感导入信息  3 轮换凭据（回车返回）").Trim()
                    if ($mode -eq "1" -and (Confirm-Change "将在当前窗口持续提供配置下载；仅在可信局域网使用，Ctrl+C 停止。")) { Invoke-Publisher }
                    elseif ($mode -eq "2") { Invoke-Publisher -Extra @("--show-info") }
                    elseif ($mode -eq "3" -and (Confirm-Change "必须先停止发布器；轮换会使旧密码和旧导入链接失效，需要重新导入并启动服务。")) { Invoke-Publisher -Extra @("--rotate-credentials") }
                }
                "5" { Invoke-Rollback -Confirm }
                "6" {
                    $mode = (Read-Host "1 只读诊断  2 核心检查（可能恢复同步）  3 完成同步恢复（回车返回）").Trim()
                    if ($mode -eq "1") { Invoke-Action -ActionName doctor }
                    elseif ($mode -eq "2" -and (Confirm-Change "核心检查可能先完成待恢复事务并写入工作清单/dist；仅查看请改选只读诊断。")) { Invoke-Release -Command check }
                    elseif ($mode -eq "3" -and (Confirm-Change "将完成已提交事务的清单/导出同步；不覆盖外部冲突，不修改客户端。")) { Invoke-Release -Command recover }
                }
                "h" { Show-Help }
                default { Write-Host "无效选项，请输入菜单编号；回车不会执行任何修改。" -ForegroundColor Yellow }
            }
        } catch { Write-Host "[错误] $($_.Exception.Message)" -ForegroundColor Red }
    }
} catch {
    $exitCode = 1
    if ($_.Exception.Data.Contains("ExitCode")) { $exitCode = [int]$_.Exception.Data["ExitCode"] }
    if ($Json) { [ordered]@{ error = $_.Exception.Message; exit_code = $exitCode } | ConvertTo-Json -Compress }
    else { Write-Host "[错误] $($_.Exception.Message)" -ForegroundColor Red }
    exit $exitCode
}
