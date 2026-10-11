[CmdletBinding()]
param(
    [ValidateSet("menu", "all", "check", "add", "remove", "disable", "enable", "publisher", "show-info", "rotate-credentials")]
    [string]$Action = "menu",
    [switch]$Offline,
    [string]$Name,
    [string]$Link,
    [string]$AdvertiseHost
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$ProjectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
Set-Location -LiteralPath $ProjectRoot
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch {}
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = "1"

$LocalRoot = Join-Path $ProjectRoot "config\local"
$Subscriptions = Join-Path $LocalRoot "subscriptions.yaml"
$OutputRoot = Join-Path $ProjectRoot "dist"
$RuntimeRoot = Join-Path $ProjectRoot "runtime"
$Platforms = @("desktop", "android")
$PreferredCoreVersion = "1.15.0-alpha.11-reF1nd"
$PublisherPort = 18080
$Utf8 = [Text.UTF8Encoding]::new($false)

# ---------------------------------------------------------------- 生成与校验

function Get-PythonCommand {
    $venv = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $venv -PathType Leaf) { return @($venv) }
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) { return @($launcher.Source, "-3") }
    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($python) { return @($python.Source) }
    throw "找不到 Python。请先运行 scripts\bootstrap\setup.bat。"
}

function Invoke-Python {
    param([string[]]$Arguments)
    $python = @(Get-PythonCommand)
    $executable = $python[0]
    $prefix = @($python | Select-Object -Skip 1)
    & $executable @prefix @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Python 命令失败（退出码 $LASTEXITCODE）。" }
}

function Get-CoreExecutable {
    if ($env:SING_BOX_CORE -and (Test-Path -LiteralPath $env:SING_BOX_CORE -PathType Leaf)) {
        return (Resolve-Path -LiteralPath $env:SING_BOX_CORE).Path
    }
    $cores = Join-Path $RuntimeRoot "cores"
    if (Test-Path -LiteralPath $cores) {
        $preferred = Join-Path $cores $PreferredCoreVersion
        if (Test-Path -LiteralPath $preferred) {
            $candidate = Get-ChildItem -LiteralPath $preferred -Filter "sing-box.exe" -File -Recurse -ErrorAction SilentlyContinue |
                Select-Object -First 1
            if ($candidate) { return $candidate.FullName }
        }
        $candidate = Get-ChildItem -LiteralPath $cores -Filter "sing-box.exe" -File -Recurse -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }
    $command = Get-Command sing-box.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    return $null
}

function Resolve-ValidationCore {
    # 返回 @{ Path = <可用核心路径，不可用为 $null>; Version = <版本行>; Reason = <不可用原因> }。
    # Get-CoreExecutable 找不到指定版本时会退回到别的 sing-box.exe，甚至 PATH 上的
    # Program Files 那个 Electron 桩（静默 exit 0）。不核对版本就拿来 check，
    # 会把核心根本没解析的配置报成"通过"。
    $core = Get-CoreExecutable
    if (-not $core) {
        return @{ Path = $null; Version = ""; Reason = "未找到 $PreferredCoreVersion CLI 核心。请安装到 runtime\cores 或通过 SING_BOX_CORE 指定路径。" }
    }
    $versionOutput = @(& $core version 2>&1)
    if ($LASTEXITCODE -ne 0) {
        return @{ Path = $null; Version = ""; Reason = "无法运行核心：$core" }
    }
    $version = [string]($versionOutput | Select-Object -First 1)
    if ($version -ne "sing-box version $PreferredCoreVersion") {
        return @{ Path = $null; Version = $version; Reason = "核心版本不匹配：$version（要求 $PreferredCoreVersion）。请更新 runtime\cores 或 SING_BOX_CORE。" }
    }
    return @{ Path = $core; Version = $version; Reason = $null }
}

function Get-Sha256Hex {
    param([Parameter(Mandatory)][string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            return ([BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-', '').ToLowerInvariant()
        } finally {
            $sha.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Publish-File {
    # 同目录内先落临时文件再原子替换，发布器不会读到写了一半的配置。
    param([string]$Source, [string]$Destination)
    $parent = Split-Path -Parent $Destination
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    $temporary = Join-Path $parent ((Split-Path -Leaf $Destination) + ".new-" + [Guid]::NewGuid().ToString("N"))
    [IO.File]::Move($Source, $temporary)
    try {
        if (Test-Path -LiteralPath $Destination) {
            $backup = $Destination + ".bak-" + [Guid]::NewGuid().ToString("N")
            try {
                [IO.File]::Replace($temporary, $Destination, $backup)
            } finally {
                Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
            }
        } else {
            [IO.File]::Move($temporary, $Destination)
        }
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-Generate {
    # 生成到临时目录 → 核心 check → 写验证标记 → 发布到 dist。任何一步失败 dist 都不变。
    if (-not (Test-Path -LiteralPath $Subscriptions -PathType Leaf)) {
        throw "找不到 config\local\subscriptions.yaml。用菜单里的 [添加订阅/节点]，或参考 config\examples\subscriptions.yaml 创建。"
    }
    $core = Resolve-ValidationCore
    if (-not $core.Path) { throw $core.Reason }
    $stage = Join-Path $RuntimeRoot ("manage-" + [Guid]::NewGuid().ToString("N"))
    [IO.Directory]::CreateDirectory($stage) | Out-Null
    try {
        $arguments = @("-m", "singbox_config.generator", "all", "--output-dir", $stage)
        if ($Offline) { $arguments += "--offline" }
        Invoke-Python -Arguments $arguments
        foreach ($platform in $Platforms) {
            & $core.Path check -c (Join-Path $stage "$platform\config.json") | Out-Host
            if ($LASTEXITCODE -ne 0) { throw "$platform 配置未通过 sing-box 核心校验。" }
        }
        foreach ($platform in $Platforms) {
            $config = Join-Path $stage "$platform\config.json"
            $stamp = Join-Path $stage "$platform\config.validated.json"
            $metadata = [ordered]@{
                schema_version = 1
                sha256 = (Get-Sha256Hex -Path $config)
                validated_at = [DateTimeOffset]::Now.ToString("o")
                validator = [string]$core.Version
            } | ConvertTo-Json
            [IO.File]::WriteAllText($stamp, $metadata + [Environment]::NewLine, $Utf8)
            Publish-File -Source $config -Destination (Join-Path $OutputRoot "$platform\config.json")
            Publish-File -Source $stamp -Destination (Join-Path $OutputRoot "$platform\config.validated.json")
            Write-Host "[完成] $platform 配置已校验并发布。" -ForegroundColor Green
        }
    } finally {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-Check {
    $ok = $true
    $core = Resolve-ValidationCore
    if ($core.Path) {
        Write-Host "核心校验：$($core.Path)" -ForegroundColor DarkGray
    } else {
        # 摘要校验只能证明文件没被改过，不能证明核心能加载它。
        Write-Host "无法进行核心校验：$($core.Reason)" -ForegroundColor Yellow
        $ok = $false
    }
    foreach ($platform in $Platforms) {
        $config = Join-Path $OutputRoot "$platform\config.json"
        $stamp = Join-Path $OutputRoot "$platform\config.validated.json"
        $problem = ""
        if (-not (Test-Path -LiteralPath $config -PathType Leaf)) {
            $problem = "缺少 config.json"
        } elseif (-not (Test-Path -LiteralPath $stamp -PathType Leaf)) {
            $problem = "缺少 config.validated.json"
        } else {
            try {
                $metadata = Get-Content -LiteralPath $stamp -Raw -Encoding UTF8 | ConvertFrom-Json
                if ((Get-Sha256Hex -Path $config) -ine [string]$metadata.sha256) { $problem = "验证摘要不匹配" }
            } catch {
                $problem = "验证文件损坏"
            }
        }
        if (-not $problem -and $core.Path) {
            & $core.Path check -c $config | Out-Host
            if ($LASTEXITCODE -ne 0) { $problem = "核心校验失败" }
        }
        if ($problem) {
            Write-Host ("{0,-8} {1}" -f $platform, $problem) -ForegroundColor Red
            $ok = $false
        } else {
            Write-Host ("{0,-8} 有效（{1}）" -f $platform, $metadata.validator) -ForegroundColor Green
        }
    }
    if (-not $ok) { throw "已发布的配置没有全部通过检查。" }
}

# ---------------------------------------------------------------- 订阅清单

function Get-ManifestEntries {
    # 逐条切出清单里的订阅块。块的结尾不含紧挨下一条的注释和空行，
    # 删除一条时不会连带删掉下一条的说明。
    param([string]$Text)
    $pattern = '(?ms)^  - name:[ \t]*(?<raw>[^\r\n]*?)[ \t]*\r?$.*?(?=(?:^[ \t]*(?:#[^\n]*)?\r?\n)*(?:^  - name:|\z))'
    foreach ($match in [Regex]::Matches($Text, $pattern)) {
        $value = $match.Groups['raw'].Value
        if ($value -match "^'(.*)'$") { $value = $Matches[1].Replace("''", "'") }
        elseif ($value -match '^"(.*)"$') { $value = $Matches[1] }
        [pscustomobject]@{
            Name = $value
            Index = $match.Index
            Block = $match.Value
            Enabled = $match.Value -notmatch '(?m)^\s+enabled:\s*false\s*$'
        }
    }
}

function Save-Manifest {
    # 写入新清单并重新生成；生成失败就恢复原清单。
    param([string]$Original, [string]$Updated)
    [IO.File]::WriteAllText($Subscriptions, $Updated, $Utf8)
    try {
        Invoke-Generate
    } catch {
        if (-not $Original) {
            Remove-Item -LiteralPath $Subscriptions -Force -ErrorAction SilentlyContinue
        } else {
            [IO.File]::WriteAllText($Subscriptions, $Original, $Utf8)
        }
        throw
    }
}

function Invoke-Add {
    $nameValue = if ($Name) { $Name.Trim() } else { (Read-Host "名称（面板里显示的名字）").Trim() }
    $linkValue = if ($Link) { $Link.Trim() } else { (Read-Host "订阅链接或单节点 URI").Trim() }
    if (-not $nameValue) { throw "名称不能为空。" }
    # 订阅格式不用选：生成器读到内容后自动识别 sing-box JSON / Clash / URI 列表。
    if ($linkValue -match '^https?://\S+$') {
        $suffix = ".url.txt"
    } elseif ($linkValue -match '(?i)^(anytls|hy2|hysteria2|ss|trojan|tuic|vless|vmess)://\S+$') {
        $suffix = ".txt"
    } else {
        throw "链接必须是 http(s) 订阅地址，或 anytls/hysteria2/ss/trojan/tuic/vless/vmess 节点 URI。"
    }
    $original = $null
    if (Test-Path -LiteralPath $Subscriptions -PathType Leaf) {
        $original = Get-Content -Raw -Encoding UTF8 -LiteralPath $Subscriptions
    }
    $text = if ($original) { $original.TrimEnd() } else { "subscriptions:" }
    if (@(Get-ManifestEntries -Text $text | Where-Object { $_.Name -eq $nameValue }).Count) {
        throw "名称 [$nameValue] 已存在，请换一个。"
    }
    $stem = [Regex]::Replace($nameValue, '[\\/:*?"<>|\s]+', '_').Trim('_', '.')
    if (-not $stem) { $stem = "node" }
    $file = Join-Path $LocalRoot "subscriptions\$stem$suffix"
    if (Test-Path -LiteralPath $file) { throw "文件已存在：$file" }
    [IO.Directory]::CreateDirectory((Split-Path -Parent $file)) | Out-Null
    [IO.File]::WriteAllText($file, $linkValue + "`n", $Utf8)
    $nl = if ($text.Contains("`r`n")) { "`r`n" } else { "`n" }
    $block = "$nl$nl  - name: '$($nameValue.Replace("'", "''"))'$nl    path: 'subscriptions/$($stem.Replace("'", "''"))$suffix'$nl"
    try {
        Save-Manifest -Original $original -Updated ($text + $block)
    } catch {
        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        throw
    }
    Write-Host "[完成] 已添加 [$nameValue]。排除节点、AI 分组等选项见 config\examples\subscriptions.yaml。" -ForegroundColor Green
}

function Invoke-Maintenance {
    param([ValidateSet("remove", "disable", "enable")][string]$Mode, [string]$SelectedName)
    $original = Get-Content -Raw -Encoding UTF8 -LiteralPath $Subscriptions
    $target = if ($SelectedName) { $SelectedName } else { (Read-Host "订阅名称").Trim() }
    $entry = Get-ManifestEntries -Text $original | Where-Object { $_.Name -eq $target } | Select-Object -First 1
    if (-not $entry) { throw "清单里没有 [$target]。" }
    $nl = if ($original.Contains("`r`n")) { "`r`n" } else { "`n" }
    $block = ""
    if ($Mode -ne "remove") {
        # enabled 默认为 true：启用就是删掉这一行，停用就是在 name 下面加一行。
        $lines = @($entry.Block -split '\r?\n' | Where-Object { $_ -notmatch '^\s+enabled:' })
        if ($Mode -eq "disable") {
            $lines = @($lines[0], "    enabled: false") + @($lines | Select-Object -Skip 1)
        }
        $block = $lines -join $nl
    }
    $updated = $original.Remove($entry.Index, $entry.Block.Length).Insert($entry.Index, $block).TrimEnd() + $nl
    Save-Manifest -Original $original -Updated $updated
    if ($Mode -eq "remove" -and $entry.Block -match '(?m)^\s+path:\s*(.+?)\s*$') {
        $relative = $Matches[1].Trim("'", '"').Replace("''", "'") -replace '/', '\'
        $file = [IO.Path]::GetFullPath((Join-Path $LocalRoot $relative))
        if ($file.StartsWith($LocalRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        }
    }
    $done = @{ remove = "删除"; disable = "停用"; enable = "启用" }[$Mode]
    Write-Host "[完成] 已$done [$target]。" -ForegroundColor Green
}

function Show-MaintenanceMenu {
    $entries = @(Get-ManifestEntries -Text (Get-Content -Raw -Encoding UTF8 -LiteralPath $Subscriptions))
    if (-not $entries.Count) { throw "订阅清单是空的。" }
    Write-Host ""
    for ($i = 0; $i -lt $entries.Count; $i++) {
        $state = if ($entries[$i].Enabled) { "" } else { "（已停用）" }
        Write-Host ("  [{0}] {1}{2}" -f ($i + 1), $entries[$i].Name, $state)
    }
    $number = 0
    $choice = (Read-Host "选择订阅（回车返回）").Trim()
    if (-not [int]::TryParse($choice, [ref]$number) -or $number -lt 1 -or $number -gt $entries.Count) { return }
    $target = $entries[$number - 1].Name
    $mode = @{ "1" = "remove"; "2" = "disable"; "3" = "enable" }[(Read-Host "对 [$target] 执行：1 删除  2 停用  3 启用（回车返回）").Trim()]
    if ($mode) { Invoke-Maintenance -Mode $mode -SelectedName $target }
}

# ---------------------------------------------------------------- 发布器

function Get-TcpBindError {
    param([Parameter(Mandatory)][int]$Port)
    $listener = $null
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)
        $listener.Start()
        return 0
    } catch [System.Net.Sockets.SocketException] {
        $code = $_.Exception.NativeErrorCode
        if (-not $code) { $code = $_.Exception.ErrorCode }
        if ($code -eq 10048 -or $code -eq 10013) { return $code }
        return 10013
    } catch {
        return 10013
    } finally {
        if ($listener) { $listener.Stop() }
    }
}

function Invoke-Elevated {
    param([string]$Command)
    $elevated = Start-Process -FilePath "powershell.exe" -Verb RunAs -Wait -PassThru -ArgumentList @(
        "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $Command
    )
    if ($elevated.ExitCode -ne 0) { throw "管理员进程返回退出码 $($elevated.ExitCode)" }
}

function Enable-PublisherPort {
    # 10048 = 端口已有监听者，发布器自己会报告。10013 = 端口被 Windows（WinNAT）保留：
    # 申请管理员权限把它留给发布器，而不是换端口——手机里存的链接带着端口号。
    $code = Get-TcpBindError -Port $PublisherPort
    if ($code -eq 0 -or $code -eq 10048) { return }
    Write-Host "端口 $PublisherPort 被 Windows 保留（WinError $code），需要管理员权限把它留给发布器。请在弹出的授权窗口里允许。" -ForegroundColor Yellow
    $command = @"
`$ErrorActionPreference = 'Stop'
`$service = Get-Service -Name winnat -ErrorAction SilentlyContinue
`$wasRunning = `$service -and `$service.Status -eq 'Running'
if (`$wasRunning) { Stop-Service -Name winnat -Force }
`$add = (& netsh interface ipv4 add excludedportrange protocol=tcp startport=$PublisherPort numberofports=1 2>&1 | Out-String).Trim()
if (`$LASTEXITCODE -ne 0 -and `$add -notmatch 'exists') {
    if (`$wasRunning) { Start-Service -Name winnat }
    throw `$add
}
if (`$wasRunning) { Start-Service -Name winnat }
"@
    try {
        Invoke-Elevated -Command $command
    } catch {
        throw "未能取得管理员权限，端口 $PublisherPort 仍然无法绑定。$($_.Exception.Message)"
    }
    $again = Get-TcpBindError -Port $PublisherPort
    if ($again -ne 0 -and $again -ne 10048) { throw "授权之后端口 $PublisherPort 仍无法绑定（Windows 错误 $again）。" }
    Write-Host "已让 Windows 保留 TCP $PublisherPort 给发布器。" -ForegroundColor Green
}

function Enable-PublisherFirewall {
    $displayName = "sing-box Android publisher (LAN)"
    $rule = $null
    $portFilter = $null
    try {
        $rule = @(Get-NetFirewallRule -DisplayName $displayName -ErrorAction SilentlyContinue) | Select-Object -First 1
        if ($rule) { $portFilter = @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue) }
    } catch {
        $rule = $null
    }
    $profiles = if ($rule) { [string]$rule.Profile } else { "" }
    $portAllowed = @($portFilter | Where-Object {
        $_.Protocol -eq "TCP" -and @($_.LocalPort) -contains "$PublisherPort"
    }).Count -gt 0
    if ($rule -and $rule.Enabled -eq "True" -and $rule.Direction -eq "Inbound" -and
        $rule.Action -eq "Allow" -and $profiles -match "(Private.*Public|Public.*Private|Any)" -and $portAllowed) {
        return
    }
    $command = @"
`$ErrorActionPreference = 'Stop'
`$name = '$displayName'
if (Get-NetFirewallRule -DisplayName `$name -ErrorAction SilentlyContinue) {
    Set-NetFirewallRule -DisplayName `$name -Enabled True -Direction Inbound -Action Allow -Profile Private,Public -Protocol TCP -LocalPort $PublisherPort | Out-Null
} else {
    New-NetFirewallRule -DisplayName `$name -Direction Inbound -Action Allow -Protocol TCP -LocalPort $PublisherPort -Profile Private,Public | Out-Null
}
"@
    try {
        Invoke-Elevated -Command $command
        Write-Host "已允许 Private/Public 网络访问 TCP $PublisherPort。" -ForegroundColor Green
    } catch {
        Write-Warning "无法自动配置 Windows 防火墙。请以管理员身份允许 Private/Public 网络的 TCP $PublisherPort，否则手机访问不到发布链接。"
    }
}

function Invoke-Publisher {
    param([string[]]$Extra = @())
    if (-not $Extra.Count) {
        Enable-PublisherPort
        Enable-PublisherFirewall
    }
    if ($AdvertiseHost) {
        # 自动探测到的地址不对时（多网卡、虚拟网卡）手动指定手机能访问到的局域网地址：
        # -Action publisher -AdvertiseHost 192.168.1.31
        $Extra = @("--advertise-host", $AdvertiseHost) + $Extra
    }
    Invoke-Python -Arguments (@("-m", "singbox_config.publisher") + $Extra)
}

# ---------------------------------------------------------------- 入口

function Invoke-Action {
    param([string]$ActionName)
    switch ($ActionName) {
        "all"                { Invoke-Generate }
        "check"              { Invoke-Check }
        "add"                { Invoke-Add }
        "remove"             { Invoke-Maintenance -Mode remove -SelectedName $Name }
        "disable"            { Invoke-Maintenance -Mode disable -SelectedName $Name }
        "enable"             { Invoke-Maintenance -Mode enable -SelectedName $Name }
        "maintain"           { Show-MaintenanceMenu }
        "publisher"          { Invoke-Publisher }
        "show-info"          { Invoke-Publisher -Extra @("--show-info") }
        "rotate-credentials" { Invoke-Publisher -Extra @("--rotate-credentials") }
    }
}

$Menu = [ordered]@{
    "1" = @("all", "更新配置（桌面 + 安卓）")
    "2" = @("check", "检查已发布的配置")
    "3" = @("add", "添加订阅/节点")
    "4" = @("maintain", "删除/停用/启用订阅")
    "5" = @("publisher", "启动发布（显示地址和凭据）")
    "6" = @("show-info", "查看发布地址和凭据")
    "7" = @("rotate-credentials", "轮换发布凭据")
}

try {
    if ($Action -ne "menu") {
        Invoke-Action -ActionName $Action
        exit 0
    }
    while ($true) {
        Write-Host ""
        Write-Host "============ sing-box 配置与发布 ============"
        foreach ($key in $Menu.Keys) { Write-Host ("  [{0}] {1}" -f $key, $Menu[$key][1]) }
        Write-Host "  [q] 退出"
        $choice = (Read-Host "请选择").Trim().ToLowerInvariant()
        if ($choice -eq "q") { break }
        if (-not $Menu.Contains($choice)) { continue }
        try {
            Invoke-Action -ActionName $Menu[$choice][0]
        } catch {
            Write-Host "[错误] $($_.Exception.Message)" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "[错误] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
