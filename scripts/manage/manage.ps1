[CmdletBinding()]
param(
    [ValidateSet("menu", "desktop", "android", "all", "quick-add", "remove", "delete", "disable", "enable", "publisher", "check", "show-info", "rotate-credentials")]
    [string]$Action = "menu",
    [switch]$Offline,
    [string]$Name,
    [string]$Link,
    [string]$Pattern,
    [ValidateSet("auto", "uri", "clash", "sing-box-json")]
    [string]$Format = "auto"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$ProjectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
Set-Location -LiteralPath $ProjectRoot
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch {}
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = "1"

$Subscriptions = Join-Path $ProjectRoot "config\local\subscriptions.yaml"
$RoutingGroups = Join-Path $ProjectRoot "config\local\routing-groups.json"
$OutputRoot = Join-Path $ProjectRoot "dist"
$RuntimeRoot = Join-Path $ProjectRoot "runtime"

function Get-PythonCommand {
    $venv = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $venv -PathType Leaf) { return @($venv) }
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) { return @($launcher.Source, "-3") }
    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($python) { return @($python.Source) }
    throw "找不到 Python。请先运行 scripts\bootstrap\setup.bat。"
}

function Get-CoreExecutable {
    if ($env:SING_BOX_CORE -and (Test-Path -LiteralPath $env:SING_BOX_CORE -PathType Leaf)) {
        return (Resolve-Path -LiteralPath $env:SING_BOX_CORE).Path
    }
    $cores = Join-Path $RuntimeRoot "cores"
    if (Test-Path -LiteralPath $cores) {
        $candidate = Get-ChildItem -LiteralPath $cores -Filter "sing-box.exe" -File -Recurse -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }
    $command = Get-Command sing-box.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    return $null
}

function Invoke-Python {
    param([string[]]$Arguments)
    $python = @(Get-PythonCommand)
    $executable = $python[0]
    $prefix = @($python | Select-Object -Skip 1)
    & $executable @prefix @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Python 命令失败（退出码 $LASTEXITCODE）。" }
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

function Write-ValidationStamp {
    param([string]$ConfigPath, [string]$StampPath, [string]$Validator)
    $stamp = [ordered]@{
        schema_version = 1
        sha256 = (Get-Sha256Hex -Path $ConfigPath)
        validated_at = [DateTimeOffset]::Now.ToString("o")
        validator = $Validator
    } | ConvertTo-Json
    [IO.File]::WriteAllText($StampPath, $stamp + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Publish-File {
    param([string]$Source, [string]$Destination)
    $parent = Split-Path -Parent $Destination
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    $temporary = Join-Path $parent ((Split-Path -Leaf $Destination) + ".new-" + [Guid]::NewGuid().ToString("N"))
    # Staging and dist live under the same project tree.  Move the staged file
    # into the destination directory instead of copying it first; this avoids
    # an unnecessary full read/write cycle for large mobile configurations.
    try {
        [IO.File]::Move($Source, $temporary)
    } catch [IO.IOException] {
        # Keep the workflow usable when a caller stages on another volume.
        Copy-Item -LiteralPath $Source -Destination $temporary
    }
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
    param([ValidateSet("desktop", "android", "all")][string]$Target)
    if (-not (Test-Path -LiteralPath $Subscriptions -PathType Leaf)) {
        throw "找不到 config\local\subscriptions.yaml。请先按 config\examples\subscriptions.yaml 创建本机订阅。"
    }
    [IO.Directory]::CreateDirectory($RuntimeRoot) | Out-Null
    $stage = Join-Path $RuntimeRoot ("manage-" + [Guid]::NewGuid().ToString("N"))
    [IO.Directory]::CreateDirectory($stage) | Out-Null
    try {
        $arguments = @("-m", "singbox_config.simple_generator", $Target, "--output-dir", $stage)
        if ($Offline) { $arguments += "--offline" }
        Invoke-Python -Arguments $arguments

        $names = if ($Target -eq "all") { @("desktop", "android") } else { @($Target) }
        $core = Get-CoreExecutable
        $validator = "内置结构校验"
        if ($core) {
            $versionOutput = @(& $core version 2>&1)
            if ($LASTEXITCODE -ne 0) { throw "无法运行校验核心：$core" }
            $version = $versionOutput | Select-Object -First 1
            foreach ($name in $names) {
                & $core check -c (Join-Path $stage "$name\config.json")
                if ($LASTEXITCODE -ne 0) { throw "$name 配置未通过 sing-box 核心校验。" }
            }
            $validator = [string]$version
        } else {
            Write-Host "[提示] 未找到 sing-box CLI 核心，已完成生成器内置结构校验。可用 SING_BOX_CORE 指定核心路径。" -ForegroundColor Yellow
        }

        foreach ($name in $names) {
            $sourceConfig = Join-Path $stage "$name\config.json"
            $sourceStamp = Join-Path $stage "$name\config.validated.json"
            Write-ValidationStamp -ConfigPath $sourceConfig -StampPath $sourceStamp -Validator $validator
            Publish-File -Source $sourceConfig -Destination (Join-Path $OutputRoot "$name\config.json")
            Publish-File -Source $sourceStamp -Destination (Join-Path $OutputRoot "$name\config.validated.json")
            Write-Host "[完成] $name 配置已校验并发布。" -ForegroundColor Green
        }
        return $true
    } finally {
        if ($stage.StartsWith($RuntimeRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-Publisher {
    param([string[]]$Extra = @())
    Invoke-Python -Arguments (@("-m", "singbox_config.publisher") + $Extra) | Out-Host
}

function ConvertTo-SafeFileStem {
    param([Parameter(Mandatory)][string]$Value)
    $stem = [Regex]::Replace($Value.Trim(), '[\\/:*?"<>|\r\n]+', '_')
    $stem = [Regex]::Replace($stem, '\s+', ' ').Trim(' ', '.')
    if (-not $stem) { $stem = "node" }
    if ($stem.Length -gt 80) { $stem = $stem.Substring(0, 80).Trim() }
    return $stem
}

function Get-LinkFormat {
    param([Parameter(Mandatory)][string]$Value)
    $trimmed = $Value.Trim()
    if ($trimmed -match '(?i)^(ss|ssr|vmess|vless|trojan|hysteria2|hy2|tuic|anytls)://') {
        return @{ Format = "uri"; Source = "file"; Content = $trimmed }
    }
    if ($trimmed -notmatch '^https?://') {
        throw "链接必须是 HTTP(S) 订阅地址或支持的单节点 URI。"
    }
    $settings = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $ProjectRoot "config\policy.yaml")
    $timeout = 20
    if ($settings -match 'timeout_seconds:\s*(\d+)') { $timeout = [int]$Matches[1] }
    try {
        $response = Invoke-WebRequest -Uri $trimmed -UseBasicParsing -TimeoutSec $timeout -Headers @{ 'User-Agent' = 'sing-box' }
    } catch {
        throw "无法读取订阅以判断格式：$($_.Exception.Message)"
    }
    $content = [string]$response.Content
    $body = $content.Trim()
    if ($body.StartsWith('{')) {
        try {
            $json = $body | ConvertFrom-Json
            if ($null -ne $json.outbounds) { return @{ Format = "sing-box-json"; Source = "url_file"; Content = $trimmed } }
        } catch {}
    }
    if ($body -match '(?m)^\s*proxies\s*:') {
        return @{ Format = "clash"; Source = "url_file"; Content = $trimmed }
    }
    if ($body -match '(?im)^\s*(ss|ssr|vmess|vless|trojan|hysteria2|hy2|tuic|anytls)://') {
        return @{ Format = "uri"; Source = "url_file"; Content = $trimmed }
    }
    throw "无法识别订阅格式；支持 sing-box JSON、Clash YAML 或 URI 列表。"
}

function Invoke-QuickAdd {
    param([string]$ProvidedName, [string]$ProvidedLink, [string]$ProvidedFormat = "auto")
    $nameValue = if ($ProvidedName) { $ProvidedName.Trim() } else { (Read-Host "节点/订阅名称").Trim() }
    $linkValue = if ($ProvidedLink) { $ProvidedLink.Trim() } else { (Read-Host "单节点 URI 或订阅链接").Trim() }
    if (-not $nameValue) { throw "名称不能为空。" }
    if (-not $linkValue) { throw "链接不能为空。" }
    $quotedName = [Regex]::Escape($nameValue)
    $localRoot = Join-Path $ProjectRoot "config\local"
    $subRoot = Join-Path $localRoot "subscriptions"
    [IO.Directory]::CreateDirectory($subRoot) | Out-Null
    if (-not (Test-Path -LiteralPath $Subscriptions -PathType Leaf)) {
        $example = Join-Path $ProjectRoot "config\examples\subscriptions.yaml"
        if (-not (Test-Path -LiteralPath $example -PathType Leaf)) {
            throw "找不到订阅清单模板：$example"
        }
        Copy-Item -LiteralPath $example -Destination $Subscriptions
    }
    $existingManifest = Get-Content -Raw -Encoding UTF8 -LiteralPath $Subscriptions
    $namePattern = '(?m)^\s*-\s+name:.*' + $quotedName
    if ($existingManifest -match $namePattern) {
        throw "名称 [$nameValue] 已存在，请换一个名称。"
    }
    if ($ProvidedFormat -and $ProvidedFormat -ne "auto") {
        if ($ProvidedFormat -eq "uri" -and $linkValue -notmatch '(?i)^(ss|ssr|vmess|vless|trojan|hysteria2|hy2|tuic|anytls)://') {
            throw "Format=uri 时链接必须是支持的单节点 URI。"
        }
        $detected = @{ Format = $ProvidedFormat; Source = if ($linkValue -match '^https?://') { "url_file" } else { "file" }; Content = $linkValue }
    } else {
        $detected = Get-LinkFormat -Value $linkValue
    }

    $stem = ConvertTo-SafeFileStem -Value $nameValue
    $suffix = if ($detected.Source -eq "url_file") { ".url.txt" } else { ".txt" }
    $relative = "subscriptions/$stem$suffix"
    $path = Join-Path $localRoot ($relative -replace '/', '\\')
    if (Test-Path -LiteralPath $path) {
        $path = Join-Path $subRoot ((ConvertTo-SafeFileStem -Value ("{0}-{1}" -f $nameValue, (Get-Date -Format "yyyyMMdd-HHmmss"))) + $suffix)
        $relative = "subscriptions/" + (Split-Path -Leaf $path)
    }
    [IO.File]::WriteAllText($path, $detected.Content + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))

    $manifestText = $existingManifest
    $escapedName = $nameValue.Replace("'", "''")
    $escapedFormat = $detected.Format
    $block = @"

  - name: '$escapedName'
    enabled: true
    format: $escapedFormat
    source: $($detected.Source)
    path: $relative
    user_agent: sing-box
    group: '$escapedName'
    prefix_node_tags: false
    node_tag: '$escapedName'
    order: 60
    ai: auto
    urltest: true
"@
    try {
        [IO.File]::WriteAllText($Subscriptions, $manifestText.TrimEnd() + $block + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
        Write-Host "[完成] 已添加“$nameValue”（$($detected.Format)，$($detected.Source)）。" -ForegroundColor Green
        Write-Host "[提示] 正在更新桌面和安卓配置；订阅类链接会在每次更新时重新拉取。" -ForegroundColor DarkGray
        return Invoke-Generate -Target "all"
    } catch {
        [IO.File]::WriteAllText($Subscriptions, $manifestText, [Text.UTF8Encoding]::new($false))
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Invoke-Maintenance {
 param([string]$Mode, [string]$SelectedName)
 $text=Get-Content -Raw -Encoding UTF8 $Subscriptions
 $rx = '(?ms)^  - name:\s*(?<raw>.+?)\s*$.*?(?=^  - name:|\z)'
 $manifestItems = [Regex]::Matches($text, $rx)
 $name = if ($SelectedName) { $SelectedName } else { (Read-Host "订阅/节点名称").Trim() }
 $m = $manifestItems | Where-Object {
   $candidate = $_.Groups['raw'].Value.Trim()
   if ($candidate.Length -ge 2 -and $candidate[0] -eq "'" -and $candidate[$candidate.Length - 1] -eq "'") { $candidate = $candidate.Substring(1, $candidate.Length - 2).Replace("''", "'") }
   elseif ($candidate.Length -ge 2 -and $candidate[0] -eq '"' -and $candidate[$candidate.Length - 1] -eq '"') { $candidate = $candidate.Substring(1, $candidate.Length - 2) }
   $candidate -eq $name
 } | Select-Object -First 1
 if(-not $m){throw "找不到订阅或节点：$name"}
 if($Mode -eq 'remove'){
   $pathMatch=[Regex]::Match($m.Value,'(?m)^\s+path:\s*(.+?)\s*$')
   $enabledCount=0
   foreach($entry in $manifestItems){if($entry.Value -notmatch '(?m)^\s+enabled:\s*false\s*$'){$enabledCount++}}
   if($enabledCount -le 1 -and $m.Value -notmatch '(?m)^\s+enabled:\s*false\s*$'){throw "不能删除最后一个启用的节点或订阅。"}
   $originalText=$text; $text=$text.Remove($m.Index,$m.Length).TrimEnd()+[Environment]::NewLine
   try {
     [IO.File]::WriteAllText($Subscriptions,$text,(New-Object Text.UTF8Encoding($false)))
     [void](Invoke-Generate -Target all)
   } catch {
     [IO.File]::WriteAllText($Subscriptions,$originalText,(New-Object Text.UTF8Encoding($false))); throw
   }
   if($pathMatch.Success){
     $localRoot=[IO.Path]::GetFullPath((Split-Path $Subscriptions)); $itemPath=[IO.Path]::GetFullPath((Join-Path $localRoot ($pathMatch.Groups[1].Value.Trim().Trim('"''') -replace '/', '\\')))
     if($itemPath.StartsWith($localRoot + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){Remove-Item -LiteralPath $itemPath -Force -ErrorAction SilentlyContinue}
   }
   Write-Host "[完成] 已删除“$name”。"; return $true
 }
 $enabled=if($Mode -eq 'enable'){'true'}else{'false'}
 if($Mode -eq 'disable'){
   $enabledCount=0
   foreach($entry in $manifestItems){if($entry.Groups['raw'].Value.Trim() -ne $m.Groups['raw'].Value.Trim() -and $entry.Value -notmatch '(?m)^\s+enabled:\s*false\s*$'){$enabledCount++}}
   if($m.Value -notmatch '(?m)^\s+enabled:\s*false\s*$' -and $enabledCount -eq 0){throw "不能禁用最后一个启用的节点或订阅。"}
 }
 $block=[Regex]::Replace($m.Value,'(?m)^(\s+enabled:\s*)\S+','$1'+$enabled); $originalText=$text; $text=$text.Remove($m.Index,$m.Length).Insert($m.Index,$block)
 try {
   [IO.File]::WriteAllText($Subscriptions,$text,(New-Object Text.UTF8Encoding($false)))
   [void](Invoke-Generate -Target all)
 } catch {
   [IO.File]::WriteAllText($Subscriptions,$originalText,(New-Object Text.UTF8Encoding($false))); throw
 }
 Write-Host "[完成] 已更新“$name”。"; return $true
}

function Show-MaintenanceMenu {
 $text=Get-Content -Raw -Encoding UTF8 $Subscriptions
 $rx='(?ms)^  - name:\s*(?<raw>.+?)\s*$.*?(?=^  - name:|\z)'; $items=@([Regex]::Matches($text,$rx))
 if($items.Count -eq 0){throw "订阅清单中没有可维护的节点或订阅。"}
 $entries = @(foreach($item in $items){$candidate=$item.Groups['raw'].Value.Trim(); if($candidate.Length -ge 2 -and $candidate[0] -eq "'" -and $candidate[$candidate.Length - 1] -eq "'"){$candidate=$candidate.Substring(1,$candidate.Length-2).Replace("''", "'")} elseif($candidate.Length -ge 2 -and $candidate[0] -eq '"' -and $candidate[$candidate.Length - 1] -eq '"'){$candidate=$candidate.Substring(1,$candidate.Length-2)}; [pscustomobject]@{Name=$candidate; Kind=if($item.Value -match '(?m)^\s+format:\s*uri\s*$'){'单节点'}else{'订阅'}; Enabled=($item.Value -notmatch '(?m)^\s+enabled:\s*false\s*$')} })
 while($true){ Write-Host "`n--- 删除/禁用维护 ---"; for($i=0;$i -lt $entries.Count;$i++){$state=if($entries[$i].Enabled){'启用'}else{'禁用'}; Write-Host ("[{0}] {1}（{2}，{3}）" -f ($i+1),$entries[$i].Name,$entries[$i].Kind,$state)}; Write-Host "[q] 返回"; $choice=(Read-Host "请选择条目").Trim(); if($choice -eq 'q'){return}; $n=0; if([int]::TryParse($choice,[ref]$n) -and $n -ge 1 -and $n -le $entries.Count){$name=$entries[$n-1].Name; $op=(Read-Host "对 [$name] 执行：1 删除  2 禁用  3 启用  q 返回").Trim(); if($op -in @('1','2','3')){Invoke-Maintenance -Mode (@{'1'='remove';'2'='disable';'3'='enable'}[$op]) -SelectedName $name; return}} else {Write-Host '无效选项。' -ForegroundColor Yellow}}
}

function Get-PolicyDirectTag {
    $policyPath = Join-Path $ProjectRoot "config\policy.yaml"
    if (-not (Test-Path -LiteralPath $policyPath -PathType Leaf)) { return "direct" }
    $settings = Get-Content -Raw -Encoding UTF8 -LiteralPath $policyPath
    if ($settings -match '(?m)^\s*direct:\s*([^\r\n#]+)') {
        $value = $Matches[1].Trim().Trim('"''')
        if ($value) { return $value }
    }
    return "direct"
}

function ConvertTo-Punycode {
    param([string]$Value)
    try { return [Uri]::new("https://" + $Value).IdnHost } catch { return $Value }
}

function Confirm-DomainValue {
    param([string]$Value, [string]$Kind)
    $value = $Value.Trim().TrimEnd('.').ToLowerInvariant()
    if ($value -match '^\*\.') { $value = $value.Substring(2) }
    $ascii = ConvertTo-Punycode -Value $value
    if ($ascii -notmatch '^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+$') {
        throw "域名格式无效：$Value。请粘贴完整链接（如 https://platform.deepseek.com/usage）或输入纯域名（如 deepseek.com）。"
    }
    if ($Kind -eq 'suffix' -and $ascii -notmatch '\.') {
        throw "后缀匹配至少需要一个点号：$Value。请使用完整域名，或改用 domain: 进行精确匹配。"
    }
    return $ascii
}

function Confirm-IpCidr {
    param([string]$Value)
    $value = $Value.Trim().Trim('[', ']')
    if ($value -match '^(\d{1,3}(\.\d{1,3}){3})(/(\d{1,2}))?$') {
        $ip = $Matches[1]
        foreach ($octet in $ip.Split('.')) {
            if ([int]$octet -gt 255) { throw "无效的 IPv4 地址：$Value" }
        }
        if ($Matches[4]) {
            $bits = [int]$Matches[4]
            if ($bits -gt 32) { throw "IPv4 前缀长度不能超过 32：$Value" }
            return "$ip/$bits"
        }
        return "$ip/32"
    }
    if ($value -match ':') {
        $parts = $value.Split('/', 2)
        try { [void][System.Net.IPAddress]::Parse($parts[0]) } catch { throw "无效的 IPv6 地址：$Value" }
        if ($parts.Count -eq 2) {
            $bits = 0
            if (-not [int]::TryParse($parts[1], [ref]$bits) -or $bits -lt 0 -or $bits -gt 128) {
                throw "无效的 IPv6 前缀长度：$Value"
            }
            return "$($parts[0])/$bits"
        }
        return "$($parts[0])/128"
    }
    throw "无法识别 IP 或网段：$Value"
}

function Get-RuleHost {
    param([string]$Value)
    $raw = $Value.Trim()
    # scheme://user:pass@host[:port]/path
    if ($raw -match '^(?i)(https?|ftp|socks[45]?)://(.+)$') {
        $rest = $Matches[2]
        if ($rest -match '^[^@]+@') { $rest = $rest.Substring($rest.IndexOf('@') + 1) }
        if ($rest -match '^\[([^\]]+)\]') { return $Matches[1] }
        $rest = ($rest -split '[/?#]')[0]
        if ($rest -match '^(.+):\d+$') { $rest = $Matches[1] }
        return $rest.Trim()
    }
    # schemeless input: strip userinfo, brackets, then path/query/fragment and port
    $hostname = $raw
    if ($hostname -match '^[^@]+@') { $hostname = $hostname.Substring($hostname.IndexOf('@') + 1) }
    if ($hostname -match '^\[([^\]]+)\]') { return $Matches[1] }
    # Keep IP and CIDR literals intact; a slash here is a prefix length, not a path.
    if ($hostname -match '^[0-9.]+(/\d{1,2})?$' -or ($hostname -match '^[0-9a-fA-F:]+(/\d{1,3})?$' -and $hostname -match ':')) {
        return $hostname.Trim()
    }
    $hostname = ($hostname -split '[/?#]')[0]
    if ($hostname -match '^(.+):\d+$') { $hostname = $Matches[1] }
    if ($hostname -match '^\*\.') { $hostname = $hostname.Substring(2) }
    return $hostname.Trim()
}

function ConvertTo-RouteMatcher {
    param([Parameter(Mandatory)][string]$Value)
    $raw = $Value.Trim()
    if (-not $raw) { throw "匹配内容不能为空。" }
    if ($raw -match '^[A-Za-z_]+:') {
        $colon = $raw.IndexOf(':')
        $prefix = $raw.Substring(0, $colon).ToLowerInvariant()
        $payload = $raw.Substring($colon + 1).Trim()
        switch ($prefix) {
            "suffix" { return "domain_suffix:" + (Confirm-DomainValue -Value $payload -Kind suffix) }
            "domain_suffix" { return "domain_suffix:" + (Confirm-DomainValue -Value $payload -Kind suffix) }
            "domain" { return "domain:" + (Confirm-DomainValue -Value $payload -Kind exact) }
            "full" { return "domain:" + (Confirm-DomainValue -Value $payload -Kind exact) }
            "keyword" {
                if (-not $payload) { throw "keyword: 后缺少关键词。" }
                return "domain_keyword:" + $payload
            }
            "regexp" { return Add-RegexMatcher -Payload $payload }
            "regex" { return Add-RegexMatcher -Payload $payload }
            "ip" { return "ip_cidr:" + (Confirm-IpCidr -Value $payload) }
            "cidr" { return "ip_cidr:" + (Confirm-IpCidr -Value $payload) }
        }
    }
    $hostname = Get-RuleHost -Value $raw
    if (-not $hostname) { throw "无法从输入中识别域名或 IP。" }
    if ($hostname -match '^[0-9.]+(/\d{1,2})?$' -or $hostname -match '^[0-9a-fA-F:]+(/\d{1,3})?$') {
        return "ip_cidr:" + (Confirm-IpCidr -Value $hostname)
    }
    return "domain_suffix:" + (Confirm-DomainValue -Value $hostname -Kind suffix)
}

function Add-RegexMatcher {
    param([string]$Payload)
    if (-not $Payload) { throw "regexp: 后缺少正则。" }
    try { [void][Regex]::new($Payload) } catch { throw "正则无效：$($_.Exception.Message)" }
    return "domain_regex:" + $Payload
}

function Split-RuleInput {
    param([Parameter(Mandatory)][string]$Value)
    $items = @($Value.Trim() -split '[\s,]+' | Where-Object { $_ })
    if ($items.Count -eq 0) { throw "未识别到任何内容。" }
    return $items
}

function Format-RouteMatcher {
    param([string]$Matcher)
    if ($Matcher -match '^domain_suffix:(.+)$') { return $Matches[1] }
    if ($Matcher -match '^domain:(.+)$') { return "full:$($Matches[1])" }
    if ($Matcher -match '^domain_keyword:(.+)$') { return "keyword:$($Matches[1])" }
    if ($Matcher -match '^domain_regex:(.+)$') { return "regexp:$($Matches[1])" }
    if ($Matcher -match '^ip_cidr:(.+)$') { return $Matches[1] }
    return $Matcher
}

function Get-RoutingGroupsData {
    $strategyTags = @(Get-PolicyStrategyTags)
    $directTag = Get-PolicyDirectTag
    if (-not (Test-Path -LiteralPath $RoutingGroups -PathType Leaf)) {
        $groups = @()
        foreach ($tag in $strategyTags) {
            $groups += [pscustomobject]@{ tag = $tag; outbounds = @(); domains = @() }
        }
        if ($directTag -and $directTag -notin $strategyTags) {
            $groups += [pscustomobject]@{ tag = $directTag; outbounds = @(); domains = @() }
        }
        return [pscustomobject]@{ schema_version = 1; groups = $groups }
    }
    try {
        $data = Get-Content -Raw -Encoding UTF8 -LiteralPath $RoutingGroups | ConvertFrom-Json
    } catch {
        throw "无法读取 routing-groups.json：$($_.Exception.Message)"
    }
    if ([int]$data.schema_version -ne 1) { throw "routing-groups.json schema_version 必须为 1。" }
    if ($null -eq $data.groups) { $data | Add-Member -NotePropertyName groups -NotePropertyValue @() -Force }
    # Everything in routing-groups.json is owned by this tool; policy-owned
    # strategy selectors and the direct outbound are kept visible so their
    # rule-only groups (empty outbounds) are not dropped.
    $groups = @($data.groups | Where-Object {
        $tag = [string]$_.tag
        ($tag -in $strategyTags) -or ($tag -eq $directTag) -or (@($_.outbounds).Count -gt 0) -or (@($_.domains).Count -gt 0)
    })
    $known = @($groups | ForEach-Object { [string]$_.tag })
    foreach ($tag in $strategyTags) {
        if ($tag -and $tag -notin $known) {
            $groups += [pscustomobject]@{ tag = $tag; outbounds = @(); domains = @() }
        }
    }
    if ($directTag -and $directTag -notin $known -and $directTag -notin $strategyTags) {
        $groups += [pscustomobject]@{ tag = $directTag; outbounds = @(); domains = @() }
    }
    $data.groups = $groups
    return $data
}

function Get-PolicyStrategyTags {
    $policyPath = Join-Path $ProjectRoot "config\policy.yaml"
    if (-not (Test-Path -LiteralPath $policyPath -PathType Leaf)) { return @() }
    $lines = Get-Content -Encoding UTF8 -LiteralPath $policyPath
    $inSelectors = $false
    $result = @()
    foreach ($line in $lines) {
        if ($line -match '^selectors:\s*$') { $inSelectors = $true; continue }
        if ($inSelectors -and $line -match '^\S') { break }
        if (-not $inSelectors) { continue }
        if ($line -match '^\s{2}(available|ai|emby|youtube):\s*(.+?)\s*$') {
            $value = $Matches[2].Trim().Trim('"''')
            if ($value -and $value -notin $result) { $result += $value }
        }
    }
    return @($result)
}

function Save-RoutingGroupsData {
    param([Parameter(Mandatory)]$Data)
    $parent = Split-Path -Parent $RoutingGroups
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    $json = $Data | ConvertTo-Json -Depth 8
    $temporary = $RoutingGroups + ".new-" + [Guid]::NewGuid().ToString("N")
    try {
        [IO.File]::WriteAllText($temporary, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $RoutingGroups -Force
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-RoutingGroupsUpdate {
    param([Parameter(Mandatory)]$Data)
    $existed = Test-Path -LiteralPath $RoutingGroups -PathType Leaf
    $original = if ($existed) { Get-Content -Raw -Encoding UTF8 -LiteralPath $RoutingGroups } else { $null }
    try {
        Save-RoutingGroupsData -Data $Data
        [void](Invoke-Generate -Target "all")
    } catch {
        if ($existed) {
            [IO.File]::WriteAllText($RoutingGroups, $original, [Text.UTF8Encoding]::new($false))
        } else {
            Remove-Item -LiteralPath $RoutingGroups -Force -ErrorAction SilentlyContinue
        }
        throw
    }
}

function Read-ListIndex {
    param(
        [Parameter(Mandatory)][array]$Items,
        [Parameter(Mandatory)][string]$Prompt,
        [scriptblock]$Label = { param($item) [string]$item }
    )
    for ($i = 0; $i -lt $Items.Count; $i++) {
        Write-Host ("[{0}] {1}" -f ($i + 1), (& $Label $Items[$i]))
    }
    Write-Host "[q] 返回"
    $choice = (Read-Host $Prompt).Trim().ToLowerInvariant()
    if ($choice -eq "q") { return -1 }
    $number = 0
    if (-not [int]::TryParse($choice, [ref]$number) -or $number -lt 1 -or $number -gt $Items.Count) {
        Write-Host "无效选项。" -ForegroundColor Yellow
        return -2
    }
    return $number - 1
}

function Get-ConfigOutboundItems {
    param([Parameter(Mandatory)][string]$Name)
    $configPath = Join-Path $OutputRoot "$Name\config.json"
    # PS 5.1 ConvertFrom-Json chokes on the large generated config; read the
    # outbound list through Python instead.
    $code = @'
import json, sys
with open(sys.argv[1], encoding='utf-8') as handle:
    data = json.load(handle)
print('\n'.join(o.get('tag', '') + '\t' + o.get('type', '') for o in data.get('outbounds', [])))
'@
    $output = @(Invoke-Python -Arguments @("-c", $code, $configPath))
    $result = @()
    foreach ($line in $output) {
        $parts = [string]$line -split "`t"
        if (-not $parts[0]) { continue }
        $result += [pscustomobject]@{ Tag = $parts[0]; Type = $parts[1] }
    }
    return $result
}

function Get-SelectableOutboundTags {
    $configPath = Join-Path $OutputRoot "desktop\config.json"
    Write-Host "[提示] 正在刷新桌面配置以读取当前可选出站。" -ForegroundColor DarkGray
    [void](Invoke-Generate -Target "desktop")
    $items = @(Get-ConfigOutboundItems -Name "desktop")
    # Exclude only user-managed selectors. Policy-owned selectors (Available,
    # AI, Emby, ...) remain valid members of a new strategy group.
    $managedTags = @((Get-RoutingGroupsData).groups | Where-Object { @($_.outbounds).Count -gt 0 } | ForEach-Object { [string]$_.tag })
    $strategyTags = @(Get-PolicyStrategyTags)
    return @($items | Where-Object {
        if (-not $_.Tag -or $_.Tag -in $managedTags) { return $false }
        # Hide subscription-generated selector/urltest groups while retaining
        # ordinary proxy nodes and policy strategy selectors as choices.
        if ($_.Type -in @('selector', 'urltest') -and $_.Tag -notin $strategyTags) { return $false }
        return $true
    } | ForEach-Object { $_.Tag })
}

function Add-RoutingGroup {
    $data = Get-RoutingGroupsData
    $tag = (Read-Host "新分组名称").Trim()
    if (-not $tag) { throw "分组名称不能为空。" }
    if ($tag -match '[\r\n]') { throw "分组名称不能包含换行。" }
    $allTags = @(Get-SelectableOutboundTags)
    $existingTags = @($data.groups | ForEach-Object { [string]$_.tag })
    if ($tag -in $allTags -or $tag -in $existingTags) { throw "名称 [$tag] 已被现有出站或分组使用。" }
    if ($allTags.Count -eq 0) { throw "当前没有可加入分组的出站。" }

    $selected = [Collections.Generic.List[string]]::new()
    while ($true) {
        Write-Host "`n--- 为 [$tag] 选择出站（可多选）---"
        for ($i = 0; $i -lt $allTags.Count; $i++) {
            $mark = if ($selected.Contains($allTags[$i])) { "x" } else { " " }
            Write-Host ("[{0}] [{1}] {2}" -f ($i + 1), $mark, $allTags[$i])
        }
        Write-Host "[0] 完成选择  [q] 返回"
        $choice = (Read-Host "输入序号切换选择").Trim().ToLowerInvariant()
        if ($choice -eq "q") { return }
        if ($choice -eq "0") {
            if ($selected.Count -eq 0) { Write-Host "请至少选择一个出站。" -ForegroundColor Yellow; continue }
            break
        }
        $number = 0
        if ([int]::TryParse($choice, [ref]$number) -and $number -ge 1 -and $number -le $allTags.Count) {
            $value = $allTags[$number - 1]
            if ($selected.Contains($value)) { [void]$selected.Remove($value) } else { $selected.Add($value) }
        } else {
            Write-Host "无效选项。" -ForegroundColor Yellow
        }
    }
    $groups = @($data.groups)
    $data.groups = @($groups + [pscustomobject]@{ tag = $tag; outbounds = @($selected); domains = @() })
    Invoke-RoutingGroupsUpdate -Data $data
    Write-Host "[完成] 已创建分组“$tag”。" -ForegroundColor Green
}

function Remove-RoutingGroup {
    $data = Get-RoutingGroupsData
    # Policy-owned selectors are not removable groups; only selectors created
    # through this menu (which carry explicit outbound members) can be deleted.
    $groups = @($data.groups | Where-Object { @($_.outbounds).Count -gt 0 })
    if ($groups.Count -eq 0) { Write-Host "暂无可删除的分组。" -ForegroundColor Yellow; return }
    $index = Read-ListIndex -Items $groups -Prompt "请选择要删除的分组" -Label { param($group) "$($group.tag)（$(@($group.domains).Count) 条分流规则）" }
    if ($index -lt 0) { return }
    $target = $groups[$index]
    $confirm = (Read-Host "删除 [$($target.tag)] 及其全部分流规则？输入 y 确认").Trim().ToLowerInvariant()
    if ($confirm -ne "y") { Write-Host "已取消。"; return }
    $data.groups = @($groups | Where-Object { $_ -ne $target })
    Invoke-RoutingGroupsUpdate -Data $data
    Write-Host "[完成] 已删除分组“$($target.tag)”。" -ForegroundColor Green
}

function Add-RoutingRule {
    $data = Get-RoutingGroupsData
    $groups = @($data.groups)
    if ($groups.Count -eq 0) { Write-Host "请先创建分组。" -ForegroundColor Yellow; return }
    $index = Read-ListIndex -Items $groups -Prompt "请选择规则所属分组" -Label { param($group) "$($group.tag)（$(@($group.domains).Count) 条规则）" }
    if ($index -lt 0) { return }
    $target = $groups[$index]
    $all = @($groups | ForEach-Object { @($_.domains) })
    $input = Read-Host "链接/域名/IP（如 https://platform.deepseek.com/usage、example.com、1.2.3.0/24、keyword:track；多个用空格或逗号分隔）"
    $added = @()
    $skipped = @()
    foreach ($item in (Split-RuleInput -Value $input)) {
        $matcher = ConvertTo-RouteMatcher -Value $item
        if ($all -contains $matcher) { $skipped += (Format-RouteMatcher -Matcher $matcher); continue }
        $target.domains += $matcher
        $all += $matcher
        $added += (Format-RouteMatcher -Matcher $matcher)
    }
    if ($added.Count -eq 0) { throw "没有新增规则：输入的内容都已存在。" }
    $data.groups = $groups
    Invoke-RoutingGroupsUpdate -Data $data
    Write-Host "[完成] 已将 $($added -join '、') 加入分组“$($target.tag)”。" -ForegroundColor Green
    if ($skipped.Count -gt 0) { Write-Host "[提示] 已存在，跳过：$($skipped -join '、')" -ForegroundColor DarkGray }
}

function Add-DirectRule {
    $data = Get-RoutingGroupsData
    $directTag = Get-PolicyDirectTag
    $group = @($data.groups | Where-Object { [string]$_.tag -eq $directTag } | Select-Object -First 1)
    if ($group.Count -eq 0) {
        $data.groups += [pscustomobject]@{ tag = $directTag; outbounds = @(); domains = @() }
        $group = @($data.groups | Where-Object { [string]$_.tag -eq $directTag } | Select-Object -First 1)
    }
    $target = $group[0]
    $all = @($data.groups | ForEach-Object { @($_.domains) })
    $input = Read-Host "要直连的链接/域名/IP（如 https://platform.deepseek.com/usage；多个用空格或逗号分隔）"
    $added = @()
    $skipped = @()
    foreach ($item in (Split-RuleInput -Value $input)) {
        $matcher = ConvertTo-RouteMatcher -Value $item
        if ($all -contains $matcher) { $skipped += (Format-RouteMatcher -Matcher $matcher); continue }
        $target.domains += $matcher
        $all += $matcher
        $added += (Format-RouteMatcher -Matcher $matcher)
    }
    if ($added.Count -eq 0) { throw "没有新增直连规则：输入的内容都已存在。" }
    Invoke-RoutingGroupsUpdate -Data $data
    Write-Host "[完成] 已添加直连规则：$($added -join '、')（DNS 走国内直连解析器）。" -ForegroundColor Green
    if ($skipped.Count -gt 0) { Write-Host "[提示] 已存在，跳过：$($skipped -join '、')" -ForegroundColor DarkGray }
}

function Remove-RoutingDomain {
    $data = Get-RoutingGroupsData
    $entries = @(
        foreach ($group in @($data.groups)) {
            foreach ($matcher in @($group.domains)) {
                [pscustomobject]@{ Group = $group; Matcher = [string]$matcher }
            }
        }
    )
    if ($entries.Count -eq 0) { Write-Host "暂无可删除的分流规则。" -ForegroundColor Yellow; return }
    $index = Read-ListIndex -Items $entries -Prompt "请选择要删除的分流规则" -Label { param($entry) "$(Format-RouteMatcher -Matcher $entry.Matcher) -> $($entry.Group.tag)" }
    if ($index -lt 0) { return }
    $target = $entries[$index]
    $target.Group | Add-Member -NotePropertyName domains -NotePropertyValue @($target.Group.domains | Where-Object { $_ -ne $target.Matcher }) -Force
    Invoke-RoutingGroupsUpdate -Data $data
    Write-Host "[完成] 已删除 $(Format-RouteMatcher -Matcher $target.Matcher) -> $($target.Group.tag)。" -ForegroundColor Green
}

function Show-RoutingGroups {
    $groups = @((Get-RoutingGroupsData).groups)
    Write-Host "`n--- 当前分组与分流规则 ---"
    if ($groups.Count -eq 0) { Write-Host "（暂无分组）"; return }
    for ($i = 0; $i -lt $groups.Count; $i++) {
        $group = $groups[$i]
        Write-Host ("[{0}] {1}" -f ($i + 1), $group.tag)
        if (@($group.outbounds).Count -gt 0) {
            Write-Host ("    出站：{0}" -f (@($group.outbounds) -join "、"))
        } else {
            Write-Host "    出站：（策略选择器 / 直连）"
        }
        $rules = @($group.domains)
        if ($rules.Count -eq 0) {
            Write-Host "    规则：（暂无）"
        } else {
            foreach ($rule in $rules) { Write-Host ("    - {0}" -f (Format-RouteMatcher -Matcher $rule)) }
        }
    }
}

function Show-RoutingGroupsMenu {
    while ($true) {
        Write-Host "`n--- 分组与分流规则 ---"
        Write-Host "[1] 增加分组"
        Write-Host "[2] 删除分组"
        Write-Host "[3] 增加分流规则（选择目标分组）"
        Write-Host "[4] 快速添加直连规则"
        Write-Host "[5] 删除分流规则"
        Write-Host "[6] 查看分组与规则"
        Write-Host "[q] 返回"
        $choice = (Read-Host "请选择").Trim().ToLowerInvariant()
        try {
            switch ($choice) {
                "1" { Add-RoutingGroup }
                "2" { Remove-RoutingGroup }
                "3" { Add-RoutingRule }
                "4" { Add-DirectRule }
                "5" { Remove-RoutingDomain }
                "6" { Show-RoutingGroups }
                "q" { return }
                default { Write-Host "无效选项。" -ForegroundColor Yellow }
            }
        } catch {
            Write-Host "[错误] $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}
function Test-PublishedConfig {
    param([string]$Name, [switch]$Quiet)
    $config = Join-Path $OutputRoot "$Name\config.json"
    $stamp = Join-Path $OutputRoot "$Name\config.validated.json"
    $ok = $true
    $message = ""
    if (-not (Test-Path -LiteralPath $config -PathType Leaf)) {
        $ok = $false; $message = "缺少 config.json"
    } elseif (-not (Test-Path -LiteralPath $stamp -PathType Leaf)) {
        $ok = $false; $message = "缺少 config.validated.json"
    } else {
        try {
            $metadata = Get-Content -LiteralPath $stamp -Raw -Encoding UTF8 | ConvertFrom-Json
            $actual = Get-Sha256Hex -Path $config
            if (-not $metadata.sha256 -or $actual -ine [string]$metadata.sha256) {
                $ok = $false; $message = "验证摘要不匹配"
            } else {
                $validatedBy = if ($metadata.validator) { $metadata.validator } elseif ($metadata.core) { $metadata.core } else { "摘要校验" }
                $message = "有效（$validatedBy）"
            }
        } catch {
            $ok = $false; $message = "验证文件损坏"
        }
    }
    if (-not $Quiet) {
        $color = if ($ok) { "Green" } else { "Red" }
        Write-Host ("{0,-8} {1}" -f $Name, $message) -ForegroundColor $color
    }
    return $ok
}

function Invoke-Check {
    $ok = $true
    $core = Get-CoreExecutable
    foreach ($name in @("desktop", "android")) {
        if (-not (Test-PublishedConfig -Name $name)) { $ok = $false; continue }
        if ($core) {
            & $core check -c (Join-Path $OutputRoot "$name\config.json")
            if ($LASTEXITCODE -ne 0) {
                Write-Host "核心校验失败：$name" -ForegroundColor Red
                $ok = $false
            } else {
                Write-Host "核心校验通过：$name" -ForegroundColor Green
            }
        }
    }
    if ($core) {
        Write-Host "核心校验：$core" -ForegroundColor DarkGray
    } else {
        Write-Host "未找到 sing-box 核心，仅完成摘要校验。" -ForegroundColor Yellow
    }
    return $ok
}

function Show-Menu {
    Write-Host ""
    Write-Host "================ sing-box 配置与发布 ================"
    Write-Host "  配置维护"
    Write-Host "    [1] 更新桌面配置"
    Write-Host "    [2] 更新安卓配置"
    Write-Host "    [3] 更新两端配置"
    Write-Host "    [4] 检查已发布配置"
    Write-Host "    [5] 快速添加节点/订阅"
    Write-Host "    [6] 删除/禁用节点或订阅"
    Write-Host "    [7] 分组与分流规则"
    Write-Host ""
    Write-Host "  配置发布"
    Write-Host "    [8] 启动发布（每次都会显示地址和凭据）"
    Write-Host "    [9] 查看发布地址和凭据"
    Write-Host "    [10] 轮换凭据并显示新发布信息"
    Write-Host "  [q] 退出"
    Write-Host "====================================================="
}

function Invoke-Action {
    param([string]$ActionName)
    switch ($ActionName) {
        "desktop"            { return Invoke-Generate -Target "desktop" }
        "android"            { return Invoke-Generate -Target "android" }
        "all"                { return Invoke-Generate -Target "all" }
        "quick-add"          { return Invoke-QuickAdd -ProvidedName $Name -ProvidedLink $Link -ProvidedFormat $Format }
        "remove"            { return Invoke-Maintenance -Mode remove -SelectedName $Name }
        "delete"            { return Invoke-Maintenance -Mode remove -SelectedName $Name }
        "disable"           { return Invoke-Maintenance -Mode disable -SelectedName $Name }
        "enable"            { return Invoke-Maintenance -Mode enable -SelectedName $Name }
        "publisher"          { Invoke-Publisher; return $true }
        "check"              { return Invoke-Check }
        "show-info"          { Invoke-Publisher -Extra @("--show-info"); return $true }
        "rotate-credentials" { Invoke-Publisher -Extra @("--rotate-credentials"); return $true }
    }
}

try {
    if ($Action -ne "menu") {
        if (-not (Invoke-Action -ActionName $Action)) { exit 1 }
        exit 0
    }
    while ($true) {
        Show-Menu
        $choice = (Read-Host "请选择").Trim().ToLowerInvariant()
        if ($choice -eq "q") { break }
        try {
            switch ($choice) {
                "1" { [void](Invoke-Generate -Target "desktop") }
                "2" { [void](Invoke-Generate -Target "android") }
                "3" { [void](Invoke-Generate -Target "all") }
                "4" { [void](Invoke-Check) }
                "5" { [void](Invoke-QuickAdd) }
                "6" { Show-MaintenanceMenu }
                "7" { Show-RoutingGroupsMenu }
                "8" { Invoke-Publisher }
                "9" { Invoke-Publisher -Extra @("--show-info") }
                "10" { Invoke-Publisher -Extra @("--rotate-credentials") }
                ""  { }
                default { Write-Host "无效选项：$choice" -ForegroundColor Yellow }
            }
        } catch {
            Write-Host "[错误] $($_.Exception.Message)" -ForegroundColor Red
        }
        if ($choice -ne "8") { [void](Read-Host "按回车返回菜单") }
    }
} catch {
    Write-Host "[错误] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
