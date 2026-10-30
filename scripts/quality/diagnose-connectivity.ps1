[CmdletBinding()]
param(
    [ValidateRange(1, 360)][int]$Samples = 6,
    [ValidateRange(1, 300)][int]$IntervalSeconds = 10,
    [string]$ReportRoot,
    [string]$CurlExecutable = "curl.exe"
)

# Bounded, read-only probes. Never restart the client, switch nodes or flush caches.
$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
if (-not $ReportRoot) { $ReportRoot = Join-Path $projectRoot ("runtime\connectivity-" + (Get-Date -Format "yyyyMMdd-HHmmss-fff")) }
function Invoke-ConnectivityProbe {
    param([string]$Executable, [string[]]$Arguments)
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $Executable
    $start.Arguments = (($Arguments | ForEach-Object {
        '"' + [regex]::Replace([regex]::Replace($_, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
    }) -join " ")
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    try {
        [void]$process.Start()
        # Native stderr is data, not a terminating PowerShell 5.1 error record.
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(10000)) {
            $process.Kill()
            $process.WaitForExit()
            return [pscustomobject]@{ exit_code = -1; result = ""; error = "Probe process exceeded 10 seconds" }
        }
        return [pscustomobject]@{
            exit_code = $process.ExitCode
            result = $stdoutTask.GetAwaiter().GetResult().Trim()
            error = $stderrTask.GetAwaiter().GetResult().Trim()
        }
    } catch {
        return [pscustomobject]@{ exit_code = -1; result = ""; error = $_.Exception.Message }
    } finally { $process.Dispose() }
}
New-Item -ItemType Directory -Path $reportRoot -ErrorAction Stop | Out-Null
$reportFile = Join-Path $reportRoot "samples.jsonl"
& ipconfig.exe /all | Out-File -LiteralPath (Join-Path $reportRoot "ipconfig.txt") -Encoding utf8
& route.exe print | Out-File -LiteralPath (Join-Path $reportRoot "routes.txt") -Encoding utf8
Write-Host "system 使用系统路由，不显式指定代理；未验证流量是否进入 TUN。探针失败会记录并继续，脚本不会切节点或修复网络。"

$previousCpu = @{}
$previousTime = Get-Date
$logicalCpus = [Math]::Max(1, [Environment]::ProcessorCount)
for ($sample = 0; $sample -lt $Samples; $sample++) {
    $sampleTime = Get-Date
    $elapsed = ($sampleTime - $previousTime).TotalSeconds
    $nextCpu = @{}
    $cpuRows = @(foreach ($process in Get-Process -ErrorAction SilentlyContinue) {
        if ($null -eq $process.CPU -or $process.Id -eq 0) { continue }
        $key = "{0}:{1}" -f $process.Id, $process.ProcessName
        $nextCpu[$key] = $process.CPU
        if ($previousCpu.ContainsKey($key) -and $elapsed -gt 0) {
            [pscustomobject]@{
                name = $process.ProcessName
                pid = $process.Id
                cpu_percent = [Math]::Round([Math]::Max([double]0, [double](($process.CPU - $previousCpu[$key]) / $elapsed / $logicalCpus * 100)), 2)
                working_set_bytes = $process.WorkingSet64
            }
        }
    })
    $previousCpu = $nextCpu
    $previousTime = $sampleTime
    $probes = @(foreach ($path in @("system", "mixed")) {
        foreach ($target in @("https://www.baidu.com", "https://www.gstatic.com/generate_204")) {
            $curlArguments = @("--disable", "--connect-timeout", "4", "--max-time", "6", "-sS", "-o", "NUL", "-w", "%{http_code}|%{remote_ip}|%{time_total}")
            if ($path -eq "mixed") { $curlArguments += @("--noproxy", "no-bypass.invalid", "--proxy", "http://127.0.0.1:7890") }
            else { $curlArguments += @("--noproxy", "*") }
            $probe = Invoke-ConnectivityProbe -Executable $CurlExecutable -Arguments ($curlArguments + $target)
            [pscustomobject]@{ path = $path; target = $target; exit_code = $probe.exit_code; result = $probe.result; error = $probe.error; tun_verified = $false }
        }
    })
    [pscustomobject]@{
        timestamp = $sampleTime.ToString("o")
        cpu_top = @($cpuRows | Sort-Object cpu_percent -Descending | Select-Object -First 8)
        sing_box = @($cpuRows | Where-Object name -Match "sing-box")
        probes = $probes
    } | ConvertTo-Json -Depth 5 -Compress | Add-Content -LiteralPath $reportFile -Encoding utf8
    Write-Host ("Sample {0}/{1}: {2}" -f ($sample + 1), $Samples, $reportFile)
    if ($sample + 1 -lt $Samples) { Start-Sleep -Seconds $IntervalSeconds }
}
Write-Host "Report: $reportRoot"
