[CmdletBinding()]
param([switch]$Offline, [switch]$NonInteractive, [switch]$Help)
$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
Set-Location -LiteralPath $ProjectRoot
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch {}
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = "1"
if ($Help) {
  Write-Host "用法：setup.bat [-Offline] [-NonInteractive]"
  Write-Host "在线：检查 Python 3.10+、订阅清单与固定核心，建立虚拟环境、安装依赖，然后生成配置。"
  Write-Host "离线：仅检查已有 .venv 和锁定依赖，不创建环境、不联网安装；复用有效订阅缓存与完整规则快照。"
  Write-Host "请先准备 config\local\subscriptions.yaml 与 runtime\cores\1.15.0-alpha.11-reF1nd\ 下的 CLI 核心（或 SING_BOX_CORE）。"
  Write-Host "不会自动下载核心、覆盖订阅清单、修改防火墙或客户端；-NonInteractive 不暂停。"
  exit 0
}
try {
$venv = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$pythonArgs = @()
if (Test-Path -LiteralPath $venv -PathType Leaf) { $python = $venv }
elseif ($Offline) { throw "离线安装需要已有 .venv；未创建或修改环境。请先在线准备环境。" }
else {
  $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
  $command = Get-Command python.exe -ErrorAction SilentlyContinue
  if ($launcher) { $python = $launcher.Source; $pythonArgs = @("-3") }
  elseif ($command) { $python = $command.Source }
  else { throw "未找到 Python；请先安装 Python 3.10 或更高版本。" }
}
& $python @pythonArgs -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if ($LASTEXITCODE -ne 0) { throw "需要 Python 3.10 或更高版本；未开始安装或生成。" }
if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot "config\local\subscriptions.yaml") -PathType Leaf)) {
  throw "请先创建 config\local\subscriptions.yaml（可参考 config\examples\subscriptions.yaml）。"
}
$core = $env:SING_BOX_CORE
if (-not $core) {
  $coreDirectory = Join-Path $ProjectRoot "runtime\cores\1.15.0-alpha.11-reF1nd"
  $candidate = Get-ChildItem -LiteralPath $coreDirectory -Filter "sing-box.exe" -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($candidate) { $core = $candidate.FullName }
}
if (-not $core -or -not (Test-Path -LiteralPath $core -PathType Leaf)) { throw "未找到固定 CLI 核心。请准备 runtime\cores\1.15.0-alpha.11-reF1nd 或设置 SING_BOX_CORE；不会自动下载。" }
$coreVersion = (& $core version | Out-String)
if ($LASTEXITCODE -ne 0 -or $coreVersion -notmatch 'sing-box version 1\.15\.0-alpha\.11-reF1nd(?:\s|$)') {
  throw "校验核心版本不符或不是有效 CLI：需要 1.15.0-alpha.11-reF1nd。未安装依赖或生成配置。"
}
if ($Offline) {
  & $venv -c "import importlib.metadata as m, pathlib, sys; lines=pathlib.Path(sys.argv[1]).read_text().splitlines(); missing=[line for line in lines if line.strip() and not line.lstrip().startswith('#') and m.version(line.split('==')[0]) != line.split('==')[1]]; sys.exit(bool(missing))" (Join-Path $ProjectRoot "requirements.lock")
  if ($LASTEXITCODE -ne 0) { throw "离线环境依赖缺失或不匹配 requirements.lock；未联网安装，请先在线准备依赖。" }
} else {
  if (-not (Test-Path -LiteralPath $venv -PathType Leaf)) {
    & $python @pythonArgs -m venv (Join-Path $ProjectRoot ".venv")
    if ($LASTEXITCODE -ne 0) { throw "虚拟环境创建失败；未安装依赖或生成配置。" }
  }
  & $venv -m pip install --disable-pip-version-check -r (Join-Path $ProjectRoot "requirements.lock")
  if ($LASTEXITCODE -ne 0) { throw "Python 依赖安装失败；未生成配置。" }
}
$manageArgs = @("-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts\manage\manage.ps1", "-Action", "all")
if ($Offline) { $manageArgs += "-Offline" }
if ($NonInteractive) { $manageArgs += "-NonInteractive" }
& powershell.exe @manageArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "完成：已生成并校验 dist\desktop 和 dist\android 配置。Windows 核心请在 SFW 中管理。"
} catch {
  Write-Host "[错误] $($_.Exception.Message)" -ForegroundColor Red
  exit 1
}
