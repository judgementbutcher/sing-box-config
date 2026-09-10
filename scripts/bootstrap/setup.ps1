[CmdletBinding()]
param([switch]$Offline)
$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $ProjectRoot
$python = Get-Command python.exe -ErrorAction Stop
$venv = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $venv)) { & $python.Source -m venv (Join-Path $ProjectRoot ".venv") }
& $venv -m pip install --disable-pip-version-check -r (Join-Path $ProjectRoot "requirements.lock")
if ($LASTEXITCODE -ne 0) { throw "Python dependency installation failed." }
if (-not (Test-Path (Join-Path $ProjectRoot "config\local\subscriptions.yaml"))) {
  throw "请先创建 config\local\subscriptions.yaml（可参考 config\examples\subscriptions.yaml）。"
}
$manageArgs = @("-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts\manage\manage.ps1", "-Action", "all")
if ($Offline) { $manageArgs += "-Offline" }
& powershell.exe @manageArgs
if ($LASTEXITCODE -ne 0) { throw "Configuration generation or validation failed." }
Write-Host "完成：已生成并校验 dist\desktop 和 dist\android 配置。Windows 核心请在 SFW 中管理。"
