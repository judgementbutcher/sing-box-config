[CmdletBinding()]
param(
    [ValidateSet("clash", "singbox-json", "uri")]
    [string]$Parser = "clash",
    [string]$FetchProxy,
    [switch]$SkipService,
    [switch]$NonInteractive
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
Set-Location -LiteralPath $PSScriptRoot

$CoreVersion = "1.14.0-alpha.41"
$CoreExecutableHash = "C68FDB0FBB8A8CEC1A9ED563469D2A5884EDEC7A5989B261DFB2B93D038B4146"
$CronetHash = "C7434CFA93C3041321DD19111C4DE6C52B8A9531A65661BA45425D3C51EC69E2"
$ServiceVersion = "2.12.0"
$ServiceHash = "05B82D46AD331CC16BDC00DE5C6332C1EF818DF8CEEFCD49C726553209B3A0DA"
$CoreDirectory = Join-Path $PSScriptRoot "cores\$CoreVersion"
$DownloadDirectory = Join-Path $PSScriptRoot "runtime\downloads"
$VenvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"

function Test-FileHash {
    param([string]$Path, [string]$ExpectedHash)
    return (Test-Path -LiteralPath $Path -PathType Leaf) -and
        ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -eq $ExpectedHash)
}

function Get-VerifiedFile {
    param([string]$Url, [string]$Destination, [string]$ExpectedHash)

    if (Test-FileHash -Path $Destination -ExpectedHash $ExpectedHash) {
        return
    }

    $parent = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $partial = "$Destination.part"
    Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
    Write-Host "Downloading $Url"
    Invoke-WebRequest -Uri $Url -OutFile $partial -UseBasicParsing
    if (-not (Test-FileHash -Path $partial -ExpectedHash $ExpectedHash)) {
        Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
        throw "SHA-256 verification failed for $Url"
    }
    Move-Item -LiteralPath $partial -Destination $Destination -Force
}

function Find-Python {
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) {
        return @($launcher.Source, "-3")
    }

    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($python) {
        return @($python.Source)
    }

    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $winget) {
        throw "Python 3.10+ is required. Install Python, then run setup.bat again."
    }

    Write-Host "Python was not found; installing Python 3.12 for the current user..."
    & $winget.Source install --id Python.Python.3.12 -e --source winget --scope user --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) {
        throw "Python installation failed with exit code $LASTEXITCODE."
    }

    $installed = Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"
    if (-not (Test-Path -LiteralPath $installed)) {
        throw "Python was installed but could not be located. Open a new terminal and run setup.bat again."
    }
    return @($installed)
}

function Invoke-Python {
    param([string[]]$CommandPrefix, [string[]]$Arguments)
    $executable = $CommandPrefix[0]
    $prefixArguments = @($CommandPrefix | Select-Object -Skip 1)
    & $executable @prefixArguments @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Python command failed with exit code $LASTEXITCODE."
    }
}

Write-Host "=== sing-box private setup ==="
$SubscriptionUrl = Read-Host "Paste the subscription URL (stored locally and ignored by Git)"
$SubscriptionUrl = $SubscriptionUrl.Trim()
$parsedUrl = $null
if (-not [Uri]::TryCreate($SubscriptionUrl, [UriKind]::Absolute, [ref]$parsedUrl) -or
    $parsedUrl.Scheme -notin @("http", "https")) {
    throw "The subscription URL must be an absolute HTTP or HTTPS URL."
}

New-Item -ItemType Directory -Force -Path (Join-Path $PSScriptRoot "subscriptions") | Out-Null
[IO.File]::WriteAllText(
    (Join-Path $PSScriptRoot "subscriptions\provider.txt"),
    $SubscriptionUrl,
    [Text.UTF8Encoding]::new($false)
)
$manifest = @"
subscriptions:
  - name: provider
    parser: $Parser
    source: url_file
    path: subscriptions/provider.txt
"@
[IO.File]::WriteAllText(
    (Join-Path $PSScriptRoot "subscriptions.yaml"),
    $manifest,
    [Text.UTF8Encoding]::new($false)
)
$SubscriptionUrl = $null

Write-Host "=== Preparing Python environment ==="
$pythonCommand = Find-Python
if (-not (Test-Path -LiteralPath $VenvPython)) {
    Invoke-Python -CommandPrefix $pythonCommand -Arguments @("-m", "venv", (Join-Path $PSScriptRoot ".venv"))
}
& $VenvPython -m pip install --disable-pip-version-check -r (Join-Path $PSScriptRoot "requirements.lock")
if ($LASTEXITCODE -ne 0) {
    throw "Dependency installation failed with exit code $LASTEXITCODE."
}

Write-Host "=== Installing verified sing-box runtime ==="
New-Item -ItemType Directory -Force -Path $DownloadDirectory | Out-Null
$archive = Join-Path $DownloadDirectory "sing-box-$CoreVersion-windows-amd64.zip"
$archiveUrl = "https://github.com/SagerNet/sing-box/releases/download/v$CoreVersion/sing-box-$CoreVersion-windows-amd64.zip"
$coreExe = Join-Path $CoreDirectory "sing-box.exe"
$cronetDll = Join-Path $CoreDirectory "libcronet.dll"
if (-not (Test-FileHash $coreExe $CoreExecutableHash) -or -not (Test-FileHash $cronetDll $CronetHash)) {
    Invoke-WebRequest -Uri $archiveUrl -OutFile $archive -UseBasicParsing
    $extractDirectory = Join-Path $DownloadDirectory "sing-box-$CoreVersion"
    Remove-Item -LiteralPath $extractDirectory -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive -LiteralPath $archive -DestinationPath $extractDirectory -Force
    $extractedExe = Get-ChildItem -LiteralPath $extractDirectory -Filter "sing-box.exe" -File -Recurse | Select-Object -First 1
    $extractedDll = Get-ChildItem -LiteralPath $extractDirectory -Filter "libcronet.dll" -File -Recurse | Select-Object -First 1
    if (-not $extractedExe -or -not $extractedDll -or
        -not (Test-FileHash $extractedExe.FullName $CoreExecutableHash) -or
        -not (Test-FileHash $extractedDll.FullName $CronetHash)) {
        throw "Downloaded sing-box files failed SHA-256 verification."
    }
    New-Item -ItemType Directory -Force -Path $CoreDirectory | Out-Null
    Copy-Item -LiteralPath $extractedExe.FullName -Destination $coreExe -Force
    Copy-Item -LiteralPath $extractedDll.FullName -Destination $cronetDll -Force
}

$serviceExe = Join-Path $PSScriptRoot "singbox-service.exe"
$serviceUrl = "https://github.com/winsw/winsw/releases/download/v$ServiceVersion/WinSW-x64.exe"
Get-VerifiedFile -Url $serviceUrl -Destination $serviceExe -ExpectedHash $ServiceHash

Write-Host "=== Generating and checking configurations ==="
$generatorArguments = @((Join-Path $PSScriptRoot "generate_config.py"), "all")
if ($FetchProxy) {
    $generatorArguments += @("--fetch-proxy", $FetchProxy)
}
& $VenvPython @generatorArguments
if ($LASTEXITCODE -ne 0) {
    throw "Configuration generation failed. The subscription must include all required regions listed in README.md."
}
& $coreExe check -c (Join-Path $PSScriptRoot "dist\desktop\config.json")
if ($LASTEXITCODE -ne 0) {
    throw "sing-box rejected the generated desktop configuration."
}

if (-not $SkipService) {
    Write-Host "=== Installing Windows service (administrator approval required) ==="
    $service = Get-Service -Name "sing-box" -ErrorAction SilentlyContinue
    $action = if ($service) { "restart" } else { "install" }
    $process = Start-Process -FilePath $serviceExe -ArgumentList $action -WorkingDirectory $PSScriptRoot -Verb RunAs -WindowStyle Hidden -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Windows service action '$action' failed with exit code $($process.ExitCode)."
    }
    if (-not $service) {
        $process = Start-Process -FilePath $serviceExe -ArgumentList "start" -WorkingDirectory $PSScriptRoot -Verb RunAs -WindowStyle Hidden -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "Windows service start failed with exit code $($process.ExitCode)."
        }
    }
}

Write-Host ""
Write-Host "Setup complete. Desktop proxy: 127.0.0.1:7890; dashboard: http://127.0.0.1:9090"
Write-Host "Use reload.bat for future subscription refreshes."
