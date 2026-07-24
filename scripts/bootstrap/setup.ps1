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
$ProjectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
Set-Location -LiteralPath $ProjectRoot

$CoreVersion = "1.14.0-beta.1"
$CoreExecutableHash = "44B66EF3A88F6B8FA2A92607CEF3BD5F4BCFED2C945111730B3F33A9BFCDA101"
$CronetHash = "C7434CFA93C3041321DD19111C4DE6C52B8A9531A65661BA45425D3C51EC69E2"
$ServiceVersion = "2.12.0"
$ServiceHash = "05B82D46AD331CC16BDC00DE5C6332C1EF818DF8CEEFCD49C726553209B3A0DA"
$LocalConfigDirectory = Join-Path $ProjectRoot "config\local"
$CoreDirectory = Join-Path $ProjectRoot "runtime\cores\$CoreVersion"
$DownloadDirectory = Join-Path $ProjectRoot "runtime\downloads"
$ServiceDirectory = Join-Path $ProjectRoot "runtime\services"
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$ServiceExe = Join-Path $ServiceDirectory "singbox-service.exe"
$TrafficServiceExe = Join-Path $ServiceDirectory "singbox-traffic-service.exe"

function Get-Sha256Hash {
    param([string]$Path)

    $stream = [IO.File]::OpenRead($Path)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return (($sha256.ComputeHash($stream) | ForEach-Object { $_.ToString("X2") }) -join "")
    } finally {
        $sha256.Dispose()
        $stream.Dispose()
    }
}

function Test-FileHash {
    param([string]$Path, [string]$ExpectedHash)
    return (Test-Path -LiteralPath $Path -PathType Leaf) -and
        ((Get-Sha256Hash -Path $Path) -eq $ExpectedHash)
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
        throw "Python 3.10+ is required. Install Python, then run scripts\bootstrap\setup.bat again."
    }

    Write-Host "Python was not found; installing Python 3.12 for the current user..."
    & $winget.Source install --id Python.Python.3.12 -e --source winget --scope user --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) {
        throw "Python installation failed with exit code $LASTEXITCODE."
    }

    $installed = Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"
    if (-not (Test-Path -LiteralPath $installed)) {
        throw "Python was installed but could not be located. Open a new terminal and run scripts\bootstrap\setup.bat again."
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

function Move-LegacyLocalPath {
    param([string]$Source, [string]$Destination)

    if ((Test-Path -LiteralPath $Source) -and -not (Test-Path -LiteralPath $Destination)) {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Destination) | Out-Null
        Move-Item -LiteralPath $Source -Destination $Destination
        Write-Host "Migrated local file: $Source"
    }
}

function Invoke-ElevatedWinSW {
    param([string]$Executable, [string]$Action)

    $process = Start-Process -FilePath $Executable -ArgumentList $Action `
        -WorkingDirectory $ProjectRoot -Verb RunAs -WindowStyle Hidden -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Windows service action '$Action' failed with exit code $($process.ExitCode)."
    }
}

function Test-ServiceUsesExecutable {
    param([string]$Name, [string]$Executable)

    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
    return $service -and $service.PathName.IndexOf($Executable, [StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Wait-ServiceStopped {
    param([string]$Name, [int]$TimeoutSeconds = 30)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if (-not $service -or $service.Status -eq "Stopped") {
            return
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    throw "Service '$Name' did not stop within $TimeoutSeconds seconds."
}

function Wait-ServiceRemoved {
    param([string]$Name, [int]$TimeoutSeconds = 30)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        if (-not (Get-Service -Name $Name -ErrorAction SilentlyContinue)) {
            return
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    throw "Service '$Name' was not removed within $TimeoutSeconds seconds."
}

function Ensure-WindowsService {
    param([string]$Name, [string]$Executable)

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($service -and -not (Test-ServiceUsesExecutable -Name $Name -Executable $Executable)) {
        Write-Host "Migrating $Name to the organized runtime directory..."
        if ($service.Status -ne "Stopped") {
            Invoke-ElevatedWinSW -Executable $Executable -Action "stop"
            Wait-ServiceStopped -Name $Name
        }
        Invoke-ElevatedWinSW -Executable $Executable -Action "uninstall"
        Wait-ServiceRemoved -Name $Name
        $service = $null
    }
    Invoke-ElevatedWinSW -Executable $Executable -Action $(if ($service) { "restart" } else { "install" })
    if (-not $service) {
        Invoke-ElevatedWinSW -Executable $Executable -Action "start"
    }
}

$LocalSubscriptionManifest = Join-Path $LocalConfigDirectory "subscriptions.yaml"
Move-LegacyLocalPath -Source (Join-Path $ProjectRoot "subscriptions.yaml") -Destination $LocalSubscriptionManifest
Move-LegacyLocalPath -Source (Join-Path $ProjectRoot "policy_aliases.yaml") -Destination (Join-Path $LocalConfigDirectory "policy_aliases.yaml")
# Prefer the versioned 1.14 template directory; ignore root template.json leftovers.
Move-LegacyLocalPath -Source (Join-Path $ProjectRoot "templates") -Destination (Join-Path $LocalConfigDirectory "templates")
if (
    (Test-Path -LiteralPath (Join-Path $ProjectRoot "template.json")) -and
    -not (Test-Path -LiteralPath (Join-Path $LocalConfigDirectory "templates\desktop-windows-sing-box-1.14.json"))
) {
    New-Item -ItemType Directory -Force -Path (Join-Path $LocalConfigDirectory "templates") | Out-Null
    Move-LegacyLocalPath `
        -Source (Join-Path $ProjectRoot "template.json") `
        -Destination (Join-Path $LocalConfigDirectory "templates\desktop-windows-sing-box-1.14.json")
}
Move-LegacyLocalPath -Source (Join-Path $ProjectRoot "subscriptions") -Destination (Join-Path $LocalConfigDirectory "subscriptions")

Write-Host "=== sing-box private setup ==="
if (-not (Test-Path -LiteralPath $LocalSubscriptionManifest)) {
    $SubscriptionUrl = (Read-Host "Paste the subscription URL (stored locally and ignored by Git)").Trim()
    $parsedUrl = $null
    if (-not [Uri]::TryCreate($SubscriptionUrl, [UriKind]::Absolute, [ref]$parsedUrl) -or
        $parsedUrl.Scheme -notin @("http", "https")) {
        throw "The subscription URL must be an absolute HTTP or HTTPS URL."
    }

    $SubscriptionDirectory = Join-Path $LocalConfigDirectory "subscriptions"
    New-Item -ItemType Directory -Force -Path $SubscriptionDirectory | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $SubscriptionDirectory "provider.txt"),
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
    [IO.File]::WriteAllText($LocalSubscriptionManifest, $manifest, [Text.UTF8Encoding]::new($false))
    $SubscriptionUrl = $null
} else {
    Write-Host "Reusing existing local subscription settings."
}

Write-Host "=== Preparing Python environment ==="
$pythonCommand = Find-Python
if (-not (Test-Path -LiteralPath $VenvPython)) {
    Invoke-Python -CommandPrefix $pythonCommand -Arguments @("-m", "venv", (Join-Path $ProjectRoot ".venv"))
}
& $VenvPython -m pip install --disable-pip-version-check -r (Join-Path $ProjectRoot "requirements.lock")
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

$serviceUrl = "https://github.com/winsw/winsw/releases/download/v$ServiceVersion/WinSW-x64.exe"
Get-VerifiedFile -Url $serviceUrl -Destination $ServiceExe -ExpectedHash $ServiceHash
New-Item -ItemType Directory -Force -Path $ServiceDirectory | Out-Null
Copy-Item -LiteralPath (Join-Path $ProjectRoot "config\services\singbox-service.xml") `
    -Destination (Join-Path $ServiceDirectory "singbox-service.xml") -Force
if (-not (Test-FileHash -Path $TrafficServiceExe -ExpectedHash $ServiceHash)) {
    Copy-Item -LiteralPath $ServiceExe -Destination $TrafficServiceExe -Force
}
Copy-Item -LiteralPath (Join-Path $ProjectRoot "config\services\singbox-traffic-service.xml") `
    -Destination (Join-Path $ServiceDirectory "singbox-traffic-service.xml") -Force

Write-Host "=== Generating and checking configurations ==="
$generatorArguments = @((Join-Path $ProjectRoot "scripts\config\generate_config.py"), "all")
if ($FetchProxy) {
    $generatorArguments += @("--fetch-proxy", $FetchProxy)
}
& $VenvPython @generatorArguments
if ($LASTEXITCODE -ne 0) {
    throw "Configuration generation failed. The subscription must include all required regions listed in README.md."
}
& $coreExe check -c (Join-Path $ProjectRoot "dist\desktop\config.json")
if ($LASTEXITCODE -ne 0) {
    throw "sing-box rejected the generated desktop configuration."
}

if (-not $SkipService) {
    Write-Host "=== Installing Windows service (administrator approval required) ==="
    Ensure-WindowsService -Name "sing-box" -Executable $ServiceExe

    Write-Host "=== Installing traffic attribution service ==="
    Ensure-WindowsService -Name "sing-box-traffic" -Executable $TrafficServiceExe
}

Write-Host ""
Write-Host "Setup complete. Desktop proxy: 127.0.0.1:7890; live dashboard: http://127.0.0.1:9090; traffic attribution: http://127.0.0.1:9091"
Write-Host "Use scripts\manage\manage.bat for future subscription refreshes."
