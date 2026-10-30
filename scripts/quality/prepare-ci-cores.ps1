[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"
if ($env:CI -ne "true") { throw "This downloader is for CI only; local setup never downloads a core automatically." }
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
# Archive digests: GitHub expanded_assets for the exact reF1nd release tags.
$cores = @(
    @{ Version = "1.15.0-alpha.11-reF1nd"; Archive = "be4b77554beab8a6dca2a2903ce398b4868ee618224de54118de9714b670bb89"; Binary = "43d22471b87e9caf10b8c3505526ccdbeaa7b403ea77e9fbb676270e5e29e7ee" },
    @{ Version = "1.15.0-alpha.13-reF1nd"; Archive = "b7174dde2bba6706f8d643ffa7bdab4ec6dac373d6688ffb4c265dae51dfd097"; Binary = "e6829fe2daa7740094d8066a2d31896f3de34cf57128b0f342ece44ac618c738" }
)
foreach ($core in $cores) {
    $name = "sing-box-$($core.Version)-windows-amd64"
    $directory = Join-Path $root "runtime\cores\$($core.Version)"
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $archive = Join-Path $directory "$name.zip"
    Invoke-WebRequest -Uri "https://github.com/reF1nd/sing-box-releases/releases/download/v$($core.Version)/$name.zip" -OutFile $archive -UseBasicParsing
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $core.Archive) { throw "Core archive digest mismatch: $name" }
    Expand-Archive -LiteralPath $archive -DestinationPath $directory -Force
    $binary = Join-Path $directory "$name\sing-box.exe"
    if ((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash -ne $core.Binary) { throw "Core binary digest mismatch: $name" }
    $version = @(& $binary version)
    if ($LASTEXITCODE -ne 0 -or $version.Count -eq 0 -or $version[0].Trim() -ne "sing-box version $($core.Version)") {
        throw "Core version mismatch: $name"
    }
    Write-Host "Verified core: $($core.Version)"
}
