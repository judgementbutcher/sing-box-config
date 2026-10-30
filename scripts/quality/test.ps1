[CmdletBinding()]
param([string[]]$PytestArgs = @())

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$ExitCode = 1
$EnvironmentBefore = @{}
$LocationChanged = $false

try {
    foreach ($argument in $PytestArgs) {
        $option = ($argument -split "=", 2)[0]
        $reservedLong = @("--basetemp", "--override-ini", "--cache-clear", "--cache-show")
        $blocked = $argument -match '^-[op]'
        foreach ($reserved in $reservedLong) {
            if ($option.Length -ge 3 -and $reserved.StartsWith($option, [StringComparison]::Ordinal)) { $blocked = $true }
        }
        if ($blocked) {
            $ExitCode = 2
            throw "PytestArgs cannot override temporary directories, configuration options, plugins or caching: $argument"
        }
    }

    $Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
        $Command = Get-Command python.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $Command) { throw "Python was not found. Prepare the project environment first; this script does not install dependencies." }
        $Python = $Command.Source
    }

    $RuntimeRoot = Join-Path $ProjectRoot "runtime"
    $TestRoot = Join-Path $RuntimeRoot "tests"
    foreach ($directory in @($RuntimeRoot, $TestRoot)) {
        if (Test-Path -LiteralPath $directory) {
            $item = Get-Item -LiteralPath $directory -Force
            if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw "The test artifact parent must be an ordinary directory: $directory"
            }
        }
    }
    $RunName = "run-{0}-{1}" -f (Get-Date -Format "yyyyMMdd-HHmmss-fff"), [Guid]::NewGuid().ToString("N")
    $RunRoot = [IO.Path]::GetFullPath((Join-Path $TestRoot $RunName))
    $ExpectedParent = [IO.Path]::GetFullPath($TestRoot).TrimEnd('\') + '\'
    if (-not $RunRoot.StartsWith($ExpectedParent, [StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $RunRoot)) {
        throw "Refusing to reuse or escape the test artifact directory."
    }
    New-Item -ItemType Directory -Path $TestRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $RunRoot | Out-Null

    $Environment = @{
        PYTHONDONTWRITEBYTECODE = "1"
        PYTHONUTF8 = "1"
        PYTEST_ADDOPTS = ""
        PYTEST_PLUGINS = ""
    }
    foreach ($name in $Environment.Keys) {
        $EnvironmentBefore[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
        [Environment]::SetEnvironmentVariable($name, $Environment[$name], "Process")
    }
    Push-Location -LiteralPath $ProjectRoot
    $LocationChanged = $true
    Write-Host "Test artifacts: $RunRoot"
    # Ignore external addopts so they cannot replace the owned temporary root.
    $Arguments = @("-B", "-u", "-m", "pytest", "-o", "addopts=", "-p", "no:cacheprovider", "--basetemp=$RunRoot") + $PytestArgs
    # Direct native argv preserves quotes under Windows PowerShell 5.1; no shell.
    $Start = New-Object System.Diagnostics.ProcessStartInfo
    $Start.FileName = $Python
    $Start.Arguments = (($Arguments | ForEach-Object {
        '"' + [regex]::Replace([regex]::Replace($_, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
    }) -join " ")
    $Start.WorkingDirectory = $ProjectRoot
    $Start.UseShellExecute = $false
    $Start.CreateNoWindow = $true
    $Start.RedirectStandardOutput = $true
    $Start.RedirectStandardError = $true
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $Start
    $Started = $false
    try {
        [void]$Process.Start()
        $Started = $true
        $Stdout = [Console]::OpenStandardOutput()
        $Stderr = [Console]::OpenStandardError()
        $OutTask = $Process.StandardOutput.BaseStream.CopyToAsync($Stdout)
        $ErrorTask = $Process.StandardError.BaseStream.CopyToAsync($Stderr)
        $Process.WaitForExit()
        [void]$OutTask.GetAwaiter().GetResult()
        [void]$ErrorTask.GetAwaiter().GetResult()
        $Stdout.Flush()
        $Stderr.Flush()
        $ExitCode = $Process.ExitCode
    } finally {
        if ($Started -and -not $Process.HasExited) {
            try { $Process.Kill(); $Process.WaitForExit() } catch {}
        }
        $Process.Dispose()
    }
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
} finally {
    if ($LocationChanged) { Pop-Location }
    foreach ($name in $EnvironmentBefore.Keys) {
        [Environment]::SetEnvironmentVariable($name, $EnvironmentBefore[$name], "Process")
    }
}

exit $ExitCode
