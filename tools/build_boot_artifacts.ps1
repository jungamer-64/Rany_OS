# build_boot_artifacts.ps1 - Runtime boot artifact builder
# Produces boot partition `/drivers/*.cell` and `/cells/*.cell` payloads.

param(
    [ValidateSet("debug", "release")]
    [string]$Profile = "debug"
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$ScriptPath = Join-Path $RepoRoot "scripts/build_runtime_boot_artifacts.sh"
$OutputRoot = Join-Path $RepoRoot "target/x86_64-exorust/$Profile/boot_artifacts"

Write-Output "=== ExoRust Boot Artifact Builder ==="
Write-Output "Profile: $Profile"

if (-not (Test-Path $ScriptPath)) {
    throw "Missing runtime boot artifact builder: $ScriptPath"
}

$Bash = Get-Command bash -ErrorAction SilentlyContinue
if (-not $Bash) {
    throw "bash was not found in PATH. Install Git Bash or WSL to run $ScriptPath."
}

Push-Location $RepoRoot
try {
    & $Bash.Source $ScriptPath --profile $Profile
    if ($LASTEXITCODE -ne 0) {
        throw "Boot artifact build failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

if (-not (Test-Path $OutputRoot)) {
    throw "Expected boot artifact output was not created: $OutputRoot"
}

Write-Output "Output:"
Write-Output "  $OutputRoot/drivers"
Write-Output "  $OutputRoot/cells"
Write-Output "=== Build Complete ==="
