#!/usr/bin/env pwsh
$ErrorActionPreference = "Stop"
$root = Join-Path $PSScriptRoot ".."
$script = Join-Path $PSScriptRoot "verify_qemu_test_only.sh"

if (-not (Test-Path $script)) {
    Write-Error "verify_qemu_test_only.sh not found"
    exit 1
}

Push-Location $root
try {
    bash $script
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
