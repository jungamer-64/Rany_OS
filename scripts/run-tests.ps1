#!/usr/bin/env pwsh
<#
.SYNOPSIS
    QEMU-first test entrypoint.
.DESCRIPTION
    Runs the QEMU-first orchestration crate (`qemu-tests`) through `cargo test`.
    This is a thin wrapper so local usage and CI usage stay identical.
#>

[CmdletBinding()]
param(
    [string[]]$CargoArgs = @()
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Join-Path $PSScriptRoot ".."
Push-Location $root
try {
    Write-Host "Running QEMU-first test suites via cargo test..." -ForegroundColor Cyan
    $args = @("test") + $CargoArgs
    & cargo @args
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
