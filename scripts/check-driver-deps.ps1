#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Check driver dependencies to ensure drivers don't depend on the kernel crate.
.DESCRIPTION
    This script scans all Cargo.toml files under drivers/* and validates that:
    - Drivers do NOT depend on the 'kernel' crate
    - Drivers SHOULD have a dependency on 'kernel_api' (optional warning)

    Exits with non-zero code if violations are found.
#>

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root\.. | Out-Null

$drivers = Get-ChildItem -Path "drivers" -Directory 2>$null

if (-not $drivers) {
    Write-Output "No drivers directory found; nothing to check."
    Pop-Location | Out-Null
    exit 0
}

$foundViolation = $false
$foundWarnings = @()

foreach ($driver in $drivers) {
    $cargoPath = Join-Path $driver.FullName 'Cargo.toml'

    if (-not (Test-Path $cargoPath)) {
        Write-Output "[$($driver.Name)] - No Cargo.toml found"
        continue
    }

    $content = Get-Content $cargoPath -Raw

    # Check for kernel dependency in a dependency table entry (exact match)
    # Use regex to avoid matching kernel_api
    if ($content -match '(^|\n)\s*kernel\s*=') {
        Write-Output "ERROR: [$($driver.Name)] Cargo.toml depends on 'kernel' crate. Drivers must not depend on kernel."
        $foundViolation = $true
    }

    # Warn if kernel_api is missing
    if (-not ($content -match '(^|\n)\s*kernel_api\s*=')) {
        $foundWarnings += "[$($driver.Name)] Cargo.toml does not depend on 'kernel_api' (recommended)."
    }

}

if ($foundWarnings.Count -gt 0) {
    Write-Output ""
    Write-Output "Warnings:"
    foreach ($w in $foundWarnings) {
        Write-Output $w
    }
}

if ($foundViolation) {
    Write-Output ""
    Write-Output "One or more drivers depend on 'kernel' crate. Fix them by depending on 'kernel_api' instead."
    Pop-Location | Out-Null
    exit 1
}

Write-Output "All drivers satisfy dependency policy."
Pop-Location | Out-Null
exit 0
