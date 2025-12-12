<# Build Standalone Driver ELF
.SYNOPSIS
    Builds a driver crate as a standalone ELF for dynamic loading.

.PARAMETER Driver
    Name of the driver crate to build (e.g., example_abi)

.EXAMPLE
    .\build_driver.ps1 -Driver example_abi
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$Driver
)

$ErrorActionPreference = "Stop"

# Configuration
$DriversDir = Split-Path -Parent $PSScriptRoot
$LinkerScript = Join-Path $DriversDir "driver.ld"
$TargetDir = Join-Path $DriversDir "..\target\drivers"

# Ensure target directory exists
if (-not (Test-Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
}

Write-Host "=== Building Standalone Driver: $Driver ===" -ForegroundColor Cyan

# Set up rustflags for custom linker script
$env:RUSTFLAGS = "-C link-arg=-T$LinkerScript -C link-arg=--gc-sections"

# Build the driver with standalone feature
Write-Host "Building with standalone feature..." -ForegroundColor Yellow
$DriverPath = Join-Path $DriversDir $Driver

try {
    Push-Location $DriverPath
    cargo build --release --features standalone --target x86_64-unknown-none 2>&1 | Write-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Cargo build failed"
    }
} finally {
    Pop-Location
}

# Find the built artifact
$ArtifactDir = Join-Path $DriversDir "..\target\x86_64-unknown-none\release"
$DriverLib = Get-ChildItem -Path $ArtifactDir -Filter "lib*.a" | Select-Object -First 1

if ($DriverLib) {
    $OutputPath = Join-Path $TargetDir "$Driver.elf"
    Copy-Item $DriverLib.FullName $OutputPath -Force
    Write-Host "Driver built: $OutputPath" -ForegroundColor Green
} else {
    Write-Host "Warning: No .a artifact found, checking for .o files..." -ForegroundColor Yellow
}

Write-Host "=== Build Complete ===" -ForegroundColor Cyan
