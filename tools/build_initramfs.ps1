# build_initramfs.ps1 - Initramfs TAR Archive Builder
# Creates initramfs.tar containing driver Cell files for dynamic loading

param(
    [string]$OutputPath = "target/initramfs.tar",
    [string]$CellsDir = "target/cells",
    [switch]$Release = $false
)

$ErrorActionPreference = "Stop"

Write-Host "=== ExoRust Initramfs Builder ===" -ForegroundColor Cyan

# Determine build profile
$Profile = if ($Release) { "release" } else { "debug" }
Write-Host "Profile: $Profile"

# Create cells directory if it doesn't exist
if (-not (Test-Path $CellsDir)) {
    New-Item -ItemType Directory -Path $CellsDir -Force | Out-Null
    Write-Host "Created directory: $CellsDir"
}

# List of drivers to build as Cells (add more as needed)
$Drivers = @(
    @{ Name = "nvme_driver"; Output = "nvme.cell" }
    # Add more drivers here:
    # @{ Name = "hid_driver"; Output = "hid.cell" }
)

$BuiltCells = @()

foreach ($Driver in $Drivers) {
    Write-Host "`nBuilding $($Driver.Name) as standalone Cell..." -ForegroundColor Yellow
    
    # Temporarily modify Cargo.toml to enable cdylib
    $CargoPath = "drivers/$($Driver.Name -replace '_driver', '')/Cargo.toml"
    if (-not (Test-Path $CargoPath)) {
        $CargoPath = "drivers/$($Driver.Name)/Cargo.toml"
    }
    
    if (-not (Test-Path $CargoPath)) {
        Write-Warning "Cargo.toml not found for $($Driver.Name), skipping"
        continue
    }
    
    # Read original content
    $Original = Get-Content $CargoPath -Raw
    
    # Replace crate-type to cdylib for standalone build
    $Modified = $Original -replace 'crate-type = \["rlib"\]', 'crate-type = ["cdylib"]'
    
    try {
        # Write modified content
        Set-Content $CargoPath -Value $Modified
        
        # Build with standalone feature
        $BuildArgs = @("build", "--package", $Driver.Name, "--features", "standalone")
        if ($Release) {
            $BuildArgs += "--release"
        }
        
        Write-Host "cargo $($BuildArgs -join ' ')"
        & cargo @BuildArgs
        
        if ($LASTEXITCODE -eq 0) {
            # Find the built .dll/.so file
            $LibPath = "target/$Profile/$($Driver.Name).dll"
            if (-not (Test-Path $LibPath)) {
                $LibPath = "target/$Profile/lib$($Driver.Name).so"
            }
            if (-not (Test-Path $LibPath)) {
                $LibPath = "target/$Profile/$($Driver.Name).so"
            }
            
            if (Test-Path $LibPath) {
                $CellPath = Join-Path $CellsDir $Driver.Output
                Copy-Item $LibPath $CellPath -Force
                $BuiltCells += $Driver.Output
                Write-Host "Created: $CellPath" -ForegroundColor Green
            } else {
                Write-Warning "Built library not found for $($Driver.Name)"
            }
        } else {
            Write-Warning "Build failed for $($Driver.Name)"
        }
    } finally {
        # Restore original Cargo.toml
        Set-Content $CargoPath -Value $Original
    }
}

# Create TAR archive
if ($BuiltCells.Count -gt 0) {
    Write-Host "`nCreating initramfs.tar..." -ForegroundColor Yellow
    
    # Use tar command (available on Windows 10+)
    Push-Location $CellsDir
    try {
        $CellFiles = $BuiltCells -join " "
        & tar -cvf "../initramfs.tar" $BuiltCells
        
        if ($LASTEXITCODE -eq 0) {
            $TarPath = Join-Path (Split-Path $CellsDir -Parent) "initramfs.tar"
            Write-Host "`nSuccess! Created: $TarPath" -ForegroundColor Green
            Write-Host "Contents:"
            & tar -tvf "../initramfs.tar"
            
            # Copy to target root for easy access
            Copy-Item "../initramfs.tar" $OutputPath -Force
            Write-Host "`nCopied to: $OutputPath"
        }
    } finally {
        Pop-Location
    }
} else {
    Write-Host "`nNo Cells were built." -ForegroundColor Yellow
}

Write-Host "`n=== Build Complete ===" -ForegroundColor Cyan
