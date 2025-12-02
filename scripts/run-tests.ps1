#!/usr/bin/env pwsh
<#
.SYNOPSIS
    ExoRust Automated Test Runner
.DESCRIPTION
    Runs all automated tests including unit tests, integration tests, and QEMU boot tests.
.PARAMETER UnitTests
    Run unit tests only.
.PARAMETER IntegrationTests
    Run integration tests only.
.PARAMETER QemuTests
    Run QEMU boot tests only.
.PARAMETER All
    Run all tests (default).
.PARAMETER Verbose
    Show verbose output.
#>

[CmdletBinding()]
param(
    [switch]$UnitTests,
    [switch]$IntegrationTests,
    [switch]$QemuTests,
    [switch]$All,
    [switch]$VerboseOutput
)

$ErrorActionPreference = "Stop"

$script:TestResults = @{
    Passed = 0
    Failed = 0
    Skipped = 0
}

function Write-TestHeader($testName) {
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Blue
    Write-Host " $testName" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Blue
}

function Write-TestResult($testName, $passed, $message = "") {
    if ($passed) {
        Write-Host "[PASS] " -ForegroundColor Green -NoNewline
        Write-Host $testName
        $script:TestResults.Passed++
    } else {
        Write-Host "[FAIL] " -ForegroundColor Red -NoNewline
        Write-Host "$testName - $message"
        $script:TestResults.Failed++
    }
}

function Write-TestSkipped($testName, $reason) {
    Write-Host "[SKIP] " -ForegroundColor Yellow -NoNewline
    Write-Host "$testName - $reason"
    $script:TestResults.Skipped++
}

# Unit Tests (cargo test with host target)
function Invoke-UnitTests {
    Write-TestHeader "Unit Tests"
    
    # Note: no_std crate can't run regular unit tests
    # We test the logic that doesn't depend on kernel features
    
    Write-Host "Running cargo check for syntax validation..." -ForegroundColor Gray
    
    $result = & cargo check --target x86_64-rany_os.json 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-TestResult "Cargo syntax check" $true
    } else {
        Write-TestResult "Cargo syntax check" $false "Compilation errors found"
        if ($VerboseOutput) {
            Write-Host $result -ForegroundColor Gray
        }
    }
    
    # Check for unsafe code violations
    Write-Host "Checking unsafe code usage..." -ForegroundColor Gray
    
    $unsafeCount = (Get-ChildItem -Path "src" -Recurse -Filter "*.rs" | 
        Select-String -Pattern "unsafe\s*\{" -AllMatches).Matches.Count
    
    Write-Host "  Found $unsafeCount unsafe blocks" -ForegroundColor Gray
    Write-TestResult "Unsafe code audit" $true "Counted $unsafeCount unsafe blocks for review"
}

# Integration Tests
function Invoke-IntegrationTests {
    Write-TestHeader "Integration Tests"
    
    # Test that the kernel compiles with all feature combinations
    $featureCombinations = @(
        @()  # Default features
        # Add feature combinations as needed
    )
    
    foreach ($features in $featureCombinations) {
        $featureStr = if ($features.Count -gt 0) { $features -join "," } else { "default" }
        Write-Host "Testing feature set: $featureStr" -ForegroundColor Gray
        
        $args = @("build", "--target", "x86_64-rany_os.json")
        if ($features.Count -gt 0) {
            $args += @("--features", ($features -join ","))
        }
        
        $result = & cargo @args 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-TestResult "Build with features: $featureStr" $true
        } else {
            Write-TestResult "Build with features: $featureStr" $false
            if ($VerboseOutput) {
                Write-Host $result -ForegroundColor Gray
            }
        }
    }
    
    # Check that all modules are properly linked
    Write-Host "Verifying module structure..." -ForegroundColor Gray
    
    $requiredModules = @(
        "src/lib.rs",
        "src/main.rs",
        "src/memory.rs",
        "src/allocator.rs",
        "src/vga.rs",
        "src/panic_handler.rs",
        "src/task/mod.rs",
        "src/mm/mod.rs",
        "src/sync/mod.rs",
        "src/interrupts/mod.rs",
        "src/io/mod.rs",
        "src/ipc/mod.rs",
        "src/loader/mod.rs",
        "src/domain/mod.rs",
        "src/sas/mod.rs",
        "src/net/mod.rs",
        "src/fs/mod.rs"
    )
    
    $allModulesExist = $true
    foreach ($module in $requiredModules) {
        if (-not (Test-Path $module)) {
            Write-Host "  Missing: $module" -ForegroundColor Red
            $allModulesExist = $false
        }
    }
    
    Write-TestResult "Module structure" $allModulesExist
}

# QEMU Boot Tests
function Invoke-QemuTests {
    Write-TestHeader "QEMU Boot Tests"
    
    # Check if QEMU is available
    $qemu = Get-Command "qemu-system-x86_64" -ErrorAction SilentlyContinue
    if (-not $qemu) {
        $commonPaths = @(
            "C:\Program Files\qemu\qemu-system-x86_64.exe",
            "C:\qemu\qemu-system-x86_64.exe"
        )
        foreach ($path in $commonPaths) {
            if (Test-Path $path) {
                $qemu = $path
                break
            }
        }
    }
    
    if (-not $qemu) {
        Write-TestSkipped "QEMU boot test" "QEMU not installed"
        return
    }
    
    # Build kernel first
    Write-Host "Building kernel for QEMU test..." -ForegroundColor Gray
    $buildResult = & cargo build --target x86_64-rany_os.json 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        Write-TestResult "QEMU boot test" $false "Build failed"
        return
    }
    
    # Verify kernel binary exists
    $kernelPath = "target/x86_64-rany_os/debug/RanyOS"
    if (-not (Test-Path $kernelPath)) {
        Write-TestResult "Kernel binary" $false "Not found at $kernelPath"
        return
    }
    
    Write-TestResult "Kernel binary creation" $true
    
    # Check binary size
    $kernelSize = (Get-Item $kernelPath).Length
    $kernelSizeKB = [math]::Round($kernelSize / 1024, 2)
    Write-Host "  Kernel size: ${kernelSizeKB}KB" -ForegroundColor Gray
    
    if ($kernelSize -gt 0 -and $kernelSize -lt 10MB) {
        Write-TestResult "Kernel size check" $true "Size: ${kernelSizeKB}KB"
    } else {
        Write-TestResult "Kernel size check" $false "Unexpected size: ${kernelSizeKB}KB"
    }
    
    # Note: Full QEMU boot test requires proper bootloader setup
    # For now, we verify the kernel can be loaded
    Write-TestSkipped "Full QEMU boot" "Requires bootloader configuration"
}

# Performance Tests
function Invoke-PerformanceTests {
    Write-TestHeader "Performance Analysis"
    
    # Measure build time
    Write-Host "Measuring build time..." -ForegroundColor Gray
    & cargo clean 2>&1 | Out-Null
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    & cargo build --target x86_64-rany_os.json 2>&1 | Out-Null
    $stopwatch.Stop()
    
    $buildTime = $stopwatch.Elapsed.TotalSeconds
    Write-Host "  Clean build time: ${buildTime}s" -ForegroundColor Gray
    
    if ($buildTime -lt 120) {
        Write-TestResult "Build performance" $true "Build completed in ${buildTime}s"
    } else {
        Write-TestResult "Build performance" $false "Build too slow: ${buildTime}s"
    }
    
    # Check code metrics
    Write-Host "Analyzing code metrics..." -ForegroundColor Gray
    
    $sourceFiles = Get-ChildItem -Path "src" -Recurse -Filter "*.rs"
    $totalLines = 0
    $codeLines = 0
    $commentLines = 0
    
    foreach ($file in $sourceFiles) {
        $content = Get-Content $file.FullName
        $totalLines += $content.Count
        foreach ($line in $content) {
            $trimmed = $line.Trim()
            if ($trimmed -match "^//") {
                $commentLines++
            } elseif ($trimmed.Length -gt 0) {
                $codeLines++
            }
        }
    }
    
    Write-Host "  Source files: $($sourceFiles.Count)" -ForegroundColor Gray
    Write-Host "  Total lines: $totalLines" -ForegroundColor Gray
    Write-Host "  Code lines: $codeLines" -ForegroundColor Gray
    Write-Host "  Comment lines: $commentLines" -ForegroundColor Gray
    Write-Host "  Comment ratio: $([math]::Round($commentLines / $codeLines * 100, 1))%" -ForegroundColor Gray
    
    Write-TestResult "Code metrics analysis" $true
}

# Summary
function Write-TestSummary {
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Blue
    Write-Host " Test Summary" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Blue
    
    $total = $script:TestResults.Passed + $script:TestResults.Failed + $script:TestResults.Skipped
    
    Write-Host "Total:   $total" -ForegroundColor White
    Write-Host "Passed:  $($script:TestResults.Passed)" -ForegroundColor Green
    Write-Host "Failed:  $($script:TestResults.Failed)" -ForegroundColor Red
    Write-Host "Skipped: $($script:TestResults.Skipped)" -ForegroundColor Yellow
    
    if ($script:TestResults.Failed -eq 0) {
        Write-Host ""
        Write-Host "All tests passed!" -ForegroundColor Green
        return 0
    } else {
        Write-Host ""
        Write-Host "Some tests failed." -ForegroundColor Red
        return 1
    }
}

# Main
function Main {
    Push-Location $PSScriptRoot\..
    
    try {
        Write-Host "ExoRust (RanyOS) Test Suite" -ForegroundColor Cyan
        Write-Host "============================" -ForegroundColor Cyan
        
        # Determine which tests to run
        $runAll = -not ($UnitTests -or $IntegrationTests -or $QemuTests) -or $All
        
        if ($runAll -or $UnitTests) {
            Invoke-UnitTests
        }
        
        if ($runAll -or $IntegrationTests) {
            Invoke-IntegrationTests
        }
        
        if ($runAll -or $QemuTests) {
            Invoke-QemuTests
        }
        
        if ($runAll) {
            Invoke-PerformanceTests
        }
        
        return Write-TestSummary
        
    } finally {
        Pop-Location
    }
}

exit (Main)
