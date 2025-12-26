# Create a 64MB raw disk image and format it as FAT32 (Windows-friendly)
# This script tries to use WSL (recommended) to run mkfs.vfat and mtools.
# Usage: .\create_test_disk.ps1

$img = "test_disk.img"
$size = "64M"

Write-Host "Creating raw image: $img ($size)"
qemu-img create -f raw $img $size | Out-Null

# Try to use WSL to run mkfs and mcopy (works on Windows with WSL installed)
if (Get-Command wsl -ErrorAction SilentlyContinue) {
    Write-Host "Using WSL to format image and add HELLO.TXT"

    $pwdWin = (Get-Location).Path -replace '\\','/'
    $wslPath = "/mnt/" + $pwdWin.Substring(0,1).ToLower() + $pwdWin.Substring(2)
    $wslImg = "$wslPath/$img"

    wsl sudo apt-get update -qq
    wsl sudo apt-get install -y -qq dosfstools mtools
    wsl mkfs.vfat -F 32 -n TEST "$wslImg"
    wsl bash -lc "echo 'E2E test file' > /tmp/hello.txt && mcopy -i '$wslImg' /tmp/hello.txt ::/HELLO.TXT"
    Write-Host "Created and populated $img"
} else {
    Write-Warning "WSL not found. Please run the following commands manually in a Linux environment or install WSL:"
    Write-Host "  qemu-img create -f raw $img $size"
    Write-Host "  sudo apt-get install dosfstools mtools"
    Write-Host "  mkfs.vfat -F 32 -n TEST $img"
    Write-Host "  echo 'E2E test file' > hello.txt; mcopy -i $img hello.txt ::/HELLO.TXT"
}
