E2E virtio-blk zero-copy test

This folder contains helper scripts to reproduce the QEMU-based E2E storage test locally.

Scripts:
- `create_test_disk.ps1`: Create a 64MB raw image and format it as FAT32 (uses WSL if available).
- `run_e2e_qemu.ps1`: Build the kernel (feature `run-integration-tests`) and run QEMU with the test disk attached.

Usage (Windows PowerShell):
1. Create the disk image: `.	ools\e2e_zero_copy\create_test_disk.ps1`
2. Build and run: `.	ools\e2e_zero_copy\run_e2e_qemu.ps1`

Note:
- The GitHub workflow `qemu-tests.yml` now formats `test_disk.img` with FAT32 and adds `HELLO.TXT`.
- CI builds the kernel with `--features run-integration-tests` so the integration test runs at boot and will exit QEMU with success/failure code.
