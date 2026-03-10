# Driver Dependency Guidelines

This document explains the driver dependency rules for the Rany_OS repository.

## Purpose

Drivers are intended to be built separately from the kernel core and must not depend on the kernel crate (internal implementation). This allows drivers to be dynamically loaded or run in isolated "cells" in the future.

## Rules

- Drivers MUST NOT add `kernel` as a dependency in Cargo.toml
- Drivers SHOULD depend on `kernel_api` for kernel-provided services and types
- Drivers may depend on `hal` for hardware access wrappers (MMIO, port I/O, etc.)
- Drivers SHOULD only use the kernel API for functionalities such as memory allocation and device-scoped DMA.
- Drivers that expose a `standalone` feature SHOULD treat it as a complete cell build contract: exported ABI entry symbol plus `kernel_api/cell_runtime`.
- Kernel code SHOULD access device-facing modules via `crate::drivers::*`, while `crate::io::*` is reserved for kernel-owned I/O infrastructure such as DMA/IOMMU, interrupt routing, and polling.

## What to do when needing kernel capabilities

- Request access via `kernel_api::service::kernel::instance()`, which provides `KernelServices` trait methods such as `alloc_dma_for_device(size, pci_locator)`. DMA buffers are reclaimed automatically on Drop.
- Obtain `pci_locator` from `kernel_api::abi::driver::DriverContext::pci_location()` or from PCI enumeration using `PackedPciLocation::new(segment, bus, device, function)`.
- If additional kernel capabilities are required, add them to `interfaces/kernel_api` and implement them inside the kernel service implementation.
- For standalone cells, enable the crate's `standalone` feature so `kernel_api::register_cell_runtime!()` can bind allocator/panic/logging to the kernel ABI table.
- Package standalone PCI cells with `tools/driver_pack_builder`; manifest selectors are limited to exact `vendor_id + device_id` or `class + subclass + prog_if` with optional `vendor_id`.
- The repository now includes `scripts/build_standalone_driver_packs.sh` for the shared wrapper-based PCI driver cells (`AHCI/NVMe/xHCI/HDA/MLX5`). It writes raw cells and packaged driver packs to `target/x86_64-exorust/<profile>/standalone_drivers/` and a deployable tarball to `target/standalone_driver_initramfs.tar`.
- `prog_if = 0x00` remains a valid exact class match. Wildcard-on-zero applies only to omitted selector fields such as `vendor_id` in class-matching packs.
- Initramfs behavior is now split:
  - `drivers/*.cell` without a PCI selector autostart immediately.
  - driver packs with a PCI selector are staged and matched during PCI enumeration with a real `DriverContext::for_pci(...)`.

## CI enforcement

- The repository provides `scripts/check-driver-deps.ps1` which scans driver Cargo.toml files and enforces the rule.
- `scripts/check-kernel-api-surface.sh` also rejects legacy `alloc_dma(...)`, driver-side hardware programming via `physical_address()`, and ad-hoc PCI locator bit packing in `drivers/`.
- Include this check in CI pipelines to prevent regressions.

## Example

- Correct: driver depends on `kernel_api` and `hal`.
- Correct: standalone driver feature expands to `["export_driver_entry", "kernel_api/cell_runtime"]`.
- Incorrect: driver depends on `kernel` crate or uses types from `kernel::io::dma` directly.


## Questions / Contribution

If you are unsure whether a symbol belongs to `kernel_api` or `kernel`, prefer adding it to `kernel_api` with a minimal interface that doesn't expose kernel internals.

If you need help migrating an existing driver, ask in a PR and attach a short plan describing the change.

See also: `docs/kernel_driver_boundary.md`
