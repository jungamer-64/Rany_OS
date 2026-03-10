# Drivers Directory Guide

This directory (drivers/) contains hardware driver implementations used by Rany_OS.

Guidelines for driver authors:

- Drivers MUST NOT depend on the kernel crate directly (i.e., no `kernel` dependency in `Cargo.toml`).
- Drivers SHOULD depend on `kernel_api` for system calls, types, and kernel services (e.g., DMA allocation).
- Drivers may use the `hal` crate for safe MMIO/port IO primitives.
- If you need to perform privileged kernel operations, extend the `kernel_api` trait and implement support in the kernel's `KernelServices` implementation.
- If a driver exposes `standalone`, that feature should mean "standalone cell build" end-to-end: export the ABI entry symbol and enable `kernel_api/cell_runtime`.

Example `Cargo.toml` for a driver:

```toml
[package]
name = "some_driver"

[dependencies]
kernel_api = { path = "../interfaces/kernel_api" }
hal = { path = "../hal" }
```

If your driver needs to allocate DMA memory:

- Use `kernel_api::service::kernel::instance().alloc_dma_for_device(size, pci_locator)` and let the returned `kernel_api::dma::DmaSlice<kernel_api::dma::CpuOwned>` reclaim itself on Drop.
- Pass a real `kernel_api::abi::driver::PackedPciLocation` from `DriverContext::pci_location()` or your PCI enumeration path. Public driver code must not rely on identity/global DMA fallback.

If your driver needs to run as a standalone cell:

- Gate `kernel_api::register_cell_runtime!();` behind `#[cfg(feature = "standalone")]` at crate root.
- Wire `standalone = ["export_driver_entry", "kernel_api/cell_runtime"]` in `Cargo.toml`.
- Build the cell image as a `cdylib`, then package it with `tools/driver_pack_builder`.
- For the shared wrapper flow used by `AHCI/NVMe/xHCI/HDA/MLX5`, use `scripts/build_standalone_driver_packs.sh --profile debug|release`. It emits raw wrapper cells plus staged PCI driver packs under `target/x86_64-exorust/<profile>/standalone_drivers/`.
- For the runtime profiles used by QEMU (`storage`, `driver_domain`, `network`, `iommu`), use `scripts/build_runtime_initramfs.sh --profile debug|release`. It merges the staged PCI driver packs with the driver-domain probe fixtures into `target/initramfs.tar`.
- PCI driver packs may use only two manifest selector shapes:
  - exact device match: `vendor_id + device_id`
  - class match: `class + subclass + prog_if`, with optional `vendor_id`
- `prog_if = 0x00` is still a valid exact class selector. Only omitted `vendor_id` is treated as wildcard.
- Non-PCI `.cell` payloads and driver packs without a PCI selector still autostart from initramfs; PCI packs with a selector are staged and bound during PCI enumeration.
- `target/initramfs.tar` is now the default merged payload consumed by the runtime QEMU profiles. Built-in kernel drivers remain fallback-only when staged standalone binding returns `NoMatch` or fails.

This directory has a verification script that checks for unauthorized kernel dependencies as part of CI: `scripts/check-driver-deps.ps1`.

Thank you for following the layering rules. This keeps drivers portable and safe for dynamic loading.
