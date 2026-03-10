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

This directory has a verification script that checks for unauthorized kernel dependencies as part of CI: `scripts/check-driver-deps.ps1`.

Thank you for following the layering rules. This keeps drivers portable and safe for dynamic loading.
