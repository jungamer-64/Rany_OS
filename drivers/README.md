# Drivers Directory Guide

This directory (drivers/) contains hardware driver implementations used by Rany_OS.

Guidelines for driver authors:

- Drivers MUST NOT depend on the kernel crate directly (i.e., no `kernel` dependency in `Cargo.toml`).
- Drivers SHOULD depend on `kernel_api` for system calls, types, and kernel services (e.g., DMA allocation).
- Drivers may use the `hal` crate for safe MMIO/port IO primitives.
- If you need to perform privileged kernel operations, extend the `kernel_api` trait and implement support in the kernel's `KernelServices` implementation.

Example `Cargo.toml` for a driver:

```toml
[package]
name = "some_driver"

[dependencies]
kernel_api = { path = "../interfaces/kernel_api" }
hal = { path = "../hal" }
```

If your driver needs to allocate DMA memory:

- Use `kernel_api::service::kernel::instance().alloc_dma(size)` and let the returned DMA slice reclaim itself on Drop.

This directory has a verification script that checks for unauthorized kernel dependencies as part of CI: `scripts/check-driver-deps.ps1`.

Thank you for following the layering rules — this keeps drivers portable and safe for dynamic loading.
