# Driver Dependency Guidelines

This document explains the driver dependency rules for the Rany_OS repository.

## Purpose

Drivers are intended to be built separately from the kernel core and must not depend on the kernel crate (internal implementation). This allows drivers to be dynamically loaded or run in isolated "cells" in the future.

## Rules

- Drivers MUST NOT add `kernel` as a dependency in Cargo.toml
- Drivers SHOULD depend on `kernel_api` for kernel-provided services and types
- Drivers may depend on `hal` for hardware access wrappers (MMIO, port I/O, etc.)
- Drivers SHOULD only use the kernel API for functionalities such as memory allocation and DMA.

## What to do when needing kernel capabilities

- Request access via `kernel_api::service::kernel::instance()`, which provides `KernelServices` trait methods such as `alloc_dma()`. DMA buffers are reclaimed automatically on Drop.
- If additional kernel capabilities are required, add them to `interfaces/kernel_api` and implement them inside the kernel service implementation.

## CI enforcement

- The repository provides `scripts/check-driver-deps.ps1` which scans driver Cargo.toml files and enforces the rule.
- Include this check in CI pipelines to prevent regressions.

## Example

- Correct: driver depends on `kernel_api` and `hal`.
- Incorrect: driver depends on `kernel` crate or uses types from `kernel::io::dma` directly.


## Questions / Contribution

If you are unsure whether a symbol belongs to `kernel_api` or `kernel`, prefer adding it to `kernel_api` with a minimal interface that doesn't expose kernel internals.

If you need help migrating an existing driver, ask in a PR and attach a short plan describing the change.
