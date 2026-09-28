# Drivers ディレクトリガイド

- Status: Component detail / drivers guide
- Audience: ドライバ作者、`kernel_api` 変更担当、レビュー担当者
- Related: [ドキュメントハブ](../docs/README.md), [ドライバ依存ルール](../docs/driver-dependency.md), [カーネル / ドライバ責務境界](../docs/kernel-driver-boundary.md)

このディレクトリには ExoRust で利用するハードウェアドライバ実装が入っています。

## 概要

- 方針: ドライバは `kernel` crate に直接依存せず、`kernel_api` と `hal` を通じてカーネル機能へ接続します。

## ガイドライン

- Drivers MUST NOT depend on the kernel crate directly (i.e., no `kernel` dependency in `Cargo.toml`).
- Drivers SHOULD depend on `kernel_api` for system calls, types, and kernel services (e.g., DMA allocation).
- Drivers use retained mapping capabilities and assigned port ranges from `hal`; a raw address is not MMIO/PIO access authority.
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

- Pass a checked `kernel_api::dma::DmaAllocationRequest` to `kernel_api::service::kernel::instance().alloc_dma_for_device(request, pci_locator)`. The returned `CpuDmaLease` owns a linear registry capability, not independently reclaimable backing memory.
- Pass a real `kernel_api::abi::driver::PackedPciLocation` from `DriverContext::pci_location()` or your PCI enumeration path. Public driver code must not rely on identity/global DMA fallback.
- Transfer CPU ownership before hardware publication. Descriptor RAM uses the shared lease protocol, not MMIO or retained Rust slices. Explicit `close` can fail and returns the quarantined capability; Drop is not successful release. See the [DMA ownership contract](../docs/driver-dependency.md).

If your driver needs to run as a standalone cell:

- Gate `kernel_api::register_cell_runtime!();` behind `#[cfg(feature = "standalone")]` at crate root.
- Wire `standalone = ["export_driver_entry", "kernel_api/cell_runtime"]` in `Cargo.toml`.
- Build the cell image as a `cdylib`, then package it with `tools/driver_pack_builder`.
- For the shared wrapper flow used by `AHCI/NVMe/xHCI/HDA/MLX5`, use `scripts/build_standalone_driver_packs.sh --profile debug|release`. It emits raw wrapper cells plus staged PCI driver packs under `target/x86_64-exorust/<profile>/standalone_drivers/`.
- For the runtime profiles used by QEMU (`storage`, `driver_domain`, `network`, `iommu`), use `scripts/build_runtime_boot_artifacts.sh --profile debug|release`. It merges the staged PCI driver packs with the driver-domain probe fixtures into:
  - `target/x86_64-exorust/<profile>/boot_artifacts/drivers/*.cell`
  - `target/x86_64-exorust/<profile>/boot_artifacts/cells/*.cell`
- PCI driver packs may use only two manifest selector shapes:
  - exact device match: `vendor_id + device_id`
  - class match: `class + subclass + prog_if`, with optional `vendor_id`
- `prog_if = 0x00` is still a valid exact class selector. Only omitted `vendor_id` is treated as wildcard.
- Non-PCI `.cell` payloads and driver packs without a PCI selector still autostart from boot artifacts; PCI packs with a selector are staged and claim their function during PCI enumeration before device enable or driver-domain start.
- `target/x86_64-exorust/<profile>/boot_artifacts/drivers` is now the default runtime payload consumed by the QEMU profiles.
- Built-in kernel drivers are fallback-only when staged matching returns `NoMatch`. A failed or uncertain staged start remains the function's authority and prohibits built-in reacquisition.

This directory has a verification script that checks for unauthorized kernel dependencies as part of CI: `scripts/check-driver-deps.ps1`.

## 関連文書

- [../docs/driver-dependency.md](../docs/driver-dependency.md)
- [../docs/kernel-driver-boundary.md](../docs/kernel-driver-boundary.md)
- [nvme/README.md](nvme/README.md)
