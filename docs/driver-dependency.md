# ドライバ依存ガイドライン

- Status: Canonical driver dependency rule
- Audience: ドライバ作者、`kernel_api` 変更担当、CI ルール整備担当
- Related: [ドキュメントハブ](README.md), [kernel-driver-boundary.md](kernel-driver-boundary.md), [../drivers/README.md](../drivers/README.md)

この文書は、ExoRust リポジトリにおけるドライバ依存ルールをまとめたものです。ドライバはカーネル本体と独立にビルドできることを前提にし、将来のセル化や動的ロードに備えて `kernel` crate への直接依存を禁止します。

## 目的

Drivers are intended to be built separately from the kernel core and must not depend on the kernel crate (internal implementation). This allows drivers to be dynamically loaded or run in isolated cells in the future.

## ルール

- Drivers MUST NOT add `kernel` as a dependency in `Cargo.toml`.
- Drivers SHOULD depend on `kernel_api` for kernel-provided services and types.
- Drivers may depend on `hal` for hardware access wrappers such as MMIO and port I/O.
- Drivers SHOULD only use the kernel API for memory allocation and device-scoped DMA.
- Drivers that expose a `standalone` feature SHOULD treat it as a complete cell build contract: exported ABI entry symbol plus `kernel_api/cell_runtime`.
- Kernel code SHOULD access device-facing modules via `crate::drivers::*`, while `crate::io::*` is reserved for kernel-owned I/O infrastructure such as DMA / IOMMU, interrupt routing, and polling.

## カーネル機能が必要な場合

- Request access via `kernel_api::service::kernel::instance()`, which provides `KernelServices` trait methods such as `alloc_dma_for_device(size, pci_locator)`. DMA buffers are reclaimed automatically on Drop.
- Obtain `pci_locator` from `kernel_api::abi::driver::DriverContext::pci_location()` or from PCI enumeration using `PackedPciLocation::new(segment, bus, device, function)`.
- If additional kernel capabilities are required, add them to `interfaces/kernel_api` and implement them inside the kernel service implementation.
- For standalone cells, enable the crate's `standalone` feature so `kernel_api::register_cell_runtime!()` can bind allocator/panic/logging to the kernel ABI table.
- Package standalone PCI cells with `tools/driver_pack_builder`; manifest selectors are limited to exact `vendor_id + device_id` or `class + subclass + prog_if` with optional `vendor_id`.
- The repository now includes `scripts/build_standalone_driver_packs.sh` for the shared wrapper-based PCI driver cells (`AHCI/NVMe/xHCI/HDA/MLX5`). It writes raw cells and packaged driver packs to `target/x86_64-exorust/<profile>/standalone_drivers/`.
- `scripts/build_runtime_boot_artifacts.sh` is the default runtime packaging path for QEMU profiles. It merges the staged standalone PCI packs with the driver-domain probe fixtures and writes:
  - `target/x86_64-exorust/<profile>/boot_artifacts/drivers/*.cell`
  - `target/x86_64-exorust/<profile>/boot_artifacts/cells/*.cell`
- `prog_if = 0x00` remains a valid exact class match. Wildcard-on-zero applies only to omitted selector fields such as `vendor_id` in class-matching packs.
- Boot artifact behavior is now split:
  - `drivers/*.cell` without a PCI selector autostart immediately.
  - driver packs with a PCI selector are staged and matched during PCI enumeration with a real `DriverContext::for_pci(...)`.
  - `storage`, `driver_domain`, `network`, and `iommu` QEMU profiles now consume the boot partition's `/drivers/*.cell` and `/cells/*.cell` payloads by default.

## CI による検証

- The repository provides `scripts/check-driver-deps.ps1` which scans driver Cargo.toml files and enforces the rule.
- `scripts/check-kernel-api-surface.sh` also rejects legacy `alloc_dma(...)`, driver-side hardware programming via legacy DMA address getters, and ad-hoc PCI locator bit packing in `drivers/`.
- Include this check in CI pipelines to prevent regressions.

## 例

- Correct: driver depends on `kernel_api` and `hal`.
- Correct: standalone driver feature expands to `["export_driver_entry", "kernel_api/cell_runtime"]`.
- Incorrect: driver depends on `kernel` crate or uses types from `kernel::io::dma` directly.


## 問い合わせ / Contribution

If you are unsure whether a symbol belongs to `kernel_api` or `kernel`, prefer adding it to `kernel_api` with a minimal interface that doesn't expose kernel internals.

If you need help migrating an existing driver, ask in a PR and attach a short plan describing the change.

See also: `docs/kernel-driver-boundary.md`

## 関連文書

- [README.md](README.md)
- [kernel-driver-boundary.md](kernel-driver-boundary.md)
- [../drivers/README.md](../drivers/README.md)
