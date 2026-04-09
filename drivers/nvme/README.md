# NVMe ドライバ開発ガイド

- Status: Component detail / NVMe driver guide
- Audience: NVMe ドライバ実装者、ストレージ I/O レビュー担当者
- Related: [ドライバディレクトリ案内](../README.md), [ドライバ依存ルール](../../docs/driver-dependency.md), [カーネル / ドライバ責務境界](../../docs/kernel-driver-boundary.md)

この NVMe ドライバは `drivers/nvme` 配下の独立 crate `nvme_driver` としてビルドされます。

## 概要

- 方針: DMA や syscalls は `kernel_api` 経由で扱い、カーネル内部型に依存しません。

## ガイドライン

- The driver uses the `kernel_api` crate for kernel-provided services like DMA allocation and syscalls.
- Prefer `kernel_api::service::kernel::instance().alloc_dma_for_device(size, pci_locator)` to allocate DMA buffers.
- Use the returned `kernel_api::dma::DmaSlice<kernel_api::dma::CpuOwned>` to obtain device-visible addresses (`device_address()`), and virtual pointers (`as_ptr()`).
- Avoid using kernel-internal DMA types (e.g., `TypedDmaBuffer`) directly — those are kernel internal and do not exist in a module-based driver.
- Use the `Driver` trait from `kernel_api::driver::Driver` to expose your driver as a kernel driver.

Examples:

Allocating DMA memory:

```rust
let kernel = kernel_api::service::kernel::instance();
let pci_locator = ctx.pci_location();
let dma_buf = kernel.alloc_dma_for_device(sq_size, pci_locator)?; // returns DmaSlice<CpuOwned>
let dev_addr = dma_buf.device_address(); // Use for IOMMU compatibility
let virt_ptr = dma_buf.as_ptr();
drop(dma_buf); // Drop releases the DMA allocation
```

Register the driver with the kernel at boot (in `kernel/src/main.rs`):

```rust
let driver = nvme_driver::NvmeDriverWrapper::new(bar0, cores, pci_locator);
kernel_driver_manager.register(Box::new(driver));
```

This mirrors the `Driver` contract declared in `interfaces/kernel_api` and allows dynamic loading of the driver in the future.

## 関連文書

- [../README.md](../README.md)
- [../../docs/driver-dependency.md](../../docs/driver-dependency.md)
- [../../docs/kernel-driver-boundary.md](../../docs/kernel-driver-boundary.md)
