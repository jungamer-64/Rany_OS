# NVMe Driver Development Guide

This NVMe driver is compiled as a standalone crate `nvme_driver` under `drivers/nvme`.

Guidelines for NVMe driver development:

- The driver uses the `kernel_api` crate for kernel-provided services like DMA allocation and syscalls.
- Prefer `kernel_api::services::kernel().alloc_dma(size)` to allocate DMA buffers.
- Use the returned `kernel_api::DmaBuffer` to obtain device-visible addresses (`device_address()`), and virtual pointers (`as_ptr()`).
- Avoid using kernel-internal DMA types (e.g., `TypedDmaBuffer`) directly — those are kernel internal and do not exist in a module-based driver.
- Use the `Driver` trait from `kernel_api::driver::Driver` to expose your driver as a kernel driver.

Examples:

Allocating DMA memory:

```rust
let kernel = kernel_api::services::kernel();
let dma_buf = kernel.alloc_dma(sq_size)?; // returns DmaBuffer
let dev_addr = dma_buf.device_address(); // Use for IOMMU compatibility
let virt_ptr = dma_buf.as_ptr();
```

Register the driver with the kernel at boot (in `kernel/src/main.rs`):

```rust
let driver = nvme_driver::NvmeDriverWrapper::new(bar0, cores);
kernel_driver_manager.register(Box::new(driver));
```

This mirrors the `Driver` contract declared in `interfaces/kernel_api` and allows dynamic loading of the driver in the future.
