# NVMe ドライバ開発ガイド

- Status: Component detail / NVMe driver guide
- Audience: NVMe ドライバ実装者、ストレージ I/O レビュー担当者
- Related: [ドライバディレクトリ案内](../README.md), [ドライバ依存ルール](../../docs/driver-dependency.md), [カーネル / ドライバ責務境界](../../docs/kernel-driver-boundary.md)

この NVMe ドライバは `drivers/nvme` 配下の独立 crate `nvme_driver` としてビルドされます。

## 概要

- 方針: DMA や syscalls は `kernel_api` 経由で扱い、カーネル内部型に依存しません。

## ガイドライン

- The kernel composition root retains the PCI resource owner and passes one checked `MappedMmio` to `ControllerAcquire`.
- Queue and transfer memory comes only from `kernel_api::service::kernel::instance().alloc_dma_for_device(DmaAllocationRequest, pci_locator)`.
- Allocation callers retain `CpuDmaLease`; byte access is limited to its checked `read`/`write` visitors. Device addresses exist only through borrowed descriptors after preparation.
- Submission consumes CPU ownership into the queue generation. Only a validated CQ entry can produce completion authority and restore CPU ownership.
- `NamespaceInfo` is derived from a 4096-byte Identify result. `IoTransfer::for_namespace` derives transfer bytes from its formatted block geometry and binds the command to that controller generation.
- Queue RAM remains `SharedDmaLease` while the controller can access it. Normal drop is not a successful finalizer; controller shutdown/reset and IOTLB reconciliation must precede release.
- Scheduler adapters belong to the kernel composition boundary. The driver crate exposes the controller protocol and does not own an ambient global instance.

## 関連文書

- [../README.md](../README.md)
- [../../docs/driver-dependency.md](../../docs/driver-dependency.md)
- [../../docs/kernel-driver-boundary.md](../../docs/kernel-driver-boundary.md)
