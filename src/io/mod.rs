// ============================================================================
// I/O Subsystem Module
// 設計書 6: I/Oサブシステム - ゼロコピーとポーリングの極致
// ============================================================================
pub mod virtio;
pub mod virtio_blk;
pub mod nvme;
pub mod polling;
pub mod dma;
pub mod iommu;

#[allow(unused_imports)]
pub use polling::{
    AdaptiveIoController, IoMode, IoStats, PollingConfig,
    net_io_controller, block_io_controller, polling_loop,
};
#[allow(unused_imports)]
pub use dma::{
    // 型安全DMA（型状態パターン）
    TypedDmaBuffer, TypedDmaSlice, TypedDmaGuard, TypedSgList,
    CpuOwned, DeviceOwned, DmaState,
    SgEntry,
};
#[allow(unused_imports)]
pub use virtio_blk::{
    VirtioBlkDevice, BlockDeviceConfig, BlockError, AsyncBlockDevice,
    VirtQueue, VringDesc, features as blk_features,
    init_virtio_blk, handle_virtio_blk_interrupt,
};
#[allow(unused_imports)]
pub use nvme::{
    NvmeController, NvmeNamespace, NvmeConfig, NvmeError, NvmeStatus,
    NvmeCommand, NvmeCompletion, NvmeQueuePair,
    init_nvme, handle_nvme_interrupt,
};
#[allow(unused_imports)]
pub use iommu::{
    IommuController, IommuDomain, IommuError, DeviceId, DmaMapping,
    init_iommu, enable_iommu, disable_iommu, with_iommu,
};
