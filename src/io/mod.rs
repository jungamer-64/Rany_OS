// ============================================================================
// I/O Subsystem Module
// 設計書 6: I/Oサブシステム - ゼロコピーとポーリングの極致
// ============================================================================
pub mod virtio;
pub mod polling;
pub mod dma;

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
