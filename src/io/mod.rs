// ============================================================================
// I/O Subsystem Module
// 設計書 6: I/Oサブシステム - ゼロコピーとポーリングの極致
// ============================================================================
pub mod virtio;
pub mod polling;
pub mod dma;

pub use polling::{
    AdaptiveIoController, IoMode, IoStats, PollingConfig,
    net_io_controller, block_io_controller, polling_loop,
};
pub use dma::{
    DmaBuffer, DmaBufferState, DmaSlice, DmaGuard, SgEntry, SgList,
};
