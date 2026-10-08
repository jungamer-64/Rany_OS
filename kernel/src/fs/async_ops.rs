// ============================================================================
// src/fs/async_ops.rs - Async File Operations
// 設計書 6.3: ストレージと非同期ファイルシステム
// ============================================================================
//!
//! Checked block extents and capability-owned direct block transfers.
//!
//! Awaiting a transfer owns its scheduler completion consumer. Cancellation
//! removes an undispatched command or leaves accepted DMA with the device;
//! filesystem code never reconstructs CPU ownership from a copied status.

#![forbid(unsafe_code)]

use super::fs_model::{FsError, FsResult};
use crate::io::io_scheduler::{
    DeviceId as IoDeviceId, IoCommand, IoCompletion, IoError, IoPriority, hybrid_coordinator,
    io_scheduler,
};
use kernel_api::dma::CpuDmaLease;
use kernel_api::service::storage::{BlockTransferOutcome, BlockTransferRetention};

mod block;

pub use block::DirectBlockHandle;

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;
