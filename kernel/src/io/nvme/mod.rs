// ============================================================================
// src/io/nvme/mod.rs - NVMe Common Module
// ============================================================================
//!
//! # NVMe共通モジュール
//!
//! NVMe仕様に基づく共通定義とドライバを提供。
//!
//! ## モジュール構成
//! - `defs`: 共通定数・構造体定義 (from nvme_driver)
//! - `commands`: コマンド構造体 (from nvme_driver)
//! - `regs`: レジスタ定義 (from nvme_driver)
//! - `queue_types`: 型安全なキュー抽象化 (from nvme_driver)
//! - `identify`: Identify構造体 (from nvme_driver)
//! - `error`: エラー型 (from nvme_driver)
//! - `controller`: コントローラレジスタと設定 (kernel local)
//! - `queue`: 低レベルキュー実装 (kernel local)
//! - `per_core`: コアごとのキュー管理 (kernel local)
//! - `polling_driver`: ポーリングモードドライバ (kernel local)
//! - `async_io`: 非同期I/Oサポート (kernel local)
//! - `global`: グローバルインスタンス (kernel local)
//! - `scheduler`: IoScheduler統合 (kernel local)
//! - `driver`: 後方互換性のための再エクスポート (kernel local)

#![allow(dead_code)]

// Local modules (kernel implementation)
pub mod controller;
pub mod queue;
pub mod per_core;
pub mod polling_driver;
pub mod async_io;
pub mod global;
pub mod scheduler;
pub mod driver;

// Re-export modules from nvme_driver
pub use nvme_driver::defs;
pub use nvme_driver::commands;
pub use nvme_driver::regs;
pub use nvme_driver::queue_types;
pub use nvme_driver::identify;
pub use nvme_driver::error;

// ============================================================================
// Re-exports - Explicit exports to avoid ambiguity
// ============================================================================

// From defs.rs - Opcodes, Status, Constants
pub use defs::{
    // Opcodes
    AdminOpcode, IoOpcode,
    // Status and Error
    NvmeStatus, NvmeError as DefsNvmeError,
    // Memory structures
    PrpEntry, PrpList, SglDescriptor, SglType,
    // Constants
    CACHE_LINE_SIZE, SQE_SIZE, CQE_SIZE, SECTOR_SIZE, PAGE_SIZE,
    MAX_QUEUE_DEPTH as DEFS_MAX_QUEUE_DEPTH,
    DEFAULT_QUEUE_DEPTH as DEFS_DEFAULT_QUEUE_DEPTH,
    ADMIN_QUEUE_DEPTH, MAX_TRANSFER_SIZE, POLL_BATCH_SIZE,
    DOORBELL_BATCH_THRESHOLD, CONTROLLER_READY_TIMEOUT_MS,
};

// From commands.rs - Command/Completion structures
pub use commands::{NvmeCommand, NvmeCompletion};

// From regs.rs - Register definitions
pub use regs::{
    offsets, cc_bits, csts_bits,
    NvmeCapabilities, NvmeControllerConfig, NvmeControllerStatus,
    NvmeAdminQueueAttributes, CmbLocation, CmbSize,
};

// From identify.rs - Identify structures
pub use identify::{
    IdentifyController, IdentifyNamespace, PowerStateDescriptor,
    LbaFormat, RelativePerformance, IdentifyCns,
};

// From error.rs
pub use error::NvmeError;

// From split driver modules (local)
pub use queue::{SubmissionQueue, CompletionQueue, QueuePair};
pub use per_core::{PerCoreNvmeQueue, NvmeQueueStats};
pub use polling_driver::{NvmePollingDriver, NvmeDriverStats};
pub use async_io::{AsyncIoRequest, IoRequestState, PendingRequests, ReadFuture, WriteFuture};
pub use global::{init as init_nvme_polling, poll as nvme_poll, get_stats, with_driver, with_driver_mut};
pub use scheduler::{NvmePollHandler, register_with_io_scheduler};
