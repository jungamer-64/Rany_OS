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
// pub mod controller; // Migrated to nvme_driver
// pub mod queue; // Migrated to nvme_driver
// pub mod per_core; // Migrated to nvme_driver
pub mod async_io;
pub mod driver;
pub mod global;
pub mod polling_driver;
pub mod scheduler;

// Re-export modules from nvme_driver
pub use nvme_driver::commands;
pub use nvme_driver::controller;
pub use nvme_driver::defs;
pub use nvme_driver::error;
pub use nvme_driver::identify;
pub use nvme_driver::per_core;
pub use nvme_driver::queue;
pub use nvme_driver::queue_types;
pub use nvme_driver::regs;

// ============================================================================
// Re-exports - Explicit exports to avoid ambiguity
// ============================================================================

// From defs.rs - Opcodes, Status, Constants
pub use defs::{
    ADMIN_QUEUE_DEPTH,
    // Opcodes
    AdminOpcode,
    // Constants
    CACHE_LINE_SIZE,
    CONTROLLER_READY_TIMEOUT_MS,
    CQE_SIZE,
    DEFAULT_QUEUE_DEPTH as DEFS_DEFAULT_QUEUE_DEPTH,
    DOORBELL_BATCH_THRESHOLD,
    IoOpcode,
    MAX_QUEUE_DEPTH as DEFS_MAX_QUEUE_DEPTH,
    MAX_TRANSFER_SIZE,
    NvmeError as DefsNvmeError,
    // Status and Error
    NvmeStatus,
    PAGE_SIZE,
    POLL_BATCH_SIZE,
    // Memory structures
    PrpEntry,
    PrpList,
    SECTOR_SIZE,
    SQE_SIZE,
    SglDescriptor,
    SglType,
};

// From commands.rs - Command/Completion structures
pub use commands::{NvmeCommand, NvmeCompletion};

// From regs.rs - Register definitions
pub use regs::{
    CmbLocation, CmbSize, NvmeAdminQueueAttributes, NvmeCapabilities, NvmeControllerConfig,
    NvmeControllerStatus, cc_bits, csts_bits, offsets,
};

// From identify.rs - Identify structures
pub use identify::{
    IdentifyCns, IdentifyController, IdentifyNamespace, LbaFormat, PowerStateDescriptor,
    RelativePerformance,
};

// From error.rs
pub use error::NvmeError;

// From split driver modules (local)
pub use async_io::{AsyncIoRequest, IoRequestState, PendingRequests, ReadFuture, WriteFuture};
pub use global::{
    get_stats, init as init_nvme_polling, poll as nvme_poll, with_driver, with_driver_mut,
};
pub use per_core::{NvmeQueueStats, PerCoreNvmeQueue};
pub use polling_driver::{NvmeDriverStats, NvmePollingDriver};
pub use queue::{CompletionQueue, QueuePair, SubmissionQueue};
pub use scheduler::{NvmePollHandler, register_with_io_scheduler};
