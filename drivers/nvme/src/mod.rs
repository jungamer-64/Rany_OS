// ============================================================================
// src/io/nvme/mod.rs - NVMe Common Module
// ============================================================================
//!
//! # NVMe共通モジュール
//!
//! NVMe仕様に基づく共通定義とドライバを提供。
//!
//! ## モジュール構成
//! - `defs`: 共通定数・構造体定義
//! - `commands`: コマンド構造体
//! - `regs`: レジスタ定義
//! - `controller`: コントローラレジスタと設定
//! - `queue_types`: 型安全なキュー抽象化
//! - `identify`: Identify構造体
//! - `queue`: 低レベルキュー実装
//! - `per_core`: コアごとのキュー管理
//! - `error`: エラー型
//! - `polling_driver`: ポーリングモードドライバ
//! - `async_io`: 非同期I/Oサポート
//! - `global`: グローバルインスタンス
//! - `scheduler`: IoScheduler統合
pub mod commands;
pub mod controller;
pub mod defs;
pub mod identify;
pub mod queue_types;
pub mod regs;

// New split modules
pub mod async_io;
pub mod error;
pub mod global;
pub mod per_core;
pub mod polling_driver;
pub mod queue;
pub mod requests;
pub mod scheduler;
pub mod sync;

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

// From split driver modules
pub use async_io::{ReadFuture, WriteFuture};
pub use error::NvmeError;
pub use global::{
    get_stats, init as init_nvme_polling, poll as nvme_poll, with_driver, with_driver_mut,
};
pub use per_core::{NvmeQueueStats, PerCoreNvmeQueue};
pub use polling_driver::{NvmeDriverStats, NvmePollingDriver};
pub use queue::{CompletionQueue, QueuePair, SubmissionQueue};
pub use requests::{AsyncIoRequest, IoRequestState, PendingRequests};
pub use scheduler::{NvmePollHandler, register_with_io_scheduler};
