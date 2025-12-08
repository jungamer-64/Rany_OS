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
//! - `driver`: 後方互換性のための再エクスポート

#![allow(dead_code)]

pub mod defs;
pub mod commands;
pub mod regs;
pub mod controller;
pub mod queue_types;
pub mod identify;

// New split modules
pub mod queue;
pub mod per_core;
pub mod error;
pub mod polling_driver;
pub mod async_io;
pub mod global;
pub mod scheduler;
pub mod driver;

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

// From split driver modules
pub use queue::{SubmissionQueue, CompletionQueue, QueuePair};
pub use per_core::{PerCoreNvmeQueue, NvmeQueueStats};
pub use error::NvmeError;
pub use polling_driver::{NvmePollingDriver, NvmeDriverStats};
pub use async_io::{AsyncIoRequest, IoRequestState, PendingRequests, ReadFuture, WriteFuture};
pub use global::{init as init_nvme_polling, poll as nvme_poll, get_stats, with_driver, with_driver_mut};
pub use scheduler::{NvmePollHandler, register_with_io_scheduler};
