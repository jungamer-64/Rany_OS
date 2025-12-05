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
//! - `queue`: キュー構造体
//! - `identify`: Identify構造体
//! - `driver`: 高性能NVMeドライバ（ポーリングモード）

#![allow(dead_code)]

pub mod defs;
pub mod commands;
pub mod regs;
pub mod queue;
pub mod queue_types;
pub mod identify;
pub mod driver;

// ============================================================================
// Re-exports - Explicit exports to avoid ambiguity
// ============================================================================

// From defs.rs - Opcodes, Status, Constants
pub use defs::{
    // Opcodes
    AdminOpcode, IoOpcode,
    // Status and Error
    NvmeStatus, NvmeError,
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

// From queue.rs - Queue structures
pub use queue::{
    NvmeSubmissionQueue, NvmeCompletionQueue, NvmeQueuePair, NvmeQueueError,
    DEFAULT_QUEUE_DEPTH, MAX_QUEUE_DEPTH, SQ_ENTRY_SIZE, CQ_ENTRY_SIZE,
};

// From identify.rs - Identify structures
pub use identify::{
    IdentifyController, IdentifyNamespace, PowerStateDescriptor,
    LbaFormat, RelativePerformance, IdentifyCns,
};

// From driver.rs - High-performance polling driver
pub use driver::{
    NvmePollingDriver, PerCoreNvmeQueue, NvmeQueueStats,
    QueuePair, SubmissionQueue, CompletionQueue,
    AsyncIoRequest, IoRequestState,
    NvmeCommand as PollingNvmeCommand, NvmeCompletion as PollingNvmeCompletion,
    init as init_nvme_polling, poll as nvme_poll,
};
