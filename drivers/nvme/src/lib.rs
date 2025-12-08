// ============================================================================
// drivers/nvme/src/lib.rs - NVMe Driver
// ============================================================================
//!
//! # NVMe Driver
//!
//! NVMe仕様に基づく共通定義とドライバを提供。
//!
//! ## Core Modules (kernel-independent)
//! - `defs`: 共通定数・構造体定義
//! - `commands`: コマンド構造体
//! - `regs`: レジスタ定義
//! - `queue_types`: 型安全なキュー抽象化
//! - `identify`: Identify構造体
//! - `error`: エラー型
//!
//! ## Kernel-Dependent (excluded)
//! ## Kernel-Dependent (excluded)
//! - `polling_driver`
//! - `async_io`, `global`, `scheduler`, `driver`

#![no_std]
#![allow(dead_code)]

extern crate alloc;

// Core modules (no kernel deps)
pub mod defs;
pub mod commands;
pub mod regs;
pub mod queue_types;
pub mod identify;
pub mod error;

// Modules migrated from kernel
// Modules migrated from kernel
pub mod controller;
pub mod queue;
pub mod per_core;

// Modules with kernel deps - excluded for now
pub mod polling_driver; // Uncommented and refactored
pub mod driver_impl;    // New wrapper

// pub mod async_io;
// pub mod global;
// pub mod scheduler;
// pub mod driver;

// Re-exports
pub use defs::{
    AdminOpcode, IoOpcode,
    NvmeStatus, NvmeError as DefsNvmeError,
    PrpEntry, PrpList, SglDescriptor, SglType,
    CACHE_LINE_SIZE, SQE_SIZE, CQE_SIZE, SECTOR_SIZE, PAGE_SIZE,
    MAX_QUEUE_DEPTH, DEFAULT_QUEUE_DEPTH, ADMIN_QUEUE_DEPTH,
    MAX_TRANSFER_SIZE, POLL_BATCH_SIZE,
    DOORBELL_BATCH_THRESHOLD, CONTROLLER_READY_TIMEOUT_MS,
};

pub use commands::{NvmeCommand, NvmeCompletion};

pub use regs::{
    offsets, cc_bits, csts_bits,
    NvmeCapabilities, NvmeControllerConfig, NvmeControllerStatus,
    NvmeAdminQueueAttributes, CmbLocation, CmbSize,
};

pub use identify::{
    IdentifyController, IdentifyNamespace, PowerStateDescriptor,
    LbaFormat, RelativePerformance, IdentifyCns,
};

pub use error::NvmeError;
