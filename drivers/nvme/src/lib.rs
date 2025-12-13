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
pub mod commands;
pub mod defs;
pub mod error;
pub mod identify;
pub mod queue_types;
pub mod regs;

// Modules migrated from kernel
// Modules migrated from kernel
pub mod controller;
pub mod per_core;
pub mod queue;

// Modules with kernel deps - excluded for now
pub mod driver_impl;
pub mod polling_driver; // Uncommented and refactored // New wrapper

// pub mod async_io;
// pub mod global;
// pub mod scheduler;
// pub mod driver;

// Re-exports
pub use defs::{
    ADMIN_QUEUE_DEPTH, AdminOpcode, CACHE_LINE_SIZE, CONTROLLER_READY_TIMEOUT_MS, CQE_SIZE,
    DEFAULT_QUEUE_DEPTH, DOORBELL_BATCH_THRESHOLD, IoOpcode, MAX_QUEUE_DEPTH, MAX_TRANSFER_SIZE,
    NvmeError as DefsNvmeError, NvmeStatus, PAGE_SIZE, POLL_BATCH_SIZE, PrpEntry, PrpList,
    SECTOR_SIZE, SQE_SIZE, SglDescriptor, SglType,
};

pub use commands::{NvmeCommand, NvmeCompletion};

pub use regs::{
    CmbLocation, CmbSize, NvmeAdminQueueAttributes, NvmeCapabilities, NvmeControllerConfig,
    NvmeControllerStatus, cc_bits, csts_bits, offsets,
};

pub use identify::{
    IdentifyCns, IdentifyController, IdentifyNamespace, LbaFormat, PowerStateDescriptor,
    RelativePerformance,
};

pub use error::NvmeError;
