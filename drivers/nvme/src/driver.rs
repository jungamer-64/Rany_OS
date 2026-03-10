// ============================================================================
// src/io/nvme/driver.rs - NVMe Driver Re-exports
// ============================================================================
//!
//! # NVMeドライバ再エクスポート
//!
//! driver.rsは分割されました。このファイルは後方互換性のための
//! 再エクスポートを提供します。
//!
//! ## 分割されたモジュール
//! - `queue`: SQ/CQ/QueuePairの低レベル実装
//! - `per_core`: コアごとのキュー管理
//! - `polling_driver`: メインポーリングドライバ
//! - `async_io`: 非同期I/Oサポート
//! - `error`: エラー型
//! - `global`: グローバルインスタンス
//! - `scheduler`: IoScheduler統合

#![allow(dead_code)]
#![allow(unused_imports)]

// ============================================================================
// Re-exports from queue.rs
// ============================================================================
// Removed: compatibility re-export. Import `nvme_driver::queue::CompletionQueue`,
// `nvme_driver::queue::QueuePair`, and `nvme_driver::queue::SubmissionQueue` directly.

// ============================================================================
// Re-exports from per_core.rs
// ============================================================================
// Removed: compatibility re-export. Import `nvme_driver::per_core::NvmeQueueStats` and
// `nvme_driver::per_core::PerCoreNvmeQueue` directly.

// ============================================================================
// Re-exports from polling_driver.rs
// ============================================================================
// Removed: compatibility re-export. Import `nvme_driver::polling_driver::NvmeDriverStats` and
// `nvme_driver::polling_driver::NvmePollingDriver` directly.

// ============================================================================
// Re-exports from async_io.rs
// ============================================================================
// Removed: compatibility re-export. Import async I/O types/functions directly from
// `nvme_driver::async_io` (e.g., `nvme_driver::async_io::AsyncIoRequest`).

// ============================================================================
// Re-exports from error.rs
// ============================================================================
// Removed: compatibility re-export. Import `nvme_driver::error::NvmeError` directly.

// ============================================================================
// Re-exports from global.rs
// ============================================================================
// Removed: compatibility re-export. Import global helpers from `nvme_driver::global` directly (e.g., `nvme_driver::global::init`).

// ============================================================================
// Re-exports from scheduler.rs
// ============================================================================
// Removed: compatibility re-export. Import `nvme_driver::scheduler::register_with_io_scheduler` or
// `nvme_driver::scheduler::NvmePollHandler` directly.

// ============================================================================
// Re-exports from commands.rs (for backward compatibility)
// ============================================================================
// Removed: compatibility re-export. Use `nvme_driver::commands::{NvmeCommand, NvmeCompletion}` directly.

// ============================================================================
// Tests
// ============================================================================
