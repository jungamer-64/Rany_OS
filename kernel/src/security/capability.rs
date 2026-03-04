//! POSIX-style Capabilities for ExoRust
//!
//! This module implements fine-grained capability-based access control
//! inspired by Linux capabilities.
//!
//! # 実装の関係
//!
//! - **正規版 (型・定数)**: `libs/security` クレート — `Capability`, `CapabilitySet`,
//!   `CapabilityError`, `GrantToken`, `ReclamationStatus`, 全 `CAP_*` 定数
//! - **本ファイル**: カーネル固有の `CapabilityManager`（監査ログ・カーネルタイマー・
//!   非同期デーモン連携付き）、`resource_mapping` ユーティリティ
//! - **テスト用**: `tools/cap_harness/src/lib.rs` (QEMUテスト用stub)

use alloc::format;
use alloc::vec::Vec;
use spin::Mutex;
use spin::Once;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::security::audit::{AuditEvent, AuditEventType};

extern crate alloc;

// ============================================================================
// 共通型・定数は libs/security クレートから再エクスポート
// ============================================================================
pub use security::{
    Capability,
    CapabilitySet,
    CapabilityError,
    GrantToken,
    ReclamationStatus,
    CAP_NET_BIND,
    CAP_NET_RAW,
    CAP_SYS_ADMIN,
    CAP_SYS_BOOT,
    CAP_SYS_TIME,
    CAP_SYS_PTRACE,
    CAP_DAC_OVERRIDE,
    CAP_KILL,
    CAP_SETUID,
    CAP_SETGID,
    CAP_CHOWN,
    CAP_FOWNER,
    CAP_SYS_RAWIO,
    CAP_IPC_LOCK,
    CAP_SYS_NICE,
    CAP_NET_ADMIN,
    CAP_SYS_MODULE,
    CAP_SYS_PHYSMEM,
    CAP_DMA,
    CAP_IOMMU,
    CAP_INTERRUPT,
    CAP_ALL,
    CAP_NONE,
    CAPABILITY_EXPIRY_INTERVAL_MS,
};

/// Capability bit flags
mod resource_mapping;
pub use resource_mapping::*;
mod manager_impl;

// ============================================================================
// カーネル固有の型定義（libs/security の型を拡張）
// ============================================================================

/// Per-domain capability state
struct DomainCapabilities {
    domain_id: u64,
    caps: CapabilitySet,
}

/// Capability manager (カーネル版: 監査ログ・カーネルタイマー連携付き)
///
/// 共通の型定義 (`CapabilitySet`, `CapabilityError`, `GrantToken`, `ReclamationStatus`)
/// は `libs/security` クレートに一元化されており、本構造体はカーネル固有の
/// `CapabilityManager` 実装のみを提供します。
pub struct CapabilityManager {
    /// Domain capabilities
    domains: Mutex<Vec<DomainCapabilities>>,
    /// Bounding set (maximum capabilities for any domain)
    bounding_set: Mutex<Capability>,
    /// Active grant tokens
    grants: Mutex<Vec<GrantToken>>,
    /// Next grant token id
    next_grant_id: AtomicU64,
    /// In-flight usage counters for tokens (token_id -> count) - stored as Vec to allow const init
    in_flight: Mutex<Vec<(u64, u64)>>,
    /// Test-only hook: force a failure for the next grant of a particular capability
    #[cfg(test)]
    fail_next_grant_for: Mutex<Option<Capability>>,
}
