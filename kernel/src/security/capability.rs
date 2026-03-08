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

use crate::security::audit::{AuditEvent, AuditEventType};
use crate::sync::PoisonLock;
use alloc::format;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Once;

extern crate alloc;

// ============================================================================
// 共通型・定数は libs/security クレートから再エクスポート
// ============================================================================
pub use security::{
    CAP_ALL, CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DMA, CAP_FOWNER, CAP_INTERRUPT, CAP_IOMMU,
    CAP_IPC_LOCK, CAP_KILL, CAP_NET_ADMIN, CAP_NET_BIND, CAP_NET_RAW, CAP_NONE, CAP_SETGID,
    CAP_SETUID, CAP_SYS_ADMIN, CAP_SYS_BOOT, CAP_SYS_MODULE, CAP_SYS_NICE, CAP_SYS_PHYSMEM,
    CAP_SYS_PTRACE, CAP_SYS_RAWIO, CAP_SYS_TIME, CAPABILITY_EXPIRY_INTERVAL_MS, Capability,
    CapabilityError, CapabilitySet, GrantToken, ReclamationStatus,
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
pub struct CapabilityManager {
    /// Domain capabilities
    domains: PoisonLock<Vec<DomainCapabilities>>,
    /// Bounding set (maximum capabilities for any domain)
    bounding_set: PoisonLock<Capability>,
    /// Active grant tokens
    grants: PoisonLock<Vec<GrantToken>>,
    /// Next grant token id
    next_grant_id: AtomicU64,
    /// In-flight usage counters for tokens (token_id -> count)
    in_flight: PoisonLock<Vec<(u64, u64)>>,
    /// Test-only hook: force a failure for the next grant of a particular capability
    #[cfg(test)]
    fail_next_grant_for: PoisonLock<Option<Capability>>,
}
