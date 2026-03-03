// ============================================================================
// domain_system/types.rs - ドメイン関連の基本型定義
// ============================================================================
//!
//! ドメインシステムで使用される基本型（`DomainId`, `DomainState`,
//! `CpuQuotaAction`, `DomainCredentials`, `DomainSecurity`, `RequestedCap`）
//! とその実装を集約するモジュール。

use alloc::sync::Arc;
use crate::security::CapabilitySet;
use spin::Once;

// ============================================================================
// CPU クォータ定数・アクション
// ============================================================================

pub const CPU_QUOTA_SUSPEND_STREAK: u8 = 3;
pub const CPU_QUOTA_SUSPEND_WINDOW_NS: u64 = 100_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuQuotaAction {
    None,
    YieldDemote,
    Suspend { until_ns: u64 },
}

// ============================================================================
// ドメインID
// ============================================================================

/// ドメインを一意に識別するID
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainId(u64);

impl DomainId {
    /// 新しいドメインIDを作成
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// IDを数値として取得
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// カーネルドメイン（常にID=0）
    pub const KERNEL: DomainId = DomainId(0);
}

impl core::fmt::Display for DomainId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Domain({})", self.0)
    }
}

// ============================================================================
// ドメイン状態
// ============================================================================

/// ドメインのライフサイクル状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainState {
    /// 初期化中
    Initializing,
    /// 実行中
    Running,
    /// 一時停止
    Suspended,
    /// 停止（エラーで）
    Stopped,
    /// 終了済み（リソース回収完了）
    Terminated,
}

impl DomainState {
    /// 実行可能な状態かどうか
    pub fn is_runnable(&self) -> bool {
        matches!(self, DomainState::Running | DomainState::Initializing)
    }

    /// アクティブな状態かどうか（リソースを保持）
    pub fn is_active(&self) -> bool {
        !matches!(self, DomainState::Terminated)
    }
}

// ============================================================================
// ドメインセキュリティ
// ============================================================================

/// ドメイン主体の資格情報
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainCredentials {
    pub uid: u32,
    pub gid: u32,
}

impl DomainCredentials {
    pub const ROOT: Self = Self { uid: 0, gid: 0 };

    pub const fn new(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }
}

/// ドメイン主体の権限情報
#[derive(Debug, Clone)]
pub struct DomainSecurity {
    pub credentials: DomainCredentials,
    pub caps: CapabilitySet,
}

impl DomainSecurity {
    pub fn kernel() -> Self {
        Self {
            credentials: DomainCredentials::ROOT,
            caps: CapabilitySet::full(),
        }
    }
}

impl Default for DomainSecurity {
    fn default() -> Self {
        Self {
            credentials: DomainCredentials::ROOT,
            caps: CapabilitySet::empty(),
        }
    }
}

pub(crate) fn kernel_security_handle() -> Arc<DomainSecurity> {
    static KERNEL_SECURITY: Once<Arc<DomainSecurity>> = Once::new();
    KERNEL_SECURITY
        .call_once(|| Arc::new(DomainSecurity::kernel()))
        .clone()
}

/// Requested capability descriptor used by `spawn_domain_with_caps`.
#[derive(Debug, Clone, Copy)]
pub struct RequestedCap {
    pub cap: u64,
    pub expires: Option<u64>,
    pub delegatable: bool,
}
