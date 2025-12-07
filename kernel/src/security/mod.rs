// ============================================================================
// src/security/mod.rs - Security Framework
// 設計書 9: セキュリティと攻撃対象領域 (TCB) の最小化
// ============================================================================
//!
//! # セキュリティフレームワーク
//!
//! ExoRustのセキュリティモデルは、以下の原則に基づいています：
//!
//! ## 設計原則
//! 1. **静的ケイパビリティ**: ランタイムチェックではなく型システムで保証
//! 2. コンパイラベースのセキュリティ（Rust型システム）
//! 3. TCB（Trusted Computing Base）の最小化
//! 4. Spectre/Meltdown緩和策
//! 5. ゼロコピー通信の安全性保証
//!
//! ## 設計変更 (v0.3.0)
//! - MAC（強制アクセス制御）の実行時チェックを排除
//! - 静的ケイパビリティベースのアクセス制御に移行
//! - 監査ログをオプション（デバッグビルドのみ）に
//!
//! ## 攻撃対策
//! - バッファオーバーフロー排除（Rust境界チェック）
//! - Type Confusion防止（強い型システム）
//! - サイドチャネル攻撃緩和

#![allow(dead_code)]

// Submodules
pub mod audit;
pub mod capability;
pub mod mac;
pub mod policy;
pub mod static_capability; // 新: 静的ケイパビリティシステム

// Re-export static capability system (preferred API)

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

// ============================================================================
// ドメインセキュリティコンテキスト
// ============================================================================

/// ドメインのセキュリティ権限
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityCapabilities {
    /// カーネルAPI呼び出し許可
    pub can_call_kernel_api: bool,
    /// メモリマップ許可
    pub can_map_memory: bool,
    /// I/Oポートアクセス許可
    pub can_access_io: bool,
    /// 割り込み登録許可
    pub can_register_interrupts: bool,
    /// 他ドメインへのIPC許可
    pub can_ipc: bool,
    /// unsafeコード実行許可（検証済みのみ）
    pub allows_unsafe: bool,
    /// ネットワークアクセス許可
    pub can_network: bool,
    /// ファイルシステムアクセス許可
    pub can_filesystem: bool,
}

impl SecurityCapabilities {
    /// 最小権限（サンドボックス）
    pub const SANDBOXED: Self = Self {
        can_call_kernel_api: false,
        can_map_memory: false,
        can_access_io: false,
        can_register_interrupts: false,
        can_ipc: false,
        allows_unsafe: false,
        can_network: false,
        can_filesystem: false,
    };

    /// ユーザーアプリケーション
    pub const USER_APP: Self = Self {
        can_call_kernel_api: true,
        can_map_memory: false,
        can_access_io: false,
        can_register_interrupts: false,
        can_ipc: true,
        allows_unsafe: false,
        can_network: true,
        can_filesystem: true,
    };

    /// ドライバドメイン
    pub const DRIVER: Self = Self {
        can_call_kernel_api: true,
        can_map_memory: true,
        can_access_io: true,
        can_register_interrupts: true,
        can_ipc: true,
        allows_unsafe: true,
        can_network: false,
        can_filesystem: false,
    };

    /// カーネルドメイン（全権限）
    pub const KERNEL: Self = Self {
        can_call_kernel_api: true,
        can_map_memory: true,
        can_access_io: true,
        can_register_interrupts: true,
        can_ipc: true,
        allows_unsafe: true,
        can_network: true,
        can_filesystem: true,
    };
}

impl Default for SecurityCapabilities {
    fn default() -> Self {
        Self::SANDBOXED
    }
}

// ============================================================================
// セキュリティレベル
// ============================================================================

/// セキュリティレベル（信頼度）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum SecurityLevel {
    /// 未検証（サンドボックス化）
    Untrusted = 0,
    /// 基本検証済み（Safe Rustのみ）
    SafeRust = 1,
    /// 監査済みunsafe
    AuditedUnsafe = 2,
    /// フレームワークコード
    Framework = 3,
    /// カーネルコア
    KernelCore = 4,
}

impl SecurityLevel {
    /// このレベルが他のレベル以上の権限を持つか
    pub fn has_privilege_over(&self, other: SecurityLevel) -> bool {
        (*self as u8) >= (other as u8)
    }
}

// ============================================================================
// アクセス制御マネージャ
// ============================================================================

/// ドメイン間アクセス制御
pub struct AccessControlManager {
    /// ドメインごとの権限マップ
    domain_caps: Mutex<Vec<(u64, SecurityCapabilities)>>,
    /// セキュリティ違反カウント
    violations: AtomicU64,
    /// 監査ログ有効化
    audit_enabled: AtomicBool,
}

impl AccessControlManager {
    /// 新しいマネージャを作成
    pub const fn new() -> Self {
        Self {
            domain_caps: Mutex::new(Vec::new()),
            violations: AtomicU64::new(0),
            audit_enabled: AtomicBool::new(true),
        }
    }

    /// ドメインの権限を設定
    pub fn set_capabilities(&self, domain_id: u64, caps: SecurityCapabilities) {
        let mut caps_map = self.domain_caps.lock();

        // 既存エントリを更新または追加
        if let Some(entry) = caps_map.iter_mut().find(|(id, _)| *id == domain_id) {
            entry.1 = caps;
        } else {
            caps_map.push((domain_id, caps));
        }
    }

    /// ドメインの権限を取得
    pub fn get_capabilities(&self, domain_id: u64) -> SecurityCapabilities {
        self.domain_caps
            .lock()
            .iter()
            .find(|(id, _)| *id == domain_id)
            .map(|(_, caps)| *caps)
            .unwrap_or(SecurityCapabilities::SANDBOXED)
    }

    /// 権限チェック
    pub fn check_permission(
        &self,
        domain_id: u64,
        required: SecurityCapabilities,
    ) -> Result<(), SecurityViolation> {
        let actual = self.get_capabilities(domain_id);

        // 各権限をチェック
        if required.can_call_kernel_api && !actual.can_call_kernel_api {
            return self.violation(domain_id, "kernel API call");
        }
        if required.can_map_memory && !actual.can_map_memory {
            return self.violation(domain_id, "memory mapping");
        }
        if required.can_access_io && !actual.can_access_io {
            return self.violation(domain_id, "I/O access");
        }
        if required.can_register_interrupts && !actual.can_register_interrupts {
            return self.violation(domain_id, "interrupt registration");
        }
        if required.can_ipc && !actual.can_ipc {
            return self.violation(domain_id, "IPC");
        }
        if required.allows_unsafe && !actual.allows_unsafe {
            return self.violation(domain_id, "unsafe code");
        }
        if required.can_network && !actual.can_network {
            return self.violation(domain_id, "network access");
        }
        if required.can_filesystem && !actual.can_filesystem {
            return self.violation(domain_id, "filesystem access");
        }

        Ok(())
    }

    /// セキュリティ違反を記録
    fn violation(&self, domain_id: u64, operation: &str) -> Result<(), SecurityViolation> {
        self.violations.fetch_add(1, Ordering::Relaxed);

        if self.audit_enabled.load(Ordering::Relaxed) {
            crate::log!(
                "[SECURITY] Violation: domain {} attempted {}\n",
                domain_id,
                operation
            );
        }

        Err(SecurityViolation {
            domain_id,
            operation: operation.into(),
        })
    }

    /// 違反カウントを取得
    pub fn violation_count(&self) -> u64 {
        self.violations.load(Ordering::Relaxed)
    }
}

/// セキュリティ違反
#[derive(Debug, Clone)]
pub struct SecurityViolation {
    pub domain_id: u64,
    pub operation: alloc::string::String,
}

impl core::fmt::Display for SecurityViolation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Security violation: domain {} attempted unauthorized {}",
            self.domain_id, self.operation
        )
    }
}

// ============================================================================
// ゼロコピー転送のセキュリティバリア
// ============================================================================

/// ゼロコピー転送のセキュリティチェック
pub struct ZeroCopySecurityBarrier {
    /// 転送されたバイト数（統計）
    bytes_transferred: AtomicU64,
    /// 拒否された転送数
    transfers_denied: AtomicU64,
}

impl ZeroCopySecurityBarrier {
    /// 新しいバリアを作成
    pub const fn new() -> Self {
        Self {
            bytes_transferred: AtomicU64::new(0),
            transfers_denied: AtomicU64::new(0),
        }
    }

    /// ドメイン間転送のセキュリティチェック
    pub fn check_transfer(
        &self,
        from_domain: u64,
        to_domain: u64,
        ptr: usize,
        size: usize,
    ) -> Result<(), TransferSecurityError> {
        // 1. ポインタの妥当性チェック
        if ptr == 0 {
            self.transfers_denied.fetch_add(1, Ordering::Relaxed);
            return Err(TransferSecurityError::NullPointer);
        }

        // 2. サイズの妥当性チェック（極端に大きいサイズを拒否）
        const MAX_TRANSFER_SIZE: usize = 1 << 30; // 1GB
        if size > MAX_TRANSFER_SIZE {
            self.transfers_denied.fetch_add(1, Ordering::Relaxed);
            return Err(TransferSecurityError::SizeTooLarge);
        }

        // 3. ドメインIDの妥当性
        if from_domain == to_domain {
            // 同一ドメイン内転送は常にOK
            self.bytes_transferred
                .fetch_add(size as u64, Ordering::Relaxed);
            return Ok(());
        }

        // 4. アドレス範囲のオーバーフローチェック
        if ptr.checked_add(size).is_none() {
            self.transfers_denied.fetch_add(1, Ordering::Relaxed);
            return Err(TransferSecurityError::AddressOverflow);
        }

        // 5. 転送を許可
        self.bytes_transferred
            .fetch_add(size as u64, Ordering::Relaxed);
        Ok(())
    }

    /// 統計を取得
    pub fn stats(&self) -> ZeroCopyStats {
        ZeroCopyStats {
            bytes_transferred: self.bytes_transferred.load(Ordering::Relaxed),
            transfers_denied: self.transfers_denied.load(Ordering::Relaxed),
        }
    }
}

/// ゼロコピー統計
#[derive(Debug, Clone)]
pub struct ZeroCopyStats {
    pub bytes_transferred: u64,
    pub transfers_denied: u64,
}

/// 転送セキュリティエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferSecurityError {
    /// NULLポインタ
    NullPointer,
    /// サイズが大きすぎる
    SizeTooLarge,
    /// アドレスオーバーフロー
    AddressOverflow,
    /// ドメインがアクセス権を持たない
    AccessDenied,
}

impl core::fmt::Display for TransferSecurityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NullPointer => write!(f, "Null pointer in transfer"),
            Self::SizeTooLarge => write!(f, "Transfer size too large"),
            Self::AddressOverflow => write!(f, "Address overflow in transfer"),
            Self::AccessDenied => write!(f, "Access denied for transfer"),
        }
    }
}

// ============================================================================
// TCBサイズ追跡
// ============================================================================

/// TCB（Trusted Computing Base）追跡
pub struct TcbTracker {
    /// unsafeブロック数
    unsafe_blocks: AtomicU64,
    /// unsafeを含む関数数
    unsafe_functions: AtomicU64,
    /// フレームワークコード行数
    framework_loc: AtomicU64,
    /// 安全コード行数
    safe_loc: AtomicU64,
}

impl TcbTracker {
    /// 新しいトラッカーを作成
    pub const fn new() -> Self {
        Self {
            unsafe_blocks: AtomicU64::new(0),
            unsafe_functions: AtomicU64::new(0),
            framework_loc: AtomicU64::new(0),
            safe_loc: AtomicU64::new(0),
        }
    }

    /// unsafeブロックを登録
    pub fn register_unsafe_block(&self) {
        self.unsafe_blocks.fetch_add(1, Ordering::Relaxed);
    }

    /// unsafe関数を登録
    pub fn register_unsafe_function(&self) {
        self.unsafe_functions.fetch_add(1, Ordering::Relaxed);
    }

    /// TCB比率を計算（%）
    pub fn tcb_ratio(&self) -> f32 {
        let framework = self.framework_loc.load(Ordering::Relaxed) as f32;
        let safe = self.safe_loc.load(Ordering::Relaxed) as f32;
        let total = framework + safe;

        if total > 0.0 {
            (framework / total) * 100.0
        } else {
            0.0
        }
    }

    /// 統計を取得
    pub fn stats(&self) -> TcbStats {
        TcbStats {
            unsafe_blocks: self.unsafe_blocks.load(Ordering::Relaxed),
            unsafe_functions: self.unsafe_functions.load(Ordering::Relaxed),
            framework_loc: self.framework_loc.load(Ordering::Relaxed),
            safe_loc: self.safe_loc.load(Ordering::Relaxed),
        }
    }
}

/// TCB統計
#[derive(Debug, Clone)]
pub struct TcbStats {
    pub unsafe_blocks: u64,
    pub unsafe_functions: u64,
    pub framework_loc: u64,
    pub safe_loc: u64,
}

// ============================================================================
// セキュリティ監査ログ
// ============================================================================

/// 監査イベントの種類
#[derive(Debug, Clone, Copy)]
pub enum AuditEventType {
    /// ドメイン作成
    DomainCreated,
    /// ドメイン終了
    DomainTerminated,
    /// 権限昇格試行
    PrivilegeEscalationAttempt,
    /// IPC転送
    IpcTransfer,
    /// メモリマップ
    MemoryMap,
    /// 割り込み登録
    InterruptRegistration,
    /// セキュリティ違反
    SecurityViolation,
}

/// 監査イベント
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// タイムスタンプ（ティック）
    pub timestamp: u64,
    /// イベント種類
    pub event_type: AuditEventType,
    /// ドメインID
    pub domain_id: u64,
    /// 詳細情報
    pub details: Option<alloc::string::String>,
}

/// 監査ログ
pub struct AuditLog {
    /// イベントバッファ
    events: Mutex<Vec<AuditEvent>>,
    /// 最大イベント数
    max_events: usize,
    /// 有効化フラグ
    enabled: AtomicBool,
}

impl AuditLog {
    /// 新しい監査ログを作成
    pub const fn new(max_events: usize) -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            max_events,
            enabled: AtomicBool::new(true),
        }
    }

    /// イベントを記録
    pub fn log(&self, event: AuditEvent) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }

        let mut events = self.events.lock();

        // 最大数を超えたら古いイベントを削除
        if events.len() >= self.max_events {
            events.remove(0);
        }

        events.push(event);
    }

    /// イベントを取得
    pub fn get_events(&self) -> Vec<AuditEvent> {
        self.events.lock().clone()
    }

    /// ログをクリア
    pub fn clear(&self) {
        self.events.lock().clear();
    }

    /// 有効化/無効化
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }
}

// ============================================================================
// グローバルインスタンス
// ============================================================================

/// グローバルアクセス制御マネージャ
static ACCESS_CONTROL: AccessControlManager = AccessControlManager::new();

/// グローバルゼロコピーセキュリティバリア
static ZERO_COPY_BARRIER: ZeroCopySecurityBarrier = ZeroCopySecurityBarrier::new();

/// グローバルTCBトラッカー
static TCB_TRACKER: TcbTracker = TcbTracker::new();

/// グローバル監査ログ
static AUDIT_LOG: AuditLog = AuditLog::new(1000);

/// アクセス制御マネージャを取得
pub fn access_control() -> &'static AccessControlManager {
    &ACCESS_CONTROL
}

/// ゼロコピーセキュリティバリアを取得
pub fn zero_copy_barrier() -> &'static ZeroCopySecurityBarrier {
    &ZERO_COPY_BARRIER
}

/// TCBトラッカーを取得
pub fn tcb_tracker() -> &'static TcbTracker {
    &TCB_TRACKER
}

/// 監査ログを取得
pub fn audit_log() -> &'static AuditLog {
    &AUDIT_LOG
}

/// セキュリティサブシステムを初期化
pub fn init() {
    // カーネルドメイン（ID=0）の権限を設定
    ACCESS_CONTROL.set_capabilities(0, SecurityCapabilities::KERNEL);

    crate::log!("[SECURITY] Security framework initialized\n");
    crate::log!("[SECURITY] Audit logging: enabled\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_capabilities() {
        let sandboxed = SecurityCapabilities::SANDBOXED;
        assert!(!sandboxed.can_call_kernel_api);
        assert!(!sandboxed.can_ipc);

        let user = SecurityCapabilities::USER_APP;
        assert!(user.can_call_kernel_api);
        assert!(user.can_ipc);
        assert!(!user.allows_unsafe);
    }

    #[test]
    fn test_security_level() {
        assert!(SecurityLevel::KernelCore.has_privilege_over(SecurityLevel::Framework));
        assert!(SecurityLevel::Framework.has_privilege_over(SecurityLevel::SafeRust));
        assert!(!SecurityLevel::SafeRust.has_privilege_over(SecurityLevel::AuditedUnsafe));
    }

    #[test]
    fn test_zero_copy_barrier() {
        let barrier = ZeroCopySecurityBarrier::new();

        // 正常な転送
        assert!(barrier.check_transfer(1, 2, 0x1000, 4096).is_ok());

        // NULLポインタ
        assert_eq!(
            barrier.check_transfer(1, 2, 0, 100),
            Err(TransferSecurityError::NullPointer)
        );

        // 大きすぎるサイズ
        assert_eq!(
            barrier.check_transfer(1, 2, 0x1000, 2 << 30),
            Err(TransferSecurityError::SizeTooLarge)
        );
    }
}
