// ============================================================================
// kernel/src/driver_cell/fault.rs - 障害分離と自動復旧
// ============================================================================
//! # ドライバセル障害管理
//!
//! 設計書 8: フォールトアイソレーションと回復メカニズム
//! 設計書 8.1: スタックアンワインドとリソース回収
//! 設計書 8.2: RedLeafの知見：プロキシパターン
//!
//! ## 障害処理フロー
//!
//! ```text
//! ドライバパニック検出
//!     │
//!     ▼
//! PoisonLock毒入れ + DOM状態更新
//!     │
//!     ▼
//! Exchange Heap上のRRefリソース回収
//!     │
//!     ▼
//! RestartPolicy判定
//!     ├─ Never → Faulted状態で放置
//!     ├─ OnPanic → リトライ数チェック → 再起動
//!     └─ Always → リトライ数チェック → 再起動
//! ```

#![allow(dead_code)]

use alloc::format;
use alloc::string::String;

use crate::domain_system::DomainId;
use crate::ipc::rref::reclaim_domain_resources;

use super::{DriverCellError, DriverCellId, DriverCellState, driver_cell_manager};

// ============================================================================
// Restart Policy
// ============================================================================

/// 再起動ポリシー
///
/// 設計書 8: ドメインクラッシュ時の回復戦略を定義
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartPolicy {
    /// 再起動しない: 障害発生時はFaulted状態で維持
    Never,
    /// パニック時のみ再起動
    OnPanic {
        /// 最大リトライ回数（0 = 無制限）
        max_retries: u32,
        /// リトライ間の待機ミリ秒（指数バックオフ）
        backoff_ms: u64,
    },
    /// 任意の障害で再起動
    Always {
        /// 最大リトライ回数（0 = 無制限）
        max_retries: u32,
        /// リトライ間の待機ミリ秒（指数バックオフ）
        backoff_ms: u64,
    },
}

impl RestartPolicy {
    /// デフォルトのOnPanicポリシー
    pub fn on_panic(max_retries: u32, backoff_ms: u64) -> Self {
        Self::OnPanic {
            max_retries,
            backoff_ms,
        }
    }

    /// デフォルトのAlwaysポリシー
    pub fn always(max_retries: u32, backoff_ms: u64) -> Self {
        Self::Always {
            max_retries,
            backoff_ms,
        }
    }

    /// 再起動が許可されているかチェック
    pub fn should_restart(&self, fault_kind: FaultKind, consecutive_faults: u32) -> bool {
        match self {
            RestartPolicy::Never => false,
            RestartPolicy::OnPanic {
                max_retries,
                ..
            } => {
                if !matches!(fault_kind, FaultKind::Panic(_)) {
                    return false;
                }
                *max_retries == 0 || consecutive_faults < *max_retries
            }
            RestartPolicy::Always {
                max_retries,
                ..
            } => *max_retries == 0 || consecutive_faults < *max_retries,
        }
    }

    /// バックオフ時間を取得（指数バックオフ）
    pub fn backoff_for_attempt(&self, attempt: u32) -> u64 {
        let base = match self {
            RestartPolicy::Never => return 0,
            RestartPolicy::OnPanic { backoff_ms, .. } => *backoff_ms,
            RestartPolicy::Always { backoff_ms, .. } => *backoff_ms,
        };
        // 指数バックオフ: base * 2^attempt (cap at 30 seconds)
        let multiplier = 1u64.checked_shl(attempt).unwrap_or(u64::MAX);
        base.saturating_mul(multiplier).min(30_000)
    }
}

impl Default for RestartPolicy {
    fn default() -> Self {
        RestartPolicy::OnPanic {
            max_retries: 3,
            backoff_ms: 100,
        }
    }
}

// ============================================================================
// Fault Kind
// ============================================================================

/// 障害の種類
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaultKind {
    /// ドライバがパニックした
    Panic(String),
    /// ドライバの初期化に失敗
    InitFailed(String),
    /// ドライバがタイムアウト
    Timeout,
    /// リソースクォータ超過
    QuotaExceeded(String),
    /// 不正なメモリアクセス
    MemoryViolation,
    /// その他のエラー
    Other(String),
}

impl core::fmt::Display for FaultKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Panic(msg) => write!(f, "Panic: {}", msg),
            Self::InitFailed(msg) => write!(f, "Init failed: {}", msg),
            Self::Timeout => write!(f, "Timeout"),
            Self::QuotaExceeded(msg) => write!(f, "Quota exceeded: {}", msg),
            Self::MemoryViolation => write!(f, "Memory violation"),
            Self::Other(msg) => write!(f, "{}", msg),
        }
    }
}

// ============================================================================
// Fault Record
// ============================================================================

/// 障害履歴レコード
#[derive(Debug, Clone)]
pub struct FaultRecord {
    /// 障害発生時刻（TSCティック）
    pub timestamp: u64,
    /// 障害の種類
    pub kind: FaultKind,
    /// 再起動の試行回数
    pub restart_attempt: u32,
    /// 再起動に成功したか
    pub restart_succeeded: bool,
}

impl FaultRecord {
    /// 新しい障害レコードを作成
    pub fn new(kind: FaultKind, restart_attempt: u32) -> Self {
        Self {
            timestamp: crate::task::timer::current_tick(),
            kind,
            restart_attempt,
            restart_succeeded: false,
        }
    }
}

// ============================================================================
// Fault Handler
// ============================================================================

/// DriverCellの障害を処理
///
/// 設計書 8.1: リソース回収フロー
/// 1. ドメインの状態を記録
/// 2. Exchange Heap上のRRefリソースを回収
/// 3. RestartPolicyに基づき自動復旧を試みる
pub fn handle_fault(
    id: DriverCellId,
    fault_kind: FaultKind,
) -> Result<FaultAction, DriverCellError> {
    let manager = driver_cell_manager();

    // 障害情報を記録
    let (restart_policy, consecutive, domain_id) = manager.with_cell_mut(id, |cell| {
        cell.consecutive_faults += 1;
        let consecutive = cell.consecutive_faults;

        let record = FaultRecord::new(fault_kind.clone(), consecutive);
        cell.fault_history.push(record);

        cell.transition_to(DriverCellState::Faulted);
        cell.stats.record_fault();

        (cell.restart_policy, consecutive, cell.domain_id)
    })?;

    let name = manager.with_cell(id, |cell| cell.name.clone())?;

    log::info!(
        "[DriverCell] Fault in '{}': {} (consecutive: {})\n",
        name,
        fault_kind,
        consecutive
    );

    // ドメインのリソースを回収
    if let Some(did) = domain_id {
        reclaim_domain_resources(did);
        crate::domain_system::handle_domain_panic(
            did,
            format!("DriverCell fault: {}", fault_kind),
        );
    }

    // ドライバを停止（可能なら）
    stop_drivers_for_cell(id);

    // 再起動ポリシーを評価
    if restart_policy.should_restart(fault_kind.clone(), consecutive) {
        let backoff = restart_policy.backoff_for_attempt(consecutive.saturating_sub(1));

        log::info!(
            "[DriverCell] Scheduling restart for '{}' (attempt {}, backoff {}ms)\n",
            name,
            consecutive,
            backoff
        );

        // 再起動を実行
        match attempt_restart(id) {
            Ok(()) => {
                // 障害レコードを更新
                manager.with_cell_mut(id, |cell| {
                    if let Some(last) = cell.fault_history.last_mut() {
                        last.restart_succeeded = true;
                    }
                })?;
                Ok(FaultAction::Restarted)
            }
            Err(e) => {
                log::warn!(
                    "[DriverCell] Restart failed for '{}': {}\n",
                    name,
                    e
                );
                Ok(FaultAction::RestartFailed(format!("{}", e)))
            }
        }
    } else {
        log::info!(
            "[DriverCell] No restart for '{}' (policy: {:?}, faults: {})\n",
            name,
            restart_policy,
            consecutive
        );
        Ok(FaultAction::Stopped)
    }
}

/// パニックハンドラからDriverCellの障害を通知
///
/// パニックハンドラ → Domain → DriverCell の連携
pub fn notify_domain_panic(domain_id: DomainId, message: String) {
    let manager = driver_cell_manager();

    // DomainIDからDriverCellを検索
    if let Some(cell_id) = manager.find_by_domain(domain_id) {
        let fault = FaultKind::Panic(message);
        if let Err(e) = handle_fault(cell_id, fault) {
            log::error!(
                "[DriverCell] Failed to handle fault for domain {}: {}\n",
                domain_id,
                e
            );
        }
    }
}

/// DriverCellの全ドライバを停止（障害処理用）
fn stop_drivers_for_cell(id: DriverCellId) {
    let manager = driver_cell_manager();
    let handles = match manager.with_cell(id, |cell| cell.driver_handles.clone()) {
        Ok(h) => h,
        Err(_) => return,
    };

    let registry = crate::driver_registry::driver_registry();
    for handle in &handles {
        if let Err(e) = registry.stop(*handle) {
            log::warn!(
                "[DriverCell] Force stop driver {:?} failed: {}\n",
                handle.index(),
                e
            );
        }
    }
}

/// DriverCellの再起動を試行
///
/// 設計書 8.1: 再起動フロー
/// 1. 古いドライバをunregister
/// 2. Domainの状態をリセット
/// 3. CellのエントリポイントからドライバをRe-register
/// 4. probe + start
fn attempt_restart(id: DriverCellId) -> Result<(), DriverCellError> {
    let manager = driver_cell_manager();

    manager.with_cell_mut(id, |cell| {
        cell.transition_to(DriverCellState::Restarting);
    })?;

    // 古いドライバをunregister
    let old_handles = manager.with_cell(id, |cell| cell.driver_handles.clone())?;
    for handle in &old_handles {
        let registry = crate::driver_registry::driver_registry();
        let _ = registry.unregister(*handle);
    }

    // DriverCell内のハンドルリストをクリア
    manager.with_cell_mut(id, |cell| {
        cell.driver_handles.clear();
    })?;

    // Domainの状態をリセット
    let domain_id = manager.with_cell(id, |cell| cell.domain_id)?;
    if let Some(did) = domain_id {
        crate::domain_system::resume_domain(did).ok();
    }

    // セルからドライバを再登録
    let cell_id = manager.with_cell(id, |cell| cell.cell_id)?;
    let cell_id = cell_id.ok_or(DriverCellError::LoadFailed(
        "No cell loaded for restart".into(),
    ))?;

    let handle = match crate::loader::register_driver_from_cell(cell_id) {
        Ok(h) => h,
        Err(e) => {
            let msg = format!("{}", e);
            manager.with_cell_mut(id, |cell| {
                cell.transition_to(DriverCellState::Faulted);
            }).ok();
            return Err(DriverCellError::DriverInitFailed(msg));
        }
    };

    // probe + start
    let registry = crate::driver_registry::driver_registry();
    if let Err(e) = registry.probe_and_start(handle) {
        let msg = format!("{}", e);
        manager.with_cell_mut(id, |cell| {
            cell.transition_to(DriverCellState::Faulted);
        }).ok();
        return Err(DriverCellError::DriverInitFailed(msg));
    }

    // DomainをRunningに
    if let Some(did) = domain_id {
        crate::domain_system::start_domain(did).ok();
    }

    // DriverCellをRunningに
    manager.with_cell_mut(id, |cell| {
        cell.add_driver_handle(handle);
        cell.transition_to(DriverCellState::Running);
        cell.stats.record_restart();
    })?;

    let name = manager.with_cell(id, |cell| cell.name.clone())?;
    log::info!("[DriverCell] Restarted: {}\n", name);

    Ok(())
}

// ============================================================================
// Fault Action
// ============================================================================

/// 障害処理の結果アクション
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaultAction {
    /// 再起動に成功した
    Restarted,
    /// 再起動に失敗した
    RestartFailed(String),
    /// 停止のまま（再起動なし）
    Stopped,
}

impl core::fmt::Display for FaultAction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Restarted => write!(f, "Restarted"),
            Self::RestartFailed(msg) => write!(f, "Restart failed: {}", msg),
            Self::Stopped => write!(f, "Stopped (no restart)"),
        }
    }
}
