// ============================================================================
// kernel/src/driver_domain/fault.rs - 障害分離と自動復旧
// ============================================================================
//! # ドライバドメイン障害管理
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
use alloc::format;
use alloc::string::String;

use crate::domain::DomainId;

use super::{
    DriverDomainError, DriverDomainId, DriverDomainState, HotSwapState, driver_domain_manager,
};

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
            RestartPolicy::OnPanic { max_retries, .. } => {
                if !matches!(fault_kind, FaultKind::Panic(_)) {
                    return false;
                }
                *max_retries == 0 || consecutive_faults <= *max_retries
            }
            RestartPolicy::Always { max_retries, .. } => {
                *max_retries == 0 || consecutive_faults <= *max_retries
            }
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
            timestamp: crate::task::current_tick(),
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
    id: DriverDomainId,
    fault_kind: FaultKind,
) -> Result<FaultAction, DriverDomainError> {
    crate::io::log::early_print("[DCF] handle_fault: enter\n");
    let manager = driver_domain_manager();

    // 障害情報を記録
    let (restart_policy, consecutive, domain_id, hot_swap_state, cell_id) =
        manager.with_cell_mut(id, |cell| {
            cell.consecutive_faults += 1;
            let consecutive = cell.consecutive_faults;

            let record = FaultRecord::new(fault_kind.clone(), consecutive);
            cell.fault_history.push(record);

            cell.transition_to(DriverDomainState::Faulted);
            cell.stats.record_fault();

            (
                cell.restart_policy,
                consecutive,
                cell.domain_id,
                cell.hot_swap_state,
                cell.cell_id,
            )
        })?;
    super::stats::global_stats().on_fault();

    let name = manager.with_cell(id, |cell| cell.name.clone())?;
    crate::io::log::early_print("[DCF] handle_fault: recorded\n");

    log::info!(
        "[DriverDomain] Fault in '{}': {} (consecutive: {})\n",
        name,
        fault_kind,
        consecutive
    );

    // ドメインのリソースを回収
    if let Some(did) = domain_id {
        crate::io::log::early_print("[DCF] handle_fault: domain panic begin\n");
        crate::domain::handle_domain_panic(did, format!("DriverDomain fault: {}", fault_kind));
        crate::io::log::early_print("[DCF] handle_fault: domain panic done\n");
    }

    // ドライバを停止（可能なら）
    crate::io::log::early_print("[DCF] handle_fault: stop drivers begin\n");
    stop_drivers_for_cell(id);
    crate::io::log::early_print("[DCF] handle_fault: stop drivers done\n");

    // ホットスワップ検証中の障害は、再起動より先にロールバックを優先
    if hot_swap_state == HotSwapState::Validating {
        crate::io::log::early_print("[DCF] handle_fault: validating rollback path\n");
        if let Some(cid) = cell_id {
            crate::io::log::early_print("[DCF] handle_fault: mark health failure\n");
            let _ = crate::loader::live_update::live_update_manager().mark_health_failure(
                cid.as_u64(),
                format!("Fault during validation: {}", fault_kind),
            );
        }

        crate::io::log::early_print("[DCF] handle_fault: rollback begin\n");
        match super::hot_swap::rollback(id) {
            Ok(()) => {
                crate::io::log::early_print("[DCF] handle_fault: rollback ok\n");
                return Ok(FaultAction::RolledBack);
            }
            Err(e) => {
                crate::io::log::early_print("[DCF] handle_fault: rollback err\n");
                log::warn!("[DriverDomain] Validation rollback failed: {}\n", e);
                return Ok(FaultAction::RollbackFailed(format!("{}", e)));
            }
        }
    }

    // 再起動ポリシーを評価
    if restart_policy.should_restart(fault_kind.clone(), consecutive) {
        let backoff = restart_policy.backoff_for_attempt(consecutive.saturating_sub(1));

        log::info!(
            "[DriverDomain] Scheduling restart for '{}' (attempt {}, backoff {}ms)\n",
            name,
            consecutive,
            backoff
        );

        spin_wait_ticks(backoff);

        // 再起動を実行
        match attempt_restart(id) {
            Ok(()) => {
                super::stats::global_stats().on_restart_succeeded();
                // 障害レコードを更新
                manager.with_cell_mut(id, |cell| {
                    if let Some(last) = cell.fault_history.last_mut() {
                        last.restart_succeeded = true;
                    }
                })?;
                Ok(FaultAction::Restarted)
            }
            Err(e) => {
                super::stats::global_stats().on_restart_failed();
                log::warn!("[DriverDomain] Restart failed for '{}': {}\n", name, e);
                Ok(FaultAction::RestartFailed(format!("{}", e)))
            }
        }
    } else {
        log::info!(
            "[DriverDomain] No restart for '{}' (policy: {:?}, faults: {})\n",
            name,
            restart_policy,
            consecutive
        );
        Ok(FaultAction::Stopped)
    }
}

/// パニックハンドラからDriverCellの障害を通知
///
/// パニックハンドラ → Domain → DriverDomain の連携
pub fn notify_domain_panic(domain_id: DomainId, message: String) {
    if let Err(e) = notify_domain_panic_inner(domain_id, message) {
        log::error!(
            "[DriverDomain] Failed to handle fault for domain {}: {}\n",
            domain_id,
            e
        );
    }
}

fn notify_domain_panic_inner(
    domain_id: DomainId,
    message: String,
) -> Result<Option<FaultAction>, DriverDomainError> {
    let manager = driver_domain_manager();

    // DomainIDからDriverCellを検索
    if let Some(cell_id) = manager.find_by_domain(domain_id) {
        let fault = FaultKind::Panic(message);
        return handle_fault(cell_id, fault).map(Some);
    }

    Ok(None)
}

/// DriverCellの全ドライバを停止（障害処理用）
fn stop_drivers_for_cell(id: DriverDomainId) {
    let manager = driver_domain_manager();
    let handles = match manager.with_cell(id, |cell| cell.driver_handles.clone()) {
        Ok(h) => h,
        Err(_) => return,
    };

    let registry = crate::driver_registry::driver_registry();
    for handle in &handles {
        if let Err(e) = registry.stop(*handle) {
            log::warn!(
                "[DriverDomain] Force stop driver {:?} failed: {}\n",
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
fn attempt_restart(id: DriverDomainId) -> Result<(), DriverDomainError> {
    let manager = driver_domain_manager();

    manager.with_cell_mut(id, |cell| {
        cell.transition_to(DriverDomainState::Restarting);
    })?;

    // 古いドライバをunregister
    let old_handles = manager.with_cell(id, |cell| cell.driver_handles.clone())?;
    for handle in &old_handles {
        if let Err(e) = crate::loader::unload_driver(*handle) {
            log::warn!(
                "[DriverDomain] Failed to unload driver handle {:?} during restart: {}\n",
                handle.index(),
                e
            );
        }
    }

    // DriverCell内のハンドルリストをクリア
    manager.with_cell_mut(id, |cell| {
        cell.driver_handles.clear();
    })?;

    // Domainの状態をリセット
    let domain_id = manager.with_cell(id, |cell| cell.domain_id)?;
    if let Some(did) = domain_id {
        crate::domain::resume_domain(did).ok();
    }

    // セルからドライバを再登録
    let (cell_id, abi_driver_context) = manager.with_cell(id, |cell| {
        Ok((
            cell.cell_id.ok_or(DriverDomainError::LoadFailed(
                "No cell loaded for restart".into(),
            ))?,
            cell.abi_driver_context,
        ))
    })??;

    let handle =
        match crate::loader::register_driver_from_cell_with_context(cell_id, abi_driver_context) {
            Ok(h) => h,
            Err(e) => {
                let msg = format!("{}", e);
                manager
                    .with_cell_mut(id, |cell| {
                        cell.transition_to(DriverDomainState::Faulted);
                    })
                    .ok();
                return Err(DriverDomainError::DriverInitFailed(msg));
            }
        };

    // probe + start
    let registry = crate::driver_registry::driver_registry();
    if let Err(e) = registry.probe_and_start(handle) {
        let msg = format!("{}", e);
        manager
            .with_cell_mut(id, |cell| {
                cell.transition_to(DriverDomainState::Faulted);
            })
            .ok();
        return Err(DriverDomainError::DriverInitFailed(msg));
    }

    // DomainをRunningに
    if let Some(did) = domain_id {
        crate::domain::start_domain(did).ok();
    }

    // DriverCellをRunningに
    manager.with_cell_mut(id, |cell| {
        cell.add_driver_handle(handle);
        cell.transition_to(DriverDomainState::Running);
        cell.stats.record_restart();
    })?;

    let name = manager.with_cell(id, |cell| cell.name.clone())?;
    log::info!("[DriverDomain] Restarted: {}\n", name);

    Ok(())
}

fn spin_wait_ticks(delay_ticks: u64) {
    if delay_ticks == 0 {
        return;
    }
    let start = crate::task::current_tick();
    let mut last_tick = start;
    let mut stagnant_loops = 0usize;
    while crate::task::current_tick().saturating_sub(start) < delay_ticks {
        let now = crate::task::current_tick();
        if now > last_tick {
            last_tick = now;
            stagnant_loops = 0;
        } else {
            stagnant_loops = stagnant_loops.saturating_add(1);
            #[cfg(feature = "qemu-test-export")]
            if stagnant_loops != 0 && (stagnant_loops % 1024) == 0 {
                // Full-boot tests run with qemu_no_if=1, so timer IRQs may not
                // advance. Inject synthetic ticks to avoid deadlocking fault
                // backoff waits in restart paths.
                crate::task::handle_timer_interrupt();
                crate::task::process_pending_timer_wakers();
            }
        }
        core::hint::spin_loop();
    }
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
    /// 検証中アップデートをロールバックした
    RolledBack,
    /// 検証中アップデートのロールバックに失敗した
    RollbackFailed(String),
    /// 停止のまま（再起動なし）
    Stopped,
}

impl core::fmt::Display for FaultAction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Restarted => write!(f, "Restarted"),
            Self::RestartFailed(msg) => write!(f, "Restart failed: {}", msg),
            Self::RolledBack => write!(f, "Rolled back"),
            Self::RollbackFailed(msg) => write!(f, "Rollback failed: {}", msg),
            Self::Stopped => write!(f, "Stopped (no restart)"),
        }
    }
}

#[cfg(feature = "qemu-test-export")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestFaultKind {
    Panic,
    Timeout,
    Other,
}

#[cfg(feature = "qemu-test-export")]
impl TestFaultKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "panic" => Some(Self::Panic),
            "timeout" => Some(Self::Timeout),
            "other" => Some(Self::Other),
            _ => None,
        }
    }
}

#[cfg(feature = "qemu-test-export")]
impl core::fmt::Display for TestFaultKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Panic => write!(f, "panic"),
            Self::Timeout => write!(f, "timeout"),
            Self::Other => write!(f, "other"),
        }
    }
}

#[cfg(feature = "qemu-test-export")]
#[derive(Debug, Clone)]
pub struct TestFaultOutcome {
    pub requested_kind: TestFaultKind,
    pub action: FaultAction,
    pub driver_domain_state_after: DriverDomainState,
    pub hot_swap_state_after: HotSwapState,
    pub consecutive_faults_after: u32,
    pub last_health_failure_after: Option<String>,
}

/// qemu-test限定の障害注入フック。
///
/// DriverCellのfault/panic経路をdeterministicに起動して、手動QEMU検証や
/// 将来のqemu-suite自動化で再利用する。
#[cfg(feature = "qemu-test-export")]
pub fn inject_test_fault(
    id: DriverDomainId,
    kind: TestFaultKind,
) -> Result<TestFaultOutcome, DriverDomainError> {
    crate::io::log::early_print("[DCF] inject_test_fault: enter\n");
    let manager = driver_domain_manager();
    let domain_id = manager.with_cell(id, |cell| cell.domain_id)?;
    crate::io::log::early_print("[DCF] inject_test_fault: got domain\n");

    let action = match kind {
        TestFaultKind::Panic => {
            crate::io::log::early_print("[DCF] inject_test_fault: panic path\n");
            if let Some(did) = domain_id {
                crate::io::log::early_print(
                    "[DCF] inject_test_fault: notify_domain_panic_inner begin\n",
                );
                match notify_domain_panic_inner(
                    did,
                    format!("qemu-test injected panic for {}", id.as_u64()),
                )? {
                    Some(a) => {
                        crate::io::log::early_print(
                            "[DCF] inject_test_fault: notify_domain_panic_inner handled\n",
                        );
                        a
                    }
                    None => handle_fault(
                        id,
                        FaultKind::Panic(format!("qemu-test injected panic for {}", id.as_u64())),
                    )
                    .map(|a| {
                        crate::io::log::early_print(
                            "[DCF] inject_test_fault: direct handle_fault done\n",
                        );
                        a
                    })?,
                }
            } else {
                crate::io::log::early_print(
                    "[DCF] inject_test_fault: no domain direct handle_fault\n",
                );
                handle_fault(
                    id,
                    FaultKind::Panic(format!("qemu-test injected panic for {}", id.as_u64())),
                )
                .map(|a| {
                    crate::io::log::early_print(
                        "[DCF] inject_test_fault: direct handle_fault done\n",
                    );
                    a
                })?
            }
        }
        TestFaultKind::Timeout => handle_fault(id, FaultKind::Timeout)?,
        TestFaultKind::Other => handle_fault(
            id,
            FaultKind::Other(format!("qemu-test injected fault for {}", id.as_u64())),
        )?,
    };

    let (
        driver_domain_state_after,
        hot_swap_state_after,
        consecutive_faults_after,
        last_health_failure_after,
    ) = manager.with_cell(id, |cell| {
        (
            cell.state,
            cell.hot_swap_state,
            cell.consecutive_faults,
            cell.last_health_failure.clone(),
        )
    })?;
    crate::io::log::early_print("[DCF] inject_test_fault: snapshot done\n");

    Ok(TestFaultOutcome {
        requested_kind: kind,
        action,
        driver_domain_state_after,
        hot_swap_state_after,
        consecutive_faults_after,
        last_health_failure_after,
    })
}
