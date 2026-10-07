// ============================================================================
// kernel/src/driver_domain/fault.rs - 障害分離と自動復旧
// ============================================================================
//! # ドライバドメイン障害管理
//!
//! 設計書 8: フォールトアイソレーションと回復メカニズム
//! 設計書 8.1: スタックアンワインドとリソース回収
//! 設計書 8.2: RedLeafの知見：プロキシパターン
//!
//! Fault reporting publishes a stop request and preserves outstanding callbacks.
//! The service host advances an admitted restart after its deadline, retaining
//! incomplete stop/remove/start phases and observing terminal recovery failure.
//! An active live update owns replacement until rollback or commit completes.
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

/// A runtime deadline in nanoseconds, independent of APIC delivery count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartDeadline {
    nanos: u64,
}

impl RestartDeadline {
    fn after_millis(now_nanos: u64, delay_millis: u64) -> Self {
        Self {
            nanos: now_nanos.saturating_add(delay_millis.saturating_mul(1_000_000)),
        }
    }
    fn is_due(self, now_nanos: u64) -> bool {
        now_nanos >= self.nanos
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
    let (restart_policy, consecutive, domain_id, rollback_cell) =
        manager.with_cell_mut(id, |cell| {
            cell.consecutive_faults += 1;
            let consecutive = cell.consecutive_faults;

            let record = FaultRecord::new(fault_kind.clone(), consecutive);
            cell.fault_history.push(record);

            // Publish recovery direction before Faulted is observable. The
            // update owns replacement and teardown even if this call is preempted.
            let rollback_cell = cell.cell_id.filter(|cell_id| {
                matches!(
                    cell.hot_swap_state,
                    HotSwapState::Switching | HotSwapState::Validating | HotSwapState::Error
                ) && crate::loader::live_update::live_update_manager().mark_health_failure(
                    cell_id.as_u64(),
                    format!("Fault during live update: {fault_kind}"),
                )
            });
            cell.transition_to(DriverDomainState::Faulted);
            cell.stats.record_fault();

            (
                cell.restart_policy,
                consecutive,
                cell.domain_id,
                rollback_cell,
            )
        })?;
    super::stats::global_stats().on_fault();

    if let Some(_cell_id) = rollback_cell {
        // The service may have completed the accepted request while this call
        // was suspended. Its Idle publication is the completion boundary.
        if manager.with_cell(id, |cell| {
            cell.state == DriverDomainState::Running && cell.hot_swap_state == HotSwapState::Idle
        })? {
            return Ok(FaultAction::RolledBack);
        }
        crate::io::log::early_print("[DCF] handle_fault: rollback begin\n");
        match super::hot_swap::rollback(id) {
            Ok(()) => {
                crate::io::log::early_print("[DCF] handle_fault: rollback ok\n");
                return Ok(FaultAction::RolledBack);
            }
            Err(cause) => {
                let retained = match &cause {
                    DriverDomainError::LifecycleInProgress { .. } => true,
                    DriverDomainError::LiveUpdate(cause) => cause.is_waiting(),
                    _ => false,
                };
                if retained {
                    // Health publication already requested rollback. The update
                    // and service host retain its callback and completion owner.
                    return Ok(FaultAction::RollbackPending(cause));
                }
                log::warn!("[DriverDomain] Validation rollback failed: {cause}");
                return Ok(FaultAction::RollbackFailed(cause));
            }
        }
    }

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
        crate::domain::registry::request_fault_stop(
            did,
            format!("DriverDomain fault: {}", fault_kind),
        )
        .map_err(DriverDomainError::DomainLifecycle)?;
        crate::io::log::early_print("[DCF] handle_fault: domain panic done\n");
    }

    // ドライバを停止（可能なら）
    crate::io::log::early_print("[DCF] handle_fault: stop drivers begin\n");
    stop_drivers_for_cell(id);
    crate::io::log::early_print("[DCF] handle_fault: stop drivers done\n");

    // 再起動ポリシーを評価
    if restart_policy.should_restart(fault_kind.clone(), consecutive) {
        let backoff = restart_policy.backoff_for_attempt(consecutive.saturating_sub(1));

        log::info!(
            "[DriverDomain] Scheduling restart for '{}' (attempt {}, backoff {}ms)\n",
            name,
            consecutive,
            backoff
        );

        let not_before =
            RestartDeadline::after_millis(crate::time::best_effort_time_nanos(), backoff);
        manager.with_cell_mut(id, |cell| {
            cell.transition_to(DriverDomainState::Restarting(
                super::RestartPhase::Backoff { not_before },
            ));
        })?;
        // The maintenance service owns execution and completion observation.
        // Fault reporting never spins or re-enters an active lifecycle callback.
        Ok(FaultAction::RestartScheduled { not_before })
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
                "[DriverDomain] Requested stop driver {:?} remains incomplete: {}\n",
                handle.index(),
                e
            );
        }
    }
}

/// The owner records progress between calls; one admitted stack owns each call.
/// Removal acknowledgements and the published new handle survive Busy retries.
fn attempt_restart(id: DriverDomainId) -> Result<(), DriverDomainError> {
    use super::RestartPhase;
    use kernel_api::driver::DriverState;
    let manager = driver_domain_manager();
    let _invocation = manager.reserve_call(id, super::LifecycleOperation::Restart)?;
    let mut phase = manager.with_cell_mut(id, |cell| match cell.state {
        DriverDomainState::Restarting(super::RestartPhase::Backoff { not_before }) => {
            if !not_before.is_due(crate::time::best_effort_time_nanos()) {
                return Err(DriverDomainError::RestartBackoff { not_before });
            }
            cell.transition_to(DriverDomainState::Restarting(RestartPhase::Removing));
            Ok(RestartPhase::Removing)
        }
        DriverDomainState::Restarting(phase) => Ok(phase),
        state => Err(DriverDomainError::InvalidStateTransition {
            from: state,
            to: DriverDomainState::Restarting(RestartPhase::Removing),
        }),
    })??;
    let domain = manager
        .with_cell(id, |cell| cell.domain_id)?
        .ok_or_else(|| {
            DriverDomainError::DomainCreationFailed("restart has no domain owner".into())
        })?;
    if phase == RestartPhase::Removing {
        let outcome =
            crate::domain::stop_domain(domain).map_err(DriverDomainError::DomainLifecycle)?;
        if outcome != crate::domain::DomainStopOutcome::Complete {
            return Err(DriverDomainError::DomainLifecycle(
                crate::domain::DomainLifecycleError::Busy(outcome),
            ));
        }
        let registry = crate::driver_registry::driver_registry();
        let handles = manager.with_cell(id, |cell| cell.driver_handles.clone())?;
        // LOOP_PROOF: mode=bounded; reason=The finite retained handle snapshot is visited once and Busy returns with the remaining owners registered.;
        for handle in handles {
            if !matches!(
                registry.state(handle),
                Some(DriverState::Stopped | DriverState::Removed)
            ) {
                registry
                    .stop(handle)
                    .map_err(DriverDomainError::DriverOperation)?;
            }
            crate::loader::unload_driver(handle).map_err(DriverDomainError::CodeReclamation)?;
            manager.with_cell_mut(id, |cell| {
                cell.driver_handles.retain(|owned| *owned != handle)
            })?;
        }
        manager.with_cell_mut(id, |cell| {
            if cell.state != DriverDomainState::Restarting(RestartPhase::Removing) {
                return Err(DriverDomainError::InvalidStateTransition {
                    from: cell.state,
                    to: DriverDomainState::Restarting(RestartPhase::Registering),
                });
            }
            cell.driver_handles
                .try_reserve(1)
                .map_err(|_| DriverDomainError::OutOfMemory)?;
            cell.transition_to(DriverDomainState::Restarting(RestartPhase::Registering));
            Ok(())
        })??;
        phase = RestartPhase::Registering;
    }
    if phase == RestartPhase::Registering {
        let (cell_id, mut context) = manager.with_cell_mut(id, |cell| {
            if cell.state != DriverDomainState::Restarting(RestartPhase::Registering) {
                return Err(DriverDomainError::InvalidStateTransition {
                    from: cell.state,
                    to: DriverDomainState::Restarting(RestartPhase::Registering),
                });
            }
            crate::domain::resume_domain(domain).map_err(DriverDomainError::DomainLifecycle)?;
            Ok((
                cell.cell_id.ok_or_else(|| {
                    DriverDomainError::LoadFailed("restart has no code owner".into())
                })?,
                cell.abi_driver_context,
            ))
        })??;
        context.driver_data = 0;
        let handle =
            crate::loader::register_driver_from_cell_with_context(cell_id, context, domain)
                .map_err(DriverDomainError::CodeReclamation)?;
        manager.with_cell_mut(id, |cell| {
            cell.driver_handles.push(handle);
            if cell.state != DriverDomainState::Restarting(RestartPhase::Registering) {
                return Err(DriverDomainError::InvalidStateTransition {
                    from: cell.state,
                    to: DriverDomainState::Restarting(RestartPhase::Starting),
                });
            }
            cell.transition_to(DriverDomainState::Restarting(RestartPhase::Starting));
            Ok(())
        })??;
    }
    let handle = manager
        .with_cell(id, |cell| cell.driver_handles.first().copied())?
        .ok_or_else(|| {
            DriverDomainError::DriverInitFailed("restart lost its admitted driver".into())
        })?;
    match crate::driver_registry::driver_registry().probe_and_start(handle) {
        Ok(()) => {}
        Err(crate::driver_registry::DriverError::Busy { .. }) => {
            return Err(DriverDomainError::StartupPending { id, handle });
        }
        Err(cause) => return Err(DriverDomainError::DriverOperation(cause)),
    }
    manager.with_cell_mut(id, |cell| {
        if cell.state != DriverDomainState::Restarting(RestartPhase::Starting) {
            return Err(DriverDomainError::InvalidStateTransition {
                from: cell.state,
                to: DriverDomainState::Running,
            });
        }
        cell.transition_to(DriverDomainState::Running);
        cell.stats.record_restart();
        if let Some(last) = cell.fault_history.last_mut() {
            last.restart_succeeded = true;
        }
        Ok(())
    })??;
    super::stats::global_stats().on_restart_succeeded();
    Ok(())
}

fn restart_waiting(cause: &DriverDomainError) -> bool {
    use crate::domain::DomainLifecycleError;
    use crate::driver_registry::DriverError;
    match cause {
        DriverDomainError::DomainLifecycle(error)
        | DriverDomainError::DriverOperation(DriverError::ResourceCleanup(error))
        | DriverDomainError::CodeReclamation(crate::loader::LoadError::DriverOperation(
            DriverError::ResourceCleanup(error),
        )) => match error {
            DomainLifecycleError::Busy(_)
            | DomainLifecycleError::CodeBusy { .. }
            | DomainLifecycleError::ReclamationInProgress
            | DomainLifecycleError::ResourceCleanupIncomplete {
                cause: kernel_api::error::KapiError::Busy,
                ..
            } => true,
            DomainLifecycleError::CodeFinalization { cause, .. } => cause.is_pending(),
            _ => false,
        },
        DriverDomainError::CodeReclamation(crate::loader::LoadError::Finalization(error)) => {
            error.is_pending()
        }
        DriverDomainError::InvalidStateTransition {
            from: DriverDomainState::Restarting(super::RestartPhase::Backoff { .. }),
            ..
        } => true,
        DriverDomainError::StartupPending { .. }
        | DriverDomainError::LifecycleInProgress { .. }
        | DriverDomainError::RestartBackoff { .. }
        | DriverDomainError::DriverOperation(DriverError::Busy { .. })
        | DriverDomainError::CodeReclamation(crate::loader::LoadError::DriverOperation(
            DriverError::Busy { .. },
        )) => true,
        _ => false,
    }
}

pub(crate) fn progress_restarts() {
    let manager = driver_domain_manager();
    for snapshot in manager.list_snapshots() {
        if !matches!(snapshot.state, DriverDomainState::Restarting(_)) {
            continue;
        }
        if let Err(cause) = attempt_restart(snapshot.id) {
            if !restart_waiting(&cause) {
                super::stats::global_stats().on_restart_failed();
                if let Err(observer) = manager.with_cell_mut(snapshot.id, |cell| {
                    if matches!(
                        cell.state,
                        DriverDomainState::Restarting(
                            super::RestartPhase::Removing
                                | super::RestartPhase::Registering
                                | super::RestartPhase::Starting
                        )
                    ) {
                        cell.transition_to(DriverDomainState::Faulted);
                    }
                }) {
                    log::error!("restart failure observer unavailable: {observer}");
                }
                log::error!(
                    "driver restart {} failed with its owners retained: {cause}",
                    snapshot.id
                );
            }
        }
    }
}

// ============================================================================
// Fault Action
// ============================================================================

/// 障害処理の結果アクション
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaultAction {
    /// Admitted recovery is owned by the maintenance service until completion.
    RestartScheduled { not_before: RestartDeadline },
    /// 検証中アップデートをロールバックした
    RolledBack,
    /// Rollback was requested; active calls or code leases retain completion.
    RollbackPending(DriverDomainError),
    /// 検証中アップデートのロールバックに失敗した
    RollbackFailed(DriverDomainError),
    /// 停止のまま（再起動なし）
    Stopped,
}

impl core::fmt::Display for FaultAction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RestartScheduled { not_before } => {
                write!(f, "Restart scheduled after {}ns", not_before.nanos)
            }
            Self::RolledBack => write!(f, "Rolled back"),
            Self::RollbackPending(cause) => write!(f, "Rollback pending: {cause}"),
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

#[cfg(test)]
mod deadline_tests {
    use super::RestartDeadline;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn backoff_uses_elapsed_time_and_saturates_at_the_clock_limit() {
        let deadline = RestartDeadline::after_millis(500, 10);
        assert!(!deadline.is_due(10_000_499));
        assert!(deadline.is_due(10_000_500));
        let deadline = RestartDeadline::after_millis(u64::MAX - 1, 1);
        assert!(!deadline.is_due(u64::MAX - 1));
        assert!(deadline.is_due(u64::MAX));
    }
}
