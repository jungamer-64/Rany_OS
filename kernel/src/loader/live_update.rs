// ============================================================================
// src/loader/live_update.rs - Epoch-based Reclamation for Live Updates
// 設計書 3.5.3: クォーラムと一貫性: Epoch-based Reclamation
// ============================================================================
//! Live replacement publishes a new dispatch while retaining the old code.
//! Epochs order publications. Reclamation depends on generation leases, which
//! outlive interrupt returns, waiting Futures and suspended task stacks.
use crate::sync::PoisonLock;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use kernel_api::abi::driver::{
    DRIVER_ENTRY_SYMBOL, DRIVER_EXPORTS_SYMBOL, DriverEntryFn, DriverExportsV1,
};

// ============================================================================
// Epoch Management
// ============================================================================

/// グローバルエポックカウンタ
pub static GLOBAL_EPOCH: AtomicU64 = AtomicU64::new(0);

/// A retired generation is quiescent only after every code reference ends.
pub fn generations_quiescent_through(target_epoch: u64) -> bool {
    crate::loader::with_registry(|registry| {
        registry
            .all_cells()
            .all(|cell| cell.code.quiescent_before(target_epoch))
    })
}

pub fn wait_for_generations_with_timeout(target_epoch: u64, max_attempts: u64) -> bool {
    for _ in 0..max_attempts {
        if generations_quiescent_through(target_epoch) {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

pub fn advance_epoch() -> u64 {
    GLOBAL_EPOCH.fetch_add(1, Ordering::SeqCst) + 1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochStats {
    pub current_epoch: u64,
    pub retained_generations: usize,
}

pub fn epoch_stats() -> EpochStats {
    let epoch = current_epoch();
    EpochStats {
        current_epoch: epoch,
        retained_generations: crate::loader::with_registry(|registry| {
            registry
                .all_cells()
                .filter(|cell| !cell.code.quiescent_before(epoch))
                .count()
        }),
    }
}

// ============================================================================
// Request Tracker
// ============================================================================

/// ドメインへのアクティブリクエスト数を追跡
pub struct RequestTracker {
    /// アクティブなリクエスト数
    active_count: AtomicU64,
    /// ドレイン（排出）シグナル
    drain_signal: AtomicBool,
}

impl RequestTracker {
    /// 新しいRequestTrackerを作成
    pub const fn new() -> Self {
        Self {
            active_count: AtomicU64::new(0),
            drain_signal: AtomicBool::new(false),
        }
    }

    /// リクエストの開始を記録
    ///
    /// ドレイン中は false を返す（新規リクエスト拒否）。
    pub fn begin_request(&self) -> bool {
        if self.drain_signal.load(Ordering::Acquire) {
            return false; // ドレイン中は新規リクエストを拒否
        }
        self.active_count.fetch_add(1, Ordering::Acquire);
        true
    }

    /// リクエストの終了を記録
    pub fn end_request(&self) {
        self.active_count.fetch_sub(1, Ordering::Release);
    }

    /// アクティブリクエスト数を取得
    pub fn active_count(&self) -> u64 {
        self.active_count.load(Ordering::Acquire)
    }

    /// ドレインを開始し、全リクエストの完了を待機
    pub fn wait_for_drain(&self) {
        self.drain_signal.store(true, Ordering::Release);
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while self.active_count.load(Ordering::Acquire) > 0 {
            core::hint::spin_loop();
        }
    }

    /// ドレインをリセット
    pub fn reset_drain(&self) {
        self.drain_signal.store(false, Ordering::Release);
    }
}

// ============================================================================
// Live Update Protocol
// ============================================================================

/// ライブアップデートの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveUpdateState {
    /// 準備完了
    Ready,
    /// 新セルロード中
    Loading,
    /// 切り替え中
    Switching,
    /// 旧セル解放待ち
    WaitingQuiescent,
    /// 完了
    Complete,
    /// エラー
    Error,
}

/// ライブアップデートエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveUpdateError {
    /// 更新中に別の更新が開始された
    UpdateInProgress,
    /// 新セルのロード失敗
    LoadFailed,
    /// Quiescent待機タイムアウト
    QuiescentTimeout,
    /// セルが見つからない
    CellNotFound,
    /// The same prepared transaction remains owned until this operation completes.
    SwitchPending {
        new_cell_id: u64,
        handle: crate::driver_registry::DriverHandle,
        cause: crate::driver_registry::DriverError,
    },
    DriverOperationFailed {
        new_cell_id: u64,
        handle: crate::driver_registry::DriverHandle,
        cause: crate::driver_registry::DriverError,
    },
    ReclamationBusy {
        cell_id: u64,
        leases: usize,
    },
    ResolutionStarted,
    RollbackIncomplete {
        remaining_drivers: usize,
        cause: crate::driver_registry::DriverError,
    },
    HealthFailed,
    ModuleFinalization {
        cell_id: u64,
        cause: kernel_api::resource::domain::CodeFinalizationError,
    },
    ModuleLifecycle {
        cell_id: u64,
        cause: super::cell_runtime::CellRuntimeError,
    },
    DomainLifecycle {
        owner: crate::domain::DomainId,
        cause: crate::domain::DomainLifecycleError,
    },
}

impl core::fmt::Display for LiveUpdateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UpdateInProgress => write!(f, "Another update is in progress"),
            Self::LoadFailed => write!(f, "Failed to load new cell"),
            Self::QuiescentTimeout => write!(f, "Timeout waiting for quiescent state"),
            Self::CellNotFound => write!(f, "Cell not found"),
            Self::SwitchPending {
                new_cell_id,
                handle,
                cause,
            } => write!(
                f,
                "Update to cell {new_cell_id}, driver {} remains incomplete: {cause}",
                handle.index()
            ),
            Self::DriverOperationFailed {
                new_cell_id,
                handle,
                cause,
            } => write!(
                f,
                "Update to cell {new_cell_id}, driver {} failed: {cause}",
                handle.index()
            ),
            Self::ReclamationBusy { cell_id, leases } => {
                write!(f, "Cell {cell_id} is retained by {leases} code leases")
            }
            Self::ResolutionStarted => {
                write!(f, "Update finalization direction is already committed")
            }
            Self::RollbackIncomplete {
                remaining_drivers,
                cause,
            } => {
                write!(
                    f,
                    "Rollback retains {remaining_drivers} drivers for retry: {cause}"
                )
            }
            Self::HealthFailed => f.write_str("A reported health failure requires rollback"),
            Self::ModuleFinalization { cell_id, cause } => {
                write!(f, "Cell {cell_id} finalization incomplete: {cause}")
            }
            Self::ModuleLifecycle { cell_id, cause } => {
                write!(f, "Cell {cell_id} runtime remains owned: {cause}")
            }
            Self::DomainLifecycle { owner, cause } => {
                write!(f, "Rollback domain {owner} remains incomplete: {cause}")
            }
        }
    }
}

impl LiveUpdateError {
    pub(crate) fn is_waiting(&self) -> bool {
        match self {
            Self::ReclamationBusy { .. } | Self::UpdateInProgress | Self::SwitchPending { .. } => {
                true
            }
            Self::ModuleLifecycle {
                cause: super::cell_runtime::CellRuntimeError::Busy { .. },
                ..
            } => true,
            Self::RollbackIncomplete { cause, .. } => driver_operation_waiting(*cause),
            Self::ModuleFinalization { cause, .. } => cause.is_pending(),
            Self::DomainLifecycle {
                cause: crate::domain::DomainLifecycleError::Busy(_),
                ..
            } => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingUpdateStatus {
    pub old_cell_id: u64,
    pub new_cell_id: u64,
    pub started_at_tick: u64,
    /// Validation starts only after every replacement has acknowledged startup.
    pub deadline_tick: Option<u64>,
    pub phase: UpdatePhase,
    pub health_failed: bool,
}

/// The direction becomes irreversible before closing a generation. A retry
/// preserves completed driver publications instead of replaying their state import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdatePhase {
    Switching,
    Validating,
    Committing,
    RollingBack,
    /// The domain has reached a stop boundary and reopened for retained restore.
    Restoring,
    RollbackPublished,
}

struct PendingUpdateContext {
    old_cell_id: crate::loader::CellId,
    new_cell_id: crate::loader::CellId,
    changes: Vec<DriverChange>,
    old_entry: Option<crate::driver_registry::PreparedDriverExports>,
    new_entry: Option<crate::driver_registry::PreparedDriverExports>,
    retirement_epoch: u64,
    resolution: UpdatePhase,
    started_at_tick: u64,
    deadline_tick: Option<u64>,
    health_failed: bool,
    health_failure_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdateTransition {
    pub old_cell_id: u64,
    pub new_cell_id: u64,
}

#[derive(Debug, Clone)]
pub enum CompletedUpdateOutcome {
    Committed {
        old_cell_id: u64,
        new_cell_id: u64,
        at_tick: u64,
    },
    RolledBack {
        old_cell_id: u64,
        new_cell_id: u64,
        at_tick: u64,
        reason: Option<String>,
    },
}

impl CompletedUpdateOutcome {
    fn matches_cell(&self, cell_id: u64) -> bool {
        match self {
            Self::Committed {
                old_cell_id,
                new_cell_id,
                ..
            }
            | Self::RolledBack {
                old_cell_id,
                new_cell_id,
                ..
            } => *old_cell_id == cell_id || *new_cell_id == cell_id,
        }
    }
}

enum DriverChange {
    AwaitingExport(crate::driver_registry::DriverHandle),
    Installing {
        backup: DriverRollbackState,
        replacement: crate::driver_registry::DriverReplacement,
    },
    Active(DriverRollbackState),
    Restoring {
        handle: crate::driver_registry::DriverHandle,
        replacement: crate::driver_registry::DriverReplacement,
    },
}

#[derive(Debug, Clone)]
struct DriverRollbackState {
    handle: crate::driver_registry::DriverHandle,
    state: Option<Arc<kernel_api::driver::DriverStateBlob>>,
    /// Device coordinates survive removal; an instance's opaque pointer does not.
    context: kernel_api::abi::driver::DriverContext,
}

/// Available owns the transaction. Invoking keeps its observable projection
/// and a coalesced notification while an exclusive guard owns code and drivers
/// on its stack. Notifications are folded back before any irreversible decision.
enum PendingUpdateSlot {
    Empty,
    Preparing {
        old_cell_id: u64,
        health_failure: Option<String>,
    },
    Available(PendingUpdateContext),
    Invoking {
        status: PendingUpdateStatus,
        health_failure: Option<String>,
    },
}

impl PendingUpdateContext {
    fn status(&self) -> PendingUpdateStatus {
        PendingUpdateStatus {
            old_cell_id: self.old_cell_id.as_u64(),
            new_cell_id: self.new_cell_id.as_u64(),
            started_at_tick: self.started_at_tick,
            deadline_tick: self.deadline_tick,
            phase: self.resolution,
            health_failed: self.health_failed,
        }
    }

    fn apply_health_failure(&mut self, reason: Option<String>) {
        if let Some(reason) = reason {
            self.health_failed = true;
            if self.health_failure_reason.is_none() {
                self.health_failure_reason = Some(reason);
            }
        }
    }
}

impl PendingUpdateStatus {
    fn matches_cell(&self, cell_id: u64) -> bool {
        self.old_cell_id == cell_id || self.new_cell_id == cell_id
    }
}

struct UpdateOperation<'a>(&'a LiveUpdateManager);
impl Drop for UpdateOperation<'_> {
    fn drop(&mut self) {
        let mut pending = self
            .0
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if matches!(*pending, PendingUpdateSlot::Preparing { .. }) {
            *pending = PendingUpdateSlot::Empty;
        }
        self.0.updating.store(false, Ordering::Release);
    }
}

/// Returning, including an error, puts every admitted owner back in its slot.
/// Completion alone consumes the guard and removes the notification target.
struct UpdateInvocation<'a> {
    manager: &'a LiveUpdateManager,
    context: Option<PendingUpdateContext>,
}

impl UpdateInvocation<'_> {
    fn context_mut(&mut self) -> &mut PendingUpdateContext {
        self.context
            .as_mut()
            .expect("an active invocation owns its context")
    }

    fn collect_health(context: &mut PendingUpdateContext, slot: &mut PendingUpdateSlot) {
        let PendingUpdateSlot::Invoking {
            status,
            health_failure,
        } = slot
        else {
            unreachable!("the invocation guard exclusively owns this slot");
        };
        context.apply_health_failure(health_failure.take());
        *status = context.status();
    }

    fn begin_commit(&mut self) -> Result<(), LiveUpdateError> {
        let mut slot = self
            .manager
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let context = self
            .context
            .as_mut()
            .expect("an active invocation owns its context");
        Self::collect_health(context, &mut slot);
        if !matches!(
            context.resolution,
            UpdatePhase::Validating | UpdatePhase::Committing
        ) {
            return Err(LiveUpdateError::ResolutionStarted);
        }
        if context.health_failed {
            return Err(LiveUpdateError::HealthFailed);
        }
        // Seal rollback before dropping any prepared code lease or closing code.
        context.resolution = UpdatePhase::Committing;
        Self::collect_health(context, &mut slot);
        Ok(())
    }

    fn begin_rollback(&mut self) -> Result<(), LiveUpdateError> {
        let mut slot = self
            .manager
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let context = self
            .context
            .as_mut()
            .expect("an active invocation owns its context");
        Self::collect_health(context, &mut slot);
        if context.resolution == UpdatePhase::Committing {
            return Err(LiveUpdateError::ResolutionStarted);
        }
        if !matches!(
            context.resolution,
            UpdatePhase::Restoring | UpdatePhase::RollbackPublished
        ) {
            context.resolution = UpdatePhase::RollingBack;
        }
        Self::collect_health(context, &mut slot);
        Ok(())
    }

    fn finish(mut self) -> PendingUpdateContext {
        let mut slot = self
            .manager
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut context = self
            .context
            .take()
            .expect("completion consumes the invocation once");
        Self::collect_health(&mut context, &mut slot);
        *slot = PendingUpdateSlot::Empty;
        context
    }
}

impl Drop for UpdateInvocation<'_> {
    fn drop(&mut self) {
        let Some(mut context) = self.context.take() else {
            return;
        };
        let mut slot = self
            .manager
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        Self::collect_health(&mut context, &mut slot);
        *self
            .manager
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = if context.health_failed {
            LiveUpdateState::Error
        } else if context.resolution == UpdatePhase::Switching {
            LiveUpdateState::Switching
        } else {
            LiveUpdateState::WaitingQuiescent
        };
        *slot = PendingUpdateSlot::Available(context);
    }
}

/// ライブアップデートマネージャ
pub struct LiveUpdateManager {
    /// 現在の状態
    state: PoisonLock<LiveUpdateState>,
    /// 更新中フラグ
    updating: AtomicBool,
    /// ロールバック猶予期間のエポック
    rollback_epoch: AtomicU64,
    /// デフォルトロールバック猶予期間（ティック）
    rollback_grace_period: AtomicU64,
    /// 検証猶予中の更新コンテキスト
    pending: PoisonLock<PendingUpdateSlot>,
    /// 直近の更新結果（DriverCell側の状態同期用）
    recent_outcomes: PoisonLock<Vec<CompletedUpdateOutcome>>,
}

impl LiveUpdateManager {
    /// 新しいLiveUpdateManagerを作成
    pub const fn new() -> Self {
        Self {
            state: PoisonLock::new(LiveUpdateState::Ready),
            updating: AtomicBool::new(false),
            rollback_epoch: AtomicU64::new(0),
            rollback_grace_period: AtomicU64::new(60 * 1000), // 60秒（ミリ秒）
            pending: PoisonLock::new(PendingUpdateSlot::Empty),
            recent_outcomes: PoisonLock::new(Vec::new()),
        }
    }

    /// 現在の状態を取得
    pub fn state(&self) -> LiveUpdateState {
        *self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// ライブアップデートを実行
    pub fn perform_update(
        &self,
        _cell_id: u64,
        _new_elf_data: &[u8],
    ) -> Result<u64, LiveUpdateError> {
        let _operation = self.begin_operation()?;
        {
            let mut slot = self
                .pending
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if !matches!(*slot, PendingUpdateSlot::Empty) {
                return Err(LiveUpdateError::UpdateInProgress);
            }
            *slot = PendingUpdateSlot::Preparing {
                old_cell_id: _cell_id,
                health_failure: None,
            };
        }
        self.perform_update_inner(_cell_id, _new_elf_data)
    }

    fn begin_operation(&self) -> Result<UpdateOperation<'_>, LiveUpdateError> {
        self.updating
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| LiveUpdateError::UpdateInProgress)?;
        Ok(UpdateOperation(self))
    }

    fn perform_update_inner(
        &self,
        old_id_u64: u64,
        new_elf_data: &[u8],
    ) -> Result<u64, LiveUpdateError> {
        let old_cell_id = crate::loader::CellId::from_u64(old_id_u64);

        // Step 0: Identify target driver(s) from old cell
        let old_drivers = crate::loader::with_registry(|r| {
            r.get(old_cell_id).map(|c| c.registered_drivers.clone())
        });

        let old_drivers = match old_drivers {
            Some(d) => d,
            None => return Err(LiveUpdateError::CellNotFound),
        };

        if old_drivers.is_empty() {
            return Err(LiveUpdateError::CellNotFound);
        }

        // Step 1: Load new cell
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = LiveUpdateState::Loading;
        log::info!("[LIVE_UPDATE] Loading new cell version...\n");

        let epoch = GLOBAL_EPOCH.load(Ordering::Relaxed);
        let name = alloc::format!("update-{}", epoch);

        let new_cell_id = match crate::loader::load_cell(&name, new_elf_data, true) {
            Ok(id) => id,
            Err(_) => return Err(LiveUpdateError::LoadFailed),
        };

        let retirement_epoch = advance_epoch();
        let mut changes = Vec::new();
        if changes.try_reserve_exact(old_drivers.len()).is_err() {
            // Even a candidate with no published dispatch has a reclamation owner.
            let context = PendingUpdateContext {
                old_cell_id,
                new_cell_id,
                changes,
                old_entry: None,
                new_entry: None,
                retirement_epoch,
                resolution: UpdatePhase::RollingBack,
                started_at_tick: crate::task::current_tick(),
                deadline_tick: None,
                health_failed: true,
                health_failure_reason: Some("publication preparation exhausted memory".into()),
            };
            self.publish_prepared(context);
            return Err(LiveUpdateError::LoadFailed);
        }
        changes.extend(old_drivers.into_iter().map(DriverChange::AwaitingExport));
        let context = PendingUpdateContext {
            old_cell_id,
            new_cell_id,
            changes,
            old_entry: None,
            new_entry: None,
            retirement_epoch,
            resolution: UpdatePhase::Switching,
            started_at_tick: crate::task::current_tick(),
            deadline_tick: None,
            health_failed: false,
            health_failure_reason: None,
        };
        self.publish_prepared(context);
        let mut invocation = self.take_pending(None)?;
        self.switch_context(invocation.context_mut())
            .map(|transition| transition.new_cell_id)
    }

    fn publish_prepared(&self, mut context: PendingUpdateContext) {
        let mut slot = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let PendingUpdateSlot::Preparing {
            old_cell_id,
            health_failure,
        } = &mut *slot
        else {
            unreachable!("publication consumes this update's preparation");
        };
        assert_eq!(*old_cell_id, context.old_cell_id.as_u64());
        context.apply_health_failure(health_failure.take());
        *slot = PendingUpdateSlot::Available(context);
    }

    fn take_pending(&self, cell_id: Option<u64>) -> Result<UpdateInvocation<'_>, LiveUpdateError> {
        let mut slot = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        match &*slot {
            PendingUpdateSlot::Available(context)
                if cell_id.is_none_or(|id| context.status().matches_cell(id)) => {}
            PendingUpdateSlot::Invoking { .. } | PendingUpdateSlot::Preparing { .. } => {
                return Err(LiveUpdateError::UpdateInProgress);
            }
            _ => return Err(LiveUpdateError::CellNotFound),
        }
        let PendingUpdateSlot::Available(context) =
            core::mem::replace(&mut *slot, PendingUpdateSlot::Empty)
        else {
            unreachable!("the locked slot owns an available transaction");
        };
        *slot = PendingUpdateSlot::Invoking {
            status: context.status(),
            health_failure: None,
        };
        Ok(UpdateInvocation {
            manager: self,
            context: Some(context),
        })
    }

    fn switch_context(
        &self,
        context: &mut PendingUpdateContext,
    ) -> Result<UpdateTransition, LiveUpdateError> {
        if context.health_failed {
            context.resolution = UpdatePhase::RollingBack;
            return Err(LiveUpdateError::HealthFailed);
        }
        *self.state.lock().unwrap_or_else(|error| error.into_inner()) = LiveUpdateState::Switching;
        let result = Self::advance_publications(context);
        match result {
            Ok(()) => {
                crate::loader::with_registry(|registry| {
                    if let Some(old) = registry.get(context.old_cell_id) {
                        old.code.retire(context.retirement_epoch);
                    }
                });
                let now = crate::task::current_tick();
                context.started_at_tick = now;
                context.deadline_tick =
                    Some(now.saturating_add(self.rollback_grace_period.load(Ordering::Acquire)));
                context.new_entry = None;
                context.resolution = UpdatePhase::Validating;
                let result = UpdateTransition {
                    old_cell_id: context.old_cell_id.as_u64(),
                    new_cell_id: context.new_cell_id.as_u64(),
                };
                self.rollback_epoch
                    .store(context.retirement_epoch, Ordering::Release);
                *self.state.lock().unwrap_or_else(|error| error.into_inner()) =
                    LiveUpdateState::WaitingQuiescent;
                Ok(result)
            }
            Err(error) => {
                if !error.is_waiting() {
                    context.health_failed = true;
                    context.health_failure_reason = Some(alloc::format!("{error}"));
                    context.resolution = UpdatePhase::RollingBack;
                    *self.state.lock().unwrap_or_else(|error| error.into_inner()) =
                        LiveUpdateState::Error;
                }
                Err(error)
            }
        }
    }

    fn advance_publications(context: &mut PendingUpdateContext) -> Result<(), LiveUpdateError> {
        let registry = crate::driver_registry::driver_registry();
        let handle = match context.changes.first() {
            Some(DriverChange::AwaitingExport(handle)) => *handle,
            Some(DriverChange::Installing { backup, .. } | DriverChange::Active(backup)) => {
                backup.handle
            }
            _ => return Err(LiveUpdateError::CellNotFound),
        };
        let owner = registry
            .driver_owner(handle)
            .ok_or(LiveUpdateError::CellNotFound)?;
        if context.old_entry.is_none() {
            context.old_entry = Some(resolve_cell_entry(context.old_cell_id, owner, false)?);
        }
        if context.new_entry.is_none() {
            crate::loader::with_registry_mut(|registry| {
                registry
                    .get_mut(context.new_cell_id)
                    .ok_or(LiveUpdateError::CellNotFound)?
                    .registered_drivers
                    .try_reserve_exact(context.changes.len())
                    .map_err(|_| LiveUpdateError::LoadFailed)
            })?;
            context.new_entry = Some(resolve_cell_entry(context.new_cell_id, owner, true)?);
        }
        for change in &mut context.changes {
            if let DriverChange::AwaitingExport(handle) = change {
                let handle = *handle;
                let state = registry
                    .export_live_state(handle)
                    .map_err(|cause| publication_error(context.new_cell_id, handle, cause))?;
                let state = state.map(Arc::try_new).transpose().map_err(|_| {
                    publication_error(
                        context.new_cell_id,
                        handle,
                        crate::driver_registry::DriverError::OutOfMemory,
                    )
                })?;
                let prepared = context
                    .new_entry
                    .as_ref()
                    .expect("candidate exports remain owned throughout switching");
                let mut device = registry
                    .driver_abi_context(handle)
                    .ok_or(LiveUpdateError::CellNotFound)?;
                device.driver_data = 0;
                let replacement = crate::driver_registry::prepare_driver_replacement(
                    handle,
                    prepared,
                    state.clone(),
                    device,
                )
                .map_err(|cause| publication_error(context.new_cell_id, handle, cause))?;
                *change = DriverChange::Installing {
                    backup: DriverRollbackState {
                        handle,
                        state,
                        context: device,
                    },
                    replacement,
                };
            }
            if let DriverChange::Installing {
                backup,
                replacement,
            } = change
            {
                let was_published = replacement.published();
                let result = replacement.advance(registry);
                if !was_published && replacement.published() {
                    Self::migrate_driver_ownership(
                        context.old_cell_id,
                        context.new_cell_id,
                        core::slice::from_ref(&backup.handle),
                    );
                }
                result.map_err(|cause| {
                    publication_error(context.new_cell_id, backup.handle, cause)
                })?;
                *change = DriverChange::Active(backup.clone());
            }
        }
        Ok(())
    }

    fn resume_switch(&self) -> Result<UpdateTransition, LiveUpdateError> {
        let _operation = self.begin_operation()?;
        let mut invocation = self.take_pending(None)?;
        self.switch_context(invocation.context_mut())
    }

    /// ドライバの所有権を旧セルから新セルへ移行
    fn migrate_driver_ownership(
        old_cell_id: crate::loader::CellId,
        new_cell_id: crate::loader::CellId,
        old_drivers: &[crate::driver_registry::DriverHandle],
    ) {
        crate::loader::with_registry_mut(|r| {
            if let Some(old_c) = r.get_mut(old_cell_id) {
                old_c
                    .registered_drivers
                    .retain(|handle| !old_drivers.contains(handle));
            }
            if let Some(new_c) = r.get_mut(new_cell_id) {
                for h in old_drivers {
                    if !new_c.registered_drivers.contains(h) {
                        new_c.registered_drivers.push(*h);
                    }
                }
            }
        });
    }

    pub fn rollback_for_cell(&self, cell_id: u64) -> Result<UpdateTransition, LiveUpdateError> {
        self.rollback_pending_update_for(cell_id)
    }

    pub fn commit_for_cell(&self, cell_id: u64) -> Result<UpdateTransition, LiveUpdateError> {
        self.commit_pending_update_for(cell_id)
    }

    pub fn pending_status(&self, cell_id: u64) -> Option<PendingUpdateStatus> {
        let slot = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let status = match &*slot {
            PendingUpdateSlot::Available(context) => context.status(),
            PendingUpdateSlot::Invoking {
                status,
                health_failure,
            } => PendingUpdateStatus {
                health_failed: status.health_failed || health_failure.is_some(),
                ..*status
            },
            _ => return None,
        };
        status.matches_cell(cell_id).then_some(status)
    }

    pub fn mark_health_failure(&self, cell_id: u64, reason: impl Into<String>) -> bool {
        let mut slot = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        match &mut *slot {
            PendingUpdateSlot::Preparing {
                old_cell_id,
                health_failure,
            } if *old_cell_id == cell_id => {
                if health_failure.is_none() {
                    *health_failure = Some(reason.into());
                }
            }
            PendingUpdateSlot::Available(context)
                if context.status().matches_cell(cell_id)
                    && context.resolution != UpdatePhase::Committing =>
            {
                context.apply_health_failure(Some(reason.into()))
            }
            PendingUpdateSlot::Invoking {
                status,
                health_failure,
            } if status.matches_cell(cell_id) && status.phase != UpdatePhase::Committing => {
                if health_failure.is_none() {
                    *health_failure = Some(reason.into());
                }
            }
            _ => return false,
        }
        *self.state.lock().unwrap_or_else(|error| error.into_inner()) = LiveUpdateState::Error;
        true
    }

    pub fn take_recent_outcome_for_cell(&self, cell_id: u64) -> Option<CompletedUpdateOutcome> {
        let mut outcomes = self
            .recent_outcomes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let idx = outcomes.iter().position(|o| o.matches_cell(cell_id))?;
        Some(outcomes.remove(idx))
    }

    pub fn poll_pending_updates(&self) {
        let (resolution, deadline_expired, health_failed) = {
            let pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            let PendingUpdateSlot::Available(p) = &*pending else {
                return;
            };
            (
                p.resolution,
                p.deadline_tick
                    .is_some_and(|deadline| crate::task::current_tick() >= deadline),
                p.health_failed,
            )
        };

        let result = match resolution {
            UpdatePhase::Switching if health_failed => self.rollback_pending_update(),
            UpdatePhase::Switching => self.resume_switch(),
            UpdatePhase::RollingBack | UpdatePhase::Restoring | UpdatePhase::RollbackPublished => {
                self.rollback_pending_update()
            }
            UpdatePhase::Committing => self.commit_pending_update(),
            UpdatePhase::Validating if health_failed => self.rollback_pending_update(),
            UpdatePhase::Validating if deadline_expired => self.commit_pending_update(),
            UpdatePhase::Validating => return,
        };
        if let Err(error) = result {
            // Outstanding leases are expected until their Future or stack ends.
            if !error.is_waiting() {
                log::warn!("[LIVE_UPDATE] Pending resolution failed: {error}");
            }
        }
    }

    fn commit_pending_update(&self) -> Result<UpdateTransition, LiveUpdateError> {
        self.commit_pending(None)
    }

    fn commit_pending_update_for(&self, cell_id: u64) -> Result<UpdateTransition, LiveUpdateError> {
        self.commit_pending(Some(cell_id))
    }

    fn commit_pending(&self, cell_id: Option<u64>) -> Result<UpdateTransition, LiveUpdateError> {
        let _operation = self.begin_operation()?;
        let mut invocation = self.take_pending(cell_id)?;
        invocation.begin_commit()?;
        let context = invocation.context_mut();
        *self.state.lock().unwrap_or_else(|error| error.into_inner()) =
            LiveUpdateState::WaitingQuiescent;
        context.old_entry = None;
        context.changes.clear();
        crate::loader::unload_cell(context.old_cell_id)
            .map_err(|error| reclamation_error(context.old_cell_id, error))?;
        let context = invocation.finish();
        let result = UpdateTransition {
            old_cell_id: context.old_cell_id.as_u64(),
            new_cell_id: context.new_cell_id.as_u64(),
        };
        self.push_outcome(CompletedUpdateOutcome::Committed {
            old_cell_id: result.old_cell_id,
            new_cell_id: result.new_cell_id,
            at_tick: crate::task::current_tick(),
        });
        *self.state.lock().unwrap_or_else(|error| error.into_inner()) = LiveUpdateState::Ready;
        self.rollback_epoch.store(0, Ordering::Release);
        Ok(result)
    }

    fn rollback_pending_update(&self) -> Result<UpdateTransition, LiveUpdateError> {
        self.rollback_pending(None)
    }

    fn rollback_pending_update_for(
        &self,
        cell_id: u64,
    ) -> Result<UpdateTransition, LiveUpdateError> {
        self.rollback_pending(Some(cell_id))
    }

    fn rollback_pending(&self, cell_id: Option<u64>) -> Result<UpdateTransition, LiveUpdateError> {
        let _operation = self.begin_operation()?;
        let mut invocation = self.take_pending(cell_id)?;
        invocation.begin_rollback()?;
        let context = invocation.context_mut();
        *self.state.lock().unwrap_or_else(|error| error.into_inner()) = LiveUpdateState::Switching;
        if context.resolution == UpdatePhase::RollingBack {
            Self::prepare_rollback_execution(context)?;
            context.resolution = UpdatePhase::Restoring;
        }
        if context.resolution != UpdatePhase::RollbackPublished {
            Self::restore_publications(context).map_err(|cause| {
                LiveUpdateError::RollbackIncomplete {
                    remaining_drivers: context.changes.len(),
                    cause,
                }
            })?;
            crate::loader::with_registry(|registry| {
                if let Some(old) = registry.get(context.old_cell_id) {
                    old.code.restore();
                }
                if let Some(new) = registry.get(context.new_cell_id) {
                    new.code.retire(advance_epoch());
                }
            });
            context.old_entry = None;
            context.new_entry = None;
            context.resolution = UpdatePhase::RollbackPublished;
        }
        *self.state.lock().unwrap_or_else(|error| error.into_inner()) =
            LiveUpdateState::WaitingQuiescent;
        crate::loader::unload_cell(context.new_cell_id)
            .map_err(|error| reclamation_error(context.new_cell_id, error))?;
        let context = invocation.finish();
        let result = UpdateTransition {
            old_cell_id: context.old_cell_id.as_u64(),
            new_cell_id: context.new_cell_id.as_u64(),
        };
        self.push_outcome(CompletedUpdateOutcome::RolledBack {
            old_cell_id: result.old_cell_id,
            new_cell_id: result.new_cell_id,
            at_tick: crate::task::current_tick(),
            reason: context.health_failure_reason,
        });
        *self.state.lock().unwrap_or_else(|error| error.into_inner()) = LiveUpdateState::Ready;
        self.rollback_epoch.store(0, Ordering::Release);
        Ok(result)
    }

    /// A fault closes ordinary domain admission. Restoration may reopen it only
    /// after every saved poll and nested execution has reached a stop boundary.
    /// The phase records that acknowledgement so Busy retries can let the same
    /// registered callbacks and their worker tasks complete.
    fn prepare_rollback_execution(context: &PendingUpdateContext) -> Result<(), LiveUpdateError> {
        let handle = match context.changes.first() {
            Some(DriverChange::AwaitingExport(handle) | DriverChange::Restoring { handle, .. }) => {
                *handle
            }
            Some(DriverChange::Installing { backup, .. } | DriverChange::Active(backup)) => {
                backup.handle
            }
            None => return Ok(()),
        };
        let owner = crate::driver_registry::driver_registry()
            .driver_owner(handle)
            .ok_or(LiveUpdateError::CellNotFound)?;
        if owner == crate::domain::DomainId::KERNEL {
            return Ok(());
        }
        let outcome = crate::domain::stop_domain(owner)
            .map_err(|cause| LiveUpdateError::DomainLifecycle { owner, cause })?;
        if outcome != crate::domain::DomainStopOutcome::Complete {
            return Err(LiveUpdateError::DomainLifecycle {
                owner,
                cause: crate::domain::DomainLifecycleError::Busy(outcome),
            });
        }
        crate::domain::resume_domain(owner)
            .map_err(|cause| LiveUpdateError::DomainLifecycle { owner, cause })
    }

    fn restore_publications(
        context: &mut PendingUpdateContext,
    ) -> Result<(), crate::driver_registry::DriverError> {
        use crate::driver_registry::DriverError;
        use kernel_api::driver::DriverState;
        let registry = crate::driver_registry::driver_registry();
        // LOOP_PROOF: mode=condition; reason=Every completed restoration removes one retained change, and an incomplete callback returns with the transaction owned for retry.;
        while let Some(change) = context.changes.last_mut() {
            match change {
                DriverChange::AwaitingExport(handle) => {
                    registry.probe_and_start(*handle)?;
                }
                DriverChange::Installing {
                    backup,
                    replacement,
                } => {
                    if replacement.published()
                        && matches!(
                            registry.state(backup.handle),
                            Some(
                                DriverState::Probing
                                    | DriverState::Starting
                                    | DriverState::Importing
                            )
                        )
                    {
                        // The original operation's task still owns its driver. Collect
                        // its completion before admitting an opposite lifecycle call.
                        replacement.advance(registry)?;
                    }
                    let prepared = context.old_entry.as_ref().ok_or(DriverError::NotFound)?;
                    let restoring = crate::driver_registry::prepare_driver_replacement(
                        backup.handle,
                        prepared,
                        backup.state.clone(),
                        backup.context,
                    )?;
                    *change = DriverChange::Restoring {
                        handle: backup.handle,
                        replacement: restoring,
                    };
                    continue;
                }
                DriverChange::Active(backup) => {
                    let prepared = context.old_entry.as_ref().ok_or(DriverError::NotFound)?;
                    let restoring = crate::driver_registry::prepare_driver_replacement(
                        backup.handle,
                        prepared,
                        backup.state.clone(),
                        backup.context,
                    )?;
                    *change = DriverChange::Restoring {
                        handle: backup.handle,
                        replacement: restoring,
                    };
                    continue;
                }
                DriverChange::Restoring {
                    handle,
                    replacement,
                } => {
                    let was_published = replacement.published();
                    let result = replacement.advance(registry);
                    if !was_published && replacement.published() {
                        Self::migrate_driver_ownership(
                            context.new_cell_id,
                            context.old_cell_id,
                            core::slice::from_ref(handle),
                        );
                    }
                    result?;
                }
            }
            context.changes.pop();
        }
        Ok(())
    }

    fn push_outcome(&self, outcome: CompletedUpdateOutcome) {
        let mut outcomes = self
            .recent_outcomes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        outcomes.push(outcome);
        if outcomes.len() > 32 {
            let drain = outcomes.len() - 32;
            outcomes.drain(0..drain);
        }
    }

    #[cfg(feature = "qemu-test-export")]
    pub fn set_rollback_grace_period_for_test(&self, ticks: u64) -> u64 {
        self.rollback_grace_period.swap(ticks, Ordering::AcqRel)
    }
}

impl Default for LiveUpdateManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod notification_tests {
    use super::*;

    fn context(phase: UpdatePhase) -> PendingUpdateContext {
        PendingUpdateContext {
            old_cell_id: super::super::CellId::from_u64(1),
            new_cell_id: super::super::CellId::from_u64(2),
            changes: Vec::new(),
            old_entry: None,
            new_entry: None,
            retirement_epoch: 1,
            resolution: phase,
            started_at_tick: 0,
            deadline_tick: None,
            health_failed: false,
            health_failure_reason: None,
        }
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn fault_during_invocation_survives_return_and_prevents_commit() {
        let manager = LiveUpdateManager::new();
        *manager
            .pending
            .lock()
            .unwrap_or_else(|_| panic!("notification owner poisoned")) =
            PendingUpdateSlot::Available(context(UpdatePhase::Validating));
        let mut invocation = manager.take_pending(Some(1)).unwrap();
        assert!(manager.mark_health_failure(2, "fault while driver callback runs"));
        assert!(manager.pending_status(1).unwrap().health_failed);
        assert!(matches!(
            invocation.begin_commit(),
            Err(LiveUpdateError::HealthFailed)
        ));
        drop(invocation);
        let mut invocation = manager.take_pending(Some(2)).unwrap();
        assert!(matches!(
            invocation.begin_commit(),
            Err(LiveUpdateError::HealthFailed)
        ));
        assert_eq!(
            invocation.context_mut().health_failure_reason.as_deref(),
            Some("fault while driver callback runs")
        );
        invocation.begin_rollback().unwrap();
        assert_eq!(
            invocation.context_mut().resolution,
            UpdatePhase::RollingBack
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn commit_seals_direction_before_foreign_finalization_and_retry() {
        let manager = LiveUpdateManager::new();
        *manager
            .pending
            .lock()
            .unwrap_or_else(|_| panic!("notification owner poisoned")) =
            PendingUpdateSlot::Available(context(UpdatePhase::Validating));
        let mut invocation = manager.take_pending(None).unwrap();
        invocation.begin_commit().unwrap();
        assert_eq!(
            manager.pending_status(1).unwrap().phase,
            UpdatePhase::Committing
        );
        assert!(!manager.mark_health_failure(1, "after the commit decision"));
        assert!(matches!(
            invocation.begin_rollback(),
            Err(LiveUpdateError::ResolutionStarted)
        ));
        drop(invocation);
        let mut invocation = manager.take_pending(None).unwrap();
        assert!(!manager.mark_health_failure(2, "between commit retries"));
        invocation.begin_commit().unwrap();
        drop(invocation.finish());
        assert!(manager.pending_status(1).is_none());
        assert!(!manager.mark_health_failure(1, "stale fault report"));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn preparation_coalesces_faults_before_candidate_publication() {
        let manager = LiveUpdateManager::new();
        *manager
            .pending
            .lock()
            .unwrap_or_else(|_| panic!("notification owner poisoned")) =
            PendingUpdateSlot::Preparing {
                old_cell_id: 1,
                health_failure: None,
            };
        assert!(manager.mark_health_failure(1, "first report"));
        assert!(manager.mark_health_failure(1, "second report"));
        assert!(!manager.mark_health_failure(9, "unrelated generation"));
        manager.publish_prepared(context(UpdatePhase::Switching));
        let mut invocation = manager.take_pending(None).unwrap();
        let context = invocation.context_mut();
        assert_eq!(
            context.health_failure_reason.as_deref(),
            Some("first report")
        );
        assert!(matches!(
            manager.switch_context(context),
            Err(LiveUpdateError::HealthFailed)
        ));
        assert_eq!(context.resolution, UpdatePhase::RollingBack);
    }
}

/// セルからドライバエントリポイントを解決
fn resolve_cell_entry(
    cell_id: crate::loader::CellId,
    owner: crate::domain::DomainId,
    call_init: bool,
) -> Result<crate::driver_registry::PreparedDriverExports, LiveUpdateError> {
    let lease = Arc::try_new(
        crate::loader::acquire_code_lease(cell_id).ok_or(LiveUpdateError::CellNotFound)?,
    )
    .map_err(|_| LiveUpdateError::LoadFailed)?;
    let _entry_scope =
        crate::task::enter_cell_domain(owner, cell_id).map_err(|_| LiveUpdateError::LoadFailed)?;
    let exports_addr = crate::loader::with_registry(|r| {
        let cell = r.get(cell_id)?;
        cell.exports
            .iter()
            .find(|(n, _)| crate::loader::str_eq(n.as_str(), DRIVER_EXPORTS_SYMBOL))
            .map(|(_, addr)| *addr)
    });

    if let Some(addr) = exports_addr {
        let exports_ptr = addr as *const DriverExportsV1;
        let mut prepared = crate::driver_registry::prepare_driver_exports(exports_ptr, call_init)
            .map_err(|cause| match cause {
            crate::driver_registry::DriverError::ModuleLifecycle(cause) => {
                LiveUpdateError::ModuleLifecycle {
                    cell_id: cell_id.as_u64(),
                    cause,
                }
            }
            _ => LiveUpdateError::LoadFailed,
        })?;
        prepared.code = Some(lease);
        return Ok(prepared);
    }

    let entry_addr = crate::loader::with_registry(|r| {
        let cell = r.get(cell_id)?;
        cell.exports
            .iter()
            .find(|(n, _)| crate::loader::str_eq(n.as_str(), DRIVER_ENTRY_SYMBOL))
            .map(|(_, addr)| *addr)
    });

    let entry_addr = match entry_addr {
        Some(a) => a,
        None => return Err(LiveUpdateError::LoadFailed),
    };

    let entry_fn: DriverEntryFn = unsafe { core::mem::transmute(entry_addr) };
    let vtable_ptr = entry_fn();
    if vtable_ptr.is_null() {
        return Err(LiveUpdateError::LoadFailed);
    }
    let providers =
        crate::driver_registry::collect_provider_descriptors_from_vtable(unsafe { &*vtable_ptr });
    Ok(crate::driver_registry::PreparedDriverExports {
        code: Some(lease),
        entry: entry_fn,
        providers,
        state_hooks: crate::driver_registry::AbiDriverStateHooks::default(),
    })
}

fn publication_error(
    candidate: crate::loader::CellId,
    handle: crate::driver_registry::DriverHandle,
    cause: crate::driver_registry::DriverError,
) -> LiveUpdateError {
    if driver_operation_waiting(cause) {
        LiveUpdateError::SwitchPending {
            new_cell_id: candidate.as_u64(),
            handle,
            cause,
        }
    } else {
        LiveUpdateError::DriverOperationFailed {
            new_cell_id: candidate.as_u64(),
            handle,
            cause,
        }
    }
}

fn driver_operation_waiting(cause: crate::driver_registry::DriverError) -> bool {
    use crate::domain::DomainLifecycleError;
    use crate::driver_registry::DriverError;
    match cause {
        DriverError::Busy { .. }
        | DriverError::ModuleLifecycle(super::cell_runtime::CellRuntimeError::Busy { .. }) => true,
        DriverError::ResourceCleanup(DomainLifecycleError::CodeFinalization { cause, .. }) => {
            cause.is_pending()
        }
        DriverError::ResourceCleanup(
            DomainLifecycleError::Busy(_)
            | DomainLifecycleError::CodeBusy { .. }
            | DomainLifecycleError::ReclamationInProgress
            | DomainLifecycleError::ResourceCleanupIncomplete {
                cause: kernel_api::error::KapiError::Busy,
                ..
            },
        ) => true,
        _ => false,
    }
}

fn reclamation_error(
    cell: crate::loader::CellId,
    error: crate::loader::LoadError,
) -> LiveUpdateError {
    match error {
        crate::loader::LoadError::CodeBusy { leases } => LiveUpdateError::ReclamationBusy {
            cell_id: cell.as_u64(),
            leases,
        },
        crate::loader::LoadError::Finalization(cause) => LiveUpdateError::ModuleFinalization {
            cell_id: cell.as_u64(),
            cause,
        },
        _ => LiveUpdateError::LoadFailed,
    }
}

// ============================================================================
// Global Instance & Initialization
// ============================================================================

/// グローバルライブアップデートマネージャ
static LIVE_UPDATE_MANAGER: LiveUpdateManager = LiveUpdateManager::new();

/// ライブアップデートマネージャを取得
pub fn live_update_manager() -> &'static LiveUpdateManager {
    &LIVE_UPDATE_MANAGER
}

/// Quiescent point などから呼ぶ保留更新の自動処理
pub fn poll_pending_updates() {
    LIVE_UPDATE_MANAGER.poll_pending_updates();
}

#[cfg(feature = "qemu-test-export")]
pub fn set_rollback_grace_period_for_test(ticks: u64) -> u64 {
    LIVE_UPDATE_MANAGER.set_rollback_grace_period_for_test(ticks)
}

/// 現在のグローバルエポックを取得
pub fn current_epoch() -> u64 {
    GLOBAL_EPOCH.load(Ordering::Acquire)
}

/// ライブアップデートサブシステムを初期化
pub fn init() {
    // 初期エポックを1に設定
    GLOBAL_EPOCH.store(1, Ordering::Release);
    log::info!("[LIVE_UPDATE] Code generation reclamation initialized\n");
}

// ============================================================================
// StateTransfer Trait - 設計書 3.5.2: 状態移行プロトコル
// ============================================================================

/// ライブアップデート時の状態エクスポートエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateExportError {
    /// シリアライズに失敗
    SerializationFailed,
    /// バッファ不足
    BufferTooSmall,
    /// 状態が不整合
    InconsistentState,
    /// サポートされていない
    NotSupported,
}

/// ライブアップデート時の状態インポートエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateImportError {
    /// デシリアライズに失敗
    DeserializationFailed,
    /// バージョン非互換
    VersionMismatch,
    /// 破損したデータ
    CorruptedData,
    /// 状態復元に失敗
    RestoreFailed,
    /// サポートされていない
    NotSupported,
}

/// エクスポートされた状態のメタデータ
#[derive(Debug, Clone)]
pub struct ExportedStateMetadata {
    /// 状態のバージョン番号
    pub version: u32,
    /// エクスポート元のセルID
    pub source_cell_id: u64,
    /// エクスポート時刻（ティック）
    pub export_time: u64,
    /// 状態データのサイズ
    pub data_size: usize,
    /// チェックサム（簡易整合性検証用）
    pub checksum: u32,
}

/// エクスポートされた状態
/// 設計書 3.5.2: 内部状態を交換ヒープ上のシリアライズ可能な形式にエクスポート
#[derive(Debug, Clone)]
pub struct ExportedState {
    /// メタデータ
    pub metadata: ExportedStateMetadata,
    /// シリアライズされた状態データ
    pub data: Vec<u8>,
}

impl ExportedState {
    /// 新しいExportedStateを作成
    pub fn new(version: u32, source_cell_id: u64, data: Vec<u8>) -> Self {
        let checksum = Self::compute_checksum(&data);
        Self {
            metadata: ExportedStateMetadata {
                version,
                source_cell_id,
                export_time: crate::task::current_tick(),
                data_size: data.len(),
                checksum,
            },
            data,
        }
    }

    /// チェックサムを計算（簡易版：バイト合計）
    fn compute_checksum(data: &[u8]) -> u32 {
        data.iter().fold(0u32, |acc, &b| acc.wrapping_add(b as u32))
    }

    /// データの整合性を検証
    pub fn verify(&self) -> bool {
        self.metadata.data_size == self.data.len()
            && self.metadata.checksum == Self::compute_checksum(&self.data)
    }
}

/// 状態移行トレイト
/// 設計書 3.5.2: セルが内部状態を持つ場合、ライブアップデート時に状態を新バージョンに移行
pub trait StateTransfer: Sized {
    /// 状態のバージョン番号
    const STATE_VERSION: u32;

    /// 内部状態をエクスポート（シリアライズ）
    fn export_state(&self) -> Result<ExportedState, StateExportError>;

    /// 状態をインポート（デシリアライズ）して新インスタンスを構築
    fn import_state(state: ExportedState) -> Result<Self, StateImportError>;

    /// バージョン互換性をチェック
    fn is_version_compatible(exported_version: u32) -> bool {
        exported_version == Self::STATE_VERSION
    }

    /// セルIDを取得（オプショナル）
    fn cell_id(&self) -> u64 {
        0
    }

    /// 状態移行を試行
    fn try_migrate(state: ExportedState) -> Result<Self, StateImportError> {
        if !state.verify() {
            return Err(StateImportError::CorruptedData);
        }

        if !Self::is_version_compatible(state.metadata.version) {
            return Err(StateImportError::VersionMismatch);
        }

        Self::import_state(state)
    }
}

/// StateTransferを実装しないセル用のダミー実装
pub struct StatelessCell;

impl StateTransfer for StatelessCell {
    const STATE_VERSION: u32 = 0;

    fn export_state(&self) -> Result<ExportedState, StateExportError> {
        Ok(ExportedState::new(Self::STATE_VERSION, 0, Vec::new()))
    }

    fn import_state(state: ExportedState) -> Result<Self, StateImportError> {
        if !state.data.is_empty() {
            return Err(StateImportError::CorruptedData);
        }
        Ok(StatelessCell)
    }
}
