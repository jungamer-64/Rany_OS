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
    /// State export/import failed before the next dispatch publication.
    StateMigrationFailed,
    ReclamationBusy {
        cell_id: u64,
        leases: usize,
    },
    ResolutionStarted,
    RollbackIncomplete {
        remaining_drivers: usize,
    },
    PartialPublication {
        new_cell_id: u64,
        updated_drivers: usize,
    },
}

impl core::fmt::Display for LiveUpdateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UpdateInProgress => write!(f, "Another update is in progress"),
            Self::LoadFailed => write!(f, "Failed to load new cell"),
            Self::QuiescentTimeout => write!(f, "Timeout waiting for quiescent state"),
            Self::CellNotFound => write!(f, "Cell not found"),
            Self::StateMigrationFailed => write!(f, "State migration failed"),
            Self::ReclamationBusy { cell_id, leases } => {
                write!(f, "Cell {cell_id} is retained by {leases} code leases")
            }
            Self::ResolutionStarted => {
                write!(f, "Update finalization direction is already committed")
            }
            Self::RollbackIncomplete { remaining_drivers } => {
                write!(f, "Rollback retains {remaining_drivers} drivers for retry")
            }
            Self::PartialPublication {
                new_cell_id,
                updated_drivers,
            } => write!(
                f,
                "Update to cell {new_cell_id} published {updated_drivers} drivers; rollback remains pending"
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingUpdateStatus {
    pub old_cell_id: u64,
    pub new_cell_id: u64,
    pub started_at_tick: u64,
    pub deadline_tick: u64,
    pub health_failed: bool,
}

/// The direction becomes irreversible before closing a generation. A retry
/// preserves completed driver publications instead of replaying their state import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdateResolution {
    Validating,
    Committing,
    RollingBack,
    RollbackPublished,
}

#[derive(Debug)]
struct PendingUpdateContext {
    old_cell_id: crate::loader::CellId,
    new_cell_id: crate::loader::CellId,
    rollback_states: Vec<DriverRollbackState>,
    old_entry: Option<crate::driver_registry::PreparedDriverExports>,
    resolution: UpdateResolution,
    started_at_tick: u64,
    deadline_tick: u64,
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

#[derive(Debug)]
struct SwapDriversResult {
    rollback_states: Vec<DriverRollbackState>,
    old_entry: Option<crate::driver_registry::PreparedDriverExports>,
}

#[derive(Debug, Clone)]
struct DriverRollbackState {
    handle: crate::driver_registry::DriverHandle,
    state: Option<kernel_api::driver::DriverStateBlob>,
}

struct UpdateOperation<'a>(&'a AtomicBool);
impl Drop for UpdateOperation<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
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
    pending: PoisonLock<Option<PendingUpdateContext>>,
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
            pending: PoisonLock::new(None),
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
        if self
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Err(LiveUpdateError::UpdateInProgress);
        }
        self.perform_update_inner(_cell_id, _new_elf_data)
    }

    fn begin_operation(&self) -> Result<UpdateOperation<'_>, LiveUpdateError> {
        self.updating
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| LiveUpdateError::UpdateInProgress)?;
        Ok(UpdateOperation(&self.updating))
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

        // Step 2: Global Epoch Increment (Pre-swap)
        let old_epoch = current_epoch();
        let new_epoch = advance_epoch();
        log::info!(
            "[LIVE_UPDATE] Epoch incremented: {} -> {}\n",
            old_epoch,
            new_epoch
        );

        // Step 3: Swap (Update Driver Registry)
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = LiveUpdateState::Switching;

        let (swap_result, failure) =
            match Self::swap_drivers(old_cell_id, new_cell_id, &old_drivers) {
                Ok(result) => result,
                Err(error) => {
                    // Preparation may have spawned Futures referencing candidate code.
                    // Keep a retryable reclamation owner even when no dispatch was published.
                    self.finalize_update(
                        old_cell_id,
                        new_cell_id,
                        old_epoch,
                        SwapDriversResult {
                            rollback_states: Vec::new(),
                            old_entry: None,
                        },
                        true,
                    )?;
                    return Err(error);
                }
            };
        let published = swap_result.rollback_states.len();
        self.finalize_update(
            old_cell_id,
            new_cell_id,
            old_epoch,
            swap_result,
            failure.is_some(),
        )?;
        if failure.is_some() {
            return Err(LiveUpdateError::PartialPublication {
                new_cell_id: new_cell_id.as_u64(),
                updated_drivers: published,
            });
        }
        Ok(new_cell_id.as_u64())
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
        let pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let p = pending.as_ref()?;
        if p.old_cell_id.as_u64() != cell_id && p.new_cell_id.as_u64() != cell_id {
            return None;
        }
        Some(PendingUpdateStatus {
            old_cell_id: p.old_cell_id.as_u64(),
            new_cell_id: p.new_cell_id.as_u64(),
            started_at_tick: p.started_at_tick,
            deadline_tick: p.deadline_tick,
            health_failed: p.health_failed,
        })
    }

    pub fn mark_health_failure(&self, cell_id: u64, reason: impl Into<String>) -> bool {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let Some(p) = pending.as_mut() else {
            return false;
        };
        if p.old_cell_id.as_u64() != cell_id && p.new_cell_id.as_u64() != cell_id {
            return false;
        }
        if p.resolution == UpdateResolution::Committing {
            return false;
        }
        p.health_failed = true;
        p.health_failure_reason = Some(reason.into());
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = LiveUpdateState::Error;
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
            let Some(p) = pending.as_ref() else {
                return;
            };
            (
                p.resolution,
                crate::task::current_tick() >= p.deadline_tick,
                p.health_failed,
            )
        };

        let result = match resolution {
            UpdateResolution::RollingBack | UpdateResolution::RollbackPublished => {
                self.rollback_pending_update()
            }
            UpdateResolution::Committing => self.commit_pending_update(),
            UpdateResolution::Validating if health_failed => self.rollback_pending_update(),
            UpdateResolution::Validating if deadline_expired => self.commit_pending_update(),
            UpdateResolution::Validating => return,
        };
        if let Err(error) = result {
            // Outstanding leases are expected until their Future or stack ends.
            if !matches!(
                error,
                LiveUpdateError::ReclamationBusy { .. } | LiveUpdateError::UpdateInProgress
            ) {
                log::warn!("[LIVE_UPDATE] Pending resolution failed: {error}");
            }
        }
    }

    fn commit_pending_update(&self) -> Result<UpdateTransition, LiveUpdateError> {
        let _operation = self.begin_operation()?;
        let ctx = {
            let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            pending.take().ok_or(LiveUpdateError::CellNotFound)?
        };
        self.commit_context(ctx)
    }

    fn commit_pending_update_for(&self, cell_id: u64) -> Result<UpdateTransition, LiveUpdateError> {
        let _operation = self.begin_operation()?;
        let ctx = {
            let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            let matches = pending
                .as_ref()
                .map(|p| p.old_cell_id.as_u64() == cell_id || p.new_cell_id.as_u64() == cell_id)
                .unwrap_or(false);
            if !matches {
                return Err(LiveUpdateError::CellNotFound);
            }
            pending.take().ok_or(LiveUpdateError::CellNotFound)?
        };
        self.commit_context(ctx)
    }

    fn commit_context(
        &self,
        mut ctx: PendingUpdateContext,
    ) -> Result<UpdateTransition, LiveUpdateError> {
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = LiveUpdateState::WaitingQuiescent;
        log::info!(
            "[LIVE_UPDATE] Committing update old={} new={}\n",
            ctx.old_cell_id.as_u64(),
            ctx.new_cell_id.as_u64()
        );

        if matches!(
            ctx.resolution,
            UpdateResolution::RollingBack | UpdateResolution::RollbackPublished
        ) {
            *self.pending.lock().unwrap_or_else(|e| e.into_inner()) = Some(ctx);
            return Err(LiveUpdateError::ResolutionStarted);
        }
        ctx.resolution = UpdateResolution::Committing;
        // Prepared rollback function pointers are code references too.
        ctx.old_entry = None;
        ctx.rollback_states.clear();
        if let Err(error) = crate::loader::unload_cell(ctx.old_cell_id) {
            let result = reclamation_error(ctx.old_cell_id, error);
            *self.pending.lock().unwrap_or_else(|e| e.into_inner()) = Some(ctx);
            return Err(result);
        }

        let result = UpdateTransition {
            old_cell_id: ctx.old_cell_id.as_u64(),
            new_cell_id: ctx.new_cell_id.as_u64(),
        };
        self.push_outcome(CompletedUpdateOutcome::Committed {
            old_cell_id: result.old_cell_id,
            new_cell_id: result.new_cell_id,
            at_tick: crate::task::current_tick(),
        });
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = LiveUpdateState::Ready;
        self.rollback_epoch.store(0, Ordering::Release);
        Ok(result)
    }

    fn rollback_pending_update(&self) -> Result<UpdateTransition, LiveUpdateError> {
        let _operation = self.begin_operation()?;
        let ctx = {
            let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            pending.take().ok_or(LiveUpdateError::CellNotFound)?
        };
        self.rollback_context(ctx)
    }

    fn rollback_pending_update_for(
        &self,
        cell_id: u64,
    ) -> Result<UpdateTransition, LiveUpdateError> {
        let _operation = self.begin_operation()?;
        let ctx = {
            let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            let matches = pending
                .as_ref()
                .map(|p| p.old_cell_id.as_u64() == cell_id || p.new_cell_id.as_u64() == cell_id)
                .unwrap_or(false);
            if !matches {
                return Err(LiveUpdateError::CellNotFound);
            }
            pending.take().ok_or(LiveUpdateError::CellNotFound)?
        };
        self.rollback_context(ctx)
    }

    fn rollback_context(
        &self,
        mut ctx: PendingUpdateContext,
    ) -> Result<UpdateTransition, LiveUpdateError> {
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = LiveUpdateState::Switching;
        log::info!(
            "[LIVE_UPDATE] Rolling back update old={} new={}\n",
            ctx.old_cell_id.as_u64(),
            ctx.new_cell_id.as_u64()
        );

        if ctx.resolution == UpdateResolution::Committing {
            *self.pending.lock().unwrap_or_else(|e| e.into_inner()) = Some(ctx);
            return Err(LiveUpdateError::ResolutionStarted);
        }
        if ctx.resolution != UpdateResolution::RollbackPublished {
            ctx.resolution = UpdateResolution::RollingBack;
            // LOOP_PROOF: mode=condition; reason=Each completed rollback removes one retained driver, and failure returns with the remaining publications owned by pending.;
            while let Some(rollback) = ctx.rollback_states.last() {
                let Some(old_entry) = ctx.old_entry.clone() else {
                    let remaining_drivers = ctx.rollback_states.len();
                    *self.pending.lock().unwrap_or_else(|e| e.into_inner()) = Some(ctx);
                    return Err(LiveUpdateError::RollbackIncomplete { remaining_drivers });
                };
                if crate::driver_registry::update_prepared_abi_driver(
                    rollback.handle,
                    old_entry,
                    rollback.state.clone(),
                )
                .is_err()
                {
                    let remaining_drivers = ctx.rollback_states.len();
                    *self.pending.lock().unwrap_or_else(|e| e.into_inner()) = Some(ctx);
                    return Err(LiveUpdateError::RollbackIncomplete { remaining_drivers });
                }
                Self::migrate_driver_ownership(
                    ctx.new_cell_id,
                    ctx.old_cell_id,
                    core::slice::from_ref(&rollback.handle),
                );
                ctx.rollback_states.pop();
            }
            crate::loader::with_registry(|registry| {
                if let Some(old) = registry.get(ctx.old_cell_id) {
                    old.code.restore();
                }
                if let Some(new) = registry.get(ctx.new_cell_id) {
                    new.code.retire(advance_epoch());
                }
            });
            ctx.old_entry = None;
            ctx.resolution = UpdateResolution::RollbackPublished;
        }
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = LiveUpdateState::WaitingQuiescent;
        if let Err(error) = crate::loader::unload_cell(ctx.new_cell_id) {
            let result = reclamation_error(ctx.new_cell_id, error);
            *self.pending.lock().unwrap_or_else(|e| e.into_inner()) = Some(ctx);
            return Err(result);
        }

        let result = UpdateTransition {
            old_cell_id: ctx.old_cell_id.as_u64(),
            new_cell_id: ctx.new_cell_id.as_u64(),
        };
        self.push_outcome(CompletedUpdateOutcome::RolledBack {
            old_cell_id: result.old_cell_id,
            new_cell_id: result.new_cell_id,
            at_tick: crate::task::current_tick(),
            reason: ctx.health_failure_reason,
        });
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = LiveUpdateState::Ready;
        self.rollback_epoch.store(0, Ordering::Release);
        Ok(result)
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

/// セルからドライバエントリポイントを解決
fn resolve_cell_entry(
    cell_id: crate::loader::CellId,
    owner: crate::domain::DomainId,
    call_init: bool,
) -> Result<crate::driver_registry::PreparedDriverExports, LiveUpdateError> {
    let lease = alloc::sync::Arc::new(
        crate::loader::acquire_code_lease(cell_id).ok_or(LiveUpdateError::CellNotFound)?,
    );
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
            .map_err(|_| LiveUpdateError::LoadFailed)?;
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
        fini: None,
        providers,
        state_hooks: crate::driver_registry::AbiDriverStateHooks::default(),
    })
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
