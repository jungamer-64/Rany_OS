// ============================================================================
// kernel/src/driver_cell/tests.rs - DriverCell QEMU test exports
// ============================================================================

#![allow(dead_code)]

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::fault::{FaultKind, RestartPolicy};
use super::stats::DriverCellStats;
use super::*;

#[cfg(feature = "qemu-test-export")]
static RUNTIME_FIXTURE_CELLS: crate::sync::PoisonLock<BTreeMap<String, Vec<u8>>> =
    crate::sync::PoisonLock::new(BTreeMap::new());

#[cfg(feature = "qemu-test-export")]
pub fn cache_runtime_fixture_cell(path: &str, data: &[u8]) {
    crate::io::log::early_print("[driver-cell-runtime] fixture-cache: enter ");
    crate::io::log::early_print(path);
    crate::io::log::early_print(" len=");
    crate::io::log::early_print_hex(data.len() as u64);
    crate::io::log::early_print("\n");
    if let Ok(mut cells) = RUNTIME_FIXTURE_CELLS.lock() {
        cells.insert(String::from(path), data.to_vec());
        crate::io::log::early_print("[driver-cell-runtime] fixture-cache: inserted\n");
    } else {
        crate::io::log::early_print("[driver-cell-runtime] fixture-cache: lock poisoned\n");
    }
}

#[cfg(feature = "qemu-test-export")]
fn cached_runtime_fixture_cell(path: &str) -> Option<Vec<u8>> {
    RUNTIME_FIXTURE_CELLS
        .lock()
        .ok()
        .and_then(|cells| cells.get(path).cloned())
}

pub fn driver_cell_state_default_is_created_smoke() -> bool {
    let state = DriverCellState::Created;
    matches!(state, DriverCellState::Created)
}

pub fn driver_cell_state_transitions_are_valid_smoke() -> bool {
    let mut state = DriverCellState::Created;
    if !matches!(state, DriverCellState::Created) {
        return false;
    }

    state = DriverCellState::Loaded;
    if !matches!(state, DriverCellState::Loaded) {
        return false;
    }

    state = DriverCellState::Running;
    if !matches!(state, DriverCellState::Running) {
        return false;
    }

    state = DriverCellState::Stopped;
    if !matches!(state, DriverCellState::Stopped) {
        return false;
    }

    state = DriverCellState::Unloaded;
    matches!(state, DriverCellState::Unloaded)
}

pub fn driver_cell_state_faulted_smoke() -> bool {
    let state = DriverCellState::Faulted;
    matches!(state, DriverCellState::Faulted)
}

pub fn driver_cell_id_equality_smoke() -> bool {
    let id1 = DriverCellId(1);
    let id2 = DriverCellId(1);
    let id3 = DriverCellId(2);

    id1 == id2 && id1 != id3
}

pub fn driver_cell_id_ordering_smoke() -> bool {
    let id1 = DriverCellId(1);
    let id2 = DriverCellId(2);
    let id3 = DriverCellId(3);

    id1 < id2 && id2 < id3
}

pub fn driver_cell_restart_policy_never_smoke() -> bool {
    let policy = RestartPolicy::Never;
    matches!(policy, RestartPolicy::Never)
}

pub fn driver_cell_restart_policy_on_panic_defaults_smoke() -> bool {
    let policy = RestartPolicy::OnPanic {
        max_retries: 3,
        backoff_ms: 100,
    };

    matches!(
        policy,
        RestartPolicy::OnPanic {
            max_retries: 3,
            backoff_ms: 100
        }
    )
}

pub fn driver_cell_restart_policy_always_smoke() -> bool {
    let policy = RestartPolicy::Always {
        max_retries: 5,
        backoff_ms: 200,
    };

    matches!(
        policy,
        RestartPolicy::Always {
            max_retries: 5,
            backoff_ms: 200
        }
    )
}

pub fn driver_cell_fault_kind_variants_smoke() -> bool {
    let kinds = [
        FaultKind::Panic(String::from("panic")),
        FaultKind::InitFailed(String::from("init")),
        FaultKind::Timeout,
        FaultKind::QuotaExceeded(String::from("quota")),
        FaultKind::MemoryViolation,
        FaultKind::Other(String::from("other")),
    ];

    for kind in kinds {
        let ok = matches!(
            kind,
            FaultKind::Panic(_)
                | FaultKind::InitFailed(_)
                | FaultKind::Timeout
                | FaultKind::QuotaExceeded(_)
                | FaultKind::MemoryViolation
                | FaultKind::Other(_)
        );
        if !ok {
            return false;
        }
    }
    true
}

pub fn driver_cell_restart_policy_retry_boundary_smoke() -> bool {
    let policy = RestartPolicy::on_panic(3, 100);
    policy.should_restart(FaultKind::Panic(String::from("x")), 1)
        && policy.should_restart(FaultKind::Panic(String::from("x")), 3)
        && !policy.should_restart(FaultKind::Panic(String::from("x")), 4)
        && !policy.should_restart(FaultKind::Timeout, 1)
}

pub fn driver_cell_restart_policy_backoff_cap_smoke() -> bool {
    let policy = RestartPolicy::always(10, 10_000);
    policy.backoff_for_attempt(0) == 10_000 && policy.backoff_for_attempt(10) == 30_000
}

pub fn driver_cell_stats_initial_values_smoke() -> bool {
    let stats = DriverCellStats::new();
    stats.load_duration_ticks == 0
        && stats.load_timestamp == 0
        && stats.start_count == 0
        && stats.stop_count == 0
        && stats.fault_count == 0
        && stats.restart_count == 0
        && stats.hot_swap_count == 0
        && stats.total_uptime_ticks == 0
        && stats.max_uptime_ticks == 0
}

pub fn driver_cell_stats_default_smoke() -> bool {
    let stats: DriverCellStats = Default::default();
    stats.start_count == 0
}

pub fn driver_cell_stats_record_start_smoke() -> bool {
    let mut stats = DriverCellStats::new();
    stats.record_start();
    stats.record_start();
    stats.start_count == 2
}

pub fn driver_cell_stats_record_stop_smoke() -> bool {
    let mut stats = DriverCellStats::new();
    stats.record_stop();
    stats.stop_count == 1
}

pub fn driver_cell_stats_record_fault_smoke() -> bool {
    let mut stats = DriverCellStats::new();
    stats.record_fault();
    stats.record_fault();
    stats.fault_count == 2
}

pub fn driver_cell_stats_record_restart_smoke() -> bool {
    let mut stats = DriverCellStats::new();
    stats.record_restart();
    stats.restart_count == 1
}

pub fn driver_cell_stats_record_hot_swap_smoke() -> bool {
    let mut stats = DriverCellStats::new();
    stats.record_hot_swap();
    stats.record_hot_swap();
    stats.record_hot_swap();
    stats.hot_swap_count == 3
}

pub fn driver_cell_error_not_found_smoke() -> bool {
    let err = DriverCellError::NotFound(DriverCellId(42));
    matches!(err, DriverCellError::NotFound(id) if id == DriverCellId(42))
}

pub fn driver_cell_error_invalid_state_smoke() -> bool {
    let err = DriverCellError::InvalidStateTransition {
        from: DriverCellState::Loaded,
        to: DriverCellState::Running,
    };

    matches!(
        err,
        DriverCellError::InvalidStateTransition {
            from: DriverCellState::Loaded,
            to: DriverCellState::Running
        }
    )
}

pub fn driver_cell_global_stats_new_smoke() -> bool {
    use super::stats::GlobalDriverCellStats;

    let stats = GlobalDriverCellStats::new();
    let summary = stats.summary();
    summary.total_created == 0 && summary.total_unloaded == 0 && summary.total_faults == 0
}

pub fn driver_cell_global_stats_tracking_smoke() -> bool {
    use super::stats::GlobalDriverCellStats;

    let stats = GlobalDriverCellStats::new();
    stats.on_created();
    stats.on_created();
    stats.on_fault();
    stats.on_hot_swap();

    let summary = stats.summary();
    summary.total_created == 2 && summary.total_faults == 1 && summary.total_hot_swaps == 1
}

#[cfg(feature = "qemu-test-export")]
#[derive(Debug, Clone, Copy)]
pub struct DriverCellRuntimeSuiteSummary {
    pub passed: u32,
    pub failed: u32,
    pub blocked: u32,
}

#[cfg(feature = "qemu-test-export")]
impl DriverCellRuntimeSuiteSummary {
    pub const fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
            blocked: 0,
        }
    }

    pub const fn is_success(&self) -> bool {
        self.failed == 0 && self.blocked == 0
    }
}

#[cfg(feature = "qemu-test-export")]
#[derive(Debug)]
enum RuntimeCaseError {
    Failed(String),
    Blocked(String),
}

#[cfg(feature = "qemu-test-export")]
impl RuntimeCaseError {
    fn failed(msg: impl Into<String>) -> Self {
        Self::Failed(msg.into())
    }

    fn blocked(msg: impl Into<String>) -> Self {
        Self::Blocked(msg.into())
    }
}

#[cfg(feature = "qemu-test-export")]
struct RuntimeContext {
    driver_cell_id: DriverCellId,
    v1_cell: Vec<u8>,
    v2_cell: Vec<u8>,
}

#[cfg(feature = "qemu-test-export")]
pub fn run_driver_cell_runtime_suite() -> DriverCellRuntimeSuiteSummary {
    let mut summary = DriverCellRuntimeSuiteSummary::new();
    runtime_log_line("[driver-cell-runtime] start");

    let mut ctx = match preflight() {
        Ok(ctx) => {
            summary.passed += 1;
            log_case("preflight", "pass", "");
            ctx
        }
        Err(RuntimeCaseError::Failed(reason)) => {
            summary.failed += 1;
            log_case("preflight", "fail", &reason);
            log_summary(&summary);
            return summary;
        }
        Err(RuntimeCaseError::Blocked(reason)) => {
            summary.blocked += 1;
            log_case("preflight", "blocked", &reason);
            log_summary(&summary);
            return summary;
        }
    };

    let old_grace = crate::loader::live_update::set_rollback_grace_period_for_test(1_000);

    run_case(
        &mut summary,
        "update_validating",
        case_update_to_validating(&mut ctx),
    );
    run_case(
        &mut summary,
        "manual_rollback",
        case_manual_rollback(&mut ctx),
    );
    run_case(
        &mut summary,
        "manual_commit",
        case_manual_commit(&mut ctx),
    );
    run_case(&mut summary, "auto_commit", case_auto_commit(&mut ctx));
    run_case(
        &mut summary,
        "auto_rollback_panic",
        case_auto_rollback_panic(&mut ctx),
    );
    run_case(
        &mut summary,
        "idle_restart_panic",
        case_idle_restart_panic(&mut ctx),
    );
    run_case(&mut summary, "unload_after_restart", case_unload(&mut ctx));

    crate::loader::live_update::set_rollback_grace_period_for_test(old_grace);
    log_summary(&summary);
    summary
}

#[cfg(feature = "qemu-test-export")]
fn preflight() -> Result<RuntimeContext, RuntimeCaseError> {
    runtime_log_line("[driver-cell-runtime] preflight: begin");
    let manager = driver_cell_manager();
    let running_cells = manager.cells_by_state(DriverCellState::Running);
    let driver_cell_id = match running_cells.as_slice() {
        [id] => *id,
        [] => {
            return Err(RuntimeCaseError::failed(
                "no Running DriverCell found (expected driver_cell_probe from initramfs)",
            ));
        }
        many => {
            return Err(RuntimeCaseError::failed(format!(
                "multiple Running DriverCells found (expected exactly 1, got {})",
                many.len()
            )));
        }
    };
    runtime_log_line("[driver-cell-runtime] preflight: selected running DriverCell");

    let (state, hot_swap_state, loader_cell_id) = manager
        .with_cell(driver_cell_id, |cell| (cell.state, cell.hot_swap_state, cell.cell_id))
        .map_err(|e| RuntimeCaseError::failed(format!("failed to inspect DriverCell: {}", e)))?;

    if state != DriverCellState::Running {
        return Err(RuntimeCaseError::failed(format!(
            "driver_cell_probe is not Running (state={})",
            state
        )));
    }
    if hot_swap_state != HotSwapState::Idle {
        return Err(RuntimeCaseError::failed(format!(
            "driver_cell_probe hot_swap state is not Idle (state={})",
            hot_swap_state
        )));
    }
    if loader_cell_id.is_none() {
        return Err(RuntimeCaseError::failed(
            "driver_cell_probe has no loader CellId",
        ));
    }

    let v1_cell = read_fixture_cell("/cells/driver_cell_probe_v1.cell")?;
    let v2_cell = read_fixture_cell("/cells/driver_cell_probe_v2.cell")?;
    runtime_log_line("[driver-cell-runtime] preflight: fixtures loaded");

    runtime_log_line("[driver-cell-runtime] preflight: wait_for_tick_progress");
    if !wait_for_tick_progress(5, 300_000) {
        return Err(RuntimeCaseError::blocked(
            "timer tick did not advance (try removing qemu_no_if=1)",
        ));
    }
    runtime_log_line("[driver-cell-runtime] preflight: tick progressed");

    Ok(RuntimeContext {
        driver_cell_id,
        v1_cell,
        v2_cell,
    })
}

#[cfg(feature = "qemu-test-export")]
fn case_update_to_validating(ctx: &mut RuntimeContext) -> Result<(), RuntimeCaseError> {
    ensure_running_idle(ctx.driver_cell_id)?;
    let result = super::hot_swap::hot_swap(ctx.driver_cell_id, &ctx.v2_cell)
        .map_err(|e| RuntimeCaseError::failed(format!("hot_swap(v2) failed: {}", e)))?;
    poll_runtime();

    let health = super::hot_swap::health_status(ctx.driver_cell_id)
        .map_err(|e| RuntimeCaseError::failed(format!("health_status failed: {}", e)))?;
    if health.hot_swap_state != HotSwapState::Validating {
        return Err(RuntimeCaseError::failed(format!(
            "expected Validating after update, got {}",
            health.hot_swap_state
        )));
    }
    if health.validation_deadline_tick.is_none() {
        return Err(RuntimeCaseError::failed(
            "validation deadline is missing after update",
        ));
    }
    if health.loader_cell_id.map(|v| v.as_u64()) != Some(result.new_cell_id.as_u64()) {
        return Err(RuntimeCaseError::failed(
            "loader CellId did not switch to new cell",
        ));
    }

    Ok(())
}

#[cfg(feature = "qemu-test-export")]
fn case_manual_rollback(ctx: &mut RuntimeContext) -> Result<(), RuntimeCaseError> {
    let before = super::hot_swap::health_status(ctx.driver_cell_id)
        .map_err(|e| RuntimeCaseError::failed(format!("health_status failed: {}", e)))?;
    if before.hot_swap_state != HotSwapState::Validating {
        return Err(RuntimeCaseError::failed(
            "manual rollback expects Validating state",
        ));
    }
    let before_loader = before
        .loader_cell_id
        .ok_or_else(|| RuntimeCaseError::failed("current loader CellId missing"))?
        .as_u64();

    super::hot_swap::rollback(ctx.driver_cell_id)
        .map_err(|e| RuntimeCaseError::failed(format!("rollback failed: {}", e)))?;
    poll_runtime();

    let after = super::hot_swap::health_status(ctx.driver_cell_id)
        .map_err(|e| RuntimeCaseError::failed(format!("health_status failed: {}", e)))?;
    if after.hot_swap_state != HotSwapState::Idle {
        return Err(RuntimeCaseError::failed(format!(
            "expected Idle after rollback, got {}",
            after.hot_swap_state
        )));
    }
    if after.validation_deadline_tick.is_some() {
        return Err(RuntimeCaseError::failed(
            "validation deadline remained after rollback",
        ));
    }
    let after_loader = after
        .loader_cell_id
        .ok_or_else(|| RuntimeCaseError::failed("loader CellId missing after rollback"))?
        .as_u64();
    if after_loader == before_loader {
        return Err(RuntimeCaseError::failed(
            "loader CellId did not move back on rollback",
        ));
    }

    Ok(())
}

#[cfg(feature = "qemu-test-export")]
fn case_manual_commit(ctx: &mut RuntimeContext) -> Result<(), RuntimeCaseError> {
    ensure_running_idle(ctx.driver_cell_id)?;
    let update = super::hot_swap::hot_swap(ctx.driver_cell_id, &ctx.v2_cell)
        .map_err(|e| RuntimeCaseError::failed(format!("hot_swap(v2) failed: {}", e)))?;
    poll_runtime();

    super::hot_swap::commit(ctx.driver_cell_id)
        .map_err(|e| RuntimeCaseError::failed(format!("commit failed: {}", e)))?;
    poll_runtime();

    let after = super::hot_swap::health_status(ctx.driver_cell_id)
        .map_err(|e| RuntimeCaseError::failed(format!("health_status failed: {}", e)))?;
    if after.hot_swap_state != HotSwapState::Idle {
        return Err(RuntimeCaseError::failed(format!(
            "expected Idle after commit, got {}",
            after.hot_swap_state
        )));
    }
    if after.validation_deadline_tick.is_some() {
        return Err(RuntimeCaseError::failed(
            "validation deadline remained after commit",
        ));
    }
    if after.loader_cell_id.map(|v| v.as_u64()) != Some(update.new_cell_id.as_u64()) {
        return Err(RuntimeCaseError::failed(
            "loader CellId is not the committed new cell",
        ));
    }

    Ok(())
}

#[cfg(feature = "qemu-test-export")]
fn case_auto_commit(ctx: &mut RuntimeContext) -> Result<(), RuntimeCaseError> {
    ensure_running_idle(ctx.driver_cell_id)?;
    let update = super::hot_swap::hot_swap(ctx.driver_cell_id, &ctx.v1_cell)
        .map_err(|e| RuntimeCaseError::failed(format!("hot_swap(v1) failed: {}", e)))?;
    poll_runtime();

    let validating = super::hot_swap::health_status(ctx.driver_cell_id)
        .map_err(|e| RuntimeCaseError::failed(format!("health_status failed: {}", e)))?;
    let deadline = validating
        .validation_deadline_tick
        .ok_or_else(|| RuntimeCaseError::failed("missing validation deadline for auto-commit"))?;

    if !wait_for_tick(deadline.saturating_add(5), 1_000_000) {
        return Err(RuntimeCaseError::blocked(
            "timer did not reach auto-commit deadline",
        ));
    }
    poll_runtime();

    let after = super::hot_swap::health_status(ctx.driver_cell_id)
        .map_err(|e| RuntimeCaseError::failed(format!("health_status failed: {}", e)))?;
    if after.hot_swap_state != HotSwapState::Idle {
        return Err(RuntimeCaseError::failed(format!(
            "auto-commit did not finish (state={})",
            after.hot_swap_state
        )));
    }
    if after.validation_deadline_tick.is_some() {
        return Err(RuntimeCaseError::failed(
            "validation deadline remained after auto-commit",
        ));
    }
    if after.loader_cell_id.map(|v| v.as_u64()) != Some(update.new_cell_id.as_u64()) {
        return Err(RuntimeCaseError::failed(
            "auto-commit did not keep new loader CellId",
        ));
    }

    Ok(())
}

#[cfg(feature = "qemu-test-export")]
fn case_auto_rollback_panic(ctx: &mut RuntimeContext) -> Result<(), RuntimeCaseError> {
    ensure_running_idle(ctx.driver_cell_id)?;
    let update = super::hot_swap::hot_swap(ctx.driver_cell_id, &ctx.v2_cell)
        .map_err(|e| RuntimeCaseError::failed(format!("hot_swap(v2) failed: {}", e)))?;
    poll_runtime();

    let (restart_before, fault_before) = driver_cell_manager()
        .with_cell(ctx.driver_cell_id, |cell| (cell.stats.restart_count, cell.stats.fault_count))
        .map_err(|e| RuntimeCaseError::failed(format!("failed to read stats: {}", e)))?;

    let outcome = super::fault::inject_test_fault(ctx.driver_cell_id, super::fault::TestFaultKind::Panic)
        .map_err(|e| RuntimeCaseError::failed(format!("inject_test_fault panic failed: {}", e)))?;
    poll_runtime();

    if outcome.action != super::fault::FaultAction::RolledBack {
        return Err(RuntimeCaseError::failed(format!(
            "expected RolledBack action, got {}",
            outcome.action
        )));
    }

    let (restart_after, fault_after) = driver_cell_manager()
        .with_cell(ctx.driver_cell_id, |cell| (cell.stats.restart_count, cell.stats.fault_count))
        .map_err(|e| RuntimeCaseError::failed(format!("failed to read stats: {}", e)))?;
    if restart_after != restart_before {
        return Err(RuntimeCaseError::failed(
            "restart_count changed during auto-rollback path",
        ));
    }
    if fault_after <= fault_before {
        return Err(RuntimeCaseError::failed(
            "fault_count did not increase after injected panic",
        ));
    }

    let after = super::hot_swap::health_status(ctx.driver_cell_id)
        .map_err(|e| RuntimeCaseError::failed(format!("health_status failed: {}", e)))?;
    if after.hot_swap_state != HotSwapState::Idle {
        return Err(RuntimeCaseError::failed(format!(
            "auto-rollback did not return to Idle (state={})",
            after.hot_swap_state
        )));
    }
    if after.validation_deadline_tick.is_some() {
        return Err(RuntimeCaseError::failed(
            "validation deadline remained after auto-rollback",
        ));
    }
    if after.loader_cell_id.map(|v| v.as_u64()) != Some(update.old_cell_id.as_u64()) {
        return Err(RuntimeCaseError::failed(
            "loader CellId did not return to old cell after auto-rollback",
        ));
    }
    if after.last_health_failure.is_none() {
        return Err(RuntimeCaseError::failed(
            "last_health_failure is empty after auto-rollback panic",
        ));
    }

    Ok(())
}

#[cfg(feature = "qemu-test-export")]
fn case_idle_restart_panic(ctx: &mut RuntimeContext) -> Result<(), RuntimeCaseError> {
    ensure_running_idle(ctx.driver_cell_id)?;
    let restart_before = driver_cell_manager()
        .with_cell(ctx.driver_cell_id, |cell| cell.stats.restart_count)
        .map_err(|e| RuntimeCaseError::failed(format!("failed to read restart_count: {}", e)))?;

    let outcome = super::fault::inject_test_fault(ctx.driver_cell_id, super::fault::TestFaultKind::Panic)
        .map_err(|e| RuntimeCaseError::failed(format!("inject_test_fault panic failed: {}", e)))?;
    poll_runtime();

    if outcome.action != super::fault::FaultAction::Restarted {
        return Err(RuntimeCaseError::failed(format!(
            "expected Restarted action in Idle panic path, got {}",
            outcome.action
        )));
    }

    let (restart_after, state_after, hot_swap_after) = driver_cell_manager()
        .with_cell(ctx.driver_cell_id, |cell| {
            (cell.stats.restart_count, cell.state, cell.hot_swap_state)
        })
        .map_err(|e| RuntimeCaseError::failed(format!("failed to inspect post-restart state: {}", e)))?;

    if restart_after <= restart_before {
        return Err(RuntimeCaseError::failed(
            "restart_count did not increase in Idle panic path",
        ));
    }
    if state_after != DriverCellState::Running {
        return Err(RuntimeCaseError::failed(format!(
            "DriverCell did not return to Running (state={})",
            state_after
        )));
    }
    if hot_swap_after != HotSwapState::Idle {
        return Err(RuntimeCaseError::failed(format!(
            "HotSwap state is not Idle after restart (state={})",
            hot_swap_after
        )));
    }

    Ok(())
}

#[cfg(feature = "qemu-test-export")]
fn case_unload(ctx: &mut RuntimeContext) -> Result<(), RuntimeCaseError> {
    super::lifecycle::unload(ctx.driver_cell_id)
        .map_err(|e| RuntimeCaseError::failed(format!("unload failed after restart: {}", e)))?;
    poll_runtime();

    match driver_cell_manager().with_cell(ctx.driver_cell_id, |_| ()) {
        Err(DriverCellError::NotFound(_)) => {}
        Ok(()) => {
            return Err(RuntimeCaseError::failed(
                "DriverCell still exists after unload",
            ));
        }
        Err(e) => {
            return Err(RuntimeCaseError::failed(format!(
                "failed to verify unload state: {}",
                e
            )));
        }
    }

    Ok(())
}

#[cfg(feature = "qemu-test-export")]
fn ensure_running_idle(id: DriverCellId) -> Result<(), RuntimeCaseError> {
    let (state, hot_swap_state) = driver_cell_manager()
        .with_cell(id, |cell| (cell.state, cell.hot_swap_state))
        .map_err(|e| RuntimeCaseError::failed(format!("failed to inspect DriverCell state: {}", e)))?;
    if state != DriverCellState::Running {
        return Err(RuntimeCaseError::failed(format!(
            "expected Running state, got {}",
            state
        )));
    }
    if hot_swap_state != HotSwapState::Idle {
        return Err(RuntimeCaseError::failed(format!(
            "expected Idle hot_swap state, got {}",
            hot_swap_state
        )));
    }
    Ok(())
}

#[cfg(feature = "qemu-test-export")]
fn poll_runtime() {
    crate::loader::live_update::poll_pending_updates();
    super::hot_swap::poll_validation_windows();
}

#[cfg(feature = "qemu-test-export")]
fn read_fixture_cell(path: &str) -> Result<Vec<u8>, RuntimeCaseError> {
    match crate::fs::read_file_content(path, "/") {
        Ok(data) => Ok(data),
        Err(fs_err) => {
            let key = path.strip_prefix('/').unwrap_or(path);
            if let Some(data) = cached_runtime_fixture_cell(key) {
                runtime_log_line(&format!(
                    "[driver-cell-runtime] fixture fallback from initramfs cache: {}",
                    path
                ));
                Ok(data)
            } else {
                Err(RuntimeCaseError::failed(format!(
                    "missing {}: {:?}",
                    path, fs_err
                )))
            }
        }
    }
}

#[cfg(feature = "qemu-test-export")]
fn maybe_inject_test_tick(stagnant_loops: usize) {
    // Full-boot QEMU profiles often run with qemu_no_if=1 to avoid unrelated
    // interrupt-path flakes. When timer ticks stop progressing, inject a
    // synthetic timer interrupt periodically so runtime validation windows can
    // advance in polling mode.
    if stagnant_loops != 0 && (stagnant_loops % 1024) == 0 {
        static LOGGED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
        if !LOGGED.swap(true, core::sync::atomic::Ordering::Relaxed) {
            runtime_log_line("[driver-cell-runtime] injecting synthetic timer ticks");
        }
        crate::task::timer::handle_timer_interrupt();
        crate::task::timer::process_pending_timer_wakers();
    }
}

#[cfg(feature = "qemu-test-export")]
fn wait_for_tick_progress(delta: u64, max_stagnant_loops: usize) -> bool {
    let start = crate::task::timer::current_tick();
    let mut last_tick = start;
    let mut stagnant = 0usize;

    while crate::task::timer::current_tick().saturating_sub(start) < delta {
        poll_runtime();
        let now = crate::task::timer::current_tick();
        if now > last_tick {
            last_tick = now;
            stagnant = 0;
        } else {
            stagnant = stagnant.saturating_add(1);
            maybe_inject_test_tick(stagnant);
        }

        if stagnant >= max_stagnant_loops {
            return false;
        }
        core::hint::spin_loop();
    }

    true
}

#[cfg(feature = "qemu-test-export")]
fn wait_for_tick(target: u64, max_stagnant_loops: usize) -> bool {
    let mut last_tick = crate::task::timer::current_tick();
    let mut stagnant = 0usize;

    while crate::task::timer::current_tick() < target {
        poll_runtime();
        let now = crate::task::timer::current_tick();
        if now > last_tick {
            last_tick = now;
            stagnant = 0;
        } else {
            stagnant = stagnant.saturating_add(1);
            maybe_inject_test_tick(stagnant);
        }

        if stagnant >= max_stagnant_loops {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

#[cfg(feature = "qemu-test-export")]
fn run_case(
    summary: &mut DriverCellRuntimeSuiteSummary,
    name: &str,
    result: Result<(), RuntimeCaseError>,
) {
    match result {
        Ok(()) => {
            summary.passed += 1;
            log_case(name, "pass", "");
        }
        Err(RuntimeCaseError::Failed(reason)) => {
            summary.failed += 1;
            log_case(name, "fail", &reason);
        }
        Err(RuntimeCaseError::Blocked(reason)) => {
            summary.blocked += 1;
            log_case(name, "blocked", &reason);
        }
    }
}

#[cfg(feature = "qemu-test-export")]
fn log_case(name: &str, status: &str, detail: &str) {
    if detail.is_empty() {
        runtime_log_line(&format!("[driver-cell-runtime] case {} ... {}", name, status));
    } else {
        runtime_log_line(&format!(
            "[driver-cell-runtime] case {} ... {} ({})",
            name,
            status,
            detail
        ));
    }
}

#[cfg(feature = "qemu-test-export")]
fn log_summary(summary: &DriverCellRuntimeSuiteSummary) {
    runtime_log_line(&format!(
        "[driver-cell-runtime] summary pass={} fail={} blocked={}",
        summary.passed,
        summary.failed,
        summary.blocked
    ));
}

#[cfg(feature = "qemu-test-export")]
fn runtime_log_line(line: &str) {
    crate::io::log::early_print(line);
    crate::io::log::early_print("\n");
}
