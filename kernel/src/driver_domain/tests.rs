// ============================================================================
// kernel/src/driver_domain/tests.rs - DriverDomain QEMU test exports
// ============================================================================

#![allow(dead_code)]

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::fault::{FaultKind, RestartPolicy};
use super::stats::DriverDomainStats;
use super::*;

#[cfg(feature = "qemu-test-export")]
static RUNTIME_FIXTURE_V1_PTR: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "qemu-test-export")]
static RUNTIME_FIXTURE_V1_LEN: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "qemu-test-export")]
static RUNTIME_FIXTURE_V2_PTR: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "qemu-test-export")]
static RUNTIME_FIXTURE_V2_LEN: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "qemu-test-export")]
pub fn cache_runtime_fixture_cell(path: &str, data: &[u8]) {
    crate::io::log::early_print("[driver-cell-runtime] fixture-cache: enter ");
    crate::io::log::early_print(path);
    crate::io::log::early_print(" len=");
    crate::io::log::early_print_hex(data.len() as u64);
    crate::io::log::early_print("\n");
    match fixture_variant(path) {
        Some(1) => {
            RUNTIME_FIXTURE_V1_PTR.store(data.as_ptr() as usize, Ordering::Release);
            RUNTIME_FIXTURE_V1_LEN.store(data.len(), Ordering::Release);
            crate::io::log::early_print("[driver-cell-runtime] fixture-cache: cached span v1\n");
        }
        Some(2) => {
            RUNTIME_FIXTURE_V2_PTR.store(data.as_ptr() as usize, Ordering::Release);
            RUNTIME_FIXTURE_V2_LEN.store(data.len(), Ordering::Release);
            crate::io::log::early_print("[driver-cell-runtime] fixture-cache: cached span v2\n");
        }
        _ => {
            crate::io::log::early_print("[driver-cell-runtime] fixture-cache: skipped unknown\n");
        }
    }
}

#[cfg(feature = "qemu-test-export")]
fn cached_runtime_fixture_cell(path: &str) -> Option<Vec<u8>> {
    match fixture_variant(path) {
        Some(1) => {
            let ptr = RUNTIME_FIXTURE_V1_PTR.load(Ordering::Acquire);
            let len = RUNTIME_FIXTURE_V1_LEN.load(Ordering::Acquire);
            (ptr != 0 && len != 0).then_some((ptr, len))
        }
        Some(2) => {
            let ptr = RUNTIME_FIXTURE_V2_PTR.load(Ordering::Acquire);
            let len = RUNTIME_FIXTURE_V2_LEN.load(Ordering::Acquire);
            (ptr != 0 && len != 0).then_some((ptr, len))
        }
        _ => None,
    }
    .map(|(ptr, len)| {
        // SAFETY: pointers/lengths are captured from boot artifact bytes, which stay
        // resident for the kernel lifetime in these QEMU test profiles.
        unsafe { core::slice::from_raw_parts(ptr as *const u8, len) }.to_vec()
    })
}

#[cfg(feature = "qemu-test-export")]
fn fixture_variant(path: &str) -> Option<u8> {
    let bytes = path.as_bytes();
    if bytes.len() < 8 {
        return None;
    }
    let n = bytes.len();
    if bytes[n - 8] != b'_' || bytes[n - 7] != b'v' || bytes[n - 5] != b'.' {
        return None;
    }
    if bytes[n - 4] != b'c' || bytes[n - 3] != b'e' || bytes[n - 2] != b'l' || bytes[n - 1] != b'l'
    {
        return None;
    }
    match bytes[n - 6] {
        b'1' => Some(1),
        b'2' => Some(2),
        _ => None,
    }
}

pub fn driver_domain_state_default_is_created_smoke() -> bool {
    let state = DriverDomainState::Created;
    matches!(state, DriverDomainState::Created)
}

pub fn driver_domain_state_transitions_are_valid_smoke() -> bool {
    let mut state = DriverDomainState::Created;
    if !matches!(state, DriverDomainState::Created) {
        return false;
    }

    state = DriverDomainState::Loaded;
    if !matches!(state, DriverDomainState::Loaded) {
        return false;
    }

    state = DriverDomainState::Running;
    if !matches!(state, DriverDomainState::Running) {
        return false;
    }

    state = DriverDomainState::Stopped;
    if !matches!(state, DriverDomainState::Stopped) {
        return false;
    }

    state = DriverDomainState::Unloaded;
    matches!(state, DriverDomainState::Unloaded)
}

pub fn driver_domain_state_faulted_smoke() -> bool {
    let state = DriverDomainState::Faulted;
    matches!(state, DriverDomainState::Faulted)
}

pub fn driver_domain_id_equality_smoke() -> bool {
    let id1 = DriverDomainId(1);
    let id2 = DriverDomainId(1);
    let id3 = DriverDomainId(2);

    id1 == id2 && id1 != id3
}

pub fn driver_domain_id_ordering_smoke() -> bool {
    let id1 = DriverDomainId(1);
    let id2 = DriverDomainId(2);
    let id3 = DriverDomainId(3);

    id1 < id2 && id2 < id3
}

pub fn driver_domain_restart_policy_never_smoke() -> bool {
    let policy = RestartPolicy::Never;
    matches!(policy, RestartPolicy::Never)
}

pub fn driver_domain_restart_policy_on_panic_defaults_smoke() -> bool {
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

pub fn driver_domain_restart_policy_always_smoke() -> bool {
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

pub fn driver_domain_fault_kind_variants_smoke() -> bool {
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

pub fn driver_domain_restart_policy_retry_boundary_smoke() -> bool {
    let policy = RestartPolicy::on_panic(3, 100);
    policy.should_restart(FaultKind::Panic(String::from("x")), 1)
        && policy.should_restart(FaultKind::Panic(String::from("x")), 3)
        && !policy.should_restart(FaultKind::Panic(String::from("x")), 4)
        && !policy.should_restart(FaultKind::Timeout, 1)
}

pub fn driver_domain_restart_policy_backoff_cap_smoke() -> bool {
    let policy = RestartPolicy::always(10, 10_000);
    policy.backoff_for_attempt(0) == 10_000 && policy.backoff_for_attempt(10) == 30_000
}

pub fn driver_domain_stats_initial_values_smoke() -> bool {
    let stats = DriverDomainStats::new();
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

pub fn driver_domain_stats_default_smoke() -> bool {
    let stats: DriverDomainStats = Default::default();
    stats.start_count == 0
}

pub fn driver_domain_stats_record_start_smoke() -> bool {
    let mut stats = DriverDomainStats::new();
    stats.record_start();
    stats.record_start();
    stats.start_count == 2
}

pub fn driver_domain_stats_record_stop_smoke() -> bool {
    let mut stats = DriverDomainStats::new();
    stats.record_stop();
    stats.stop_count == 1
}

pub fn driver_domain_stats_record_fault_smoke() -> bool {
    let mut stats = DriverDomainStats::new();
    stats.record_fault();
    stats.record_fault();
    stats.fault_count == 2
}

pub fn driver_domain_stats_record_restart_smoke() -> bool {
    let mut stats = DriverDomainStats::new();
    stats.record_restart();
    stats.restart_count == 1
}

pub fn driver_domain_stats_record_hot_swap_smoke() -> bool {
    let mut stats = DriverDomainStats::new();
    stats.record_hot_swap();
    stats.record_hot_swap();
    stats.record_hot_swap();
    stats.hot_swap_count == 3
}

pub fn driver_domain_error_not_found_smoke() -> bool {
    let err = DriverDomainError::NotFound(DriverDomainId(42));
    matches!(err, DriverDomainError::NotFound(id) if id == DriverDomainId(42))
}

pub fn driver_domain_error_invalid_state_smoke() -> bool {
    let err = DriverDomainError::InvalidStateTransition {
        from: DriverDomainState::Loaded,
        to: DriverDomainState::Running,
    };

    matches!(
        err,
        DriverDomainError::InvalidStateTransition {
            from: DriverDomainState::Loaded,
            to: DriverDomainState::Running
        }
    )
}

pub fn driver_domain_global_stats_new_smoke() -> bool {
    use super::stats::GlobalDriverDomainStats;

    let stats = GlobalDriverDomainStats::new();
    let summary = stats.summary();
    summary.total_created == 0 && summary.total_unloaded == 0 && summary.total_faults == 0
}

pub fn driver_domain_global_stats_tracking_smoke() -> bool {
    use super::stats::GlobalDriverDomainStats;

    let stats = GlobalDriverDomainStats::new();
    stats.on_created();
    stats.on_created();
    stats.on_fault();
    stats.on_hot_swap();

    let summary = stats.summary();
    summary.total_created == 2 && summary.total_faults == 1 && summary.total_hot_swaps == 1
}

#[cfg(feature = "qemu-test-export")]
#[derive(Debug, Clone, Copy)]
pub struct DriverDomainRuntimeSuiteSummary {
    pub passed: u32,
    pub failed: u32,
    pub blocked: u32,
}

#[cfg(feature = "qemu-test-export")]
impl DriverDomainRuntimeSuiteSummary {
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
    driver_domain_id: DriverDomainId,
    staged_pci_domain_id: DriverDomainId,
    v1_cell: Vec<u8>,
    v2_cell: Vec<u8>,
    too_new_pack: Vec<u8>,
}

#[cfg(feature = "qemu-test-export")]
#[repr(C)]
#[derive(Clone, Copy)]
struct ObservedDriverContext {
    probe_count: u32,
    start_count: u32,
    reserved: [u32; 2],
    ctx: kernel_api::abi::driver::DriverContext,
}

#[cfg(feature = "qemu-test-export")]
fn case_matches_filter(case_filter: Option<&str>, name: &str) -> bool {
    case_filter.is_none_or(|filter| crate::loader::str_eq(filter, name))
}

#[cfg(feature = "qemu-test-export")]
pub fn run_driver_domain_runtime_suite(
    case_filter: Option<&str>,
) -> DriverDomainRuntimeSuiteSummary {
    let mut summary = DriverDomainRuntimeSuiteSummary::new();
    runtime_log_line("[driver-cell-runtime] start");
    crate::io::iommu::api::reset_map_unmap_counts();
    let old_aslr = crate::loader::elf::is_aslr_enabled();
    crate::loader::elf::set_aslr_enabled(false);

    let mut selected_any = false;
    for name in [
        "staged_pci_probe_receives_real_driver_context",
        "no_dma_fallbacks_recorded",
        "loader_rejects_too_new_kernel_api",
        "update_validating",
        "manual_rollback",
        "manual_commit",
        "auto_commit",
        "auto_rollback_panic",
        "idle_restart_panic",
        "unload",
    ] {
        if case_matches_filter(case_filter, name) {
            selected_any = true;
            break;
        }
    }

    if !selected_any {
        summary.failed = 1;
        log_case(
            case_filter.unwrap_or("driver_domain.case_selection"),
            "fail",
            "no matching runtime case",
        );
        log_summary(&summary);
        crate::loader::elf::set_aslr_enabled(old_aslr);
        return summary;
    }

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
            crate::loader::elf::set_aslr_enabled(old_aslr);
            return summary;
        }
        Err(RuntimeCaseError::Blocked(reason)) => {
            summary.blocked += 1;
            log_case("preflight", "blocked", &reason);
            log_summary(&summary);
            crate::loader::elf::set_aslr_enabled(old_aslr);
            return summary;
        }
    };

    let old_grace = crate::loader::live_update::set_rollback_grace_period_for_test(1_000);

    if case_matches_filter(case_filter, "staged_pci_probe_receives_real_driver_context") {
        run_case(
            &mut summary,
            "staged_pci_probe_receives_real_driver_context",
            case_staged_pci_probe_receives_real_driver_context(&ctx),
        );
    }
    if case_matches_filter(case_filter, "no_dma_fallbacks_recorded") {
        run_case(
            &mut summary,
            "no_dma_fallbacks_recorded",
            case_no_dma_fallbacks_recorded(),
        );
    }
    if case_matches_filter(case_filter, "loader_rejects_too_new_kernel_api") {
        run_case(
            &mut summary,
            "loader_rejects_too_new_kernel_api",
            case_loader_rejects_too_new_kernel_api(&ctx),
        );
    }
    if case_matches_filter(case_filter, "update_validating") {
        run_case(
            &mut summary,
            "update_validating",
            case_update_to_validating(&mut ctx),
        );
    }
    if case_matches_filter(case_filter, "manual_rollback") {
        run_case(
            &mut summary,
            "manual_rollback",
            case_manual_rollback(&mut ctx),
        );
    }
    if case_matches_filter(case_filter, "manual_commit") {
        run_case(&mut summary, "manual_commit", case_manual_commit(&mut ctx));
    }
    if case_matches_filter(case_filter, "auto_commit") {
        run_case(&mut summary, "auto_commit", case_auto_commit(&mut ctx));
    }
    if case_matches_filter(case_filter, "auto_rollback_panic") {
        run_case(
            &mut summary,
            "auto_rollback_panic",
            case_auto_rollback_panic(&mut ctx),
        );
    }
    if case_matches_filter(case_filter, "idle_restart_panic") {
        run_case(
            &mut summary,
            "idle_restart_panic",
            case_idle_restart_panic(&mut ctx),
        );
    }
    if case_matches_filter(case_filter, "unload") {
        run_case(&mut summary, "unload", case_unload(&mut ctx));
    }

    crate::loader::live_update::set_rollback_grace_period_for_test(old_grace);
    crate::loader::elf::set_aslr_enabled(old_aslr);
    log_summary(&summary);
    summary
}

#[cfg(feature = "qemu-test-export")]
fn preflight() -> Result<RuntimeContext, RuntimeCaseError> {
    runtime_log_line("[driver-cell-runtime] preflight: begin");
    let manager = driver_domain_manager();
    let running_cells = manager.cells_by_state(DriverDomainState::Running);
    let mut driver_domain_id = None;
    let mut staged_pci_domain_id = None;
    for id in running_cells {
        let name = manager
            .with_cell(id, |cell| cell.name.clone())
            .map_err(|e| {
                RuntimeCaseError::failed(format!("failed to inspect DriverDomain: {}", e))
            })?;
        if crate::loader::str_eq(name.as_str(), "driver_cell_probe") {
            driver_domain_id = Some(id);
        } else if name.starts_with("driver_cell_probe_pci@") {
            staged_pci_domain_id = Some(id);
        }
    }
    let driver_domain_id = driver_domain_id.ok_or_else(|| {
        RuntimeCaseError::failed(
            "no Running DriverDomain named driver_cell_probe found (expected generic boot artifact fixture)",
        )
    })?;
    let staged_pci_domain_id = staged_pci_domain_id.ok_or_else(|| {
        RuntimeCaseError::failed(
            "no staged PCI probe DriverDomain found (expected driver_cell_probe_pci@...)",
        )
    })?;
    runtime_log_line("[driver-cell-runtime] preflight: selected running DriverDomain");

    let (state, hot_swap_state, loader_cell_id) = manager
        .with_cell(driver_domain_id, |cell| {
            (cell.state, cell.hot_swap_state, cell.cell_id)
        })
        .map_err(|e| RuntimeCaseError::failed(format!("failed to inspect DriverDomain: {}", e)))?;

    if state != DriverDomainState::Running {
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
    let too_new_pack = crate::loader::driver_pack::build_unsigned_driver_pack(
        "driver_cell_probe_too_new",
        &v1_cell,
        kernel_api::abi::driver::KERNEL_API_ABI_VERSION + 1,
    );
    runtime_log_line("[driver-cell-runtime] preflight: fixtures loaded");

    runtime_log_line("[driver-cell-runtime] preflight: wait_for_tick_progress");
    if !wait_for_tick_progress(5, 300_000) {
        return Err(RuntimeCaseError::blocked(
            "timer tick did not advance (try removing qemu_no_if=1)",
        ));
    }
    runtime_log_line("[driver-cell-runtime] preflight: tick progressed");

    Ok(RuntimeContext {
        driver_domain_id,
        staged_pci_domain_id,
        v1_cell,
        v2_cell,
        too_new_pack,
    })
}

#[cfg(feature = "qemu-test-export")]
fn case_staged_pci_probe_receives_real_driver_context(
    ctx: &RuntimeContext,
) -> Result<(), RuntimeCaseError> {
    let expected_dev = crate::platform::pci::find_by_class(0x04, 0x03)
        .into_iter()
        .next()
        .ok_or_else(|| RuntimeCaseError::failed("intel-hda test device not found"))?;
    let bar0 =
        expected_dev.bars[0].ok_or_else(|| RuntimeCaseError::failed("intel-hda BAR0 missing"))?;
    let expected_mmio =
        crate::memory::phys_to_virt(x86_64::PhysAddr::new_truncate(bar0.base())).as_u64();
    let expected_ctx = kernel_api::abi::driver::DriverContext::for_pci(
        expected_mmio,
        expected_dev.interrupt_line as u32,
        expected_dev.vendor_id.0,
        expected_dev.device_id.0,
        ((expected_dev.class_code.class as u32) << 16)
            | ((expected_dev.class_code.subclass as u32) << 8)
            | expected_dev.class_code.prog_if as u32,
        expected_dev.packed_locator(),
    );

    let (maybe_cell_id, stored_ctx) = driver_domain_manager()
        .with_cell(ctx.staged_pci_domain_id, |cell| {
            (cell.cell_id, cell.abi_driver_context)
        })
        .map_err(|e| {
            RuntimeCaseError::failed(format!("failed to inspect staged DriverDomain: {}", e))
        })?;
    let cell_id = maybe_cell_id
        .ok_or_else(|| RuntimeCaseError::failed("staged PCI probe cell_id missing"))?;

    if stored_ctx.device_address != expected_ctx.device_address
        || stored_ctx.irq != expected_ctx.irq
        || stored_ctx.vendor_id != expected_ctx.vendor_id
        || stored_ctx.device_id != expected_ctx.device_id
        || stored_ctx.class_code != expected_ctx.class_code
        || stored_ctx.pci_location() != expected_ctx.pci_location()
    {
        return Err(RuntimeCaseError::failed(format!(
            "staged DriverDomain context mismatch: stored={:?} expected={:?}",
            stored_ctx, expected_ctx
        )));
    }

    let observed = read_observed_context(cell_id)?;
    if observed.probe_count == 0 || observed.start_count == 0 {
        return Err(RuntimeCaseError::failed(format!(
            "staged probe fixture counters invalid: probe_count={} start_count={}",
            observed.probe_count, observed.start_count
        )));
    }
    if observed.ctx.device_address != expected_ctx.device_address
        || observed.ctx.irq != expected_ctx.irq
        || observed.ctx.vendor_id != expected_ctx.vendor_id
        || observed.ctx.device_id != expected_ctx.device_id
        || observed.ctx.class_code != expected_ctx.class_code
        || observed.ctx.pci_location() != expected_ctx.pci_location()
    {
        return Err(RuntimeCaseError::failed(format!(
            "observed driver context mismatch: observed={:?} expected={:?}",
            observed.ctx, expected_ctx
        )));
    }

    Ok(())
}

#[cfg(feature = "qemu-test-export")]
fn read_observed_context(
    cell_id: crate::loader::CellId,
) -> Result<ObservedDriverContext, RuntimeCaseError> {
    let observed_addr = crate::loader::with_registry(|r| {
        r.get(cell_id).and_then(|cell| {
            cell.exports
                .iter()
                .find(|(name, _)| {
                    crate::loader::str_eq(
                        name.as_str(),
                        "__exorust_driver_cell_probe_observed_context",
                    )
                })
                .map(|(_, addr)| *addr)
        })
    })
    .ok_or_else(|| {
        RuntimeCaseError::failed(
            "driver_cell_probe observed context export missing from staged cell",
        )
    })?;

    Ok(unsafe { core::ptr::read(observed_addr as *const ObservedDriverContext) })
}

#[cfg(feature = "qemu-test-export")]
fn case_no_dma_fallbacks_recorded() -> Result<(), RuntimeCaseError> {
    if crate::io::iommu::api::get_identity_fallback_count() != 0 {
        return Err(RuntimeCaseError::failed(
            "driver_domain profile recorded identity DMA fallback usage",
        ));
    }
    Ok(())
}

#[cfg(feature = "qemu-test-export")]
fn case_loader_rejects_too_new_kernel_api(ctx: &RuntimeContext) -> Result<(), RuntimeCaseError> {
    ensure_running_idle(ctx.driver_domain_id)?;

    let driver_registry = crate::driver_registry::driver_registry();
    let driver_count_before = driver_registry.count();
    let running_driver_count_before = driver_registry.running_count();
    let cell_count_before = crate::loader::with_registry(|r| r.all_cells().count());
    let running_domains_before = driver_domain_manager().cells_by_state(DriverDomainState::Running);
    let health_before = super::hot_swap::health_status(ctx.driver_domain_id)
        .map_err(|e| RuntimeCaseError::failed(format!("health_status failed: {}", e)))?;

    match crate::loader::load_driver_pack("driver_cell_probe_too_new", &ctx.too_new_pack, true) {
        Err(crate::loader::LoadError::AbiIncompatible(msg))
            if crate::loader::str_eq(msg.as_str(), "Kernel API ABI version too old") => {}
        Err(e) => {
            return Err(RuntimeCaseError::failed(format!(
                "unexpected load_driver_pack error: {}",
                e
            )));
        }
        Ok(handle) => {
            return Err(RuntimeCaseError::failed(format!(
                "load_driver_pack unexpectedly succeeded: {:?}",
                handle
            )));
        }
    }

    let driver_count_after = driver_registry.count();
    let running_driver_count_after = driver_registry.running_count();
    let cell_count_after = crate::loader::with_registry(|r| r.all_cells().count());
    let running_domains_after = driver_domain_manager().cells_by_state(DriverDomainState::Running);
    let health_after = super::hot_swap::health_status(ctx.driver_domain_id)
        .map_err(|e| RuntimeCaseError::failed(format!("health_status failed: {}", e)))?;

    if driver_count_after != driver_count_before {
        return Err(RuntimeCaseError::failed(format!(
            "driver count changed after ABI rejection: {} -> {}",
            driver_count_before, driver_count_after
        )));
    }
    if running_driver_count_after != running_driver_count_before {
        return Err(RuntimeCaseError::failed(format!(
            "running driver count changed after ABI rejection: {} -> {}",
            running_driver_count_before, running_driver_count_after
        )));
    }
    if cell_count_after != cell_count_before {
        return Err(RuntimeCaseError::failed(format!(
            "loader cell count changed after ABI rejection: {} -> {}",
            cell_count_before, cell_count_after
        )));
    }
    if running_domains_after != running_domains_before {
        return Err(RuntimeCaseError::failed(
            "running DriverDomain set changed after ABI rejection",
        ));
    }
    if health_after.hot_swap_state != health_before.hot_swap_state {
        return Err(RuntimeCaseError::failed(format!(
            "hot_swap state changed after ABI rejection: {} -> {}",
            health_before.hot_swap_state, health_after.hot_swap_state
        )));
    }
    if health_after.loader_cell_id != health_before.loader_cell_id {
        return Err(RuntimeCaseError::failed(
            "loader CellId changed after ABI rejection",
        ));
    }
    if health_after.last_health_failure != health_before.last_health_failure {
        return Err(RuntimeCaseError::failed(
            "last_health_failure changed after ABI rejection",
        ));
    }

    Ok(())
}

#[cfg(feature = "qemu-test-export")]
fn case_update_to_validating(ctx: &mut RuntimeContext) -> Result<(), RuntimeCaseError> {
    ensure_running_idle(ctx.driver_domain_id)?;
    let result = super::hot_swap::hot_swap(ctx.driver_domain_id, &ctx.v2_cell)
        .map_err(|e| RuntimeCaseError::failed(format!("hot_swap(v2) failed: {}", e)))?;
    poll_runtime();

    let health = super::hot_swap::health_status(ctx.driver_domain_id)
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
    let before = super::hot_swap::health_status(ctx.driver_domain_id)
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

    super::hot_swap::rollback(ctx.driver_domain_id)
        .map_err(|e| RuntimeCaseError::failed(format!("rollback failed: {}", e)))?;
    poll_runtime();

    let after = super::hot_swap::health_status(ctx.driver_domain_id)
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
    ensure_running_idle(ctx.driver_domain_id)?;
    let update = super::hot_swap::hot_swap(ctx.driver_domain_id, &ctx.v2_cell)
        .map_err(|e| RuntimeCaseError::failed(format!("hot_swap(v2) failed: {}", e)))?;
    poll_runtime();

    super::hot_swap::commit(ctx.driver_domain_id)
        .map_err(|e| RuntimeCaseError::failed(format!("commit failed: {}", e)))?;
    poll_runtime();

    let after = super::hot_swap::health_status(ctx.driver_domain_id)
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
    ensure_running_idle(ctx.driver_domain_id)?;
    let update = super::hot_swap::hot_swap(ctx.driver_domain_id, &ctx.v1_cell)
        .map_err(|e| RuntimeCaseError::failed(format!("hot_swap(v1) failed: {}", e)))?;
    poll_runtime();

    let validating = super::hot_swap::health_status(ctx.driver_domain_id)
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

    let after = super::hot_swap::health_status(ctx.driver_domain_id)
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
    ensure_running_idle(ctx.driver_domain_id)?;
    runtime_log_line("[driver-cell-runtime] auto_rollback_panic: hot_swap begin");
    let update = super::hot_swap::hot_swap(ctx.driver_domain_id, &ctx.v2_cell)
        .map_err(|e| RuntimeCaseError::failed(format!("hot_swap(v2) failed: {}", e)))?;
    runtime_log_line("[driver-cell-runtime] auto_rollback_panic: hot_swap done");
    runtime_log_line("[driver-cell-runtime] auto_rollback_panic: poll_runtime begin");
    poll_runtime();
    runtime_log_line("[driver-cell-runtime] auto_rollback_panic: poll_runtime done");

    runtime_log_line("[driver-cell-runtime] auto_rollback_panic: read stats begin");
    let (restart_before, fault_before) = driver_domain_manager()
        .with_cell(ctx.driver_domain_id, |cell| {
            (cell.stats.restart_count, cell.stats.fault_count)
        })
        .map_err(|e| RuntimeCaseError::failed(format!("failed to read stats: {}", e)))?;
    runtime_log_line("[driver-cell-runtime] auto_rollback_panic: read stats done");

    runtime_log_line("[driver-cell-runtime] auto_rollback_panic: inject panic begin");
    let outcome = super::fault::inject_test_fault(
        ctx.driver_domain_id,
        super::fault::TestFaultKind::Panic,
    )
    .map_err(|e| RuntimeCaseError::failed(format!("inject_test_fault panic failed: {}", e)))?;
    runtime_log_line("[driver-cell-runtime] auto_rollback_panic: inject panic done");
    runtime_log_line("[driver-cell-runtime] auto_rollback_panic: poll_runtime2 begin");
    poll_runtime();
    runtime_log_line("[driver-cell-runtime] auto_rollback_panic: poll_runtime2 done");

    if outcome.action != super::fault::FaultAction::RolledBack {
        return Err(RuntimeCaseError::failed(format!(
            "expected RolledBack action, got {}",
            outcome.action
        )));
    }

    let (restart_after, fault_after) = driver_domain_manager()
        .with_cell(ctx.driver_domain_id, |cell| {
            (cell.stats.restart_count, cell.stats.fault_count)
        })
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

    let after = super::hot_swap::health_status(ctx.driver_domain_id)
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
    ensure_running_idle(ctx.driver_domain_id)?;
    let restart_before = driver_domain_manager()
        .with_cell(ctx.driver_domain_id, |cell| cell.stats.restart_count)
        .map_err(|e| RuntimeCaseError::failed(format!("failed to read restart_count: {}", e)))?;

    let outcome = super::fault::inject_test_fault(
        ctx.driver_domain_id,
        super::fault::TestFaultKind::Panic,
    )
    .map_err(|e| RuntimeCaseError::failed(format!("inject_test_fault panic failed: {}", e)))?;
    poll_runtime();

    if outcome.action != super::fault::FaultAction::Restarted {
        return Err(RuntimeCaseError::failed(format!(
            "expected Restarted action in Idle panic path, got {}",
            outcome.action
        )));
    }

    let (restart_after, state_after, hot_swap_after) = driver_domain_manager()
        .with_cell(ctx.driver_domain_id, |cell| {
            (cell.stats.restart_count, cell.state, cell.hot_swap_state)
        })
        .map_err(|e| {
            RuntimeCaseError::failed(format!("failed to inspect post-restart state: {}", e))
        })?;

    if restart_after <= restart_before {
        return Err(RuntimeCaseError::failed(
            "restart_count did not increase in Idle panic path",
        ));
    }
    if state_after != DriverDomainState::Running {
        return Err(RuntimeCaseError::failed(format!(
            "DriverDomain did not return to Running (state={})",
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
    super::lifecycle::unload(ctx.driver_domain_id)
        .map_err(|e| RuntimeCaseError::failed(format!("unload failed after restart: {}", e)))?;
    poll_runtime();

    match driver_domain_manager().with_cell(ctx.driver_domain_id, |_| ()) {
        Err(DriverDomainError::NotFound(_)) => {}
        Ok(()) => {
            return Err(RuntimeCaseError::failed(
                "DriverDomain still exists after unload",
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
fn ensure_running_idle(id: DriverDomainId) -> Result<(), RuntimeCaseError> {
    let (state, hot_swap_state) = driver_domain_manager()
        .with_cell(id, |cell| (cell.state, cell.hot_swap_state))
        .map_err(|e| {
            RuntimeCaseError::failed(format!("failed to inspect DriverDomain state: {}", e))
        })?;
    if state != DriverDomainState::Running {
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
                    "[driver-cell-runtime] fixture fallback from boot artifact cache: {}",
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

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
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

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
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
    summary: &mut DriverDomainRuntimeSuiteSummary,
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
        runtime_log_line(&format!(
            "[driver-cell-runtime] case {} ... {}",
            name, status
        ));
    } else {
        runtime_log_line(&format!(
            "[driver-cell-runtime] case {} ... {} ({})",
            name, status, detail
        ));
    }
}

#[cfg(feature = "qemu-test-export")]
fn log_summary(summary: &DriverDomainRuntimeSuiteSummary) {
    runtime_log_line(&format!(
        "[driver-cell-runtime] summary pass={} fail={} blocked={}",
        summary.passed, summary.failed, summary.blocked
    ));
}

#[cfg(feature = "qemu-test-export")]
fn runtime_log_line(line: &str) {
    crate::io::log::early_print(line);
    crate::io::log::early_print("\n");
}
