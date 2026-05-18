#[cfg(feature = "qemu-test-export")]
use alloc::format;
#[cfg(feature = "qemu-test-export")]
use alloc::string::String;
#[cfg(feature = "qemu-test-export")]
use alloc::sync::Arc;
#[cfg(feature = "qemu-test-export")]
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[cfg(feature = "qemu-test-export")]
use crate::fs::{FileMode, Inode, MemoryInode};
#[cfg(feature = "qemu-test-export")]
use crate::task::{self, InterruptSource, Task};

#[cfg(feature = "qemu-test-export")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootRuntimeSuiteSummary {
    pub passed: u32,
    pub failed: u32,
    pub blocked: u32,
}

#[cfg(feature = "qemu-test-export")]
impl BootRuntimeSuiteSummary {
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
enum BootCaseError {
    Failed(String),
    Blocked(String),
}

#[cfg(feature = "qemu-test-export")]
impl BootCaseError {
    fn failed(msg: impl Into<String>) -> Self {
        Self::Failed(msg.into())
    }

    fn blocked(msg: impl Into<String>) -> Self {
        Self::Blocked(msg.into())
    }
}

#[cfg(feature = "qemu-test-export")]
type BootCase = fn() -> Result<(), BootCaseError>;

#[cfg(feature = "qemu-test-export")]
static BOOT_RUNTIME_CASES: &[(&str, BootCase)] = &[
    ("interrupts_enabled", case_interrupts_enabled),
    ("smp_workers_online", case_smp_workers_online),
    ("per_core_workers_running", case_per_core_workers_running),
    (
        "async_boot_stages_distributed",
        case_async_boot_stages_distributed,
    ),
    (
        "runtime_local_timers_enabled",
        case_runtime_local_timers_enabled,
    ),
    (
        "pit_irq0_masked_after_handoff",
        case_pit_irq0_masked_after_handoff,
    ),
    (
        "apic_timers_armed_on_all_online_cpus",
        case_apic_timers_armed_on_all_online_cpus,
    ),
    (
        "per_cpu_local_ticks_progress",
        case_per_cpu_local_ticks_progress,
    ),
    (
        "cross_core_preemption_isolated",
        case_cross_core_preemption_isolated,
    ),
    ("uptime_ms_progresses", case_uptime_ms_progresses),
    ("tick_progresses", case_tick_progresses),
    ("sleep_ms_resumes", case_sleep_ms_resumes),
    ("timer_waker_deferred_path", case_timer_waker_deferred_path),
    (
        "keyboard_deferred_wake_path",
        case_keyboard_deferred_wake_path,
    ),
    ("serial_deferred_wake_path", case_serial_deferred_wake_path),
    (
        "time_service_wall_clock_consumers",
        case_time_service_wall_clock_consumers,
    ),
];

#[cfg(feature = "qemu-test-export")]
#[inline]
fn str_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }

    let mut i = 0usize;
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while i < a_bytes.len() {
        if a_bytes[i] != b_bytes[i] {
            return false;
        }
        i += 1;
    }

    true
}

#[cfg(feature = "qemu-test-export")]
pub fn run_boot_runtime_suite(case_filter: Option<&str>) -> BootRuntimeSuiteSummary {
    log::info!(target: "init", "[kernel-test][boot] start");

    let mut summary = BootRuntimeSuiteSummary::new();
    let mut selected_any = false;

    for (id, run_case) in BOOT_RUNTIME_CASES {
        if let Some(filter) = case_filter {
            if !str_eq(id, filter) {
                continue;
            }
        }

        selected_any = true;
        match run_case() {
            Ok(()) => {
                summary.passed += 1;
                log::info!(target: "init", "[kernel-test][boot] case {id} ok");
            }
            Err(BootCaseError::Failed(reason)) => {
                summary.failed += 1;
                log::info!(target: "init", "[kernel-test][boot] case {id} fail ({reason})");
            }
            Err(BootCaseError::Blocked(reason)) => {
                summary.blocked += 1;
                log::info!(target: "init", "[kernel-test][boot] case {id} blocked ({reason})");
            }
        }
    }

    if !selected_any {
        summary.failed = 1;
        log::info!(
            target: "init",
            "[kernel-test][boot] case {} fail (no matching case)",
            case_filter.unwrap_or("boot.case_selection")
        );
    }

    log::info!(
        target: "init",
        "[kernel-test][boot] summary pass={} fail={} blocked={}",
        summary.passed,
        summary.failed,
        summary.blocked
    );
    log::info!(
        target: "init",
        "[kernel-test][boot] result {}",
        if summary.is_success() { "pass" } else { "fail" }
    );

    summary
}

#[cfg(feature = "qemu-test-export")]
fn case_interrupts_enabled() -> Result<(), BootCaseError> {
    if crate::interrupts::are_interrupts_enabled() {
        Ok(())
    } else {
        Err(BootCaseError::failed(
            "interrupts are disabled in boot-smoke runtime",
        ))
    }
}

#[cfg(feature = "qemu-test-export")]
fn case_smp_workers_online() -> Result<(), BootCaseError> {
    let cpu_count = crate::cpu::count() as usize;
    if cpu_count <= 1 {
        return Err(BootCaseError::blocked(
            "smp_workers_online requires a multi-core QEMU configuration",
        ));
    }

    let per_cpu_count = crate::cpu::count();
    if per_cpu_count != cpu_count {
        return Err(BootCaseError::failed(format!(
            "per_cpu active count mismatch: expected={} actual={}",
            cpu_count, per_cpu_count
        )));
    }

    let executor_cpu_count = task::executor_slot_count();
    if executor_cpu_count != cpu_count {
        return Err(BootCaseError::failed(format!(
            "executor active count mismatch: expected={} actual={}",
            cpu_count, executor_cpu_count
        )));
    }

    if !crate::cpu::workers_released() {
        return Err(BootCaseError::failed(
            "runtime workers were not released before boot runtime checks",
        ));
    }

    Ok(())
}

#[cfg(feature = "qemu-test-export")]
fn case_per_core_workers_running() -> Result<(), BootCaseError> {
    let cpu_count = crate::cpu::count() as usize;
    if cpu_count <= 1 {
        return Err(BootCaseError::blocked(
            "per_core_workers_running requires a multi-core QEMU configuration",
        ));
    }

    for cpu_id in 0..cpu_count {
        let Some(stage) = crate::cpu::stage_name(cpu_id) else {
            return Err(BootCaseError::failed(format!(
                "runtime worker stage unavailable for cpu{}",
                cpu_id
            )));
        };

        if !str_eq(stage, "executor_running") {
            return Err(BootCaseError::failed(format!(
                "cpu{} did not reach per-core executor run stage: stage={}",
                cpu_id, stage
            )));
        }
    }

    Ok(())
}

#[cfg(feature = "qemu-test-export")]
fn case_async_boot_stages_distributed() -> Result<(), BootCaseError> {
    let cpu_count = crate::cpu::count() as usize;
    if cpu_count <= 1 {
        return Err(BootCaseError::blocked(
            "async_boot_stages_distributed requires a multi-core QEMU configuration",
        ));
    }

    let snapshot = crate::async_boot_stage_runtime_snapshot();
    if snapshot.platform.started_cpu != Some(0) {
        return Err(BootCaseError::failed(format!(
            "platform stage did not start on BSP: snapshot={:?}",
            snapshot
        )));
    }

    let non_bsp_stage_seen = [
        snapshot.graphics.started_cpu,
        snapshot.core_services.started_cpu,
        snapshot.driver.started_cpu,
        snapshot.post_driver.started_cpu,
        snapshot.finalizer.started_cpu,
    ]
    .into_iter()
    .flatten()
    .any(|cpu_id| cpu_id != 0);
    if !non_bsp_stage_seen {
        return Err(BootCaseError::failed(format!(
            "no async boot stage started on an AP: snapshot={:?}",
            snapshot
        )));
    }

    if snapshot.finalizer.started_cpu != Some(0) && snapshot.finalizer.started_cpu.is_some() {
        return Ok(());
    }

    Err(BootCaseError::failed(format!(
        "finalizer stage did not start on an AP: snapshot={:?}",
        snapshot
    )))
}

#[cfg(feature = "qemu-test-export")]
fn case_runtime_local_timers_enabled() -> Result<(), BootCaseError> {
    let snapshot = crate::interrupts::runtime_timer_snapshot();
    if snapshot.enabled {
        Ok(())
    } else {
        Err(BootCaseError::failed(
            "runtime handoff did not enable per-core LAPIC timers",
        ))
    }
}

#[cfg(feature = "qemu-test-export")]
fn case_pit_irq0_masked_after_handoff() -> Result<(), BootCaseError> {
    if crate::interrupts::pit_irq0_masked() {
        Ok(())
    } else {
        Err(BootCaseError::failed(
            "legacy PIT IRQ0 is still unmasked after runtime handoff",
        ))
    }
}

#[cfg(feature = "qemu-test-export")]
fn case_apic_timers_armed_on_all_online_cpus() -> Result<(), BootCaseError> {
    let deadline_ns = crate::time::precise_time_nanos().saturating_add(250 * 1_000_000);

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while crate::time::precise_time_nanos() < deadline_ns {
        let snapshot = crate::interrupts::runtime_timer_snapshot();
        if snapshot.enabled {
            let mut all_armed = true;
            let mut cpu_id = 0usize;
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
            while cpu_id < snapshot.cpu_count {
                if !snapshot.armed[cpu_id] {
                    all_armed = false;
                    break;
                }
                cpu_id += 1;
            }
            if all_armed {
                return Ok(());
            }
        }
        core::hint::spin_loop();
    }

    let snapshot = crate::interrupts::runtime_timer_snapshot();
    Err(BootCaseError::failed(format!(
        "runtime LAPIC timers not armed on all CPUs: enabled={} cpu_count={} armed={:?}",
        snapshot.enabled,
        snapshot.cpu_count,
        &snapshot.armed[..snapshot.cpu_count]
    )))
}

#[cfg(feature = "qemu-test-export")]
fn case_per_cpu_local_ticks_progress() -> Result<(), BootCaseError> {
    let before = task::per_cpu_preemption_snapshot();
    let deadline_ns = crate::time::precise_time_nanos().saturating_add(250 * 1_000_000);

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while crate::time::precise_time_nanos() < deadline_ns {
        let after = task::per_cpu_preemption_snapshot();
        let mut all_progressed = true;
        let mut cpu_id = 0usize;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while cpu_id < after.cpu_count {
            if after.local_ticks[cpu_id] <= before.local_ticks[cpu_id] {
                all_progressed = false;
                break;
            }
            cpu_id += 1;
        }
        if all_progressed {
            return Ok(());
        }
        core::hint::spin_loop();
    }

    let after = task::per_cpu_preemption_snapshot();
    Err(BootCaseError::failed(format!(
        "per-cpu local preemption ticks did not advance: before={:?} after={:?}",
        &before.local_ticks[..before.cpu_count],
        &after.local_ticks[..after.cpu_count]
    )))
}

#[cfg(feature = "qemu-test-export")]
fn case_cross_core_preemption_isolated() -> Result<(), BootCaseError> {
    let cpu_count = crate::cpu::count() as usize;
    if cpu_count < 3 {
        return Err(BootCaseError::blocked(
            "cross_core_preemption_isolated requires >=3 CPUs so the runtime test runner stays off cpu0/cpu1",
        ));
    }

    let timer_snapshot = crate::interrupts::runtime_timer_snapshot();
    if !timer_snapshot.enabled {
        return Err(BootCaseError::failed(
            "runtime LAPIC timers are not enabled for cross-core isolation",
        ));
    }

    let before = task::per_cpu_preemption_snapshot();
    let heartbeat = Arc::new(AtomicU64::new(0));
    let keep_running = Arc::new(AtomicBool::new(true));

    task::spawn_on_cpu_for_test(0, {
        let heartbeat = heartbeat.clone();
        let keep_running = keep_running.clone();
        async move {
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
            while keep_running.load(Ordering::SeqCst) {
                heartbeat.fetch_add(1, Ordering::SeqCst);
                task::yield_now().await;
            }
        }
    });

    task::spawn_on_cpu_for_test(1, async move {
        let deadline_ns = crate::time::precise_time_nanos().saturating_add(150 * 1_000_000);
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while crate::time::precise_time_nanos() < deadline_ns {
            let chunk_deadline = crate::time::precise_time_nanos().saturating_add(15 * 1_000_000);
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
            while crate::time::precise_time_nanos() < chunk_deadline {
                task::yield_point_with_quota_check();
                core::hint::spin_loop();
            }
            task::yield_now().await;
        }
    });

    let heartbeat_start = heartbeat.load(Ordering::SeqCst);
    let deadline_ns = crate::time::precise_time_nanos().saturating_add(500 * 1_000_000);
    let mut forced_seen = false;
    let mut heartbeat_after_forced_start = None;
    let mut heartbeat_progress_after_forced = false;

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while crate::time::precise_time_nanos() < deadline_ns {
        let snapshot = task::per_cpu_preemption_snapshot();
        forced_seen |= snapshot.forced_preemptions[1] > before.forced_preemptions[1];

        let heartbeat_now = heartbeat.load(Ordering::SeqCst);
        if forced_seen {
            if let Some(start) = heartbeat_after_forced_start {
                if heartbeat_now > start {
                    heartbeat_progress_after_forced = true;
                    break;
                }
            } else {
                heartbeat_after_forced_start = Some(heartbeat_now);
            }
        } else if heartbeat_now <= heartbeat_start {
            core::hint::spin_loop();
            continue;
        }

        core::hint::spin_loop();
    }

    keep_running.store(false, Ordering::SeqCst);

    if !forced_seen {
        let after = task::per_cpu_preemption_snapshot();
        return Err(BootCaseError::failed(format!(
            "cpu1 did not record forced preemption: before={} after={}",
            before.forced_preemptions[1], after.forced_preemptions[1]
        )));
    }

    if !heartbeat_progress_after_forced {
        return Err(BootCaseError::failed(format!(
            "cpu0 heartbeat stopped while cpu1 was being preempted: heartbeat_start={} heartbeat_end={}",
            heartbeat_start,
            heartbeat.load(Ordering::SeqCst)
        )));
    }

    Ok(())
}

#[cfg(feature = "qemu-test-export")]
fn case_uptime_ms_progresses() -> Result<(), BootCaseError> {
    let raw_before = crate::interrupts::get_timer_ticks();
    let uptime_before = crate::time::get_uptime_ms();
    let deadline_ns = crate::time::precise_time_nanos().saturating_add(250 * 1_000_000);
    let mut saw_raw_tick = false;

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while crate::time::precise_time_nanos() < deadline_ns {
        let uptime_after = crate::time::get_uptime_ms();
        if uptime_after > uptime_before {
            return Ok(());
        }
        saw_raw_tick |= crate::interrupts::get_timer_ticks() > raw_before;
        core::hint::spin_loop();
    }

    if saw_raw_tick {
        Err(BootCaseError::failed(format!(
            "kernel uptime did not advance on raw timer IRQs: before={} after={}",
            uptime_before,
            crate::time::get_uptime_ms()
        )))
    } else {
        Err(BootCaseError::blocked(
            "raw timer ticks did not advance for uptime_ms_progresses",
        ))
    }
}

#[cfg(feature = "qemu-test-export")]
fn case_tick_progresses() -> Result<(), BootCaseError> {
    let raw_before = crate::interrupts::get_timer_ticks();
    let tick_before = task::current_tick();

    if !wait_for_raw_tick_advance(raw_before, 250) {
        return Err(BootCaseError::blocked(
            "raw timer ticks did not advance with real IRQs enabled",
        ));
    }

    if task::current_tick() <= tick_before {
        return Err(BootCaseError::failed(
            "task timer tick did not advance on the ISR-driven time service path",
        ));
    }

    Ok(())
}

#[cfg(feature = "qemu-test-export")]
fn case_sleep_ms_resumes() -> Result<(), BootCaseError> {
    let mut executor = task::TestExecutor::new();
    let completed = Arc::new(AtomicBool::new(false));
    let completed_at_tick = Arc::new(AtomicU64::new(0));
    let completed_clone = completed.clone();
    let completed_at_tick_clone = completed_at_tick.clone();
    let start_tick = task::current_tick();

    executor.spawn(Task::new(async move {
        task::sleep_ms(2).await;
        completed_at_tick_clone.store(task::current_tick(), Ordering::SeqCst);
        completed_clone.store(true, Ordering::SeqCst);
    }));
    executor.drive_once_for_test();

    let raw_before = crate::interrupts::get_timer_ticks();
    match drive_executor_until(&mut executor, &completed, raw_before, 500) {
        PumpResult::Completed => {
            let completed_tick = completed_at_tick.load(Ordering::SeqCst);
            if completed_tick < start_tick.saturating_add(2) {
                return Err(BootCaseError::failed(format!(
                    "sleep_ms resumed too early: start_tick={} completed_tick={}",
                    start_tick, completed_tick
                )));
            }
            Ok(())
        }
        PumpResult::NoRawTickProgress => Err(BootCaseError::blocked(
            "raw timer ticks did not advance during sleep_ms case",
        )),
        PumpResult::TimedOut => Err(BootCaseError::failed(
            "sleep_ms future did not resume on the phase-2 executor path",
        )),
    }
}

#[cfg(feature = "qemu-test-export")]
fn case_timer_waker_deferred_path() -> Result<(), BootCaseError> {
    let mut executor = task::TestExecutor::new();
    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();
    executor.spawn(Task::new(async move {
        task::wait_for_interrupt(InterruptSource::Timer).await;
        completed_clone.store(true, Ordering::SeqCst);
    }));
    executor.drive_once_for_test();

    let stats_before = task::interrupt_waker::interrupt_waker_registry().stats();
    let raw_before = crate::interrupts::get_timer_ticks();
    let delegated_tick_before = task::current_tick();

    if !wait_for_raw_tick_advance(raw_before, 250) {
        return Err(BootCaseError::blocked(
            "raw timer IRQ did not arrive for timer_waker_deferred_path",
        ));
    }
    if task::current_tick() <= delegated_tick_before {
        return Err(BootCaseError::failed(
            "timer service tick did not advance on the raw IRQ path",
        ));
    }
    let stats_after_irq = task::interrupt_waker::interrupt_waker_registry().stats();
    if stats_after_irq.interrupt_count != stats_before.interrupt_count
        || stats_after_irq.wake_count != stats_before.wake_count
    {
        return Err(BootCaseError::failed(
            "timer interrupt waker stats changed before executor-side drain",
        ));
    }
    if completed.load(Ordering::SeqCst) {
        return Err(BootCaseError::failed(
            "timer wait future completed before executor-side drain",
        ));
    }

    executor.drive_once_for_test();

    let stats_after_drain = task::interrupt_waker::interrupt_waker_registry().stats();
    if stats_after_drain.interrupt_count <= stats_before.interrupt_count {
        return Err(BootCaseError::failed(
            "timer wake was not bridged into the interrupt waker registry",
        ));
    }
    if stats_after_drain.wake_count <= stats_before.wake_count {
        return Err(BootCaseError::failed(
            "timer wake was not drained outside ISR context",
        ));
    }
    if completed.load(Ordering::SeqCst) {
        return Err(BootCaseError::failed(
            "timer wait future completed before the requeued task was re-polled",
        ));
    }

    executor.drive_once_for_test();
    if !completed.load(Ordering::SeqCst) {
        return Err(BootCaseError::failed(
            "timer wait future did not complete after deferred executor wake",
        ));
    }

    Ok(())
}

#[cfg(feature = "qemu-test-export")]
fn case_time_service_wall_clock_consumers() -> Result<(), BootCaseError> {
    let original_ms = crate::drivers::time::unix_timestamp_ms();
    let run = || -> Result<(), BootCaseError> {
        let target_secs = crate::drivers::time::unix_timestamp().saturating_add(120);
        let ntp_client =
            crate::net::services::ntp::NtpClient::new(crate::net::runtime::default_runtime());
        ntp_client.apply_synced_unix_time(target_secs);

        if crate::drivers::time::unix_timestamp() < target_secs {
            return Err(BootCaseError::failed(
                "time service readers did not observe the NTP wall-clock update",
            ));
        }

        let expected_boot =
            crate::drivers::time::unix_timestamp().saturating_sub(task::current_tick() / 1000);
        if crate::system_info::boot_time_secs() != expected_boot {
            return Err(BootCaseError::failed(
                "system_info boot_time_secs no longer tracks the time service",
            ));
        }

        let before_ms = crate::drivers::time::unix_timestamp_ms();
        let inode = MemoryInode::new_file(1, "time-service-check", FileMode::DEFAULT_FILE);
        let attrs = inode
            .getattr()
            .map_err(|_| BootCaseError::failed("memfs getattr failed after wall-clock update"))?;
        let after_ms = crate::drivers::time::unix_timestamp_ms();
        let ctime_ms = attrs.ctime / 1_000_000;
        if ctime_ms < before_ms || ctime_ms > after_ms {
            return Err(BootCaseError::failed(format!(
                "memfs timestamp was not sourced from the time service: ctime_ms={} window=[{}, {}]",
                ctime_ms, before_ms, after_ms
            )));
        }

        Ok(())
    };

    let result = run();
    crate::drivers::time::set_unix_timestamp_ms(original_ms);
    result
}

#[cfg(feature = "qemu-test-export")]
fn case_keyboard_deferred_wake_path() -> Result<(), BootCaseError> {
    case_synthetic_interrupt_deferred_path(InterruptSource::Keyboard, "keyboard")
}

#[cfg(feature = "qemu-test-export")]
fn case_serial_deferred_wake_path() -> Result<(), BootCaseError> {
    case_synthetic_interrupt_deferred_path(InterruptSource::Serial, "serial")
}

#[cfg(feature = "qemu-test-export")]
fn case_synthetic_interrupt_deferred_path(
    source: InterruptSource,
    label: &str,
) -> Result<(), BootCaseError> {
    let mut executor = task::TestExecutor::new();
    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();
    executor.spawn(Task::new(async move {
        task::wait_for_interrupt(source).await;
        completed_clone.store(true, Ordering::SeqCst);
    }));
    executor.drive_once_for_test();

    let stats_before = task::interrupt_waker::interrupt_waker_registry().stats();
    task::wake_from_interrupt(source);
    let stats_after_enqueue = task::interrupt_waker::interrupt_waker_registry().stats();
    if stats_after_enqueue.interrupt_count <= stats_before.interrupt_count {
        return Err(BootCaseError::failed(format!(
            "{label} interrupt was not queued into the deferred wake registry"
        )));
    }
    if stats_after_enqueue.wake_count != stats_before.wake_count {
        return Err(BootCaseError::failed(format!(
            "{label} interrupt woke a task before executor-side drain"
        )));
    }
    if completed.load(Ordering::SeqCst) {
        return Err(BootCaseError::failed(format!(
            "{label} wait future completed before executor-side drain"
        )));
    }

    executor.drive_once_for_test();
    let stats_after_drain = task::interrupt_waker::interrupt_waker_registry().stats();
    if stats_after_drain.wake_count <= stats_before.wake_count {
        return Err(BootCaseError::failed(format!(
            "{label} deferred wake did not drain on executor poll"
        )));
    }
    if completed.load(Ordering::SeqCst) {
        return Err(BootCaseError::failed(format!(
            "{label} wait future completed before the requeued task was re-polled"
        )));
    }

    executor.drive_once_for_test();
    if !completed.load(Ordering::SeqCst) {
        return Err(BootCaseError::failed(format!(
            "{label} wait future did not complete after deferred wake"
        )));
    }

    Ok(())
}

#[cfg(feature = "qemu-test-export")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PumpResult {
    Completed,
    NoRawTickProgress,
    TimedOut,
}

#[cfg(feature = "qemu-test-export")]
fn drive_executor_until(
    executor: &mut task::TestExecutor,
    completed: &AtomicBool,
    raw_tick_start: u64,
    timeout_ms: u64,
) -> PumpResult {
    let deadline_ns = crate::time::precise_time_nanos().saturating_add(timeout_ms * 1_000_000);
    let mut saw_raw_tick = false;

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while crate::time::precise_time_nanos() < deadline_ns {
        if completed.load(Ordering::SeqCst) {
            return PumpResult::Completed;
        }

        executor.drive_once_for_test();
        if completed.load(Ordering::SeqCst) {
            return PumpResult::Completed;
        }

        saw_raw_tick |= crate::interrupts::get_timer_ticks() > raw_tick_start;
        core::hint::spin_loop();
    }

    if saw_raw_tick {
        PumpResult::TimedOut
    } else {
        PumpResult::NoRawTickProgress
    }
}

#[cfg(feature = "qemu-test-export")]
fn wait_for_raw_tick_advance(start_tick: u64, timeout_ms: u64) -> bool {
    let deadline_ns = crate::time::precise_time_nanos().saturating_add(timeout_ms * 1_000_000);

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while crate::time::precise_time_nanos() < deadline_ns {
        if crate::interrupts::get_timer_ticks() > start_tick {
            return true;
        }
        core::hint::spin_loop();
    }

    false
}
