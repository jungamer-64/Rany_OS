#[cfg(feature = "qemu-test-export")]
use alloc::boxed::Box;
#[cfg(feature = "qemu-test-export")]
use alloc::format;
#[cfg(feature = "qemu-test-export")]
use alloc::string::String;
#[cfg(feature = "qemu-test-export")]
use alloc::sync::Arc;
#[cfg(feature = "qemu-test-export")]
use core::future::Future;
#[cfg(feature = "qemu-test-export")]
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[cfg(feature = "qemu-test-export")]
use crate::fs::{FileMode, Inode, MemoryInode};
#[cfg(feature = "qemu-test-export")]
use crate::task::{self, InterruptSource, TaskPlacement, TimeoutResult};

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
    ("cpu_topology_published", case_cpu_topology_published),
    (
        "scheduler_covers_online_cpus",
        case_scheduler_covers_online_cpus,
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
        "pinned_task_runs_on_online_cpu",
        case_pinned_task_runs_on_online_cpu,
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
fn case_cpu_topology_published() -> Result<(), BootCaseError> {
    let snapshot = crate::cpu::snapshot();
    if !snapshot.possible().contains(crate::cpu::CpuId::BOOTSTRAP)
        || !snapshot.present().contains(crate::cpu::CpuId::BOOTSTRAP)
        || !snapshot.online().contains(crate::cpu::CpuId::BOOTSTRAP)
    {
        return Err(BootCaseError::failed(
            "bootstrap CPU is not the permanent possible/present/online anchor",
        ));
    }

    for slot in snapshot.slots() {
        let possible = snapshot.possible().contains(slot.id);
        let present = snapshot.present().contains(slot.id);
        let online = snapshot.online().contains(slot.id);
        if !possible || present != slot.state.is_present() || online != slot.state.is_schedulable()
        {
            return Err(BootCaseError::failed(format!(
                "CPU snapshot projections disagree for cpu={} state={}",
                slot.id,
                slot.state.name()
            )));
        }
    }

    Ok(())
}

#[cfg(feature = "qemu-test-export")]
fn case_scheduler_covers_online_cpus() -> Result<(), BootCaseError> {
    let topology = crate::cpu::snapshot();
    let scheduler = task::scheduler_snapshot()
        .ok_or_else(|| BootCaseError::failed("task scheduler is not initialized"))?;

    if scheduler.run_queues.len() != topology.online().len() {
        return Err(BootCaseError::failed(format!(
            "scheduler queue count does not match sparse online set: queues={} online={}",
            scheduler.run_queues.len(),
            topology.online().len()
        )));
    }
    for cpu in topology.online() {
        if !scheduler.run_queues.iter().any(|queue| queue.cpu == cpu) {
            return Err(BootCaseError::failed(format!(
                "scheduler has no run queue for online cpu={cpu}"
            )));
        }
    }

    Ok(())
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
        let snapshot = crate::cpu::snapshot();
        if snapshot.online().iter().all(|cpu| {
            crate::cpu::runtime()
                .cpu_local(cpu)
                .is_some_and(|local| local.remote().runtime_timer_armed())
        }) {
            return Ok(());
        }
        core::hint::spin_loop();
    }

    let snapshot = crate::cpu::snapshot();
    let unarmed = snapshot
        .online()
        .iter()
        .filter(|&cpu| {
            crate::cpu::runtime()
                .cpu_local(cpu)
                .is_none_or(|local| !local.remote().runtime_timer_armed())
        })
        .map(crate::cpu::CpuId::as_u16)
        .collect::<alloc::vec::Vec<_>>();
    Err(BootCaseError::failed(format!(
        "runtime LAPIC timers are not armed for online CPUs: {unarmed:?}"
    )))
}

#[cfg(feature = "qemu-test-export")]
fn case_pinned_task_runs_on_online_cpu() -> Result<(), BootCaseError> {
    let target = peer_online_cpu()?;
    let observed_cpu = Arc::new(AtomicU64::new(u64::MAX));
    let observed_cpu_task = observed_cpu.clone();
    task::spawn(
        async move {
            let observed = crate::cpu::CurrentCpu::acquire()
                .map(|current| u64::from(current.id().as_u16()))
                .unwrap_or(u64::MAX - 1);
            observed_cpu_task.store(observed, Ordering::Release);
        },
        TaskPlacement::Pinned(target),
    )
    .map_err(|error| {
        BootCaseError::failed(format!(
            "failed to spawn pinned production task on cpu={target}: {error:?}"
        ))
    })?;

    if !wait_for_atomic_change(&observed_cpu, u64::MAX, 500) {
        return Err(BootCaseError::failed(format!(
            "pinned production task did not run on cpu={target}"
        )));
    }
    let observed = observed_cpu.load(Ordering::Acquire);
    if observed != u64::from(target.as_u16()) {
        return Err(BootCaseError::failed(format!(
            "pinned production task ran on cpu={observed}, expected cpu={target}"
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
    let target = peer_online_cpu()?;
    let completed = Arc::new(AtomicBool::new(false));
    let completed_at_tick = Arc::new(AtomicU64::new(0));
    let completed_clone = completed.clone();
    let completed_at_tick_clone = completed_at_tick.clone();
    let start_tick = task::current_tick();

    task::spawn(
        async move {
            task::sleep_ms(2).await;
            completed_at_tick_clone.store(task::current_tick(), Ordering::Release);
            completed_clone.store(true, Ordering::Release);
        },
        TaskPlacement::Pinned(target),
    )
    .map_err(|error| {
        BootCaseError::failed(format!(
            "failed to spawn sleep task on cpu={target}: {error:?}"
        ))
    })?;

    if !wait_for_atomic_bool(&completed, 500) {
        return Err(BootCaseError::failed(format!(
            "sleep_ms task did not resume on cpu={target}"
        )));
    }
    let completed_tick = completed_at_tick.load(Ordering::Acquire);
    if completed_tick < start_tick.saturating_add(2) {
        return Err(BootCaseError::failed(format!(
            "sleep_ms resumed too early: start_tick={start_tick} completed_tick={completed_tick}"
        )));
    }

    Ok(())
}

#[cfg(feature = "qemu-test-export")]
fn case_timer_waker_deferred_path() -> Result<(), BootCaseError> {
    let target = peer_online_cpu()?;
    let armed = Arc::new(AtomicBool::new(false));
    let completed = Arc::new(AtomicBool::new(false));
    let timed_out = Arc::new(AtomicBool::new(false));
    let armed_clone = armed.clone();
    let completed_clone = completed.clone();
    let timed_out_clone = timed_out.clone();
    task::spawn(
        async move {
            match task::with_timeout(
                wait_for_registered_interrupt(InterruptSource::Timer, armed_clone),
                500,
            )
            .await
            {
                TimeoutResult::Completed(()) => completed_clone.store(true, Ordering::Release),
                TimeoutResult::TimedOut => timed_out_clone.store(true, Ordering::Release),
            }
        },
        TaskPlacement::Pinned(target),
    )
    .map_err(|error| {
        BootCaseError::failed(format!(
            "failed to spawn timer-wait task on cpu={target}: {error:?}"
        ))
    })?;

    if !wait_for_atomic_bool(&armed, 250) {
        return Err(BootCaseError::failed(format!(
            "timer-wait task was not polled on cpu={target}"
        )));
    }

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
    if !wait_for_atomic_bool(&completed, 500) {
        if timed_out.load(Ordering::Acquire) {
            return Err(BootCaseError::failed(
                "timer interrupt wait timed out on the production scheduler",
            ));
        }
        return Err(BootCaseError::failed(
            "timer interrupt wait did not complete on the production scheduler",
        ));
    }

    let stats_after = task::interrupt_waker::interrupt_waker_registry().stats();
    if stats_after.interrupt_count <= stats_before.interrupt_count {
        return Err(BootCaseError::failed(
            "timer wake was not bridged into the interrupt waker registry",
        ));
    }
    if stats_after.wake_count <= stats_before.wake_count {
        return Err(BootCaseError::failed(
            "timer wake was not drained outside ISR context",
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
        let inode = MemoryInode::new_file(1, FileMode::DEFAULT_FILE);
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
    let target = peer_online_cpu()?;
    let armed = Arc::new(AtomicBool::new(false));
    let completed = Arc::new(AtomicBool::new(false));
    let timed_out = Arc::new(AtomicBool::new(false));
    let armed_clone = armed.clone();
    let completed_clone = completed.clone();
    let timed_out_clone = timed_out.clone();
    task::spawn(
        async move {
            match task::with_timeout(wait_for_registered_interrupt(source, armed_clone), 500).await
            {
                TimeoutResult::Completed(()) => completed_clone.store(true, Ordering::Release),
                TimeoutResult::TimedOut => timed_out_clone.store(true, Ordering::Release),
            }
        },
        TaskPlacement::Pinned(target),
    )
    .map_err(|error| {
        BootCaseError::failed(format!(
            "failed to spawn {label} wait task on cpu={target}: {error:?}"
        ))
    })?;

    if !wait_for_atomic_bool(&armed, 250) {
        return Err(BootCaseError::failed(format!(
            "{label} wait task was not polled on cpu={target}"
        )));
    }

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
    task::interrupt_waker::process_interrupt_events();
    let stats_after_drain = task::interrupt_waker::interrupt_waker_registry().stats();
    if stats_after_drain.wake_count <= stats_before.wake_count {
        return Err(BootCaseError::failed(format!(
            "{label} deferred wake did not drain on executor poll"
        )));
    }
    if !wait_for_atomic_bool(&completed, 500) {
        if timed_out.load(Ordering::Acquire) {
            return Err(BootCaseError::failed(format!(
                "{label} interrupt wait timed out on the production scheduler"
            )));
        }
        return Err(BootCaseError::failed(format!(
            "{label} wait future did not complete after deferred wake"
        )));
    }

    Ok(())
}

#[cfg(feature = "qemu-test-export")]
async fn wait_for_registered_interrupt(source: InterruptSource, armed: Arc<AtomicBool>) {
    let mut wait = Box::pin(task::wait_for_interrupt(source));
    core::future::poll_fn(move |context| {
        let poll = wait.as_mut().poll(context);
        if poll.is_pending() {
            armed.store(true, Ordering::Release);
        }
        poll
    })
    .await;
}

#[cfg(feature = "qemu-test-export")]
fn peer_online_cpu() -> Result<crate::cpu::CpuId, BootCaseError> {
    let current = crate::cpu::CurrentCpu::acquire()
        .ok_or_else(|| BootCaseError::failed("runtime test task has no CurrentCpu binding"))?
        .id();
    crate::cpu::snapshot()
        .online()
        .iter()
        .find(|&cpu| cpu != current)
        .ok_or_else(|| {
            BootCaseError::blocked("production scheduler task cases require two online CPUs")
        })
}

#[cfg(feature = "qemu-test-export")]
fn wait_for_atomic_bool(value: &AtomicBool, timeout_ms: u64) -> bool {
    let deadline_ns = crate::time::precise_time_nanos().saturating_add(timeout_ms * 1_000_000);

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while crate::time::precise_time_nanos() < deadline_ns {
        if value.load(Ordering::Acquire) {
            return true;
        }
        core::hint::spin_loop();
    }

    value.load(Ordering::Acquire)
}

#[cfg(feature = "qemu-test-export")]
fn wait_for_atomic_change(value: &AtomicU64, initial: u64, timeout_ms: u64) -> bool {
    let deadline_ns = crate::time::precise_time_nanos().saturating_add(timeout_ms * 1_000_000);

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while crate::time::precise_time_nanos() < deadline_ns {
        if value.load(Ordering::Acquire) != initial {
            return true;
        }
        core::hint::spin_loop();
    }

    value.load(Ordering::Acquire) != initial
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
