#[cfg(feature = "qemu-test-export")]
use alloc::format;
#[cfg(feature = "qemu-test-export")]
use alloc::string::String;
#[cfg(feature = "qemu-test-export")]
use alloc::sync::Arc;
#[cfg(feature = "qemu-test-export")]
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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
    ("tick_progresses", case_tick_progresses),
    ("sleep_ms_resumes", case_sleep_ms_resumes),
    ("timer_waker_deferred_path", case_timer_waker_deferred_path),
    (
        "keyboard_deferred_wake_path",
        case_keyboard_deferred_wake_path,
    ),
    ("serial_deferred_wake_path", case_serial_deferred_wake_path),
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
fn case_tick_progresses() -> Result<(), BootCaseError> {
    let mut executor = task::Executor::new();
    let raw_before = crate::interrupts::get_timer_ticks();
    let tick_before = task::current_tick();

    if !wait_for_raw_tick_advance(raw_before, 250) {
        return Err(BootCaseError::blocked(
            "raw timer ticks did not advance with real IRQs enabled",
        ));
    }

    executor.drive_once_for_test();

    if task::current_tick() <= tick_before {
        return Err(BootCaseError::failed(
            "task timer tick did not advance after executor poll",
        ));
    }

    Ok(())
}

#[cfg(feature = "qemu-test-export")]
fn case_sleep_ms_resumes() -> Result<(), BootCaseError> {
    let mut executor = task::Executor::new();
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
    let mut executor = task::Executor::new();
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
    if task::current_tick() != delegated_tick_before {
        return Err(BootCaseError::failed(
            "timer service tick advanced before executor-side poll",
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
    if task::current_tick() <= delegated_tick_before {
        return Err(BootCaseError::failed(
            "timer service did not advance on executor-side poll",
        ));
    }
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
    let mut executor = task::Executor::new();
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
    executor: &mut task::Executor,
    completed: &AtomicBool,
    raw_tick_start: u64,
    timeout_ms: u64,
) -> PumpResult {
    let deadline_ns = crate::time::precise_time_nanos().saturating_add(timeout_ms * 1_000_000);
    let mut saw_raw_tick = false;

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

    while crate::time::precise_time_nanos() < deadline_ns {
        if crate::interrupts::get_timer_ticks() > start_tick {
            return true;
        }
        core::hint::spin_loop();
    }

    false
}
