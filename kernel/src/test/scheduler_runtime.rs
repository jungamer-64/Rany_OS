//! Runtime contracts observed through admitted tasks and production snapshots.

use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll};

use crate::cpu::{CpuId, CurrentCpu};
use crate::domain::{DomainId, DomainLifecycleError, DomainPriority};
use crate::task::{TaskOptions, TaskPlacement, TaskPriority, fuel::Fuel};

use super::RuntimeTestResult;

struct Progress {
    stop: AtomicBool,
    valid: AtomicBool,
    polls: [AtomicU64; 5],
}

struct ProgressPoll {
    progress: Arc<Progress>,
    index: usize,
    cpu: CpuId,
    domain: DomainId,
}

impl Future for ProgressPoll {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        if self.progress.stop.load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        let identity = CurrentCpu::acquire().is_some_and(|cpu| cpu.id() == self.cpu)
            && crate::domain::current_domain() == self.domain;
        let fresh_fuel = Fuel::is_active()
            && Fuel::remaining() == crate::task::config::SCHEDULER_CONFIG.fuel_per_poll;
        let consumed = Fuel::consume(crate::task::config::SCHEDULER_CONFIG.fuel_per_poll);
        let exhausted_but_active = Fuel::is_active() && Fuel::remaining() == 0;
        self.progress.valid.fetch_and(
            identity && fresh_fuel && consumed && exhausted_but_active,
            Ordering::AcqRel,
        );
        let end = crate::time::precise_time_nanos().saturating_add(1_000_000);
        // LOOP_PROOF: mode=condition; reason=The independent nanosecond clock bounds each poll's CPU work to one millisecond.;
        while crate::time::precise_time_nanos() < end {
            core::hint::spin_loop();
        }
        self.progress.polls[self.index].fetch_add(1, Ordering::Release);
        context.waker().wake_by_ref();
        Poll::Pending
    }
}

async fn close_domain(domain: DomainId) -> bool {
    let deadline = crate::time::precise_time_nanos().saturating_add(1_000_000_000);
    // LOOP_PROOF: mode=event; reason=Typed incomplete shutdown is retried after a timer wait until reclamation completes or the nanosecond deadline expires.;
    loop {
        match crate::domain::terminate_domain(domain) {
            Ok(()) => return true,
            Err(
                DomainLifecycleError::Busy(_)
                | DomainLifecycleError::CodeBusy { .. }
                | DomainLifecycleError::ReclamationInProgress,
            ) if crate::time::precise_time_nanos() < deadline => {
                if crate::task::sleep_ms(1).await.is_err() {
                    return false;
                }
            }
            Err(error) => {
                log::error!("scheduler runtime domain shutdown failed: {error:?}");
                return false;
            }
        }
    }
}

async fn progress_case(quota: bool) -> RuntimeTestResult {
    let Some(cpu) = CurrentCpu::acquire().map(|current| current.id()) else {
        return RuntimeTestResult::fail("progress probe has no CPU owner");
    };
    let Ok(normal) = crate::domain::create_domain("scheduler-progress".into()) else {
        return RuntimeTestResult::fail("cannot create progress domain");
    };
    let Ok(high) = crate::domain::create_domain("scheduler-progress-peer".into()) else {
        let _ = close_domain(normal).await;
        return RuntimeTestResult::fail("cannot create progress peer");
    };
    let policy = if quota {
        // One poll consumes at least one percent of the 100ms quota period,
        // so the wait is observable even when other CPUs contend for dispatch.
        crate::domain::registry::set_domain_resource_limits(normal, 1, u64::MAX, 0)
    } else {
        crate::domain::registry::set_domain_priority(high, DomainPriority::High)
    };
    let progress = Arc::new(Progress {
        stop: AtomicBool::new(false),
        valid: AtomicBool::new(true),
        polls: [const { AtomicU64::new(0) }; 5],
    });
    let tasks = if quota {
        &[
            (normal, TaskPriority::Critical),
            (high, TaskPriority::Normal),
        ][..]
    } else {
        &[
            (normal, TaskPriority::Low),
            (normal, TaskPriority::Normal),
            (normal, TaskPriority::High),
            (normal, TaskPriority::Critical),
            (high, TaskPriority::Normal),
        ][..]
    };
    let mut result = RuntimeTestResult::pass();
    if let Err(error) = policy {
        log::error!("scheduler progress policy admission failed: {error:?}");
        result = RuntimeTestResult::fail("cannot admit progress policy");
    } else {
        for (index, &(domain, priority)) in tasks.iter().enumerate() {
            if crate::task::spawn_in_domain(
                ProgressPoll {
                    progress: Arc::clone(&progress),
                    index,
                    cpu,
                    domain,
                },
                TaskOptions::new(priority, TaskPlacement::pinned(cpu)),
                domain,
            )
            .is_err()
            {
                result = RuntimeTestResult::fail("cannot admit progress task");
                break;
            }
        }
    }
    let deadline = crate::time::precise_time_nanos().saturating_add(400_000_000);
    let mut waited_at = None;
    let mut blocked_sample = None;
    let mut successor_progressed = false;
    let mut recovered = false;
    // LOOP_PROOF: mode=condition; reason=Each progress sample awaits the production timer, and the fixed nanosecond deadline or an observed failure ends sampling.;
    while result.status == super::RuntimeCaseStatus::Pass
        && crate::time::precise_time_nanos() < deadline
    {
        let limited = progress.polls[0].load(Ordering::Acquire);
        let peer = progress.polls[1].load(Ordering::Acquire);
        if crate::domain::quota_manager()
            .cpu_wait_deadline(normal, crate::time::precise_time_nanos())
            .is_some()
            && crate::task::scheduler_snapshot().is_some_and(|snapshot| snapshot.quota_waiting != 0)
        {
            waited_at.get_or_insert(limited);
            if let Some((previous_limited, previous_peer)) = blocked_sample {
                successor_progressed |= limited == previous_limited && peer > previous_peer;
            }
            blocked_sample = Some((limited, peer));
        } else {
            blocked_sample = None;
        }
        if waited_at.is_some_and(|before| limited > before) {
            recovered = true;
        }
        if crate::task::sleep_ms(2).await.is_err() {
            result = RuntimeTestResult::fail("progress timer admission failed");
        }
    }
    progress.stop.store(true, Ordering::Release);
    let counts =
        core::array::from_fn::<_, 5, _>(|index| progress.polls[index].load(Ordering::Acquire));
    // Stop and confirm reclamation even on assertion/admission failure. A
    // returned Pending has no suspended stack and may be retired normally.
    let normal_closed = close_domain(normal).await;
    let high_closed = close_domain(high).await;
    if !normal_closed || !high_closed {
        return RuntimeTestResult::fail("progress task ownership did not retire");
    }
    if result.status != super::RuntimeCaseStatus::Pass {
        return result;
    }
    log::info!("scheduler progress quota={quota} polls={counts:?}");
    if !progress.valid.load(Ordering::Acquire) || counts[..tasks.len()].contains(&0) {
        return RuntimeTestResult::fail("a priority starved or new-poll fuel/identity was invalid");
    }
    if quota {
        if waited_at.is_none() {
            return RuntimeTestResult::fail("limited task never entered quota waiting");
        }
        if !recovered {
            return RuntimeTestResult::fail("limited task did not resume after quota rollover");
        }
        if !successor_progressed {
            return RuntimeTestResult::fail(
                "successor did not progress while its peer waited for quota",
            );
        }
    } else if counts[3] < counts[0] * 3
        || counts[3] > counts[0] * 16
        || counts[2] < counts[1]
        || counts[4] * 2 < counts[2]
        || counts[2] * 2 < counts[4]
    {
        return RuntimeTestResult::fail("task/domain priority weights did not govern CPU progress");
    }
    RuntimeTestResult::pass()
}

pub(super) async fn weighted_progress() -> RuntimeTestResult {
    progress_case(false).await
}

pub(super) async fn quota_recovery() -> RuntimeTestResult {
    progress_case(true).await
}

struct RetainedWake {
    polls: AtomicU64,
    drops: AtomicU64,
    waker: crate::sync::Mutex<Option<core::task::Waker>>,
}

struct WaitingPoll(Arc<RetainedWake>);

impl Future for WaitingPoll {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        self.0.polls.fetch_add(1, Ordering::AcqRel);
        let mut waker = self.0.waker.lock();
        if waker.is_none() {
            *waker = Some(context.waker().clone());
        }
        Poll::Pending
    }
}

impl Drop for WaitingPoll {
    fn drop(&mut self) {
        self.0.drops.fetch_add(1, Ordering::Release);
    }
}

fn retained_wake() -> Arc<RetainedWake> {
    Arc::new(RetainedWake {
        polls: AtomicU64::new(0),
        drops: AtomicU64::new(0),
        waker: crate::sync::Mutex::new(None),
    })
}

async fn wait_for_poll(state: &RetainedWake) -> bool {
    let deadline = crate::time::precise_time_nanos().saturating_add(2_000_000_000);
    // LOOP_PROOF: mode=condition; reason=Each unsuccessful observation awaits a timer and the independent nanosecond deadline bounds the admission-to-poll wait.;
    while state.polls.load(Ordering::Acquire) == 0 && crate::time::precise_time_nanos() < deadline {
        if crate::task::sleep_ms(1).await.is_err() {
            return false;
        }
    }
    state.polls.load(Ordering::Acquire) != 0
}

pub(super) async fn capacity_retirement_and_stale_wake() -> RuntimeTestResult {
    let Some(cpu) = CurrentCpu::acquire().map(|current| current.id()) else {
        return RuntimeTestResult::fail("capacity probe has no CPU owner");
    };
    let Ok(domain) = crate::domain::create_domain("scheduler-capacity".into()) else {
        return RuntimeTestResult::fail("cannot create capacity domain");
    };
    let state = retained_wake();
    let mut admitted = 0;
    let mut slots_exhausted = false;
    for _ in 0..=crate::task::config::SCHEDULER_CONFIG.max_tasks {
        match crate::task::spawn_in_domain(
            WaitingPoll(Arc::clone(&state)),
            TaskOptions::pinned(cpu),
            domain,
        ) {
            Ok(_) => admitted += 1,
            Err(crate::task::SpawnError::TaskSlotsExhausted) => {
                slots_exhausted = true;
                break;
            }
            Err(error) => {
                log::error!("scheduler capacity admission failed: {error:?}");
                break;
            }
        }
    }
    let polled = admitted != 0 && wait_for_poll(&state).await;
    if !close_domain(domain).await {
        return RuntimeTestResult::fail("capacity shutdown retained task resources");
    }
    if !slots_exhausted || !polled || state.drops.load(Ordering::Acquire) != admitted + 1 {
        return RuntimeTestResult::fail("task limit or unpublished Future rollback was invalid");
    }
    let stale = state.waker.lock().take();
    let Some(stale) = stale else {
        return RuntimeTestResult::fail("capacity probe did not retain a task waker");
    };
    let Ok(replacement_domain) = crate::domain::create_domain("scheduler-capacity-reuse".into())
    else {
        return RuntimeTestResult::fail("cannot create replacement domain");
    };
    let replacement = retained_wake();
    let admitted = crate::task::spawn_in_domain(
        WaitingPoll(Arc::clone(&replacement)),
        TaskOptions::pinned(cpu),
        replacement_domain,
    )
    .is_ok();
    let polled = admitted && wait_for_poll(&replacement).await;
    for _ in 0..1000 {
        stale.wake_by_ref();
    }
    let observed = crate::task::sleep_ms(20).await.is_ok();
    let polls = replacement.polls.load(Ordering::Acquire);
    let closed = close_domain(replacement_domain).await;
    if !admitted || !polled || !observed || !closed || polls != 1 {
        return RuntimeTestResult::fail(
            "retired stack slot was not reusable or a stale wake repolled its successor",
        );
    }
    RuntimeTestResult::pass()
}
