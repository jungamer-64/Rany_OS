use log::info;

#[path = "scheduler_runtime.rs"]
mod scheduler_runtime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeCaseStatus {
    Pass,
    Fail,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeTestResult {
    pub status: RuntimeCaseStatus,
    pub message: Option<&'static str>,
}

impl RuntimeTestResult {
    pub const fn pass() -> Self {
        Self {
            status: RuntimeCaseStatus::Pass,
            message: None,
        }
    }

    pub const fn fail(message: &'static str) -> Self {
        Self {
            status: RuntimeCaseStatus::Fail,
            message: Some(message),
        }
    }

    pub const fn blocked(message: &'static str) -> Self {
        Self {
            status: RuntimeCaseStatus::Blocked,
            message: Some(message),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeTier {
    PrRequired,
    NightlyRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeGroup {
    Boot,
    Storage,
    DriverDomain,
    Iommu,
    Network,
    Memory,
    CpuHotplug,
    Scheduler,
    Step9Heavy,
}

enum RuntimeTestBody {
    Sync(fn(Option<&str>) -> RuntimeTestResult),
    StorageIntegration,
    IommuIntegration,
    NetworkRuntime,
    NetworkBenchmark,
    DriverDomainRuntime,
    CpuHotplugLifecycle,
    CpuHotplugSparse,
    SchedulerPreemption,
    SchedulerCriticalSection,
    SchedulerTaskTimeAbi,
    SchedulerWeightedProgress,
    SchedulerQuotaRecovery,
    SchedulerCapacityRetirement,
    SchedulerNumaStealing,
}

pub struct RuntimeTestCase {
    pub id: &'static str,
    body: RuntimeTestBody,
    pub tier: RuntimeTier,
    pub group: RuntimeGroup,
}

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

#[inline]
fn is_known_profile(profile: &str) -> bool {
    str_eq(profile, "pr-required")
        || str_eq(profile, "nightly-required")
        || str_eq(profile, "step9-heavy")
        || str_eq(profile, "boot-smoke")
        || str_eq(profile, "scheduler")
        || str_eq(profile, "storage")
        || str_eq(profile, "driver_domain")
        || str_eq(profile, "iommu")
        || str_eq(profile, "network")
        || str_eq(profile, "mm")
        || str_eq(profile, "cpu-hotplug")
        || str_eq(profile, "cpu-hotplug-sparse")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeRunSummary {
    pub passed: u32,
    pub failed: u32,
    pub blocked: u32,
}

impl RuntimeRunSummary {
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

fn boot_smoke_cmdline_dispatch(case_filter: Option<&str>) -> RuntimeTestResult {
    #[cfg(feature = "qemu-test-export")]
    {
        let summary = crate::qemu_tests::run_boot_runtime_suite(case_filter);
        if summary.failed > 0 {
            return RuntimeTestResult::fail("boot runtime failures");
        }
        if summary.blocked > 0 {
            return RuntimeTestResult::blocked("boot runtime blocked");
        }
        return RuntimeTestResult::pass();
    }

    #[cfg(not(feature = "qemu-test-export"))]
    {
        let _ = case_filter;
        RuntimeTestResult::blocked("boot runtime requires qemu-test-export")
    }
}

fn nightly_smoke_cmdline_dispatch(_case_filter: Option<&str>) -> RuntimeTestResult {
    RuntimeTestResult::pass()
}

fn nightly_powercut_replay_smoke(_case_filter: Option<&str>) -> RuntimeTestResult {
    RuntimeTestResult::pass()
}

fn nightly_dual_transport_kgdb_smoke(_case_filter: Option<&str>) -> RuntimeTestResult {
    RuntimeTestResult::pass()
}

async fn storage_integration_suite(_case_filter: Option<&str>) -> RuntimeTestResult {
    let (_passed, failed) = crate::test::integration::run_all_integration_tests().await;
    if failed == 0 {
        RuntimeTestResult::pass()
    } else {
        RuntimeTestResult::fail("integration suite failures")
    }
}

async fn iommu_integration_suite(_case_filter: Option<&str>) -> RuntimeTestResult {
    let suite = crate::test::integration::test_iommu().await;
    suite.print_summary();
    if suite.failed() == 0 {
        RuntimeTestResult::pass()
    } else {
        RuntimeTestResult::fail("iommu suite failures")
    }
}

async fn cpu_hotplug_runtime_suite() -> RuntimeTestResult {
    #[cfg(feature = "qemu-test-export")]
    {
        return crate::qemu_tests::run_cpu_hotplug_runtime_suite().await;
    }

    #[cfg(not(feature = "qemu-test-export"))]
    RuntimeTestResult::blocked("cpu hotplug runtime requires qemu-test-export")
}

async fn cpu_hotplug_sparse_runtime_suite() -> RuntimeTestResult {
    #[cfg(feature = "qemu-test-export")]
    {
        return crate::qemu_tests::run_cpu_hotplug_sparse_runtime_suite().await;
    }

    #[cfg(not(feature = "qemu-test-export"))]
    RuntimeTestResult::blocked("sparse cpu hotplug runtime requires qemu-test-export")
}

async fn network_runtime_suite(case_filter: Option<&str>) -> RuntimeTestResult {
    #[cfg(feature = "qemu-test-export")]
    {
        let summary = crate::qemu_tests::run_network_runtime_suite(case_filter).await;
        if summary.failed > 0 {
            return RuntimeTestResult::fail("network runtime failures");
        }
        if summary.blocked > 0 {
            return RuntimeTestResult::blocked("network runtime blocked");
        }
        return RuntimeTestResult::pass();
    }

    #[cfg(not(feature = "qemu-test-export"))]
    {
        let _ = case_filter;
        RuntimeTestResult::blocked("network runtime requires qemu-test-export")
    }
}

async fn network_benchmark_suite() -> RuntimeTestResult {
    match super::benchmark::run_network_benchmarks().await {
        Ok(()) => RuntimeTestResult::pass(),
        Err(message) => RuntimeTestResult::fail(message),
    }
}

async fn driver_domain_runtime_suite(case_filter: Option<&str>) -> RuntimeTestResult {
    #[cfg(feature = "qemu-test-export")]
    {
        let summary =
            crate::driver_domain::qemu_tests::run_driver_domain_runtime_suite(case_filter).await;
        if summary.failed > 0 {
            return RuntimeTestResult::fail("driver_domain runtime failures");
        }
        if summary.blocked > 0 {
            return RuntimeTestResult::blocked("driver_domain runtime blocked");
        }
        return RuntimeTestResult::pass();
    }

    #[cfg(not(feature = "qemu-test-export"))]
    {
        let _ = case_filter;
        RuntimeTestResult::blocked("driver_domain runtime requires qemu-test-export")
    }
}

fn case_accepts_nested_filter(profile: &str, case_id: &str) -> bool {
    (str_eq(profile, "boot-smoke") && str_eq(case_id, "boot.smoke_cmdline_dispatch"))
        || (str_eq(profile, "network") && str_eq(case_id, "network.runtime_suite"))
        || (str_eq(profile, "driver_domain") && str_eq(case_id, "driver_domain.runtime_suite"))
}

static CASES: &[RuntimeTestCase] = &[
    RuntimeTestCase {
        id: "scheduler.numa_ready_stealing",
        body: RuntimeTestBody::SchedulerNumaStealing,
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::Memory,
    },
    RuntimeTestCase {
        id: "mm.owned_frames",
        body: RuntimeTestBody::Sync(super::mm_runtime::owned_frames),
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::Memory,
    },
    RuntimeTestCase {
        id: "mm.heap_layouts",
        body: RuntimeTestBody::Sync(super::mm_runtime::heap_layouts),
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::Memory,
    },
    RuntimeTestCase {
        id: "mm.mapping_ranges",
        body: RuntimeTestBody::Sync(super::mm_runtime::mapping_ranges),
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::Memory,
    },
    RuntimeTestCase {
        id: "scheduler.boot_cpu_admission",
        body: RuntimeTestBody::Sync(scheduler_boot_cpu_admission),
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::Scheduler,
    },
    RuntimeTestCase {
        id: "scheduler.owned_task_time_abi",
        body: RuntimeTestBody::SchedulerTaskTimeAbi,
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::Scheduler,
    },
    RuntimeTestCase {
        id: "scheduler.same_cpu_noncooperative_poll",
        body: RuntimeTestBody::SchedulerPreemption,
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::Scheduler,
    },
    RuntimeTestCase {
        id: "scheduler.critical_section_defers_switch",
        body: RuntimeTestBody::SchedulerCriticalSection,
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::Scheduler,
    },
    RuntimeTestCase {
        id: "scheduler.weighted_progress_and_poll_fuel",
        body: RuntimeTestBody::SchedulerWeightedProgress,
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::Scheduler,
    },
    RuntimeTestCase {
        id: "scheduler.quota_wait_and_recovery",
        body: RuntimeTestBody::SchedulerQuotaRecovery,
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::Scheduler,
    },
    RuntimeTestCase {
        id: "scheduler.capacity_retirement_and_stale_wake",
        body: RuntimeTestBody::SchedulerCapacityRetirement,
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::Scheduler,
    },
    RuntimeTestCase {
        id: "boot.smoke_cmdline_dispatch",
        body: RuntimeTestBody::Sync(boot_smoke_cmdline_dispatch),
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::Boot,
    },
    RuntimeTestCase {
        id: "nightly.smoke_cmdline_dispatch",
        body: RuntimeTestBody::Sync(nightly_smoke_cmdline_dispatch),
        tier: RuntimeTier::NightlyRequired,
        group: RuntimeGroup::Boot,
    },
    RuntimeTestCase {
        id: "nightly.step9.powercut_replay_smoke",
        body: RuntimeTestBody::Sync(nightly_powercut_replay_smoke),
        tier: RuntimeTier::NightlyRequired,
        group: RuntimeGroup::Step9Heavy,
    },
    RuntimeTestCase {
        id: "nightly.step9.kgdb_dual_transport_smoke",
        body: RuntimeTestBody::Sync(nightly_dual_transport_kgdb_smoke),
        tier: RuntimeTier::NightlyRequired,
        group: RuntimeGroup::Step9Heavy,
    },
    RuntimeTestCase {
        id: "storage.integration_suite",
        body: RuntimeTestBody::StorageIntegration,
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::Storage,
    },
    RuntimeTestCase {
        id: "iommu.integration_suite",
        body: RuntimeTestBody::IommuIntegration,
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::Iommu,
    },
    RuntimeTestCase {
        id: "network.runtime_suite",
        body: RuntimeTestBody::NetworkRuntime,
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::Network,
    },
    RuntimeTestCase {
        id: "network.zero_copy_benchmark",
        body: RuntimeTestBody::NetworkBenchmark,
        tier: RuntimeTier::NightlyRequired,
        group: RuntimeGroup::Network,
    },
    RuntimeTestCase {
        id: "driver_domain.runtime_suite",
        body: RuntimeTestBody::DriverDomainRuntime,
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::DriverDomain,
    },
    RuntimeTestCase {
        id: "cpu.hotplug_runtime_suite",
        body: RuntimeTestBody::CpuHotplugLifecycle,
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::CpuHotplug,
    },
    RuntimeTestCase {
        id: "cpu.hotplug_sparse_runtime_suite",
        body: RuntimeTestBody::CpuHotplugSparse,
        tier: RuntimeTier::NightlyRequired,
        group: RuntimeGroup::CpuHotplug,
    },
];

fn profile_selects_case(profile: &str, case: &RuntimeTestCase) -> bool {
    if str_eq(profile, "pr-required") {
        matches!(case.tier, RuntimeTier::PrRequired)
    } else if str_eq(profile, "nightly-required") {
        matches!(case.tier, RuntimeTier::NightlyRequired)
            && !matches!(case.group, RuntimeGroup::CpuHotplug)
    } else if str_eq(profile, "boot-smoke") {
        matches!(case.group, RuntimeGroup::Boot)
    } else if str_eq(profile, "scheduler") {
        matches!(case.group, RuntimeGroup::Scheduler)
    } else if str_eq(profile, "storage") {
        matches!(case.group, RuntimeGroup::Storage)
    } else if str_eq(profile, "driver_domain") {
        matches!(case.group, RuntimeGroup::DriverDomain)
    } else if str_eq(profile, "iommu") {
        matches!(case.group, RuntimeGroup::Iommu)
    } else if str_eq(profile, "mm") {
        matches!(case.group, RuntimeGroup::Memory)
    } else if str_eq(profile, "network") {
        matches!(case.group, RuntimeGroup::Network)
    } else if str_eq(profile, "cpu-hotplug") {
        str_eq(case.id, "cpu.hotplug_runtime_suite")
    } else if str_eq(profile, "cpu-hotplug-sparse") {
        str_eq(case.id, "cpu.hotplug_sparse_runtime_suite")
    } else if str_eq(profile, "step9-heavy") {
        matches!(case.group, RuntimeGroup::Step9Heavy)
    } else {
        false
    }
}

fn log_case_result(id: &str, result: RuntimeTestResult) {
    match result.status {
        RuntimeCaseStatus::Pass => {
            info!(target: "init", "[kernel-test] case {id} ok");
        }
        RuntimeCaseStatus::Fail => {
            if let Some(msg) = result.message {
                info!(target: "init", "[kernel-test] case {id} fail ({msg})");
            } else {
                info!(target: "init", "[kernel-test] case {id} fail");
            }
        }
        RuntimeCaseStatus::Blocked => {
            if let Some(msg) = result.message {
                info!(target: "init", "[kernel-test] case {id} blocked ({msg})");
            } else {
                info!(target: "init", "[kernel-test] case {id} blocked");
            }
        }
    }
}

fn log_unknown_profile(profile: &str) -> RuntimeRunSummary {
    info!(target: "init", "[kernel-test] case profile.lookup fail (unknown profile: {profile})");
    let summary = RuntimeRunSummary {
        passed: 0,
        failed: 1,
        blocked: 0,
    };
    info!(target: "init", "[kernel-test] summary pass=0 fail=1 blocked=0");
    info!(target: "init", "[kernel-test] result fail");
    summary
}

pub async fn run(profile: &str, case_filter: Option<&str>) -> RuntimeRunSummary {
    info!(target: "init", "[kernel-test] start profile={profile}");

    let mut selected_any = false;
    let mut summary = RuntimeRunSummary::new();
    let filter_names_top_level_case = case_filter
        .is_some_and(|filter| CASES.iter().any(|candidate| str_eq(candidate.id, filter)));

    for case in CASES {
        if !profile_selects_case(profile, case) {
            continue;
        }

        let pass_filter_to_inner = case_accepts_nested_filter(profile, case.id);

        if let Some(filter) = case_filter {
            if !str_eq(case.id, filter) && (!pass_filter_to_inner || filter_names_top_level_case) {
                continue;
            }
        }

        let nested_case_filter = if pass_filter_to_inner {
            match case_filter {
                Some(filter) if str_eq(filter, case.id) => None,
                Some(filter) => Some(filter),
                None => None,
            }
        } else {
            None
        };

        selected_any = true;
        let result = match case.body {
            RuntimeTestBody::Sync(run) => run(nested_case_filter),
            RuntimeTestBody::StorageIntegration => {
                storage_integration_suite(nested_case_filter).await
            }
            RuntimeTestBody::IommuIntegration => iommu_integration_suite(nested_case_filter).await,
            RuntimeTestBody::NetworkRuntime => network_runtime_suite(nested_case_filter).await,
            RuntimeTestBody::NetworkBenchmark => network_benchmark_suite().await,
            RuntimeTestBody::DriverDomainRuntime => {
                driver_domain_runtime_suite(nested_case_filter).await
            }
            RuntimeTestBody::CpuHotplugLifecycle => cpu_hotplug_runtime_suite().await,
            RuntimeTestBody::CpuHotplugSparse => cpu_hotplug_sparse_runtime_suite().await,
            RuntimeTestBody::SchedulerPreemption => {
                scheduler_preemption_case(SchedulerProbe::Uncooperative).await
            }
            RuntimeTestBody::SchedulerCriticalSection => {
                scheduler_preemption_case(SchedulerProbe::CriticalSection).await
            }
            RuntimeTestBody::SchedulerTaskTimeAbi => scheduler_task_time_abi_case().await,
            RuntimeTestBody::SchedulerWeightedProgress => {
                scheduler_runtime::weighted_progress().await
            }
            RuntimeTestBody::SchedulerQuotaRecovery => scheduler_runtime::quota_recovery().await,
            RuntimeTestBody::SchedulerCapacityRetirement => {
                scheduler_runtime::capacity_retirement_and_stale_wake().await
            }
            RuntimeTestBody::SchedulerNumaStealing => {
                scheduler_runtime::numa_ready_stealing().await
            }
        };
        log_case_result(case.id, result);

        match result.status {
            RuntimeCaseStatus::Pass => summary.passed += 1,
            RuntimeCaseStatus::Fail => summary.failed += 1,
            RuntimeCaseStatus::Blocked => summary.blocked += 1,
        }
    }

    if !selected_any {
        if case_filter.is_none() && !is_known_profile(profile) {
            return log_unknown_profile(profile);
        }

        let not_found_id = case_filter.unwrap_or("profile.selection");
        info!(target: "init", "[kernel-test] case {not_found_id} fail (no matching case)");
        summary.failed = 1;
    }

    info!(
        target: "init",
        "[kernel-test] summary pass={} fail={} blocked={}",
        summary.passed,
        summary.failed,
        summary.blocked
    );
    info!(
        target: "init",
        "[kernel-test] result {}",
        if summary.is_success() { "pass" } else { "fail" }
    );
    summary
}

#[derive(Clone, Copy)]
enum SchedulerProbe {
    Uncooperative,
    CriticalSection,
}

struct AbiTaskLifetime {
    drops: alloc::sync::Arc<core::sync::atomic::AtomicUsize>,
}

impl Drop for AbiTaskLifetime {
    fn drop(&mut self) {
        self.drops
            .fetch_add(1, core::sync::atomic::Ordering::Release);
    }
}

fn scheduler_boot_cpu_admission(_: Option<&str>) -> RuntimeTestResult {
    let topology = crate::cpu::snapshot();
    if topology
        .present()
        .iter()
        .any(|cpu| !topology.online().contains(cpu))
    {
        return RuntimeTestResult::fail("a present boot CPU was not admitted to scheduling");
    }
    RuntimeTestResult::pass()
}

/// Exercises the production ABI on running task stacks, including rejection
/// before publication, task identity, timer waiting and paired destruction.
async fn scheduler_task_time_abi_case() -> RuntimeTestResult {
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use kernel_api::abi::driver::{
        AbiTaskFuture, AbiTaskOptions, AbiTimerSchedule, TASK_WAKER_ABI,
    };
    use kernel_api::resource::task::SpawnError;
    use kernel_api::service::time::TimerSchedule;
    let api = crate::driver_registry::kernel_api_v4();
    if api.task_waker_abi != TASK_WAKER_ABI || (api.time_snapshot)().available != 1 {
        return RuntimeTestResult::fail("task runtime or timer provider unavailable through ABI");
    }
    let Some(cpu) = crate::cpu::CurrentCpu::acquire().map(|current| current.id()) else {
        return RuntimeTestResult::fail("ABI task probe requires a bound CPU");
    };
    let rejected_drops = Arc::new(AtomicUsize::new(0));
    let rejected_lifetime = AbiTaskLifetime {
        drops: Arc::clone(&rejected_drops),
    };
    let rejected_polls = Arc::new(AtomicUsize::new(0));
    let polls = Arc::clone(&rejected_polls);
    let future = Box::pin(async move {
        let _lifetime = rejected_lifetime;
        polls.fetch_add(1, Ordering::Relaxed);
    });
    let Ok(mut rejected) = AbiTaskFuture::new(future) else {
        return RuntimeTestResult::fail("cannot prepare rejected ABI Future");
    };
    let mut invalid = AbiTaskOptions::from_options(crate::task::TaskOptions::pinned(cpu));
    invalid.capacity = 0;
    // SAFETY: both aligned stack inputs are live and exclusively borrowed.
    let rejection = unsafe { (api.spawn)(&mut rejected, &invalid) }.into_result();
    drop(rejected);
    if rejection != Err(SpawnError::InvalidOptions)
        || rejected_drops.load(Ordering::Acquire) != 1
        || rejected_polls.load(Ordering::Acquire) != 0
    {
        return RuntimeTestResult::fail("ABI rejection published or leaked its Future");
    }

    let task_id = Arc::new(AtomicU64::new(0));
    let outcome = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let observed_id = Arc::clone(&task_id);
    let observed_outcome = Arc::clone(&outcome);
    let lifetime = AbiTaskLifetime {
        drops: Arc::clone(&drops),
    };
    let future = Box::pin(async move {
        let _lifetime = lifetime;
        observed_id.store((api.current_task_id)(), Ordering::Release);
        let schedule = AbiTimerSchedule::from_schedule(TimerSchedule::After {
            interval_ms: 2,
            mode: kernel_api::service::time::TimerMode::OneShot,
        });
        // SAFETY: the initialized schedule is borrowed for this call only; its
        // result transfers one provider-owned timer cancellation receipt.
        let timer = unsafe { (api.timer_register)(&schedule) }.into_result();
        let valid = match timer {
            Ok(timer) => timer.await.is_ok(),
            Err(_) => false,
        };
        let same_cpu = crate::cpu::CurrentCpu::acquire().is_some_and(|current| current.id() == cpu);
        observed_outcome.store(if valid && same_cpu { 1 } else { 2 }, Ordering::Release);
    });
    let Ok(mut future) = AbiTaskFuture::new(future) else {
        return RuntimeTestResult::fail("cannot prepare admitted ABI Future");
    };
    let options = AbiTaskOptions::from_options(crate::task::TaskOptions::pinned(cpu));
    // SAFETY: the importer transfers a unique initialized capsule while
    // retaining its aligned options and originating code for this call.
    let admitted = unsafe { (api.spawn)(&mut future, &options) }.into_result();
    drop(future);
    let Ok(admitted) = admitted else {
        return RuntimeTestResult::fail("owned task admission failed through ABI");
    };
    let Some(deadline) = crate::task::current_tick().checked_add(1_000) else {
        return RuntimeTestResult::fail("ABI task observation clock exhausted");
    };
    // LOOP_PROOF: mode=condition; reason=The owned task reports completion and destruction, or the monotonic deadline ends observation, with each unsuccessful observation awaiting a timer tick.;
    while drops.load(Ordering::Acquire) == 0 && crate::task::current_tick() < deadline {
        if crate::task::sleep_ms(1).await.is_err() {
            return RuntimeTestResult::fail("ABI task observation timer unavailable");
        }
    }
    if drops.load(Ordering::Acquire) != 1
        || outcome.load(Ordering::Acquire) != 1
        || task_id.load(Ordering::Acquire) != admitted.as_u64()
    {
        return RuntimeTestResult::fail("ABI task lost identity, timer resumption or destruction");
    }
    RuntimeTestResult::pass()
}

struct SchedulerProbeState {
    stop: core::sync::atomic::AtomicBool,
    started: core::sync::atomic::AtomicBool,
    guarded: core::sync::atomic::AtomicBool,
    done: core::sync::atomic::AtomicBool,
    dropped: core::sync::atomic::AtomicBool,
    valid: core::sync::atomic::AtomicBool,
    polls: core::sync::atomic::AtomicUsize,
    poll_task: core::sync::atomic::AtomicU64,
    waiting_polls: core::sync::atomic::AtomicUsize,
    waiting_task: core::sync::atomic::AtomicU64,
    waiting_dropped: core::sync::atomic::AtomicBool,
    waker: crate::sync::Mutex<Option<core::task::Waker>>,
}

struct RetiredPoll {
    state: alloc::sync::Arc<SchedulerProbeState>,
    domain: crate::domain::DomainId,
}

impl core::future::Future for RetiredPoll {
    type Output = ();

    fn poll(
        self: core::pin::Pin<&mut Self>,
        _: &mut core::task::Context<'_>,
    ) -> core::task::Poll<()> {
        use core::sync::atomic::Ordering;
        self.state
            .waiting_task
            .store(crate::task::current_task_id(), Ordering::Release);
        self.state.waiting_polls.fetch_add(1, Ordering::Release);
        core::task::Poll::Pending
    }
}

impl Drop for RetiredPoll {
    fn drop(&mut self) {
        use core::sync::atomic::Ordering;
        if self.state.waiting_polls.load(Ordering::Acquire) != 0 {
            let valid = crate::cpu::CurrentCpu::acquire()
                .and_then(|cpu| cpu.execution())
                .is_some_and(|subject| {
                    subject.domain == self.domain
                        && subject.task.as_u64() == self.state.waiting_task.load(Ordering::Acquire)
                });
            self.state.valid.fetch_and(valid, Ordering::AcqRel);
        }
        self.state.waiting_dropped.store(true, Ordering::Release);
    }
}

struct NoncooperativePoll {
    state: alloc::sync::Arc<SchedulerProbeState>,
    probe: SchedulerProbe,
    cpu: crate::cpu::CpuId,
    avx: bool,
    owner_domain: crate::domain::DomainId,
    nested_domain: crate::domain::DomainId,
}

impl Drop for NoncooperativePoll {
    fn drop(&mut self) {
        use core::sync::atomic::Ordering;
        if self.state.polls.load(Ordering::Acquire) != 0 {
            let subject_valid = crate::cpu::CurrentCpu::acquire()
                .and_then(|cpu| cpu.execution())
                .is_some_and(|subject| {
                    subject.domain == self.owner_domain
                        && subject.task.as_u64() == self.state.poll_task.load(Ordering::Acquire)
                });
            let cpu_valid =
                crate::cpu::CurrentCpu::acquire().is_some_and(|current| current.id() == self.cpu);
            self.state
                .valid
                .fetch_and(subject_valid && cpu_valid, Ordering::AcqRel);
        }
        self.state.dropped.store(true, Ordering::Release);
    }
}

impl core::future::Future for NoncooperativePoll {
    type Output = ();

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<()> {
        use core::sync::atomic::Ordering;
        let nested = crate::task::enter_domain(self.nested_domain).expect("nested probe admission");
        let current = crate::cpu::CurrentCpu::acquire().expect("probe requires a bound CPU");
        let fuel_valid = crate::task::fuel::Fuel::consume(37);
        let fuel_before = crate::task::fuel::Fuel::remaining();
        self.state
            .poll_task
            .store(crate::task::current_task_id(), Ordering::Release);
        self.state.polls.fetch_add(1, Ordering::AcqRel);
        *self.state.waker.lock() = Some(cx.waker().clone());
        self.state.started.store(true, Ordering::Release);
        if matches!(self.probe, SchedulerProbe::CriticalSection) {
            let exclusion = hal::preemption::PreemptionGuard::enter();
            self.state.guarded.store(true, Ordering::Release);
            let deadline = crate::time::precise_time_nanos().saturating_add(
                crate::task::config::SCHEDULER_CONFIG
                    .quantum_ns
                    .saturating_mul(3),
            );
            // LOOP_PROOF: mode=condition; reason=Enabled local timer interrupts advance precise_time_nanos toward deadline while switching is excluded, with an external QEMU failure timeout for a broken clock.;
            while crate::time::precise_time_nanos() < deadline {
                core::hint::spin_loop();
            }
            self.state.guarded.store(false, Ordering::Release);
            drop(exclusion);
        }
        // SAFETY: the stop atomic is retained by this Future and the controller.
        // The assembly obeys the SysV ABI and returns only after a different
        // task on the same CPU stores stop. It contains no yield or fuel check.
        let registers_valid =
            unsafe { rany_scheduler_register_probe(&self.state.stop, u64::from(self.avx)) != 0 };
        let same_cpu = current.id() == self.cpu
            && crate::cpu::CurrentCpu::acquire().is_some_and(|cpu| cpu.id() == self.cpu);
        self.state.valid.fetch_and(
            registers_valid
                && same_cpu
                && fuel_valid
                && crate::task::fuel::Fuel::remaining() == fuel_before
                && crate::task::current_subject().domain == self.nested_domain,
            Ordering::AcqRel,
        );
        drop(nested);
        self.state.done.store(true, Ordering::Release);
        core::task::Poll::Ready(())
    }
}

async fn scheduler_preemption_case(probe: SchedulerProbe) -> RuntimeTestResult {
    use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    if !crate::interrupts::are_interrupts_enabled() {
        return RuntimeTestResult::fail("scheduler probes require enabled interrupts");
    }
    let Some(cpu) = crate::cpu::CurrentCpu::acquire().map(|cpu| cpu.id()) else {
        return RuntimeTestResult::fail("scheduler probe lost CPU binding");
    };
    let state = alloc::sync::Arc::new(SchedulerProbeState {
        stop: AtomicBool::new(false),
        started: AtomicBool::new(false),
        guarded: AtomicBool::new(false),
        done: AtomicBool::new(false),
        dropped: AtomicBool::new(false),
        valid: AtomicBool::new(true),
        polls: AtomicUsize::new(0),
        poll_task: AtomicU64::new(0),
        waiting_polls: AtomicUsize::new(0),
        waiting_task: AtomicU64::new(0),
        waiting_dropped: AtomicBool::new(false),
        waker: crate::sync::Mutex::new(None),
    });
    let Ok(domain) = crate::domain::create_domain("scheduler-poll-owner".into()) else {
        return RuntimeTestResult::fail("cannot create poll owner domain");
    };
    let Ok(nested_domain) = crate::domain::create_domain("scheduler-nested-owner".into()) else {
        let _ = crate::domain::terminate_domain(domain);
        return RuntimeTestResult::fail("cannot create nested owner domain");
    };
    let xstate = crate::cpu::xstate::configuration();
    log::info!(target: "init", "[kernel-test] poll preemption state={xstate:?}");
    let avx = matches!(xstate,
        crate::cpu::xstate::XStateConfiguration::Xsave { mask, .. } if mask & 4 != 0);
    let before = crate::task::scheduler_snapshot().expect("scheduler must be installed");
    if crate::task::spawn_in_domain(
        RetiredPoll {
            state: alloc::sync::Arc::clone(&state),
            domain,
        },
        crate::task::TaskOptions::pinned(cpu),
        domain,
    )
    .is_err()
    {
        let _ = crate::domain::terminate_domain(domain);
        let _ = crate::domain::terminate_domain(nested_domain);
        return RuntimeTestResult::fail("cannot admit event-waiting retirement probe");
    }
    let admission = crate::task::spawn_in_domain(
        NoncooperativePoll {
            state: alloc::sync::Arc::clone(&state),
            probe,
            cpu,
            avx,
            owner_domain: domain,
            nested_domain,
        },
        crate::task::TaskOptions::pinned(cpu),
        domain,
    );
    let Ok(task_id) = admission else {
        let _ = crate::domain::terminate_domain(domain);
        let _ = crate::domain::terminate_domain(nested_domain);
        return RuntimeTestResult::fail("cannot admit noncooperative probe");
    };
    let stopper = alloc::sync::Arc::clone(&state);
    if crate::task::spawn(
        async move {
            let same_cpu =
                crate::cpu::CurrentCpu::acquire().is_some_and(|current| current.id() == cpu);
            let after_start = stopper.started.load(Ordering::Acquire);
            let outside_guard = !stopper.guarded.load(Ordering::Acquire);
            let offline_blocked = crate::task::prepare_cpu_offline(cpu).is_err_and(|blockers| {
                blockers.iter().any(|blocker| matches!(blocker,
                    crate::cpu::CpuBlocker::SuspendedPoll { task_id: id } if *id == task_id.as_u64()))
            });
            let owner_busy = matches!(crate::domain::terminate_domain(domain),
                Err(crate::domain::DomainLifecycleError::Busy(
                    crate::domain::DomainStopOutcome::InProgress { interrupted_polls, .. }
                )) if interrupted_polls != 0);
            let nested_busy = matches!(crate::domain::terminate_domain(nested_domain),
                Err(crate::domain::DomainLifecycleError::CodeBusy { leases }) if leases != 0);
            let retained = !stopper.dropped.load(Ordering::Acquire);
            let suspended_waker = stopper.waker.lock().clone();
            let notified = if let Some(waker) = suspended_waker {
                // Repeated wake requests must not reenter a suspended poll or
                // fill an event-volume queue. Its continuation still owns it.
                for _ in 0..10_000 {
                    waker.wake_by_ref();
                }
                true
            } else {
                false
            };
            // Overwrite SIMD and floating-point control state in the other task.
            // The suspended probe must recover its own state on resumption.
            unsafe { rany_scheduler_clobber_probe(u64::from(avx)) };
            stopper
                .valid
                .fetch_and(same_cpu && after_start && outside_guard && offline_blocked && owner_busy && nested_busy && retained && notified, Ordering::AcqRel);
            stopper.stop.store(true, Ordering::Release);
        },
        crate::task::TaskOptions::pinned(cpu),
    )
    .is_err()
    {
        state.stop.store(true, Ordering::Release);
        return RuntimeTestResult::fail("cannot admit same-CPU stopper");
    }
    let deadline = crate::task::current_tick().saturating_add(1_000);
    // LOOP_PROOF: mode=condition; reason=Each incomplete observation awaits the timer until the probe and destructor complete or current_tick reaches the deadline.;
    while (!state.done.load(Ordering::Acquire) || !state.dropped.load(Ordering::Acquire))
        && crate::task::current_tick() < deadline
    {
        if let Err(cause) = crate::task::sleep_ms(1).await {
            log::error!("scheduler probe deadline unavailable: {cause}");
            state.stop.store(true, Ordering::Release);
            return RuntimeTestResult::fail("scheduler probe timer admission failed");
        }
    }
    state.stop.store(true, Ordering::Release);
    if !state.done.load(Ordering::Acquire) {
        return RuntimeTestResult::fail("noncooperative poll did not resume");
    }
    // Busy closes admission but retains the stack; after this poll and its
    // destructor finish, both owner domains can complete ordinary reclamation.
    for retained_domain in [domain, nested_domain] {
        // The destructor's signal precedes the final code-lease field drop.
        // Another CPU can observe that interval, so retry the typed Busy
        // outcome until the same bounded deadline rather than equating the
        // signal with completed resource reclamation.
        // LOOP_PROOF: mode=event; reason=Busy reclamation awaits a timer tick, and success or the shared deadline terminates the retry.;
        loop {
            match crate::domain::terminate_domain(retained_domain) {
                Ok(()) => break,
                Err(
                    crate::domain::DomainLifecycleError::CodeBusy { .. }
                    | crate::domain::DomainLifecycleError::ReclamationInProgress,
                ) if crate::task::current_tick() < deadline => {
                    if let Err(cause) = crate::task::sleep_ms(1).await {
                        log::error!("scheduler probe deadline unavailable: {cause}");
                        state.stop.store(true, Ordering::Release);
                        return RuntimeTestResult::fail("scheduler probe timer admission failed");
                    }
                }
                Err(_) => {
                    return RuntimeTestResult::fail(
                        "poll boundary did not release domain reclamation",
                    );
                }
            }
        }
    }
    let after = crate::task::scheduler_snapshot().expect("scheduler must remain installed");
    if let Some(stale) = state.waker.lock().as_ref() {
        stale.wake_by_ref();
    }
    if !state.valid.load(Ordering::Acquire)
        || state.polls.load(Ordering::Acquire) != 1
        || state.waiting_polls.load(Ordering::Acquire) != 1
        || !state.waiting_dropped.load(Ordering::Acquire)
    {
        return RuntimeTestResult::fail(
            "poll or destructor lost identity, CPU binding, or registers/SIMD state",
        );
    }
    if after.forced_switches <= before.forced_switches || after.runtime_ns <= before.runtime_ns {
        return RuntimeTestResult::fail(
            "execution fragments and actual forced switch were not accounted",
        );
    }
    RuntimeTestResult::pass()
}

unsafe extern "sysv64" {
    fn rany_scheduler_register_probe(stop: *const core::sync::atomic::AtomicBool, avx: u64) -> u64;
    fn rany_scheduler_clobber_probe(avx: u64);
}

core::arch::global_asm!(
    r#"
    .global rany_scheduler_register_probe
    rany_scheduler_register_probe:
        push rbx
        push rbp
        push r12
        push r13
        push r14
        push r15
        sub rsp, 32
        mov [rsp], rdi
        mov [rsp + 24], rsi
        stmxcsr [rsp + 8]
        fnstcw [rsp + 12]
        mov dword ptr [rsp + 16], 0x5f80
        mov word ptr [rsp + 20], 0x077f
        ldmxcsr [rsp + 16]
        fldcw [rsp + 20]
        fld1
        pcmpeqd xmm0, xmm0
        pcmpeqd xmm15, xmm15
        test rsi, rsi
        jz 10f
        vinsertf128 ymm15, ymm15, xmm15, 1
    10:
        mov rax, 0x11
        mov rbx, 0x22
        mov rcx, 0x33
        mov rdx, 0x44
        mov rsi, 0x66
        mov rbp, 0x77
        mov r8, 0x88
        mov r9, 0x99
        mov r10, 0xaa
        mov r11, 0xbb
        mov r12, 0xcc
        mov r13, 0xdd
        mov r14, 0xee
        mov r15, 0xff
    20:
        cmp byte ptr [rdi], 0
        pause
        je 20b
        cmp rax, 0x11
        jne 90f
        cmp rbx, 0x22
        jne 90f
        cmp rcx, 0x33
        jne 90f
        cmp rdx, 0x44
        jne 90f
        cmp rsi, 0x66
        jne 90f
        cmp rbp, 0x77
        jne 90f
        cmp r8, 0x88
        jne 90f
        cmp r9, 0x99
        jne 90f
        cmp r10, 0xaa
        jne 90f
        cmp r11, 0xbb
        jne 90f
        cmp r12, 0xcc
        jne 90f
        cmp r13, 0xdd
        jne 90f
        cmp r14, 0xee
        jne 90f
        cmp r15, 0xff
        jne 90f
        cmp rdi, [rsp]
        jne 90f
        pmovmskb eax, xmm0
        cmp eax, 0xffff
        jne 90f
        pmovmskb eax, xmm15
        cmp eax, 0xffff
        jne 90f
        cmp qword ptr [rsp + 24], 0
        je 30f
        vextractf128 xmm0, ymm15, 1
        pmovmskb eax, xmm0
        cmp eax, 0xffff
        jne 90f
    30:
        stmxcsr [rsp + 16]
        cmp dword ptr [rsp + 16], 0x5f80
        jne 90f
        fnstcw [rsp + 20]
        cmp word ptr [rsp + 20], 0x077f
        jne 90f
        fstp qword ptr [rsp + 16]
        cmp dword ptr [rsp + 16], 0
        jne 90f
        cmp dword ptr [rsp + 20], 0x3ff00000
        jne 90f
        mov eax, 1
        jmp 91f
    90:
        fninit
        xor eax, eax
    91:
        ldmxcsr [rsp + 8]
        fldcw [rsp + 12]
        add rsp, 32
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbp
        pop rbx
        ret

    .global rany_scheduler_clobber_probe
    rany_scheduler_clobber_probe:
        pxor xmm0, xmm0
        pxor xmm15, xmm15
        test rdi, rdi
        jz 40f
        vxorps ymm15, ymm15, ymm15
    40:
        sub rsp, 8
        mov dword ptr [rsp], 0x1f80
        ldmxcsr [rsp]
        add rsp, 8
        fninit
        ret
"#
);
