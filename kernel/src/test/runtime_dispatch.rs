use log::info;

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
    DriverCell,
}

pub struct RuntimeTestCase {
    pub id: &'static str,
    pub run: fn() -> RuntimeTestResult,
    pub tier: RuntimeTier,
    pub group: RuntimeGroup,
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

fn boot_smoke_cmdline_dispatch() -> RuntimeTestResult {
    RuntimeTestResult::pass()
}

fn storage_integration_suite() -> RuntimeTestResult {
    let (_passed, failed) = crate::test::integration::run_all_integration_tests();
    if failed == 0 {
        RuntimeTestResult::pass()
    } else {
        RuntimeTestResult::fail("integration suite failures")
    }
}

fn driver_cell_runtime_suite() -> RuntimeTestResult {
    #[cfg(feature = "qemu-test-export")]
    {
        let summary = crate::driver_cell::qemu_tests::run_driver_cell_runtime_suite();
        if summary.failed > 0 {
            return RuntimeTestResult::fail("driver_cell runtime failures");
        }
        if summary.blocked > 0 {
            return RuntimeTestResult::blocked("driver_cell runtime blocked");
        }
        return RuntimeTestResult::pass();
    }

    #[cfg(not(feature = "qemu-test-export"))]
    {
        RuntimeTestResult::blocked("driver_cell runtime requires qemu-test-export")
    }
}

static CASES: &[RuntimeTestCase] = &[
    RuntimeTestCase {
        id: "boot.smoke_cmdline_dispatch",
        run: boot_smoke_cmdline_dispatch,
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::Boot,
    },
    RuntimeTestCase {
        id: "storage.integration_suite",
        run: storage_integration_suite,
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::Storage,
    },
    RuntimeTestCase {
        id: "driver_cell.runtime_suite",
        run: driver_cell_runtime_suite,
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::DriverCell,
    },
];

fn profile_selects_case(profile: &str, case: &RuntimeTestCase) -> bool {
    match profile {
        "pr-required" => matches!(case.tier, RuntimeTier::PrRequired),
        "nightly-required" => {
            matches!(case.tier, RuntimeTier::PrRequired | RuntimeTier::NightlyRequired)
        }
        "boot-smoke" => matches!(case.group, RuntimeGroup::Boot),
        "storage" => matches!(case.group, RuntimeGroup::Storage),
        "driver_cell" => matches!(case.group, RuntimeGroup::DriverCell),
        _ => false,
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

pub fn run(profile: &str, case_filter: Option<&str>) -> RuntimeRunSummary {
    info!(target: "init", "[kernel-test] start profile={profile}");

    let mut selected_any = false;
    let mut summary = RuntimeRunSummary::new();

    for case in CASES {
        if !profile_selects_case(profile, case) {
            continue;
        }

        if let Some(filter) = case_filter {
            if case.id != filter {
                continue;
            }
        }

        selected_any = true;
        let result = (case.run)();
        log_case_result(case.id, result);

        match result.status {
            RuntimeCaseStatus::Pass => summary.passed += 1,
            RuntimeCaseStatus::Fail => summary.failed += 1,
            RuntimeCaseStatus::Blocked => summary.blocked += 1,
        }
    }

    if !selected_any {
        if case_filter.is_none()
            && !matches!(
                profile,
                "pr-required" | "nightly-required" | "boot-smoke" | "storage" | "driver_cell"
            )
        {
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
