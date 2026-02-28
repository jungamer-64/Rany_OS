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
    Iommu,
}

pub struct RuntimeTestCase {
    pub id: &'static str,
    pub run: fn() -> RuntimeTestResult,
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
        || str_eq(profile, "boot-smoke")
        || str_eq(profile, "storage")
        || str_eq(profile, "driver_cell")
        || str_eq(profile, "iommu")
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

fn nightly_smoke_cmdline_dispatch() -> RuntimeTestResult {
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

fn iommu_integration_suite() -> RuntimeTestResult {
    let suite = crate::test::integration::test_iommu();
    suite.print_summary();
    if suite.failed() == 0 {
        RuntimeTestResult::pass()
    } else {
        RuntimeTestResult::fail("iommu suite failures")
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
        id: "nightly.smoke_cmdline_dispatch",
        run: nightly_smoke_cmdline_dispatch,
        tier: RuntimeTier::NightlyRequired,
        group: RuntimeGroup::Boot,
    },
    RuntimeTestCase {
        id: "storage.integration_suite",
        run: storage_integration_suite,
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::Storage,
    },
    RuntimeTestCase {
        id: "iommu.integration_suite",
        run: iommu_integration_suite,
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::Iommu,
    },
    RuntimeTestCase {
        id: "driver_cell.runtime_suite",
        run: driver_cell_runtime_suite,
        tier: RuntimeTier::PrRequired,
        group: RuntimeGroup::DriverCell,
    },
];

fn profile_selects_case(profile: &str, case: &RuntimeTestCase) -> bool {
    if str_eq(profile, "pr-required") {
        matches!(case.tier, RuntimeTier::PrRequired)
    } else if str_eq(profile, "nightly-required") {
        matches!(case.tier, RuntimeTier::NightlyRequired)
    } else if str_eq(profile, "boot-smoke") {
        matches!(case.group, RuntimeGroup::Boot)
    } else if str_eq(profile, "storage") {
        matches!(case.group, RuntimeGroup::Storage)
    } else if str_eq(profile, "driver_cell") {
        matches!(case.group, RuntimeGroup::DriverCell)
    } else if str_eq(profile, "iommu") {
        matches!(case.group, RuntimeGroup::Iommu)
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

pub fn run(profile: &str, case_filter: Option<&str>) -> RuntimeRunSummary {
    info!(target: "init", "[kernel-test] start profile={profile}");

    if str_eq(profile, "nightly-required") {
        let nightly_case_id = "nightly.smoke_cmdline_dispatch";
        let mut summary = RuntimeRunSummary::new();

        if let Some(filter) = case_filter {
            if !str_eq(filter, nightly_case_id) {
                crate::io::log::early_print("[kernel-test] case ");
                crate::io::log::early_print(filter);
                crate::io::log::early_print(" fail (no matching case)\n");
                summary.failed = 1;
                crate::io::log::early_print("[kernel-test] summary pass=0 fail=1 blocked=0\n");
                crate::io::log::early_print("[kernel-test] result fail\n");
                return summary;
            }
        }

        let result = nightly_smoke_cmdline_dispatch();
        match result.status {
            RuntimeCaseStatus::Pass => summary.passed += 1,
            RuntimeCaseStatus::Fail => summary.failed += 1,
            RuntimeCaseStatus::Blocked => summary.blocked += 1,
        }

        match result.status {
            RuntimeCaseStatus::Pass => {
                crate::io::log::early_print("[kernel-test] case nightly.smoke_cmdline_dispatch ok\n");
            }
            RuntimeCaseStatus::Fail => {
                crate::io::log::early_print("[kernel-test] case nightly.smoke_cmdline_dispatch fail\n");
            }
            RuntimeCaseStatus::Blocked => {
                crate::io::log::early_print("[kernel-test] case nightly.smoke_cmdline_dispatch blocked\n");
            }
        }
        crate::io::log::early_print("[kernel-test] summary pass=");
        crate::io::log::early_print_dec(summary.passed as u64);
        crate::io::log::early_print(" fail=");
        crate::io::log::early_print_dec(summary.failed as u64);
        crate::io::log::early_print(" blocked=");
        crate::io::log::early_print_dec(summary.blocked as u64);
        crate::io::log::early_print("\n");
        crate::io::log::early_print("[kernel-test] result ");
        if summary.is_success() {
            crate::io::log::early_print("pass\n");
        } else {
            crate::io::log::early_print("fail\n");
        }
        return summary;
    }

    let mut selected_any = false;
    let mut summary = RuntimeRunSummary::new();

    for case in CASES {
        if !profile_selects_case(profile, case) {
            continue;
        }

        if let Some(filter) = case_filter {
            if !str_eq(case.id, filter) {
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
