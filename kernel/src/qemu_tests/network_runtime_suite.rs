use log::info;

#[path = "generated/network_case_table.rs"]
mod network_case_table;

use network_case_table::NETWORK_RUNTIME_CASES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkRuntimeSuiteSummary {
    pub passed: u32,
    pub failed: u32,
    pub blocked: u32,
}

impl NetworkRuntimeSuiteSummary {
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

pub fn run_network_runtime_suite(case_filter: Option<&str>) -> NetworkRuntimeSuiteSummary {
    info!(target: "init", "[kernel-test][net] start");
    crate::io::iommu::api::reset_map_unmap_counts();

    let mut summary = NetworkRuntimeSuiteSummary::new();
    let mut selected_any = false;

    for (id, run_case) in NETWORK_RUNTIME_CASES {
        if let Some(filter) = case_filter {
            if !str_eq(id, filter) {
                continue;
            }
        }

        selected_any = true;
        if run_case() {
            summary.passed += 1;
            info!(target: "init", "[kernel-test][net] case {id} ok");
        } else {
            summary.failed += 1;
            info!(target: "init", "[kernel-test][net] case {id} fail");
        }
    }

    if !selected_any {
        let not_found_id = case_filter.unwrap_or("network.case_selection");
        summary.failed = 1;
        info!(
            target: "init",
            "[kernel-test][net] case {not_found_id} fail (no matching case)"
        );
    }

    if selected_any && !crate::io::iommu::api::is_iommu_enabled() {
        summary.failed += 1;
        info!(
            target: "init",
            "[kernel-test][net] case net.iommu_active fail"
        );
    }

    info!(
        target: "init",
        "[kernel-test][net] summary pass={} fail={} blocked={}",
        summary.passed,
        summary.failed,
        summary.blocked
    );
    info!(
        target: "init",
        "[kernel-test][net] result {}",
        if summary.is_success() { "pass" } else { "fail" }
    );

    summary
}
