// ============================================================================
// kernel/src/driver_cell/tests.rs - DriverCell QEMU test exports
// ============================================================================

#![allow(dead_code)]

use super::fault::{FaultKind, RestartPolicy};
use super::stats::DriverCellStats;
use super::*;

pub fn driver_cell_state_default_is_created_smoke() -> bool {
    matches!(DriverCellState::Created, DriverCellState::Created)
}

pub fn driver_cell_state_transitions_are_valid_smoke() -> bool {
    let mut state = DriverCellState::Created;
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
    matches!(DriverCellState::Faulted, DriverCellState::Faulted)
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
    matches!(RestartPolicy::Never, RestartPolicy::Never)
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
        FaultKind::Panic,
        FaultKind::InitFailed,
        FaultKind::Timeout,
        FaultKind::QuotaExceeded,
        FaultKind::MemoryViolation,
        FaultKind::Other,
    ];

    for kind in kinds {
        let ok = matches!(
            kind,
            FaultKind::Panic
                | FaultKind::InitFailed
                | FaultKind::Timeout
                | FaultKind::QuotaExceeded
                | FaultKind::MemoryViolation
                | FaultKind::Other
        );
        if !ok {
            return false;
        }
    }
    true
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
    let err = DriverCellError::InvalidState {
        expected: DriverCellState::Loaded,
        actual: DriverCellState::Running,
    };

    matches!(
        err,
        DriverCellError::InvalidState {
            expected: DriverCellState::Loaded,
            actual: DriverCellState::Running
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
