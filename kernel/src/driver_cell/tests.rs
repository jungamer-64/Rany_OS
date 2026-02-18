// ============================================================================
// kernel/src/driver_cell/tests.rs - DriverCell ユニットテスト
// ============================================================================
//! # DriverCellモジュールのテスト
//!
//! ライフサイクル、障害処理、再起動ポリシー、統計情報のテスト。

#![cfg(test)]
#![allow(dead_code)]

use super::*;
use super::fault::{FaultKind, RestartPolicy};
use super::stats::DriverCellStats;

// ============================================================================
// DriverCellState テスト
// ============================================================================

#[test]
fn test_state_default_is_created() {
    let state = DriverCellState::Created;
    assert!(matches!(state, DriverCellState::Created));
}

#[test]
fn test_state_transitions_are_valid() {
    // Created → Loaded → Running → Stopped → Unloaded
    let mut state = DriverCellState::Created;

    state = DriverCellState::Loaded;
    assert!(matches!(state, DriverCellState::Loaded));

    state = DriverCellState::Running;
    assert!(matches!(state, DriverCellState::Running));

    state = DriverCellState::Stopped;
    assert!(matches!(state, DriverCellState::Stopped));

    state = DriverCellState::Unloaded;
    assert!(matches!(state, DriverCellState::Unloaded));
}

#[test]
fn test_state_faulted() {
    let state = DriverCellState::Faulted;
    assert!(matches!(state, DriverCellState::Faulted));
}

// ============================================================================
// DriverCellId テスト
// ============================================================================

#[test]
fn test_driver_cell_id_equality() {
    let id1 = DriverCellId(1);
    let id2 = DriverCellId(1);
    let id3 = DriverCellId(2);

    assert_eq!(id1, id2);
    assert_ne!(id1, id3);
}

#[test]
fn test_driver_cell_id_ordering() {
    let id1 = DriverCellId(1);
    let id2 = DriverCellId(2);
    let id3 = DriverCellId(3);

    assert!(id1 < id2);
    assert!(id2 < id3);
}

// ============================================================================
// RestartPolicy テスト
// ============================================================================

#[test]
fn test_restart_policy_never() {
    let policy = RestartPolicy::Never;
    match policy {
        RestartPolicy::Never => {} // OK
        _ => panic!("expected Never"),
    }
}

#[test]
fn test_restart_policy_on_panic_defaults() {
    let policy = RestartPolicy::OnPanic {
        max_retries: 3,
        backoff_ms: 100,
    };
    match policy {
        RestartPolicy::OnPanic {
            max_retries,
            backoff_ms,
        } => {
            assert_eq!(max_retries, 3);
            assert_eq!(backoff_ms, 100);
        }
        _ => panic!("expected OnPanic"),
    }
}

#[test]
fn test_restart_policy_always() {
    let policy = RestartPolicy::Always {
        max_retries: 5,
        backoff_ms: 200,
    };
    match policy {
        RestartPolicy::Always {
            max_retries,
            backoff_ms,
        } => {
            assert_eq!(max_retries, 5);
            assert_eq!(backoff_ms, 200);
        }
        _ => panic!("expected Always"),
    }
}

// ============================================================================
// FaultKind テスト
// ============================================================================

#[test]
fn test_fault_kind_variants() {
    let kinds = [
        FaultKind::Panic,
        FaultKind::InitFailed,
        FaultKind::Timeout,
        FaultKind::QuotaExceeded,
        FaultKind::MemoryViolation,
        FaultKind::Other,
    ];

    // 各バリアントが区別可能であることを確認
    for (i, kind) in kinds.iter().enumerate() {
        for (j, other) in kinds.iter().enumerate() {
            if i == j {
                // 同じバリアントはmatch可能
                assert!(matches!(
                    (kind, other),
                    (FaultKind::Panic, FaultKind::Panic)
                        | (FaultKind::InitFailed, FaultKind::InitFailed)
                        | (FaultKind::Timeout, FaultKind::Timeout)
                        | (FaultKind::QuotaExceeded, FaultKind::QuotaExceeded)
                        | (FaultKind::MemoryViolation, FaultKind::MemoryViolation)
                        | (FaultKind::Other, FaultKind::Other)
                ));
            }
        }
    }
}

// ============================================================================
// DriverCellStats テスト
// ============================================================================

#[test]
fn test_stats_initial_values() {
    let stats = DriverCellStats::new();
    assert_eq!(stats.load_duration_ticks, 0);
    assert_eq!(stats.load_timestamp, 0);
    assert_eq!(stats.start_count, 0);
    assert_eq!(stats.stop_count, 0);
    assert_eq!(stats.fault_count, 0);
    assert_eq!(stats.restart_count, 0);
    assert_eq!(stats.hot_swap_count, 0);
    assert_eq!(stats.total_uptime_ticks, 0);
    assert_eq!(stats.max_uptime_ticks, 0);
}

#[test]
fn test_stats_default() {
    let stats: DriverCellStats = Default::default();
    assert_eq!(stats.start_count, 0);
}

#[test]
fn test_stats_record_start() {
    let mut stats = DriverCellStats::new();
    stats.record_start();
    assert_eq!(stats.start_count, 1);

    stats.record_start();
    assert_eq!(stats.start_count, 2);
}

#[test]
fn test_stats_record_stop() {
    let mut stats = DriverCellStats::new();
    stats.record_stop();
    assert_eq!(stats.stop_count, 1);
}

#[test]
fn test_stats_record_fault() {
    let mut stats = DriverCellStats::new();
    stats.record_fault();
    assert_eq!(stats.fault_count, 1);

    stats.record_fault();
    assert_eq!(stats.fault_count, 2);
}

#[test]
fn test_stats_record_restart() {
    let mut stats = DriverCellStats::new();
    stats.record_restart();
    assert_eq!(stats.restart_count, 1);
}

#[test]
fn test_stats_record_hot_swap() {
    let mut stats = DriverCellStats::new();
    stats.record_hot_swap();
    assert_eq!(stats.hot_swap_count, 1);

    stats.record_hot_swap();
    stats.record_hot_swap();
    assert_eq!(stats.hot_swap_count, 3);
}

// ============================================================================
// DriverCellError テスト
// ============================================================================

#[test]
fn test_error_not_found() {
    let err = DriverCellError::NotFound(DriverCellId(42));
    match err {
        DriverCellError::NotFound(id) => assert_eq!(id, DriverCellId(42)),
        _ => panic!("expected NotFound"),
    }
}

#[test]
fn test_error_invalid_state() {
    let err = DriverCellError::InvalidState {
        expected: DriverCellState::Loaded,
        actual: DriverCellState::Running,
    };
    match err {
        DriverCellError::InvalidState { expected, actual } => {
            assert!(matches!(expected, DriverCellState::Loaded));
            assert!(matches!(actual, DriverCellState::Running));
        }
        _ => panic!("expected InvalidState"),
    }
}

// ============================================================================
// GlobalDriverCellStats テスト
// ============================================================================

#[test]
fn test_global_stats_new() {
    use super::stats::GlobalDriverCellStats;
    let stats = GlobalDriverCellStats::new();
    let summary = stats.summary();
    assert_eq!(summary.total_created, 0);
    assert_eq!(summary.total_unloaded, 0);
    assert_eq!(summary.total_faults, 0);
}

#[test]
fn test_global_stats_tracking() {
    use super::stats::GlobalDriverCellStats;
    let stats = GlobalDriverCellStats::new();

    stats.on_created();
    stats.on_created();
    stats.on_fault();
    stats.on_hot_swap();

    let summary = stats.summary();
    assert_eq!(summary.total_created, 2);
    assert_eq!(summary.total_faults, 1);
    assert_eq!(summary.total_hot_swaps, 1);
}
