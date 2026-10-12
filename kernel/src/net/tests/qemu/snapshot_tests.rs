// ============================================================================
// kernel/src/net/tests/qemu/snapshot_tests.rs - Runtime observation ownership
// ============================================================================

use crate::net::obs::observability_in;
use crate::net::obs::snapshot::snapshot_in;
use crate::net::obs::trace::{NetEventKind, NetLayer};
use crate::net::runtime::{create_runtime, manager};

pub fn snapshot_counter_deltas_and_events_smoke() -> bool {
    let runtime = create_runtime().expect("snapshot runtime");
    let before = snapshot_in(runtime);
    let observability = observability_in(runtime);
    observability.counters().record_rx(64);
    observability.counters().record_tx(32);
    observability.counters().record_drop();
    observability.counters().record_error();
    observability.trace().push(
        NetLayer::Service,
        NetEventKind::Rx,
        "obs-snapshot-test-event",
    );
    let after = snapshot_in(runtime);
    assert_eq!(after.rx_packets, before.rx_packets + 1);
    assert_eq!(after.tx_packets, before.tx_packets + 1);
    assert_eq!(after.rx_bytes, before.rx_bytes + 64);
    assert_eq!(after.tx_bytes, before.tx_bytes + 32);
    assert_eq!(after.drops, before.drops + 1);
    assert_eq!(after.errors, before.errors + 1);
    assert!(
        after
            .recent_events
            .iter()
            .any(|event| event.message == "obs-snapshot-test-event")
    );
    true
}

pub fn snapshot_runtime_isolation_smoke() -> bool {
    let first = create_runtime().expect("first observation runtime");
    let second = create_runtime().expect("second observation runtime");
    let observability = observability_in(first);
    observability.counters().record_rx(128);
    observability
        .trace()
        .push(NetLayer::Driver, NetEventKind::Rx, "runtime-a-only-event");
    let first_snapshot = snapshot_in(first);
    let second_snapshot = snapshot_in(second);
    assert_eq!(first_snapshot.rx_packets, 1);
    assert_eq!(first_snapshot.rx_bytes, 128);
    assert!(
        first_snapshot
            .recent_events
            .iter()
            .any(|event| event.message == "runtime-a-only-event")
    );
    assert_eq!(second_snapshot.rx_packets, 0);
    assert_eq!(second_snapshot.rx_bytes, 0);
    assert!(
        second_snapshot
            .recent_events
            .iter()
            .all(|event| event.message != "runtime-a-only-event")
    );
    true
}

pub fn snapshot_registered_interface_smoke() -> bool {
    let runtime = create_runtime().expect("interface observation runtime");
    manager::init_network_manager_in(runtime);
    manager::register_interface_in(runtime, "obs-snapshot-if", manager::PrimaryPreference::Auto)
        .expect("observed interface registration");
    let snapshot = snapshot_in(runtime);
    assert_eq!(snapshot.interfaces.len(), 1);
    assert_eq!(snapshot.interfaces[0].name, "obs-snapshot-if");
    true
}
