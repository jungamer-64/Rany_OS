// ============================================================================
// kernel/src/net/obs/snapshot.rs - obs / snapshot
// ============================================================================

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::net::obs::observability_in;
use crate::net::obs::trace::NetTraceEvent;
use crate::net::runtime::{NetRuntimeHandle, bridge, manager};

extern crate alloc;

#[derive(Debug)]
pub struct InterfaceSnapshot {
    pub name: alloc::string::String,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

#[derive(Debug)]
pub struct NetSnapshot {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub drops: u64,
    pub errors: u64,
    pub interfaces: Vec<InterfaceSnapshot>,
    pub recent_events: Vec<NetTraceEvent>,
}

fn collect_interface_snapshots(runtime: NetRuntimeHandle) -> Vec<InterfaceSnapshot> {
    let mut interfaces = Vec::new();
    let mut index_by_if = BTreeMap::new();

    if let Ok(ifaces) = manager::list_interfaces_in(runtime) {
        for iface in ifaces {
            let idx = interfaces.len();
            interfaces.push(InterfaceSnapshot {
                name: alloc::string::String::from(iface.name),
                rx_packets: 0,
                tx_packets: 0,
            });
            index_by_if.insert(iface.if_id, idx);
        }
    }

    for stats in bridge::list_stack_glue_stats_in(runtime) {
        if let Some(idx) = index_by_if.get(&stats.if_id).copied() {
            if let Some(entry) = interfaces.get_mut(idx) {
                entry.rx_packets = stats.rx_packets;
                entry.tx_packets = stats.tx_packets;
            }
            continue;
        }

        let name = manager::get_interface_in(runtime, stats.if_id)
            .ok()
            .flatten()
            .map(|iface| alloc::string::String::from(iface.name))
            .unwrap_or_else(|| alloc::format!("if{}", stats.if_id.0));

        let idx = interfaces.len();
        interfaces.push(InterfaceSnapshot {
            name,
            rx_packets: stats.rx_packets,
            tx_packets: stats.tx_packets,
        });
        index_by_if.insert(stats.if_id, idx);
    }

    interfaces
}

pub fn snapshot_in(runtime: NetRuntimeHandle) -> NetSnapshot {
    let observability = observability_in(runtime);
    let c = observability.counters();
    NetSnapshot {
        rx_packets: c.rx_packets.load(core::sync::atomic::Ordering::Relaxed),
        tx_packets: c.tx_packets.load(core::sync::atomic::Ordering::Relaxed),
        rx_bytes: c.rx_bytes.load(core::sync::atomic::Ordering::Relaxed),
        tx_bytes: c.tx_bytes.load(core::sync::atomic::Ordering::Relaxed),
        drops: c.drops.load(core::sync::atomic::Ordering::Relaxed),
        errors: c.errors.load(core::sync::atomic::Ordering::Relaxed),
        interfaces: collect_interface_snapshots(runtime),
        recent_events: observability.trace().recent(64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::obs::observability_in;
    use crate::net::obs::trace::{NetEventKind, NetLayer};
    use crate::net::runtime::create_runtime;

    #[cfg_attr(test, test_case)]
    fn snapshot_reflects_counter_deltas_and_recent_events() {
        let runtime = create_runtime().expect("test runtime allocation");
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
        assert!(after.rx_packets >= before.rx_packets + 1);
        assert!(after.tx_packets >= before.tx_packets + 1);
        assert!(after.rx_bytes >= before.rx_bytes + 64);
        assert!(after.tx_bytes >= before.tx_bytes + 32);
        assert!(after.drops >= before.drops + 1);
        assert!(after.errors >= before.errors + 1);
        assert!(
            after
                .recent_events
                .iter()
                .any(|e| e.message == "obs-snapshot-test-event")
        );
    }

    #[cfg_attr(test, test_case)]
    fn snapshot_keeps_runtime_observability_isolated() {
        let runtime_a = create_runtime().expect("runtime a allocation");
        let runtime_b = create_runtime().expect("runtime b allocation");

        let obs_a = observability_in(runtime_a);
        obs_a.counters().record_rx(128);
        obs_a
            .trace()
            .push(NetLayer::Driver, NetEventKind::Rx, "runtime-a-only-event");

        let snap_a = snapshot_in(runtime_a);
        let snap_b = snapshot_in(runtime_b);

        assert_eq!(snap_a.rx_packets, 1);
        assert_eq!(snap_a.rx_bytes, 128);
        assert!(
            snap_a
                .recent_events
                .iter()
                .any(|e| e.message == "runtime-a-only-event")
        );

        assert_eq!(snap_b.rx_packets, 0);
        assert_eq!(snap_b.rx_bytes, 0);
        assert!(
            snap_b
                .recent_events
                .iter()
                .all(|e| e.message != "runtime-a-only-event")
        );
    }

    #[cfg_attr(test, test_case)]
    fn snapshot_contains_registered_interface_entries() {
        let runtime = create_runtime().expect("test runtime allocation");
        manager::init_network_manager_in(runtime);
        assert!(
            manager::register_interface_in(
                runtime,
                "obs-snapshot-if",
                manager::PrimaryPreference::Auto,
            )
            .is_ok()
        );

        let snap = snapshot_in(runtime);
        assert!(
            snap.interfaces
                .iter()
                .any(|iface| iface.name == "obs-snapshot-if")
        );
    }
}
