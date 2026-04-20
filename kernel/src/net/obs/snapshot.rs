// ============================================================================
// kernel/src/net/obs/snapshot.rs - obs / snapshot
// ============================================================================

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::net::obs::counters;
use crate::net::obs::trace::{NetTraceEvent, recent_events};
use crate::net::runtime::{bridge, default_runtime, manager};

extern crate alloc;

#[derive(Debug, Clone)]
pub struct InterfaceSnapshot {
    pub name: alloc::string::String,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

#[derive(Debug, Clone)]
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

fn collect_interface_snapshots() -> Vec<InterfaceSnapshot> {
    let runtime = default_runtime();
    let mut interfaces = Vec::new();
    let mut index_by_if = BTreeMap::new();

    if let Ok(ifaces) = manager::list_interfaces_in(runtime) {
        for iface in ifaces {
            let idx = interfaces.len();
            interfaces.push(InterfaceSnapshot {
                name: iface.name,
                rx_packets: 0,
                tx_packets: 0,
            });
            index_by_if.insert(iface.if_id, idx);
        }
    }

    for stats in bridge::list_stack_glue_stats() {
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
            .map(|iface| iface.name)
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

pub fn snapshot() -> NetSnapshot {
    let c = counters::global();
    NetSnapshot {
        rx_packets: c.rx_packets.load(core::sync::atomic::Ordering::Relaxed),
        tx_packets: c.tx_packets.load(core::sync::atomic::Ordering::Relaxed),
        rx_bytes: c.rx_bytes.load(core::sync::atomic::Ordering::Relaxed),
        tx_bytes: c.tx_bytes.load(core::sync::atomic::Ordering::Relaxed),
        drops: c.drops.load(core::sync::atomic::Ordering::Relaxed),
        errors: c.errors.load(core::sync::atomic::Ordering::Relaxed),
        interfaces: collect_interface_snapshots(),
        recent_events: recent_events(64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::obs::trace::{self, NetEventKind, NetLayer};

    #[cfg_attr(test, test_case)]
    fn snapshot_reflects_counter_deltas_and_recent_events() {
        let before = snapshot();

        counters::global().record_rx(64);
        counters::global().record_tx(32);
        counters::global().record_drop();
        counters::global().record_error();
        trace::push_event(
            NetLayer::Service,
            NetEventKind::Rx,
            "obs-snapshot-test-event",
        );

        let after = snapshot();
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
    fn snapshot_contains_registered_interface_entries() {
        let runtime = default_runtime();
        manager::init_network_manager_in(runtime);
        assert!(manager::register_interface_in(runtime, "obs-snapshot-if").is_ok());

        let snap = snapshot();
        assert!(
            snap.interfaces
                .iter()
                .any(|iface| iface.name == "obs-snapshot-if")
        );
    }
}
