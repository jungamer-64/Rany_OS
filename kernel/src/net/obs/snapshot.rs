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
