use alloc::vec::Vec;

use crate::net::api::shell::{NetworkStatsSnapshot, get_network_stats};
use crate::net::obs::{NetSnapshot, NetTraceEvent, snapshot};

extern crate alloc;

pub fn network_snapshot() -> NetSnapshot {
    snapshot()
}

pub fn network_stats() -> Option<NetworkStatsSnapshot> {
    get_network_stats()
}

pub fn network_recent_events(limit: usize) -> Vec<NetTraceEvent> {
    let snap = snapshot();
    snap.recent_events.into_iter().take(limit).collect()
}
