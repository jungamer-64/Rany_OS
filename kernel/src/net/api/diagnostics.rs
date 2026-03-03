// ============================================================================
// kernel/src/net/api/diagnostics.rs - ネットワーク診断・DNS・スナップショット
// ============================================================================
//! ネットワーク診断スナップショット、最新イベント取得、簡易DNS解決。

use alloc::string::String;
use alloc::vec::Vec;

use crate::net::obs::{NetSnapshot, NetTraceEvent, snapshot};

extern crate alloc;

pub fn dns_resolve(hostname: &str) -> Result<Vec<[u8; 4]>, String> {
    match hostname {
        "localhost" => Ok(alloc::vec![[127, 0, 0, 1]]),
        "gateway" | "router" => Ok(alloc::vec![[10, 0, 2, 2]]),
        _ => Err(String::from("DNS server not configured")),
    }
}

pub fn network_snapshot() -> NetSnapshot {
    snapshot()
}

pub fn network_recent_events(limit: usize) -> Vec<NetTraceEvent> {
    let snap = snapshot();
    snap.recent_events.into_iter().take(limit).collect()
}
