// ============================================================================
// kernel/src/net/api/diagnostics.rs - ネットワーク診断・DNS・スナップショット
// ============================================================================
//! ネットワーク診断スナップショット、最新イベント取得、簡易DNS解決。

use alloc::string::String;
use alloc::vec::Vec;

use crate::net::obs::{NetSnapshot, NetTraceEvent, snapshot};

extern crate alloc;

// Removed: `dns_resolve()` — deprecated stub. Use `crate::net::services::dns` instead.

pub fn network_snapshot() -> NetSnapshot {
    snapshot()
}

pub fn network_recent_events(limit: usize) -> Vec<NetTraceEvent> {
    let snap = snapshot();
    snap.recent_events.into_iter().take(limit).collect()
}
