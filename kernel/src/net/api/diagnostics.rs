// ============================================================================
// kernel/src/net/api/diagnostics.rs - ネットワーク診断・DNS・スナップショット
// ============================================================================
//! ネットワーク診断スナップショット、最新イベント取得、簡易DNS解決。

use alloc::vec::Vec;

use crate::net::obs::{NetSnapshot, NetTraceEvent, snapshot};

extern crate alloc;

// Removed: `dns_resolve()` — deprecated stub. Use `crate::net::services::dns` instead.

fn network_snapshot_sync() -> NetSnapshot {
    snapshot()
}

fn network_recent_events_sync(limit: usize) -> Vec<NetTraceEvent> {
    let snap = network_snapshot_sync();
    snap.recent_events.into_iter().take(limit).collect()
}

pub async fn network_snapshot() -> NetSnapshot {
    let (result_slot, waker, command_future) =
        crate::net::runtime::stack::new_command_channel::<NetSnapshot>();
    let event = crate::net::l4::endpoint::event::NetworkEvent::AsyncGetNetworkSnapshot {
        result_slot,
        waker,
    };
    if crate::net::l4::endpoint::event::send_event(event).is_err() {
        return network_snapshot_sync();
    }
    crate::net::runtime::stack::pump_network_events_if_needed();
    command_future.await
}

pub async fn network_recent_events(limit: usize) -> Vec<NetTraceEvent> {
    let (result_slot, waker, command_future) =
        crate::net::runtime::stack::new_command_channel::<Vec<NetTraceEvent>>();
    let event = crate::net::l4::endpoint::event::NetworkEvent::AsyncGetNetworkRecentEvents {
        limit,
        result_slot,
        waker,
    };
    if crate::net::l4::endpoint::event::send_event(event).is_err() {
        return network_recent_events_sync(limit);
    }
    crate::net::runtime::stack::pump_network_events_if_needed();
    command_future.await
}

#[cfg(test)]
mod tests {
    #[test]
    fn async_recent_events_completes_without_event_task() {
        let events = crate::task::block_on(super::network_recent_events(1));
        assert!(events.len() <= 1);
    }
}
