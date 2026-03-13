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
    let event =
        crate::net::l4::endpoint::event::NetworkEvent::GetNetworkSnapshot { result_slot, waker };
    let _ = crate::net::l4::endpoint::event::send_event(event).await;
    command_future.await
}

pub async fn network_recent_events(limit: usize) -> Vec<NetTraceEvent> {
    let (result_slot, waker, command_future) =
        crate::net::runtime::stack::new_command_channel::<Vec<NetTraceEvent>>();
    let event = crate::net::l4::endpoint::event::NetworkEvent::GetNetworkRecentEvents {
        limit,
        result_slot,
        waker,
    };
    let _ = crate::net::l4::endpoint::event::send_event(event).await;
    command_future.await
}

#[cfg(test)]
mod tests {
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn recent_events_complete_with_event_task() {
        let events = {
            crate::net::l4::endpoint::event::reset_event_system_for_tests();
            let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
            let completed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
            let mut executor = crate::task::TestExecutor::new();
            let result_slot_clone = result_slot.clone();
            let completed_clone = completed.clone();
            executor.spawn(crate::task::Task::new(async move {
                let output = super::network_recent_events(1).await;
                let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
                *slot = Some(output);
                completed_clone.store(true, core::sync::atomic::Ordering::Release);
            }));
            executor.spawn(crate::task::Task::new(async {
                crate::net::l4::endpoint::tcp_rx::network_event_task().await;
            }));

            let mut output = None;
            for _ in 0..100_000 {
                executor.drive_once_for_test();
                if completed.load(core::sync::atomic::Ordering::Acquire) {
                    output = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                    break;
                }
            }
            crate::net::l4::endpoint::event::reset_event_system_for_tests();
            output.expect("network_recent_events test timed out")
        };
        assert!(events.len() <= 1);
    }
}
