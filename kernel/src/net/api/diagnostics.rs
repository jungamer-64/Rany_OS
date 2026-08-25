// ============================================================================
// kernel/src/net/api/diagnostics.rs - ネットワーク診断・DNS・スナップショット
// ============================================================================
//! ネットワーク診断スナップショット、最新イベント取得、簡易DNS解決。

use alloc::vec::Vec;

use crate::net::obs::{NetSnapshot, NetTraceEvent};
use crate::net::runtime::NetRuntimeHandle;

extern crate alloc;

// Removed: `dns_resolve()` — deprecated stub. Use `crate::net::services::dns` instead.

pub async fn network_snapshot_in(runtime: NetRuntimeHandle) -> NetSnapshot {
    let (reply, command_future) =
        crate::net::runtime::command::new_command_channel_in::<NetSnapshot>(runtime);
    let event = crate::net::runtime::command::RuntimeCommand::Control(
        crate::net::runtime::command::ControlCommand::GetNetworkSnapshot { reply },
    );
    let _ = crate::net::runtime::command::send_command_in(runtime, event).await;
    command_future.await
}

pub async fn network_recent_events_in(
    runtime: NetRuntimeHandle,
    limit: usize,
) -> Vec<NetTraceEvent> {
    let (reply, command_future) =
        crate::net::runtime::command::new_command_channel_in::<Vec<NetTraceEvent>>(runtime);
    let event = crate::net::runtime::command::RuntimeCommand::Control(
        crate::net::runtime::command::ControlCommand::GetNetworkRecentEvents { limit, reply },
    );
    let _ = crate::net::runtime::command::send_command_in(runtime, event).await;
    command_future.await
}
