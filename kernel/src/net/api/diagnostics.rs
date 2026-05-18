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

#[cfg(test)]
mod tests {
    use core::future::Future;
    use core::task::{Context, Poll};

    fn run_with_event_task<F>(future: F) -> F::Output
    where
        F: Future,
    {
        let runtime = crate::net::runtime::default_runtime();
        crate::net::runtime::command::reset_command_system_for_tests_in(runtime);
        let mut executor = crate::task::TestExecutor::new();
        executor.spawn(crate::task::Task::new(async {
            crate::net::runtime::command_loop::runtime_command_task_in(runtime).await;
        }));

        let waker = crate::net::l4::test_support::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future = core::pin::pin!(future);
        for _ in 0..100_000 {
            executor.drive_once_for_test();
            if let Poll::Ready(output) = Future::poll(future.as_mut(), &mut cx) {
                crate::net::runtime::command::reset_command_system_for_tests_in(runtime);
                return output;
            }
        }

        crate::net::runtime::command::reset_command_system_for_tests_in(runtime);
        panic!("network_recent_events test timed out")
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn recent_events_complete_with_event_task() {
        let events = run_with_event_task(super::network_recent_events_in(
            crate::net::runtime::default_runtime(),
            1,
        ));
        assert!(events.len() <= 1);
    }
}
