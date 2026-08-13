// ============================================================================
// kernel/src/net/runtime/stack/core_impl/global_instance.rs - ランタイム / スタック / コア実装 / グローバルインスタンス
// ============================================================================

use super::*;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::{
    CommandReplyTicket, new_detached_command_channel_in, poll_command_result,
};

/// Initialize a runtime-local network stack.
pub(crate) fn init_in(runtime: NetRuntimeHandle) {
    for stack_lock in &runtime.context().stacks {
        let mut stack = stack_lock.lock_for_init("[NET] Global Stack init");
        if stack.is_none() {
            *stack = Some(NetworkStack::new_in(runtime));
        }
    }
}

/// Get the runtime-local network stack
pub(crate) fn stack_in(runtime: NetRuntimeHandle) -> &'static PoisonLock<Option<NetworkStack>> {
    let cpu_id = crate::cpu::try_current_id().unwrap_or(0);
    &runtime.context().stacks[cpu_id]
}

/// 非同期タイムアウト処理タスク
///
/// 定期的に `RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::ProcessTimeouts)` を投入する常駐タスク。
/// TCPリトランスミッション、Keep-Alive、TIME_WAIT、ARP期限切れ等の
/// タイマー処理をイベントキュー経由で非同期コンテキストで実行する。
///
/// 以前の実装ではasyncループ内で直接`NETWORK_STACK.lock()`を取得していたが、
/// イベントキュー経由にすることで、イベントハンドラ側でスタックロックを
/// 取得して処理するため、ロック競合を回避できる。
pub(crate) async fn timeout_task_in(runtime: NetRuntimeHandle) {
    log::info!(
        "[NET] timeout_task started on CPU {} (event-queue mode)",
        crate::cpu::try_current_id().unwrap_or(0)
    );
    log::info!("[NET][boot] timeout_task stage: registering first 100ms sleep");
    // LOOP_PROOF: mode=event; reason=Timeout task intentionally runs for system lifetime and sleeps between finite timeout-processing passes.;
    loop {
        // 100msごとにタイムアウトを処理
        crate::task::sleep_ms(100).await;

        // 全 CPU コアのキューへローカルタイムアウト処理（100ms）をブロードキャスト
        crate::net::runtime::command::broadcast_command_in(runtime, || {
            crate::net::runtime::command::RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ProcessLocalTimeouts,
            )
        });

        // CPU 0 にのみグローバルタイムアウト処理を要求
        if let Some(queue) = runtime.context().command_queues.first() {
            let _ = queue.send(crate::net::runtime::command::RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ProcessGlobalTimeouts,
            ));
        }
    }
}

// ============================================================================
// 非同期 Multicast API（イベントキュー経由・ロック競合回避）
// ============================================================================

/// 非同期マルチキャスト参加 Future
struct MulticastJoinFuture {
    runtime: NetRuntimeHandle,
    if_id: super::NetIfId,
    reply: CommandReplyTicket<bool>,
    sent: bool,
    group: Ipv4Address,
}

impl core::future::Future for MulticastJoinFuture {
    type Output = bool;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        if !self.sent {
            let mut enqueue = crate::net::runtime::command::send_command_in(
                self.runtime,
                crate::net::runtime::command::RuntimeCommand::Control(
                    crate::net::runtime::command::ControlCommand::MulticastJoin {
                        if_id: self.if_id,
                        group: *self.group.as_bytes(),
                        reply: self.reply,
                    },
                ),
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                core::task::Poll::Ready(Ok(())) => {
                    self.sent = true;
                }
                core::task::Poll::Ready(Err(_)) => return core::task::Poll::Ready(false),
                core::task::Poll::Pending => return core::task::Poll::Pending,
            }
        }

        poll_command_result(self.reply, cx)
    }
}

/// 非同期マルチキャスト離脱 Future
struct MulticastLeaveFuture {
    runtime: NetRuntimeHandle,
    if_id: super::NetIfId,
    reply: CommandReplyTicket<bool>,
    sent: bool,
    group: Ipv4Address,
}

impl core::future::Future for MulticastLeaveFuture {
    type Output = bool;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        if !self.sent {
            let mut enqueue = crate::net::runtime::command::send_command_in(
                self.runtime,
                crate::net::runtime::command::RuntimeCommand::Control(
                    crate::net::runtime::command::ControlCommand::MulticastLeave {
                        if_id: self.if_id,
                        group: *self.group.as_bytes(),
                        reply: self.reply,
                    },
                ),
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                core::task::Poll::Ready(Ok(())) => {
                    self.sent = true;
                }
                core::task::Poll::Ready(Err(_)) => return core::task::Poll::Ready(false),
                core::task::Poll::Pending => return core::task::Poll::Pending,
            }
        }

        poll_command_result(self.reply, cx)
    }
}

pub(crate) fn join_multicast_in(
    runtime: NetRuntimeHandle,
    if_id: super::NetIfId,
    group: Ipv4Address,
) -> impl core::future::Future<Output = bool> {
    MulticastJoinFuture {
        runtime,
        if_id,
        reply: new_detached_command_channel_in(runtime),
        sent: false,
        group,
    }
}

pub(crate) fn leave_multicast_in(
    runtime: NetRuntimeHandle,
    if_id: super::NetIfId,
    group: Ipv4Address,
) -> impl core::future::Future<Output = bool> {
    MulticastLeaveFuture {
        runtime,
        if_id,
        reply: new_detached_command_channel_in(runtime),
        sent: false,
        group,
    }
}
