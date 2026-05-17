// ============================================================================
// kernel/src/net/runtime/stack/core_impl/global_instance.rs - ランタイム / スタック / コア実装 / グローバルインスタンス
// ============================================================================

use super::*;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::{
    CommandReplyTicket, new_detached_command_channel_in, poll_command_result,
};
use crate::net::runtime::context::default_runtime;

/// Initialize a runtime-local network stack
pub(crate) fn init_in(runtime: NetRuntimeHandle, config: NetworkConfig) {
    // Initialization-time best-effort recovery: use helper
    let mut stack = stack_in(runtime).lock_for_init("[NET] Global Stack init");
    *stack = Some(NetworkStack::new_in(runtime, config));
}

/// Get the runtime-local network stack
pub(crate) fn stack_in(runtime: NetRuntimeHandle) -> &'static PoisonLock<Option<NetworkStack>> {
    &runtime.context().stack
}

/// Process a batch of received packets on a specific runtime.
pub(crate) fn receive_batch_on_in(
    runtime: NetRuntimeHandle,
    if_id: Option<super::NetIfId>,
    batch: PacketBatch,
) {
    // Offload each packet in the batch to the async event queue to avoid
    // taking the global stack lock in interrupt/polling contexts.
    for pkt in batch.into_iter() {
        crate::net::runtime::command::enqueue_command_ignore_in(
            runtime,
            crate::net::runtime::command::RuntimeCommand::Ingress(
                crate::net::runtime::command::IngressCommand::Packet { if_id, packet: pkt },
            ),
        );
    }
}

pub(crate) fn enqueue_udp_send_scoped_with_src_in(
    runtime: NetRuntimeHandle,
    scope: crate::net::types::InterfaceScope,
    src_ip: Ipv4Address,
    src_port: u16,
    dst_ip: Ipv4Address,
    dst_port: u16,
    payload: kernel_api::resource::net::PacketPayload,
    ttl: u8,
) -> bool {
    if let Some(if_id) = scope.as_if_id() {
        return enqueue_udp_send_on_with_src_in(
            runtime, if_id, src_ip, src_port, dst_ip, dst_port, payload, ttl,
        );
    }
    let reply = new_detached_command_channel_in(runtime);
    crate::net::runtime::command::enqueue_command_ignore_in(
        runtime,
        crate::net::runtime::command::RuntimeCommand::Transport(
            crate::net::runtime::command::TransportCommand::RawUdpSend {
                src_port,
                src_ip: Some(*src_ip.as_bytes()),
                dst_ip: *dst_ip.as_bytes(),
                dst_port,
                payload,
                ttl,
                completion_id: None,
                reply,
            },
        ),
    );
    true
}

pub(crate) fn enqueue_udp_v6_send_scoped_in(
    runtime: NetRuntimeHandle,
    scope: crate::net::types::InterfaceScope,
    src_port: u16,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_port: u16,
    payload: kernel_api::resource::net::PacketPayload,
    ttl: u8,
) -> bool {
    if let Some(if_id) = scope.as_if_id() {
        return enqueue_udp_v6_send_on_in(
            runtime, if_id, src_port, src_ip, dst_ip, dst_port, payload, ttl,
        );
    }
    let reply = new_detached_command_channel_in(runtime);
    crate::net::runtime::command::enqueue_command_ignore_in(
        runtime,
        crate::net::runtime::command::RuntimeCommand::Transport(
            crate::net::runtime::command::TransportCommand::RawUdpV6Send {
                src_port,
                src_ip: src_ip.octets(),
                dst_ip: dst_ip.octets(),
                dst_port,
                payload,
                ttl,
                completion_id: None,
                reply,
            },
        ),
    );
    true
}

pub(crate) fn enqueue_tcp_send_in(
    runtime: NetRuntimeHandle,
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    payload: kernel_api::resource::net::PacketPayload,
    completion_id: Option<u64>,
) -> bool {
    let reply = new_detached_command_channel_in(runtime);
    crate::net::runtime::command::enqueue_command_ignore_in(
        runtime,
        crate::net::runtime::command::RuntimeCommand::Transport(
            crate::net::runtime::command::TransportCommand::RawTcpSend {
                src_ip: *src_ip.as_bytes(),
                dst_ip: *dst_ip.as_bytes(),
                payload,
                completion_id,
                reply,
            },
        ),
    );
    true
}

pub(crate) fn enqueue_tcp_v6_send_in(
    runtime: NetRuntimeHandle,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    payload: kernel_api::resource::net::PacketPayload,
    completion_id: Option<u64>,
) -> bool {
    let reply = new_detached_command_channel_in(runtime);
    crate::net::runtime::command::enqueue_command_ignore_in(
        runtime,
        crate::net::runtime::command::RuntimeCommand::Transport(
            crate::net::runtime::command::TransportCommand::RawTcpV6Send {
                src_ip: src_ip.octets(),
                dst_ip: dst_ip.octets(),
                payload,
                completion_id,
                reply,
            },
        ),
    );
    true
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
pub(crate) async fn timeout_task() {
    timeout_task_in(default_runtime()).await;
}

async fn timeout_task_in(runtime: NetRuntimeHandle) {
    log::info!(
        "[NET] timeout_task started on CPU {} (event-queue mode)",
        crate::cpu::try_current_id().unwrap_or(0)
    );
    log::info!("[NET][boot] timeout_task stage: registering first 100ms sleep");
    // LOOP_PROOF: mode=event; reason=Timeout task intentionally runs for system lifetime and sleeps between finite timeout-processing passes.;
    loop {
        // 100msごとにタイムアウトを処理
        crate::task::sleep_ms(100).await;

        // イベントキュー経由でタイムアウト処理をリクエスト
        // イベントハンドラ側でNETWORK_STACKロックを取得して処理するため、
        // asyncタスク内での同期ロック取得を回避
        crate::net::runtime::command::enqueue_command_ignore_in(
            runtime,
            crate::net::runtime::command::RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ProcessTimeouts,
            ),
        );
    }
}

// ============================================================================
// 非同期 Multicast API（イベントキュー経由・ロック競合回避）
// ============================================================================

/// 非同期マルチキャスト参加 Future
struct MulticastJoinFuture {
    runtime: NetRuntimeHandle,
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
    group: Ipv4Address,
) -> impl core::future::Future<Output = bool> {
    MulticastJoinFuture {
        runtime,
        reply: new_detached_command_channel_in(runtime),
        sent: false,
        group,
    }
}

pub(crate) fn leave_multicast_in(
    runtime: NetRuntimeHandle,
    group: Ipv4Address,
) -> impl core::future::Future<Output = bool> {
    MulticastLeaveFuture {
        runtime,
        reply: new_detached_command_channel_in(runtime),
        sent: false,
        group,
    }
}

// ============================================================================
// 非同期 send_*_on API（インターフェース指定送信・イベントキュー経由）
// ============================================================================

pub(crate) fn enqueue_udp_send_on_with_src_in(
    runtime: NetRuntimeHandle,
    if_id: super::NetIfId,
    src_ip: Ipv4Address,
    src_port: u16,
    dst_ip: Ipv4Address,
    dst_port: u16,
    payload: kernel_api::resource::net::PacketPayload,
    ttl: u8,
) -> bool {
    let reply = new_detached_command_channel_in(runtime);
    crate::net::runtime::command::enqueue_command_ignore_in(
        runtime,
        crate::net::runtime::command::RuntimeCommand::Transport(
            crate::net::runtime::command::TransportCommand::RawUdpSendOn {
                if_id: if_id.0,
                src_port,
                src_ip: Some(*src_ip.as_bytes()),
                dst_ip: *dst_ip.as_bytes(),
                dst_port,
                payload,
                ttl,
                completion_id: None,
                reply,
            },
        ),
    );
    true
}

pub(crate) fn enqueue_tcp_send_on_in(
    runtime: NetRuntimeHandle,
    if_id: super::NetIfId,
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    payload: kernel_api::resource::net::PacketPayload,
    completion_id: Option<u64>,
) -> bool {
    let reply = new_detached_command_channel_in(runtime);
    crate::net::runtime::command::enqueue_command_ignore_in(
        runtime,
        crate::net::runtime::command::RuntimeCommand::Transport(
            crate::net::runtime::command::TransportCommand::RawTcpSendOn {
                if_id: if_id.0,
                src_ip: *src_ip.as_bytes(),
                dst_ip: *dst_ip.as_bytes(),
                payload,
                completion_id,
                reply,
            },
        ),
    );
    true
}

fn enqueue_udp_v6_send_on_in(
    runtime: NetRuntimeHandle,
    if_id: super::NetIfId,
    src_port: u16,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_port: u16,
    payload: kernel_api::resource::net::PacketPayload,
    ttl: u8,
) -> bool {
    let reply = new_detached_command_channel_in(runtime);
    crate::net::runtime::command::enqueue_command_ignore_in(
        runtime,
        crate::net::runtime::command::RuntimeCommand::Transport(
            crate::net::runtime::command::TransportCommand::RawUdpV6SendOn {
                if_id: if_id.0,
                src_port,
                src_ip: src_ip.octets(),
                dst_ip: dst_ip.octets(),
                dst_port,
                payload,
                ttl,
                completion_id: None,
                reply,
            },
        ),
    );
    true
}

pub(crate) fn enqueue_tcp_v6_send_on_in(
    runtime: NetRuntimeHandle,
    if_id: super::NetIfId,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    payload: kernel_api::resource::net::PacketPayload,
    completion_id: Option<u64>,
) -> bool {
    let reply = new_detached_command_channel_in(runtime);
    crate::net::runtime::command::enqueue_command_ignore_in(
        runtime,
        crate::net::runtime::command::RuntimeCommand::Transport(
            crate::net::runtime::command::TransportCommand::RawTcpV6SendOn {
                if_id: if_id.0,
                src_ip: src_ip.octets(),
                dst_ip: dst_ip.octets(),
                payload,
                completion_id,
                reply,
            },
        ),
    );
    true
}
