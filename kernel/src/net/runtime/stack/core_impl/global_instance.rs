// ============================================================================
// kernel/src/net/runtime/stack/core_impl/global_instance.rs - ランタイム / スタック / コア実装 / グローバルインスタンス
// ============================================================================

use super::*;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::{
    CommandReplyTicket, RawIpv4Source, RawIpv4Transport, RawIpv6Transport, RawSendCommand,
    TransportCommand, new_detached_command_channel_in, poll_command_result,
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

pub(crate) fn register_interface_in(
    runtime: NetRuntimeHandle,
    id: NetIfId,
    config: NetworkConfig,
) -> bool {
    register_interface_with_optional_current_stack_in(runtime, id, config, None)
}

pub(crate) fn register_interface_with_current_stack_in(
    runtime: NetRuntimeHandle,
    id: NetIfId,
    config: NetworkConfig,
    current_stack: &mut NetworkStack,
) -> bool {
    register_interface_with_optional_current_stack_in(runtime, id, config, Some(current_stack))
}

fn register_interface_with_optional_current_stack_in(
    runtime: NetRuntimeHandle,
    id: NetIfId,
    config: NetworkConfig,
    current_stack: Option<&mut NetworkStack>,
) -> bool {
    let mut success = false;

    if let Some(stack) = current_stack {
        stack.register_interface_state(id, config);
        success = true;
    } else {
        // No current stack provided — we're in an early init path; try lock for
        // a best-effort synchronous update on the current core only.
        let current_core = crate::cpu::try_current_id().unwrap_or(0);
        if let Some(stack_lock) = runtime.context().stacks.get(current_core) {
            if let Ok(mut guard) = stack_lock.try_lock() {
                if let Some(stack) = &mut *guard {
                    stack.register_interface_state(id, config);
                    success = true;
                }
            }
        }
    }

    // Broadcast InterfaceConfigChanged to all Per-Core queues.
    // Each worker will deterministically call stack.register_interface_state()
    // without any cross-core lock acquisition.
    crate::net::runtime::command::broadcast_command_in(runtime, move || {
        crate::net::runtime::command::RuntimeCommand::Control(
            crate::net::runtime::command::ControlCommand::InterfaceConfigChanged {
                if_id: id,
                config,
            },
        )
    });

    success
}

pub(crate) fn unregister_interface_in(runtime: NetRuntimeHandle, id: NetIfId) {
    unregister_interface_with_optional_current_stack_in(runtime, id, None);
}

pub(crate) fn unregister_interface_with_current_stack_in(
    runtime: NetRuntimeHandle,
    id: NetIfId,
    current_stack: &mut NetworkStack,
) {
    unregister_interface_with_optional_current_stack_in(runtime, id, Some(current_stack));
}

fn unregister_interface_with_optional_current_stack_in(
    runtime: NetRuntimeHandle,
    id: NetIfId,
    current_stack: Option<&mut NetworkStack>,
) {
    if let Some(stack) = current_stack {
        stack.unregister_interface_state(id);
    } else {
        let current_core = crate::cpu::try_current_id().unwrap_or(0);
        if let Some(stack_lock) = runtime.context().stacks.get(current_core) {
            if let Ok(mut guard) = stack_lock.try_lock() {
                if let Some(stack) = &mut *guard {
                    stack.unregister_interface_state(id);
                }
            }
        }
    }

    crate::net::runtime::command::broadcast_command_in(runtime, move || {
        crate::net::runtime::command::RuntimeCommand::Control(
            crate::net::runtime::command::ControlCommand::InterfaceRemoved { if_id: id },
        )
    });
}

/// Get the runtime-local network stack
pub(crate) fn stack_in(runtime: NetRuntimeHandle) -> &'static PoisonLock<Option<NetworkStack>> {
    let cpu_id = crate::cpu::try_current_id().unwrap_or(0);
    &runtime.context().stacks[cpu_id]
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
        let _ = crate::net::runtime::command::try_enqueue_command_from_isr_in(
            runtime,
            crate::net::runtime::command::RuntimeCommand::Ingress(
                crate::net::runtime::command::IngressCommand::Packet { if_id, packet: pkt },
            ),
        );
    }
}

fn enqueue_raw_send_in(runtime: NetRuntimeHandle, command: RawSendCommand) -> bool {
    let reply = new_detached_command_channel_in(runtime);
    let _ = crate::net::runtime::command::try_enqueue_command_in(
        runtime,
        crate::net::runtime::command::RuntimeCommand::Transport(TransportCommand::RawSend {
            command,
            reply,
        }),
    );
    true
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
    enqueue_raw_send_in(
        runtime,
        RawSendCommand::Ipv4 {
            scope,
            dst: *dst_ip.as_bytes(),
            transport: RawIpv4Transport::Udp {
                src: RawIpv4Source::Addr(*src_ip.as_bytes()),
                src_port,
                dst_port,
                ttl,
            },
            payload,
            completion_id: None,
        },
    )
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
    enqueue_raw_send_in(
        runtime,
        RawSendCommand::Ipv6 {
            scope,
            dst: dst_ip.octets(),
            transport: RawIpv6Transport::Udp {
                src: src_ip.octets(),
                src_port,
                dst_port,
                ttl,
            },
            payload,
            completion_id: None,
        },
    )
}

pub(crate) fn enqueue_tcp_send_in(
    runtime: NetRuntimeHandle,
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    payload: kernel_api::resource::net::PacketPayload,
    completion_id: Option<u64>,
) -> bool {
    enqueue_raw_send_in(
        runtime,
        RawSendCommand::Ipv4 {
            scope: crate::net::types::InterfaceScope::Any,
            dst: *dst_ip.as_bytes(),
            transport: RawIpv4Transport::Tcp {
                src: *src_ip.as_bytes(),
            },
            payload,
            completion_id,
        },
    )
}

pub(crate) fn enqueue_tcp_v6_send_in(
    runtime: NetRuntimeHandle,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    payload: kernel_api::resource::net::PacketPayload,
    completion_id: Option<u64>,
) -> bool {
    enqueue_raw_send_in(
        runtime,
        RawSendCommand::Ipv6 {
            scope: crate::net::types::InterfaceScope::Any,
            dst: dst_ip.octets(),
            transport: RawIpv6Transport::Tcp {
                src: src_ip.octets(),
            },
            payload,
            completion_id,
        },
    )
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
    enqueue_raw_send_in(
        runtime,
        RawSendCommand::Ipv4 {
            scope: crate::net::types::InterfaceScope::Pinned(if_id),
            dst: *dst_ip.as_bytes(),
            transport: RawIpv4Transport::Udp {
                src: RawIpv4Source::Addr(*src_ip.as_bytes()),
                src_port,
                dst_port,
                ttl,
            },
            payload,
            completion_id: None,
        },
    )
}

pub(crate) fn enqueue_tcp_send_on_in(
    runtime: NetRuntimeHandle,
    if_id: super::NetIfId,
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    payload: kernel_api::resource::net::PacketPayload,
    completion_id: Option<u64>,
) -> bool {
    enqueue_raw_send_in(
        runtime,
        RawSendCommand::Ipv4 {
            scope: crate::net::types::InterfaceScope::Pinned(if_id),
            dst: *dst_ip.as_bytes(),
            transport: RawIpv4Transport::Tcp {
                src: *src_ip.as_bytes(),
            },
            payload,
            completion_id,
        },
    )
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
    enqueue_raw_send_in(
        runtime,
        RawSendCommand::Ipv6 {
            scope: crate::net::types::InterfaceScope::Pinned(if_id),
            dst: dst_ip.octets(),
            transport: RawIpv6Transport::Udp {
                src: src_ip.octets(),
                src_port,
                dst_port,
                ttl,
            },
            payload,
            completion_id: None,
        },
    )
}

pub(crate) fn enqueue_tcp_v6_send_on_in(
    runtime: NetRuntimeHandle,
    if_id: super::NetIfId,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    payload: kernel_api::resource::net::PacketPayload,
    completion_id: Option<u64>,
) -> bool {
    enqueue_raw_send_in(
        runtime,
        RawSendCommand::Ipv6 {
            scope: crate::net::types::InterfaceScope::Pinned(if_id),
            dst: dst_ip.octets(),
            transport: RawIpv6Transport::Tcp {
                src: src_ip.octets(),
            },
            payload,
            completion_id,
        },
    )
}
