use super::*;
use crate::net::l4::endpoint::event::{
    new_command_channel, new_detached_command_channel, poll_command_result,
};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::context::{default_runtime, default_runtime_context};

/// Initialize the global network stack
pub fn init(config: NetworkConfig) {
    init_in(default_runtime(), config);
}

/// Initialize a runtime-local network stack
pub fn init_in(runtime: NetRuntimeHandle, config: NetworkConfig) {
    // Initialization-time best-effort recovery: use helper
    let mut stack = stack_in(runtime).lock_for_init("[NET] Global Stack init");
    *stack = Some(NetworkStack::new(config));
}

/// Initialize with default configuration
pub fn init_default() {
    init(NetworkConfig::default());
}

/// Get the global network stack
pub fn stack() -> &'static PoisonLock<Option<NetworkStack>> {
    &default_runtime_context().stack
}

/// Get the runtime-local network stack
pub fn stack_in(runtime: NetRuntimeHandle) -> &'static PoisonLock<Option<NetworkStack>> {
    &runtime.context().stack
}

/// Process a batch of received packets on a specific runtime.
pub fn receive_batch_on_in(
    runtime: NetRuntimeHandle,
    if_id: Option<super::NetIfId>,
    batch: PacketBatch,
) {
    // Offload each packet in the batch to the async event queue to avoid
    // taking the global stack lock in interrupt/polling contexts.
    for pkt in batch.into_iter() {
        crate::net::l4::endpoint::event::enqueue_event_ignore_in(
            runtime,
            crate::net::l4::endpoint::event::NetworkEvent::IngressPacket { if_id, packet: pkt },
        );
    }
}

/// Send a UDP datagram (async, event-queue based)
///
/// イベントキュー経由で非同期に送信する。NETWORK_STACKロックを取得しないため、
/// あらゆるコンテキストから安全に呼び出せる。
pub async fn send_udp(
    src_port: u16,
    dst_ip: Ipv4Address,
    dst_port: u16,
    payload: kernel_api::resource::net::PacketPayload,
) -> Result<(), crate::net::l4::endpoint::types::EndpointError> {
    send_udp_in(default_runtime(), src_port, dst_ip, dst_port, payload).await
}

async fn send_udp_in(
    runtime: NetRuntimeHandle,
    src_port: u16,
    dst_ip: Ipv4Address,
    dst_port: u16,
    payload: kernel_api::resource::net::PacketPayload,
) -> Result<(), crate::net::l4::endpoint::types::EndpointError> {
    let (completion_id, completion_future) =
        crate::net::runtime::device::register_tx_completion_in(runtime);
    let (result_slot, waker, command_future) = new_command_channel();
    let event = crate::net::l4::endpoint::event::NetworkEvent::RawUdpSend {
        src_port,
        src_ip: None,
        dst_ip: *dst_ip.as_bytes(),
        dst_port,
        payload,
        ttl: 64,
        completion_id: Some(completion_id),
        result_slot,
        waker,
    };
    if crate::net::l4::endpoint::event::send_event_in(runtime, event)
        .await
        .is_err()
    {
        let _ = crate::net::runtime::device::complete_tx_request_in(
            runtime,
            completion_id,
            Err("network event queue full"),
        );
        return Err(crate::net::l4::endpoint::types::EndpointError::ResourceExhausted);
    }

    command_future.await?;
    completion_future
        .await
        .map_err(|_| crate::net::l4::endpoint::types::EndpointError::ResourceExhausted)
}

pub fn enqueue_udp_send_scoped_with_src_in(
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
    let (result_slot, waker) = new_detached_command_channel();
    crate::net::l4::endpoint::event::enqueue_event_ignore_in(
        runtime,
        crate::net::l4::endpoint::event::NetworkEvent::RawUdpSend {
            src_port,
            src_ip: Some(*src_ip.as_bytes()),
            dst_ip: *dst_ip.as_bytes(),
            dst_port,
            payload,
            ttl,
            completion_id: None,
            result_slot,
            waker,
        },
    );
    true
}

pub fn enqueue_udp_v6_send_scoped_in(
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
    let (result_slot, waker) = new_detached_command_channel();
    crate::net::l4::endpoint::event::enqueue_event_ignore_in(
        runtime,
        crate::net::l4::endpoint::event::NetworkEvent::RawUdpV6Send {
            src_port,
            src_ip: src_ip.octets(),
            dst_ip: dst_ip.octets(),
            dst_port,
            payload,
            ttl,
            completion_id: None,
            result_slot,
            waker,
        },
    );
    true
}

/// Send a TCP segment (IPv4, async, event-queue based)
///
/// イベントキュー経由で非同期に送信する。NETWORK_STACKロックを取得しない。
pub async fn send_tcp(
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    payload: kernel_api::resource::net::PacketPayload,
) -> Result<(), crate::net::l4::endpoint::types::EndpointError> {
    send_tcp_in(default_runtime(), src_ip, dst_ip, payload).await
}

async fn send_tcp_in(
    runtime: NetRuntimeHandle,
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    payload: kernel_api::resource::net::PacketPayload,
) -> Result<(), crate::net::l4::endpoint::types::EndpointError> {
    let (completion_id, completion_future) =
        crate::net::runtime::device::register_tx_completion_in(runtime);
    let (result_slot, waker, command_future) = new_command_channel();
    let event = crate::net::l4::endpoint::event::NetworkEvent::RawTcpSend {
        src_ip: *src_ip.as_bytes(),
        dst_ip: *dst_ip.as_bytes(),
        payload,
        completion_id: Some(completion_id),
        result_slot,
        waker,
    };
    if crate::net::l4::endpoint::event::send_event_in(runtime, event)
        .await
        .is_err()
    {
        let _ = crate::net::runtime::device::complete_tx_request_in(
            runtime,
            completion_id,
            Err("network event queue full"),
        );
        return Err(crate::net::l4::endpoint::types::EndpointError::ResourceExhausted);
    }

    command_future.await?;
    completion_future
        .await
        .map_err(|_| crate::net::l4::endpoint::types::EndpointError::ResourceExhausted)
}

pub fn enqueue_tcp_send_in(
    runtime: NetRuntimeHandle,
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    payload: kernel_api::resource::net::PacketPayload,
) -> bool {
    let (result_slot, waker) = new_detached_command_channel();
    crate::net::l4::endpoint::event::enqueue_event_ignore_in(
        runtime,
        crate::net::l4::endpoint::event::NetworkEvent::RawTcpSend {
            src_ip: *src_ip.as_bytes(),
            dst_ip: *dst_ip.as_bytes(),
            payload,
            completion_id: None,
            result_slot,
            waker,
        },
    );
    true
}

pub fn enqueue_tcp_v6_send_in(
    runtime: NetRuntimeHandle,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    payload: kernel_api::resource::net::PacketPayload,
) -> bool {
    let (result_slot, waker) = new_detached_command_channel();
    crate::net::l4::endpoint::event::enqueue_event_ignore_in(
        runtime,
        crate::net::l4::endpoint::event::NetworkEvent::RawTcpV6Send {
            src_ip: src_ip.octets(),
            dst_ip: dst_ip.octets(),
            payload,
            completion_id: None,
            result_slot,
            waker,
        },
    );
    true
}

/// 非同期タイムアウト処理タスク
///
/// 定期的に `NetworkEvent::ProcessTimeouts` を投入する常駐タスク。
/// TCPリトランスミッション、Keep-Alive、TIME_WAIT、ARP期限切れ等の
/// タイマー処理をイベントキュー経由で非同期コンテキストで実行する。
///
/// 以前の実装ではasyncループ内で直接`NETWORK_STACK.lock()`を取得していたが、
/// イベントキュー経由にすることで、イベントハンドラ側でスタックロックを
/// 取得して処理するため、ロック競合を回避できる。
pub async fn timeout_task() {
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
        crate::net::l4::endpoint::event::enqueue_event_ignore_in(
            runtime,
            crate::net::l4::endpoint::event::NetworkEvent::ProcessTimeouts,
        );
    }
}

// ============================================================================
// 非同期 Multicast API（イベントキュー経由・ロック競合回避）
// ============================================================================

/// 非同期マルチキャスト参加 Future
pub struct MulticastJoinFuture {
    runtime: NetRuntimeHandle,
    result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
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
            let mut enqueue = crate::net::l4::endpoint::event::send_event_in(
                self.runtime,
                crate::net::l4::endpoint::event::NetworkEvent::MulticastJoin {
                    group: *self.group.as_bytes(),
                    result_slot: self.result_slot.clone(),
                    waker: self.waker.clone(),
                },
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                core::task::Poll::Ready(Ok(())) => {
                    self.sent = true;
                }
                core::task::Poll::Ready(Err(_)) => return core::task::Poll::Ready(false),
                core::task::Poll::Pending => return core::task::Poll::Pending,
            }
        }

        poll_command_result(&self.result_slot, &self.waker, cx)
    }
}

/// 非同期マルチキャスト離脱 Future
pub struct MulticastLeaveFuture {
    runtime: NetRuntimeHandle,
    result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
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
            let mut enqueue = crate::net::l4::endpoint::event::send_event_in(
                self.runtime,
                crate::net::l4::endpoint::event::NetworkEvent::MulticastLeave {
                    group: *self.group.as_bytes(),
                    result_slot: self.result_slot.clone(),
                    waker: self.waker.clone(),
                },
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                core::task::Poll::Ready(Ok(())) => {
                    self.sent = true;
                }
                core::task::Poll::Ready(Err(_)) => return core::task::Poll::Ready(false),
                core::task::Poll::Pending => return core::task::Poll::Pending,
            }
        }

        poll_command_result(&self.result_slot, &self.waker, cx)
    }
}

pub(crate) fn join_multicast_in(
    runtime: NetRuntimeHandle,
    group: Ipv4Address,
) -> MulticastJoinFuture {
    MulticastJoinFuture {
        runtime,
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        group,
    }
}

pub(crate) fn leave_multicast_in(
    runtime: NetRuntimeHandle,
    group: Ipv4Address,
) -> MulticastLeaveFuture {
    MulticastLeaveFuture {
        runtime,
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        group,
    }
}

// ============================================================================
// 非同期 send_*_on API（インターフェース指定送信・イベントキュー経由）
// ============================================================================

fn enqueue_udp_send_on_with_ttl_in(
    runtime: NetRuntimeHandle,
    if_id: super::NetIfId,
    src_port: u16,
    dst_ip: Ipv4Address,
    dst_port: u16,
    payload: kernel_api::resource::net::PacketPayload,
    ttl: u8,
) -> bool {
    let (result_slot, waker) = new_detached_command_channel();
    crate::net::l4::endpoint::event::enqueue_event_ignore_in(
        runtime,
        crate::net::l4::endpoint::event::NetworkEvent::RawUdpSendOn {
            if_id: if_id.0,
            src_port,
            src_ip: None,
            dst_ip: *dst_ip.as_bytes(),
            dst_port,
            payload,
            ttl,
            completion_id: None,
            result_slot,
            waker,
        },
    );
    true
}

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
    let (result_slot, waker) = new_detached_command_channel();
    crate::net::l4::endpoint::event::enqueue_event_ignore_in(
        runtime,
        crate::net::l4::endpoint::event::NetworkEvent::RawUdpSendOn {
            if_id: if_id.0,
            src_port,
            src_ip: Some(*src_ip.as_bytes()),
            dst_ip: *dst_ip.as_bytes(),
            dst_port,
            payload,
            ttl,
            completion_id: None,
            result_slot,
            waker,
        },
    );
    true
}

pub(crate) fn enqueue_tcp_send_on_in(
    runtime: NetRuntimeHandle,
    if_id: super::NetIfId,
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    payload: kernel_api::resource::net::PacketPayload,
) -> bool {
    let (result_slot, waker) = new_detached_command_channel();
    crate::net::l4::endpoint::event::enqueue_event_ignore_in(
        runtime,
        crate::net::l4::endpoint::event::NetworkEvent::RawTcpSendOn {
            if_id: if_id.0,
            src_ip: *src_ip.as_bytes(),
            dst_ip: *dst_ip.as_bytes(),
            payload,
            completion_id: None,
            result_slot,
            waker,
        },
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
    let (result_slot, waker) = new_detached_command_channel();
    crate::net::l4::endpoint::event::enqueue_event_ignore_in(
        runtime,
        crate::net::l4::endpoint::event::NetworkEvent::RawUdpV6SendOn {
            if_id: if_id.0,
            src_port,
            src_ip: src_ip.octets(),
            dst_ip: dst_ip.octets(),
            dst_port,
            payload,
            ttl,
            completion_id: None,
            result_slot,
            waker,
        },
    );
    true
}

pub(crate) fn enqueue_tcp_v6_send_on_in(
    runtime: NetRuntimeHandle,
    if_id: super::NetIfId,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    payload: kernel_api::resource::net::PacketPayload,
) -> bool {
    let (result_slot, waker) = new_detached_command_channel();
    crate::net::l4::endpoint::event::enqueue_event_ignore_in(
        runtime,
        crate::net::l4::endpoint::event::NetworkEvent::RawTcpV6SendOn {
            if_id: if_id.0,
            src_ip: src_ip.octets(),
            dst_ip: dst_ip.octets(),
            payload,
            completion_id: None,
            result_slot,
            waker,
        },
    );
    true
}
