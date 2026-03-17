use super::*;
use crate::net::l4::endpoint::types::EndpointFd;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::context::{default_runtime, default_runtime_context};

pub(crate) struct CommandFuture<T> {
    result_slot: alloc::sync::Arc<PoisonLock<Option<T>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
}

impl<T> core::future::Future for CommandFuture<T> {
    type Output = T;

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        let this = self.get_mut();
        poll_command_result(&this.result_slot, &this.waker, cx)
    }
}

pub(crate) fn poll_command_result<T>(
    result_slot: &alloc::sync::Arc<PoisonLock<Option<T>>>,
    waker: &alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    cx: &mut core::task::Context<'_>,
) -> core::task::Poll<T> {
    if let Ok(mut slot) = result_slot.lock() {
        if let Some(result) = slot.take() {
            return core::task::Poll::Ready(result);
        }
    }
    waker.register(cx.waker());
    if let Ok(mut slot) = result_slot.lock() {
        if let Some(result) = slot.take() {
            return core::task::Poll::Ready(result);
        }
    }
    core::task::Poll::Pending
}

pub(crate) fn new_command_channel<T>() -> (
    alloc::sync::Arc<PoisonLock<Option<T>>>,
    alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    CommandFuture<T>,
) {
    let result_slot = alloc::sync::Arc::new(PoisonLock::new(None));
    let waker = alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new());
    let future = CommandFuture {
        result_slot: result_slot.clone(),
        waker: waker.clone(),
    };
    (result_slot, waker, future)
}

pub(crate) fn new_detached_command_channel<T>() -> (
    alloc::sync::Arc<PoisonLock<Option<T>>>,
    alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
) {
    let (result_slot, waker, _future) = new_command_channel();
    (result_slot, waker)
}

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

/// Returns true when the global network stack has been initialized.
pub fn is_initialized() -> bool {
    is_initialized_in(default_runtime())
}

/// Returns true when the runtime-local network stack has been initialized.
pub fn is_initialized_in(runtime: NetRuntimeHandle) -> bool {
    match stack_in(runtime).lock() {
        Ok(guard) => guard.is_some(),
        Err(_) => false,
    }
}

/// Process a received packet
pub fn receive(data: &[u8]) {
    receive_on_in(crate::net::runtime::default_runtime(), None, data);
}

/// Process a received packet and preserve the ingress interface when known.
pub fn receive_on(if_id: Option<super::NetIfId>, data: &[u8]) {
    receive_on_in(crate::net::runtime::default_runtime(), if_id, data);
}

/// Process a received packet on a specific runtime and preserve the ingress interface when known.
pub fn receive_on_in(runtime: NetRuntimeHandle, if_id: Option<super::NetIfId>, data: &[u8]) {
    use crate::net::datapath::mempool::alloc_packet;

    // Allocate PacketRef to bridge legacy driver to Zero-Copy stack
    if let Some(mut packet) = alloc_packet() {
        // Copy data (Bridge)
        let len = data.len().min(packet.capacity());
        packet.data_mut()[..len].copy_from_slice(&data[..len]);
        packet.set_len(len);

        // 非同期経路へオフロードして即時戻す（割り込み/ポーリングコンテキストでのロック取得を回避）
        crate::net::l4::endpoint::event::enqueue_event_ignore_in(
            runtime,
            crate::net::l4::endpoint::event::NetworkEvent::IngressPacket { if_id, packet },
        );
    } else {
        // Drop packet due to OOM
        // Ideally record stats
    }
}

/// Process a batch of received packets
pub fn receive_batch(batch: PacketBatch) {
    receive_batch_on_in(crate::net::runtime::default_runtime(), None, batch);
}

/// Process a batch of received packets and preserve the ingress interface when known.
pub fn receive_batch_on(if_id: Option<super::NetIfId>, batch: PacketBatch) {
    receive_batch_on_in(crate::net::runtime::default_runtime(), if_id, batch);
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
    data: &[u8],
) -> Result<(), crate::net::l4::endpoint::types::EndpointError> {
    send_udp_in(default_runtime(), src_port, dst_ip, dst_port, data).await
}

pub async fn send_udp_in(
    runtime: NetRuntimeHandle,
    src_port: u16,
    dst_ip: Ipv4Address,
    dst_port: u16,
    data: &[u8],
) -> Result<(), crate::net::l4::endpoint::types::EndpointError> {
    let (completion_id, completion_future) =
        crate::net::runtime::device::register_tx_completion_in(runtime);
    let (result_slot, waker, command_future) = new_command_channel();
    let event = crate::net::l4::endpoint::event::NetworkEvent::RawUdpSend {
        src_port,
        src_ip: None,
        dst_ip: *dst_ip.as_bytes(),
        dst_port,
        data: Vec::from(data),
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

/// Send a UDP datagram via the async event queue (non-blocking).
///
/// Instead of synchronously acquiring the NETWORK_STACK lock, the send request
/// is posted to the `NetworkEventQueue` and processed by the `network_event_task`.
/// This avoids lock contention and potential deadlocks when called from async contexts.
///
/// ソースIPはスタックの設定IPアドレスを使用する。
/// DHCP等でソースIPを明示的に指定する場合は `enqueue_udp_send_with_src` を使用すること。
pub fn enqueue_udp_send(
    src_port: u16,
    dst_ip: Ipv4Address,
    dst_port: u16,
    data: &[u8],
    ttl: u8,
) -> bool {
    enqueue_udp_send_scoped(
        crate::net::types::InterfaceScope::Any,
        src_port,
        dst_ip,
        dst_port,
        data,
        ttl,
    )
}

/// Send a UDP datagram via the async event queue with an explicit interface scope.
pub fn enqueue_udp_send_scoped(
    scope: crate::net::types::InterfaceScope,
    src_port: u16,
    dst_ip: Ipv4Address,
    dst_port: u16,
    data: &[u8],
    ttl: u8,
) -> bool {
    enqueue_udp_send_scoped_in(
        default_runtime(),
        scope,
        src_port,
        dst_ip,
        dst_port,
        data,
        ttl,
    )
}

pub fn enqueue_udp_send_scoped_in(
    runtime: NetRuntimeHandle,
    scope: crate::net::types::InterfaceScope,
    src_port: u16,
    dst_ip: Ipv4Address,
    dst_port: u16,
    data: &[u8],
    ttl: u8,
) -> bool {
    if let Some(if_id) = scope.as_if_id() {
        return enqueue_udp_send_on_with_ttl_in(
            runtime, if_id, src_port, dst_ip, dst_port, data, ttl,
        );
    }
    let (result_slot, waker) = new_detached_command_channel();
    crate::net::l4::endpoint::event::enqueue_event_ignore_in(
        runtime,
        crate::net::l4::endpoint::event::NetworkEvent::RawUdpSend {
            src_port,
            src_ip: None,
            dst_ip: *dst_ip.as_bytes(),
            dst_port,
            data: Vec::from(data),
            ttl,
            completion_id: None,
            result_slot,
            waker,
        },
    );
    true
}

/// Send a UDP datagram with explicit source IP via the async event queue.
///
/// RFC 2131 準拠: DHCP DISCOVER/初期REQUEST では src_ip = 0.0.0.0 を指定する。
/// リニューアルでは取得済みIPを指定する。
pub fn enqueue_udp_send_with_src(
    src_ip: Ipv4Address,
    src_port: u16,
    dst_ip: Ipv4Address,
    dst_port: u16,
    data: &[u8],
    ttl: u8,
) -> bool {
    enqueue_udp_send_scoped_with_src(
        crate::net::types::InterfaceScope::Any,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        data,
        ttl,
    )
}

/// Send a UDP datagram with explicit source IP and interface scope.
pub fn enqueue_udp_send_scoped_with_src(
    scope: crate::net::types::InterfaceScope,
    src_ip: Ipv4Address,
    src_port: u16,
    dst_ip: Ipv4Address,
    dst_port: u16,
    data: &[u8],
    ttl: u8,
) -> bool {
    enqueue_udp_send_scoped_with_src_in(
        default_runtime(),
        scope,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        data,
        ttl,
    )
}

pub fn enqueue_udp_send_scoped_with_src_in(
    runtime: NetRuntimeHandle,
    scope: crate::net::types::InterfaceScope,
    src_ip: Ipv4Address,
    src_port: u16,
    dst_ip: Ipv4Address,
    dst_port: u16,
    data: &[u8],
    ttl: u8,
) -> bool {
    if let Some(if_id) = scope.as_if_id() {
        return enqueue_udp_send_on_with_src_in(
            runtime, if_id, src_ip, src_port, dst_ip, dst_port, data, ttl,
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
            data: Vec::from(data),
            ttl,
            completion_id: None,
            result_slot,
            waker,
        },
    );
    true
}

/// Send a UDP datagram over IPv6 via the async event queue (non-blocking).
pub fn enqueue_udp_v6_send(
    src_port: u16,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_port: u16,
    data: &[u8],
    ttl: u8,
) -> bool {
    enqueue_udp_v6_send_scoped(
        crate::net::types::InterfaceScope::Any,
        src_port,
        src_ip,
        dst_ip,
        dst_port,
        data,
        ttl,
    )
}

/// Send a UDP datagram over IPv6 via the async event queue with an explicit scope.
pub fn enqueue_udp_v6_send_scoped(
    scope: crate::net::types::InterfaceScope,
    src_port: u16,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_port: u16,
    data: &[u8],
    ttl: u8,
) -> bool {
    enqueue_udp_v6_send_scoped_in(
        default_runtime(),
        scope,
        src_port,
        src_ip,
        dst_ip,
        dst_port,
        data,
        ttl,
    )
}

pub fn enqueue_udp_v6_send_scoped_in(
    runtime: NetRuntimeHandle,
    scope: crate::net::types::InterfaceScope,
    src_port: u16,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_port: u16,
    data: &[u8],
    ttl: u8,
) -> bool {
    if let Some(if_id) = scope.as_if_id() {
        return enqueue_udp_v6_send_on_in(
            runtime, if_id, src_port, src_ip, dst_ip, dst_port, data, ttl,
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
            data: Vec::from(data),
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
    tcp_segment: &[u8],
) -> Result<(), crate::net::l4::endpoint::types::EndpointError> {
    send_tcp_in(default_runtime(), src_ip, dst_ip, tcp_segment).await
}

pub async fn send_tcp_in(
    runtime: NetRuntimeHandle,
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    tcp_segment: &[u8],
) -> Result<(), crate::net::l4::endpoint::types::EndpointError> {
    let (completion_id, completion_future) =
        crate::net::runtime::device::register_tx_completion_in(runtime);
    let (result_slot, waker, command_future) = new_command_channel();
    let event = crate::net::l4::endpoint::event::NetworkEvent::RawTcpSend {
        src_ip: *src_ip.as_bytes(),
        dst_ip: *dst_ip.as_bytes(),
        segment: Vec::from(tcp_segment),
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

/// Send a TCP segment (IPv4) via the async event queue (non-blocking).
pub fn enqueue_tcp_send(src_ip: Ipv4Address, dst_ip: Ipv4Address, tcp_segment: &[u8]) -> bool {
    enqueue_tcp_send_in(default_runtime(), src_ip, dst_ip, tcp_segment)
}

pub fn enqueue_tcp_send_in(
    runtime: NetRuntimeHandle,
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    tcp_segment: &[u8],
) -> bool {
    let (result_slot, waker) = new_detached_command_channel();
    crate::net::l4::endpoint::event::enqueue_event_ignore_in(
        runtime,
        crate::net::l4::endpoint::event::NetworkEvent::RawTcpSend {
            src_ip: *src_ip.as_bytes(),
            dst_ip: *dst_ip.as_bytes(),
            segment: Vec::from(tcp_segment),
            completion_id: None,
            result_slot,
            waker,
        },
    );
    true
}

/// Send a TCP segment over IPv6 via the async event queue (non-blocking).
pub fn enqueue_tcp_v6_send(
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    tcp_segment: &[u8],
) -> bool {
    enqueue_tcp_v6_send_in(default_runtime(), src_ip, dst_ip, tcp_segment)
}

pub fn enqueue_tcp_v6_send_in(
    runtime: NetRuntimeHandle,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    tcp_segment: &[u8],
) -> bool {
    let (result_slot, waker) = new_detached_command_channel();
    crate::net::l4::endpoint::event::enqueue_event_ignore_in(
        runtime,
        crate::net::l4::endpoint::event::NetworkEvent::RawTcpV6Send {
            src_ip: src_ip.octets(),
            dst_ip: dst_ip.octets(),
            segment: Vec::from(tcp_segment),
            completion_id: None,
            result_slot,
            waker,
        },
    );
    true
}

/// Bind a UDP socket (async, event-queue based)
///
/// イベントキュー経由でbindを実行する。NETWORK_STACKロックを取得しない。
/// スタック初期化前は失敗を返す。
pub async fn bind_udp(port: u16) -> Option<UdpEndpoint> {
    bind_udp_scoped(crate::net::types::InterfaceScope::Any, port).await
}

/// Bind a UDP socket to an explicit interface scope.
pub async fn bind_udp_scoped(
    scope: crate::net::types::InterfaceScope,
    port: u16,
) -> Option<UdpEndpoint> {
    bind_udp_endpoint_scoped(scope, port).await
}

/// Process retransmission timeouts (async, event-queue based)
///
/// イベントキュー経由でタイムアウト処理をリクエストする。
/// NETWORK_STACKロックを取得しない。
pub fn process_timeouts(_current_time: u64) {
    process_timeouts_in(default_runtime(), _current_time);
}

pub fn process_timeouts_in(runtime: NetRuntimeHandle, _current_time: u64) {
    crate::net::l4::endpoint::event::enqueue_event_ignore_in(
        runtime,
        crate::net::l4::endpoint::event::NetworkEvent::ProcessTimeouts,
    );
}

/// 非同期タイムアウト処理タスク
///
/// 定期的に`process_timeouts()`を実行する常駐タスク。
/// TCPリトランスミッション、Keep-Alive、TIME_WAIT、ARP期限切れ等の
/// タイマー処理をイベントキュー経由で非同期コンテキストで実行する。
///
/// 以前の実装ではasyncループ内で直接`NETWORK_STACK.lock()`を取得していたが、
/// イベントキュー経由にすることで、イベントハンドラ側でスタックロックを
/// 取得して処理するため、ロック競合を回避できる。
pub async fn timeout_task() {
    timeout_task_in(default_runtime()).await;
}

pub async fn timeout_task_in(runtime: NetRuntimeHandle) {
    log::info!("[NET] timeout_task started (event-queue mode)");
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

/// Bind a UDP socket with an optional capability token (async, event-queue based)
pub async fn bind_udp_with_token(port: u16, token: Option<u64>) -> Option<UdpEndpoint> {
    bind_udp_with_token_scoped(crate::net::types::InterfaceScope::Any, port, token).await
}

/// Bind a UDP socket with a token and explicit interface scope.
pub async fn bind_udp_with_token_scoped(
    scope: crate::net::types::InterfaceScope,
    port: u16,
    token: Option<u64>,
) -> Option<UdpEndpoint> {
    bind_udp_endpoint_with_token_scoped(scope, port, token).await
}

/// Apply IPv6 global address obtained via DHCPv6 (async, event-queue based)
pub fn enqueue_apply_ipv6_global_address(addr: crate::net::l3::ipv6::Ipv6Address) {
    enqueue_apply_ipv6_global_address_in(default_runtime(), addr);
}

pub fn enqueue_apply_ipv6_global_address_in(
    runtime: NetRuntimeHandle,
    addr: crate::net::l3::ipv6::Ipv6Address,
) {
    crate::net::l4::endpoint::event::enqueue_event_ignore_in(
        runtime,
        crate::net::l4::endpoint::event::NetworkEvent::ApplyIpv6Address {
            addr: addr.octets(),
            result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
            waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        },
    );
}

/// Unbind a TCP connection (fire-and-forget, event-queue based)
pub fn enqueue_unbind_tcp(local: TcpEndpointAddr, remote: TcpEndpointAddr) {
    enqueue_unbind_tcp_in(default_runtime(), local, remote);
}

pub fn enqueue_unbind_tcp_in(
    runtime: NetRuntimeHandle,
    local: TcpEndpointAddr,
    remote: TcpEndpointAddr,
) {
    crate::net::l4::endpoint::event::enqueue_event_ignore_in(
        runtime,
        crate::net::l4::endpoint::event::NetworkEvent::UnbindTcp {
            local,
            remote,
            result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
            waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        },
    );
}

/// Unbind a TCP listener (fire-and-forget, event-queue based)
pub fn enqueue_unbind_tcp_listener(fd: EndpointFd) {
    enqueue_unbind_tcp_listener_in(default_runtime(), fd);
}

pub fn enqueue_unbind_tcp_listener_in(runtime: NetRuntimeHandle, fd: EndpointFd) {
    crate::net::l4::endpoint::event::enqueue_event_ignore_in(
        runtime,
        crate::net::l4::endpoint::event::NetworkEvent::UnbindTcpListener {
            fd,
            result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
            waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        },
    );
}

/// Bind a TCP listener (sync, acquires NETWORK_STACK lock)
///
/// **非推奨 (deprecated)**: エグゼキュータ未起動時の同期コンテキストでのみ使用すること。
/// asyncコンテキストでは `bind_tcp_listener()` を使用すること。
///
/// # 完全非同期化
/// 以前はNETWORK_STACKのロックを直接取得していたが、イベントキュー経由の
/// 非同期パスに統一し、ロック競合を排除。ブートストラップ時のみIRQ無効化 +
/// 同期ドレインで処理する。
#[cfg(any(test, feature = "qemu-test-export"))]
pub fn bind_tcp_sync(addr: TcpEndpointAddr) -> Result<TcpListener, TcpError> {
    bind_tcp_sync_in(default_runtime(), addr)
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub fn bind_tcp_sync_in(
    runtime: NetRuntimeHandle,
    addr: TcpEndpointAddr,
) -> Result<TcpListener, TcpError> {
    let _ = (runtime, addr);
    Err(TcpError::InvalidState)
}

// ============================================================================
// Multicast Group Management (Global API) - 完全非同期化
// ============================================================================

/// Join a multicast group (async, event-queue based)
///
/// イベントキュー経由でリクエストする。NETWORK_STACKロックを取得しない。
pub fn join_multicast_group(group: Ipv4Address) -> Result<(), IgmpError> {
    join_multicast_group_in(default_runtime(), group)
}

pub fn join_multicast_group_in(
    runtime: NetRuntimeHandle,
    group: Ipv4Address,
) -> Result<(), IgmpError> {
    crate::net::l4::endpoint::event::enqueue_event_ignore_in(
        runtime,
        crate::net::l4::endpoint::event::NetworkEvent::MulticastJoin {
            group: *group.as_bytes(),
            result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
            waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        },
    );
    Ok(())
}

/// Leave a multicast group (async, event-queue based)
///
/// イベントキュー経由でリクエストする。NETWORK_STACKロックを取得しない。
pub fn leave_multicast_group(group: Ipv4Address) -> Result<(), IgmpError> {
    leave_multicast_group_in(default_runtime(), group)
}

pub fn leave_multicast_group_in(
    runtime: NetRuntimeHandle,
    group: Ipv4Address,
) -> Result<(), IgmpError> {
    crate::net::l4::endpoint::event::enqueue_event_ignore_in(
        runtime,
        crate::net::l4::endpoint::event::NetworkEvent::MulticastLeave {
            group: *group.as_bytes(),
            result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
            waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        },
    );
    Ok(())
}

// ============================================================================
// 非同期 TCP connect（TcpStreamを返す完全非同期版）
// ============================================================================

/// 非同期TCP connect Future（TcpStreamを返す）
///
/// `connect_tcp()` と異なり、結果として `TcpStream` を返す。
/// `TcpStream::dial()`から使用される。
pub struct TcpConnectStreamFuture {
    runtime: NetRuntimeHandle,
    result_slot: alloc::sync::Arc<PoisonLock<Option<Result<TcpStream, TcpError>>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    local: TcpEndpointAddr,
    remote: TcpEndpointAddr,
}

impl core::future::Future for TcpConnectStreamFuture {
    type Output = Result<TcpStream, TcpError>;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        if !self.sent {
            let mut enqueue = crate::net::l4::endpoint::event::send_event_in(
                self.runtime,
                crate::net::l4::endpoint::event::NetworkEvent::TcpConnectStream {
                    local: self.local,
                    remote: self.remote,
                    result_slot: self.result_slot.clone(),
                    waker: self.waker.clone(),
                },
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                core::task::Poll::Ready(Ok(())) => {
                    self.sent = true;
                }
                core::task::Poll::Ready(Err(_)) => {
                    return core::task::Poll::Ready(Err(TcpError::InvalidState));
                }
                core::task::Poll::Pending => return core::task::Poll::Pending,
            }
        }

        poll_command_result(&self.result_slot, &self.waker, cx)
    }
}

/// 非同期TCP connect（TcpStreamを返す完全非同期版）
///
/// イベントキュー経由でconnectリクエストを送信し、イベントハンドラ側で
/// スタックロックを取得してTcpStreamを作成する。
pub fn connect_tcp_stream(
    local: TcpEndpointAddr,
    remote: TcpEndpointAddr,
) -> TcpConnectStreamFuture {
    connect_tcp_stream_in(default_runtime(), local, remote)
}

pub fn connect_tcp_stream_in(
    runtime: NetRuntimeHandle,
    local: TcpEndpointAddr,
    remote: TcpEndpointAddr,
) -> TcpConnectStreamFuture {
    TcpConnectStreamFuture {
        runtime,
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        local,
        remote,
    }
}

// ============================================================================
// 非同期 TCP bind（TcpListenerを返す完全非同期版）
// ============================================================================

/// 非同期TCP bind Future（TcpListenerを返す）
pub struct TcpBindListenerFuture {
    runtime: NetRuntimeHandle,
    result_slot: alloc::sync::Arc<PoisonLock<Option<Result<TcpListener, TcpError>>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    addr: TcpEndpointAddr,
}

impl core::future::Future for TcpBindListenerFuture {
    type Output = Result<TcpListener, TcpError>;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        if !self.sent {
            let mut enqueue = crate::net::l4::endpoint::event::send_event_in(
                self.runtime,
                crate::net::l4::endpoint::event::NetworkEvent::TcpBindListener {
                    local: self.addr,
                    result_slot: self.result_slot.clone(),
                    waker: self.waker.clone(),
                },
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                core::task::Poll::Ready(Ok(())) => {
                    self.sent = true;
                }
                core::task::Poll::Ready(Err(_)) => {
                    return core::task::Poll::Ready(Err(TcpError::InvalidState));
                }
                core::task::Poll::Pending => return core::task::Poll::Pending,
            }
        }

        poll_command_result(&self.result_slot, &self.waker, cx)
    }
}

/// 非同期TCP bind（TcpListenerを返す完全非同期版）
pub fn bind_tcp_listener(addr: TcpEndpointAddr) -> TcpBindListenerFuture {
    bind_tcp_listener_in(default_runtime(), addr)
}

pub fn bind_tcp_listener_in(
    runtime: NetRuntimeHandle,
    addr: TcpEndpointAddr,
) -> TcpBindListenerFuture {
    TcpBindListenerFuture {
        runtime,
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        addr,
    }
}

/// 非同期TCP bind with token Future（TcpListenerを返す）
pub struct TcpBindListenerWithTokenFuture {
    runtime: NetRuntimeHandle,
    result_slot: alloc::sync::Arc<PoisonLock<Option<Result<TcpListener, TcpError>>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    addr: TcpEndpointAddr,
    token: Option<u64>,
}

impl core::future::Future for TcpBindListenerWithTokenFuture {
    type Output = Result<TcpListener, TcpError>;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        if !self.sent {
            let mut enqueue = crate::net::l4::endpoint::event::send_event_in(
                self.runtime,
                crate::net::l4::endpoint::event::NetworkEvent::TcpBindListenerWithToken {
                    local: self.addr,
                    token: self.token,
                    result_slot: self.result_slot.clone(),
                    waker: self.waker.clone(),
                },
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                core::task::Poll::Ready(Ok(())) => {
                    self.sent = true;
                }
                core::task::Poll::Ready(Err(_)) => {
                    return core::task::Poll::Ready(Err(TcpError::InvalidState));
                }
                core::task::Poll::Pending => return core::task::Poll::Pending,
            }
        }

        poll_command_result(&self.result_slot, &self.waker, cx)
    }
}

/// 非同期TCP bind with token（TcpListenerを返す完全非同期版）
pub fn bind_tcp_listener_with_token(
    addr: TcpEndpointAddr,
    token: Option<u64>,
) -> TcpBindListenerWithTokenFuture {
    bind_tcp_listener_with_token_in(default_runtime(), addr, token)
}

pub fn bind_tcp_listener_with_token_in(
    runtime: NetRuntimeHandle,
    addr: TcpEndpointAddr,
    token: Option<u64>,
) -> TcpBindListenerWithTokenFuture {
    TcpBindListenerWithTokenFuture {
        runtime,
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        addr,
        token,
    }
}

// ============================================================================
// 非同期 UDP bind（UdpEndpointを返す完全非同期版）
// ============================================================================

/// 非同期UDP bind Future（UdpEndpointを返す）
pub struct UdpBindEndpointFuture {
    runtime: NetRuntimeHandle,
    result_slot: alloc::sync::Arc<PoisonLock<Option<Option<UdpEndpoint>>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    port: u16,
    scope: crate::net::types::InterfaceScope,
}

impl core::future::Future for UdpBindEndpointFuture {
    type Output = Option<UdpEndpoint>;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        if !self.sent {
            let mut enqueue = crate::net::l4::endpoint::event::send_event_in(
                self.runtime,
                crate::net::l4::endpoint::event::NetworkEvent::UdpBindEndpoint {
                    port: self.port,
                    scope: self.scope,
                    result_slot: self.result_slot.clone(),
                    waker: self.waker.clone(),
                },
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                core::task::Poll::Ready(Ok(())) => {
                    self.sent = true;
                }
                core::task::Poll::Ready(Err(_)) => return core::task::Poll::Ready(None),
                core::task::Poll::Pending => return core::task::Poll::Pending,
            }
        }

        poll_command_result(&self.result_slot, &self.waker, cx)
    }
}

/// 非同期UDP bind（UdpEndpointを返す完全非同期版）
///
/// イベントキュー経由でbindリクエストを送信し、UdpEndpointを返す。
/// asyncコンテキストからの同期ロック取得を完全に回避する。
pub fn bind_udp_endpoint(port: u16) -> UdpBindEndpointFuture {
    bind_udp_endpoint_in(default_runtime(), port)
}

pub fn bind_udp_endpoint_in(runtime: NetRuntimeHandle, port: u16) -> UdpBindEndpointFuture {
    bind_udp_endpoint_scoped_in(runtime, crate::net::types::InterfaceScope::Any, port)
}

/// 非同期UDP bind（UdpEndpointを返す完全非同期版、scope 指定）
pub fn bind_udp_endpoint_scoped(
    scope: crate::net::types::InterfaceScope,
    port: u16,
) -> UdpBindEndpointFuture {
    bind_udp_endpoint_scoped_in(default_runtime(), scope, port)
}

pub fn bind_udp_endpoint_scoped_in(
    runtime: NetRuntimeHandle,
    scope: crate::net::types::InterfaceScope,
    port: u16,
) -> UdpBindEndpointFuture {
    UdpBindEndpointFuture {
        runtime,
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        port,
        scope,
    }
}

/// 非同期UDP bind with token Future（UdpEndpointを返す）
pub struct UdpBindEndpointWithTokenFuture {
    runtime: NetRuntimeHandle,
    result_slot: alloc::sync::Arc<PoisonLock<Option<Option<UdpEndpoint>>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    port: u16,
    token: Option<u64>,
    scope: crate::net::types::InterfaceScope,
}

impl core::future::Future for UdpBindEndpointWithTokenFuture {
    type Output = Option<UdpEndpoint>;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        if !self.sent {
            let mut enqueue = crate::net::l4::endpoint::event::send_event_in(
                self.runtime,
                crate::net::l4::endpoint::event::NetworkEvent::UdpBindEndpointWithToken {
                    port: self.port,
                    scope: self.scope,
                    token: self.token,
                    result_slot: self.result_slot.clone(),
                    waker: self.waker.clone(),
                },
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                core::task::Poll::Ready(Ok(())) => {
                    self.sent = true;
                }
                core::task::Poll::Ready(Err(_)) => return core::task::Poll::Ready(None),
                core::task::Poll::Pending => return core::task::Poll::Pending,
            }
        }

        poll_command_result(&self.result_slot, &self.waker, cx)
    }
}

/// 非同期UDP bind with token（UdpEndpointを返す完全非同期版）
pub fn bind_udp_endpoint_with_token(
    port: u16,
    token: Option<u64>,
) -> UdpBindEndpointWithTokenFuture {
    bind_udp_endpoint_with_token_in(default_runtime(), port, token)
}

pub fn bind_udp_endpoint_with_token_in(
    runtime: NetRuntimeHandle,
    port: u16,
    token: Option<u64>,
) -> UdpBindEndpointWithTokenFuture {
    bind_udp_endpoint_with_token_scoped_in(
        runtime,
        crate::net::types::InterfaceScope::Any,
        port,
        token,
    )
}

/// 非同期UDP bind with token（UdpEndpointを返す完全非同期版、scope 指定）
pub fn bind_udp_endpoint_with_token_scoped(
    scope: crate::net::types::InterfaceScope,
    port: u16,
    token: Option<u64>,
) -> UdpBindEndpointWithTokenFuture {
    bind_udp_endpoint_with_token_scoped_in(default_runtime(), scope, port, token)
}

pub fn bind_udp_endpoint_with_token_scoped_in(
    runtime: NetRuntimeHandle,
    scope: crate::net::types::InterfaceScope,
    port: u16,
    token: Option<u64>,
) -> UdpBindEndpointWithTokenFuture {
    UdpBindEndpointWithTokenFuture {
        runtime,
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        port,
        token,
        scope,
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

/// 非同期マルチキャスト参加: イベントキュー経由
///
/// 同期版`join_multicast_group()`と異なり、呼び出し元でロックを取得しない。
pub fn join_multicast(group: Ipv4Address) -> MulticastJoinFuture {
    join_multicast_in(default_runtime(), group)
}

pub fn join_multicast_in(runtime: NetRuntimeHandle, group: Ipv4Address) -> MulticastJoinFuture {
    MulticastJoinFuture {
        runtime,
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        group,
    }
}

/// 非同期マルチキャスト離脱: イベントキュー経由
///
/// 同期版`leave_multicast_group()`と異なり、呼び出し元でロックを取得しない。
pub fn leave_multicast(group: Ipv4Address) -> MulticastLeaveFuture {
    leave_multicast_in(default_runtime(), group)
}

pub fn leave_multicast_in(runtime: NetRuntimeHandle, group: Ipv4Address) -> MulticastLeaveFuture {
    MulticastLeaveFuture {
        runtime,
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        group,
    }
}

// ============================================================================
// 非同期 unbind API（イベントキュー経由・ロック競合回避）
// ============================================================================

/// 非同期UDP unbind Future
pub struct UnbindUdpFuture {
    runtime: NetRuntimeHandle,
    result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    port: u16,
    scope: crate::net::types::InterfaceScope,
}

impl core::future::Future for UnbindUdpFuture {
    type Output = bool;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        if !self.sent {
            let mut enqueue = crate::net::l4::endpoint::event::send_event_in(
                self.runtime,
                crate::net::l4::endpoint::event::NetworkEvent::UnbindUdp {
                    port: self.port,
                    scope: self.scope,
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

/// 非同期UDP unbind: イベントキュー経由でunbindリクエストを送信
///
/// 同期版`unbind_udp()`と異なり、呼び出し元でNETWORK_STACKのロックを
/// 取得しないため、asyncタスクから安全に呼び出せる。
pub fn unbind_udp(port: u16) -> UnbindUdpFuture {
    unbind_udp_in(default_runtime(), port)
}

pub fn unbind_udp_in(runtime: NetRuntimeHandle, port: u16) -> UnbindUdpFuture {
    unbind_udp_scoped_in(runtime, crate::net::types::InterfaceScope::Any, port)
}

/// 非同期UDP unbind: 明示的な interface scope 付き
pub fn unbind_udp_scoped(scope: crate::net::types::InterfaceScope, port: u16) -> UnbindUdpFuture {
    unbind_udp_scoped_in(default_runtime(), scope, port)
}

pub fn unbind_udp_scoped_in(
    runtime: NetRuntimeHandle,
    scope: crate::net::types::InterfaceScope,
    port: u16,
) -> UnbindUdpFuture {
    UnbindUdpFuture {
        runtime,
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        port,
        scope,
    }
}

/// 非同期TCP unbind Future
pub struct UnbindTcpFuture {
    runtime: NetRuntimeHandle,
    result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    local: TcpEndpointAddr,
    remote: TcpEndpointAddr,
}

impl core::future::Future for UnbindTcpFuture {
    type Output = bool;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        if !self.sent {
            let mut enqueue = crate::net::l4::endpoint::event::send_event_in(
                self.runtime,
                crate::net::l4::endpoint::event::NetworkEvent::UnbindTcp {
                    local: self.local,
                    remote: self.remote,
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

/// 非同期TCP unbind: イベントキュー経由でunbindリクエストを送信
pub fn unbind_tcp(local: TcpEndpointAddr, remote: TcpEndpointAddr) -> UnbindTcpFuture {
    unbind_tcp_in(default_runtime(), local, remote)
}

pub fn unbind_tcp_in(
    runtime: NetRuntimeHandle,
    local: TcpEndpointAddr,
    remote: TcpEndpointAddr,
) -> UnbindTcpFuture {
    UnbindTcpFuture {
        runtime,
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        local,
        remote,
    }
}

/// 非同期TCPリスナー unbind Future
pub struct UnbindTcpListenerFuture {
    runtime: NetRuntimeHandle,
    result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    fd: EndpointFd,
}

impl core::future::Future for UnbindTcpListenerFuture {
    type Output = bool;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        if !self.sent {
            let mut enqueue = crate::net::l4::endpoint::event::send_event_in(
                self.runtime,
                crate::net::l4::endpoint::event::NetworkEvent::UnbindTcpListener {
                    fd: self.fd,
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

/// 非同期TCPリスナー unbind: イベントキュー経由でunbindリクエストを送信
pub fn unbind_tcp_listener(fd: EndpointFd) -> UnbindTcpListenerFuture {
    unbind_tcp_listener_in(default_runtime(), fd)
}

pub fn unbind_tcp_listener_in(
    runtime: NetRuntimeHandle,
    fd: EndpointFd,
) -> UnbindTcpListenerFuture {
    UnbindTcpListenerFuture {
        runtime,
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        fd,
    }
}

// ============================================================================
// 非同期 IPv6アドレス適用 API
// ============================================================================

/// 非同期IPv6グローバルアドレス適用 Future
pub struct ApplyIpv6AddressFuture {
    runtime: NetRuntimeHandle,
    result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    addr: crate::net::l3::ipv6::Ipv6Address,
}

impl core::future::Future for ApplyIpv6AddressFuture {
    type Output = bool;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        if !self.sent {
            let mut enqueue = crate::net::l4::endpoint::event::send_event_in(
                self.runtime,
                crate::net::l4::endpoint::event::NetworkEvent::ApplyIpv6Address {
                    addr: self.addr.octets(),
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

/// 非同期IPv6グローバルアドレス適用: イベントキュー経由
pub fn apply_ipv6_global_address(
    addr: crate::net::l3::ipv6::Ipv6Address,
) -> ApplyIpv6AddressFuture {
    apply_ipv6_global_address_in(default_runtime(), addr)
}

pub fn apply_ipv6_global_address_in(
    runtime: NetRuntimeHandle,
    addr: crate::net::l3::ipv6::Ipv6Address,
) -> ApplyIpv6AddressFuture {
    ApplyIpv6AddressFuture {
        runtime,
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        addr,
    }
}

// ============================================================================
// 非同期 send_*_on API（インターフェース指定送信・イベントキュー経由）
// ============================================================================

/// インターフェース指定UDP送信（非同期版・イベントキュー経由）
///
/// 同期版`send_udp_on()`と異なり、呼び出し元でNETWORK_STACKのロックを
/// 取得しない。イベントキュー経由でハンドラ側にオフロードする。
pub fn enqueue_udp_send_on(
    if_id: super::NetIfId,
    src_port: u16,
    dst_ip: Ipv4Address,
    dst_port: u16,
    data: &[u8],
) -> bool {
    enqueue_udp_send_on_with_ttl_in(
        default_runtime(),
        if_id,
        src_port,
        dst_ip,
        dst_port,
        data,
        64,
    )
}

/// インターフェース指定UDP送信（非同期版・イベントキュー経由、明示 TTL）
pub fn enqueue_udp_send_on_with_ttl(
    if_id: super::NetIfId,
    src_port: u16,
    dst_ip: Ipv4Address,
    dst_port: u16,
    data: &[u8],
    ttl: u8,
) -> bool {
    enqueue_udp_send_on_with_ttl_in(
        default_runtime(),
        if_id,
        src_port,
        dst_ip,
        dst_port,
        data,
        ttl,
    )
}

pub fn enqueue_udp_send_on_with_ttl_in(
    runtime: NetRuntimeHandle,
    if_id: super::NetIfId,
    src_port: u16,
    dst_ip: Ipv4Address,
    dst_port: u16,
    data: &[u8],
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
            data: Vec::from(data),
            ttl,
            completion_id: None,
            result_slot,
            waker,
        },
    );
    true
}

pub fn enqueue_udp_send_on_with_src(
    if_id: super::NetIfId,
    src_ip: Ipv4Address,
    src_port: u16,
    dst_ip: Ipv4Address,
    dst_port: u16,
    data: &[u8],
    ttl: u8,
) -> bool {
    enqueue_udp_send_on_with_src_in(
        default_runtime(),
        if_id,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        data,
        ttl,
    )
}

pub fn enqueue_udp_send_on_with_src_in(
    runtime: NetRuntimeHandle,
    if_id: super::NetIfId,
    src_ip: Ipv4Address,
    src_port: u16,
    dst_ip: Ipv4Address,
    dst_port: u16,
    data: &[u8],
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
            data: Vec::from(data),
            ttl,
            completion_id: None,
            result_slot,
            waker,
        },
    );
    true
}

/// インターフェース指定TCP送信（非同期版・イベントキュー経由）
pub fn enqueue_tcp_send_on(
    _if_id: super::NetIfId,
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    tcp_segment: &[u8],
) -> bool {
    enqueue_tcp_send_on_in(default_runtime(), _if_id, src_ip, dst_ip, tcp_segment)
}

pub fn enqueue_tcp_send_on_in(
    runtime: NetRuntimeHandle,
    if_id: super::NetIfId,
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    tcp_segment: &[u8],
) -> bool {
    let (result_slot, waker) = new_detached_command_channel();
    crate::net::l4::endpoint::event::enqueue_event_ignore_in(
        runtime,
        crate::net::l4::endpoint::event::NetworkEvent::RawTcpSendOn {
            if_id: if_id.0,
            src_ip: *src_ip.as_bytes(),
            dst_ip: *dst_ip.as_bytes(),
            segment: Vec::from(tcp_segment),
            completion_id: None,
            result_slot,
            waker,
        },
    );
    true
}

/// インターフェース指定IPv6 UDP送信（非同期版・イベントキュー経由）
pub fn enqueue_udp_v6_send_on(
    if_id: super::NetIfId,
    src_port: u16,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_port: u16,
    data: &[u8],
    ttl: u8,
) -> bool {
    enqueue_udp_v6_send_on_in(
        default_runtime(),
        if_id,
        src_port,
        src_ip,
        dst_ip,
        dst_port,
        data,
        ttl,
    )
}

pub fn enqueue_udp_v6_send_on_in(
    runtime: NetRuntimeHandle,
    if_id: super::NetIfId,
    src_port: u16,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_port: u16,
    data: &[u8],
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
            data: Vec::from(data),
            ttl,
            completion_id: None,
            result_slot,
            waker,
        },
    );
    true
}

/// インターフェース指定IPv6 TCP送信（非同期版・イベントキュー経由）
pub fn enqueue_tcp_v6_send_on(
    if_id: super::NetIfId,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    tcp_segment: &[u8],
) -> bool {
    enqueue_tcp_v6_send_on_in(default_runtime(), if_id, src_ip, dst_ip, tcp_segment)
}

pub fn enqueue_tcp_v6_send_on_in(
    runtime: NetRuntimeHandle,
    if_id: super::NetIfId,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    tcp_segment: &[u8],
) -> bool {
    let (result_slot, waker) = new_detached_command_channel();
    crate::net::l4::endpoint::event::enqueue_event_ignore_in(
        runtime,
        crate::net::l4::endpoint::event::NetworkEvent::RawTcpV6SendOn {
            if_id: if_id.0,
            src_ip: src_ip.octets(),
            dst_ip: dst_ip.octets(),
            segment: Vec::from(tcp_segment),
            completion_id: None,
            result_slot,
            waker,
        },
    );
    true
}
