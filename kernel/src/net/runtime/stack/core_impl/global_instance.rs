use super::*;


/// Global network stack instance
pub(crate) static NETWORK_STACK: PoisonLock<Option<NetworkStack>> = PoisonLock::new(None);

/// Initialize the global network stack
pub fn init(config: NetworkConfig) {
    // Initialization-time best-effort recovery: use helper
    let mut stack = NETWORK_STACK.lock_for_init("[NET] Global Stack init");
    *stack = Some(NetworkStack::new(config));
}

/// Initialize with default configuration
pub fn init_default() {
    init(NetworkConfig::default());
}

/// Get the global network stack
pub fn stack() -> &'static PoisonLock<Option<NetworkStack>> {
    &NETWORK_STACK
}

/// Returns true when the global network stack has been initialized.
pub fn is_initialized() -> bool {
    match NETWORK_STACK.lock() {
        Ok(guard) => guard.is_some(),
        Err(_) => false,
    }
}

/// Process a received packet
pub fn receive(data: &[u8]) {
    use crate::net::datapath::mempool::alloc_packet;

    // Allocate PacketRef to bridge legacy driver to Zero-Copy stack
    if let Some(mut packet) = alloc_packet() {
        // Copy data (Bridge)
        let len = data.len().min(packet.capacity());
        packet.data_mut()[..len].copy_from_slice(&data[..len]);
        packet.set_len(len);

        // 非同期経路へオフロードして即時戻す（割り込み/ポーリングコンテキストでのロック取得を回避）
        crate::net::l4::endpoint::event::send_event_ignore(
            crate::net::l4::endpoint::event::NetworkEvent::IngressPacket { packet },
        );
    } else {
        // Drop packet due to OOM
        // Ideally record stats
    }
}

/// Process a batch of received packets
pub fn receive_batch(batch: PacketBatch) {
    // Offload each packet in the batch to the async event queue to avoid
    // taking the global stack lock in interrupt/polling contexts.
    for pkt in batch.into_iter() {
        crate::net::l4::endpoint::event::send_event_ignore(
            crate::net::l4::endpoint::event::NetworkEvent::IngressPacket { packet: pkt },
        );
    }
}

/// Send a UDP datagram (async, event-queue based)
///
/// イベントキュー経由で非同期に送信する。NETWORK_STACKロックを取得しないため、
/// あらゆるコンテキストから安全に呼び出せる。
pub fn send_udp(src_port: u16, dst_ip: Ipv4Address, dst_port: u16, data: &[u8]) -> bool {
    send_udp_async(src_port, dst_ip, dst_port, data, 64)
}

/// Send a UDP datagram via the async event queue (non-blocking).
///
/// Instead of synchronously acquiring the NETWORK_STACK lock, the send request
/// is posted to the `NetworkEventQueue` and processed by the `network_event_task`.
/// This avoids lock contention and potential deadlocks when called from async contexts.
///
/// ソースIPはスタックの設定IPアドレスを使用する。
/// DHCP等でソースIPを明示的に指定する場合は `send_udp_async_with_src` を使用すること。
pub fn send_udp_async(src_port: u16, dst_ip: Ipv4Address, dst_port: u16, data: &[u8], ttl: u8) -> bool {
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::RawUdpSend {
            src_port,
            src_ip: None,
            dst_ip: *dst_ip.as_bytes(),
            dst_port,
            data: Vec::from(data),
            ttl,
        },
    );
    true
}

/// Send a UDP datagram with explicit source IP via the async event queue.
///
/// RFC 2131 準拠: DHCP DISCOVER/初期REQUEST では src_ip = 0.0.0.0 を指定する。
/// リニューアルでは取得済みIPを指定する。
pub fn send_udp_async_with_src(src_ip: Ipv4Address, src_port: u16, dst_ip: Ipv4Address, dst_port: u16, data: &[u8], ttl: u8) -> bool {
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::RawUdpSend {
            src_port,
            src_ip: Some(*src_ip.as_bytes()),
            dst_ip: *dst_ip.as_bytes(),
            dst_port,
            data: Vec::from(data),
            ttl,
        },
    );
    true
}

/// Send a UDP datagram over IPv6 via the async event queue (non-blocking).
pub fn send_udp_v6_async(
    src_port: u16,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_port: u16,
    data: &[u8],
    ttl: u8,
) -> bool {
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::RawUdpV6Send {
            src_port,
            src_ip: src_ip.octets(),
            dst_ip: dst_ip.octets(),
            dst_port,
            data: Vec::from(data),
            ttl,
        },
    );
    true
}

/// Send a TCP segment (IPv4, async, event-queue based)
///
/// イベントキュー経由で非同期に送信する。NETWORK_STACKロックを取得しない。
pub fn send_tcp(src_ip: Ipv4Address, dst_ip: Ipv4Address, tcp_segment: &[u8]) -> bool {
    send_tcp_async(src_ip, dst_ip, tcp_segment)
}

/// Send a TCP segment (IPv4) via the async event queue (non-blocking).
pub fn send_tcp_async(src_ip: Ipv4Address, dst_ip: Ipv4Address, tcp_segment: &[u8]) -> bool {
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::RawTcpSend {
            src_ip: *src_ip.as_bytes(),
            dst_ip: *dst_ip.as_bytes(),
            segment: Vec::from(tcp_segment),
        },
    );
    true
}

/// Send a TCP segment over IPv6 via the async event queue (non-blocking).
pub fn send_tcp_v6_async(
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    tcp_segment: &[u8],
) -> bool {
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::RawTcpV6Send {
            src_ip: src_ip.octets(),
            dst_ip: dst_ip.octets(),
            segment: Vec::from(tcp_segment),
        },
    );
    true
}

/// Bind a UDP socket (async, event-queue based)
///
/// イベントキュー経由でbindを実行する。NETWORK_STACKロックを取得しない。
/// スタック初期化前は失敗を返す。
pub fn bind_udp(port: u16) -> Option<UdpEndpoint> {
    // イベントキュー経由の非同期bind
    // 同期コンテキストからは直接Futureをawaitできないため、
    // スタックが初期化済みならエンドポイントを作成してイベントキュー経由でbindする
    let endpoint = UdpEndpoint::new(port);
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::AsyncUdpBind {
            port,
            result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
            waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        },
    );
    Some(endpoint)
}

/// Process retransmission timeouts (async, event-queue based)
///
/// イベントキュー経由でタイムアウト処理をリクエストする。
/// NETWORK_STACKロックを取得しない。
pub fn process_timeouts(_current_time: u64) {
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::AsyncProcessTimeouts,
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
pub async fn async_timeout_task() {
    log::info!("[NET] async_timeout_task started (event-queue mode)");
    loop {
        // 100msごとにタイムアウトを処理
        crate::task::sleep_ms(100).await;

        // イベントキュー経由でタイムアウト処理をリクエスト
        // イベントハンドラ側でNETWORK_STACKロックを取得して処理するため、
        // asyncタスク内での同期ロック取得を回避
        crate::net::l4::endpoint::event::send_event_ignore(
            crate::net::l4::endpoint::event::NetworkEvent::AsyncProcessTimeouts,
        );
    }
}

/// Bind a UDP socket with an optional capability token (async, event-queue based)
pub fn bind_udp_with_token(port: u16, token: Option<u64>) -> Option<UdpEndpoint> {
    let endpoint = UdpEndpoint::new_with_token(port, token);
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::AsyncUdpBind {
            port,
            result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
            waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        },
    );
    Some(endpoint)
}

/// Apply IPv6 global address obtained via DHCPv6 (async, event-queue based)
pub fn apply_ipv6_global_address(addr: crate::net::l3::ipv6::Ipv6Address) {
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::AsyncApplyIpv6Address {
            addr: addr.octets(),
            result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
            waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        },
    );
}

/// Unbind a UDP socket (async, event-queue based)
pub fn unbind_udp(port: u16) {
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::AsyncUnbindUdp {
            port,
            result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
            waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        },
    );
}

/// Unbind a TCP connection (async, event-queue based)
pub fn unbind_tcp(local: TcpEndpointAddr, remote: TcpEndpointAddr) {
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::AsyncUnbindTcp {
            local,
            remote,
            result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
            waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        },
    );
}

/// Unbind a TCP listener (async, event-queue based)
pub fn unbind_tcp_listener(local: TcpEndpointAddr) {
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::AsyncUnbindTcpListener {
            local,
            result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
            waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        },
    );
}

/// Bind a TCP listener (sync, acquires NETWORK_STACK lock)
///
/// **非推奨 (deprecated)**: エグゼキュータ未起動時の同期コンテキストでのみ使用すること。
/// asyncコンテキストでは `bind_tcp_listener_async()` を使用すること。
///
/// # 完全非同期化
/// 以前はNETWORK_STACKのロックを直接取得していたが、イベントキュー経由の
/// 非同期パスに統一し、ロック競合を排除。ブートストラップ時のみIRQ無効化 +
/// 同期ドレインで処理する。
pub fn bind_tcp(addr: TcpEndpointAddr) -> Result<TcpListener, TcpError> {
    // イベントキュー経由でbindリクエストを送信（非同期パスと統一）
    let result_slot = alloc::sync::Arc::new(PoisonLock::new(None));
    let waker = alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new());
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::AsyncTcpBindListener {
            local: addr,
            result_slot: result_slot.clone(),
            waker: waker.clone(),
        },
    );
    // ブートストラップ互換: イベントキューを同期ドレインして処理
    // asyncエグゼキュータ未起動時はイベントがキューに滞留するため、
    // sync_process_network_events()で即時処理する
    crate::net::runtime::bridge::sync_process_network_events();

    // 結果スロットから結果を取得
    match result_slot.lock() {
        Ok(mut slot) => match slot.take() {
            Some(result) => result,
            None => {
                log::warn!("[NET] bind_tcp sync: result not yet available after drain");
                Err(TcpError::InvalidState)
            }
        },
        Err(_) => {
            log::error!("[NET] bind_tcp sync: result_slot poisoned");
            Err(TcpError::InvalidState)
        }
    }
}

// ============================================================================
// Multicast Group Management (Global API) - 完全非同期化
// ============================================================================

/// Join a multicast group (async, event-queue based)
///
/// イベントキュー経由でリクエストする。NETWORK_STACKロックを取得しない。
pub fn join_multicast_group(group: Ipv4Address) -> Result<(), IgmpError> {
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::AsyncMulticastJoin {
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
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::AsyncMulticastLeave {
            group: *group.as_bytes(),
            result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
            waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        },
    );
    Ok(())
}

// ============================================================================
// 非同期 bind/connect API（イベントキュー経由・ロック競合回避）
// ============================================================================

/// 非同期TCP bind Future
///
/// `NetworkEventQueue`経由でbindリクエストを送信し、
/// イベントハンドラ側でスタックロックを取得して処理する。
/// 呼び出し元でのロック競合を回避する。
pub struct TcpBindFuture {
    result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), crate::net::l4::endpoint::types::EndpointError>>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    addr: TcpEndpointAddr,
}

impl core::future::Future for TcpBindFuture {
    type Output = Result<(), crate::net::l4::endpoint::types::EndpointError>;

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        // 初回ポーリング時にイベントを送信
        if !self.sent {
            self.waker.register(cx.waker());
            let event = crate::net::l4::endpoint::event::NetworkEvent::AsyncTcpBind {
                local: self.addr,
                result_slot: self.result_slot.clone(),
                waker: self.waker.clone(),
            };
            if crate::net::l4::endpoint::event::send_event(event).is_err() {
                return core::task::Poll::Ready(Err(
                    crate::net::l4::endpoint::types::EndpointError::ResourceExhausted,
                ));
            }
            self.sent = true;
            return core::task::Poll::Pending;
        }

        // 結果を確認
        self.waker.register(cx.waker());
        if let Ok(slot) = self.result_slot.lock() {
            if let Some(ref result) = *slot {
                return core::task::Poll::Ready(result.clone());
            }
        }
        core::task::Poll::Pending
    }
}

/// 非同期TCP bind: イベントキュー経由でbindリクエストを送信
///
/// 同期版`bind_tcp()`と異なり、呼び出し元でNETWORK_STACKのロックを
/// 取得しないため、ネットワークイベントタスクと同時に動作するasyncタスクから
/// 安全に呼び出せる。
pub fn bind_tcp_async(addr: TcpEndpointAddr) -> TcpBindFuture {
    TcpBindFuture {
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        addr,
    }
}

/// 非同期UDP bind Future
pub struct UdpBindFuture {
    result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    port: u16,
}

impl core::future::Future for UdpBindFuture {
    type Output = bool;

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        if !self.sent {
            self.waker.register(cx.waker());
            let event = crate::net::l4::endpoint::event::NetworkEvent::AsyncUdpBind {
                port: self.port,
                result_slot: self.result_slot.clone(),
                waker: self.waker.clone(),
            };
            if crate::net::l4::endpoint::event::send_event(event).is_err() {
                return core::task::Poll::Ready(false);
            }
            self.sent = true;
            return core::task::Poll::Pending;
        }

        self.waker.register(cx.waker());
        if let Ok(slot) = self.result_slot.lock() {
            if let Some(result) = *slot {
                return core::task::Poll::Ready(result);
            }
        }
        core::task::Poll::Pending
    }
}

/// 非同期UDP bind: イベントキュー経由でbindリクエストを送信
///
/// 同期版`bind_udp()`と異なり、呼び出し元でNETWORK_STACKのロックを
/// 取得しないため、ネットワークイベントタスクと同時に動作するasyncタスクから
/// 安全に呼び出せる。
pub fn bind_udp_async(port: u16) -> UdpBindFuture {
    UdpBindFuture {
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        port,
    }
}

// ============================================================================
// 非同期 TCP connect API（イベントキュー経由・ロック競合回避）
// ============================================================================

/// 非同期TCP connect Future
///
/// `NetworkEventQueue`経由でconnectリクエストを送信し、
/// イベントハンドラ側でスタックロックを取得して処理する。
pub struct TcpConnectFuture {
    result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), crate::net::l4::endpoint::types::EndpointError>>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    local: TcpEndpointAddr,
    remote: TcpEndpointAddr,
}

impl core::future::Future for TcpConnectFuture {
    type Output = Result<(), crate::net::l4::endpoint::types::EndpointError>;

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        if !self.sent {
            self.waker.register(cx.waker());
            let event = crate::net::l4::endpoint::event::NetworkEvent::AsyncTcpConnect {
                local: self.local,
                remote: self.remote,
                result_slot: self.result_slot.clone(),
                waker: self.waker.clone(),
            };
            if crate::net::l4::endpoint::event::send_event(event).is_err() {
                return core::task::Poll::Ready(Err(
                    crate::net::l4::endpoint::types::EndpointError::ResourceExhausted,
                ));
            }
            self.sent = true;
            return core::task::Poll::Pending;
        }

        self.waker.register(cx.waker());
        if let Ok(slot) = self.result_slot.lock() {
            if let Some(ref result) = *slot {
                return core::task::Poll::Ready(result.clone());
            }
        }
        core::task::Poll::Pending
    }
}

/// 非同期TCP connect: イベントキュー経由でconnectリクエストを送信
///
/// 同期版`connect_tcp()`と異なり、呼び出し元でNETWORK_STACKのロックを
/// 取得しない。asyncタスクから安全に呼び出せる。
pub fn connect_tcp_async(local: TcpEndpointAddr, remote: TcpEndpointAddr) -> TcpConnectFuture {
    TcpConnectFuture {
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        local,
        remote,
    }
}

// ============================================================================
// 非同期 TCP connect（TcpStreamを返す完全非同期版）
// ============================================================================

/// 非同期TCP connect Future（TcpStreamを返す）
///
/// `connect_tcp_async()`と異なり、結果として`TcpStream`を返す。
/// `TcpStream::dial()`から使用される。
pub struct TcpConnectStreamFuture {
    result_slot: alloc::sync::Arc<PoisonLock<Option<Result<TcpStream, TcpError>>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    local: TcpEndpointAddr,
    remote: TcpEndpointAddr,
}

impl core::future::Future for TcpConnectStreamFuture {
    type Output = Result<TcpStream, TcpError>;

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        if !self.sent {
            self.waker.register(cx.waker());
            let event = crate::net::l4::endpoint::event::NetworkEvent::AsyncTcpConnectStream {
                local: self.local,
                remote: self.remote,
                result_slot: self.result_slot.clone(),
                waker: self.waker.clone(),
            };
            if crate::net::l4::endpoint::event::send_event(event).is_err() {
                return core::task::Poll::Ready(Err(TcpError::InvalidState));
            }
            self.sent = true;
            return core::task::Poll::Pending;
        }

        self.waker.register(cx.waker());
        if let Ok(mut slot) = self.result_slot.lock() {
            if let Some(result) = slot.take() {
                return core::task::Poll::Ready(result);
            }
        }
        core::task::Poll::Pending
    }
}

/// 非同期TCP connect（TcpStreamを返す完全非同期版）
///
/// イベントキュー経由でconnectリクエストを送信し、イベントハンドラ側で
/// スタックロックを取得してTcpStreamを作成する。
pub fn connect_tcp_stream_async(local: TcpEndpointAddr, remote: TcpEndpointAddr) -> TcpConnectStreamFuture {
    TcpConnectStreamFuture {
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
    result_slot: alloc::sync::Arc<PoisonLock<Option<Result<TcpListener, TcpError>>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    addr: TcpEndpointAddr,
}

impl core::future::Future for TcpBindListenerFuture {
    type Output = Result<TcpListener, TcpError>;

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        if !self.sent {
            self.waker.register(cx.waker());
            let event = crate::net::l4::endpoint::event::NetworkEvent::AsyncTcpBindListener {
                local: self.addr,
                result_slot: self.result_slot.clone(),
                waker: self.waker.clone(),
            };
            if crate::net::l4::endpoint::event::send_event(event).is_err() {
                return core::task::Poll::Ready(Err(TcpError::InvalidState));
            }
            self.sent = true;
            return core::task::Poll::Pending;
        }

        self.waker.register(cx.waker());
        if let Ok(mut slot) = self.result_slot.lock() {
            if let Some(result) = slot.take() {
                return core::task::Poll::Ready(result);
            }
        }
        core::task::Poll::Pending
    }
}

/// 非同期TCP bind（TcpListenerを返す完全非同期版）
pub fn bind_tcp_listener_async(addr: TcpEndpointAddr) -> TcpBindListenerFuture {
    TcpBindListenerFuture {
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        addr,
    }
}

/// 非同期TCP bind with token Future（TcpListenerを返す）
pub struct TcpBindListenerWithTokenFuture {
    result_slot: alloc::sync::Arc<PoisonLock<Option<Result<TcpListener, TcpError>>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    addr: TcpEndpointAddr,
    token: Option<u64>,
}

impl core::future::Future for TcpBindListenerWithTokenFuture {
    type Output = Result<TcpListener, TcpError>;

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        if !self.sent {
            self.waker.register(cx.waker());
            let event = crate::net::l4::endpoint::event::NetworkEvent::AsyncTcpBindListenerWithToken {
                local: self.addr,
                token: self.token,
                result_slot: self.result_slot.clone(),
                waker: self.waker.clone(),
            };
            if crate::net::l4::endpoint::event::send_event(event).is_err() {
                return core::task::Poll::Ready(Err(TcpError::InvalidState));
            }
            self.sent = true;
            return core::task::Poll::Pending;
        }

        self.waker.register(cx.waker());
        if let Ok(mut slot) = self.result_slot.lock() {
            if let Some(result) = slot.take() {
                return core::task::Poll::Ready(result);
            }
        }
        core::task::Poll::Pending
    }
}

/// 非同期TCP bind with token（TcpListenerを返す完全非同期版）
pub fn bind_tcp_listener_with_token_async(addr: TcpEndpointAddr, token: Option<u64>) -> TcpBindListenerWithTokenFuture {
    TcpBindListenerWithTokenFuture {
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
    result_slot: alloc::sync::Arc<PoisonLock<Option<Option<UdpEndpoint>>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    port: u16,
}

impl core::future::Future for UdpBindEndpointFuture {
    type Output = Option<UdpEndpoint>;

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        if !self.sent {
            self.waker.register(cx.waker());
            let event = crate::net::l4::endpoint::event::NetworkEvent::AsyncUdpBindEndpoint {
                port: self.port,
                result_slot: self.result_slot.clone(),
                waker: self.waker.clone(),
            };
            if crate::net::l4::endpoint::event::send_event(event).is_err() {
                return core::task::Poll::Ready(None);
            }
            self.sent = true;
            return core::task::Poll::Pending;
        }

        self.waker.register(cx.waker());
        if let Ok(mut slot) = self.result_slot.lock() {
            if let Some(result) = slot.take() {
                return core::task::Poll::Ready(result);
            }
        }
        core::task::Poll::Pending
    }
}

/// 非同期UDP bind（UdpEndpointを返す完全非同期版）
///
/// イベントキュー経由でbindリクエストを送信し、UdpEndpointを返す。
/// asyncコンテキストからの同期ロック取得を完全に回避する。
pub fn bind_udp_endpoint_async(port: u16) -> UdpBindEndpointFuture {
    UdpBindEndpointFuture {
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        port,
    }
}

/// 非同期UDP bind with token Future（UdpEndpointを返す）
pub struct UdpBindEndpointWithTokenFuture {
    result_slot: alloc::sync::Arc<PoisonLock<Option<Option<UdpEndpoint>>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    port: u16,
    token: Option<u64>,
}

impl core::future::Future for UdpBindEndpointWithTokenFuture {
    type Output = Option<UdpEndpoint>;

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        if !self.sent {
            self.waker.register(cx.waker());
            let event = crate::net::l4::endpoint::event::NetworkEvent::AsyncUdpBindEndpointWithToken {
                port: self.port,
                token: self.token,
                result_slot: self.result_slot.clone(),
                waker: self.waker.clone(),
            };
            if crate::net::l4::endpoint::event::send_event(event).is_err() {
                return core::task::Poll::Ready(None);
            }
            self.sent = true;
            return core::task::Poll::Pending;
        }

        self.waker.register(cx.waker());
        if let Ok(mut slot) = self.result_slot.lock() {
            if let Some(result) = slot.take() {
                return core::task::Poll::Ready(result);
            }
        }
        core::task::Poll::Pending
    }
}

/// 非同期UDP bind with token（UdpEndpointを返す完全非同期版）
pub fn bind_udp_endpoint_with_token_async(port: u16, token: Option<u64>) -> UdpBindEndpointWithTokenFuture {
    UdpBindEndpointWithTokenFuture {
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        port,
        token,
    }
}

// ============================================================================
// 非同期 Multicast API（イベントキュー経由・ロック競合回避）
// ============================================================================

/// 非同期マルチキャスト参加 Future
pub struct MulticastJoinFuture {
    result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    group: Ipv4Address,
}

impl core::future::Future for MulticastJoinFuture {
    type Output = bool;

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        if !self.sent {
            self.waker.register(cx.waker());
            let event = crate::net::l4::endpoint::event::NetworkEvent::AsyncMulticastJoin {
                group: *self.group.as_bytes(),
                result_slot: self.result_slot.clone(),
                waker: self.waker.clone(),
            };
            if crate::net::l4::endpoint::event::send_event(event).is_err() {
                return core::task::Poll::Ready(false);
            }
            self.sent = true;
            return core::task::Poll::Pending;
        }

        self.waker.register(cx.waker());
        if let Ok(slot) = self.result_slot.lock() {
            if let Some(result) = *slot {
                return core::task::Poll::Ready(result);
            }
        }
        core::task::Poll::Pending
    }
}

/// 非同期マルチキャスト離脱 Future
pub struct MulticastLeaveFuture {
    result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    group: Ipv4Address,
}

impl core::future::Future for MulticastLeaveFuture {
    type Output = bool;

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        if !self.sent {
            self.waker.register(cx.waker());
            let event = crate::net::l4::endpoint::event::NetworkEvent::AsyncMulticastLeave {
                group: *self.group.as_bytes(),
                result_slot: self.result_slot.clone(),
                waker: self.waker.clone(),
            };
            if crate::net::l4::endpoint::event::send_event(event).is_err() {
                return core::task::Poll::Ready(false);
            }
            self.sent = true;
            return core::task::Poll::Pending;
        }

        self.waker.register(cx.waker());
        if let Ok(slot) = self.result_slot.lock() {
            if let Some(result) = *slot {
                return core::task::Poll::Ready(result);
            }
        }
        core::task::Poll::Pending
    }
}

/// 非同期マルチキャスト参加: イベントキュー経由
///
/// 同期版`join_multicast_group()`と異なり、呼び出し元でロックを取得しない。
pub fn join_multicast_async(group: Ipv4Address) -> MulticastJoinFuture {
    MulticastJoinFuture {
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        group,
    }
}

/// 非同期マルチキャスト離脱: イベントキュー経由
///
/// 同期版`leave_multicast_group()`と異なり、呼び出し元でロックを取得しない。
pub fn leave_multicast_async(group: Ipv4Address) -> MulticastLeaveFuture {
    MulticastLeaveFuture {
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        group,
    }
}

// ============================================================================
// 非同期 unbind API（イベントキュー経由・ロック競合回避）
// ============================================================================

/// 汎用の非同期 bool 結果 Future（unbind等の fire-and-forget 操作用）
struct AsyncBoolFuture<F: FnOnce() -> crate::net::l4::endpoint::event::NetworkEvent> {
    result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    event_fn: Option<F>,
}

impl<F: FnOnce() -> crate::net::l4::endpoint::event::NetworkEvent + Unpin> core::future::Future for AsyncBoolFuture<F> {
    type Output = bool;

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        if !self.sent {
            self.waker.register(cx.waker());
            if let Some(f) = self.event_fn.take() {
                let event = f();
                if crate::net::l4::endpoint::event::send_event(event).is_err() {
                    return core::task::Poll::Ready(false);
                }
            }
            self.sent = true;
            return core::task::Poll::Pending;
        }

        self.waker.register(cx.waker());
        if let Ok(slot) = self.result_slot.lock() {
            if let Some(result) = *slot {
                return core::task::Poll::Ready(result);
            }
        }
        core::task::Poll::Pending
    }
}

/// 非同期UDP unbind Future
pub struct UnbindUdpFuture {
    result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    port: u16,
}

impl core::future::Future for UnbindUdpFuture {
    type Output = bool;

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        if !self.sent {
            self.waker.register(cx.waker());
            let event = crate::net::l4::endpoint::event::NetworkEvent::AsyncUnbindUdp {
                port: self.port,
                result_slot: self.result_slot.clone(),
                waker: self.waker.clone(),
            };
            if crate::net::l4::endpoint::event::send_event(event).is_err() {
                return core::task::Poll::Ready(false);
            }
            self.sent = true;
            return core::task::Poll::Pending;
        }

        self.waker.register(cx.waker());
        if let Ok(slot) = self.result_slot.lock() {
            if let Some(result) = *slot {
                return core::task::Poll::Ready(result);
            }
        }
        core::task::Poll::Pending
    }
}

/// 非同期UDP unbind: イベントキュー経由でunbindリクエストを送信
///
/// 同期版`unbind_udp()`と異なり、呼び出し元でNETWORK_STACKのロックを
/// 取得しないため、asyncタスクから安全に呼び出せる。
pub fn unbind_udp_async(port: u16) -> UnbindUdpFuture {
    UnbindUdpFuture {
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        port,
    }
}

/// 非同期TCP unbind Future
pub struct UnbindTcpFuture {
    result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    local: TcpEndpointAddr,
    remote: TcpEndpointAddr,
}

impl core::future::Future for UnbindTcpFuture {
    type Output = bool;

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        if !self.sent {
            self.waker.register(cx.waker());
            let event = crate::net::l4::endpoint::event::NetworkEvent::AsyncUnbindTcp {
                local: self.local,
                remote: self.remote,
                result_slot: self.result_slot.clone(),
                waker: self.waker.clone(),
            };
            if crate::net::l4::endpoint::event::send_event(event).is_err() {
                return core::task::Poll::Ready(false);
            }
            self.sent = true;
            return core::task::Poll::Pending;
        }

        self.waker.register(cx.waker());
        if let Ok(slot) = self.result_slot.lock() {
            if let Some(result) = *slot {
                return core::task::Poll::Ready(result);
            }
        }
        core::task::Poll::Pending
    }
}

/// 非同期TCP unbind: イベントキュー経由でunbindリクエストを送信
pub fn unbind_tcp_async(local: TcpEndpointAddr, remote: TcpEndpointAddr) -> UnbindTcpFuture {
    UnbindTcpFuture {
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        local,
        remote,
    }
}

/// 非同期TCPリスナー unbind Future
pub struct UnbindTcpListenerFuture {
    result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    local: TcpEndpointAddr,
}

impl core::future::Future for UnbindTcpListenerFuture {
    type Output = bool;

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        if !self.sent {
            self.waker.register(cx.waker());
            let event = crate::net::l4::endpoint::event::NetworkEvent::AsyncUnbindTcpListener {
                local: self.local,
                result_slot: self.result_slot.clone(),
                waker: self.waker.clone(),
            };
            if crate::net::l4::endpoint::event::send_event(event).is_err() {
                return core::task::Poll::Ready(false);
            }
            self.sent = true;
            return core::task::Poll::Pending;
        }

        self.waker.register(cx.waker());
        if let Ok(slot) = self.result_slot.lock() {
            if let Some(result) = *slot {
                return core::task::Poll::Ready(result);
            }
        }
        core::task::Poll::Pending
    }
}

/// 非同期TCPリスナー unbind: イベントキュー経由でunbindリクエストを送信
pub fn unbind_tcp_listener_async(local: TcpEndpointAddr) -> UnbindTcpListenerFuture {
    UnbindTcpListenerFuture {
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        local,
    }
}

// ============================================================================
// 非同期 bind with token API（イベントキュー経由・ロック競合回避）
// ============================================================================

/// 非同期TCP bind with token Future
pub struct TcpBindWithTokenFuture {
    result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), crate::net::l4::endpoint::types::EndpointError>>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    addr: TcpEndpointAddr,
    token: Option<u64>,
}

impl core::future::Future for TcpBindWithTokenFuture {
    type Output = Result<(), crate::net::l4::endpoint::types::EndpointError>;

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        if !self.sent {
            self.waker.register(cx.waker());
            let event = crate::net::l4::endpoint::event::NetworkEvent::AsyncTcpBindWithToken {
                local: self.addr,
                token: self.token,
                result_slot: self.result_slot.clone(),
                waker: self.waker.clone(),
            };
            if crate::net::l4::endpoint::event::send_event(event).is_err() {
                return core::task::Poll::Ready(Err(
                    crate::net::l4::endpoint::types::EndpointError::ResourceExhausted,
                ));
            }
            self.sent = true;
            return core::task::Poll::Pending;
        }

        self.waker.register(cx.waker());
        if let Ok(slot) = self.result_slot.lock() {
            if let Some(ref result) = *slot {
                return core::task::Poll::Ready(result.clone());
            }
        }
        core::task::Poll::Pending
    }
}

/// 非同期TCP bind with token: イベントキュー経由でbindリクエストを送信
pub fn bind_tcp_with_token_async(addr: TcpEndpointAddr, token: Option<u64>) -> TcpBindWithTokenFuture {
    TcpBindWithTokenFuture {
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        addr,
        token,
    }
}

/// 非同期UDP bind with token Future
pub struct UdpBindWithTokenFuture {
    result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    port: u16,
    token: Option<u64>,
}

impl core::future::Future for UdpBindWithTokenFuture {
    type Output = bool;

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        if !self.sent {
            self.waker.register(cx.waker());
            let event = crate::net::l4::endpoint::event::NetworkEvent::AsyncUdpBindWithToken {
                port: self.port,
                token: self.token,
                result_slot: self.result_slot.clone(),
                waker: self.waker.clone(),
            };
            if crate::net::l4::endpoint::event::send_event(event).is_err() {
                return core::task::Poll::Ready(false);
            }
            self.sent = true;
            return core::task::Poll::Pending;
        }

        self.waker.register(cx.waker());
        if let Ok(slot) = self.result_slot.lock() {
            if let Some(result) = *slot {
                return core::task::Poll::Ready(result);
            }
        }
        core::task::Poll::Pending
    }
}

/// 非同期UDP bind with token: イベントキュー経由でbindリクエストを送信
pub fn bind_udp_with_token_async(port: u16, token: Option<u64>) -> UdpBindWithTokenFuture {
    UdpBindWithTokenFuture {
        result_slot: alloc::sync::Arc::new(PoisonLock::new(None)),
        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        sent: false,
        port,
        token,
    }
}

// ============================================================================
// 非同期 IPv6アドレス適用 API
// ============================================================================

/// 非同期IPv6グローバルアドレス適用 Future
pub struct ApplyIpv6AddressFuture {
    result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    sent: bool,
    addr: crate::net::l3::ipv6::Ipv6Address,
}

impl core::future::Future for ApplyIpv6AddressFuture {
    type Output = bool;

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        if !self.sent {
            self.waker.register(cx.waker());
            let event = crate::net::l4::endpoint::event::NetworkEvent::AsyncApplyIpv6Address {
                addr: self.addr.octets(),
                result_slot: self.result_slot.clone(),
                waker: self.waker.clone(),
            };
            if crate::net::l4::endpoint::event::send_event(event).is_err() {
                return core::task::Poll::Ready(false);
            }
            self.sent = true;
            return core::task::Poll::Pending;
        }

        self.waker.register(cx.waker());
        if let Ok(slot) = self.result_slot.lock() {
            if let Some(result) = *slot {
                return core::task::Poll::Ready(result);
            }
        }
        core::task::Poll::Pending
    }
}

/// 非同期IPv6グローバルアドレス適用: イベントキュー経由
pub fn apply_ipv6_global_address_async(addr: crate::net::l3::ipv6::Ipv6Address) -> ApplyIpv6AddressFuture {
    ApplyIpv6AddressFuture {
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
pub fn send_udp_on_async(if_id: super::NetIfId, src_port: u16, dst_ip: Ipv4Address, dst_port: u16, data: &[u8]) -> bool {
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::RawUdpSendOn {
            if_id: if_id.0,
            src_port,
            dst_ip: *dst_ip.as_bytes(),
            dst_port,
            data: Vec::from(data),
            ttl: 64,
        },
    );
    true
}

/// インターフェース指定TCP送信（非同期版・イベントキュー経由）
pub fn send_tcp_on_async(_if_id: super::NetIfId, src_ip: Ipv4Address, dst_ip: Ipv4Address, tcp_segment: &[u8]) -> bool {
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::RawTcpSendOn {
            if_id: _if_id.0,
            src_ip: *src_ip.as_bytes(),
            dst_ip: *dst_ip.as_bytes(),
            segment: Vec::from(tcp_segment),
        },
    );
    true
}

/// インターフェース指定IPv6 UDP送信（非同期版・イベントキュー経由）
pub fn send_udp_v6_on_async(
    if_id: super::NetIfId,
    src_port: u16,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_port: u16,
    data: &[u8],
) -> bool {
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::RawUdpV6SendOn {
            if_id: if_id.0,
            src_port,
            src_ip: src_ip.octets(),
            dst_ip: dst_ip.octets(),
            dst_port,
            data: Vec::from(data),
            ttl: 64,
        },
    );
    true
}