// ============================================================================
// kernel/src/net/endpoint/futures.rs
// ============================================================================
//! # Async Futures - 非同期ソケット操作
//!
//! RecvFuture, SendFuture, AcceptFuture, RecvFromFuture

use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use super::endpoint_core::{OwnedEndpoint, Endpoint};
use super::types::{EndpointAddr, EndpointError, EndpointResult, EndpointState, EndpointType};

use crate::net::l4::tcp::TcpStream;
use crate::net::datapath::mempool::PacketRef;

/// 非同期受信Future
pub struct RecvFuture {
    endpoint: Endpoint,
    buffer: Vec<u8>,
}

impl RecvFuture {
    /// 新規作成
    pub fn new(endpoint: Endpoint, size: usize) -> Self {
        Self {
            endpoint,
            buffer: alloc::vec![0u8; size],
        }
    }
}

impl Future for RecvFuture {
    type Output = EndpointResult<Vec<u8>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        let mut inner = this.endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());

        // 状態チェック
        if !inner.state.can_receive() {
            return Poll::Ready(Err(EndpointError::NotConnected));
        }

        // データがあれば即座に返す（O(1)）
        if !inner.recv_buffer.is_empty() {
            let len = this.buffer.len().min(inner.recv_buffer.len());
            for i in 0..len {
                if let Some(byte) = inner.recv_buffer.pop_front() {
                    this.buffer[i] = byte;
                }
            }
            this.buffer.truncate(len);
            return Poll::Ready(Ok(core::mem::take(&mut this.buffer)));
        }

        // クローズ済みならEOF
        if matches!(inner.state, EndpointState::Closed | EndpointState::Closing) {
            return Poll::Ready(Ok(Vec::new()));
        }

        // Wakerを登録してPending
        inner.recv_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// 非同期送信Future
pub struct SendFuture {
    endpoint: Endpoint,
    data: Vec<u8>,
    offset: usize,
}

impl SendFuture {
    /// 新規作成
    pub fn new(endpoint: Endpoint, data: Vec<u8>) -> Self {
        Self {
            endpoint,
            data,
            offset: 0,
        }
    }
}

impl Future for SendFuture {
    type Output = EndpointResult<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        // Acquire inner to inspect/modify buffers
        let mut inner = this.endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());

        // 状態チェック
        if !inner.state.can_send() {
            return Poll::Ready(Err(EndpointError::NotConnected));
        }

        // 全データ送信済みなら完了
        if this.offset >= this.data.len() {
            return Poll::Ready(Ok(this.offset));
        }

        // バッファに空きがあれば書き込み
        let available = inner
            .send_buffer_limit
            .saturating_sub(inner.send_buffer.len());

        // Track whether we've written anything so we can notify the stack after dropping the lock
        let mut wrote = 0usize;
        if available > 0 {
            let remaining = &this.data[this.offset..];
            let to_send = remaining.len().min(available);
            inner
                .send_buffer
                .extend(remaining[..to_send].iter().copied());
            this.offset += to_send;
            wrote = to_send;

            // If not finished, register our waker so we get notified when space is available
            if this.offset < this.data.len() {
                inner.send_waker = Some(cx.waker().clone());
            }
        } else {
            // No space: register waker and return Pending
            inner.send_waker = Some(cx.waker().clone());
        }

        // Drop lock before notifying the event queue to avoid lock-ordering issues
        drop(inner);

        // If we wrote data, notify the network stack so it can attempt to send
        if wrote > 0 {
            let _ = super::event::send_event(super::event::NetworkEvent::DataReady {
                fd: this.endpoint.fd(),
                endpoint_type: this.endpoint.socket_type(),
            });

            // If we've written all the user's data, complete the future
            if this.offset >= this.data.len() {
                return Poll::Ready(Ok(this.offset));
            }
        }

        Poll::Pending
    }
}

/// 非同期UDP送信Future
pub struct SendToFuture {
    endpoint: Endpoint,
    data: Vec<u8>,
    addr: EndpointAddr,
}

impl SendToFuture {
    /// 新規作成
    pub fn new(endpoint: Endpoint, data: Vec<u8>, addr: EndpointAddr) -> Self {
        Self {
            endpoint,
            data,
            addr,
        }
    }
}

impl Future for SendToFuture {
    type Output = EndpointResult<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        // UDPは現在バッファリングせず即座にイベントキューへ
        match this.endpoint.send_to(&this.data, this.addr) {
            Ok(len) => Poll::Ready(Ok(len)),
            Err(EndpointError::ResourceExhausted) => {
                // イベントキューが満杯: Wakerを登録し TxAvailable 発生時に再ポーリングされるようにする
                this.endpoint.register_send_waker(cx.waker().clone());
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

/// 非同期接続受け入れFuture
pub struct AcceptFuture {
    endpoint: Endpoint,
}

impl AcceptFuture {
    /// 新規作成
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }
}

impl Future for AcceptFuture {
    type Output = EndpointResult<(OwnedEndpoint, EndpointAddr)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.endpoint.next_incoming() {
            Ok(( ep, addr)) => Poll::Ready(Ok((OwnedEndpoint::from_endpoint(ep), addr))),
            Err(EndpointError::Timeout) => {
                // Wakerを登録してPending
                self.endpoint.register_accept_waker(cx.waker().clone());
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

/// 非同期UDP受信Future
pub struct RecvFromFuture {
    endpoint: Endpoint,
    buffer: Vec<u8>,
}

impl RecvFromFuture {
    /// 新規作成
    pub fn new(endpoint: Endpoint, size: usize) -> Self {
        Self {
            endpoint,
            buffer: alloc::vec![0u8; size],
        }
    }
}

impl Future for RecvFromFuture {
    type Output = EndpointResult<(Vec<u8>, EndpointAddr)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        // バッファサイズを取得
        let buf_len = this.buffer.len();
        let mut temp_buf = alloc::vec![0u8; buf_len];

        match this.endpoint.recv_from(&mut temp_buf) {
            Ok((len, addr)) => {
                this.buffer.truncate(len);
                this.buffer[..len].copy_from_slice(&temp_buf[..len]);
                Poll::Ready(Ok((core::mem::take(&mut this.buffer), addr)))
            }
            Err(EndpointError::Timeout) => {
                // Wakerを登録してPending
                this.endpoint.register_recv_waker(cx.waker().clone());
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

/// 非同期ゼロコピー受信Future（TCP専用）
/// 成功時に `Some(PacketRef)` を返す。接続クローズ時は `None`。
pub struct RecvPacketFuture {
    stream: TcpStream,
}

impl RecvPacketFuture {
    /// 新規作成
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }
}

impl Future for RecvPacketFuture {
    type Output = Option<PacketRef>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        this.stream.poll_recv_zero_copy(cx)
    }
}

/// TCPゼロコピー用の小さなストリームラッパー（使いやすいヘルパ）
pub struct TcpPacketStream {
    stream: TcpStream,
}

impl TcpPacketStream {
    /// 新規作成
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    /// 次のパケットを受信するFutureを返す
    pub fn next_packet(&self) -> RecvPacketFuture {
        RecvPacketFuture::new(self.stream.clone())
    }
}

/// UDPゼロコピー用の小さなストリームラッパー（使いやすいヘルパ）
pub struct UdpPacketStream {
    ep: crate::net::l4::udp::UdpEndpoint,
}

impl UdpPacketStream {
    /// 新規作成
    pub fn new(ep: crate::net::l4::udp::UdpEndpoint) -> Self {
        Self { ep }
    }

    /// 次のパケットを受信するFutureを返す
    pub fn next_packet(&self) -> crate::net::l4::udp::UdpRecvFuture {
        self.ep.recv()
    }
}

// =====================================================
// 非同期拡張メソッド
// =====================================================

impl OwnedEndpoint {
    /// 非同期受信
    pub fn recv_async(&self, size: usize) -> Option<RecvFuture> {
        self.endpoint().map(|s| RecvFuture::new(s.clone(), size))
    }

    /// 非同期送信
    pub fn send_async(&self, data: Vec<u8>) -> Option<SendFuture> {
        self.endpoint().map(|s| SendFuture::new(s.clone(), data))
    }

    /// 非同期UDP送信
    pub fn send_to_async(&self, data: Vec<u8>, addr: EndpointAddr) -> Option<SendToFuture> {
        self.endpoint().map(|s| SendToFuture::new(s.clone(), data, addr))
    }

    /// 非同期接続受け入れ
    pub fn accept_async(&self) -> Option<AcceptFuture> {
        self.endpoint().map(|s| AcceptFuture::new(s.clone()))
    }

    /// 非同期UDP受信
    pub fn recv_from_async(&self, size: usize) -> Option<RecvFromFuture> {
        self.endpoint().map(|s| RecvFromFuture::new(s.clone(), size))
    }

    /// TCPのゼロコピーストリームを取得（`TcpStream`をクローンして返す）
    pub fn tcp_stream(&self) -> Option<TcpStream> {
        self.endpoint().and_then(|s| s.inner().lock().unwrap_or_else(|e| e.into_inner()).tcp().and_then(|t| t.stream.clone()))
    }

    /// 非同期ゼロコピー受信（TCP向け） - 成功すると `PacketRef` を返す
    pub fn recv_packet_async(&self) -> Option<RecvPacketFuture> {
        self.endpoint().and_then(|s| {
            s.inner()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .tcp()
                .and_then(|t| t.stream.clone())
                .map(|stream| RecvPacketFuture::new(stream))
        })
    }

    /// UDPのゼロコピー受信ヘルパ（内部UDPソケットが設定されている場合にのみ利用可能）
    pub fn recv_packet_from_udp(&self) -> Option<crate::net::l4::udp::UdpRecvFuture> {
        if self.endpoint().map(|s| s.socket_type()) != Some(super::types::EndpointType::Udp) {
            return None;
        }
        self.endpoint().and_then(|s| {
            // Clone the optional UdpEndpoint from the inner state and produce a future
            let opt = s.inner().lock().unwrap_or_else(|e| e.into_inner()).udp().and_then(|u| u.socket.clone());
            opt.map(|u| u.recv())
        })
    }

    /// TCP向けゼロコピー受信のストリームラッパーを取得（`TcpStream`をクローンして返す）
    pub fn tcp_packet_stream(&self) -> Option<TcpPacketStream> {
        self.tcp_stream().map(|s| TcpPacketStream::new(s))
    }

    /// UDP向けゼロコピー受信のストリームラッパーを取得（内部UDPソケットが設定されている場合）
    pub fn udp_packet_stream(&self) -> Option<UdpPacketStream> {
        self.endpoint().and_then(|s| s.inner().lock().unwrap_or_else(|e| e.into_inner()).udp().and_then(|u| u.socket.clone())).map(|u| UdpPacketStream::new(u))
    }
}

// ============================================================================
// 非同期 open_connection Future
// ============================================================================

/// 非同期接続開始Future
///
/// `Endpoint::open_connection_async()` から返される。
/// イベントキュー経由で接続イベントを送出し、接続完了をWakerで通知する。
pub struct OpenConnectionFuture {
    endpoint: Endpoint,
    remote: EndpointAddr,
    phase: OpenConnectionPhase,
}

enum OpenConnectionPhase {
    /// 初回poll: イベント送信
    Init,
    /// SYN送信済み: 接続完了待ち
    WaitingEstablished,
}

impl OpenConnectionFuture {
    /// 新規作成
    pub fn new(endpoint: Endpoint, remote: EndpointAddr) -> Self {
        Self {
            endpoint,
            remote,
            phase: OpenConnectionPhase::Init,
        }
    }
}

impl Future for OpenConnectionFuture {
    type Output = EndpointResult<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        match this.phase {
            OpenConnectionPhase::Init => {
                // ローカルアドレスを取得（未設定は0で自動割当）
                let local_addr;
                {
                    let mut inner = this.endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
                    if !inner.state.can_connect() {
                        return Poll::Ready(Err(EndpointError::AlreadyConnected));
                    }
                    local_addr = inner.local_addr.unwrap_or_else(|| {
                        EndpointAddr::new([0, 0, 0, 0], 0)
                    });
                    inner.remote_addr = Some(this.remote);
                    if let Err(e) = inner.transition_to(EndpointState::Connecting) {
                        return Poll::Ready(Err(e));
                    }
                    // Wakerを登録
                    inner.connect_waker = Some(cx.waker().clone());
                }

                // イベントキュー経由でConnect送信（ロック競合回避）
                if let Err(e) = super::event::send_event(super::event::NetworkEvent::Connect {
                    fd: this.endpoint.fd(),
                    local: local_addr,
                    remote: this.remote,
                }) {
                    return Poll::Ready(Err(e));
                }

                this.phase = OpenConnectionPhase::WaitingEstablished;
                Poll::Pending
            }
            OpenConnectionPhase::WaitingEstablished => {
                let inner = this.endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
                match inner.state {
                    EndpointState::Connected => Poll::Ready(Ok(())),
                    EndpointState::Closed | EndpointState::Closing => {
                        Poll::Ready(Err(EndpointError::ConnectionRefused))
                    }
                    EndpointState::Connecting => {
                        // まだ接続中: Wakerを再登録
                        drop(inner);
                        let mut inner = this.endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
                        inner.connect_waker = Some(cx.waker().clone());
                        Poll::Pending
                    }
                    _ => Poll::Ready(Err(EndpointError::InvalidStateTransition)),
                }
            }
        }
    }
}

// ============================================================================
// 非同期 start_listening Future
// ============================================================================

/// 非同期リッスン開始Future
///
/// `Endpoint::start_listening_async()` から返される。
/// イベントキュー経由でbind_tcpを実行し、Listenモードに遷移する。
pub struct StartListeningFuture {
    endpoint: Endpoint,
    backlog: u32,
    phase: StartListeningPhase,
}

enum StartListeningPhase {
    /// 初回poll: 非同期bindFutureを作成
    Init,
    /// bind完了待ち
    WaitingBind {
        bind_future: crate::net::runtime::stack::TcpBindListenerFuture,
    },
}

impl StartListeningFuture {
    /// 新規作成
    pub fn new(endpoint: Endpoint, backlog: u32) -> Self {
        Self {
            endpoint,
            backlog,
            phase: StartListeningPhase::Init,
        }
    }
}

impl Future for StartListeningFuture {
    type Output = EndpointResult<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        loop {
            match &mut this.phase {
                StartListeningPhase::Init => {
                    // ソケット状態チェック
                    let local_addr;
                    {
                        let inner = this.endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
                        if this.endpoint.socket_type() != EndpointType::Tcp {
                            return Poll::Ready(Err(EndpointError::InvalidArgument));
                        }
                        if !inner.state.can_listen() {
                            return Poll::Ready(Err(EndpointError::InvalidStateTransition));
                        }
                        local_addr = match inner.local_addr {
                            Some(addr) => addr,
                            None => return Poll::Ready(Err(EndpointError::InvalidArgument)),
                        };
                    }

                    // 非同期bind_tcp_listener_asyncを開始
                    let bind_future = crate::net::runtime::stack::bind_tcp_listener_async(local_addr);
                    this.phase = StartListeningPhase::WaitingBind { bind_future };
                    // fallthrough to poll bind_future
                }
                StartListeningPhase::WaitingBind { bind_future } => {
                    // bind Futureをポーリング
                    let pinned = unsafe { Pin::new_unchecked(bind_future) };
                    match pinned.poll(cx) {
                        Poll::Ready(Ok(listener)) => {
                            // bind成功: EndpointInnerにリスナーを設定
                            let mut inner = this.endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
                            inner.ensure_tcp().listener = Some(listener);
                            if let Err(e) = inner.transition_to(EndpointState::Listening) {
                                return Poll::Ready(Err(e));
                            }
                            let local_addr = inner.local_addr.unwrap();
                            drop(inner);

                            // Listenイベントを送信
                            let _ = super::event::send_event(super::event::NetworkEvent::Listen {
                                fd: this.endpoint.fd(),
                                local: local_addr,
                                backlog: this.backlog,
                            });

                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Err(e)) => {
                            return Poll::Ready(Err(EndpointError::from_tcp_error(e)));
                        }
                        Poll::Pending => {
                            return Poll::Pending;
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// 非同期 close Future
// ============================================================================

/// 非同期クローズFuture
///
/// `Endpoint::close_async()` から返される。
/// エンドポイントの状態をクリーンアップし、Closeイベントを送出する。
pub struct CloseAsyncFuture {
    endpoint: Endpoint,
    done: bool,
}

impl CloseAsyncFuture {
    /// 新規作成
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            done: false,
        }
    }
}

impl Future for CloseAsyncFuture {
    type Output = EndpointResult<()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        if this.done {
            return Poll::Ready(Ok(()));
        }

        // 内部状態クリーンアップ
        {
            let mut inner = this.endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());

            inner.clear_protocol();
            inner.recv_buffer.clear();
            inner.send_buffer.clear();

            // 待機中のタスクを起こす
            if let Some(waker) = inner.recv_waker.take() {
                waker.wake();
            }
            if let Some(waker) = inner.send_waker.take() {
                waker.wake();
            }
            if let Some(waker) = inner.connect_waker.take() {
                waker.wake();
            }

            let _ = inner.transition_to(EndpointState::Closed);
        }

        // イベントキュー経由でCloseを送出（ロック競合回避）
        super::event::send_event_ignore(super::event::NetworkEvent::Close {
            fd: this.endpoint.fd(),
        });

        this.done = true;
        Poll::Ready(Ok(()))
    }
}

// ============================================================================
// ICMP Echo 非同期Future
// ============================================================================

use alloc::collections::BTreeMap;
use crate::sync::PoisonLock;

/// ICMP Echo 応答の結果
#[derive(Debug, Clone, Copy)]
pub struct IcmpEchoResult {
    /// 応答送信元IP
    pub source: [u8; 4],
    /// シーケンス番号
    pub sequence: u16,
    /// ラウンドトリップタイム（マイクロ秒）
    pub rtt_us: u64,
}

/// ping待ちエントリ
struct PingWaiter {
    waker: Option<core::task::Waker>,
    result: Option<IcmpEchoResult>,
    start_tick: u64,
    timeout_us: u64,
}

/// ICMP Echo応答をトラッキングするグローバルレジストリ
///
/// キー: (target_ip_u32, sequence) のペアでping待ちを一意に識別
struct IcmpEchoRegistry {
    waiters: BTreeMap<(u32, u16), PingWaiter>,
}

impl IcmpEchoRegistry {
    const fn new() -> Self {
        Self {
            waiters: BTreeMap::new(),
        }
    }

    /// 新しいping待ちを登録
    fn register(&mut self, target: [u8; 4], sequence: u16, timeout_us: u64) {
        let key = (u32::from_be_bytes(target), sequence);
        let now = crate::task::timer::current_tick();
        self.waiters.insert(key, PingWaiter {
            waker: None,
            result: None,
            start_tick: now,
            timeout_us,
        });
    }

    /// wakerを設定
    fn set_waker(&mut self, target: [u8; 4], sequence: u16, waker: core::task::Waker) {
        let key = (u32::from_be_bytes(target), sequence);
        if let Some(entry) = self.waiters.get_mut(&key) {
            entry.waker = Some(waker);
        }
    }

    /// 応答を通知
    fn notify_reply(&mut self, source: [u8; 4], sequence: u16, rtt_us: u64) {
        let key = (u32::from_be_bytes(source), sequence);
        if let Some(entry) = self.waiters.get_mut(&key) {
            entry.result = Some(IcmpEchoResult {
                source,
                sequence,
                rtt_us,
            });
            if let Some(waker) = entry.waker.take() {
                waker.wake();
            }
        }
    }

    /// 結果をポーリング
    fn poll_result(&mut self, target: [u8; 4], sequence: u16) -> Poll<Result<IcmpEchoResult, EndpointError>> {
        let key = (u32::from_be_bytes(target), sequence);
        if let Some(entry) = self.waiters.get(&key) {
            if let Some(result) = entry.result {
                // 結果あり → 成功
                self.waiters.remove(&key);
                return Poll::Ready(Ok(result));
            }
            // タイムアウトチェック
            let now = crate::task::timer::current_tick();
            let elapsed = now.saturating_sub(entry.start_tick);
            if elapsed > entry.timeout_us {
                self.waiters.remove(&key);
                return Poll::Ready(Err(EndpointError::Timeout));
            }
            Poll::Pending
        } else {
            Poll::Ready(Err(EndpointError::NotFound))
        }
    }

    /// 期限切れエントリをクリーンアップ
    fn cleanup_expired(&mut self) {
        let now = crate::task::timer::current_tick();
        self.waiters.retain(|_key, entry| {
            let elapsed = now.saturating_sub(entry.start_tick);
            elapsed <= entry.timeout_us
        });
    }
}

/// グローバルICMP Echoレジストリ
static ICMP_ECHO_REGISTRY: PoisonLock<IcmpEchoRegistry> = PoisonLock::new(IcmpEchoRegistry::new());

/// ICMP Echo応答を通知する（スタックのICMP処理から呼ばれる）
pub fn notify_icmp_echo_reply(source: [u8; 4], sequence: u16, rtt_us: u64) {
    if let Ok(mut registry) = ICMP_ECHO_REGISTRY.lock() {
        registry.notify_reply(source, sequence, rtt_us);
    }
}

/// 期限切れのping待ちをクリーンアップ
pub fn cleanup_icmp_echo_waiters() {
    if let Ok(mut registry) = ICMP_ECHO_REGISTRY.lock() {
        registry.cleanup_expired();
    }
}

/// 非同期ICMP Echo Future
///
/// `IcmpEchoFuture::new(target, sequence)` で ICMP Echo Request を送信し、
/// `.await` で応答を待機する。タイムアウト付き。
///
/// # 使用例
/// ```ignore
/// let result = IcmpEchoFuture::new([8, 8, 8, 8], 1).await;
/// match result {
///     Ok(echo) => log::info!("ping RTT: {} us", echo.rtt_us),
///     Err(e) => log::warn!("ping failed: {:?}", e),
/// }
/// ```
pub struct IcmpEchoFuture {
    target: [u8; 4],
    sequence: u16,
    sent: bool,
    timeout_us: u64,
}

impl IcmpEchoFuture {
    /// デフォルトタイムアウト（5秒）でFutureを作成
    pub fn new(target: [u8; 4], sequence: u16) -> Self {
        Self {
            target,
            sequence,
            sent: false,
            timeout_us: 5_000_000, // 5秒
        }
    }

    /// カスタムタイムアウトでFutureを作成
    pub fn with_timeout(target: [u8; 4], sequence: u16, timeout_us: u64) -> Self {
        Self {
            target,
            sequence,
            sent: false,
            timeout_us,
        }
    }
}

impl Future for IcmpEchoFuture {
    type Output = Result<IcmpEchoResult, EndpointError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        // 初回poll: Echo Requestを送信してレジストリに登録
        if !this.sent {
            // レジストリに事前登録
            if let Ok(mut registry) = ICMP_ECHO_REGISTRY.lock() {
                registry.register(this.target, this.sequence, this.timeout_us);
            }

            // イベントキュー経由でICMP Echo Requestを送信
            crate::net::l4::endpoint::event::send_event_ignore(
                crate::net::l4::endpoint::event::NetworkEvent::IcmpEchoRequest {
                    target: this.target,
                    sequence: this.sequence,
                },
            );
            this.sent = true;
        }

        // 結果をポーリング
        if let Ok(mut registry) = ICMP_ECHO_REGISTRY.lock() {
            registry.set_waker(this.target, this.sequence, cx.waker().clone());
            registry.poll_result(this.target, this.sequence)
        } else {
            Poll::Ready(Err(EndpointError::Internal))
        }
    }
}


// ==========================
// Tests for SendFuture
// ==========================

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;
    use crate::net::l4::endpoint::manager::init_endpoint_manager;
    use crate::net::l4::endpoint::tcb::{tcb_table, TcpConnectionState, TcpControlBlockEntry};
    use crate::net::l4::endpoint::{EndpointAddr, EndpointState};
    use crate::net::l4::endpoint::{create_tcp_endpoint, create_udp_endpoint, NetworkEvent};
    use crate::net::runtime::stack;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, Waker};

    pub fn sendfuture_wakes_on_send_smoke() -> bool {
        init_endpoint_manager();

        stack::init_default();
        if let Ok(mut guard) = stack::stack().lock() {
            if let Some(ref mut s) = *guard {
                s.set_transmit_fn(|_if: Option<crate::net::runtime::manager::NetIfId>, _data: &[u8]| {
                    assert!(_if.is_none());
                    true
                });
            }
        }

        let sock = create_tcp_endpoint();
        let fd = sock.fd();
        let local = EndpointAddr::new([127, 0, 0, 1], 12345);
        let remote = EndpointAddr::new([127, 0, 0, 1], 80);
        if let Some(s) = sock.endpoint() {
            let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(local);
            inner.remote_addr = Some(remote);
            let _ = inner.transition_to(EndpointState::Bound);
            let _ = inner.transition_to(EndpointState::Connected);
        }

        let mut tcb = TcpControlBlockEntry::new(fd, local, remote);
        tcb.state = TcpConnectionState::Established;
        tcb_table().insert(tcb);

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        let expected = alloc::vec![1u8, 2u8, 3u8, 4u8];
        let Some(mut fut) = sock.send_async(expected.clone()) else {
            return false;
        };
        let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };

        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(Ok(n)) => n == expected.len(),
            Poll::Pending => {
                let handler = crate::net::l4::endpoint::handler::NetworkEventHandler::new();
                let _ = handler.handle_event(NetworkEvent::DataReady {
                    fd,
                    endpoint_type: crate::net::l4::endpoint::types::EndpointType::Tcp,
                });

                match pinned.as_mut().poll(&mut cx) {
                    Poll::Ready(Ok(n)) => n == expected.len(),
                    Poll::Pending => {
                        if let Some(s) = sock.endpoint() {
                            let inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
                            let staged: alloc::vec::Vec<u8> =
                                inner.send_buffer.iter().copied().collect();
                            staged == expected
                        } else {
                            false
                        }
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }

    pub fn recv_packet_zero_copy_via_owned_socket_smoke() -> bool {
        init_endpoint_manager();
        stack::init_default();

        let sock = create_tcp_endpoint();
        let local = EndpointAddr::new([127, 0, 0, 1], 12345);
        let remote = EndpointAddr::new([127, 0, 0, 1], 80);
        if let Some(s) = sock.endpoint() {
            let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(local);
            inner.remote_addr = Some(remote);
        }

        use alloc::sync::Arc;
        use crate::sync::PoisonLock;
        use crate::net::l4::tcp::{
            Ipv4Addr as TcpIpv4Addr, EndpointAddr as TcpEndpointAddr, TcpControlBlock,
            TcpStream,
        };

        let t_local = TcpEndpointAddr::new([127, 0, 0, 1], 12345);
        let t_remote = TcpEndpointAddr::new([127, 0, 0, 1], 80);

        let mut tcb = TcpControlBlock::new(t_local);
        tcb.set_remote_addr(t_remote);
        tcb.enter_established();
        let tcb_arc = Arc::new(PoisonLock::new(tcb));
        let stream = TcpStream { tcb: tcb_arc.clone() };

        if let Some(s) = sock.endpoint() {
            let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.ensure_tcp().stream = Some(stream.clone());
            let _ = inner.transition_to(EndpointState::Bound);
            let _ = inner.transition_to(EndpointState::Connected);
        }

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        let mut fut = match sock.recv_packet_async() {
            Some(f) => f,
            None => RecvPacketFuture::new(stream),
        };
        let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };

        matches!(pinned.as_mut().poll(&mut cx), Poll::Pending)
    }

    pub fn tcp_packet_stream_multiple_packets_smoke() -> bool {
        init_endpoint_manager();
        stack::init_default();

        let sock = create_tcp_endpoint();
        let local = EndpointAddr::new([127, 0, 0, 1], 12345);
        let remote = EndpointAddr::new([127, 0, 0, 1], 80);
        if let Some(s) = sock.endpoint() {
            let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(local);
            inner.remote_addr = Some(remote);
        }

        use alloc::sync::Arc;
        use crate::sync::PoisonLock;
        use crate::net::l4::tcp::{
            Ipv4Addr as TcpIpv4Addr, EndpointAddr as TcpEndpointAddr, TcpControlBlock,
            TcpStream,
        };

        let t_local = TcpEndpointAddr::new([127, 0, 0, 1], 12345);
        let t_remote = TcpEndpointAddr::new([127, 0, 0, 1], 80);

        let mut tcb = TcpControlBlock::new(t_local);
        tcb.set_remote_addr(t_remote);
        tcb.enter_established();
        let tcb_arc = Arc::new(PoisonLock::new(tcb));
        let stream = TcpStream { tcb: tcb_arc.clone() };

        if let Some(s) = sock.endpoint() {
            let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.ensure_tcp().stream = Some(stream.clone());
            let _ = inner.transition_to(EndpointState::Bound);
            let _ = inner.transition_to(EndpointState::Connected);
        }

        let Some(stream_wrapper) = sock.tcp_packet_stream() else {
            return false;
        };

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = stream_wrapper.next_packet();
        let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };
        matches!(pinned.as_mut().poll(&mut cx), Poll::Pending)
    }

    pub fn udp_packet_stream_delivered_smoke() -> bool {
        init_endpoint_manager();

        let processor = crate::net::l4::udp::UdpProcessor::new();
        let port = 40000u16;
        let Ok(u) = processor.bind_with_token(port, None) else {
            return false;
        };

        let sock = create_udp_endpoint();
        if let Some(s) = sock.endpoint() {
            let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(EndpointAddr::new([127, 0, 0, 1], port));
            inner.ensure_udp().socket = Some(u.clone());
            let _ = inner.transition_to(EndpointState::Bound);
            let _ = inner.transition_to(EndpointState::Connected);
        }

        let Some(stream) = sock.udp_packet_stream() else {
            return false;
        };

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        let mut fut = stream.next_packet();
        let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };
        matches!(pinned.as_mut().poll(&mut cx), Poll::Pending)
    }
}
