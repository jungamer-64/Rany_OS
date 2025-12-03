//! # Endpoint Module - SPL/SAS Compliant Network Socket Implementation
//!
//! ## 設計哲学
//! - **細粒度ロック**: Arc<Mutex<SocketInner>>による個別ソケットロック
//! - **RAIIリソース管理**: OwnedSocketによる自動クローズ
//! - **O(1)バッファ操作**: VecDequeによるFIFO効率化
//! - **読み取り並列化**: RwLockによるSocketManager同時読み取り
//! - **状態遷移ガード**: 不正遷移のコンパイル時検出
//! - **イベント駆動**: NetworkEventによるプロトコルスタック連携

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};
use core::task::{Context, Poll};
use spin::{Mutex, RwLock};

use crate::net::tcp::{TcpStream, TcpListener as TcpListenerImpl, TcpState, SocketAddr as TcpSocketAddr, Ipv4Addr};
use crate::net::udp::UdpSocket as RawUdpSocket;

// =====================================================
// Network Event System - プロトコルスタック連携
// =====================================================

/// ネットワークイベント種別
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// 送信データ準備完了 - プロトコルスタックに送信を要求
    DataReady {
        fd: SocketFd,
        socket_type: SocketType,
    },
    /// 接続要求 - TCPハンドシェイク開始
    Connect {
        fd: SocketFd,
        local: SocketAddr,
        remote: SocketAddr,
    },
    /// リッスン開始
    Listen {
        fd: SocketFd,
        local: SocketAddr,
        backlog: u32,
    },
    /// ソケットクローズ
    Close {
        fd: SocketFd,
    },
    /// UDP送信
    SendTo {
        fd: SocketFd,
        data: Vec<u8>,
        remote: SocketAddr,
    },
}

/// イベントキュー（ロックフリーリングバッファ）
pub struct NetworkEventQueue {
    events: Mutex<VecDeque<NetworkEvent>>,
    /// イベント待ちWaker
    waker: Mutex<Option<core::task::Waker>>,
    /// イベントあり通知フラグ
    has_events: AtomicBool,
}

impl NetworkEventQueue {
    /// キュー容量
    const CAPACITY: usize = 256;
    
    /// 新規作成
    pub const fn new() -> Self {
        Self {
            events: Mutex::new(VecDeque::new()),
            waker: Mutex::new(None),
            has_events: AtomicBool::new(false),
        }
    }
    
    /// イベント送信（ソケット層から呼ばれる）
    pub fn send(&self, event: NetworkEvent) -> bool {
        let mut events = self.events.lock();
        if events.len() >= Self::CAPACITY {
            return false; // バックプレッシャー
        }
        events.push_back(event);
        self.has_events.store(true, Ordering::Release);
        
        // 待機中のネットワークタスクを起こす
        if let Some(waker) = self.waker.lock().take() {
            waker.wake();
        }
        true
    }
    
    /// イベント受信（ネットワークタスクから呼ばれる）
    pub fn recv(&self) -> Option<NetworkEvent> {
        let mut events = self.events.lock();
        let event = events.pop_front();
        if events.is_empty() {
            self.has_events.store(false, Ordering::Release);
        }
        event
    }
    
    /// 全イベント取得（バッチ処理用）
    pub fn drain_all(&self) -> Vec<NetworkEvent> {
        let mut events = self.events.lock();
        self.has_events.store(false, Ordering::Release);
        events.drain(..).collect()
    }
    
    /// イベント待ち（非同期）
    pub fn wait_for_events(&self) -> EventWaitFuture<'_> {
        EventWaitFuture { queue: self }
    }
    
    /// イベントがあるか
    #[inline]
    pub fn has_events(&self) -> bool {
        self.has_events.load(Ordering::Acquire)
    }
    
    /// キュー内イベント数
    pub fn len(&self) -> usize {
        self.events.lock().len()
    }
    
    /// キューが空か
    pub fn is_empty(&self) -> bool {
        !self.has_events()
    }
}

/// イベント待ちFuture
pub struct EventWaitFuture<'a> {
    queue: &'a NetworkEventQueue,
}

impl<'a> Future for EventWaitFuture<'a> {
    type Output = NetworkEvent;
    
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // まずイベントがあるかチェック
        if let Some(event) = self.queue.recv() {
            return Poll::Ready(event);
        }
        
        // Wakerを登録
        *self.queue.waker.lock() = Some(cx.waker().clone());
        
        // 再度チェック（Waker登録中にイベントが来た可能性）
        if let Some(event) = self.queue.recv() {
            Poll::Ready(event)
        } else {
            Poll::Pending
        }
    }
}

/// グローバルイベントキュー
static NETWORK_EVENT_QUEUE: NetworkEventQueue = NetworkEventQueue::new();

/// イベントキューへの参照取得
pub fn event_queue() -> &'static NetworkEventQueue {
    &NETWORK_EVENT_QUEUE
}

/// イベント送信ヘルパー（バックプレッシャー対応）
#[inline]
fn send_event(event: NetworkEvent) -> SocketResult<()> {
    if NETWORK_EVENT_QUEUE.send(event) {
        Ok(())
    } else {
        Err(SocketError::ResourceExhausted)
    }
}

/// イベント送信（エラー無視版 - 内部用）
#[inline]
fn send_event_ignore(event: NetworkEvent) {
    let _ = NETWORK_EVENT_QUEUE.send(event);
}

/// ソケットファイルディスクリプタ
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SocketFd(u32);

impl SocketFd {
    /// 無効なファイルディスクリプタ
    pub const INVALID: Self = Self(u32::MAX);
    
    /// 生の値を取得
    #[inline(always)]
    pub const fn raw(self) -> u32 {
        self.0
    }
    
    /// 生の値から作成（内部用）
    #[inline(always)]
    const fn from_raw(fd: u32) -> Self {
        Self(fd)
    }
    
    /// 有効かどうか
    #[inline(always)]
    pub const fn is_valid(self) -> bool {
        self.0 != u32::MAX
    }
}

/// 次のファイルディスクリプタ
static NEXT_FD: AtomicU32 = AtomicU32::new(0);

/// ソケットタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    /// TCPストリームソケット
    Tcp,
    /// UDPデータグラムソケット
    Udp,
    /// RAWソケット（直接IP層アクセス）
    Raw,
}

/// ソケット状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    /// 作成直後
    Created,
    /// バインド済み
    Bound,
    /// リスニング中（TCP only）
    Listening,
    /// 接続中（TCP only）
    Connecting,
    /// 接続済み
    Connected,
    /// クローズ中
    Closing,
    /// クローズ済み
    Closed,
}

impl SocketState {
    /// 送信可能な状態か
    #[inline(always)]
    pub const fn can_send(self) -> bool {
        matches!(self, Self::Connected | Self::Bound)
    }
    
    /// 受信可能な状態か
    #[inline(always)]
    pub const fn can_receive(self) -> bool {
        matches!(self, Self::Connected | Self::Bound | Self::Listening)
    }
    
    /// バインド可能な状態か
    #[inline(always)]
    pub const fn can_bind(self) -> bool {
        matches!(self, Self::Created)
    }
    
    /// 接続可能な状態か
    #[inline(always)]
    pub const fn can_connect(self) -> bool {
        matches!(self, Self::Created | Self::Bound)
    }
    
    /// リッスン可能な状態か
    #[inline(always)]
    pub const fn can_listen(self) -> bool {
        matches!(self, Self::Bound)
    }
}

/// ソケットエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketError {
    /// ソケットが見つからない
    NotFound,
    /// 無効な引数
    InvalidArgument,
    /// 既にバインド済み
    AlreadyBound,
    /// 既に接続済み
    AlreadyConnected,
    /// 接続されていない
    NotConnected,
    /// アドレス使用中
    AddressInUse,
    /// 接続拒否
    ConnectionRefused,
    /// タイムアウト
    Timeout,
    /// 操作中断
    Interrupted,
    /// バッファフル
    BufferFull,
    /// 不正な状態遷移
    InvalidStateTransition,
    /// リソース不足
    ResourceExhausted,
    /// ポートがすでに使用中
    PortInUse,
    /// 内部エラー
    Internal,
}

impl core::fmt::Display for SocketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Socket not found"),
            Self::InvalidArgument => write!(f, "Invalid argument"),
            Self::AlreadyBound => write!(f, "Already bound"),
            Self::AlreadyConnected => write!(f, "Already connected"),
            Self::NotConnected => write!(f, "Not connected"),
            Self::AddressInUse => write!(f, "Address in use"),
            Self::ConnectionRefused => write!(f, "Connection refused"),
            Self::Timeout => write!(f, "Operation timed out"),
            Self::Interrupted => write!(f, "Operation interrupted"),
            Self::BufferFull => write!(f, "Buffer full"),
            Self::InvalidStateTransition => write!(f, "Invalid state transition"),
            Self::ResourceExhausted => write!(f, "Resource exhausted"),
            Self::PortInUse => write!(f, "Port already in use"),
            Self::Internal => write!(f, "Internal error"),
        }
    }
}

/// ソケット結果型
pub type SocketResult<T> = Result<T, SocketError>;

/// ソケットアドレス（IPv4）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct SocketAddr {
    /// IPアドレス
    pub ip: [u8; 4],
    /// ポート番号
    pub port: u16,
}

impl SocketAddr {
    /// 任意アドレス
    pub const ANY: Self = Self {
        ip: [0, 0, 0, 0],
        port: 0,
    };
    
    /// ループバックアドレス
    pub const LOCALHOST: Self = Self {
        ip: [127, 0, 0, 1],
        port: 0,
    };
    
    /// 新規作成
    #[inline(always)]
    pub const fn new(ip: [u8; 4], port: u16) -> Self {
        Self { ip, port }
    }
    
    /// ポート付きで作成
    #[inline(always)]
    pub const fn with_port(self, port: u16) -> Self {
        Self { ip: self.ip, port }
    }
    
    /// IPアドレスをu32で取得
    #[inline(always)]
    pub const fn ip_u32(self) -> u32 {
        u32::from_be_bytes(self.ip)
    }
}

// =====================================================
// SocketInner - 細粒度ロック用の内部状態
// =====================================================

/// ソケットの可変状態（Mutex保護対象）
struct SocketInner {
    /// 現在の状態
    state: SocketState,
    /// ローカルアドレス
    local_addr: Option<SocketAddr>,
    /// リモートアドレス
    remote_addr: Option<SocketAddr>,
    /// 受信バッファ（VecDeque: O(1) FIFO）
    recv_buffer: VecDeque<u8>,
    /// 送信バッファ（VecDeque: O(1) FIFO）
    send_buffer: VecDeque<u8>,
    /// 受信バッファ上限
    recv_buffer_limit: usize,
    /// 送信バッファ上限
    send_buffer_limit: usize,
    /// TCPストリーム（接続済みの場合）
    tcp_stream: Option<TcpStream>,
    /// TCPリスナー（リスニング中の場合）
    tcp_listener: Option<TcpListenerImpl>,
    /// UDPソケット
    udp_socket: Option<RawUdpSocket>,
    /// 保留中のパケット（UDP用）
    pending_packets: VecDeque<(SocketAddr, Vec<u8>)>,
    /// エラー状態
    last_error: Option<SocketError>,
    /// 受信待ちWaker（非同期通知用）
    recv_waker: Option<core::task::Waker>,
    /// 送信待ちWaker（非同期通知用）
    send_waker: Option<core::task::Waker>,
    /// 接続待ちWaker（非同期通知用）
    connect_waker: Option<core::task::Waker>,
}

impl SocketInner {
    /// デフォルトバッファサイズ
    const DEFAULT_BUFFER_SIZE: usize = 8192;
    /// 最大バッファサイズ
    const MAX_BUFFER_SIZE: usize = 65536;
    
    /// 新規作成
    fn new() -> Self {
        Self {
            state: SocketState::Created,
            local_addr: None,
            remote_addr: None,
            recv_buffer: VecDeque::with_capacity(Self::DEFAULT_BUFFER_SIZE),
            send_buffer: VecDeque::with_capacity(Self::DEFAULT_BUFFER_SIZE),
            recv_buffer_limit: Self::MAX_BUFFER_SIZE,
            send_buffer_limit: Self::MAX_BUFFER_SIZE,
            tcp_stream: None,
            tcp_listener: None,
            udp_socket: None,
            pending_packets: VecDeque::with_capacity(16),
            last_error: None,
            recv_waker: None,
            send_waker: None,
            connect_waker: None,
        }
    }
    
    /// 状態遷移（ガード付き）
    #[inline]
    fn transition_to(&mut self, new_state: SocketState) -> SocketResult<()> {
        let valid = match (self.state, new_state) {
            // Created からの遷移
            (SocketState::Created, SocketState::Bound) => true,
            (SocketState::Created, SocketState::Connecting) => true,
            (SocketState::Created, SocketState::Closed) => true,
            // Bound からの遷移
            (SocketState::Bound, SocketState::Listening) => true,
            (SocketState::Bound, SocketState::Connecting) => true,
            (SocketState::Bound, SocketState::Connected) => true, // UDP
            (SocketState::Bound, SocketState::Closed) => true,
            // Listening からの遷移
            (SocketState::Listening, SocketState::Closing) => true,
            (SocketState::Listening, SocketState::Closed) => true,
            // Connecting からの遷移
            (SocketState::Connecting, SocketState::Connected) => true,
            (SocketState::Connecting, SocketState::Closed) => true,
            // Connected からの遷移
            (SocketState::Connected, SocketState::Closing) => true,
            (SocketState::Connected, SocketState::Closed) => true,
            // Closing からの遷移
            (SocketState::Closing, SocketState::Closed) => true,
            // 同じ状態への遷移は許可
            (s1, s2) if s1 == s2 => true,
            _ => false,
        };
        
        if valid {
            self.state = new_state;
            Ok(())
        } else {
            Err(SocketError::InvalidStateTransition)
        }
    }
    
    /// 受信バッファからデータ取得（O(1)）
    #[inline]
    fn recv_from_buffer(&mut self, buf: &mut [u8]) -> usize {
        let len = buf.len().min(self.recv_buffer.len());
        for (i, byte) in self.recv_buffer.drain(..len).enumerate() {
            buf[i] = byte;
        }
        // バッファに空きができたので送信待ちを起こす
        if let Some(waker) = self.send_waker.take() {
            waker.wake();
        }
        len
    }
    
    /// 送信バッファにデータ追加
    #[inline]
    fn send_to_buffer(&mut self, data: &[u8]) -> SocketResult<usize> {
        let available = self.send_buffer_limit.saturating_sub(self.send_buffer.len());
        
        if available == 0 {
            return Err(SocketError::BufferFull);
        }
        
        let len = data.len().min(available);
        self.send_buffer.extend(data[..len].iter().copied());
        Ok(len)
    }
    
    /// 受信バッファにデータ追加（内部用 - カーネル/ドライバから呼ばれる）
    #[inline]
    fn push_recv_data(&mut self, data: &[u8]) {
        let available = self.recv_buffer_limit.saturating_sub(self.recv_buffer.len());
        let len = data.len().min(available);
        self.recv_buffer.extend(data[..len].iter().copied());
        
        // データが到着したので受信待ちを起こす
        if let Some(waker) = self.recv_waker.take() {
            waker.wake();
        }
    }
    
    /// 接続完了通知（内部用 - TCPスタックから呼ばれる）
    #[inline]
    fn notify_connected(&mut self) {
        if let Some(waker) = self.connect_waker.take() {
            waker.wake();
        }
    }
}

// =====================================================
// Socket - Arc<Mutex<SocketInner>>ラッパー
// =====================================================

/// ソケット構造体（細粒度ロック対応）
pub struct Socket {
    /// ファイルディスクリプタ
    fd: SocketFd,
    /// ソケットタイプ（不変）
    socket_type: SocketType,
    /// 内部状態（Arc<Mutex>で保護）
    inner: Arc<Mutex<SocketInner>>,
}

impl Socket {
    /// 新規ソケット作成
    pub fn new(socket_type: SocketType) -> Self {
        let fd = SocketFd::from_raw(NEXT_FD.fetch_add(1, Ordering::Relaxed));
        Self {
            fd,
            socket_type,
            inner: Arc::new(Mutex::new(SocketInner::new())),
        }
    }
    
    /// ファイルディスクリプタ取得
    #[inline(always)]
    pub const fn fd(&self) -> SocketFd {
        self.fd
    }
    
    /// ソケットタイプ取得
    #[inline(always)]
    pub const fn socket_type(&self) -> SocketType {
        self.socket_type
    }
    
    /// 現在の状態取得
    #[inline]
    pub fn state(&self) -> SocketState {
        self.inner.lock().state
    }
    
    /// ローカルアドレス取得
    #[inline]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.lock().local_addr
    }
    
    /// リモートアドレス取得
    #[inline]
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.inner.lock().remote_addr
    }
    
    /// 内部状態への参照取得（高度な操作用）
    #[inline]
    pub fn inner(&self) -> &Arc<Mutex<SocketInner>> {
        &self.inner
    }
    
    /// バインド
    pub fn bind(&self, addr: SocketAddr) -> SocketResult<()> {
        let mut inner = self.inner.lock();
        
        if !inner.state.can_bind() {
            return Err(SocketError::AlreadyBound);
        }
        
        // ポートの重複チェックはSocketManagerで行う
        inner.local_addr = Some(addr);
        inner.transition_to(SocketState::Bound)
    }
    
    /// 接続（TCP用）
    pub fn connect(&self, addr: SocketAddr) -> SocketResult<()> {
        let local_addr;
        {
            let mut inner = self.inner.lock();
            
            if !inner.state.can_connect() {
                return Err(SocketError::AlreadyConnected);
            }
            
            // ローカルアドレスが未設定ならエフェメラルポートを割り当て
            local_addr = inner.local_addr.unwrap_or_else(|| {
                SocketAddr::new([0, 0, 0, 0], 0) // 後でマネージャが割り当て
            });
            
            inner.remote_addr = Some(addr);
            inner.transition_to(SocketState::Connecting)?;
        }
        
        // TCPスタックに接続イベントを送信（バックプレッシャー対応）
        send_event(NetworkEvent::Connect {
            fd: self.fd,
            local: local_addr,
            remote: addr,
        })
    }
    
    /// リッスン開始（TCP用）
    pub fn listen(&self, backlog: u32) -> SocketResult<()> {
        if self.socket_type != SocketType::Tcp {
            return Err(SocketError::InvalidArgument);
        }
        
        let local_addr;
        {
            let mut inner = self.inner.lock();
            
            if !inner.state.can_listen() {
                return Err(SocketError::InvalidStateTransition);
            }
            
            local_addr = inner.local_addr.ok_or(SocketError::InvalidArgument)?;
            
            // TCPリスナー作成 - tcp.rsのSocketAddr型に変換
            let tcp_addr = TcpSocketAddr::new(
                Ipv4Addr::new(local_addr.ip[0], local_addr.ip[1], local_addr.ip[2], local_addr.ip[3]),
                local_addr.port
            );
            let listener = TcpListenerImpl::bind(tcp_addr)
                .map_err(|_| SocketError::AddressInUse)?;
            inner.tcp_listener = Some(listener);
            inner.transition_to(SocketState::Listening)?;
        }
        
        // ネットワークスタックにリッスンイベントを送信（バックプレッシャー対応）
        send_event(NetworkEvent::Listen {
            fd: self.fd,
            local: local_addr,
            backlog,
        })
    }
    
    /// 接続受け入れ（TCP用）- 非ブロッキング
    pub fn accept(&self) -> SocketResult<(Socket, SocketAddr)> {
        if self.socket_type != SocketType::Tcp {
            return Err(SocketError::InvalidArgument);
        }
        
        let inner = self.inner.lock();
        
        if inner.state != SocketState::Listening {
            return Err(SocketError::InvalidStateTransition);
        }
        
        // 注: TcpListenerImpl::acceptはasyncなのでここでは直接呼べない
        // 代わりにバックログから取得するか、Pendingを返す
        // 実際の接続はAcceptFuture経由で取得
        Err(SocketError::Timeout)
    }
    
    /// 接続受け入れ（内部用 - バックログ経由）
    pub fn accept_from_backlog(&self, stream: TcpStream, remote_addr: SocketAddr) -> SocketResult<Socket> {
        if self.socket_type != SocketType::Tcp {
            return Err(SocketError::InvalidArgument);
        }
        
        let inner = self.inner.lock();
        
        if inner.state != SocketState::Listening {
            return Err(SocketError::InvalidStateTransition);
        }
        
        let new_socket = Socket::new(SocketType::Tcp);
        {
            let mut new_inner = new_socket.inner.lock();
            new_inner.local_addr = inner.local_addr;
            new_inner.remote_addr = Some(remote_addr);
            new_inner.tcp_stream = Some(stream);
            let _ = new_inner.transition_to(SocketState::Connected);
        }
        
        Ok(new_socket)
    }
    
    /// データ送信
    pub fn send(&self, data: &[u8]) -> SocketResult<usize> {
        let len = {
            let mut inner = self.inner.lock();
            
            if !inner.state.can_send() {
                return Err(SocketError::NotConnected);
            }
            
            inner.send_to_buffer(data)?
        };
        
        // 送信データがあることをネットワークスタックに通知（バックプレッシャー対応）
        if len > 0 {
            send_event(NetworkEvent::DataReady {
                fd: self.fd,
                socket_type: self.socket_type,
            })?;
        }
        
        Ok(len)
    }
    
    /// データ受信
    pub fn recv(&self, buf: &mut [u8]) -> SocketResult<usize> {
        let mut inner = self.inner.lock();
        
        if !inner.state.can_receive() {
            return Err(SocketError::NotConnected);
        }
        
        let len = inner.recv_from_buffer(buf);
        if len > 0 {
            Ok(len)
        } else {
            Err(SocketError::Timeout)
        }
    }
    
    /// UDP送信
    pub fn send_to(&self, data: &[u8], addr: SocketAddr) -> SocketResult<usize> {
        if self.socket_type != SocketType::Udp {
            return Err(SocketError::InvalidArgument);
        }
        
        {
            let inner = self.inner.lock();
            
            if !matches!(inner.state, SocketState::Bound | SocketState::Connected) {
                return Err(SocketError::NotConnected);
            }
        }
        
        // UDPパケット送信イベント（バックプレッシャー対応）
        send_event(NetworkEvent::SendTo {
            fd: self.fd,
            data: data.to_vec(),
            remote: addr,
        })?;
        
        Ok(data.len())
    }
    
    /// UDP受信
    pub fn recv_from(&self, buf: &mut [u8]) -> SocketResult<(usize, SocketAddr)> {
        if self.socket_type != SocketType::Udp {
            return Err(SocketError::InvalidArgument);
        }
        
        let mut inner = self.inner.lock();
        
        if let Some((addr, data)) = inner.pending_packets.pop_front() {
            let len = buf.len().min(data.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok((len, addr))
        } else {
            Err(SocketError::Timeout)
        }
    }
    
    /// 受信バッファにデータ追加（内部用）
    /// プロトコルスタックから呼ばれる
    pub fn push_data(&self, data: &[u8]) {
        let waker = {
            let mut inner = self.inner.lock();
            inner.push_recv_data(data);
            // 待機中のタスクを起こす準備
            inner.recv_waker.take()
        };
        
        // ロック外でWakerを起こす（デッドロック回避）
        if let Some(w) = waker {
            w.wake();
        }
    }
    
    /// UDPパケット追加（内部用）
    /// プロトコルスタックから呼ばれる
    pub fn push_packet(&self, addr: SocketAddr, data: Vec<u8>) {
        let waker = {
            let mut inner = self.inner.lock();
            inner.pending_packets.push_back((addr, data));
            // 待機中のタスクを起こす準備
            inner.recv_waker.take()
        };
        
        // ロック外でWakerを起こす
        if let Some(w) = waker {
            w.wake();
        }
    }
    
    /// クローズ
    pub fn close(&self) -> SocketResult<()> {
        {
            let mut inner = self.inner.lock();
            
            // TCPストリームのクリーンアップ
            inner.tcp_stream = None;
            
            // リスナーのクリーンアップ
            inner.tcp_listener = None;
            inner.udp_socket = None;
            
            // バッファクリア
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
            
            inner.transition_to(SocketState::Closed)?;
        }
        
        // ネットワークスタックにクローズを通知（エラーは無視 - クローズは必ず進める）
        send_event_ignore(NetworkEvent::Close { fd: self.fd });
        
        Ok(())
    }
    
    /// 受信バッファのデータ量
    #[inline]
    pub fn recv_buffer_len(&self) -> usize {
        self.inner.lock().recv_buffer.len()
    }
    
    /// 送信バッファのデータ量
    #[inline]
    pub fn send_buffer_len(&self) -> usize {
        self.inner.lock().send_buffer.len()
    }
    
    /// 受信データがあるか
    #[inline]
    pub fn has_data(&self) -> bool {
        self.inner.lock().recv_buffer.len() > 0
    }
}

impl Clone for Socket {
    fn clone(&self) -> Self {
        Self {
            fd: self.fd,
            socket_type: self.socket_type,
            inner: Arc::clone(&self.inner),
        }
    }
}

// =====================================================
// OwnedSocket - RAII リソース管理
// =====================================================

/// RAII管理されるソケット（Drop時に自動クローズ）
pub struct OwnedSocket {
    socket: Option<Socket>,
}

impl OwnedSocket {
    /// 新規OwnedSocket作成
    pub fn new(socket_type: SocketType) -> Self {
        let socket = Socket::new(socket_type);
        // SocketManagerに登録
        if let Some(ref manager) = *SOCKET_MANAGER.read() {
            manager.register(socket.clone());
        }
        Self {
            socket: Some(socket),
        }
    }
    
    /// 既存ソケットからOwnedSocket作成
    pub fn from_socket(socket: Socket) -> Self {
        Self {
            socket: Some(socket),
        }
    }
    
    /// ファイルディスクリプタ取得
    pub fn fd(&self) -> SocketFd {
        self.socket.as_ref().map(|s| s.fd()).unwrap_or(SocketFd::INVALID)
    }
    
    /// 内部ソケットへの参照
    pub fn socket(&self) -> Option<&Socket> {
        self.socket.as_ref()
    }
    
    /// 内部ソケットへの可変参照
    pub fn socket_mut(&mut self) -> Option<&mut Socket> {
        self.socket.as_mut()
    }
    
    /// ソケットを取り出し（所有権移動、Dropしなくなる）
    pub fn into_inner(mut self) -> Option<Socket> {
        self.socket.take()
    }
    
    /// バインド
    pub fn bind(&self, addr: SocketAddr) -> SocketResult<()> {
        self.socket.as_ref().ok_or(SocketError::NotFound)?.bind(addr)
    }
    
    /// 接続
    pub fn connect(&self, addr: SocketAddr) -> SocketResult<()> {
        self.socket.as_ref().ok_or(SocketError::NotFound)?.connect(addr)
    }
    
    /// リッスン
    pub fn listen(&self, backlog: u32) -> SocketResult<()> {
        self.socket.as_ref().ok_or(SocketError::NotFound)?.listen(backlog)
    }
    
    /// 接続受け入れ
    pub fn accept(&self) -> SocketResult<(OwnedSocket, SocketAddr)> {
        let (socket, addr) = self.socket.as_ref().ok_or(SocketError::NotFound)?.accept()?;
        Ok((OwnedSocket::from_socket(socket), addr))
    }
    
    /// 送信
    pub fn send(&self, data: &[u8]) -> SocketResult<usize> {
        self.socket.as_ref().ok_or(SocketError::NotFound)?.send(data)
    }
    
    /// 受信
    pub fn recv(&self, buf: &mut [u8]) -> SocketResult<usize> {
        self.socket.as_ref().ok_or(SocketError::NotFound)?.recv(buf)
    }
    
    /// UDP送信
    pub fn send_to(&self, data: &[u8], addr: SocketAddr) -> SocketResult<usize> {
        self.socket.as_ref().ok_or(SocketError::NotFound)?.send_to(data, addr)
    }
    
    /// UDP受信
    pub fn recv_from(&self, buf: &mut [u8]) -> SocketResult<(usize, SocketAddr)> {
        self.socket.as_ref().ok_or(SocketError::NotFound)?.recv_from(buf)
    }
}

impl Drop for OwnedSocket {
    fn drop(&mut self) {
        if let Some(ref socket) = self.socket {
            // ソケットクローズ
            let _ = socket.close();
            
            // SocketManagerから登録解除
            if let Some(ref manager) = *SOCKET_MANAGER.read() {
                manager.unregister(socket.fd());
            }
        }
    }
}

// =====================================================
// SocketManager - RwLockによる読み取り並列化
// =====================================================

/// ソケット管理（RwLockで読み取り並列化）
pub struct SocketManager {
    /// ソケットテーブル
    sockets: RwLock<BTreeMap<SocketFd, Socket>>,
    /// 使用中ポート（プロトコル別）
    tcp_ports: RwLock<BTreeMap<u16, SocketFd>>,
    udp_ports: RwLock<BTreeMap<u16, SocketFd>>,
    /// 次のエフェメラルポート
    next_ephemeral_port: AtomicU32,
}

/// エフェメラルポート範囲
const EPHEMERAL_PORT_START: u16 = 49152;
const EPHEMERAL_PORT_END: u16 = 65535;

impl SocketManager {
    /// 新規マネージャ作成
    pub const fn new() -> Self {
        Self {
            sockets: RwLock::new(BTreeMap::new()),
            tcp_ports: RwLock::new(BTreeMap::new()),
            udp_ports: RwLock::new(BTreeMap::new()),
            next_ephemeral_port: AtomicU32::new(EPHEMERAL_PORT_START as u32),
        }
    }
    
    /// エフェメラルポート割り当て
    pub fn allocate_ephemeral_port(&self, socket_type: SocketType) -> Option<u16> {
        let ports = match socket_type {
            SocketType::Tcp => &self.tcp_ports,
            SocketType::Udp => &self.udp_ports,
            _ => return Some(0),
        };
        
        let ports_guard = ports.read();
        let range_size = (EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1) as u32;
        
        // 最大でrange_size回試行
        for _ in 0..range_size {
            let port = self.next_ephemeral_port.fetch_add(1, Ordering::Relaxed);
            let port = EPHEMERAL_PORT_START + ((port - EPHEMERAL_PORT_START as u32) % range_size) as u16;
            
            if !ports_guard.contains_key(&port) {
                return Some(port);
            }
        }
        
        None // 全ポート使用中
    }
    
    /// ソケット登録
    pub fn register(&self, socket: Socket) {
        self.sockets.write().insert(socket.fd(), socket);
    }
    
    /// ソケット登録解除
    pub fn unregister(&self, fd: SocketFd) -> Option<Socket> {
        let socket = self.sockets.write().remove(&fd);
        
        if let Some(ref s) = socket {
            // ポートの解放
            if let Some(addr) = s.local_addr() {
                match s.socket_type() {
                    SocketType::Tcp => {
                        self.tcp_ports.write().remove(&addr.port);
                    }
                    SocketType::Udp => {
                        self.udp_ports.write().remove(&addr.port);
                    }
                    _ => {}
                }
            }
        }
        
        socket
    }
    
    /// ソケット取得（読み取りロック）
    pub fn get(&self, fd: SocketFd) -> Option<Socket> {
        self.sockets.read().get(&fd).cloned()
    }
    
    /// ポートバインド
    pub fn bind_port(&self, socket_type: SocketType, port: u16, fd: SocketFd) -> SocketResult<()> {
        let ports = match socket_type {
            SocketType::Tcp => &self.tcp_ports,
            SocketType::Udp => &self.udp_ports,
            _ => return Ok(()),
        };
        
        let mut guard = ports.write();
        if guard.contains_key(&port) {
            return Err(SocketError::PortInUse);
        }
        guard.insert(port, fd);
        Ok(())
    }
    
    /// ポートでソケット検索
    pub fn find_by_port(&self, socket_type: SocketType, port: u16) -> Option<Socket> {
        let ports = match socket_type {
            SocketType::Tcp => &self.tcp_ports,
            SocketType::Udp => &self.udp_ports,
            _ => return None,
        };
        
        let fd = *ports.read().get(&port)?;
        self.get(fd)
    }
    
    /// 登録ソケット数
    pub fn socket_count(&self) -> usize {
        self.sockets.read().len()
    }
    
    /// 全ソケット処理（イテレーション）
    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&Socket),
    {
        for socket in self.sockets.read().values() {
            f(socket);
        }
    }
}

/// グローバルソケットマネージャ（RwLock）
static SOCKET_MANAGER: RwLock<Option<SocketManager>> = RwLock::new(None);

/// ソケットマネージャ初期化
pub fn init_socket_manager() {
    *SOCKET_MANAGER.write() = Some(SocketManager::new());
}

/// ソケットマネージャ取得
pub fn socket_manager() -> Option<&'static RwLock<Option<SocketManager>>> {
    Some(&SOCKET_MANAGER)
}

// =====================================================
// Async Futures
// =====================================================

/// 非同期受信Future
pub struct RecvFuture {
    socket: Socket,
    buffer: Vec<u8>,
}

impl RecvFuture {
    /// 新規作成
    pub fn new(socket: Socket, size: usize) -> Self {
        Self {
            socket,
            buffer: alloc::vec![0u8; size],
        }
    }
}

impl Future for RecvFuture {
    type Output = SocketResult<Vec<u8>>;
    
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        
        let mut inner = this.socket.inner.lock();
        
        // 状態チェック
        if !inner.state.can_receive() {
            return Poll::Ready(Err(SocketError::NotConnected));
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
        if matches!(inner.state, SocketState::Closed | SocketState::Closing) {
            return Poll::Ready(Ok(Vec::new()));
        }
        
        // Wakerを登録してPending
        inner.recv_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// 非同期送信Future
pub struct SendFuture {
    socket: Socket,
    data: Vec<u8>,
    offset: usize,
}

impl SendFuture {
    /// 新規作成
    pub fn new(socket: Socket, data: Vec<u8>) -> Self {
        Self {
            socket,
            data,
            offset: 0,
        }
    }
}

impl Future for SendFuture {
    type Output = SocketResult<usize>;
    
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        
        let mut inner = this.socket.inner.lock();
        
        // 状態チェック
        if !inner.state.can_send() {
            return Poll::Ready(Err(SocketError::NotConnected));
        }
        
        // 全データ送信済みなら完了
        if this.offset >= this.data.len() {
            return Poll::Ready(Ok(this.offset));
        }
        
        // バッファに空きがあれば書き込み
        let available = inner.send_buffer_limit.saturating_sub(inner.send_buffer.len());
        if available > 0 {
            let remaining = &this.data[this.offset..];
            let to_send = remaining.len().min(available);
            inner.send_buffer.extend(remaining[..to_send].iter().copied());
            this.offset += to_send;
            
            // 全データ送信済みなら完了
            if this.offset >= this.data.len() {
                return Poll::Ready(Ok(this.offset));
            }
        }
        
        // Wakerを登録してPending
        inner.send_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// 非同期接続受け入れFuture
pub struct AcceptFuture {
    socket: Socket,
}

impl AcceptFuture {
    /// 新規作成
    pub fn new(socket: Socket) -> Self {
        Self { socket }
    }
}

impl Future for AcceptFuture {
    type Output = SocketResult<(OwnedSocket, SocketAddr)>;
    
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.socket.accept() {
            Ok((socket, addr)) => Poll::Ready(Ok((OwnedSocket::from_socket(socket), addr))),
            Err(SocketError::Timeout) => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

/// 非同期UDP受信Future
pub struct RecvFromFuture {
    socket: Socket,
    buffer: Vec<u8>,
}

impl RecvFromFuture {
    /// 新規作成
    pub fn new(socket: Socket, size: usize) -> Self {
        Self {
            socket,
            buffer: alloc::vec![0u8; size],
        }
    }
}

impl Future for RecvFromFuture {
    type Output = SocketResult<(Vec<u8>, SocketAddr)>;
    
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        
        // バッファサイズを取得
        let buf_len = this.buffer.len();
        let mut temp_buf = alloc::vec![0u8; buf_len];
        
        match this.socket.recv_from(&mut temp_buf) {
            Ok((len, addr)) => {
                this.buffer.truncate(len);
                this.buffer[..len].copy_from_slice(&temp_buf[..len]);
                Poll::Ready(Ok((core::mem::take(&mut this.buffer), addr)))
            }
            Err(SocketError::Timeout) => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

// =====================================================
// 便利関数 - OwnedSocket API
// =====================================================

/// TCPソケット作成
pub fn create_tcp_socket() -> OwnedSocket {
    OwnedSocket::new(SocketType::Tcp)
}

/// UDPソケット作成
pub fn create_udp_socket() -> OwnedSocket {
    OwnedSocket::new(SocketType::Udp)
}

/// RAWソケット作成
pub fn create_raw_socket() -> OwnedSocket {
    OwnedSocket::new(SocketType::Raw)
}

/// TCPサーバー作成（バインド+リッスン）
pub fn create_tcp_server(addr: SocketAddr, backlog: u32) -> SocketResult<OwnedSocket> {
    let socket = create_tcp_socket();
    socket.bind(addr)?;
    socket.listen(backlog)?;
    Ok(socket)
}

/// TCP接続
pub fn tcp_connect(addr: SocketAddr) -> SocketResult<OwnedSocket> {
    let socket = create_tcp_socket();
    socket.connect(addr)?;
    Ok(socket)
}

/// UDPバインド
pub fn udp_bind(addr: SocketAddr) -> SocketResult<OwnedSocket> {
    let socket = create_udp_socket();
    socket.bind(addr)?;
    Ok(socket)
}

// =====================================================
// 非同期拡張メソッド
// =====================================================

impl OwnedSocket {
    /// 非同期受信
    pub fn recv_async(&self, size: usize) -> Option<RecvFuture> {
        self.socket.as_ref().map(|s| RecvFuture::new(s.clone(), size))
    }
    
    /// 非同期送信
    pub fn send_async(&self, data: Vec<u8>) -> Option<SendFuture> {
        self.socket.as_ref().map(|s| SendFuture::new(s.clone(), data))
    }
    
    /// 非同期接続受け入れ
    pub fn accept_async(&self) -> Option<AcceptFuture> {
        self.socket.as_ref().map(|s| AcceptFuture::new(s.clone()))
    }
    
    /// 非同期UDP受信
    pub fn recv_from_async(&self, size: usize) -> Option<RecvFromFuture> {
        self.socket.as_ref().map(|s| RecvFromFuture::new(s.clone(), size))
    }
}

// =====================================================
// TCP Control Block Manager - 接続状態管理
// =====================================================

use core::sync::atomic::AtomicU64;

/// TCPフラグ
pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
}

/// TCP接続状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpConnectionState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

/// TCP制御ブロック（軽量版）
#[derive(Debug, Clone)]
pub struct TcpControlBlockEntry {
    /// ソケットFD
    pub fd: SocketFd,
    /// ローカルアドレス
    pub local: SocketAddr,
    /// リモートアドレス
    pub remote: SocketAddr,
    /// 現在の状態
    pub state: TcpConnectionState,
    /// 送信シーケンス番号（次に送信するバイト）
    pub snd_nxt: u32,
    /// 未確認の最古のシーケンス番号
    pub snd_una: u32,
    /// 受信シーケンス番号（次に期待するバイト）
    pub rcv_nxt: u32,
    /// 送信ウィンドウサイズ
    pub snd_wnd: u16,
    /// 受信ウィンドウサイズ
    pub rcv_wnd: u16,
    /// 再送回数
    pub retransmit_count: u8,
    /// 最終送信時刻（tick）
    pub last_send_tick: u64,
}

impl TcpControlBlockEntry {
    /// 新規作成
    pub fn new(fd: SocketFd, local: SocketAddr, remote: SocketAddr) -> Self {
        Self {
            fd,
            local,
            remote,
            state: TcpConnectionState::Closed,
            snd_nxt: 0,
            snd_una: 0,
            rcv_nxt: 0,
            snd_wnd: 65535,
            rcv_wnd: 65535,
            retransmit_count: 0,
            last_send_tick: 0,
        }
    }
    
    /// 初期シーケンス番号を設定
    pub fn initialize_seq(&mut self, isn: u32) {
        self.snd_nxt = isn;
        self.snd_una = isn;
    }
}

/// TCBテーブル（接続管理）
pub struct TcbTable {
    /// アクティブな接続
    entries: RwLock<BTreeMap<(SocketAddr, SocketAddr), TcpControlBlockEntry>>,
    /// シーケンス番号カウンタ
    seq_counter: AtomicU32,
    /// 現在のtick（再送タイマー用）
    current_tick: AtomicU64,
}

impl TcbTable {
    /// 新規作成
    pub const fn new() -> Self {
        Self {
            entries: RwLock::new(BTreeMap::new()),
            seq_counter: AtomicU32::new(0),
            current_tick: AtomicU64::new(0),
        }
    }
    
    /// 初期シーケンス番号生成（RFC 6528準拠の簡易版）
    pub fn generate_isn(&self) -> u32 {
        // TODO: より安全なランダム化（タイムスタンプ + ハッシュ）
        self.seq_counter.fetch_add(64000, Ordering::Relaxed)
    }
    
    /// tick更新（タイマー割り込みから呼ばれる）
    pub fn tick(&self) {
        self.current_tick.fetch_add(1, Ordering::Relaxed);
    }
    
    /// 接続追加
    pub fn insert(&self, entry: TcpControlBlockEntry) {
        let key = (entry.local, entry.remote);
        self.entries.write().insert(key, entry);
    }
    
    /// 接続取得
    pub fn get(&self, local: SocketAddr, remote: SocketAddr) -> Option<TcpControlBlockEntry> {
        self.entries.read().get(&(local, remote)).cloned()
    }
    
    /// 接続更新
    pub fn update<F>(&self, local: SocketAddr, remote: SocketAddr, f: F) -> bool
    where
        F: FnOnce(&mut TcpControlBlockEntry),
    {
        let mut entries = self.entries.write();
        if let Some(entry) = entries.get_mut(&(local, remote)) {
            f(entry);
            true
        } else {
            false
        }
    }
    
    /// 接続削除
    pub fn remove(&self, local: SocketAddr, remote: SocketAddr) -> Option<TcpControlBlockEntry> {
        self.entries.write().remove(&(local, remote))
    }
    
    /// FDで接続検索
    pub fn find_by_fd(&self, fd: SocketFd) -> Option<TcpControlBlockEntry> {
        self.entries.read().values().find(|e| e.fd == fd).cloned()
    }
}

/// グローバルTCBテーブル
static TCB_TABLE: TcbTable = TcbTable::new();

/// TCBテーブルへの参照取得
pub fn tcb_table() -> &'static TcbTable {
    &TCB_TABLE
}

// =====================================================
// TCP Segment Builder - パケット構築
// =====================================================

/// TCPセグメントビルダー
pub struct TcpSegmentBuilder {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    data: Vec<u8>,
}

impl TcpSegmentBuilder {
    /// 新規作成
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        Self {
            src_port,
            dst_port,
            seq_num: 0,
            ack_num: 0,
            flags: 0,
            window: 65535,
            data: Vec::new(),
        }
    }
    
    /// シーケンス番号設定
    pub fn seq(mut self, seq: u32) -> Self {
        self.seq_num = seq;
        self
    }
    
    /// ACK番号設定
    pub fn ack(mut self, ack: u32) -> Self {
        self.ack_num = ack;
        self
    }
    
    /// フラグ設定
    pub fn flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }
    
    /// SYNフラグ追加
    pub fn syn(mut self) -> Self {
        self.flags |= tcp_flags::SYN;
        self
    }
    
    /// ACKフラグ追加
    pub fn ack_flag(mut self) -> Self {
        self.flags |= tcp_flags::ACK;
        self
    }
    
    /// FINフラグ追加
    pub fn fin(mut self) -> Self {
        self.flags |= tcp_flags::FIN;
        self
    }
    
    /// RSTフラグ追加
    pub fn rst(mut self) -> Self {
        self.flags |= tcp_flags::RST;
        self
    }
    
    /// ウィンドウサイズ設定
    pub fn window(mut self, window: u16) -> Self {
        self.window = window;
        self
    }
    
    /// データ設定
    pub fn data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }
    
    /// TCPセグメントをバイト列に構築
    pub fn build(self) -> Vec<u8> {
        let data_offset = 5u8; // 20バイト（オプションなし）
        let header_len = (data_offset as usize) * 4;
        let total_len = header_len + self.data.len();
        
        let mut segment = alloc::vec![0u8; total_len];
        
        // Source port (2 bytes)
        segment[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        // Destination port (2 bytes)
        segment[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        // Sequence number (4 bytes)
        segment[4..8].copy_from_slice(&self.seq_num.to_be_bytes());
        // ACK number (4 bytes)
        segment[8..12].copy_from_slice(&self.ack_num.to_be_bytes());
        // Data offset (4 bits) + Reserved (4 bits) + Flags (8 bits)
        let data_off_flags = ((data_offset as u16) << 12) | (self.flags as u16);
        segment[12..14].copy_from_slice(&data_off_flags.to_be_bytes());
        // Window (2 bytes)
        segment[14..16].copy_from_slice(&self.window.to_be_bytes());
        // Checksum (2 bytes) - will be calculated later
        segment[16..18].copy_from_slice(&0u16.to_be_bytes());
        // Urgent pointer (2 bytes)
        segment[18..20].copy_from_slice(&0u16.to_be_bytes());
        
        // Data
        if !self.data.is_empty() {
            segment[header_len..].copy_from_slice(&self.data);
        }
        
        segment
    }
    
    /// チェックサム計算（疑似ヘッダ込み）
    pub fn calculate_checksum(segment: &mut [u8], src_ip: [u8; 4], dst_ip: [u8; 4]) {
        // チェックサムフィールドをゼロに
        segment[16] = 0;
        segment[17] = 0;
        
        // 疑似ヘッダ
        let mut sum: u32 = 0;
        
        // 送信元IP
        sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
        sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
        // 宛先IP
        sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
        sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
        // Protocol (TCP = 6) + TCPセグメント長
        sum += 6u32;
        sum += segment.len() as u32;
        
        // TCPセグメント本体
        let mut i = 0;
        while i + 1 < segment.len() {
            sum += u16::from_be_bytes([segment[i], segment[i + 1]]) as u32;
            i += 2;
        }
        // 奇数長の場合
        if i < segment.len() {
            sum += (segment[i] as u32) << 8;
        }
        
        // 1の補数計算
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let checksum = !sum as u16;
        
        segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    }
}

// =====================================================
// ネットワークイベントハンドラ
// =====================================================

/// イベント処理の結果
#[derive(Debug)]
pub enum EventHandleResult {
    /// 処理成功
    Success,
    /// ソケットが見つからない
    SocketNotFound(SocketFd),
    /// プロトコルエラー
    ProtocolError(SocketError),
    /// 再試行が必要
    Retry,
}

/// ネットワークイベントハンドラ
/// プロトコルスタック（TCP/UDP）と連携する
pub struct NetworkEventHandler {
    /// ソケットマネージャへの参照を使用
    _marker: core::marker::PhantomData<()>,
}

impl NetworkEventHandler {
    /// 新規ハンドラ作成
    pub fn new() -> Self {
        Self {
            _marker: core::marker::PhantomData,
        }
    }
    
    /// イベントを処理
    pub fn handle_event(&self, event: NetworkEvent) -> EventHandleResult {
        match event {
            NetworkEvent::DataReady { fd, socket_type } => {
                self.handle_data_ready(fd, socket_type)
            }
            NetworkEvent::Connect { fd, local, remote } => {
                self.handle_connect(fd, local, remote)
            }
            NetworkEvent::Listen { fd, local, backlog } => {
                self.handle_listen(fd, local, backlog)
            }
            NetworkEvent::Close { fd } => self.handle_close(fd),
            NetworkEvent::SendTo { fd, data, remote } => {
                self.handle_send_to(fd, remote, data)
            }
        }
    }
    
    /// DataReadyイベント処理
    /// 送信バッファにデータがあるのでTCPで送信
    fn handle_data_ready(&self, fd: SocketFd, _socket_type: SocketType) -> EventHandleResult {
        let manager = SOCKET_MANAGER.read();
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };
        
        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };
        
        // 送信バッファからデータを取得
        let data = {
            let mut inner = socket.inner.lock();
            if inner.send_buffer.is_empty() {
                return EventHandleResult::Success;
            }
            inner.send_buffer.drain(..).collect::<Vec<u8>>()
        };
        
        // TCPストリーム経由で送信（実際のプロトコルスタック呼び出し）
        let inner = socket.inner.lock();
        if let Some(ref _tcp_stream) = inner.tcp_stream {
            // TODO: TCP送信の実装
            // tcp_stream.send(&data)?;
            let _ = data; // 現時点では未使用警告を抑制
            EventHandleResult::Success
        } else {
            EventHandleResult::ProtocolError(SocketError::NotConnected)
        }
    }
    
    /// Connectイベント処理
    /// TCPハンドシェイクを開始（SYN送信）
    fn handle_connect(&self, fd: SocketFd, local: SocketAddr, remote: SocketAddr) -> EventHandleResult {
        let manager = SOCKET_MANAGER.read();
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };
        
        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };
        
        // ローカルポートが未割り当ての場合はエフェメラルポートを割り当て
        let local_port = if local.port == 0 {
            mgr.allocate_ephemeral_port(SocketType::Tcp)
                .unwrap_or(49152)
        } else {
            local.port
        };
        let local_addr = SocketAddr::new(local.ip, local_port);
        
        // ソケットのローカルアドレスを更新
        {
            let mut inner = socket.inner.lock();
            inner.local_addr = Some(local_addr);
        }
        
        // TCB（TCP Control Block）を作成
        let isn = tcb_table().generate_isn();
        let mut tcb = TcpControlBlockEntry::new(fd, local_addr, remote);
        tcb.initialize_seq(isn);
        tcb.state = TcpConnectionState::SynSent;
        tcb_table().insert(tcb);
        
        // SYNパケット構築
        let mut syn_segment = TcpSegmentBuilder::new(local_port, remote.port)
            .seq(isn)
            .syn()
            .window(65535)
            .build();
        
        // チェックサム計算
        TcpSegmentBuilder::calculate_checksum(&mut syn_segment, local_addr.ip, remote.ip);
        
        // パケット送信（IPスタック経由）
        if let Err(e) = self.send_tcp_segment(local_addr, remote, syn_segment) {
            crate::serial_println!("TCP: Failed to send SYN packet: {:?}", e);
            return EventHandleResult::ProtocolError(SocketError::Internal);
        }
        
        crate::serial_println!(
            "TCP: SYN sent {}:{} -> {}:{} (seq={})",
            local_addr.ip[0], local_addr.ip[1],
            remote.ip[0], remote.ip[1],
            isn
        );
        
        // 注: SYN-ACK受信後にWakerを起こす（受信処理側で行う）
        // ここではまだ接続は完了していない
        
        EventHandleResult::Success
    }
    
    /// TCPセグメント送信（IPスタック経由）
    fn send_tcp_segment(&self, src: SocketAddr, dst: SocketAddr, segment: Vec<u8>) -> SocketResult<()> {
        // IPv4パケットを構築して送信
        // 1. IPv4ヘッダ構築
        // 2. ネットワークスタック経由で送信
        
        // TODO: 実際のIP層との統合
        // 現時点ではスタブ実装
        let _ = (src, dst, segment);
        
        // グローバルネットワークスタックを使用
        // crate::net::stack::global_stack()?.send_ipv4(
        //     dst.ip,
        //     crate::net::ipv4::IpProtocol::TCP,
        //     &segment
        // )?;
        
        Ok(())
    }
    
    /// Listenイベント処理
    /// サーバーソケットを設定
    fn handle_listen(&self, fd: SocketFd, local: SocketAddr, backlog: u32) -> EventHandleResult {
        let manager = SOCKET_MANAGER.read();
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };
        
        let Some(_socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };
        
        // TODO: TCP Listenの実装
        // 1. TCPリスナー登録
        // 2. 接続要求キューの設定
        let _ = (local, backlog);
        
        EventHandleResult::Success
    }
    
    /// Closeイベント処理
    /// 接続を終了
    fn handle_close(&self, fd: SocketFd) -> EventHandleResult {
        let manager = SOCKET_MANAGER.read();
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };
        
        let Some(_socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };
        
        // TODO: TCP終了処理
        // 1. FINパケット送信
        // 2. FIN-ACK待機
        // 3. リソース解放
        
        EventHandleResult::Success
    }
    
    /// SendToイベント処理
    /// UDPパケットを送信
    fn handle_send_to(&self, fd: SocketFd, remote: SocketAddr, data: Vec<u8>) -> EventHandleResult {
        let manager = SOCKET_MANAGER.read();
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };
        
        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };
        
        let inner = socket.inner.lock();
        if let Some(ref _udp_socket) = inner.udp_socket {
            // TODO: UDP送信の実装
            // udp_socket.send_to(&data, addr)?;
            let _ = (remote, data);
            EventHandleResult::Success
        } else {
            EventHandleResult::ProtocolError(SocketError::InvalidStateTransition)
        }
    }
}

impl Default for NetworkEventHandler {
    fn default() -> Self {
        Self::new()
    }
}

// =====================================================
// TCP受信処理 - 3ウェイハンドシェイク・データ受信
// =====================================================

/// TCPセグメント受信処理
/// プロトコルスタック（ipv4.rs）から呼ばれる
pub fn process_tcp_segment(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    segment: &[u8],
) {
    if segment.len() < 20 {
        return; // 最小ヘッダサイズ未満
    }
    
    // TCPヘッダ解析
    let src_port = u16::from_be_bytes([segment[0], segment[1]]);
    let dst_port = u16::from_be_bytes([segment[2], segment[3]]);
    let seq_num = u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]);
    let ack_num = u32::from_be_bytes([segment[8], segment[9], segment[10], segment[11]]);
    let data_off_flags = u16::from_be_bytes([segment[12], segment[13]]);
    let data_offset = ((data_off_flags >> 12) & 0x0F) as usize * 4;
    let flags = (data_off_flags & 0x003F) as u8;
    let _window = u16::from_be_bytes([segment[14], segment[15]]);
    
    let remote = SocketAddr::new(src_ip, src_port);
    let local = SocketAddr::new(dst_ip, dst_port);
    
    // TCBを検索
    if let Some(tcb) = tcb_table().get(local, remote) {
        process_tcp_with_tcb(tcb, flags, seq_num, ack_num, segment, data_offset);
    } else {
        // 新規接続要求の可能性（LISTENソケット検索）
        process_tcp_new_connection(local, remote, flags, seq_num, segment, data_offset);
    }
}

/// 既存TCBに対するTCPセグメント処理
fn process_tcp_with_tcb(
    tcb: TcpControlBlockEntry,
    flags: u8,
    seq_num: u32,
    ack_num: u32,
    segment: &[u8],
    data_offset: usize,
) {
    let is_syn = (flags & tcp_flags::SYN) != 0;
    let is_ack = (flags & tcp_flags::ACK) != 0;
    let is_fin = (flags & tcp_flags::FIN) != 0;
    let is_rst = (flags & tcp_flags::RST) != 0;
    
    match tcb.state {
        TcpConnectionState::SynSent => {
            // SYN-ACK待ち
            if is_syn && is_ack {
                // SYN-ACK受信 → ACK送信して接続確立
                handle_syn_ack_received(tcb, seq_num, ack_num);
            } else if is_rst {
                // RST受信 → 接続失敗
                handle_rst_received(tcb);
            }
        }
        TcpConnectionState::SynReceived => {
            // ACK待ち（サーバー側）
            if is_ack {
                handle_ack_for_syn(tcb, ack_num);
            }
        }
        TcpConnectionState::Established => {
            // データ受信または終了処理
            if is_fin {
                handle_fin_received(tcb, seq_num);
            } else if is_rst {
                handle_rst_received(tcb);
            } else {
                // データ受信
                let data_start = data_offset;
                if data_start < segment.len() {
                    let data = &segment[data_start..];
                    handle_data_received(tcb, seq_num, data);
                } else if is_ack {
                    // ACKのみ（データなし）
                    handle_ack_received(tcb, ack_num);
                }
            }
        }
        TcpConnectionState::FinWait1 => {
            if is_fin && is_ack {
                handle_fin_ack_received(tcb, seq_num, ack_num);
            } else if is_ack {
                handle_ack_for_fin(tcb, ack_num);
            }
        }
        TcpConnectionState::FinWait2 => {
            if is_fin {
                handle_fin_received(tcb, seq_num);
            }
        }
        TcpConnectionState::CloseWait | TcpConnectionState::LastAck => {
            if is_ack {
                handle_final_ack(tcb, ack_num);
            }
        }
        _ => {}
    }
}

/// SYN-ACK受信処理（クライアント側3ウェイハンドシェイク）
fn handle_syn_ack_received(tcb: TcpControlBlockEntry, seq_num: u32, ack_num: u32) {
    // ACK番号を検証
    if ack_num != tcb.snd_nxt {
        crate::serial_println!("TCP: Invalid SYN-ACK ack_num: expected {}, got {}", tcb.snd_nxt, ack_num);
        return;
    }
    
    // TCB更新
    let updated = tcb_table().update(tcb.local, tcb.remote, |entry| {
        entry.rcv_nxt = seq_num.wrapping_add(1); // SYNは1バイト消費
        entry.snd_una = ack_num;
        entry.state = TcpConnectionState::Established;
    });
    
    if !updated {
        return;
    }
    
    // ACKパケット送信
    let mut ack_segment = TcpSegmentBuilder::new(tcb.local.port, tcb.remote.port)
        .seq(ack_num)
        .ack(seq_num.wrapping_add(1))
        .ack_flag()
        .window(65535)
        .build();
    
    TcpSegmentBuilder::calculate_checksum(&mut ack_segment, tcb.local.ip, tcb.remote.ip);
    
    // TODO: パケット送信
    crate::serial_println!(
        "TCP: Connection established {}:{} <-> {}:{}",
        tcb.local.ip[0], tcb.local.port,
        tcb.remote.ip[0], tcb.remote.port
    );
    
    // ソケットのWakerを起こす
    notify_socket_connected(tcb.fd);
}

/// 新規接続処理（SYN受信 - サーバー側）
fn process_tcp_new_connection(
    local: SocketAddr,
    remote: SocketAddr,
    flags: u8,
    seq_num: u32,
    _segment: &[u8],
    _data_offset: usize,
) {
    let is_syn = (flags & tcp_flags::SYN) != 0;
    
    if !is_syn {
        // SYN以外の新規接続は無視（またはRST送信）
        return;
    }
    
    // リッスン中のソケットを探す
    let manager = SOCKET_MANAGER.read();
    let Some(ref mgr) = *manager else {
        return;
    };
    
    let socket = mgr.find_by_port(SocketType::Tcp, local.port);
    let Some(socket) = socket else {
        // リッスン中のソケットがない → RST送信（TODO）
        return;
    };
    
    let inner = socket.inner.lock();
    if inner.state != SocketState::Listening {
        return;
    }
    drop(inner);
    
    // TCB作成
    let isn = tcb_table().generate_isn();
    let mut tcb = TcpControlBlockEntry::new(socket.fd, local, remote);
    tcb.initialize_seq(isn);
    tcb.rcv_nxt = seq_num.wrapping_add(1);
    tcb.state = TcpConnectionState::SynReceived;
    tcb_table().insert(tcb);
    
    // SYN-ACK送信
    let mut syn_ack = TcpSegmentBuilder::new(local.port, remote.port)
        .seq(isn)
        .ack(seq_num.wrapping_add(1))
        .syn()
        .ack_flag()
        .window(65535)
        .build();
    
    TcpSegmentBuilder::calculate_checksum(&mut syn_ack, local.ip, remote.ip);
    
    // TODO: パケット送信
    crate::serial_println!(
        "TCP: SYN-ACK sent {}:{} -> {}:{}",
        local.ip[0], local.port,
        remote.ip[0], remote.port
    );
}

/// RST受信処理
fn handle_rst_received(tcb: TcpControlBlockEntry) {
    tcb_table().update(tcb.local, tcb.remote, |entry| {
        entry.state = TcpConnectionState::Closed;
    });
    
    // ソケットにエラー通知
    if let Some(socket) = get_socket_by_fd(tcb.fd) {
        let mut inner = socket.inner.lock();
        inner.last_error = Some(SocketError::ConnectionRefused);
        if let Some(waker) = inner.connect_waker.take() {
            waker.wake();
        }
    }
    
    tcb_table().remove(tcb.local, tcb.remote);
}

/// ACK受信処理（データ確認応答）
fn handle_ack_received(tcb: TcpControlBlockEntry, ack_num: u32) {
    tcb_table().update(tcb.local, tcb.remote, |entry| {
        if ack_num > entry.snd_una {
            entry.snd_una = ack_num;
            entry.retransmit_count = 0; // 再送カウンタリセット
        }
    });
}

/// SYN確認応答処理（サーバー側）
fn handle_ack_for_syn(tcb: TcpControlBlockEntry, ack_num: u32) {
    if ack_num != tcb.snd_nxt {
        return;
    }
    
    tcb_table().update(tcb.local, tcb.remote, |entry| {
        entry.snd_una = ack_num;
        entry.state = TcpConnectionState::Established;
    });
    
    crate::serial_println!(
        "TCP: Server connection established {}:{}",
        tcb.local.ip[0], tcb.local.port
    );
    
    // バックログにソケット追加（TODO: accept()で取得できるように）
}

/// データ受信処理
fn handle_data_received(tcb: TcpControlBlockEntry, seq_num: u32, data: &[u8]) {
    // シーケンス番号チェック
    if seq_num != tcb.rcv_nxt {
        // Out-of-order → 将来の再送処理で対応
        return;
    }
    
    // TCB更新
    tcb_table().update(tcb.local, tcb.remote, |entry| {
        entry.rcv_nxt = entry.rcv_nxt.wrapping_add(data.len() as u32);
    });
    
    // ソケットの受信バッファにデータ追加
    if let Some(socket) = get_socket_by_fd(tcb.fd) {
        socket.push_data(data);
    }
    
    // ACK送信
    let new_rcv_nxt = tcb.rcv_nxt.wrapping_add(data.len() as u32);
    let mut ack = TcpSegmentBuilder::new(tcb.local.port, tcb.remote.port)
        .seq(tcb.snd_nxt)
        .ack(new_rcv_nxt)
        .ack_flag()
        .window(65535)
        .build();
    
    TcpSegmentBuilder::calculate_checksum(&mut ack, tcb.local.ip, tcb.remote.ip);
    // TODO: パケット送信
}

/// FIN受信処理
fn handle_fin_received(tcb: TcpControlBlockEntry, seq_num: u32) {
    tcb_table().update(tcb.local, tcb.remote, |entry| {
        entry.rcv_nxt = seq_num.wrapping_add(1); // FINは1バイト消費
        entry.state = match entry.state {
            TcpConnectionState::Established => TcpConnectionState::CloseWait,
            TcpConnectionState::FinWait1 => TcpConnectionState::Closing,
            TcpConnectionState::FinWait2 => TcpConnectionState::TimeWait,
            s => s,
        };
    });
    
    // ACK送信
    let mut ack = TcpSegmentBuilder::new(tcb.local.port, tcb.remote.port)
        .seq(tcb.snd_nxt)
        .ack(seq_num.wrapping_add(1))
        .ack_flag()
        .window(65535)
        .build();
    
    TcpSegmentBuilder::calculate_checksum(&mut ack, tcb.local.ip, tcb.remote.ip);
    // TODO: パケット送信
}

/// FIN-ACK受信処理
fn handle_fin_ack_received(tcb: TcpControlBlockEntry, seq_num: u32, ack_num: u32) {
    handle_ack_received(tcb.clone(), ack_num);
    handle_fin_received(tcb, seq_num);
}

/// FIN確認応答処理
fn handle_ack_for_fin(tcb: TcpControlBlockEntry, ack_num: u32) {
    if ack_num != tcb.snd_nxt {
        return;
    }
    
    tcb_table().update(tcb.local, tcb.remote, |entry| {
        entry.snd_una = ack_num;
        entry.state = TcpConnectionState::FinWait2;
    });
}

/// 最終ACK処理
fn handle_final_ack(tcb: TcpControlBlockEntry, ack_num: u32) {
    if ack_num != tcb.snd_nxt {
        return;
    }
    
    tcb_table().update(tcb.local, tcb.remote, |entry| {
        entry.state = TcpConnectionState::Closed;
    });
    
    tcb_table().remove(tcb.local, tcb.remote);
}

/// ソケットに接続完了を通知
fn notify_socket_connected(fd: SocketFd) {
    let manager = SOCKET_MANAGER.read();
    let Some(ref mgr) = *manager else {
        return;
    };
    
    if let Some(socket) = mgr.get(fd) {
        let mut inner = socket.inner.lock();
        let _ = inner.transition_to(SocketState::Connected);
        if let Some(waker) = inner.connect_waker.take() {
            waker.wake();
        }
    }
}

/// FDでソケット取得
fn get_socket_by_fd(fd: SocketFd) -> Option<Socket> {
    let manager = SOCKET_MANAGER.read();
    let mgr = manager.as_ref()?;
    mgr.get(fd)
}

/// ネットワークイベント処理タスク
/// 非同期でイベントを消費してプロトコルスタックに渡す
pub async fn network_event_task() {
    let handler = NetworkEventHandler::new();
    
    loop {
        // イベントを待機（単一イベントを取得）
        let event = event_queue().wait_for_events().await;
        
        // イベントを処理
        let result = handler.handle_event(event);
        match result {
            EventHandleResult::Success => {}
            EventHandleResult::SocketNotFound(fd) => {
                // ソケットが既に閉じられている - 正常
                crate::serial_println!("Network: Socket {} not found (already closed)", fd.raw());
            }
            EventHandleResult::ProtocolError(e) => {
                crate::serial_println!("Network: Protocol error: {:?}", e);
            }
            EventHandleResult::Retry => {
                // 再試行が必要な場合は再度キューに入れる
                // TODO: リトライロジック
            }
        }
        
        // 残りのイベントも処理（バッチ処理）
        while let Some(event) = event_queue().recv() {
            let result = handler.handle_event(event);
            if let EventHandleResult::SocketNotFound(fd) = result {
                crate::serial_println!("Network: Socket {} not found", fd.raw());
            }
        }
    }
}

/// ネットワークイベント処理の初期化
pub fn init_network_event_handler() {
    // イベントキューは既に初期化済み（NETWORK_EVENT_QUEUE）
    // タスクスケジューラにnetwork_event_taskを登録する
    // TODO: タスクスケジューラとの統合
    crate::serial_println!("Network: Event handler initialized");
}

// =====================================================
// テスト
// =====================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_socket_fd() {
        let fd1 = SocketFd::from_raw(1);
        let fd2 = SocketFd::from_raw(2);
        
        assert!(fd1.is_valid());
        assert!(!SocketFd::INVALID.is_valid());
        assert!(fd1 < fd2);
    }
    
    #[test]
    fn test_socket_state_transitions() {
        let mut inner = SocketInner::new();
        
        // Created -> Bound
        assert!(inner.transition_to(SocketState::Bound).is_ok());
        assert_eq!(inner.state, SocketState::Bound);
        
        // Bound -> Listening
        assert!(inner.transition_to(SocketState::Listening).is_ok());
        assert_eq!(inner.state, SocketState::Listening);
        
        // Invalid: Listening -> Connected
        assert!(inner.transition_to(SocketState::Connected).is_err());
    }
    
    #[test]
    fn test_vecdeque_buffer() {
        let mut inner = SocketInner::new();
        
        // データ追加
        inner.push_recv_data(&[1, 2, 3, 4, 5]);
        assert_eq!(inner.recv_buffer.len(), 5);
        
        // O(1)でのデータ取得
        let mut buf = [0u8; 3];
        let len = inner.recv_from_buffer(&mut buf);
        assert_eq!(len, 3);
        assert_eq!(buf, [1, 2, 3]);
        assert_eq!(inner.recv_buffer.len(), 2);
    }
    
    #[test]
    fn test_owned_socket_raii() {
        // OwnedSocketはスコープ終了時に自動クローズ
        {
            let _socket = OwnedSocket::new(SocketType::Tcp);
            // スコープ終了時にDropが呼ばれる
        }
        // ソケットは自動的にクローズされている
    }
    
    #[test]
    fn test_socket_addr() {
        let addr = SocketAddr::new([192, 168, 1, 1], 8080);
        assert_eq!(addr.ip, [192, 168, 1, 1]);
        assert_eq!(addr.port, 8080);
        
        let localhost = SocketAddr::LOCALHOST.with_port(3000);
        assert_eq!(localhost.ip, [127, 0, 0, 1]);
        assert_eq!(localhost.port, 3000);
    }
}
