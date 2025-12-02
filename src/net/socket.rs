// ============================================================================
// src/net/socket.rs - BSD-style Socket API
// ============================================================================
//!
//! # ソケットAPI
//!
//! BSD互換のソケットインターフェースを提供。
//!
//! ## 機能
//! - TCP/UDPソケット
//! - 非同期I/O対応
//! - ソケットオプション
//! - マルチプレクシング（select/poll風）
//!
//! ## 型安全性
//! - SocketFd, SocketType等のNewtype
//! - 状態機械によるライフサイクル管理

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;

use super::ipv4::Ipv4Address;

// ============================================================================
// Type-Safe Identifiers (Newtype Pattern)
// ============================================================================

/// ソケットファイルディスクリプタ
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SocketFd(pub u32);

impl SocketFd {
    pub const INVALID: Self = Self(u32::MAX);

    pub const fn new(fd: u32) -> Self {
        Self(fd)
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }

    pub fn is_valid(self) -> bool {
        self != Self::INVALID
    }
}

/// ポート番号
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Port(pub u16);

impl Port {
    pub const fn new(port: u16) -> Self {
        Self(port)
    }

    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// 特権ポートかどうか
    pub fn is_privileged(self) -> bool {
        self.0 < 1024
    }

    /// エフェメラルポートかどうか
    pub fn is_ephemeral(self) -> bool {
        self.0 >= 49152
    }
}

/// バックログサイズ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backlog(pub u32);

impl Backlog {
    pub const DEFAULT: Self = Self(128);
    pub const MAX: Self = Self(4096);

    pub const fn new(size: u32) -> Self {
        Self(if size > Self::MAX.0 { Self::MAX.0 } else { size })
    }
}

// ============================================================================
// Socket Address
// ============================================================================

/// ソケットアドレス（IPv4）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketAddr {
    pub ip: Ipv4Address,
    pub port: Port,
}

impl SocketAddr {
    pub const fn new(ip: Ipv4Address, port: u16) -> Self {
        Self {
            ip,
            port: Port::new(port),
        }
    }

    pub const fn any(port: u16) -> Self {
        Self::new(Ipv4Address::ANY, port)
    }

    pub const fn localhost(port: u16) -> Self {
        Self::new(Ipv4Address::LOOPBACK, port)
    }
}

// ============================================================================
// Socket Types and Options
// ============================================================================

/// ソケットタイプ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketType {
    /// ストリームソケット（TCP）
    Stream,
    /// データグラムソケット（UDP）
    Datagram,
    /// RAWソケット
    Raw,
}

/// アドレスファミリ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressFamily {
    /// IPv4
    Inet,
    /// IPv6
    Inet6,
    /// Unixドメイン
    Unix,
}

/// シャットダウンモード
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShutdownMode {
    /// 読み取りをシャットダウン
    Read,
    /// 書き込みをシャットダウン
    Write,
    /// 両方をシャットダウン
    Both,
}

/// ソケットオプションレベル
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketLevel {
    Socket,
    Tcp,
    Udp,
    Ip,
}

/// ソケットオプション
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketOption {
    // SOL_SOCKET レベル
    ReuseAddr,
    ReusePort,
    KeepAlive,
    Broadcast,
    Linger,
    ReceiveBuffer,
    SendBuffer,
    ReceiveTimeout,
    SendTimeout,
    Error,
    Type,
    // TCP レベル
    TcpNoDelay,
    TcpKeepIdle,
    TcpKeepInterval,
    TcpKeepCount,
    // IP レベル
    IpTtl,
    IpTos,
}

/// ソケットオプション値
#[derive(Clone, Debug)]
pub enum SocketOptionValue {
    Bool(bool),
    Int(i32),
    Timeout(u64),
    Linger { enable: bool, timeout: u32 },
}

// ============================================================================
// Socket State Machine
// ============================================================================

/// TCPソケット状態
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
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

/// ソケット状態
#[derive(Clone, Debug)]
pub enum SocketState {
    /// 未接続
    Unbound,
    /// バインド済み
    Bound {
        local: SocketAddr,
    },
    /// リスニング中（TCPサーバー）
    Listening {
        local: SocketAddr,
        backlog: Backlog,
    },
    /// 接続中（TCP）
    Connecting {
        local: SocketAddr,
        remote: SocketAddr,
    },
    /// 接続済み（TCP）/ アクティブ（UDP）
    Connected {
        local: SocketAddr,
        remote: Option<SocketAddr>,
        tcp_state: Option<TcpState>,
    },
    /// クローズ中
    Closing,
    /// クローズ済み
    Closed,
}

// ============================================================================
// Socket Error
// ============================================================================

/// ソケットエラー
#[derive(Clone, Debug)]
pub enum SocketError {
    /// 無効なソケット
    InvalidSocket,
    /// アドレス使用中
    AddressInUse,
    /// 接続拒否
    ConnectionRefused,
    /// 接続リセット
    ConnectionReset,
    /// タイムアウト
    TimedOut,
    /// ホスト到達不能
    HostUnreachable,
    /// ネットワーク到達不能
    NetworkUnreachable,
    /// バッファ不足
    NoBufferSpace,
    /// 操作がブロックする
    WouldBlock,
    /// 進行中
    InProgress,
    /// 既に接続済み
    AlreadyConnected,
    /// 未接続
    NotConnected,
    /// 無効な引数
    InvalidArgument,
    /// 権限不足
    PermissionDenied,
    /// プロトコルエラー
    ProtocolError,
    /// 内部エラー
    Internal,
}

pub type SocketResult<T> = Result<T, SocketError>;

// ============================================================================
// Socket
// ============================================================================

/// ソケット
pub struct Socket {
    /// ファイルディスクリプタ
    fd: SocketFd,
    /// ソケットタイプ
    socket_type: SocketType,
    /// アドレスファミリ
    family: AddressFamily,
    /// 状態
    state: SocketState,
    /// オプション
    options: SocketOptions,
    /// 受信バッファ
    recv_buffer: Vec<u8>,
    /// 送信バッファ
    send_buffer: Vec<u8>,
    /// 受信待ちのWaker
    recv_waker: Option<Waker>,
    /// 送信待ちのWaker
    send_waker: Option<Waker>,
    /// 接続待ちのWaker
    connect_waker: Option<Waker>,
    /// Accept待ちのWaker
    accept_waker: Option<Waker>,
    /// 保留中の接続（リスニングソケット用）
    pending_connections: Vec<PendingConnection>,
}

/// ソケットオプション
#[derive(Clone, Debug)]
pub struct SocketOptions {
    pub reuse_addr: bool,
    pub reuse_port: bool,
    pub keep_alive: bool,
    pub broadcast: bool,
    pub tcp_no_delay: bool,
    pub recv_buffer_size: u32,
    pub send_buffer_size: u32,
    pub recv_timeout: Option<u64>,
    pub send_timeout: Option<u64>,
    pub linger: Option<u32>,
    pub ttl: u8,
    pub tos: u8,
}

impl Default for SocketOptions {
    fn default() -> Self {
        Self {
            reuse_addr: false,
            reuse_port: false,
            keep_alive: false,
            broadcast: false,
            tcp_no_delay: false,
            recv_buffer_size: 65536,
            send_buffer_size: 65536,
            recv_timeout: None,
            send_timeout: None,
            linger: None,
            ttl: 64,
            tos: 0,
        }
    }
}

/// 保留中の接続
#[derive(Clone)]
pub struct PendingConnection {
    pub remote: SocketAddr,
    pub local: SocketAddr,
    pub syn_received_at: u64,
}

impl Socket {
    /// 新しいソケットを作成
    fn new(fd: SocketFd, socket_type: SocketType, family: AddressFamily) -> Self {
        let options = SocketOptions::default();
        Self {
            fd,
            socket_type,
            family,
            state: SocketState::Unbound,
            options: options.clone(),
            recv_buffer: Vec::with_capacity(options.recv_buffer_size as usize),
            send_buffer: Vec::with_capacity(options.send_buffer_size as usize),
            recv_waker: None,
            send_waker: None,
            connect_waker: None,
            accept_waker: None,
            pending_connections: Vec::new(),
        }
    }

    /// ファイルディスクリプタを取得
    pub fn fd(&self) -> SocketFd {
        self.fd
    }

    /// ソケットタイプを取得
    pub fn socket_type(&self) -> SocketType {
        self.socket_type
    }

    /// アドレスファミリを取得
    pub fn family(&self) -> AddressFamily {
        self.family
    }

    /// 状態を取得
    pub fn state(&self) -> &SocketState {
        &self.state
    }

    /// ローカルアドレスを取得
    pub fn local_addr(&self) -> Option<SocketAddr> {
        match &self.state {
            SocketState::Bound { local } => Some(*local),
            SocketState::Listening { local, .. } => Some(*local),
            SocketState::Connecting { local, .. } => Some(*local),
            SocketState::Connected { local, .. } => Some(*local),
            _ => None,
        }
    }

    /// リモートアドレスを取得
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        match &self.state {
            SocketState::Connecting { remote, .. } => Some(*remote),
            SocketState::Connected { remote, .. } => *remote,
            _ => None,
        }
    }

    /// バインド
    pub fn bind(&mut self, addr: SocketAddr) -> SocketResult<()> {
        match &self.state {
            SocketState::Unbound => {
                // ポートが使用中かチェック（実際の実装では）
                self.state = SocketState::Bound { local: addr };
                Ok(())
            }
            _ => Err(SocketError::InvalidArgument),
        }
    }

    /// リッスン開始（TCPのみ）
    pub fn listen(&mut self, backlog: Backlog) -> SocketResult<()> {
        if self.socket_type != SocketType::Stream {
            return Err(SocketError::InvalidArgument);
        }

        match &self.state {
            SocketState::Bound { local } => {
                self.state = SocketState::Listening {
                    local: *local,
                    backlog,
                };
                Ok(())
            }
            _ => Err(SocketError::InvalidArgument),
        }
    }

    /// 接続（TCPのみ）
    pub fn connect(&mut self, remote: SocketAddr) -> SocketResult<()> {
        if self.socket_type != SocketType::Stream {
            return Err(SocketError::InvalidArgument);
        }

        let local = match &self.state {
            SocketState::Unbound => {
                // エフェメラルポートを割り当て
                let local = SocketAddr::any(allocate_ephemeral_port());
                local
            }
            SocketState::Bound { local } => *local,
            SocketState::Connected { .. } => return Err(SocketError::AlreadyConnected),
            _ => return Err(SocketError::InvalidArgument),
        };

        self.state = SocketState::Connecting { local, remote };

        // 実際にはTCPスタックにSYNを送信する処理が入る
        // ここでは状態遷移のみ

        Ok(())
    }

    /// UDPでリモートアドレスを関連付け
    pub fn connect_udp(&mut self, remote: SocketAddr) -> SocketResult<()> {
        if self.socket_type != SocketType::Datagram {
            return Err(SocketError::InvalidArgument);
        }

        let local = match &self.state {
            SocketState::Unbound => SocketAddr::any(allocate_ephemeral_port()),
            SocketState::Bound { local } => *local,
            SocketState::Connected { local, .. } => *local,
            _ => return Err(SocketError::InvalidArgument),
        };

        self.state = SocketState::Connected {
            local,
            remote: Some(remote),
            tcp_state: None,
        };

        Ok(())
    }

    /// データを送信
    pub fn send(&mut self, data: &[u8]) -> SocketResult<usize> {
        match &self.state {
            SocketState::Connected { .. } => {
                let available = self.options.send_buffer_size as usize - self.send_buffer.len();
                let to_send = data.len().min(available);

                if to_send == 0 {
                    return Err(SocketError::WouldBlock);
                }

                self.send_buffer.extend_from_slice(&data[..to_send]);
                Ok(to_send)
            }
            _ => Err(SocketError::NotConnected),
        }
    }

    /// 指定アドレスにデータを送信（UDP）
    pub fn send_to(&mut self, data: &[u8], addr: SocketAddr) -> SocketResult<usize> {
        if self.socket_type != SocketType::Datagram {
            return Err(SocketError::InvalidArgument);
        }

        match &self.state {
            SocketState::Bound { .. } | SocketState::Connected { .. } | SocketState::Unbound => {
                // バインドされていない場合は自動バインド
                if matches!(self.state, SocketState::Unbound) {
                    let local = SocketAddr::any(allocate_ephemeral_port());
                    self.state = SocketState::Bound { local };
                }

                // 実際にはUDPスタックに送信処理が入る
                Ok(data.len())
            }
            _ => Err(SocketError::InvalidArgument),
        }
    }

    /// データを受信
    pub fn recv(&mut self, buf: &mut [u8]) -> SocketResult<usize> {
        if self.recv_buffer.is_empty() {
            return Err(SocketError::WouldBlock);
        }

        let to_read = buf.len().min(self.recv_buffer.len());
        buf[..to_read].copy_from_slice(&self.recv_buffer[..to_read]);
        self.recv_buffer.drain(..to_read);

        Ok(to_read)
    }

    /// アドレス付きでデータを受信（UDP）
    pub fn recv_from(&mut self, buf: &mut [u8]) -> SocketResult<(usize, SocketAddr)> {
        if self.socket_type != SocketType::Datagram {
            return Err(SocketError::InvalidArgument);
        }

        // 実際にはUDPスタックから受信処理が入る
        Err(SocketError::WouldBlock)
    }

    /// ソケットオプションを設定
    pub fn set_option(&mut self, option: SocketOption, value: SocketOptionValue) -> SocketResult<()> {
        match (option, value) {
            (SocketOption::ReuseAddr, SocketOptionValue::Bool(v)) => {
                self.options.reuse_addr = v;
            }
            (SocketOption::ReusePort, SocketOptionValue::Bool(v)) => {
                self.options.reuse_port = v;
            }
            (SocketOption::KeepAlive, SocketOptionValue::Bool(v)) => {
                self.options.keep_alive = v;
            }
            (SocketOption::Broadcast, SocketOptionValue::Bool(v)) => {
                self.options.broadcast = v;
            }
            (SocketOption::TcpNoDelay, SocketOptionValue::Bool(v)) => {
                self.options.tcp_no_delay = v;
            }
            (SocketOption::ReceiveBuffer, SocketOptionValue::Int(v)) => {
                self.options.recv_buffer_size = v as u32;
            }
            (SocketOption::SendBuffer, SocketOptionValue::Int(v)) => {
                self.options.send_buffer_size = v as u32;
            }
            (SocketOption::ReceiveTimeout, SocketOptionValue::Timeout(v)) => {
                self.options.recv_timeout = if v == 0 { None } else { Some(v) };
            }
            (SocketOption::SendTimeout, SocketOptionValue::Timeout(v)) => {
                self.options.send_timeout = if v == 0 { None } else { Some(v) };
            }
            (SocketOption::Linger, SocketOptionValue::Linger { enable, timeout }) => {
                self.options.linger = if enable { Some(timeout) } else { None };
            }
            (SocketOption::IpTtl, SocketOptionValue::Int(v)) => {
                self.options.ttl = v as u8;
            }
            (SocketOption::IpTos, SocketOptionValue::Int(v)) => {
                self.options.tos = v as u8;
            }
            _ => return Err(SocketError::InvalidArgument),
        }
        Ok(())
    }

    /// ソケットオプションを取得
    pub fn get_option(&self, option: SocketOption) -> SocketResult<SocketOptionValue> {
        match option {
            SocketOption::ReuseAddr => Ok(SocketOptionValue::Bool(self.options.reuse_addr)),
            SocketOption::ReusePort => Ok(SocketOptionValue::Bool(self.options.reuse_port)),
            SocketOption::KeepAlive => Ok(SocketOptionValue::Bool(self.options.keep_alive)),
            SocketOption::Broadcast => Ok(SocketOptionValue::Bool(self.options.broadcast)),
            SocketOption::TcpNoDelay => Ok(SocketOptionValue::Bool(self.options.tcp_no_delay)),
            SocketOption::ReceiveBuffer => Ok(SocketOptionValue::Int(self.options.recv_buffer_size as i32)),
            SocketOption::SendBuffer => Ok(SocketOptionValue::Int(self.options.send_buffer_size as i32)),
            SocketOption::ReceiveTimeout => Ok(SocketOptionValue::Timeout(self.options.recv_timeout.unwrap_or(0))),
            SocketOption::SendTimeout => Ok(SocketOptionValue::Timeout(self.options.send_timeout.unwrap_or(0))),
            SocketOption::Linger => Ok(SocketOptionValue::Linger {
                enable: self.options.linger.is_some(),
                timeout: self.options.linger.unwrap_or(0),
            }),
            SocketOption::IpTtl => Ok(SocketOptionValue::Int(self.options.ttl as i32)),
            SocketOption::IpTos => Ok(SocketOptionValue::Int(self.options.tos as i32)),
            _ => Err(SocketError::InvalidArgument),
        }
    }

    /// シャットダウン
    pub fn shutdown(&mut self, mode: ShutdownMode) -> SocketResult<()> {
        match &self.state {
            SocketState::Connected { .. } => {
                // 実際にはTCP FINを送信する処理が入る
                self.state = SocketState::Closing;
                Ok(())
            }
            _ => Err(SocketError::NotConnected),
        }
    }

    /// クローズ
    pub fn close(&mut self) -> SocketResult<()> {
        self.state = SocketState::Closed;
        self.recv_buffer.clear();
        self.send_buffer.clear();
        Ok(())
    }

    /// 受信バッファにデータを追加（内部用）
    pub(crate) fn push_recv_data(&mut self, data: &[u8]) {
        let available = self.options.recv_buffer_size as usize - self.recv_buffer.len();
        let to_push = data.len().min(available);
        self.recv_buffer.extend_from_slice(&data[..to_push]);

        // Wakerを起動
        if let Some(waker) = self.recv_waker.take() {
            waker.wake();
        }
    }

    /// 接続完了を通知（内部用）
    pub(crate) fn connection_established(&mut self, local: SocketAddr, remote: SocketAddr) {
        self.state = SocketState::Connected {
            local,
            remote: Some(remote),
            tcp_state: Some(TcpState::Established),
        };

        if let Some(waker) = self.connect_waker.take() {
            waker.wake();
        }
    }
}

// ============================================================================
// Async Operations
// ============================================================================

/// 非同期接続Future
pub struct ConnectFuture<'a> {
    socket: &'a mut Socket,
    remote: SocketAddr,
}

impl<'a> Future for ConnectFuture<'a> {
    type Output = SocketResult<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &self.socket.state {
            SocketState::Connected { .. } => Poll::Ready(Ok(())),
            SocketState::Connecting { .. } => {
                self.socket.connect_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            SocketState::Closed => Poll::Ready(Err(SocketError::ConnectionRefused)),
            _ => Poll::Ready(Err(SocketError::InvalidArgument)),
        }
    }
}

/// 非同期受信Future
pub struct RecvFuture<'a> {
    socket: &'a mut Socket,
    buf: &'a mut [u8],
}

impl<'a> Future for RecvFuture<'a> {
    type Output = SocketResult<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if !this.socket.recv_buffer.is_empty() {
            let to_read = this.buf.len().min(this.socket.recv_buffer.len());
            let data: Vec<u8> = this.socket.recv_buffer.drain(..to_read).collect();
            this.buf[..to_read].copy_from_slice(&data);
            return Poll::Ready(Ok(to_read));
        }

        match &this.socket.state {
            SocketState::Connected { .. } | SocketState::Bound { .. } => {
                this.socket.recv_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            SocketState::Closed | SocketState::Closing => {
                Poll::Ready(Ok(0)) // EOF
            }
            _ => Poll::Ready(Err(SocketError::NotConnected)),
        }
    }
}

/// 非同期送信Future
pub struct SendFuture<'a> {
    socket: &'a mut Socket,
    data: &'a [u8],
    sent: usize,
}

impl<'a> Future for SendFuture<'a> {
    type Output = SocketResult<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &self.socket.state {
            SocketState::Connected { .. } => {
                let available = self.socket.options.send_buffer_size as usize
                    - self.socket.send_buffer.len();

                if available > 0 {
                    let remaining = &self.data[self.sent..];
                    let to_send = remaining.len().min(available);
                    self.socket.send_buffer.extend_from_slice(&remaining[..to_send]);
                    self.sent += to_send;

                    if self.sent == self.data.len() {
                        return Poll::Ready(Ok(self.sent));
                    }
                }

                self.socket.send_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            _ => Poll::Ready(Err(SocketError::NotConnected)),
        }
    }
}

// ============================================================================
// Socket Manager
// ============================================================================

/// ソケットマネージャ
pub struct SocketManager {
    /// ソケットマップ
    sockets: BTreeMap<SocketFd, Socket>,
    /// 次のFD
    next_fd: AtomicU32,
    /// エフェメラルポートカウンタ
    next_ephemeral_port: AtomicU32,
    /// バインドされたポート
    bound_ports: Vec<(Port, SocketFd)>,
}

impl SocketManager {
    /// 新しいソケットマネージャを作成
    pub fn new() -> Self {
        Self {
            sockets: BTreeMap::new(),
            next_fd: AtomicU32::new(3), // 0, 1, 2はstdin/stdout/stderr
            next_ephemeral_port: AtomicU32::new(49152),
            bound_ports: Vec::new(),
        }
    }

    /// ソケットを作成
    pub fn socket(&mut self, family: AddressFamily, socket_type: SocketType) -> SocketResult<SocketFd> {
        let fd = SocketFd::new(self.next_fd.fetch_add(1, Ordering::SeqCst));
        let socket = Socket::new(fd, socket_type, family);
        self.sockets.insert(fd, socket);
        Ok(fd)
    }

    /// ソケットを取得
    pub fn get(&self, fd: SocketFd) -> Option<&Socket> {
        self.sockets.get(&fd)
    }

    /// ソケットをミュータブルに取得
    pub fn get_mut(&mut self, fd: SocketFd) -> Option<&mut Socket> {
        self.sockets.get_mut(&fd)
    }

    /// ソケットをクローズ
    pub fn close(&mut self, fd: SocketFd) -> SocketResult<()> {
        if let Some(mut socket) = self.sockets.remove(&fd) {
            socket.close()?;
            
            // バインドされたポートを解放
            if let Some(local) = socket.local_addr() {
                self.bound_ports.retain(|(p, _)| *p != local.port);
            }
        }
        Ok(())
    }

    /// エフェメラルポートを割り当て
    pub fn allocate_ephemeral_port(&self) -> Port {
        let port = self.next_ephemeral_port.fetch_add(1, Ordering::SeqCst);
        if port > 65535 {
            self.next_ephemeral_port.store(49152, Ordering::SeqCst);
        }
        Port::new(port as u16)
    }

    /// ポートがバインド済みかチェック
    pub fn is_port_bound(&self, port: Port) -> bool {
        self.bound_ports.iter().any(|(p, _)| *p == port)
    }

    /// ポートをバインド
    pub fn bind_port(&mut self, port: Port, fd: SocketFd) -> SocketResult<()> {
        if self.is_port_bound(port) {
            return Err(SocketError::AddressInUse);
        }
        self.bound_ports.push((port, fd));
        Ok(())
    }
}

// ============================================================================
// Global State
// ============================================================================

/// グローバルソケットマネージャ
static SOCKET_MANAGER: Mutex<Option<SocketManager>> = Mutex::new(None);

/// エフェメラルポートカウンタ（簡易実装）
static EPHEMERAL_PORT_COUNTER: AtomicU32 = AtomicU32::new(49152);

/// エフェメラルポートを割り当て
fn allocate_ephemeral_port() -> u16 {
    let port = EPHEMERAL_PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    if port > 65535 {
        EPHEMERAL_PORT_COUNTER.store(49152, Ordering::SeqCst);
    }
    port as u16
}

/// ソケットサブシステムを初期化
pub fn init() {
    *SOCKET_MANAGER.lock() = Some(SocketManager::new());
}

/// ソケットを作成
pub fn socket(family: AddressFamily, socket_type: SocketType) -> SocketResult<SocketFd> {
    SOCKET_MANAGER
        .lock()
        .as_mut()
        .ok_or(SocketError::Internal)?
        .socket(family, socket_type)
}

/// ソケットをバインド
pub fn bind(fd: SocketFd, addr: SocketAddr) -> SocketResult<()> {
    let mut guard = SOCKET_MANAGER.lock();
    let manager = guard.as_mut().ok_or(SocketError::Internal)?;

    // ポートをバインド
    if !addr.port.is_privileged() || true {
        // 権限チェックは省略
        manager.bind_port(addr.port, fd)?;
    }

    manager
        .get_mut(fd)
        .ok_or(SocketError::InvalidSocket)?
        .bind(addr)
}

/// リッスン開始
pub fn listen(fd: SocketFd, backlog: u32) -> SocketResult<()> {
    SOCKET_MANAGER
        .lock()
        .as_mut()
        .ok_or(SocketError::Internal)?
        .get_mut(fd)
        .ok_or(SocketError::InvalidSocket)?
        .listen(Backlog::new(backlog))
}

/// 接続
pub fn connect(fd: SocketFd, addr: SocketAddr) -> SocketResult<()> {
    SOCKET_MANAGER
        .lock()
        .as_mut()
        .ok_or(SocketError::Internal)?
        .get_mut(fd)
        .ok_or(SocketError::InvalidSocket)?
        .connect(addr)
}

/// データ送信
pub fn send(fd: SocketFd, data: &[u8]) -> SocketResult<usize> {
    SOCKET_MANAGER
        .lock()
        .as_mut()
        .ok_or(SocketError::Internal)?
        .get_mut(fd)
        .ok_or(SocketError::InvalidSocket)?
        .send(data)
}

/// データ受信
pub fn recv(fd: SocketFd, buf: &mut [u8]) -> SocketResult<usize> {
    SOCKET_MANAGER
        .lock()
        .as_mut()
        .ok_or(SocketError::Internal)?
        .get_mut(fd)
        .ok_or(SocketError::InvalidSocket)?
        .recv(buf)
}

/// ソケットをクローズ
pub fn close(fd: SocketFd) -> SocketResult<()> {
    SOCKET_MANAGER
        .lock()
        .as_mut()
        .ok_or(SocketError::Internal)?
        .close(fd)
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// TCPソケットを作成
pub fn tcp_socket() -> SocketResult<SocketFd> {
    socket(AddressFamily::Inet, SocketType::Stream)
}

/// UDPソケットを作成
pub fn udp_socket() -> SocketResult<SocketFd> {
    socket(AddressFamily::Inet, SocketType::Datagram)
}

/// ソケットオプションを設定
pub fn setsockopt(fd: SocketFd, option: SocketOption, value: SocketOptionValue) -> SocketResult<()> {
    SOCKET_MANAGER
        .lock()
        .as_mut()
        .ok_or(SocketError::Internal)?
        .get_mut(fd)
        .ok_or(SocketError::InvalidSocket)?
        .set_option(option, value)
}

/// ソケットオプションを取得
pub fn getsockopt(fd: SocketFd, option: SocketOption) -> SocketResult<SocketOptionValue> {
    SOCKET_MANAGER
        .lock()
        .as_ref()
        .ok_or(SocketError::Internal)?
        .get(fd)
        .ok_or(SocketError::InvalidSocket)?
        .get_option(option)
}
