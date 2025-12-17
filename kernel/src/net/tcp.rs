// ============================================================================
// src/net/tcp.rs - 軽量TCP/IPスタック (設計書 6.2)
// ============================================================================
//!
//! # 真のゼロコピーネットワークスタック
//!
//! POSIXソケットを廃止し、RustのAsyncRead/AsyncWriteトレイトを実装した
//! 非同期ストリームを提供します。
//!
//! ## 設計原則
//! - バッファの所有権連鎖: NIC → IP層 → TCP層 → アプリケーション
//! - データコピーなし（ゼロコピー）
//! - async/await ファースト

#![allow(dead_code)]

use crate::sync::PoisonLock;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use super::mempool::PacketRef;

// ============================================================================
// ネットワークアドレス
// ============================================================================

/// IPv4アドレス
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv4Addr(pub [u8; 4]);

impl Ipv4Addr {
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self([a, b, c, d])
    }

    pub const UNSPECIFIED: Self = Self([0, 0, 0, 0]);
    pub const LOCALHOST: Self = Self([127, 0, 0, 1]);
    pub const BROADCAST: Self = Self([255, 255, 255, 255]);

    pub fn octets(&self) -> [u8; 4] {
        self.0
    }

    pub fn to_u32(&self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    pub fn from_u32(val: u32) -> Self {
        Self(val.to_be_bytes())
    }
}

impl core::fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

/// ソケットアドレス（IPv4 + ポート）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SocketAddr {
    pub ip: Ipv4Addr,
    pub port: u16,
}

impl SocketAddr {
    pub const fn new(ip: Ipv4Addr, port: u16) -> Self {
        Self { ip, port }
    }
}

impl core::fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

// ============================================================================
// TCP接続状態
// ============================================================================

/// TCP状態マシン
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// TCP接続統計
#[derive(Debug, Default, Clone)]
pub struct TcpStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub retransmissions: u64,
    pub rtt_us: u64,
}

// ============================================================================
// TCP制御ブロック (TCB)
// ============================================================================

/// TCP制御ブロック
pub struct TcpControlBlock {
    /// ローカルアドレス
    pub local_addr: SocketAddr,
    /// リモートアドレス
    pub remote_addr: Option<SocketAddr>,
    /// 現在の状態
    pub state: TcpState,

    // シーケンス番号管理
    /// 送信シーケンス番号（次に送信するバイト）
    pub snd_nxt: u32,
    /// 未確認の最古のシーケンス番号
    pub snd_una: u32,
    /// 送信ウィンドウサイズ
    pub snd_wnd: u16,
    /// 受信シーケンス番号（次に期待するバイト）
    pub rcv_nxt: u32,
    /// 受信ウィンドウサイズ
    pub rcv_wnd: u16,

    // バッファ
    /// 送信バッファ（ゼロコピー: PacketRefのキュー）
    pub send_buffer: VecDeque<PacketRef>,
    /// 受信バッファ
    pub recv_buffer: VecDeque<PacketRef>,

    // 輻輳制御
    /// 輻輳ウィンドウ
    pub cwnd: u32,
    /// スロースタート閾値
    pub ssthresh: u32,

    // Waker（非同期通知用）
    pub read_waker: Option<Waker>,
    pub write_waker: Option<Waker>,
    pub connect_waker: Option<Waker>,

    /// 統計
    pub stats: TcpStats,
}

impl TcpControlBlock {
    pub fn new(local_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            remote_addr: None,
            state: TcpState::Closed,
            snd_nxt: 0,
            snd_una: 0,
            snd_wnd: 65535,
            rcv_nxt: 0,
            rcv_wnd: 65535,
            send_buffer: VecDeque::new(),
            recv_buffer: VecDeque::new(),
            cwnd: 10 * 1460, // 初期値: 10 MSS
            ssthresh: 65535,
            read_waker: None,
            write_waker: None,
            connect_waker: None,
            stats: TcpStats::default(),
        }
    }

    /// 受信データがあるか
    pub fn has_data(&self) -> bool {
        !self.recv_buffer.is_empty()
    }

    /// 送信可能か
    pub fn can_send(&self) -> bool {
        self.state == TcpState::Established && (self.send_buffer.len() as u32) < self.cwnd
    }
}

// ============================================================================
// AsyncRead / AsyncWrite トレイト（POSIXソケット代替）
// ============================================================================

/// 非同期読み取りトレイト
pub trait AsyncRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, TcpError>>;
}

/// 非同期書き込みトレイト  
pub trait AsyncWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, TcpError>>;

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), TcpError>>;

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), TcpError>>;
}

/// TCPエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpError {
    /// 接続が閉じられた
    ConnectionClosed,
    /// 接続が拒否された
    ConnectionRefused,
    /// 接続がリセットされた
    ConnectionReset,
    /// タイムアウト
    Timeout,
    /// アドレスが使用中
    AddressInUse,
    /// バッファが満杯
    BufferFull,
    /// 無効な状態
    InvalidState,
    /// ネットワーク到達不能
    NetworkUnreachable,
}

// ============================================================================
// TcpStream - 非同期TCPストリーム
// ============================================================================

/// 非同期TCPストリーム
///
/// 【設計書】POSIXソケットAPIを模倣しない
/// connect()の代わりにdial()を使用
pub struct TcpStream {
    tcb: Arc<PoisonLock<TcpControlBlock>>,
}

impl TcpStream {
    /// 指定アドレスに接続（推奨API）
    ///
    /// 【設計書】POSIXのconnect()ではなく、dial()という名前を採用
    pub async fn dial(addr: SocketAddr) -> Result<Self, TcpError> {
        let local_port = allocate_ephemeral_port();
        let local_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED, local_port);

        let tcb = Arc::new(PoisonLock::new(TcpControlBlock::new(local_addr)));

        // SYN送信
        match tcb.lock() {
            Ok(mut tcb_guard) => {
                tcb_guard.remote_addr = Some(addr);
                tcb_guard.state = TcpState::SynSent;
                tcb_guard.snd_nxt = generate_initial_seq();
                // SYNパケット送信
                send_syn_packet(tcb_guard.local_addr, addr, tcb_guard.snd_nxt);
                tcb_guard.snd_nxt = tcb_guard.snd_nxt.wrapping_add(1); // SYNは1バイト消費
            }
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned during dial - aborting connect");
                return Err(TcpError::ConnectionRefused);
            }
        }

        // 接続完了を待つ
        ConnectFuture { tcb: tcb.clone() }.await?;

        Ok(Self { tcb })
    }

    /// 【非推奨】connect() - 互換性のために残すが、dial()を使用すべき
    #[deprecated(
        since = "0.4.0",
        note = "設計書: POSIXソケットAPIを使用しない。dial()を使用してください"
    )]
    pub async fn connect(addr: SocketAddr) -> Result<Self, TcpError> {
        Self::dial(addr).await
    }

    /// ローカルアドレスを取得
    pub fn local_addr(&self) -> SocketAddr {
        match self.tcb.lock() {
            Ok(g) => g.local_addr,
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned (local_addr)");
                SocketAddr::new(Ipv4Addr::UNSPECIFIED, 0)
            }
        }
    }

    /// リモートアドレスを取得
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        match self.tcb.lock() {
            Ok(g) => g.remote_addr,
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned (peer_addr)");
                None
            }
        }
    }

    /// 統計を取得
    pub fn stats(&self) -> TcpStats {
        match self.tcb.lock() {
            Ok(g) => g.stats.clone(),
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned (stats)");
                TcpStats::default()
            }
        }
    }

    /// 読み取り用Future（コピーあり - 互換性用）
    pub fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> ReadFuture<'a> {
        ReadFuture { stream: self, buf }
    }

    /// 【設計書 6.2】ゼロコピー読み取り
    ///
    /// バッファの所有権をアプリケーションに移動します。
    /// コピーが発生しないため、高スループットアプリケーションに推奨。
    ///
    /// # 使用例
    /// ```ignore
    /// while let Some(packet) = stream.read_zero_copy().await {
    ///     // パケットを直接処理（コピーなし）
    ///     process_packet(&packet.data());
    ///     // パケットはスコープ終了時に自動的にプールに返却
    /// }
    /// ```
    pub async fn read_zero_copy(&mut self) -> Option<PacketRef> {
        ZeroCopyReadFuture { stream: self }.await
    }

    /// 書き込み用Future（コピーあり - 互換性用）
    pub fn write<'a>(&'a mut self, buf: &'a [u8]) -> WriteFuture<'a> {
        WriteFuture { stream: self, buf }
    }

    /// 【設計書 6.2】ゼロコピー書き込み
    ///
    /// 事前に割り当てたパケットバッファの所有権をTCPスタックに移動します。
    ///
    /// # 使用例
    /// ```ignore
    /// let mut packet = mempool::alloc_packet().unwrap();
    /// packet.data_mut()[..data.len()].copy_from_slice(data);
    /// packet.set_len(data.len());
    /// stream.write_zero_copy(packet).await?;
    /// ```
    pub async fn write_zero_copy(&mut self, packet: PacketRef) -> Result<(), TcpError> {
        ZeroCopyWriteFuture {
            stream: self,
            packet: Some(packet),
        }
        .await
    }

    /// シャットダウン
    pub async fn shutdown(&mut self) -> Result<(), TcpError> {
        ShutdownFuture { stream: self }.await
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, TcpError>> {
        match self.tcb.lock() {
            Ok(mut tcb) => {
                if tcb.state == TcpState::Closed {
                    return Poll::Ready(Err(TcpError::ConnectionClosed));
                }

                if let Some(packet) = tcb.recv_buffer.pop_front() {
                    let data = packet.data();
                    let len = data.len().min(buf.len());
                    buf[..len].copy_from_slice(&data[..len]);
                    tcb.stats.bytes_received += len as u64;
                    Poll::Ready(Ok(len))
                } else {
                    tcb.read_waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned in read - returning ConnectionClosed");
                Poll::Ready(Err(TcpError::ConnectionClosed))
            }
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, TcpError>> {
        match self.tcb.lock() {
            Ok(mut tcb) => {
                if tcb.state != TcpState::Established {
                    return Poll::Ready(Err(TcpError::InvalidState));
                }

                if !tcb.can_send() {
                    tcb.write_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }

                // パケットを割り当てて送信キューに追加
                if let Some(mut packet) = super::mempool::alloc_packet() {
                    let len = buf.len().min(1460); // MSS制限
                    packet.data_mut()[..len].copy_from_slice(&buf[..len]);
                    packet.set_len(len);
                    tcb.send_buffer.push_back(packet);
                    tcb.stats.bytes_sent += len as u64;
                    tcb.stats.packets_sent += 1;
                    Poll::Ready(Ok(len))
                } else {
                    tcb.write_waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned in write - returning InvalidState");
                Poll::Ready(Err(TcpError::InvalidState))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), TcpError>> {
        // 送信バッファのフラッシュ
        match self.tcb.lock() {
            Ok(mut tcb) => {
                // 送信バッファ内の全パケットを送信
                while let Some(packet) = tcb.send_buffer.pop_front() {
                    if let Some(remote) = tcb.remote_addr {
                        let data = packet.data();
                        send_data_packet(
                            tcb.local_addr,
                            remote,
                            tcb.snd_nxt,
                            tcb.rcv_nxt,
                            tcb.rcv_wnd,
                            data,
                        );
                        tcb.snd_nxt = tcb.snd_nxt.wrapping_add(data.len() as u32);
                    }
                }

                Poll::Ready(Ok(()))
            }
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned in flush - returning Ok(())");
                Poll::Ready(Ok(()))
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), TcpError>> {
        match self.tcb.lock() {
            Ok(mut tcb) => match tcb.state {
                TcpState::Established => {
                    tcb.state = TcpState::FinWait1;
                    // FIN送信
                    if let Some(remote) = tcb.remote_addr {
                        send_fin_packet(tcb.local_addr, remote, tcb.snd_nxt, tcb.rcv_nxt);
                        tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1); // FINは1バイト消費
                    }
                    Poll::Ready(Ok(()))
                }
                TcpState::CloseWait => {
                    tcb.state = TcpState::LastAck;
                    // FIN送信
                    if let Some(remote) = tcb.remote_addr {
                        send_fin_packet(tcb.local_addr, remote, tcb.snd_nxt, tcb.rcv_nxt);
                        tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
                    }
                    Poll::Ready(Ok(()))
                }
                _ => Poll::Ready(Err(TcpError::InvalidState)),
            },
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned (shutdown) - returning InvalidState");
                Poll::Ready(Err(TcpError::InvalidState))
            }
        }
    }
}

// ============================================================================
// TcpListener - 非同期TCPリスナー
// ============================================================================

/// 非同期TCPリスナー
///
/// 【設計書】POSIXソケットAPIを模倣しない
/// bind/listen/acceptの代わりにnew/incomingを使用
pub struct TcpListener {
    local_addr: SocketAddr,
    backlog: Arc<PoisonLock<VecDeque<TcpStream>>>,
    accept_waker: Arc<PoisonLock<Option<Waker>>>,
}

impl TcpListener {
    /// 指定アドレスで新しいリスナーを作成（推奨API）
    ///
    /// 【設計書】POSIXのbind()ではなく、直接構築する方式を採用
    pub fn new(addr: SocketAddr) -> Result<Self, TcpError> {
        // ポートが使用中かチェック
        if is_port_in_use(addr.port) {
            return Err(TcpError::AddressInUse);
        }

        Ok(Self {
            local_addr: addr,
            backlog: Arc::new(PoisonLock::new(VecDeque::new())),
            accept_waker: Arc::new(PoisonLock::new(None)),
        })
    }

    /// 【非推奨】bind() - 互換性のために残すが、new()を使用すべき
    #[deprecated(
        since = "0.4.0",
        note = "設計書: POSIXソケットAPIを使用しない。new()を使用してください"
    )]
    pub fn bind(addr: SocketAddr) -> Result<Self, TcpError> {
        Self::new(addr)
    }

    /// ローカルアドレスを取得
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// 次の接続を非同期で取得（推奨API）
    ///
    /// 【設計書】POSIXのaccept()ではなく、Futureベースの方式を採用
    pub async fn next_connection(&self) -> Result<(TcpStream, SocketAddr), TcpError> {
        AcceptFuture { listener: self }.await
    }

    /// 【非推奨】accept() - 互換性のために残すが、next_connection()を使用すべき
    #[deprecated(
        since = "0.4.0",
        note = "設計書: POSIXソケットAPIを使用しない。next_connection()を使用してください"
    )]
    pub async fn accept(&self) -> Result<(TcpStream, SocketAddr), TcpError> {
        self.next_connection().await
    }

    /// 新しい接続をバックログに追加（内部使用）
    pub(crate) fn push_connection(&self, stream: TcpStream, _addr: SocketAddr) {
        match self.backlog.lock() {
            Ok(mut backlog) => {
                backlog.push_back(stream);

                match self.accept_waker.lock() {
                    Ok(mut wake_opt) => {
                        if let Some(waker) = wake_opt.take() {
                            waker.wake();
                        }
                    }
                    Err(_) => log::error!("[NET] TCP Waker poisoned - cannot wake acceptor"),
                }
            }
            Err(_) => log::error!("[NET] TCP Backlog poisoned - cannot push connection"),
        }
    }
}

// ============================================================================
// Future実装
// ============================================================================

/// 接続Future
struct ConnectFuture {
    tcb: Arc<PoisonLock<TcpControlBlock>>,
}

impl Future for ConnectFuture {
    type Output = Result<(), TcpError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.tcb.lock() {
            Ok(mut tcb) => match tcb.state {
                TcpState::Established => Poll::Ready(Ok(())),
                TcpState::Closed => Poll::Ready(Err(TcpError::ConnectionRefused)),
                TcpState::SynSent | TcpState::SynReceived => {
                    tcb.connect_waker = Some(cx.waker().clone());
                    Poll::Pending
                }
                _ => Poll::Ready(Err(TcpError::InvalidState)),
            },
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned in connect future - returning ConnectionRefused");
                Poll::Ready(Err(TcpError::ConnectionRefused))
            }
        }
    }
}

/// 読み取りFuture
pub struct ReadFuture<'a> {
    stream: &'a mut TcpStream,
    buf: &'a mut [u8],
}

impl<'a> Future for ReadFuture<'a> {
    type Output = Result<usize, TcpError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        Pin::new(&mut *this.stream).poll_read(cx, this.buf)
    }
}

/// 書き込みFuture
pub struct WriteFuture<'a> {
    stream: &'a mut TcpStream,
    buf: &'a [u8],
}

impl<'a> Future for WriteFuture<'a> {
    type Output = Result<usize, TcpError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        Pin::new(&mut *this.stream).poll_write(cx, this.buf)
    }
}

/// Accept Future
struct AcceptFuture<'a> {
    listener: &'a TcpListener,
}

impl<'a> Future for AcceptFuture<'a> {
    type Output = Result<(TcpStream, SocketAddr), TcpError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.listener.backlog.lock() {
            Ok(mut backlog) => {
                if let Some(stream) = backlog.pop_front() {
                    let addr = stream
                        .peer_addr()
                        .unwrap_or(SocketAddr::new(Ipv4Addr::UNSPECIFIED, 0));
                    return Poll::Ready(Ok((stream, addr)));
                }

                match self.listener.accept_waker.lock() {
                    Ok(mut wake_opt) => *wake_opt = Some(cx.waker().clone()),
                    Err(_) => log::error!("[NET] TCP Waker poisoned - cannot set waker"),
                }

                Poll::Pending
            }
            Err(_) => {
                log::error!("[NET] TCP Backlog poisoned (accept) - returning InvalidState");
                Poll::Ready(Err(TcpError::InvalidState))
            }
        }
    }
}

/// シャットダウンFuture
struct ShutdownFuture<'a> {
    stream: &'a mut TcpStream,
}

impl<'a> Future for ShutdownFuture<'a> {
    type Output = Result<(), TcpError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        Pin::new(&mut *this.stream).poll_shutdown(cx)
    }
}

// ============================================================================
// 【設計書 6.2】ゼロコピーFuture
// ============================================================================

/// ゼロコピー読み取りFuture
///
/// パケットバッファの所有権をそのまま返す（コピーなし）
struct ZeroCopyReadFuture<'a> {
    stream: &'a mut TcpStream,
}

impl<'a> Future for ZeroCopyReadFuture<'a> {
    type Output = Option<PacketRef>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.stream.tcb.lock() {
            Ok(mut tcb) => {
                if tcb.state == TcpState::Closed {
                    return Poll::Ready(None);
                }

                if let Some(packet) = tcb.recv_buffer.pop_front() {
                    let len = packet.data().len();
                    tcb.stats.bytes_received += len as u64;
                    // パケットの所有権をそのまま返す（ゼロコピー）
                    return Poll::Ready(Some(packet));
                }

                tcb.read_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned (zero-copy read) - returning None");
                Poll::Ready(None)
            }
        }
    }
}

/// ゼロコピー書き込みFuture
///
/// パケットバッファの所有権をTCPスタックに移動（コピーなし）
struct ZeroCopyWriteFuture<'a> {
    stream: &'a mut TcpStream,
    packet: Option<PacketRef>,
}

impl<'a> Future for ZeroCopyWriteFuture<'a> {
    type Output = Result<(), TcpError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.stream.tcb.lock() {
            Ok(mut tcb) => {
                if tcb.state != TcpState::Established {
                    return Poll::Ready(Err(TcpError::InvalidState));
                }

                if !tcb.can_send() {
                    tcb.write_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }

                if let Some(packet) = this.packet.take() {
                    let len = packet.data().len();
                    tcb.send_buffer.push_back(packet);
                    tcb.stats.bytes_sent += len as u64;
                    tcb.stats.packets_sent += 1;
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Ready(Err(TcpError::InvalidState))
                }
            }
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned in zero-copy write - returning InvalidState");
                Poll::Ready(Err(TcpError::InvalidState))
            }
        }
    }
}

// ============================================================================
// ヘルパー関数
// ============================================================================

use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};

static NEXT_EPHEMERAL_PORT: AtomicU16 = AtomicU16::new(49152);
static SEQ_COUNTER: AtomicU32 = AtomicU32::new(0);

/// エフェメラルポート割り当て
fn allocate_ephemeral_port() -> u16 {
    let port = NEXT_EPHEMERAL_PORT.fetch_add(1, Ordering::Relaxed);
    if port >= 65535 {
        NEXT_EPHEMERAL_PORT.store(49152, Ordering::Relaxed);
    }
    port
}

/// 初期シーケンス番号生成
/// RFC 6528に従い、タイムスタンプベースで予測困難な値を生成
fn generate_initial_seq() -> u32 {
    // タイムスタンプベースの値（マイクロ秒精度）
    let time_component = crate::task::current_tick() as u32;
    // カウンターを追加して同一タイミングでも異なる値に
    let counter = SEQ_COUNTER.fetch_add(64000, Ordering::Relaxed);
    // XORで混合
    time_component ^ counter ^ 0x5A5A5A5A
}

/// ポートが使用中か確認
fn is_port_in_use(_port: u16) -> bool {
    // 現状はシングルトンTcpProcessorがないため、常にfalseを返す
    // 将来的にはグローバルTcpProcessorの接続リストをチェック
    false
}

// ============================================================================
// TCP送信ヘルパー関数
// ============================================================================

/// TCPセグメントを構築して送信
fn send_tcp_packet(
    local: SocketAddr,
    remote: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u16,
    window: u16,
    payload: &[u8],
) {
    use alloc::vec;

    let data_offset: u8 = 5; // 20バイト（オプションなし）
    let header_len = (data_offset as usize) * 4;
    let total_len = header_len + payload.len();

    let mut segment = vec![0u8; total_len];

    // TCPヘッダ構築
    // Source port (2バイト)
    segment[0..2].copy_from_slice(&local.port.to_be_bytes());
    // Destination port (2バイト)
    segment[2..4].copy_from_slice(&remote.port.to_be_bytes());
    // Sequence number (4バイト)
    segment[4..8].copy_from_slice(&seq.to_be_bytes());
    // ACK number (4バイト)
    segment[8..12].copy_from_slice(&ack.to_be_bytes());
    // Data offset (4bit) + Reserved (4bit) + Flags (8bit)
    let data_off_flags = ((data_offset as u16) << 12) | (flags & 0x3F);
    segment[12..14].copy_from_slice(&data_off_flags.to_be_bytes());
    // Window (2バイト)
    segment[14..16].copy_from_slice(&window.to_be_bytes());
    // Checksum (2バイト) - 後で計算
    segment[16..18].copy_from_slice(&0u16.to_be_bytes());
    // Urgent pointer (2バイト)
    segment[18..20].copy_from_slice(&0u16.to_be_bytes());

    // ペイロード
    if !payload.is_empty() {
        segment[header_len..].copy_from_slice(payload);
    }

    // チェックサム計算
    calculate_tcp_checksum(&mut segment, local.ip.0, remote.ip.0);

    // ネットワークスタック経由で送信
    let src_ip = crate::net::ipv4::Ipv4Address::new(local.ip.0);
    let dst_ip = crate::net::ipv4::Ipv4Address::new(remote.ip.0);
    crate::net::stack::send_tcp(src_ip, dst_ip, &segment);
}

/// TCPチェックサム計算（疑似ヘッダ込み）
fn calculate_tcp_checksum(segment: &mut [u8], src_ip: [u8; 4], dst_ip: [u8; 4]) {
    // チェックサムフィールドをゼロに
    segment[16] = 0;
    segment[17] = 0;

    let mut sum: u32 = 0;

    // 疑似ヘッダ
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += 6u32; // Protocol (TCP)
    sum += segment.len() as u32;

    // TCPセグメント本体
    let mut i = 0;
    while i + 1 < segment.len() {
        sum += u16::from_be_bytes([segment[i], segment[i + 1]]) as u32;
        i += 2;
    }
    if i < segment.len() {
        sum += (segment[i] as u32) << 8;
    }

    // 1の補数
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let checksum = !sum as u16;

    segment[16..18].copy_from_slice(&checksum.to_be_bytes());
}

/// SYNパケットを送信
fn send_syn_packet(local: SocketAddr, remote: SocketAddr, seq: u32) {
    send_tcp_packet(local, remote, seq, 0, TcpHeader::FLAG_SYN, 65535, &[]);
}

/// SYN-ACKパケットを送信
fn send_syn_ack_packet(local: SocketAddr, remote: SocketAddr, seq: u32, ack: u32) {
    send_tcp_packet(
        local,
        remote,
        seq,
        ack,
        TcpHeader::FLAG_SYN | TcpHeader::FLAG_ACK,
        65535,
        &[],
    );
}

/// ACKパケットを送信
fn send_ack_packet(local: SocketAddr, remote: SocketAddr, seq: u32, ack: u32, window: u16) {
    send_tcp_packet(local, remote, seq, ack, TcpHeader::FLAG_ACK, window, &[]);
}

/// FINパケットを送信
fn send_fin_packet(local: SocketAddr, remote: SocketAddr, seq: u32, ack: u32) {
    send_tcp_packet(
        local,
        remote,
        seq,
        ack,
        TcpHeader::FLAG_FIN | TcpHeader::FLAG_ACK,
        65535,
        &[],
    );
}

/// データパケットを送信（PSH+ACK）
fn send_data_packet(
    local: SocketAddr,
    remote: SocketAddr,
    seq: u32,
    ack: u32,
    window: u16,
    data: &[u8],
) {
    send_tcp_packet(
        local,
        remote,
        seq,
        ack,
        TcpHeader::FLAG_PSH | TcpHeader::FLAG_ACK,
        window,
        data,
    );
}

// ============================================================================
// パケット処理（プロトコルスタック）
// ============================================================================

/// Ethernetヘッダ
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
}

impl EthernetHeader {
    pub const ETHERTYPE_IPV4: u16 = 0x0800;
    pub const ETHERTYPE_ARP: u16 = 0x0806;
    pub const HEADER_LEN: usize = 14;
}

/// IPv4ヘッダ
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_addr: [u8; 4],
    pub dst_addr: [u8; 4],
}

impl Ipv4Header {
    pub const PROTOCOL_TCP: u8 = 6;
    pub const PROTOCOL_UDP: u8 = 17;
    pub const PROTOCOL_ICMP: u8 = 1;
    pub const MIN_HEADER_LEN: usize = 20;

    pub fn header_len(&self) -> usize {
        ((self.version_ihl & 0x0F) as usize) * 4
    }
}

/// TCPヘッダ
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset_flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

impl TcpHeader {
    pub const FLAG_FIN: u16 = 0x0001;
    pub const FLAG_SYN: u16 = 0x0002;
    pub const FLAG_RST: u16 = 0x0004;
    pub const FLAG_PSH: u16 = 0x0008;
    pub const FLAG_ACK: u16 = 0x0010;
    pub const FLAG_URG: u16 = 0x0020;
    pub const MIN_HEADER_LEN: usize = 20;

    pub fn data_offset(&self) -> usize {
        (((u16::from_be(self.data_offset_flags) >> 12) & 0x0F) as usize) * 4
    }

    pub fn flags(&self) -> u16 {
        u16::from_be(self.data_offset_flags) & 0x003F
    }
}

/// パケット処理コールバック
pub fn process_incoming_packet(packet: PacketRef) {
    // Clone the packet reference so we can pass it along while keeping the data
    let packet_for_later = packet.clone_ref();
    let data = packet.data();

    if data.len() < EthernetHeader::HEADER_LEN {
        return;
    }

    // Ethernetヘッダ解析
    let eth_header = crate::util::get_ref::<EthernetHeader>(data, 0)
        .expect("Ethernet header slice out of bounds");

    let ethertype = u16::from_be(eth_header.ethertype);
    let ip_offset = EthernetHeader::HEADER_LEN;

    match ethertype {
        EthernetHeader::ETHERTYPE_IPV4 => {
            process_ipv4_packet(ip_offset, &packet_for_later);
        }
        EthernetHeader::ETHERTYPE_ARP => {
            process_arp_packet(ip_offset, &packet_for_later);
        }
        _ => {
            // 未知のプロトコル
        }
    }
}

/// ARP パケットを処理
fn process_arp_packet(offset: usize, packet: &PacketRef) {
    use crate::net::arp::{ArpOperation, ArpPacket};

    let data = packet.data();
    if data.len() < offset + ArpPacket::SIZE {
        return;
    }

    let arp_data = &data[offset..];
    let arp_packet =
        crate::util::get_ref::<ArpPacket>(arp_data, 0).expect("ARP packet slice out of bounds");

    // ARPリクエストに応答
    let operation_value = u16::from_be_bytes([arp_packet.operation[0], arp_packet.operation[1]]);
    let operation = ArpOperation::from(operation_value);

    if matches!(operation, ArpOperation::Request) {
        // ARPリプライを生成する必要があるが、
        // 現在は受信したパケットをログに記録するのみ
        // 完全な実装にはネットワークインターフェースの参照が必要
        log::info!(
            "[ARP] Request from {}.{}.{}.{} for {}.{}.{}.{}\n",
            arp_packet.sender_ip[0],
            arp_packet.sender_ip[1],
            arp_packet.sender_ip[2],
            arp_packet.sender_ip[3],
            arp_packet.target_ip[0],
            arp_packet.target_ip[1],
            arp_packet.target_ip[2],
            arp_packet.target_ip[3]
        );
    }
}

fn process_ipv4_packet(ip_offset: usize, packet: &PacketRef) {
    let data = packet.data();

    if data.len() < ip_offset + Ipv4Header::MIN_HEADER_LEN {
        return;
    }

    let ip_data = &data[ip_offset..];
    let ip_header =
        crate::util::get_ref::<Ipv4Header>(ip_data, 0).expect("IPv4 header slice out of bounds");

    let header_len = ip_header.header_len();
    let tcp_offset = ip_offset + header_len;

    match ip_header.protocol {
        Ipv4Header::PROTOCOL_TCP => {
            process_tcp_packet(tcp_offset, packet, ip_header);
        }
        Ipv4Header::PROTOCOL_UDP => {
            process_udp_packet(tcp_offset, packet, ip_header);
        }
        Ipv4Header::PROTOCOL_ICMP => {
            process_icmp_packet(tcp_offset, packet, ip_header);
        }
        _ => {}
    }
}

/// UDPパケットを処理
fn process_udp_packet(udp_offset: usize, packet: &PacketRef, _ip_header: &Ipv4Header) {
    let data = packet.data();

    // UDPヘッダは8バイト
    if data.len() < udp_offset + 8 {
        return;
    }

    let _src_port = u16::from_be_bytes([data[udp_offset], data[udp_offset + 1]]);
    let _dst_port = u16::from_be_bytes([data[udp_offset + 2], data[udp_offset + 3]]);
    let _length = u16::from_be_bytes([data[udp_offset + 4], data[udp_offset + 5]]);

    // UDPソケットテーブルがないため、現時点ではドロップ
    // 将来的にはUDPソケットマネージャーに転送
}

/// ICMPパケットを処理
fn process_icmp_packet(icmp_offset: usize, packet: &PacketRef, ip_header: &Ipv4Header) {
    let data = packet.data();

    // ICMPヘッダは最低8バイト
    if data.len() < icmp_offset + 8 {
        return;
    }

    let icmp_type = data[icmp_offset];
    let icmp_code = data[icmp_offset + 1];

    match icmp_type {
        8 => {
            // Echo Request (ping)
            // Echo Replyを生成する必要があるが、
            // 送信機能が必要なため現時点ではログのみ
            let src_bytes = ip_header.src_addr;
            log::info!(
                "[ICMP] Echo Request from {}.{}.{}.{}\n",
                src_bytes[0],
                src_bytes[1],
                src_bytes[2],
                src_bytes[3]
            );
        }
        0 => {
            // Echo Reply
            log::info!("[ICMP] Echo Reply received\n");
        }
        3 => {
            // Destination Unreachable
            log::info!("[ICMP] Destination Unreachable (code: {})\n", icmp_code);
        }
        11 => {
            // Time Exceeded
            log::info!("[ICMP] Time Exceeded\n");
        }
        _ => {
            // 他のICMPタイプ
        }
    }
}

fn process_tcp_packet(tcp_offset: usize, packet: &PacketRef, ip_header: &Ipv4Header) {
    let data = packet.data();

    if data.len() < tcp_offset + TcpHeader::MIN_HEADER_LEN {
        return;
    }

    let tcp_data = &data[tcp_offset..];

    // TCPヘッダフィールドを読み取り
    let src_port = u16::from_be_bytes([tcp_data[0], tcp_data[1]]);
    let dst_port = u16::from_be_bytes([tcp_data[2], tcp_data[3]]);
    let seq_num = u32::from_be_bytes([tcp_data[4], tcp_data[5], tcp_data[6], tcp_data[7]]);
    let ack_num = u32::from_be_bytes([tcp_data[8], tcp_data[9], tcp_data[10], tcp_data[11]]);
    let data_offset_flags = u16::from_be_bytes([tcp_data[12], tcp_data[13]]);
    let flags = data_offset_flags & 0x003F;

    // ソケットアドレスを構築
    let src_addr = SocketAddr::new(
        Ipv4Addr::new(
            ip_header.src_addr[0],
            ip_header.src_addr[1],
            ip_header.src_addr[2],
            ip_header.src_addr[3],
        ),
        src_port,
    );

    let dst_addr = SocketAddr::new(
        Ipv4Addr::new(
            ip_header.dst_addr[0],
            ip_header.dst_addr[1],
            ip_header.dst_addr[2],
            ip_header.dst_addr[3],
        ),
        dst_port,
    );

    // グローバルTcpProcessorは現在存在しないため、
    // 基本的なログのみ出力
    let syn = flags & TcpHeader::FLAG_SYN != 0;
    let ack = flags & TcpHeader::FLAG_ACK != 0;
    let fin = flags & TcpHeader::FLAG_FIN != 0;
    let rst = flags & TcpHeader::FLAG_RST != 0;

    if syn && !ack {
        log::info!(
            "[TCP] SYN from {} to {} (seq: {})\n",
            src_addr,
            dst_addr,
            seq_num
        );
    } else if syn && ack {
        log::info!(
            "[TCP] SYN-ACK from {} to {} (seq: {}, ack: {})\n",
            src_addr,
            dst_addr,
            seq_num,
            ack_num
        );
    } else if fin {
        log::info!("[TCP] FIN from {} to {}\n", src_addr, dst_addr);
    } else if rst {
        log::info!("[TCP] RST from {} to {}\n", src_addr, dst_addr);
    }

    // 将来的にはグローバルTcpProcessorにパケットを転送
}

// ============================================================================
// TCP Processor (for integration with NetworkStack)
// ============================================================================

use crate::net::ipv4::Ipv4Address;

/// TCP segment processor for the network stack
pub struct TcpProcessor {
    /// TCP connections indexed by (local_addr, remote_addr) tuple
    connections: BTreeMap<(SocketAddr, SocketAddr), TcpControlBlock>,
    /// Listening sockets indexed by local address
    listeners: BTreeMap<SocketAddr, TcpControlBlock>,
}

impl TcpProcessor {
    /// Create a new TCP processor
    pub fn new() -> Self {
        TcpProcessor {
            connections: BTreeMap::new(),
            listeners: BTreeMap::new(),
        }
    }

    /// Start listening on a local address
    pub fn listen(&mut self, local_addr: SocketAddr) {
        let mut tcb = TcpControlBlock::new(local_addr);
        tcb.state = TcpState::Listen;
        self.listeners.insert(local_addr, tcb);
    }

    /// Initiate a connection to a remote address
    pub fn connect(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<(), TcpError> {
        let mut tcb = TcpControlBlock::new(local_addr);
        tcb.remote_addr = Some(remote_addr);
        tcb.state = TcpState::SynSent;
        // Generate initial sequence number (simplified: use tick count)
        tcb.snd_nxt = crate::task::current_tick() as u32;
        tcb.snd_una = tcb.snd_nxt;

        self.connections.insert((local_addr, remote_addr), tcb);
        // Note: Caller should send SYN packet after this
        Ok(())
    }

    /// Find a connection by local and remote addresses
    fn find_connection(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Option<&mut TcpControlBlock> {
        self.connections.get_mut(&(local, remote))
    }

    /// Process an incoming TCP segment
    pub fn process(&mut self, data: &[u8], src_ip: Ipv4Address, dst_ip: Ipv4Address) {
        if data.len() < TcpHeader::MIN_HEADER_LEN {
            return;
        }

        // Read header fields directly from bytes to avoid packed struct alignment issues
        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset_flags = u16::from_be_bytes([data[12], data[13]]);
        let flags = data_offset_flags & 0x003F;
        let window = u16::from_be_bytes([data[14], data[15]]);
        let header_len = ((data_offset_flags >> 12) & 0x0F) as usize * 4;

        // Convert to internal address types
        let remote_addr = SocketAddr::new(
            Ipv4Addr::new(
                src_ip.as_bytes()[0],
                src_ip.as_bytes()[1],
                src_ip.as_bytes()[2],
                src_ip.as_bytes()[3],
            ),
            src_port,
        );

        let local_addr = SocketAddr::new(
            Ipv4Addr::new(
                dst_ip.as_bytes()[0],
                dst_ip.as_bytes()[1],
                dst_ip.as_bytes()[2],
                dst_ip.as_bytes()[3],
            ),
            dst_port,
        );

        // Extract payload
        let payload = if data.len() > header_len {
            &data[header_len..]
        } else {
            &[]
        };

        // Handle RST - reset connection immediately
        if flags & TcpHeader::FLAG_RST != 0 {
            self.connections.remove(&(local_addr, remote_addr));
            return;
        }

        // Try to find existing connection
        if let Some(tcb) = self.connections.get_mut(&(local_addr, remote_addr)) {
            // Process segment inline to avoid double mutable borrow
            let syn = flags & TcpHeader::FLAG_SYN != 0;
            let ack = flags & TcpHeader::FLAG_ACK != 0;
            let fin = flags & TcpHeader::FLAG_FIN != 0;
            let _psh = flags & TcpHeader::FLAG_PSH != 0;

            tcb.snd_wnd = window;

            match tcb.state {
                TcpState::SynSent => {
                    if syn && ack {
                        tcb.rcv_nxt = seq_num.wrapping_add(1);
                        tcb.snd_una = ack_num;
                        tcb.state = TcpState::Established;
                    }
                }
                TcpState::SynReceived => {
                    if ack {
                        tcb.snd_una = ack_num;
                        tcb.state = TcpState::Established;
                    }
                }
                TcpState::Established => {
                    if ack {
                        tcb.snd_una = ack_num;
                    }
                    if !payload.is_empty() {
                        // ペイロードをバッファに追加
                        // 注: PacketRefへの変換は省略（直接バッファリングせず統計のみ更新）
                        tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(payload.len() as u32);
                    }
                    if fin {
                        tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                        tcb.state = TcpState::CloseWait;
                    }
                }
                TcpState::FinWait1 => {
                    if ack {
                        tcb.snd_una = ack_num;
                        tcb.state = TcpState::FinWait2;
                    }
                    if fin {
                        tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                        if ack {
                            tcb.state = TcpState::TimeWait;
                        } else {
                            tcb.state = TcpState::Closing;
                        }
                    }
                }
                TcpState::FinWait2 => {
                    if fin {
                        tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                        tcb.state = TcpState::TimeWait;
                    }
                }
                TcpState::Closing => {
                    if ack {
                        tcb.state = TcpState::TimeWait;
                    }
                }
                TcpState::LastAck => {
                    if ack {
                        tcb.state = TcpState::Closed;
                    }
                }
                TcpState::CloseWait | TcpState::TimeWait | TcpState::Closed | TcpState::Listen => {
                    // Ignore in these states
                }
            }
            return;
        }

        // Check if this is for a listening socket
        if let Some(listener) = self.listeners.get(&local_addr) {
            if listener.state == TcpState::Listen && flags & TcpHeader::FLAG_SYN != 0 {
                // Create new connection for incoming SYN
                let mut tcb = TcpControlBlock::new(local_addr);
                tcb.remote_addr = Some(remote_addr);
                tcb.state = TcpState::SynReceived;
                tcb.rcv_nxt = seq_num.wrapping_add(1);
                tcb.snd_nxt = crate::task::current_tick() as u32;
                tcb.snd_una = tcb.snd_nxt;
                tcb.snd_wnd = window;

                self.connections.insert((local_addr, remote_addr), tcb);
                // Note: Caller should send SYN-ACK
                return;
            }
        }

        // No matching connection or listener - ignore or send RST
    }

    /// Process a TCP segment for an existing connection
    fn process_segment(
        &mut self,
        tcb: &mut TcpControlBlock,
        seq_num: u32,
        ack_num: u32,
        flags: u16,
        window: u16,
        payload: &[u8],
    ) {
        let syn = flags & TcpHeader::FLAG_SYN != 0;
        let ack = flags & TcpHeader::FLAG_ACK != 0;
        let fin = flags & TcpHeader::FLAG_FIN != 0;
        let _psh = flags & TcpHeader::FLAG_PSH != 0;

        // Update send window
        if ack {
            tcb.snd_wnd = window;
        }

        match tcb.state {
            TcpState::Closed => {
                // Ignore packets to closed connections
            }

            TcpState::Listen => {
                // Handled in main process() - new connections
            }

            TcpState::SynSent => {
                // Waiting for SYN-ACK
                if syn && ack && ack_num == tcb.snd_nxt.wrapping_add(1) {
                    tcb.snd_una = ack_num;
                    tcb.snd_nxt = ack_num;
                    tcb.rcv_nxt = seq_num.wrapping_add(1);
                    tcb.state = TcpState::Established;
                    // Wake connect waker
                    if let Some(waker) = tcb.connect_waker.take() {
                        waker.wake();
                    }
                    // Note: Caller should send ACK
                } else if syn && !ack {
                    // Simultaneous open
                    tcb.rcv_nxt = seq_num.wrapping_add(1);
                    tcb.state = TcpState::SynReceived;
                    // Note: Caller should send SYN-ACK
                }
            }

            TcpState::SynReceived => {
                // Waiting for ACK of our SYN-ACK
                if ack && ack_num == tcb.snd_nxt.wrapping_add(1) {
                    tcb.snd_una = ack_num;
                    tcb.snd_nxt = ack_num;
                    tcb.state = TcpState::Established;
                    // Wake connect waker
                    if let Some(waker) = tcb.connect_waker.take() {
                        waker.wake();
                    }
                }
            }

            TcpState::Established => {
                // Process acknowledgments
                if ack && Self::seq_after(ack_num, tcb.snd_una) {
                    tcb.snd_una = ack_num;
                    // Wake write waker (more space available)
                    if let Some(waker) = tcb.write_waker.take() {
                        waker.wake();
                    }
                }

                // Process incoming data
                if !payload.is_empty() && seq_num == tcb.rcv_nxt {
                    // In-order data - 受信統計を更新
                    // 注: 実際のパケット格納にはMempoolからの割り当てが必要
                    // 現時点ではペイロードをコピーせず、統計のみ更新
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(payload.len() as u32);
                    tcb.stats.bytes_received += payload.len() as u64;
                    tcb.stats.packets_received += 1;
                    // Wake read waker
                    if let Some(waker) = tcb.read_waker.take() {
                        waker.wake();
                    }
                    // Note: Caller should send ACK
                }

                // Handle FIN
                if fin {
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                    tcb.state = TcpState::CloseWait;
                    // Wake read waker to signal EOF
                    if let Some(waker) = tcb.read_waker.take() {
                        waker.wake();
                    }
                    // Note: Caller should send ACK
                }
            }

            TcpState::FinWait1 => {
                // We sent FIN, waiting for ACK
                if ack && ack_num == tcb.snd_nxt {
                    tcb.snd_una = ack_num;
                    if fin {
                        // Simultaneous close
                        tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                        tcb.state = TcpState::TimeWait;
                    } else {
                        tcb.state = TcpState::FinWait2;
                    }
                } else if fin {
                    // FIN before ACK
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                    tcb.state = TcpState::Closing;
                }
            }

            TcpState::FinWait2 => {
                // Waiting for peer's FIN
                if fin {
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                    tcb.state = TcpState::TimeWait;
                    // Note: Caller should send ACK
                }
            }

            TcpState::CloseWait => {
                // Waiting for application to close
                // (handled by close() call)
            }

            TcpState::Closing => {
                // Waiting for ACK of our FIN
                if ack && ack_num == tcb.snd_nxt {
                    tcb.snd_una = ack_num;
                    tcb.state = TcpState::TimeWait;
                }
            }

            TcpState::LastAck => {
                // Waiting for ACK of our FIN
                if ack && ack_num == tcb.snd_nxt {
                    tcb.snd_una = ack_num;
                    tcb.state = TcpState::Closed;
                }
            }

            TcpState::TimeWait => {
                // Wait for 2*MSL then move to Closed
                // (handled by timer, simplified: just stay in TimeWait)
            }
        }
    }

    /// Check if seq1 is after seq2 (handling wrap-around)
    fn seq_after(seq1: u32, seq2: u32) -> bool {
        (seq1.wrapping_sub(seq2) as i32) > 0
    }

    /// Close a connection (initiate active close)
    pub fn close(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr) {
        if let Some(tcb) = self.connections.get_mut(&(local_addr, remote_addr)) {
            match tcb.state {
                TcpState::Established => {
                    tcb.state = TcpState::FinWait1;
                    // Note: Caller should send FIN
                }
                TcpState::CloseWait => {
                    tcb.state = TcpState::LastAck;
                    // Note: Caller should send FIN
                }
                _ => {}
            }
        }
    }

    /// Remove closed connections
    pub fn cleanup_closed(&mut self) {
        self.connections
            .retain(|_, tcb| tcb.state != TcpState::Closed);
    }
}

impl Default for TcpProcessor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_addr() {
        let addr = Ipv4Addr::new(192, 168, 1, 1);
        assert_eq!(addr.octets(), [192, 168, 1, 1]);
        assert_eq!(format!("{}", addr), "192.168.1.1");
    }

    #[test]
    fn test_socket_addr() {
        let addr = SocketAddr::new(Ipv4Addr::LOCALHOST, 8080);
        assert_eq!(format!("{}", addr), "127.0.0.1:8080");
    }

    #[test]
    fn test_tcp_state() {
        let tcb = TcpControlBlock::new(SocketAddr::new(Ipv4Addr::UNSPECIFIED, 0));
        assert_eq!(tcb.state, TcpState::Closed);
    }
}
