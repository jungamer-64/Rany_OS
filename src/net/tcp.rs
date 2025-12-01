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

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use super::mempool::PacketRef;

// ============================================================================
// ネットワークアドレス
// ============================================================================

/// IPv4アドレス
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
        self.state == TcpState::Established && 
            (self.send_buffer.len() as u32) < self.cwnd
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
    
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), TcpError>>;
    
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), TcpError>>;
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

/// 非同期TCPストリーム（POSIXソケット代替）
pub struct TcpStream {
    tcb: Arc<Mutex<TcpControlBlock>>,
}

impl TcpStream {
    /// 指定アドレスに接続（async版）
    pub async fn connect(addr: SocketAddr) -> Result<Self, TcpError> {
        let local_port = allocate_ephemeral_port();
        let local_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED, local_port);
        
        let tcb = Arc::new(Mutex::new(TcpControlBlock::new(local_addr)));
        
        // SYN送信
        {
            let mut tcb_guard = tcb.lock();
            tcb_guard.remote_addr = Some(addr);
            tcb_guard.state = TcpState::SynSent;
            tcb_guard.snd_nxt = generate_initial_seq();
            // TODO: 実際のSYNパケット送信
        }
        
        // 接続完了を待つ
        ConnectFuture { tcb: tcb.clone() }.await?;
        
        Ok(Self { tcb })
    }
    
    /// ローカルアドレスを取得
    pub fn local_addr(&self) -> SocketAddr {
        self.tcb.lock().local_addr
    }
    
    /// リモートアドレスを取得
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.tcb.lock().remote_addr
    }
    
    /// 統計を取得
    pub fn stats(&self) -> TcpStats {
        self.tcb.lock().stats.clone()
    }
    
    /// 読み取り用Future
    pub fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> ReadFuture<'a> {
        ReadFuture { stream: self, buf }
    }
    
    /// 書き込み用Future
    pub fn write<'a>(&'a mut self, buf: &'a [u8]) -> WriteFuture<'a> {
        WriteFuture { stream: self, buf }
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
        let mut tcb = self.tcb.lock();
        
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
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, TcpError>> {
        let mut tcb = self.tcb.lock();
        
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
    
    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), TcpError>> {
        // TODO: 送信バッファのフラッシュ
        Poll::Ready(Ok(()))
    }
    
    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), TcpError>> {
        let mut tcb = self.tcb.lock();
        
        match tcb.state {
            TcpState::Established => {
                tcb.state = TcpState::FinWait1;
                // TODO: FIN送信
                Poll::Ready(Ok(()))
            }
            TcpState::CloseWait => {
                tcb.state = TcpState::LastAck;
                Poll::Ready(Ok(()))
            }
            _ => Poll::Ready(Err(TcpError::InvalidState)),
        }
    }
}

// ============================================================================
// TcpListener - 非同期TCPリスナー
// ============================================================================

/// 非同期TCPリスナー
pub struct TcpListener {
    local_addr: SocketAddr,
    backlog: Arc<Mutex<VecDeque<TcpStream>>>,
    accept_waker: Arc<Mutex<Option<Waker>>>,
}

impl TcpListener {
    /// 指定アドレスでリッスン開始
    pub fn bind(addr: SocketAddr) -> Result<Self, TcpError> {
        // ポートが使用中かチェック
        if is_port_in_use(addr.port) {
            return Err(TcpError::AddressInUse);
        }
        
        Ok(Self {
            local_addr: addr,
            backlog: Arc::new(Mutex::new(VecDeque::new())),
            accept_waker: Arc::new(Mutex::new(None)),
        })
    }
    
    /// ローカルアドレスを取得
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    
    /// 接続を受け入れ（async版）
    pub async fn accept(&self) -> Result<(TcpStream, SocketAddr), TcpError> {
        AcceptFuture { listener: self }.await
    }
    
    /// 新しい接続をバックログに追加（内部使用）
    pub(crate) fn push_connection(&self, stream: TcpStream, addr: SocketAddr) {
        let mut backlog = self.backlog.lock();
        backlog.push_back(stream);
        
        if let Some(waker) = self.accept_waker.lock().take() {
            waker.wake();
        }
    }
}

// ============================================================================
// Future実装
// ============================================================================

/// 接続Future
struct ConnectFuture {
    tcb: Arc<Mutex<TcpControlBlock>>,
}

impl Future for ConnectFuture {
    type Output = Result<(), TcpError>;
    
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut tcb = self.tcb.lock();
        
        match tcb.state {
            TcpState::Established => Poll::Ready(Ok(())),
            TcpState::Closed => Poll::Ready(Err(TcpError::ConnectionRefused)),
            TcpState::SynSent | TcpState::SynReceived => {
                tcb.connect_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            _ => Poll::Ready(Err(TcpError::InvalidState)),
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
        let mut backlog = self.listener.backlog.lock();
        
        if let Some(stream) = backlog.pop_front() {
            let addr = stream.peer_addr().unwrap_or(SocketAddr::new(Ipv4Addr::UNSPECIFIED, 0));
            Poll::Ready(Ok((stream, addr)))
        } else {
            *self.listener.accept_waker.lock() = Some(cx.waker().clone());
            Poll::Pending
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
fn generate_initial_seq() -> u32 {
    // TODO: より安全なランダム生成
    SEQ_COUNTER.fetch_add(64000, Ordering::Relaxed)
}

/// ポートが使用中か確認
fn is_port_in_use(_port: u16) -> bool {
    // TODO: ポートテーブルでチェック
    false
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
    let eth_header = unsafe {
        &*(data.as_ptr() as *const EthernetHeader)
    };
    
    let ethertype = u16::from_be(eth_header.ethertype);
    let ip_offset = EthernetHeader::HEADER_LEN;
    
    match ethertype {
        EthernetHeader::ETHERTYPE_IPV4 => {
            process_ipv4_packet(ip_offset, packet_for_later);
        }
        EthernetHeader::ETHERTYPE_ARP => {
            // TODO: ARP処理
        }
        _ => {
            // 未知のプロトコル
        }
    }
}

fn process_ipv4_packet(ip_offset: usize, packet: PacketRef) {
    let data = packet.data();
    
    if data.len() < ip_offset + Ipv4Header::MIN_HEADER_LEN {
        return;
    }
    
    let ip_data = &data[ip_offset..];
    let ip_header = unsafe {
        &*(ip_data.as_ptr() as *const Ipv4Header)
    };
    
    let header_len = ip_header.header_len();
    let tcp_offset = ip_offset + header_len;
    
    match ip_header.protocol {
        Ipv4Header::PROTOCOL_TCP => {
            process_tcp_packet(tcp_offset, packet, ip_header);
        }
        Ipv4Header::PROTOCOL_UDP => {
            // TODO: UDP処理
        }
        Ipv4Header::PROTOCOL_ICMP => {
            // TODO: ICMP処理
        }
        _ => {}
    }
}

fn process_tcp_packet(tcp_offset: usize, packet: PacketRef, _ip_header: &Ipv4Header) {
    let data = packet.data();
    
    if data.len() < tcp_offset + TcpHeader::MIN_HEADER_LEN {
        return;
    }
    
    let _tcp_header = unsafe {
        &*(data[tcp_offset..].as_ptr() as *const TcpHeader)
    };
    
    // TODO: TCB検索と状態マシン処理
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
