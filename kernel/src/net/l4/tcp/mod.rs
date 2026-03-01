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


use crate::sync::PoisonLock;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use crate::net::datapath::mempool::PacketRef;

// ============================================================================
// ネットワークアドレス
// ============================================================================

/// IPv4アドレス
mod async_traits;
pub use async_traits::*;
mod control_block_impl;
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

/// ソケットアドレス（IPv4 / IPv6 - unified）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SocketAddr {
    V4 { ip: Ipv4Addr, port: u16 },
    V6 { ip: crate::net::l3::ipv6::Ipv6Address, port: u16 },
}

impl SocketAddr {
    /// Backwards-compatible constructor for IPv4
    pub const fn new(ip: Ipv4Addr, port: u16) -> Self {
        SocketAddr::V4 { ip, port }
    }

    /// IPv6 constructor
    pub const fn new_v6(ip: crate::net::l3::ipv6::Ipv6Address, port: u16) -> Self {
        SocketAddr::V6 { ip, port }
    }

    /// Return true if IPv4
    #[inline]
    pub fn is_ipv4(&self) -> bool {
        matches!(self, SocketAddr::V4 { .. })
    }

    /// Return true if IPv6
    #[inline]
    pub fn is_ipv6(&self) -> bool {
        matches!(self, SocketAddr::V6 { .. })
    }

    /// Return IPv4 addr when available (or None)
    #[inline]
    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        match *self {
            SocketAddr::V4 { ip, .. } => Some(ip),
            SocketAddr::V6 { ip, .. } => {
                // map ::ffff:a.b.c.d -> a.b.c.d, otherwise None
                let bytes = ip.octets();
                if bytes[..10] == [0u8; 10] && bytes[10] == 0xff && bytes[11] == 0xff {
                    Some(Ipv4Addr::from_u32(u32::from_be_bytes([
                        bytes[12], bytes[13], bytes[14], bytes[15],
                    ])))
                } else {
                    None
                }
            }
        }
    }

    /// Return IPv6 bytes (for IPv4 returns mapped form)
    #[inline]
    pub fn as_ipv6(&self) -> crate::net::l3::ipv6::Ipv6Address {
        match *self {
            SocketAddr::V6 { ip, .. } => ip,
            SocketAddr::V4 { ip, .. } => {
                let mut b = [0u8; 16];
                b[10] = 0xff;
                b[11] = 0xff;
                let oct = ip.octets();
                b[12..16].copy_from_slice(&oct);
                crate::net::l3::ipv6::Ipv6Address::new(b)
            }
        }
    }

    /// Return port
    #[inline]
    pub fn port(&self) -> u16 {
        match *self {
            SocketAddr::V4 { port, .. } => port,
            SocketAddr::V6 { port, .. } => port,
        }
    }}

impl core::fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            SocketAddr::V4 { ip, port } => write!(f, "{}:{}", ip, port),
            SocketAddr::V6 { ip, port } => {
                // Use bracketed IPv6 literal
                write!(f, "[{}]:{}", ip, port)
            }
        }
    }
}

// ============================================================================
// TCP接続状態
// ============================================================================

use core::sync::atomic::{AtomicUsize, Ordering};

/// 全接続での合計OOOセグメント数
pub(crate) static GLOBAL_OOO_COUNT: AtomicUsize = AtomicUsize::new(0);
const GLOBAL_MAX_OOO_SEGMENTS: usize = 512;

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
    /// TCPとして受理した受信バイト数（wire側、再assembly後のpayload単位）
    pub bytes_received: u64,
    pub packets_sent: u64,
    /// TCPとして受理した受信セグメント数（payload を伴うもの）
    pub packets_received: u64,
    /// アプリケーションへ実際に引き渡した受信バイト数（read/read_zero_copy）
    pub app_bytes_delivered: u64,
    pub retransmissions: u64,
    pub rtt_us: u64,
    /// Zero-copy受信に失敗してVecフォールバックした総バイト数
    pub recv_copy_fallback_bytes: u64,
    /// Zero-copy受信に失敗してVecフォールバックした総パケット数
    pub recv_copy_fallback_packets: u64,
    /// Vecフォールバックキューのピークバイト数
    pub recv_copy_fallback_peak_bytes: u64,
    /// OOMでドロップされた受信パケット数
    pub oom_dropped_packets: u64,
    /// OOMでドロップされた受信バイト数
    pub oom_dropped_bytes: u64,
}

impl TcpStats {
    #[inline]
    pub fn record_tx_enqueued(&mut self, len: usize) {
        self.bytes_sent = self.bytes_sent.saturating_add(len as u64);
        self.packets_sent = self.packets_sent.saturating_add(1);
    }

    #[inline]
    pub fn record_rx_segment(&mut self, len: usize) {
        self.bytes_received = self.bytes_received.saturating_add(len as u64);
        self.packets_received = self.packets_received.saturating_add(1);
    }

    #[inline]
    pub fn record_rx_delivered(&mut self, len: usize) {
        self.app_bytes_delivered = self.app_bytes_delivered.saturating_add(len as u64);
    }

    #[inline]
    pub fn record_recv_copy_fallback(&mut self, len: usize, queue_bytes: usize) {
        self.recv_copy_fallback_bytes = self.recv_copy_fallback_bytes.saturating_add(len as u64);
        self.recv_copy_fallback_packets = self.recv_copy_fallback_packets.saturating_add(1);
        self.recv_copy_fallback_peak_bytes =
            self.recv_copy_fallback_peak_bytes.max(queue_bytes as u64);
    }

    #[inline]
    pub fn record_oom_drop(&mut self, len: usize) {
        self.oom_dropped_packets = self.oom_dropped_packets.saturating_add(1);
        self.oom_dropped_bytes = self.oom_dropped_bytes.saturating_add(len as u64);
    }
}

/// `recv_queue` (Vec fallback) の上限バイト数.
///
/// **NOTE:** the original design touted "zero copy", but the fallback allowed
/// `Vec<u8>` copies up to this many bytes.  We are in the process of
/// deprecating the fallback entirely; setting the constant to `0` causes any
/// attempt to enqueue data to close the connection instead, forcing callers to
/// address the condition explicitly.  Eventually the `recv_queue` field will be
/// removed once the rest of the stack no longer depends on it.
pub const TCP_RECV_COPY_FALLBACK_LIMIT_BYTES: usize = 0; // disabled

/// Zero-copy receive buffer limit (bytes)
pub const TCP_RECV_BUFFER_LIMIT_DEFAULT: usize = 128 * 1024; // 128 KB


/// TCP受信状態（バッファ管理）
struct TcpRxState {
    /// 受信バッファ (zero-copy when available)
    recv_buffer: VecDeque<PacketRef>,
    /// `recv_buffer` 内の合計バイト数
    recv_buffer_bytes: usize,
    /// `recv_buffer` の総バイト上限 (Security: prevent memory exhaustion)
    recv_buffer_limit_bytes: usize,
    /// 受信バッファ (コピー版フォールバック)
    recv_queue: VecDeque<Vec<u8>>,
    /// `recv_queue` 内の合計バイト数
    recv_queue_bytes: usize,
    /// `recv_queue` の総バイト上限
    recv_queue_limit_bytes: usize,
    /// Out-of-order segments queue
    ooo_queue: BTreeMap<u32, PacketRef>,
}

impl TcpRxState {
    fn new() -> Self {
        Self {
            recv_buffer: VecDeque::new(),
            recv_buffer_bytes: 0,
            recv_buffer_limit_bytes: TCP_RECV_BUFFER_LIMIT_DEFAULT,
            recv_queue: VecDeque::new(),
            recv_queue_bytes: 0,
            // limit initialized from constant above (currently zero)
            recv_queue_limit_bytes: TCP_RECV_COPY_FALLBACK_LIMIT_BYTES,
            ooo_queue: BTreeMap::new(),
        }
    }
}

/// TCPシーケンス/ウィンドウ状態（基本の送受信番号）
struct TcpSeqState {
    /// 送信シーケンス番号（次に送信するバイト）
    snd_nxt: u32,
    /// 未確認の最古のシーケンス番号
    snd_una: u32,
    /// 送信ウィンドウサイズ
    snd_wnd: u16,
    /// 受信シーケンス番号（次に期待するバイト）
    rcv_nxt: u32,
    /// 受信ウィンドウサイズ
    rcv_wnd: u16,
}

impl TcpSeqState {
    fn new(isn: u32) -> Self {
        Self {
            snd_nxt: isn,
            snd_una: isn,
            snd_wnd: 65535,
            rcv_nxt: 0,
            rcv_wnd: 65535,
        }
    }
}

/// TCP送信キュー状態（送信バッファ/未確認送信量）
struct TcpTxState {
    /// 送信バッファ（ゼロコピー: PacketRefのキュー）
    send_buffer: VecDeque<PacketRef>,
    /// 送信バッファ内のバイト数（キューされている未送信バイト）
    send_buffer_bytes: u32,
    /// 送信済みだが未確認のバイト数（in-flight）
    outstanding_bytes: u32,
}

impl TcpTxState {
    fn new() -> Self {
        Self {
            send_buffer: VecDeque::new(),
            send_buffer_bytes: 0,
            outstanding_bytes: 0,
        }
    }
}

/// TCP輻輳制御/送信挙動状態
struct TcpCongestionState {
    /// 輻輳ウィンドウ
    cwnd: u32,
    /// スロースタート閾値
    ssthresh: u32,
    /// Maximum Segment Size (default 1460 for Ethernet)
    mss: u16,
    /// Duplicate ACK counter (for fast retransmit)
    dup_ack_count: u8,
    /// Last ACK number received
    last_ack: u32,
    /// Fast recovery state
    in_recovery: bool,
    /// Nagle's algorithm enabled (delays small packets until ACK received)
    nagle_enabled: bool,
}

impl TcpCongestionState {
    fn new() -> Self {
        Self {
            cwnd: 10 * 1460, // 初期値: 10 MSS (RFC 6928)
            ssthresh: 65535,
            mss: 1460, // Ethernet MTU - IP/TCP headers
            dup_ack_count: 0,
            last_ack: 0,
            in_recovery: false,
            nagle_enabled: true, // Nagle's algorithm on by default
        }
    }
}

/// TCPオプション拡張状態（WSCALE/TS/SACK）
struct TcpOptionsState {
    // TCP Window Scaling (RFC 7323)
    /// Our window scale factor (0-14)
    snd_wscale: u8,
    /// Peer's window scale factor (0-14)
    rcv_wscale: u8,
    /// Window scaling enabled (negotiated during SYN)
    wscale_enabled: bool,
    /// Actual receive window (scaled: rcv_wnd << rcv_wscale)
    rcv_wnd_scaled: u32,

    // TCP Timestamps (RFC 7323)
    /// Timestamps enabled (negotiated during SYN)
    ts_enabled: bool,
    /// Our timestamp value (monotonically increasing)
    ts_val: u32,
    /// Last received timestamp echo reply
    ts_ecr: u32,
    /// Timestamp of last segment for RTT measurement
    ts_recent: u32,
    /// Age of ts_recent (for PAWS check, in milliseconds)
    ts_recent_age: u64,

    // TCP SACK (RFC 2018)
    /// SACK enabled (negotiated during SYN)
    sack_enabled: bool,
    /// SACK blocks - received out-of-order segments [(left_edge, right_edge)]
    sack_blocks: [(u32, u32); 4],
    /// Number of valid SACK blocks
    sack_block_count: u8,
    /// Segments marked as SACKed (for selective retransmit)
    sack_scoreboard: alloc::vec::Vec<(u32, u32)>,
}

impl TcpOptionsState {
    fn new() -> Self {
        Self {
            snd_wscale: 7,
            rcv_wscale: 0, // Set when peer SYN received
            wscale_enabled: false, // Negotiated during handshake
            rcv_wnd_scaled: 65535 << 7, // Initial scaled window
            ts_enabled: false,
            ts_val: 0,
            ts_ecr: 0,
            ts_recent: 0,
            ts_recent_age: 0,
            sack_enabled: false,
            sack_blocks: [(0, 0); 4],
            sack_block_count: 0,
            sack_scoreboard: alloc::vec::Vec::new(),
        }
    }
}

/// TCPタイマー/再送/keepalive状態
struct TcpTimerState {
    // Retransmission Timer (RFC 6298)
    /// Smoothed Round-Trip Time (milliseconds)
    srtt: Option<u64>,
    /// Round-Trip Time Variation (milliseconds)
    rttvar: Option<u64>,
    /// Retransmission Timeout (milliseconds)
    rto: u64,
    /// Last retransmit timestamp (tick/ms)
    last_retransmit_time: u64,
    /// Retransmission count for current segment
    retransmit_count: u8,
    /// Unacknowledged segments queue (for retransmission)
    unacked_segments: VecDeque<UnackedSegment>,

    // TCP Keepalive
    /// Keepalive enabled
    keepalive_enabled: bool,
    /// Keepalive idle time (milliseconds) - time before first probe
    keepalive_idle: u64,
    /// Keepalive interval (milliseconds) - time between probes
    keepalive_interval: u64,
    /// Keepalive probe count before giving up
    keepalive_count: u8,
    /// Current keepalive probe count
    keepalive_probes_sent: u8,
    /// Last activity timestamp (milliseconds) - last data received
    last_activity_time: u64,
    /// Timestamp when TIME_WAIT state was entered (milliseconds)
    time_wait_entered: u64,

    // Zero-Window Probe (RFC 1122 Section 4.2.2.17)
    /// Number of zero-window probes sent since peer window became 0
    zwp_probes_sent: u8,
    /// Timestamp of last zero-window probe sent (milliseconds)
    zwp_last_probe_time: u64,
}

impl TcpTimerState {
    fn new() -> Self {
        Self {
            srtt: None,
            rttvar: None,
            rto: 1_000, // Initial RTO = 1 second (in milliseconds)
            last_retransmit_time: 0,
            retransmit_count: 0,
            unacked_segments: VecDeque::new(),
            keepalive_enabled: false,
            keepalive_idle: 7_200_000, // 2 hours in milliseconds
            keepalive_interval: 75_000, // 75 seconds in milliseconds
            keepalive_count: 9,
            keepalive_probes_sent: 0,
            last_activity_time: 0,
            time_wait_entered: 0,
            zwp_probes_sent: 0,
            zwp_last_probe_time: 0,
        }
    }
}

/// TCP接続のエンドポイント情報
struct TcpEndpointMeta {
    /// ローカルアドレス
    local_addr: SocketAddr,
    /// リモートアドレス
    remote_addr: Option<SocketAddr>,
}

impl TcpEndpointMeta {
    fn new(local_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            remote_addr: None,
        }
    }
}

/// TCP非同期待機状態（waker/backlog）
#[derive(Default)]
struct TcpAsyncWaiters {
    read_waker: crate::sync::atomic_waker::AtomicWaker,
    write_waker: crate::sync::atomic_waker::AtomicWaker,
    connect_waker: crate::sync::atomic_waker::AtomicWaker,
    backlog: Option<Arc<PoisonLock<VecDeque<TcpStream>>>>,
    accept_waker: Option<Arc<crate::sync::atomic_waker::AtomicWaker>>,
}

// ============================================================================
// TCP制御ブロック (TCB)
// ============================================================================

impl Drop for TcpControlBlock {
    fn drop(&mut self) {
        let ooo_count = self.rx.ooo_queue.len();
        if ooo_count > 0 {
            GLOBAL_OOO_COUNT.fetch_sub(ooo_count, Ordering::Relaxed);
        }
    }
}

/// TCP制御ブロック
pub struct TcpControlBlock {
    /// 接続エンドポイント情報
    endpoints: TcpEndpointMeta,
    /// 現在の状態
    state: TcpState,

    // シーケンス番号管理
    /// 基本シーケンス/ウィンドウ状態
    seq: TcpSeqState,

    // バッファ
    /// 送信状態（送信キュー/未確認送信量）
    tx: TcpTxState,
    /// 受信バッファ群
    rx: TcpRxState,

    // 輻輳制御
    congestion: TcpCongestionState,

    // TCPオプション拡張
    options: TcpOptionsState,

    // タイマー/再送/keepalive
    timers: TcpTimerState,

    // Waker / backlog（非同期通知用）
    waiters: TcpAsyncWaiters,

    /// 統計
    stats: TcpStats,

    /// 接続作成時刻 (tick)
    created_at: u64,
}

/// Unacknowledged segment for retransmission (internal queue entry)
#[derive(Clone)]
struct UnackedSegment {
    /// Sequence number of first byte
    seq: u32,
    /// Segment data
    data: Vec<u8>,
    /// Timestamp when sent (tick)
    sent_time: u64,
    /// Number of retransmissions
    retransmit_count: u8,
    /// Flags associated with the segment (SYN/FIN/PSH/etc)
    flags: u16,
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;
