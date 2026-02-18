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
mod async_traits;
pub use async_traits::*;
mod control_block_impl;
pub use control_block_impl::*;
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
    /// 送信バッファ内のバイト数（キューされている未送信バイト）
    pub send_buffer_bytes: u32,
    /// 送信済みだが未確認のバイト数（in-flight）
    pub outstanding_bytes: u32,
    /// 受信バッファ (zero-copy when available)
    pub recv_buffer: VecDeque<PacketRef>,
    /// 受信バッファ (コピー版フォールバック)
    pub recv_queue: VecDeque<Vec<u8>>,

    // 輻輳制御
    /// 輻輳ウィンドウ
    pub cwnd: u32,
    /// スロースタート閾値
    pub ssthresh: u32,
    /// Maximum Segment Size (default 1460 for Ethernet)
    pub mss: u16,
    /// Duplicate ACK counter (for fast retransmit)
    pub dup_ack_count: u8,
    /// Last ACK number received
    pub last_ack: u32,
    /// Fast recovery state
    pub in_recovery: bool,
    /// Nagle's algorithm enabled (delays small packets until ACK received)
    pub nagle_enabled: bool,

    // Waker（非同期通知用）
    pub read_waker: Option<Waker>,
    pub write_waker: Option<Waker>,
    pub connect_waker: Option<Waker>,

    // For listening sockets
    pub backlog: Option<Arc<PoisonLock<VecDeque<TcpStream>>>>,
    pub accept_waker: Option<Arc<PoisonLock<Option<Waker>>>>,

    /// 統計
    pub stats: TcpStats,

    // Retransmission Timer (RFC 6298)
    /// Smoothed Round-Trip Time (microseconds)
    pub srtt: Option<u64>,
    /// Round-Trip Time Variation (microseconds)
    pub rttvar: Option<u64>,
    /// Retransmission Timeout (microseconds)
    pub rto: u64,
    /// Last retransmit timestamp (tick)
    pub last_retransmit_time: u64,
    /// Retransmission count for current segment
    pub retransmit_count: u8,
    /// Unacknowledged segments queue (for retransmission)
    pub unacked_segments: VecDeque<UnackedSegment>,

    // TCP Keepalive
    /// Keepalive enabled
    pub keepalive_enabled: bool,
    /// Keepalive idle time (microseconds) - time before first probe
    pub keepalive_idle: u64,
    /// Keepalive interval (microseconds) - time between probes
    pub keepalive_interval: u64,
    /// Keepalive probe count before giving up
    pub keepalive_count: u8,
    /// Current keepalive probe count
    pub keepalive_probes_sent: u8,
    /// Last activity timestamp (microseconds) - last data received
    pub last_activity_time: u64,
    /// Timestamp when TIME_WAIT state was entered (microseconds)
    pub time_wait_entered: u64,

    // TCP Window Scaling (RFC 7323)
    /// Our window scale factor (0-14)
    pub snd_wscale: u8,
    /// Peer's window scale factor (0-14)
    pub rcv_wscale: u8,
    /// Window scaling enabled (negotiated during SYN)
    pub wscale_enabled: bool,
    /// Actual receive window (scaled: rcv_wnd << rcv_wscale)
    pub rcv_wnd_scaled: u32,

    // TCP Timestamps (RFC 7323)
    /// Timestamps enabled (negotiated during SYN)
    pub ts_enabled: bool,
    /// Our timestamp value (monotonically increasing)
    pub ts_val: u32,
    /// Last received timestamp echo reply
    pub ts_ecr: u32,
    /// Timestamp of last segment for RTT measurement
    pub ts_recent: u32,
    /// Age of ts_recent (for PAWS check)
    pub ts_recent_age: u64,

    // TCP SACK (RFC 2018)
    /// SACK enabled (negotiated during SYN)
    pub sack_enabled: bool,
    /// SACK blocks - received out-of-order segments [(left_edge, right_edge)]
    pub sack_blocks: [(u32, u32); 4],
    /// Number of valid SACK blocks
    pub sack_block_count: u8,
    /// Segments marked as SACKed (for selective retransmit)
    pub sack_scoreboard: alloc::vec::Vec<(u32, u32)>,
}

/// Unacknowledged segment for retransmission
#[derive(Clone)]
pub struct UnackedSegment {
    /// Sequence number of first byte
    pub seq: u32,
    /// Segment data
    pub data: Vec<u8>,
    /// Timestamp when sent (tick)
    pub sent_time: u64,
    /// Number of retransmissions
    pub retransmit_count: u8,
    /// Flags associated with the segment (SYN/FIN/PSH/etc)
    pub flags: u16,
}
