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
            send_buffer_bytes: 0,
            outstanding_bytes: 0,
            recv_buffer: VecDeque::new(),
            recv_queue: VecDeque::new(),
            cwnd: 10 * 1460, // 初期値: 10 MSS (RFC 6928)
            ssthresh: 65535,
            mss: 1460, // Ethernet MTU - IP/TCP headers
            dup_ack_count: 0,
            last_ack: 0,
            in_recovery: false,
            nagle_enabled: true, // Nagle's algorithm on by default
            read_waker: None,
            write_waker: None,
            connect_waker: None,
            backlog: None,
            accept_waker: None,
            stats: TcpStats::default(),
            // Retransmission Timer (RFC 6298 defaults)
            srtt: None,
            rttvar: None,
            rto: 1_000_000, // Initial RTO = 1 second (in microseconds)
            last_retransmit_time: 0,
            retransmit_count: 0,
            unacked_segments: VecDeque::new(),
            // TCP Keepalive (defaults: 2 hours idle, 75s interval, 9 probes)
            keepalive_enabled: false,
            keepalive_idle: 7_200_000_000,    // 2 hours in microseconds
            keepalive_interval: 75_000_000,   // 75 seconds in microseconds
            keepalive_count: 9,
            keepalive_probes_sent: 0,
            last_activity_time: 0,
            time_wait_entered: 0,
            // Window Scaling (RFC 7323) - default scale factor 7 = 128KB max window
            snd_wscale: 7,
            rcv_wscale: 0, // Set when peer SYN received
            wscale_enabled: false, // Negotiated during handshake
            rcv_wnd_scaled: 65535 << 7, // Initial scaled window
            // Timestamps (RFC 7323) - disabled by default, negotiated in SYN
            ts_enabled: false,
            ts_val: 0,
            ts_ecr: 0,
            ts_recent: 0,
            ts_recent_age: 0,
            // SACK (RFC 2018) - disabled by default
            sack_enabled: false,
            sack_blocks: [(0, 0); 4],
            sack_block_count: 0,
            sack_scoreboard: alloc::vec::Vec::new(),
        }
    }

    /// 受信データがあるか
    pub fn has_data(&self) -> bool {
        !self.recv_buffer.is_empty() || !self.recv_queue.is_empty()
    }

    /// 送信可能か（バイト単位で判定、受信ウィンドウとの最小値を使用）
    pub fn can_send(&self) -> bool {
        if self.state != TcpState::Established {
            return false;
        }
        let available = core::cmp::min(self.cwnd, self.snd_wnd as u32);
        // Consider both in-flight (outstanding) and queued bytes
        let total_outstanding = self.outstanding_bytes.saturating_add(self.send_buffer_bytes);
        total_outstanding < available
    }

    /// Update RTO based on RTT measurement (RFC 6298)
    /// 
    /// Called when an ACK is received for a segment that was not retransmitted.
    pub fn update_rto(&mut self, rtt_sample: u64) {
        const ALPHA: u64 = 8;  // 1/8
        const BETA: u64 = 4;   // 1/4
        const MIN_RTO: u64 = 200_000;    // 200ms in microseconds
        const MAX_RTO: u64 = 60_000_000; // 60 seconds in microseconds

        if let (Some(srtt), Some(rttvar)) = (self.srtt, self.rttvar) {
            // Subsequent measurements
            let diff = if rtt_sample > srtt {
                rtt_sample - srtt
            } else {
                srtt - rtt_sample
            };
            self.rttvar = Some(rttvar - rttvar / BETA + diff / BETA);
            self.srtt = Some(srtt - srtt / ALPHA + rtt_sample / ALPHA);
        } else {
            // First measurement
            self.srtt = Some(rtt_sample);
            self.rttvar = Some(rtt_sample / 2);
        }

        // RTO = SRTT + max(G, 4 * RTTVAR) where G is clock granularity
        let srtt = self.srtt.unwrap_or(rtt_sample);
        let rttvar = self.rttvar.unwrap_or(rtt_sample / 2);
        self.rto = (srtt + 4 * rttvar).clamp(MIN_RTO, MAX_RTO);
    }

    /// Backoff RTO on retransmission timeout
    pub fn backoff_rto(&mut self) {
        const MAX_RTO: u64 = 60_000_000; // 60 seconds
        self.rto = (self.rto * 2).min(MAX_RTO);
        self.retransmit_count += 1;
    }

    /// Queue a segment for potential retransmission (stores flags too)
    pub fn queue_unacked(&mut self, seq: u32, data: Vec<u8>, current_time: u64, flags: u16) {
        // Count sequence-space bytes consumed by this segment for outstanding accounting
        let mut added: u32 = data.len() as u32;
        if flags & TcpHeader::FLAG_SYN != 0 {
            added = added.saturating_add(1);
        }
        if flags & TcpHeader::FLAG_FIN != 0 {
            added = added.saturating_add(1);
        }

        self.outstanding_bytes = self.outstanding_bytes.saturating_add(added);
        self.unacked_segments.push_back(UnackedSegment {
            seq,
            data,
            sent_time: current_time,
            retransmit_count: 0,
            flags,
        });
    }

    /// Remove acknowledged segments from retransmission queue
    pub fn ack_segments(&mut self, ack_num: u32) {
        // Compute total bytes before (include SYN/FIN sequence-space)
        let before: u32 = self.unacked_segments.iter().map(|s| {
            let mut cnt = s.data.len() as u32;
            if s.flags & TcpHeader::FLAG_SYN != 0 { cnt = cnt.saturating_add(1); }
            if s.flags & TcpHeader::FLAG_FIN != 0 { cnt = cnt.saturating_add(1); }
            cnt
        }).sum();

        // Remove all segments with seq + len <= ack_num
        self.unacked_segments.retain(|seg| {
            let mut end_seq = seg.seq.wrapping_add(seg.data.len() as u32);
            if seg.flags & TcpHeader::FLAG_SYN != 0 { end_seq = end_seq.wrapping_add(1); }
            if seg.flags & TcpHeader::FLAG_FIN != 0 { end_seq = end_seq.wrapping_add(1); }
            // Keep if segment is after ack_num (not yet acknowledged)
            TcpProcessor::seq_after(end_seq, ack_num)
        });

        // Compute removed bytes and adjust outstanding_bytes
        let after: u32 = self.unacked_segments.iter().map(|s| {
            let mut cnt = s.data.len() as u32;
            if s.flags & TcpHeader::FLAG_SYN != 0 { cnt = cnt.saturating_add(1); }
            if s.flags & TcpHeader::FLAG_FIN != 0 { cnt = cnt.saturating_add(1); }
            cnt
        }).sum();
        let removed = before.saturating_sub(after);
        self.outstanding_bytes = self.outstanding_bytes.saturating_sub(removed);

        // Reset retransmit count on successful ACK
        if self.unacked_segments.is_empty() {
            self.retransmit_count = 0;
        }
    }

    /// Check if retransmission timeout has occurred
    pub fn check_retransmit_timeout(&self, current_time: u64) -> bool {
        if self.unacked_segments.is_empty() {
            return false;
        }
        
        // Check if oldest unacked segment has timed out
        if let Some(oldest) = self.unacked_segments.front() {
            let elapsed = current_time.saturating_sub(oldest.sent_time);
            return elapsed >= self.rto;
        }
        false
    }

    // ========================================================================
    // Congestion Control (RFC 5681)
    // ========================================================================

    /// Called when a new (non-duplicate) ACK is received
    ///
    /// Implements:
    /// - Slow Start (cwnd < ssthresh): cwnd += mss
    /// - Congestion Avoidance (cwnd >= ssthresh): cwnd += mss*mss/cwnd
    pub fn on_new_ack(&mut self, bytes_acked: u32) {
        let mss = self.mss as u32;
        
        // Exit fast recovery on new ACK
        if self.in_recovery {
            self.in_recovery = false;
            self.cwnd = self.ssthresh;
        }
        
        // Reset dup ACK counter
        self.dup_ack_count = 0;
        
        if self.cwnd < self.ssthresh {
            // Slow Start: exponential growth
            // Increase cwnd by mss for each ACK (roughly doubles per RTT)
            self.cwnd = self.cwnd.saturating_add(mss);
        } else {
            // Congestion Avoidance: linear growth (AIMD - Additive Increase)
            // cwnd += mss * mss / cwnd (approximately +1 MSS per RTT)
            let increment = (mss as u64 * mss as u64 / self.cwnd as u64).max(1) as u32;
            self.cwnd = self.cwnd.saturating_add(increment);
        }
    }

    /// Called when a duplicate ACK is received
    ///
    /// Returns true if fast retransmit should be triggered (3rd dup ACK)
    pub fn on_dup_ack(&mut self) -> bool {
        self.dup_ack_count = self.dup_ack_count.saturating_add(1);
        
        if self.dup_ack_count == 3 && !self.in_recovery {
            // Fast Retransmit + Fast Recovery (RFC 5681)
            self.enter_fast_recovery();
            return true; // Trigger fast retransmit
        }
        
        if self.in_recovery && self.dup_ack_count > 3 {
            // Inflate cwnd during fast recovery
            self.cwnd = self.cwnd.saturating_add(self.mss as u32);
        }
        
        false
    }

    /// Enter Fast Recovery mode (RFC 5681 Section 3.2)
    fn enter_fast_recovery(&mut self) {
        let mss = self.mss as u32;
        
        // ssthresh = max(FlightSize / 2, 2*MSS)
        self.ssthresh = (self.outstanding_bytes / 2).max(2 * mss);
        
        // cwnd = ssthresh + 3*MSS (for the 3 dup ACKs)
        self.cwnd = self.ssthresh.saturating_add(3 * mss);
        
        self.in_recovery = true;
    }

    /// Called when a loss is detected (RTO timeout)
    ///
    /// More severe than fast retransmit - go back to slow start
    pub fn on_loss(&mut self) {
        let mss = self.mss as u32;
        
        // ssthresh = max(cwnd / 2, 2*MSS)
        self.ssthresh = (self.cwnd / 2).max(2 * mss);
        
        // cwnd = 1 MSS (slow start)
        self.cwnd = mss;
        
        // Exit recovery if in it
        self.in_recovery = false;
        self.dup_ack_count = 0;
    }

    /// Check if sending should be delayed (Nagle's algorithm)
    ///
    /// Nagle's algorithm: If there is unacknowledged data AND data to send
    /// is less than MSS, delay sending until either:
    /// 1. All data is acknowledged (outstanding_bytes == 0)
    /// 2. Enough data to fill MSS
    ///
    /// This reduces small packet overhead on interactive connections.
    pub fn should_delay_send(&self, data_len: usize) -> bool {
        if !self.nagle_enabled {
            return false;
        }
        
        // If data fills an MSS, send immediately
        if data_len >= self.mss as usize {
            return false;
        }
        
        // If no outstanding data, send immediately
        if self.outstanding_bytes == 0 {
            return false;
        }
        
        // Small packet with outstanding data: delay
        true
    }

    /// Disable Nagle's algorithm (like TCP_NODELAY socket option)
    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.nagle_enabled = !nodelay;
    }

    // ========================================================================
    // TCP Keepalive
    // ========================================================================

    /// Enable/disable keepalive with custom parameters
    pub fn set_keepalive(&mut self, enabled: bool, idle_us: Option<u64>, interval_us: Option<u64>, count: Option<u8>) {
        self.keepalive_enabled = enabled;
        if let Some(idle) = idle_us {
            self.keepalive_idle = idle;
        }
        if let Some(interval) = interval_us {
            self.keepalive_interval = interval;
        }
        if let Some(c) = count {
            self.keepalive_count = c;
        }
    }

    /// Record activity on the connection (resets keepalive timer)
    pub fn on_activity(&mut self, current_time: u64) {
        self.last_activity_time = current_time;
        self.keepalive_probes_sent = 0;
    }

    /// Check if keepalive probe should be sent
    /// 
    /// Returns:
    /// - None: No action needed
    /// - Some(true): Send keepalive probe
    /// - Some(false): Connection dead (too many probes failed)
    pub fn check_keepalive(&mut self, current_time: u64) -> Option<bool> {
        if !self.keepalive_enabled {
            return None;
        }
        
        if self.state != TcpState::Established {
            return None;
        }
        
        let elapsed = current_time.saturating_sub(self.last_activity_time);
        
        if self.keepalive_probes_sent == 0 {
            // First probe after idle time
            if elapsed >= self.keepalive_idle {
                self.keepalive_probes_sent = 1;
                return Some(true);
            }
        } else {
            // Subsequent probes at interval
            let probe_time = self.keepalive_idle + 
                (self.keepalive_probes_sent as u64 - 1) * self.keepalive_interval;
            
            if elapsed >= probe_time + self.keepalive_interval {
                if self.keepalive_probes_sent >= self.keepalive_count {
                    // Too many probes - connection is dead
                    return Some(false);
                }
                self.keepalive_probes_sent += 1;
                return Some(true);
            }
        }
        
        None
    }

    /// Reset keepalive state (call when ACK received)
    pub fn reset_keepalive(&mut self) {
        self.keepalive_probes_sent = 0;
    }

    // ========================================================================
    // TCP Window Scaling (RFC 7323)
    // ========================================================================

    /// Get effective send window (peer's window scaled)
    pub fn get_effective_snd_wnd(&self) -> u32 {
        if self.wscale_enabled {
            (self.snd_wnd as u32) << self.rcv_wscale
        } else {
            self.snd_wnd as u32
        }
    }

    /// Get effective receive window (our window scaled)
    pub fn get_effective_rcv_wnd(&self) -> u32 {
        self.rcv_wnd_scaled
    }

    /// Set peer's window scale factor (from SYN/SYN-ACK option)
    pub fn set_peer_wscale(&mut self, scale: u8) {
        // RFC 7323: scale factor must be <= 14
        self.rcv_wscale = scale.min(14);
        self.wscale_enabled = true;
    }

    /// Calculate optimal window scale factor based on buffer size
    /// Returns scale factor (0-14) for the given max window size
    pub fn calculate_wscale(max_window: u32) -> u8 {
        if max_window <= 65535 {
            return 0;
        }
        for scale in 1..=14u8 {
            if (65535u32 << scale) >= max_window {
                return scale;
            }
        }
        14 // Maximum scale factor
    }

    /// Update our advertised receive window
    pub fn update_rcv_wnd(&mut self, available_buffer: u32) {
        self.rcv_wnd_scaled = available_buffer;
        // Calculate the 16-bit window field (scaled down)
        if self.wscale_enabled {
            self.rcv_wnd = (available_buffer >> self.snd_wscale).min(65535) as u16;
        } else {
            self.rcv_wnd = available_buffer.min(65535) as u16;
        }
    }

    // ========================================================================
    // TCP Timestamps (RFC 7323)
    // ========================================================================

    /// Get current timestamp value for outgoing segment
    pub fn get_ts_val(&mut self) -> u32 {
        self.ts_val = self.ts_val.wrapping_add(1);
        self.ts_val
    }

    /// Process incoming timestamp option
    /// 
    /// Updates ts_recent for PAWS and prepares ts_ecr for reply
    pub fn process_ts_option(&mut self, ts_val: u32, ts_ecr: u32, current_time: u64, seq_num: u32) {
        // Only update ts_recent if segment is in sequence
        if seq_num == self.rcv_nxt || self.ts_recent == 0 {
            self.ts_recent = ts_val;
            self.ts_recent_age = current_time;
        }
        
        // Echo back the received timestamp
        self.ts_ecr = ts_val;
    }

    /// Check PAWS (Protection Against Wrapped Sequences)
    /// 
    /// Returns true if segment should be rejected (old duplicate)
    pub fn check_paws(&self, ts_val: u32, current_time: u64) -> bool {
        if !self.ts_enabled || self.ts_recent == 0 {
            return false;
        }
        
        // RFC 7323: If ts_recent is less than 24 days old and 
        // incoming ts_val < ts_recent, reject segment
        const PAWS_IDLE_LIMIT: u64 = 24 * 24 * 60 * 60 * 1_000_000; // 24 days in microseconds
        
        let age = current_time.saturating_sub(self.ts_recent_age);
        if age < PAWS_IDLE_LIMIT {
            // Compare timestamps (handling wrap-around)
            let diff = ts_val.wrapping_sub(self.ts_recent) as i32;
            if diff < 0 {
                return true; // Old duplicate - reject
            }
        }
        
        false
    }

    /// Measure RTT from timestamp echo
    /// 
    /// Returns RTT in microseconds if measurement is valid
    pub fn measure_rtt_from_ts(&self, ts_ecr: u32, current_ts: u32) -> Option<u64> {
        if !self.ts_enabled || ts_ecr == 0 {
            return None;
        }
        
        // RTT = current_ts - ts_ecr (in timestamp units)
        // Assuming 1ms per tick (common convention)
        let rtt_ticks = current_ts.wrapping_sub(ts_ecr);
        Some(rtt_ticks as u64 * 1000) // Convert to microseconds
    }

    /// Enable timestamps (call when negotiated in SYN)
    pub fn enable_timestamps(&mut self, initial_ts: u32) {
        self.ts_enabled = true;
        self.ts_val = initial_ts;
    }

    // ========================================================================
    // TCP SACK (RFC 2018)
    // ========================================================================

    /// Enable SACK (call when negotiated in SYN)
    pub fn enable_sack(&mut self) {
        self.sack_enabled = true;
    }

    /// Add a SACK block for out-of-order segment received
    /// 
    /// Called when we receive data out of order to build SACK option
    pub fn add_sack_block(&mut self, left: u32, right: u32) {
        if !self.sack_enabled {
            return;
        }
        
        // Insert new block, maintaining most recent first
        // Shift existing blocks down
        for i in (1..4).rev() {
            self.sack_blocks[i] = self.sack_blocks[i - 1];
        }
        self.sack_blocks[0] = (left, right);
        self.sack_block_count = (self.sack_block_count + 1).min(4);
    }

    /// Process SACK option received from peer
    /// 
    /// Updates scoreboard to mark segments as selectively acknowledged
    pub fn process_sack_option(&mut self, blocks: &[(u32, u32)]) {
        for &(left, right) in blocks {
            // Merge or add to scoreboard
            let mut merged = false;
            for (l, r) in self.sack_scoreboard.iter_mut() {
                // Check for overlap or adjacency
                if Self::seq_in_range(left, *l, *r) || Self::seq_in_range(*l, left, right) ||
                   right == *l || *r == left {
                    *l = core::cmp::min(*l, left);
                    *r = core::cmp::max(*r, right);
                    merged = true;
                    break;
                }
            }
            if !merged {
                self.sack_scoreboard.push((left, right));
            }
        }
    }

    /// Check if a sequence number is within a range (handling wrap-around)
    fn seq_in_range(seq: u32, left: u32, right: u32) -> bool {
        let diff_left = seq.wrapping_sub(left) as i32;
        let diff_right = right.wrapping_sub(seq) as i32;
        diff_left >= 0 && diff_right > 0
    }

    /// Check if a segment is marked as SACKed
    pub fn is_sacked(&self, seq: u32, len: u32) -> bool {
        let end = seq.wrapping_add(len);
        for &(left, right) in &self.sack_scoreboard {
            if Self::seq_in_range(seq, left, right) && 
               (Self::seq_in_range(end, left, right) || end == right) {
                return true;
            }
        }
        false
    }

    /// Get next unsacked segment for retransmission
    /// 
    /// Returns Some(seq) of the first segment that needs retransmitting
    pub fn get_next_unsacked(&self) -> Option<u32> {
        for seg in &self.unacked_segments {
            if !self.is_sacked(seg.seq, seg.data.len() as u32) {
                return Some(seg.seq);
            }
        }
        None
    }

    /// Clear SACK scoreboard on new cumulative ACK
    pub fn clear_sacked_below(&mut self, ack: u32) {
        self.sack_scoreboard.retain(|&(left, _)| {
            let diff = left.wrapping_sub(ack) as i32;
            diff >= 0
        });
    }

    /// Get SACK blocks to include in outgoing ACK
    pub fn get_sack_blocks(&self) -> &[(u32, u32)] {
        &self.sack_blocks[..self.sack_block_count as usize]
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
    pub(crate) tcb: Arc<PoisonLock<TcpControlBlock>>,
}

impl TcpStream {
    /// 指定アドレスに接続（推奨API）
    ///
    /// 【設計書】POSIXのconnect()ではなく、dial()という名前を採用
    /// 指定アドレスに接続（推奨API）
    ///
    /// 【設計書】POSIXのconnect()ではなく、dial()という名前を採用
    pub async fn dial(addr: SocketAddr) -> Result<Self, TcpError> {
        // ローカルポートの割り当てとTCBの作成、初期SYNの送信は Global Stack に委譲
        let local_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED, allocate_ephemeral_port());
        
        let stream = crate::net::stack::connect_tcp(local_addr, addr)?;
        
        // 接続完了を待つ
        let tcb = stream.tcb.clone();
        ConnectFuture { tcb }.await?;

        Ok(stream)
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

impl Clone for TcpStream {
    fn clone(&self) -> Self {
        TcpStream { tcb: self.tcb.clone() }
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

                    // If there is remaining payload, create a new PacketRef view and requeue it at the front
                    if data.len() > len {
                        let mut rem = packet.clone_ref();
                        rem.advance(len);
                        rem.set_len(data.len() - len);
                        tcb.recv_buffer.push_front(rem);
                    }

                    Poll::Ready(Ok(len))
                } else if let Some(mut vec) = tcb.recv_queue.pop_front() {
                    let len = vec.len().min(buf.len());
                    buf[..len].copy_from_slice(&vec[..len]);
                    tcb.stats.bytes_received += len as u64;

                    if len < vec.len() {
                        // Push remainder back to the front
                        let remainder = vec.split_off(len);
                        tcb.recv_queue.push_front(remainder);
                    }

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

                // Compute available bytes (cwnd, snd_wnd) minus outstanding and queued bytes
                let available = core::cmp::min(tcb.cwnd, tcb.snd_wnd as u32)
                    .saturating_sub(tcb.outstanding_bytes.saturating_add(tcb.send_buffer_bytes)) as usize;

                if available == 0 {
                    tcb.write_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }

                // パケットを割り当てて送信キューに追加
                if let Some(mut packet) = super::mempool::alloc_packet() {
                    let len = buf.len().min(1460).min(available); // MSS制限 + available
                    if len == 0 {
                        tcb.write_waker = Some(cx.waker().clone());
                        return Poll::Pending;
                    }
                    packet.data_mut()[..len].copy_from_slice(&buf[..len]);
                    packet.set_len(len);
                    tcb.send_buffer_bytes = tcb.send_buffer_bytes.saturating_add(len as u32);
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
                // Get current time for retransmit tracking (microseconds)
                let current_time = crate::time::precise_time_nanos() / 1000;
                
                // 送信バッファ内の全パケットを送信
                while let Some(packet) = tcb.send_buffer.pop_front() {
                    if let Some(remote) = tcb.remote_addr {
                        let data = packet.data();
                        let len = data.len();
                        // Decrement send buffer bytes now that we're attempting to send it
                        tcb.send_buffer_bytes = tcb.send_buffer_bytes.saturating_sub(len as u32);
                        let seq = tcb.snd_nxt;

                        let sent = send_data_packet(
                            tcb.local_addr,
                            remote,
                            seq,
                            tcb.rcv_nxt,
                            tcb.rcv_wnd,
                            data,
                        );

                        if sent {
                            // Queue for retransmission (PSH+ACK)
                            tcb.queue_unacked(seq, data.to_vec(), current_time, TcpHeader::FLAG_PSH | TcpHeader::FLAG_ACK);
                            tcb.last_retransmit_time = current_time;

                            tcb.snd_nxt = tcb.snd_nxt.wrapping_add(len as u32);
                        } else {
                            // Send failed (e.g., ARP unresolved). Requeue packet at front and restore counters
                            tcb.send_buffer_bytes = tcb.send_buffer_bytes.saturating_add(len as u32);
                            tcb.send_buffer.push_front(packet);
                            break; // stop trying further sends for now
                        }
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
                        let current_time = crate::time::precise_time_nanos() / 1000;
                        let sent = send_fin_packet(tcb.local_addr, remote, tcb.snd_nxt, tcb.rcv_nxt);
                        if sent {
                            // Queue FIN as unacked (FIN consumes 1 seq)
                            let snd_nxt = tcb.snd_nxt;
                            tcb.queue_unacked(snd_nxt, Vec::new(), current_time, TcpHeader::FLAG_FIN | TcpHeader::FLAG_ACK);
                            tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
                            tcb.last_retransmit_time = current_time;
                        } else {
                            // Could not send now; leave in queue and rely on process_timeouts to retry
                            log::info!("[NET] FIN send failed (will retry)");
                        }
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
    /// 【設計書】POSIXのbind()と同様の動作
    pub fn bind(addr: SocketAddr) -> Result<Self, TcpError> {
        crate::net::stack::bind_tcp(addr)
    }

    // Legacy constructor `TcpListener::new` removed; use `TcpListener::bind(addr)` instead.


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

/// Connect future with timeout support
struct ConnectTimeoutFuture {
    tcb: Arc<PoisonLock<TcpControlBlock>>,
    start_us: u64,
    timeout_us: u64,
}

impl Future for ConnectTimeoutFuture {
    type Output = Result<(), TcpError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.tcb.lock() {
            Ok(mut tcb) => match tcb.state {
                TcpState::Established => Poll::Ready(Ok(())),
                TcpState::Closed => Poll::Ready(Err(TcpError::ConnectionRefused)),
                TcpState::SynSent | TcpState::SynReceived => {
                    // Register waker
                    tcb.connect_waker = Some(cx.waker().clone());

                    // Check timeout
                    let now = crate::time::precise_time_nanos() / 1000;
                    if now.saturating_sub(self.start_us) >= self.timeout_us {
                        // Timeout: treat as Timeout error and close TCB
                        tcb.state = TcpState::Closed;
                        return Poll::Ready(Err(TcpError::Timeout));
                    }

                    Poll::Pending
                }
                _ => Poll::Ready(Err(TcpError::InvalidState)),
            },
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned in connect timeout future - returning ConnectionRefused");
                Poll::Ready(Err(TcpError::ConnectionRefused))
            }
        }
    }
}

impl TcpStream {
    /// Connect with a timeout in microseconds
    pub async fn dial_timeout(addr: SocketAddr, timeout_us: u64) -> Result<Self, TcpError> {
        let local_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED, allocate_ephemeral_port());
        let stream = crate::net::stack::connect_tcp(local_addr, addr)?;
        let start = crate::time::precise_time_nanos() / 1000;
        let tcb = stream.tcb.clone();
        ConnectTimeoutFuture { tcb, start_us: start, timeout_us }.await?;
        Ok(stream)
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

                // Compute available bytes
                let available = core::cmp::min(tcb.cwnd, tcb.snd_wnd as u32)
                    .saturating_sub(tcb.outstanding_bytes.saturating_add(tcb.send_buffer_bytes)) as usize;

                if !tcb.can_send() || available == 0 {
                    tcb.write_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }

                if let Some(packet) = this.packet.take() {
                    let len = packet.data().len();
                    if len > available {
                        // Not enough window yet
                        this.packet = Some(packet);
                        tcb.write_waker = Some(cx.waker().clone());
                        return Poll::Pending;
                    }
                    tcb.send_buffer_bytes = tcb.send_buffer_bytes.saturating_add(len as u32);
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
    let time_component = crate::task::timer::current_tick() as u32;
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

/// TCPセグメントを構築して送信。戻り値は送信成功かどうか（ARP未解決等で失敗することがある）
fn send_tcp_packet(
    local: SocketAddr,
    remote: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u16,
    window: u16,
    payload: &[u8],
) -> bool {
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

    // ネットワークスタック経由で送信 - 戻り値を返す
    let src_ip = crate::net::ipv4::Ipv4Address::new(local.ip.0);
    let dst_ip = crate::net::ipv4::Ipv4Address::new(remote.ip.0);
    crate::net::stack::send_tcp(src_ip, dst_ip, &segment)
}

/// TCPチェックサム計算（疑似ヘッダ込み）
pub(crate) fn calculate_tcp_checksum(segment: &mut [u8], src_ip: [u8; 4], dst_ip: [u8; 4]) {
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
pub(crate) fn send_syn_packet(local: SocketAddr, remote: SocketAddr, seq: u32) -> bool {
    send_tcp_packet(local, remote, seq, 0, TcpHeader::FLAG_SYN, 65535, &[])
}

/// SYNパケットをオプション付きで送信 (MSS, Window Scale, SACK Permitted, Timestamps)
pub(crate) fn send_syn_packet_with_options(
    local: SocketAddr,
    remote: SocketAddr,
    seq: u32,
    mss: u16,
    window_scale: u8,
    sack_permitted: bool,
    timestamps: Option<(u32, u32)>,
) -> bool {
    use crate::net::endpoint::window_scale::TcpOptionBuilder;

    let mut opt_builder = TcpOptionBuilder::new();
    opt_builder.add_mss(mss);
    opt_builder.add_window_scale(window_scale);
    if sack_permitted {
        opt_builder.add_sack_permitted();
    }
    if let Some((ts_val, ts_ecr)) = timestamps {
        opt_builder.add_timestamps(ts_val, ts_ecr);
    }

    let options = opt_builder.finalize();
    send_tcp_packet_with_options(local, remote, seq, 0, TcpHeader::FLAG_SYN, 65535, &[], options)
}

/// SYN-ACKパケットをオプション付きで送信
pub(crate) fn send_syn_ack_packet_with_options(
    local: SocketAddr,
    remote: SocketAddr,
    seq: u32,
    ack: u32,
    mss: u16,
    window_scale: u8,
    sack_permitted: bool,
    timestamps: Option<(u32, u32)>,
) -> bool {
    use crate::net::endpoint::window_scale::TcpOptionBuilder;

    let mut opt_builder = TcpOptionBuilder::new();
    opt_builder.add_mss(mss);
    opt_builder.add_window_scale(window_scale);
    if sack_permitted {
        opt_builder.add_sack_permitted();
    }
    if let Some((ts_val, ts_ecr)) = timestamps {
        opt_builder.add_timestamps(ts_val, ts_ecr);
    }

    let options = opt_builder.finalize();
    send_tcp_packet_with_options(
        local,
        remote,
        seq,
        ack,
        TcpHeader::FLAG_SYN | TcpHeader::FLAG_ACK,
        65535,
        &[],
        options,
    )
}

/// TCPセグメントをオプション付きで構築して送信
fn send_tcp_packet_with_options(
    local: SocketAddr,
    remote: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u16,
    window: u16,
    payload: &[u8],
    options: &[u8],
) -> bool {
    use alloc::vec;

    // オプション長は4バイト境界に揃える
    let options_len = options.len();
    let padded_options_len = (options_len + 3) & !3;
    let data_offset: u8 = (20 + padded_options_len as usize / 4) as u8; // 5 + オプション分
    let header_len = (data_offset as usize) * 4;
    let total_len = header_len + payload.len();

    let mut segment = vec![0u8; total_len];

    // TCPヘッダ構築
    segment[0..2].copy_from_slice(&local.port.to_be_bytes());
    segment[2..4].copy_from_slice(&remote.port.to_be_bytes());
    segment[4..8].copy_from_slice(&seq.to_be_bytes());
    segment[8..12].copy_from_slice(&ack.to_be_bytes());

    let data_off_flags = ((data_offset as u16) << 12) | (flags & 0x3F);
    segment[12..14].copy_from_slice(&data_off_flags.to_be_bytes());
    segment[14..16].copy_from_slice(&window.to_be_bytes());
    segment[16..18].copy_from_slice(&0u16.to_be_bytes()); // Checksum placeholder
    segment[18..20].copy_from_slice(&0u16.to_be_bytes()); // Urgent pointer

    // オプションをコピー
    if !options.is_empty() {
        segment[20..20 + options_len].copy_from_slice(options);
    }

    // ペイロード
    if !payload.is_empty() {
        segment[header_len..].copy_from_slice(payload);
    }

    // チェックサム計算
    calculate_tcp_checksum(&mut segment, local.ip.0, remote.ip.0);

    // ネットワークスタック経由で送信
    let src_ip = crate::net::ipv4::Ipv4Address::new(local.ip.0);
    let dst_ip = crate::net::ipv4::Ipv4Address::new(remote.ip.0);
    crate::net::stack::send_tcp(src_ip, dst_ip, &segment)
}

/// SYN-ACKパケットを送信
pub(crate) fn send_syn_ack_packet(local: SocketAddr, remote: SocketAddr, seq: u32, ack: u32) -> bool {
    send_tcp_packet(
        local,
        remote,
        seq,
        ack,
        TcpHeader::FLAG_SYN | TcpHeader::FLAG_ACK,
        65535,
        &[],
    )
}

/// ACKパケットを送信
pub(crate) fn send_ack_packet(local: SocketAddr, remote: SocketAddr, seq: u32, ack: u32, window: u16) -> bool {
    send_tcp_packet(local, remote, seq, ack, TcpHeader::FLAG_ACK, window, &[])
}

/// FINパケットを送信
pub(crate) fn send_fin_packet(local: SocketAddr, remote: SocketAddr, seq: u32, ack: u32) -> bool {
    send_tcp_packet(
        local,
        remote,
        seq,
        ack,
        TcpHeader::FLAG_FIN | TcpHeader::FLAG_ACK,
        65535,
        &[],
    )
}

/// データパケットを送信（PSH+ACK）
pub(crate) fn send_data_packet(
    local: SocketAddr,
    remote: SocketAddr,
    seq: u32,
    ack: u32,
    window: u16,
    data: &[u8],
) -> bool {
    send_tcp_packet(
        local,
        remote,
        seq,
        ack,
        TcpHeader::FLAG_PSH | TcpHeader::FLAG_ACK,
        window,
        data,
    )
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

/// Result of TCP Processing
#[derive(Debug)]
pub enum TcpProcessResult {
    None,
    SendPacket {
        local: SocketAddr,
        remote: SocketAddr,
        seq: u32,
        ack: u32,
        flags: u16,
        window: u16,
        payload: Vec<u8>
    },
}

/// TCP segment processor for the network stack
pub struct TcpProcessor {
    /// TCP connections indexed by (local_addr, remote_addr) tuple
    connections: BTreeMap<(SocketAddr, SocketAddr), Arc<PoisonLock<TcpControlBlock>>>,
    /// Listening sockets indexed by local address
    listeners: BTreeMap<SocketAddr, Arc<PoisonLock<TcpControlBlock>>>,
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
        self.listeners.insert(local_addr, Arc::new(PoisonLock::new(tcb)));
    }
    
    /// Bind to a specific port
    pub fn bind(&mut self, addr: SocketAddr) -> Result<TcpListener, TcpError> {
        if self.listeners.contains_key(&addr) || 
           self.connections.keys().any(|(local, _)| local == &addr) {
            return Err(TcpError::AddressInUse);
        }
        
        // Create shared state for backlog and waker
        let backlog = Arc::new(PoisonLock::new(VecDeque::new()));
        let accept_waker = Arc::new(PoisonLock::new(None));

        // Create TCB with this shared state
        let mut tcb = TcpControlBlock::new(addr);
        tcb.state = TcpState::Listen;
        tcb.backlog = Some(backlog.clone());
        tcb.accept_waker = Some(accept_waker.clone());
        
        // Wrap in Arc<PoisonLock>
        let tcb_arc = Arc::new(PoisonLock::new(tcb));
        
        self.listeners.insert(addr, tcb_arc);
        
        Ok(TcpListener {
            local_addr: addr,
            backlog,
            accept_waker,
        })
    }

    /// Initiate a connection to a remote address
    pub fn connect(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<TcpStream, TcpError> {
        let mut tcb = TcpControlBlock::new(local_addr);
        tcb.remote_addr = Some(remote_addr);
        tcb.state = TcpState::SynSent;
        // Generate initial sequence number (simplified: use tick count)
        tcb.snd_nxt = crate::task::timer::current_tick() as u32;
        tcb.snd_una = tcb.snd_nxt;

        let tcb_arc = Arc::new(PoisonLock::new(tcb));

        self.connections.insert(
            (local_addr, remote_addr),
            tcb_arc.clone(),
        );
        // Note: Caller should send SYN packet after this (handled by stack wrapper or here?)
        // Better if caller does it, or we return an action.
        // But connect() is synchronous state setup.
        
        Ok(TcpStream { tcb: tcb_arc })
    }

    /// Test-only helper to seed an existing connection.
    #[cfg(any(test, feature = "full_mm_tests"))]
    pub fn insert_test_connection(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        tcb: Arc<PoisonLock<TcpControlBlock>>,
    ) {
        self.connections.insert((local_addr, remote_addr), tcb);
    }



    /// Process an incoming TCP segment
    pub fn process(&mut self, data: &[u8], src_ip: Ipv4Address, dst_ip: Ipv4Address, current_time: u64) -> TcpProcessResult {
        if data.len() < TcpHeader::MIN_HEADER_LEN {
            return TcpProcessResult::None;
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
            return TcpProcessResult::None;
        }

        // Try to find existing connection
        if let Some(tcb_lock) = self.connections.get(&(local_addr, remote_addr)).cloned() {
            if let Ok(mut tcb) = tcb_lock.lock() {
                return self.process_segment(&tcb_lock, &mut *tcb, seq_num, ack_num, flags, window, header_len, payload, None, current_time);
            }
        }

        // Check if this is for a listening socket
        if let Some(listener_lock) = self.listeners.get(&local_addr) {
            if let Ok(listener) = listener_lock.lock() {
                if listener.state == TcpState::Listen && flags & TcpHeader::FLAG_SYN != 0 {
                    // Create new connection for incoming SYN
                    let mut tcb = TcpControlBlock::new(local_addr);
                    tcb.remote_addr = Some(remote_addr);
                    tcb.state = TcpState::SynReceived;
                    tcb.rcv_nxt = seq_num.wrapping_add(1);
                    tcb.snd_nxt = crate::task::timer::current_tick() as u32;
                    tcb.snd_una = tcb.snd_nxt;
                    tcb.snd_wnd = window;
                    
                    // Propagate backlog/waker from listener to child
                    tcb.backlog = listener.backlog.clone();
                    tcb.accept_waker = listener.accept_waker.clone();
    
                    // Prepare SYN-ACK
                    let syn_ack = TcpProcessResult::SendPacket {
                        local: local_addr,
                        remote: remote_addr,
                        seq: tcb.snd_nxt,
                        ack: tcb.rcv_nxt,
                        flags: TcpHeader::FLAG_SYN | TcpHeader::FLAG_ACK,
                        window: 65535, // Default window
                        payload: Vec::new(),
                    };
    
                    self.connections.insert(
                        (local_addr, remote_addr),
                        Arc::new(PoisonLock::new(tcb)),
                    );
                    return syn_ack;
                }
            }
        }

        // No matching connection or listener - ignore or send RST
        TcpProcessResult::None
    }

    /// Process an incoming TCP segment using a PacketRef (zero-copy path)
    pub fn process_with_packet(
        &mut self,
        data: &[u8],
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        packet: PacketRef,
        current_time: u64,
    ) -> TcpProcessResult {
        // Short-circuit to the connection-specific fast-path that can enqueue
        // a zero-copy PacketRef view for payload when possible. For non-connection
        // packets we delegate back to the standard `process()` implementation.
        if data.len() < TcpHeader::MIN_HEADER_LEN {
            return TcpProcessResult::None;
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
        let payload = if data.len() > header_len { &data[header_len..] } else { &[] };

        // Handle RST - reset connection immediately
        if flags & TcpHeader::FLAG_RST != 0 {
            self.connections.remove(&(local_addr, remote_addr));
            return TcpProcessResult::None;
        }

        // Try to find existing connection and use the packet for zero-copy enqueue
        if let Some(tcb_lock) = self.connections.get(&(local_addr, remote_addr)).cloned() {
            if let Ok(mut tcb) = tcb_lock.lock() {
                return self.process_segment(
                    &tcb_lock,
                    &mut *tcb,
                    seq_num,
                    ack_num,
                    flags,
                    window,
                    header_len,
                    payload,
                    Some(packet),
                    current_time,
                );
            }
        }

        // Not an existing connection - fall back to normal processing (listener/SYN handling)
        self.process(data, src_ip, dst_ip, current_time)
    }

    /// Process a TCP segment for an existing connection
    fn process_segment(
        &mut self,
        tcb_arc: &Arc<PoisonLock<TcpControlBlock>>,
        tcb: &mut TcpControlBlock,
        seq_num: u32,
        ack_num: u32,
        flags: u16,
        window: u16,
        header_len: usize,
        payload: &[u8],
        packet_opt: Option<PacketRef>,
        current_time: u64,
    ) -> TcpProcessResult {
        let syn = flags & TcpHeader::FLAG_SYN != 0;
        let ack = flags & TcpHeader::FLAG_ACK != 0;
        let fin = flags & TcpHeader::FLAG_FIN != 0;
        let _psh = flags & TcpHeader::FLAG_PSH != 0;

        let payload_len = payload.len();
        let mut result = TcpProcessResult::None;

        // Update send window
        if ack {
            tcb.snd_wnd = window;
        }

        match tcb.state {
            TcpState::Closed => {
                // Ignore packets to closed connections
            }

            TcpState::Listen => {
                // Handled in main process()
            }

            TcpState::SynSent => {
                // Waiting for SYN-ACK
                // Accept ACK that acknowledges the initial SYN (snd_una + 1)
                if syn && ack && ack_num == tcb.snd_una.wrapping_add(1) {
                    tcb.snd_una = ack_num;
                    tcb.snd_nxt = ack_num;
                    tcb.rcv_nxt = seq_num.wrapping_add(1);
                    tcb.state = TcpState::Established;
                    // Wake connect waker
                    if let Some(waker) = tcb.connect_waker.take() {
                        waker.wake();
                    }
                    // Send ACK
                    result = TcpProcessResult::SendPacket {
                        local: tcb.local_addr,
                        remote: tcb.remote_addr.unwrap(),
                        seq: tcb.snd_nxt,
                        ack: tcb.rcv_nxt,
                        flags: TcpHeader::FLAG_ACK,
                        window: tcb.rcv_wnd,
                        payload: Vec::new(),
                    };
                } else if syn && !ack {
                    // Simultaneous open
                    tcb.rcv_nxt = seq_num.wrapping_add(1);
                    tcb.state = TcpState::SynReceived;
                    // Send SYN-ACK
                    result = TcpProcessResult::SendPacket {
                        local: tcb.local_addr,
                        remote: tcb.remote_addr.unwrap(),
                        seq: tcb.snd_nxt,
                        ack: tcb.rcv_nxt,
                        flags: TcpHeader::FLAG_SYN | TcpHeader::FLAG_ACK,
                        window: tcb.rcv_wnd,
                        payload: Vec::new(),
                    };
                }
            }

            TcpState::SynReceived => {
                // ACK acknowledging our SYN (snd_una + 1)
                if ack && ack_num == tcb.snd_una.wrapping_add(1) {
                    tcb.snd_una = ack_num;
                    tcb.snd_nxt = ack_num;
                    tcb.state = TcpState::Established;
                    
                    // Push to backlog if present
                    if let Some(backlog_lock) = &tcb.backlog {
                        if let Ok(mut backlog) = backlog_lock.lock() {
                            backlog.push_back(TcpStream { tcb: tcb_arc.clone() });
                            
                            if let Some(waker_lock) = &tcb.accept_waker {
                                if let Ok(mut waker_opt) = waker_lock.lock() {
                                    if let Some(waker) = waker_opt.take() {
                                        waker.wake();
                                    }
                                }
                            }
                        }
                    }

                    if let Some(waker) = tcb.connect_waker.take() {
                        waker.wake();
                    }
                }
            }

            TcpState::Established => {
                if ack && Self::seq_after(ack_num, tcb.snd_una) {
                    // New ACK - calculate bytes acknowledged
                    let bytes_acked = ack_num.wrapping_sub(tcb.snd_una);
                    tcb.last_ack = ack_num;
                    tcb.snd_una = ack_num;
                    
                    // Remove acknowledged segments from retransmit queue
                    tcb.ack_segments(ack_num);
                    
                    // Congestion control: update cwnd on new ACK
                    tcb.on_new_ack(bytes_acked);
                    
                    if let Some(waker) = tcb.write_waker.take() {
                        waker.wake();
                    }
                } else if ack && ack_num == tcb.snd_una && tcb.outstanding_bytes > 0 {
                    // Duplicate ACK - same ack_num but we have outstanding data
                    let should_retransmit = tcb.on_dup_ack();
                    if should_retransmit {
                        // Fast retransmit: immediately resend oldest unacked segment
                        if let Some(oldest) = tcb.unacked_segments.front() {
                            if let Some(remote) = tcb.remote_addr {
                                result = TcpProcessResult::SendPacket {
                                    local: tcb.local_addr,
                                    remote,
                                    seq: oldest.seq,
                                    ack: tcb.rcv_nxt,
                                    flags: oldest.flags,
                                    window: tcb.rcv_wnd,
                                    payload: oldest.data.clone(),
                                };
                            }
                        }
                    }
                }

                if payload_len > 0 && seq_num == tcb.rcv_nxt {
                    // In-order data - Update stats
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(payload_len as u32);
                    tcb.stats.bytes_received += payload_len as u64;
                    tcb.stats.packets_received += 1;

                    // Prefer zero-copy when a PacketRef is available
                    if let Some(mut pkt) = packet_opt {
                        // Ensure header_len is within packet and adjust view to payload
                        if header_len <= pkt.len() && payload_len <= pkt.len() - header_len {
                            pkt.advance(header_len);
                            pkt.set_len(payload_len);
                            tcb.recv_buffer.push_back(pkt);
                        } else {
                            // View doesn't match expected layout - fallback to copy
                            if let Some(mut packet) = super::mempool::alloc_packet() {
                                let data_slice = packet.data_mut();
                                if payload_len <= data_slice.len() {
                                    data_slice[..payload_len].copy_from_slice(payload);
                                    packet.set_len(payload_len);
                                    tcb.recv_buffer.push_back(packet);
                                } else {
                                    // Payload too large for packet, use Vec fallback
                                    tcb.recv_queue.push_back(payload.to_vec());
                                }
                            } else {
                                // mempool exhausted - fallback to copy
                                tcb.recv_queue.push_back(payload.to_vec());
                            }
                        }
                    } else {
                        // No PacketRef available - copy into a new PacketRef when possible
                        if let Some(mut packet) = super::mempool::alloc_packet() {
                            let data_slice = packet.data_mut();
                            if payload_len <= data_slice.len() {
                                data_slice[..payload_len].copy_from_slice(payload);
                                packet.set_len(payload_len);
                                tcb.recv_buffer.push_back(packet);
                            } else {
                                // Payload too large for packet, use Vec fallback
                                tcb.recv_queue.push_back(payload.to_vec());
                            }
                        } else {
                            // mempool exhausted - fallback to copy
                            tcb.recv_queue.push_back(payload.to_vec());
                        }
                    }

                    if let Some(waker) = tcb.read_waker.take() {
                        waker.wake();
                    }
                    // Send ACK
                    result = TcpProcessResult::SendPacket {
                        local: tcb.local_addr,
                        remote: tcb.remote_addr.unwrap(),
                        seq: tcb.snd_nxt,
                        ack: tcb.rcv_nxt,
                        flags: TcpHeader::FLAG_ACK,
                        window: tcb.rcv_wnd,
                        payload: Vec::new(),
                    };
                } else if payload_len > 0 {
                    // Out-of-order - Send ACK for expected
                     result = TcpProcessResult::SendPacket {
                        local: tcb.local_addr,
                        remote: tcb.remote_addr.unwrap(),
                        seq: tcb.snd_nxt,
                        ack: tcb.rcv_nxt,
                        flags: TcpHeader::FLAG_ACK,
                        window: tcb.rcv_wnd,
                        payload: Vec::new(),
                    };
                }

                if fin {
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                    tcb.state = TcpState::CloseWait;
                    if let Some(waker) = tcb.read_waker.take() {
                        waker.wake();
                    }
                    result = TcpProcessResult::SendPacket {
                        local: tcb.local_addr,
                        remote: tcb.remote_addr.unwrap(),
                        seq: tcb.snd_nxt,
                        ack: tcb.rcv_nxt,
                        flags: TcpHeader::FLAG_ACK,
                        window: tcb.rcv_wnd,
                        payload: Vec::new(),
                    };
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
                        tcb.time_wait_entered = current_time;
                        // Send ACK
                         result = TcpProcessResult::SendPacket {
                            local: tcb.local_addr,
                            remote: tcb.remote_addr.unwrap(),
                            seq: tcb.snd_nxt,
                            ack: tcb.rcv_nxt,
                            flags: TcpHeader::FLAG_ACK,
                            window: tcb.rcv_wnd,
                            payload: Vec::new(),
                        };
                    } else {
                        tcb.state = TcpState::FinWait2;
                    }
                } else if fin {
                    // FIN before ACK
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                    tcb.state = TcpState::Closing;
                     // Send ACK
                     result = TcpProcessResult::SendPacket {
                        local: tcb.local_addr,
                        remote: tcb.remote_addr.unwrap(),
                        seq: tcb.snd_nxt,
                        ack: tcb.rcv_nxt,
                        flags: TcpHeader::FLAG_ACK,
                        window: tcb.rcv_wnd,
                        payload: Vec::new(),
                    };
                }
            }

            TcpState::FinWait2 => {
                // Waiting for peer's FIN
                if fin {
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                    tcb.state = TcpState::TimeWait;
                    tcb.time_wait_entered = current_time;
                    // Send ACK
                     result = TcpProcessResult::SendPacket {
                        local: tcb.local_addr,
                        remote: tcb.remote_addr.unwrap(),
                        seq: tcb.snd_nxt,
                        ack: tcb.rcv_nxt,
                        flags: TcpHeader::FLAG_ACK,
                        window: tcb.rcv_wnd,
                        payload: Vec::new(),
                    };
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
                    tcb.time_wait_entered = current_time;
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
                // RFC 793: Wait for 2*MSL (Maximum Segment Lifetime) then move to Closed
                // MSL = 120 seconds, 2*MSL = 240 seconds = 240_000_000 microseconds
                const TWO_MSL_US: u64 = 240_000_000;
                if current_time.saturating_sub(tcb.time_wait_entered) >= TWO_MSL_US {
                    tcb.state = TcpState::Closed;
                }
            }
        }
        
        result
    }

    /// Check if seq1 is after seq2 (handling wrap-around)
    fn seq_after(seq1: u32, seq2: u32) -> bool {
        (seq1.wrapping_sub(seq2) as i32) > 0
    }

    /// Close a connection (initiate active close)
    pub fn close(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr) {
        if let Some(tcb_lock) = self.connections.get(&(local_addr, remote_addr)) {
            if let Ok(mut tcb) = tcb_lock.lock() {
                match tcb.state {
                    TcpState::Established => {
                        let seq = tcb.snd_nxt;
                        let ack = tcb.rcv_nxt;
                        tcb.state = TcpState::FinWait1;
                        // Send FIN+ACK
                        send_fin_packet(local_addr, remote_addr, seq, ack);
                        tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1); // FIN consumes 1 seq
                    }
                    TcpState::CloseWait => {
                        let seq = tcb.snd_nxt;
                        let ack = tcb.rcv_nxt;
                        tcb.state = TcpState::LastAck;
                        // Send FIN+ACK
                        send_fin_packet(local_addr, remote_addr, seq, ack);
                        tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1); // FIN consumes 1 seq
                    }
                    _ => {}
                }
            }
        }
    }

    /// Remove closed and expired TIME_WAIT connections
    pub fn cleanup_closed(&mut self) {
        const TWO_MSL_US: u64 = 240_000_000;
        self.connections.retain(|_, tcb_lock| {
            if let Ok(tcb) = tcb_lock.lock() {
                match tcb.state {
                    TcpState::Closed => false,
                    TcpState::TimeWait => {
                        // Keep if 2MSL has not yet passed
                        // Use last_activity_time as fallback if time_wait_entered is 0
                        let entered = if tcb.time_wait_entered > 0 {
                            tcb.time_wait_entered
                        } else {
                            tcb.last_activity_time
                        };
                        let elapsed = tcb.last_activity_time
                            .max(entered)
                            .saturating_sub(entered);
                        elapsed < TWO_MSL_US
                    }
                    _ => true,
                }
            } else {
                // If lock is poisoned, remove the connection
                false
            }
        });
    }

    /// Check for retransmission timeouts and generate retransmit packets
    /// Returns a vector of `TcpProcessResult::SendPacket` items for timed-out segments.
    pub fn check_retransmissions(&mut self, current_time: u64) -> Vec<TcpProcessResult> {
        let mut results: Vec<TcpProcessResult> = Vec::new();

        for (_key, tcb_arc) in self.connections.iter() {
            if let Ok(mut tcb) = tcb_arc.lock() {
                if tcb.check_retransmit_timeout(current_time) {
                    // Scope the mutable borrow of oldest segment
                    let packet_data = if let Some(oldest) = tcb.unacked_segments.front_mut() {
                        // Update retransmit metadata
                        oldest.sent_time = current_time;
                        oldest.retransmit_count = oldest.retransmit_count.saturating_add(1);
                        // Extract data needed for packet creation
                        Some((oldest.seq, oldest.data.clone()))
                    } else {
                        None
                    };

                    if let Some((seq, payload)) = packet_data {
                        tcb.backoff_rto();
                        tcb.retransmit_count = tcb.retransmit_count.saturating_add(1);
                        
                        // RFC 5681: On RTO, go back to slow start
                        tcb.on_loss();

                        // Build a packet resend (PSH+ACK)
                        if let Some(remote) = tcb.remote_addr {
                            results.push(TcpProcessResult::SendPacket {
                                local: tcb.local_addr,
                                remote,
                                seq,
                                ack: tcb.rcv_nxt,
                                flags: TcpHeader::FLAG_PSH | TcpHeader::FLAG_ACK,
                                window: tcb.rcv_wnd,
                                payload,
                            });
                        }
                    }
                }
            }
        }

        results
    }

    /// Process TCP keepalive timers and generate keepalive probes
    /// Returns packets to send for keepalive probes
    pub fn process_keepalives(&mut self, current_time: u64) -> Vec<TcpProcessResult> {
        let mut results = Vec::new();
        let mut dead_connections = Vec::new();

        for (key, tcb_lock) in self.connections.iter() {
            if let Ok(mut tcb) = tcb_lock.lock() {
                match tcb.check_keepalive(current_time) {
                    Some(true) => {
                        // Send keepalive probe: ACK with seq = snd_una - 1
                        if let Some(remote) = tcb.remote_addr {
                            results.push(TcpProcessResult::SendPacket {
                                local: tcb.local_addr,
                                remote,
                                seq: tcb.snd_una.wrapping_sub(1),
                                ack: tcb.rcv_nxt,
                                flags: TcpHeader::FLAG_ACK,
                                window: tcb.rcv_wnd,
                                payload: Vec::new(),
                            });
                        }
                    }
                    Some(false) => {
                        // Connection dead - too many probes without response
                        dead_connections.push(*key);
                    }
                    None => {
                        // No action needed
                    }
                }
            }
        }

        // Mark dead connections as closed
        for key in dead_connections {
            if let Some(tcb_lock) = self.connections.get(&key) {
                if let Ok(mut tcb) = tcb_lock.lock() {
                    tcb.state = TcpState::Closed;
                }
            }
        }

        results
    }

    /// Mark that a retransmit for a given (local, remote, seq) has been sent.
    /// Updates the corresponding unacked segment's sent_time and retransmit counters
    /// and applies RTO backoff.
    pub fn mark_retransmit_sent(&mut self, local: SocketAddr, remote: SocketAddr, seq: u32, current_time: u64) {
        if let Some(tcb_lock) = self.connections.get(&(local, remote)).cloned() {
            if let Ok(mut tcb) = tcb_lock.lock() {
                if let Some(seg) = tcb.unacked_segments.iter_mut().find(|s| s.seq == seq) {
                    seg.sent_time = current_time;
                    seg.retransmit_count = seg.retransmit_count.saturating_add(1);
                    tcb.backoff_rto();
                    tcb.retransmit_count = tcb.retransmit_count.saturating_add(1);
                    tcb.last_retransmit_time = current_time;
                }
            }
        }
    }

    /// Record that a TCP segment was actually sent on the wire for a connection.
    /// This updates TCB state (snd_nxt) and queues the data for potential retransmit.
    pub fn record_sent_packet(&mut self, local: SocketAddr, remote: SocketAddr, seq: u32, flags: u16, payload: &[u8], current_time: u64) {
        if let Some(tcb_lock) = self.connections.get(&(local, remote)).cloned() {
            if let Ok(mut tcb) = tcb_lock.lock() {
                // Determine how many sequence numbers are consumed
                let mut consumed: u32 = payload.len() as u32;
                if flags & TcpHeader::FLAG_SYN != 0 {
                    consumed = consumed.saturating_add(1);
                }
                if flags & TcpHeader::FLAG_FIN != 0 {
                    consumed = consumed.saturating_add(1);
                }

                if consumed > 0 {
                    // Queue for retransmission
                    tcb.queue_unacked(seq, payload.to_vec(), current_time, flags);
                    tcb.last_retransmit_time = current_time;
                    // Advance snd_nxt to reflect the bytes consumed
                    tcb.snd_nxt = seq.wrapping_add(consumed);
                }
            }
        }
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

    #[test_case]
    fn test_ipv4_addr() {
        let addr = Ipv4Addr::new(192, 168, 1, 1);
        assert_eq!(addr.octets(), [192, 168, 1, 1]);
        assert_eq!(format!("{}", addr), "192.168.1.1");
    }

    #[test_case]
    fn test_socket_addr() {
        let addr = SocketAddr::new(Ipv4Addr::LOCALHOST, 8080);
        assert_eq!(format!("{}", addr), "127.0.0.1:8080");
    }

    #[test_case]
    fn test_tcp_state() {
        let tcb = TcpControlBlock::new(SocketAddr::new(Ipv4Addr::UNSPECIFIED, 0));
        assert_eq!(tcb.state, TcpState::Closed);
    }

    #[test_case]
    fn test_process_with_packet_zero_copy() {
        // Initialize a small mempool for tests
        let _ = crate::net::mempool::init_net_mempool(2);

        let mut processor = TcpProcessor::new();
        let local = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1), 1000);
        let remote = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1), 2000);

        // Create TCB and register connection
        let mut tcb = TcpControlBlock::new(local);
        tcb.remote_addr = Some(remote);
        tcb.state = TcpState::Established;
        tcb.rcv_nxt = 1;
        let tcb_arc = Arc::new(PoisonLock::new(tcb));
        processor.connections.insert((local, remote), tcb_arc.clone());

        // Build a simple TCP segment with a small payload
        let mut packet = crate::net::mempool::alloc_packet().expect("alloc packet");
        let payload = b"hello";
        let header_len = 20usize;

        // Src port 2000, dst port 1000
        packet.data_mut()[0..2].copy_from_slice(&2000u16.to_be_bytes());
        packet.data_mut()[2..4].copy_from_slice(&1000u16.to_be_bytes());
        // Seq = 1 (in-order)
        packet.data_mut()[4..8].copy_from_slice(&1u32.to_be_bytes());
        // Ack = 0
        packet.data_mut()[8..12].copy_from_slice(&0u32.to_be_bytes());
        // Data offset = 5 (20 bytes), flags = 0
        let data_off_flags = ((5u16 << 12) | 0u16).to_be_bytes();
        packet.data_mut()[12..14].copy_from_slice(&data_off_flags);
        // Window
        packet.data_mut()[14..16].copy_from_slice(&65535u16.to_be_bytes());
        // Payload
        packet.data_mut()[header_len..header_len + payload.len()].copy_from_slice(payload);
        packet.set_len(header_len + payload.len());

        // Call process_with_packet (zero-copy path)
        let data = alloc::vec::Vec::from(packet.data());
        let res = processor.process_with_packet(
            &data,
            Ipv4Address::from_octets(127, 0, 0, 1),
            Ipv4Address::from_octets(127, 0, 0, 1),
            packet,
            0,
        );

        // Ensure payload was enqueued as PacketRef
        if let Ok(g) = tcb_arc.lock() {
            assert!(!g.recv_buffer.is_empty());
            let first = g.recv_buffer.front().unwrap();
            assert_eq!(first.data(), payload);
        } else {
            panic!("TCB lock poisoned in test");
        }
    }

    #[test_case]
    fn test_can_send_respects_cwnd_bytes() {
        let local = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1), 1000);
        let mut tcb = TcpControlBlock::new(local);
        tcb.state = TcpState::Established;
        tcb.cwnd = 100;
        tcb.outstanding_bytes = 0;
        tcb.send_buffer_bytes = 0;
        assert!(tcb.can_send());
        // If queued bytes alone already exceed cwnd, cannot send
        tcb.send_buffer_bytes = 100;
        assert!(!tcb.can_send());
    }

    #[test_case]
    fn test_send_buffer_bytes_decrement_on_flush() {
        // Initialize a small mempool for tests
        let _ = crate::net::mempool::init_net_mempool(2);

        let local = SocketAddr::new(Ipv4Addr::new(127,0,0,1), 1001);
        let remote = SocketAddr::new(Ipv4Addr::new(127,0,0,1), 2001);

        // Create TCB and wrap in Arc<PoisonLock>
        let mut tcb = TcpControlBlock::new(local);
        tcb.state = TcpState::Established;
        tcb.remote_addr = Some(remote);
        let tcb_arc = Arc::new(PoisonLock::new(tcb));
        let mut stream = TcpStream { tcb: tcb_arc.clone() };

        // Create packet and enqueue
        let mut packet = crate::net::mempool::alloc_packet().expect("alloc packet");
        let payload = [0u8; 120];
        packet.data_mut()[..payload.len()].copy_from_slice(&payload);
        packet.set_len(payload.len());

        if let Ok(mut g) = tcb_arc.lock() {
            g.send_buffer_bytes = g.send_buffer_bytes.saturating_add(packet.len() as u32);
            g.send_buffer.push_back(packet);
        } else {
            panic!("TCB lock poisoned in test");
        }

        // Create a noop Context
        use core::task::{Context, RawWaker, RawWakerVTable, Waker};
        use core::pin::Pin;
        use core::task::Poll;
        const VTABLE: RawWakerVTable = RawWakerVTable::new(
            |_| RawWaker::new(core::ptr::null(), &VTABLE),
            |_| {},
            |_| {},
            |_| {},
        );
        let raw_waker = RawWaker::new(core::ptr::null(), &VTABLE);
        let waker = unsafe { Waker::from_raw(raw_waker) };
        let mut cx = Context::from_waker(&waker);

        // Call poll_flush
        let mut pinned_stream = unsafe { Pin::new_unchecked(&mut stream) };
        match pinned_stream.as_mut().poll_flush(&mut cx) {
            Poll::Ready(Ok(())) => {},
            other => panic!("poll_flush returned {:?}", other),
        }

        // Verify packet was requeued on send failure and outstanding is unchanged
        if let Ok(g) = tcb_arc.lock() {
            assert_eq!(g.send_buffer_bytes, payload.len() as u32);
            assert!(!g.send_buffer.is_empty());
            assert_eq!(g.outstanding_bytes, 0);
        } else {
            panic!("TCB lock poisoned");
        }
    }

    #[test_case]
    fn test_three_way_handshake() {
        // Initialize mempool for any packet allocations
        let _ = crate::net::mempool::init_net_mempool(4);

        let mut client = TcpProcessor::new();
        let mut server = TcpProcessor::new();

        let client_addr = SocketAddr::new(Ipv4Addr::new(127,0,0,1), 2000);
        let server_addr = SocketAddr::new(Ipv4Addr::new(127,0,0,1), 1000);

        // Server binds (creates a listener with backlog)
        let listener = server.bind(server_addr).expect("bind");

        // Client initiates connection (sets up a SynSent TCB)
        let client_stream = client.connect(client_addr, server_addr).expect("connect");

        // Grab client's initial sequence number
        let client_tcb_arc = client
            .connections
            .get(&(client_addr, server_addr))
            .expect("client tcb missing")
            .clone();

        let client_initial_seq = match client_tcb_arc.lock() {
            Ok(g) => g.snd_nxt,
            Err(_) => panic!("TCB lock poisoned"),
        };

        // Build SYN from client -> server
        let mut syn = [0u8; 20];
        syn[0..2].copy_from_slice(&client_addr.port.to_be_bytes());
        syn[2..4].copy_from_slice(&server_addr.port.to_be_bytes());
        syn[4..8].copy_from_slice(&client_initial_seq.to_be_bytes());
        syn[8..12].copy_from_slice(&0u32.to_be_bytes());
        let data_off_flags = ((5u16 << 12) | TcpHeader::FLAG_SYN).to_be_bytes();
        syn[12..14].copy_from_slice(&data_off_flags);
        syn[14..16].copy_from_slice(&65535u16.to_be_bytes());

        // Server processes SYN -> should return a SYN-ACK
        let res = server.process(
            &syn,
            Ipv4Address::from_octets(127, 0, 0, 1),
            Ipv4Address::from_octets(127, 0, 0, 1),
            0,
        );
        let syn_ack_pkt = match res {
            TcpProcessResult::SendPacket { local, remote, seq, ack, flags, .. } => {
                assert!(flags & TcpHeader::FLAG_SYN != 0);
                assert!(flags & TcpHeader::FLAG_ACK != 0);
                (local, remote, seq, ack)
            }
            _ => panic!("Expected SYN-ACK from server"),
        };

        // Build SYN-ACK bytes and feed to client
        let mut synack = [0u8; 20];
        synack[0..2].copy_from_slice(&syn_ack_pkt.0.port.to_be_bytes());
        synack[2..4].copy_from_slice(&syn_ack_pkt.1.port.to_be_bytes());
        synack[4..8].copy_from_slice(&syn_ack_pkt.2.to_be_bytes());
        synack[8..12].copy_from_slice(&syn_ack_pkt.3.to_be_bytes());
        let off_flags = ((5u16 << 12) | (TcpHeader::FLAG_SYN | TcpHeader::FLAG_ACK)).to_be_bytes();
        synack[12..14].copy_from_slice(&off_flags);
        synack[14..16].copy_from_slice(&65535u16.to_be_bytes());

        // Client processes SYN-ACK -> should generate an ACK
        let client_res = client.process(
            &synack,
            Ipv4Address::from_octets(127, 0, 0, 1),
            Ipv4Address::from_octets(127, 0, 0, 1),
            0,
        );

        let ack_pkt = match client_res {
            TcpProcessResult::SendPacket { local, remote, seq, ack, flags, .. } => {
                assert!(flags & TcpHeader::FLAG_ACK != 0);
                (local, remote, seq, ack)
            }
            _ => panic!("Expected ACK from client"),
        };

        // Build ACK bytes and feed back to server to complete handshake
        let mut ack = [0u8; 20];
        ack[0..2].copy_from_slice(&ack_pkt.0.port.to_be_bytes());
        ack[2..4].copy_from_slice(&ack_pkt.1.port.to_be_bytes());
        ack[4..8].copy_from_slice(&ack_pkt.2.to_be_bytes());
        ack[8..12].copy_from_slice(&ack_pkt.3.to_be_bytes());
        let ack_off_flags = ((5u16 << 12) | (TcpHeader::FLAG_ACK)).to_be_bytes();
        ack[12..14].copy_from_slice(&ack_off_flags);
        ack[14..16].copy_from_slice(&65535u16.to_be_bytes());

        let srv_res = server.process(
            &ack,
            Ipv4Address::from_octets(127, 0, 0, 1),
            Ipv4Address::from_octets(127, 0, 0, 1),
            0,
        );

        // Server should have moved the child TCB to Established and queued it in backlog
        match srv_res {
            TcpProcessResult::SendPacket { flags, .. } => {
                // Server may send an ACK back; that's fine
                assert!(flags & TcpHeader::FLAG_ACK != 0);
            }
            TcpProcessResult::None => {}
        }

        // Check backlog
        if let Ok(mut backlog) = listener.backlog.lock() {
            assert!(!backlog.is_empty());
            let stream = backlog.pop_front().unwrap();
            assert_eq!(stream.peer_addr().unwrap(), client_addr);
        } else {
            panic!("Listener backlog poisoned");
        }
    }

    #[test_case]
    fn test_retransmit_on_timeout() {
        let _ = crate::net::mempool::init_net_mempool(2);

        let mut proc = TcpProcessor::new();
        let local = SocketAddr::new(Ipv4Addr::new(127,0,0,1), 1000);
        let remote = SocketAddr::new(Ipv4Addr::new(127,0,0,1), 2000);

        let mut tcb = TcpControlBlock::new(local);
        tcb.remote_addr = Some(remote);
        tcb.state = TcpState::Established;
        // Add an unacked segment with old timestamp
        tcb.unacked_segments.push_back(UnackedSegment {
            seq: 1,
            data: vec![1,2,3],
            sent_time: 0,
            retransmit_count: 0,
            flags: TcpHeader::FLAG_PSH | TcpHeader::FLAG_ACK,
        });
        // Reflect outstanding bytes for the unacked segment
        tcb.outstanding_bytes = 3;
        tcb.rto = 1; // small RTO

        let tcb_arc = Arc::new(PoisonLock::new(tcb));
        proc.connections.insert((local, remote), tcb_arc.clone());

        let res = proc.check_retransmissions(2); // current_time > sent_time + rto
        assert_eq!(res.len(), 1);
        if let TcpProcessResult::SendPacket { seq, payload, .. } = &res[0] {
            assert_eq!(*seq, 1);
            assert_eq!(payload, &vec![1,2,3]);
        } else {
            panic!("Expected SendPacket");
        }
    }

    #[test_case]
    fn test_connect_future_wakes_on_established() {
        use core::task::{Context, RawWaker, RawWakerVTable, Waker};
        use core::pin::Pin;
        use core::task::Poll;
        use core::sync::atomic::{AtomicUsize, Ordering};

        static WAKE_COUNT: AtomicUsize = AtomicUsize::new(0);

        // Create a TCB in SynSent state
        let local = SocketAddr::new(Ipv4Addr::new(127,0,0,1), 4000);
        let mut tcb = TcpControlBlock::new(local);
        tcb.state = TcpState::SynSent;
        let tcb_arc = Arc::new(PoisonLock::new(tcb));

        // Create ConnectFuture
        let mut fut = ConnectFuture { tcb: tcb_arc.clone() };

        const VTABLE: RawWakerVTable = RawWakerVTable::new(
            |_| RawWaker::new(core::ptr::null(), &VTABLE),
            |_| { WAKE_COUNT.fetch_add(1, Ordering::SeqCst); },
            |_| { WAKE_COUNT.fetch_add(1, Ordering::SeqCst); },
            |_| {},
        );
        let raw_waker = RawWaker::new(core::ptr::null(), &VTABLE);
        let waker = unsafe { Waker::from_raw(raw_waker) };
        let mut cx = Context::from_waker(&waker);

        let mut pinned_fut = unsafe { Pin::new_unchecked(&mut fut) };

        // First poll should be Pending and register waker
        match pinned_fut.as_mut().poll(&mut cx) {
            Poll::Pending => {}
            other => panic!("ConnectFuture poll expected Pending, got {:?}", other),
        }

        // Ensure waker was stored in TCB
        if let Ok(g) = tcb_arc.lock() {
            assert!(g.connect_waker.is_some());
        } else {
            panic!("TCB lock poisoned");
        }

        // Simulate connection establishment and wake
        if let Ok(mut g) = tcb_arc.lock() {
            g.state = TcpState::Established;
            if let Some(w) = g.connect_waker.take() {
                w.wake();
            }
        }

        // Poll again, should be Ready(Ok(()))
        match pinned_fut.as_mut().poll(&mut cx) {
            Poll::Ready(Ok(())) => {}
            other => panic!("ConnectFuture poll expected Ready(Ok(())), got {:?}", other),
        }
    }

    #[test_case]
    fn test_record_sent_packet_updates_tcb() {
        // Create processor and register a connection
        let mut proc = TcpProcessor::new();
        let local = SocketAddr::new(Ipv4Addr::new(127,0,0,1), 7000);
        let remote = SocketAddr::new(Ipv4Addr::new(127,0,0,1), 8000);

        let mut tcb = TcpControlBlock::new(local);
        tcb.remote_addr = Some(remote);
        tcb.state = TcpState::Established;
        let tcb_arc = Arc::new(PoisonLock::new(tcb));
        proc.connections.insert((local, remote), tcb_arc.clone());

        // Simulate sending a data segment (length 4)
        let seq = 100u32;
        let payload = [1u8, 2, 3, 4];
        let now = 123456u64;

        proc.record_sent_packet(local, remote, seq, TcpHeader::FLAG_PSH | TcpHeader::FLAG_ACK, &payload, now);

        if let Ok(g) = tcb_arc.lock() {
            assert_eq!(g.outstanding_bytes, 4);
            assert_eq!(g.snd_nxt, seq.wrapping_add(4));
            assert_eq!(g.unacked_segments.front().unwrap().seq, seq);
        } else {
            panic!("TCB lock poisoned");
        }
    }

    #[test_case]
    fn test_ack_segments_removes_unacked_and_reduces_outstanding() {
        let mut tcb = TcpControlBlock::new(SocketAddr::new(Ipv4Addr::LOCALHOST, 9000));
        tcb.state = TcpState::Established;

        // Add an unacked segment
        tcb.unacked_segments.push_back(UnackedSegment {
            seq: 10,
            data: vec![1,2,3,4],
            sent_time: 0,
            retransmit_count: 0,
            flags: TcpHeader::FLAG_PSH | TcpHeader::FLAG_ACK,
        });
        tcb.outstanding_bytes = 4;

        // ACK that acknowledges the segment
        tcb.ack_segments(14); // seq + len

        assert!(tcb.unacked_segments.is_empty());
        assert_eq!(tcb.outstanding_bytes, 0);
    }

    #[test_case]
    fn test_accept_future_returns_on_push_connection() {
        use core::task::{Context, RawWaker, RawWakerVTable, Waker};
        use core::pin::Pin;
        use core::task::Poll;

        let mut server = TcpProcessor::new();
        let server_addr = SocketAddr::new(Ipv4Addr::new(127,0,0,1), 5000);
        let listener = server.bind(server_addr).expect("bind");

        // Create AcceptFuture manually
        let mut fut = AcceptFuture { listener: &listener };

        const VTABLE: RawWakerVTable = RawWakerVTable::new(
            |_| RawWaker::new(core::ptr::null(), &VTABLE),
            |_| {},
            |_| {},
            |_| {},
        );
        let raw_waker = RawWaker::new(core::ptr::null(), &VTABLE);
        let waker = unsafe { Waker::from_raw(raw_waker) };
        let mut cx = Context::from_waker(&waker);

        let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };

        // First poll: Pending (no backlog)
        match pinned.as_mut().poll(&mut cx) {
            Poll::Pending => {}
            _ => panic!("AcceptFuture expected Pending"),
        }

        // Prepare a TcpStream and push into backlog
        let local = SocketAddr::new(Ipv4Addr::new(127,0,0,1), 5000);
        let remote = SocketAddr::new(Ipv4Addr::new(127,0,0,1), 6000);
        let mut tcb = TcpControlBlock::new(local);
        tcb.remote_addr = Some(remote);
        tcb.state = TcpState::Established;
        let stream = TcpStream { tcb: Arc::new(PoisonLock::new(tcb)) };

        listener.push_connection(stream, remote);

        // Second poll should return Ready with the connection
        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(Ok((stream, addr))) => {
                assert_eq!(addr, remote);
                assert!(stream.peer_addr().is_some());
            }
            _ => panic!("AcceptFuture expected Ready"),
        }
    }

    #[test_case]
    fn test_connect_timeout_expires() {
        use core::task::{Context, RawWaker, RawWakerVTable, Waker};
        use core::pin::Pin;
        use core::task::Poll;

        let now = crate::time::precise_time_nanos() / 1000;
        let local = SocketAddr::new(Ipv4Addr::LOCALHOST, 4001);
        let mut tcb = TcpControlBlock::new(local);
        tcb.state = TcpState::SynSent;
        let tcb_arc = Arc::new(PoisonLock::new(tcb));

        // Create a ConnectTimeoutFuture that already expired
        let timeout_us = 1000u64;
        let start_us = now.saturating_sub(timeout_us + 1);
        let mut fut = ConnectTimeoutFuture {
            tcb: tcb_arc.clone(),
            start_us,
            timeout_us,
        };

        const VTABLE: RawWakerVTable = RawWakerVTable::new(
            |_| RawWaker::new(core::ptr::null(), &VTABLE),
            |_| {},
            |_| {},
            |_| {},
        );
        let raw_waker = RawWaker::new(core::ptr::null(), &VTABLE);
        let waker = unsafe { Waker::from_raw(raw_waker) };
        let mut cx = Context::from_waker(&waker);

        let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };

        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(Err(TcpError::Timeout)) => {}
            other => panic!("ConnectTimeoutFuture expected Timeout, got {:?}", other),
        }
    }
}
