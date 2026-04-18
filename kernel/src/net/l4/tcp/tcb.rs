// ============================================================================
// kernel/src/net/l4/endpoint/tcb.rs
// ============================================================================
//! # TCP Control Block - 接続状態管理
//!
//! TcpConnectionState, TcpControlBlockEntry, TcbTable, tcp_flags

use crate::sync::PoisonRwLock;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use super::congestion::{CongestionAlgorithm, CongestionControllerVariant};
use super::flow_control::FlowController;
use super::retransmit::check_retransmit_timeouts;
use crate::net::l4::types::{EndpointAddr, EndpointError, EndpointFd, conn_key_hash, seq_after};
use super::window_scale::WindowScaleOption;
use crate::net::runtime::manager::NetIfId;
use crate::net::types::InterfaceScope;

/// TCPフラグ
pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;
}

pub use crate::net::l4::tcp::TcpState as TcpConnectionState;

/// TCP制御ブロック（RFC 5681/7323準拠）
#[derive(Debug)]
pub struct TcpControlBlockEntry {
    pub fd: EndpointFd,
    pub local: EndpointAddr,
    pub remote: EndpointAddr,
    pub scope: InterfaceScope,
    pub ingress_if_id: Option<NetIfId>,
    pub state: TcpConnectionState,
    pub snd_nxt: u32,
    pub snd_una: u32,
    pub rcv_nxt: u32,
    pub snd_wnd: u16,
    pub max_snd_wnd: u32,
    pub rcv_wnd: u16,
    pub retransmit_count: u8,
    pub last_send_tick: u64,
    pub congestion: CongestionControllerVariant,
    pub window_scale: WindowScaleOption,
    pub flow_control: FlowController,
    pub mss: u32,
    pub snd_up: u32,
    pub snd_urg: bool,
    pub rcv_up: u32,
    pub rcv_urg: bool,
    pub sack_enabled: bool,
    pub ts_enabled: bool,
    pub ts_val: u32,
    pub ts_ecr: u32,
    pub nagle_enabled: bool,
    pub priority: u8,
    pub delayed_ack_pending: u8,
    pub delayed_ack_timer: u64,
    pub pending_error: Option<EndpointError>,
}

#[derive(Debug, Clone, Copy)]
pub struct TcpControlBlockSnapshot {
    pub fd: EndpointFd,
    pub local: EndpointAddr,
    pub remote: EndpointAddr,
    pub scope: InterfaceScope,
    pub ingress_if_id: Option<NetIfId>,
    pub state: TcpConnectionState,
    pub snd_nxt: u32,
    pub snd_una: u32,
    pub rcv_nxt: u32,
    pub snd_wnd: u16,
    pub max_snd_wnd: u32,
    pub rcv_wnd: u16,
    pub scaled_snd_wnd: u32,
    pub effective_send_window: u32,
    pub advertised_recv_window: u16,
    pub effective_recv_window: u32,
    pub mss: u32,
    pub snd_up: u32,
    pub snd_urg: bool,
    pub rcv_up: u32,
    pub rcv_urg: bool,
    pub sack_enabled: bool,
    pub ts_enabled: bool,
    pub ts_val: u32,
    pub ts_ecr: u32,
    pub nagle_enabled: bool,
    pub priority: u8,
    pub delayed_ack_pending: u8,
    pub delayed_ack_timer: u64,
}

impl From<&TcpControlBlockEntry> for TcpControlBlockSnapshot {
    fn from(value: &TcpControlBlockEntry) -> Self {
        Self {
            fd: value.fd,
            local: value.local,
            remote: value.remote,
            scope: value.scope,
            ingress_if_id: value.ingress_if_id,
            state: value.state,
            snd_nxt: value.snd_nxt,
            snd_una: value.snd_una,
            rcv_nxt: value.rcv_nxt,
            snd_wnd: value.snd_wnd,
            max_snd_wnd: value.max_snd_wnd,
            rcv_wnd: value.rcv_wnd,
            scaled_snd_wnd: value.window_scale.scale_snd_window(value.snd_wnd),
            effective_send_window: value.effective_send_window(),
            advertised_recv_window: value.advertised_recv_window(),
            effective_recv_window: value.effective_recv_window(),
            mss: value.mss,
            snd_up: value.snd_up,
            snd_urg: value.snd_urg,
            rcv_up: value.rcv_up,
            rcv_urg: value.rcv_urg,
            sack_enabled: value.sack_enabled,
            ts_enabled: value.ts_enabled,
            ts_val: value.ts_val,
            ts_ecr: value.ts_ecr,
            nagle_enabled: value.nagle_enabled,
            priority: value.priority,
            delayed_ack_pending: value.delayed_ack_pending,
            delayed_ack_timer: value.delayed_ack_timer,
        }
    }
}

impl TcpControlBlockSnapshot {
    pub fn effective_send_window(self) -> u32 {
        self.effective_send_window
    }

    pub fn advertised_recv_window(self) -> u16 {
        self.advertised_recv_window
    }

    pub fn effective_recv_window(self) -> u32 {
        self.effective_recv_window
    }

    pub fn is_outstanding(self) -> bool {
        self.snd_nxt != self.snd_una
    }

    pub fn is_nodelay_enabled(self) -> bool {
        !self.nagle_enabled
    }

    pub fn should_delay_send(self, data_len: usize) -> bool {
        if data_len >= self.mss as usize {
            return false;
        }
        let sws_threshold = self.max_snd_wnd / 2;
        let scaled_rwnd = self.scaled_snd_wnd;
        if scaled_rwnd >= sws_threshold && scaled_rwnd > 0 && data_len > 0 {
        } else if self.is_outstanding() {
            return true;
        }
        if !self.nagle_enabled {
            return false;
        }
        if self.is_outstanding() {
            return true;
        }
        false
    }
}

impl TcpControlBlockEntry {
    pub fn new(fd: EndpointFd, local: EndpointAddr, remote: EndpointAddr) -> Self {
        Self::with_algorithm(fd, local, remote, CongestionAlgorithm::NewReno)
    }

    pub fn with_algorithm(
        fd: EndpointFd,
        local: EndpointAddr,
        remote: EndpointAddr,
        algorithm: CongestionAlgorithm,
    ) -> Self {
        Self {
            fd,
            local,
            remote,
            scope: InterfaceScope::Any,
            ingress_if_id: None,
            state: TcpConnectionState::Closed,
            snd_nxt: 0,
            snd_una: 0,
            rcv_nxt: 0,
            snd_wnd: 65535,
            max_snd_wnd: 65535,
            rcv_wnd: 65535,
            retransmit_count: 0,
            last_send_tick: 0,
            congestion: CongestionControllerVariant::from_algorithm(algorithm),
            window_scale: WindowScaleOption::default_enabled(),
            flow_control: FlowController::new(),
            mss: 536,
            snd_up: 0,
            snd_urg: false,
            rcv_up: 0,
            rcv_urg: false,
            sack_enabled: false,
            ts_enabled: false,
            ts_val: 0,
            ts_ecr: 0,
            nagle_enabled: true,
            priority: 0,
            delayed_ack_pending: 0,
            delayed_ack_timer: 0,
            pending_error: None,
        }
    }

    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.nagle_enabled = !nodelay;
    }

    pub fn set_mss(&mut self, mss: u32) {
        self.mss = mss;
        self.congestion.update_mss(mss);
    }

    pub fn set_priority(&mut self, priority: u8) {
        self.priority = priority & 0x3F;
    }

    pub fn is_nodelay_enabled(&self) -> bool {
        !self.nagle_enabled
    }

    pub fn should_delay_send(&self, data_len: usize) -> bool {
        if data_len >= self.mss as usize {
            return false;
        }
        let sws_threshold = self.max_snd_wnd / 2;
        let scaled_rwnd = self.window_scale.scale_snd_window(self.snd_wnd);
        if scaled_rwnd >= sws_threshold && scaled_rwnd > 0 && data_len > 0 {
        } else if self.is_outstanding() {
            return true;
        }
        if !self.nagle_enabled {
            return false;
        }
        if self.is_outstanding() {
            return true;
        }
        false
    }

    pub fn is_outstanding(&self) -> bool {
        self.snd_nxt != self.snd_una
    }

    pub fn initialize_seq(&mut self, isn: u32) {
        self.snd_nxt = isn;
        self.snd_una = isn;
    }

    pub fn effective_send_window(&self) -> u32 {
        let scaled_rwnd = self.window_scale.scale_snd_window(self.snd_wnd);
        self.congestion.available_window(scaled_rwnd)
    }

    pub fn effective_recv_window(&self) -> u32 {
        self.flow_control.advertised_window()
    }

    pub fn advertised_recv_window(&self) -> u16 {
        self.window_scale
            .advertised_window(self.flow_control.advertised_window())
    }

    pub fn on_ack_received(
        &mut self,
        ack_num: u32,
        is_dup: bool,
        current_time_ms: u64,
        rtt_sample_ms: u64,
    ) {
        let is_valid_ack = (ack_num.wrapping_sub(self.snd_una) as i32) > 0
            && (ack_num.wrapping_sub(self.snd_nxt) as i32) <= 0;

        let bytes_acked = if is_valid_ack && !is_dup {
            ack_num.wrapping_sub(self.snd_una)
        } else {
            0
        };

        self.congestion.on_ack(
            bytes_acked,
            is_dup,
            self.snd_una,
            current_time_ms,
            rtt_sample_ms,
        );

        if !is_dup && is_valid_ack {
            self.snd_una = ack_num;
        }
    }

    pub fn on_data_received(&mut self, bytes: u32) {
        self.flow_control.on_receive(bytes);
        self.rcv_wnd = self.advertised_recv_window();
    }

    pub fn on_data_consumed(&mut self, bytes: u32) {
        self.flow_control.on_consume(bytes);
        self.rcv_wnd = self.advertised_recv_window();
    }

    pub fn on_send(&mut self, bytes: u32) {
        let tick = self.last_send_tick;
        self.congestion.on_send(bytes, tick);
        self.delayed_ack_pending = 0;
    }

    pub fn on_timeout(&mut self) {
        let tick = self.last_send_tick;
        self.congestion.on_timeout(tick);
        self.retransmit_count = self.retransmit_count.saturating_add(1);
    }

    pub fn update_peer_window(&mut self, window: u16) {
        self.snd_wnd = window;
        let scaled = self.window_scale.scale_snd_window(window);
        self.flow_control.update_peer_window(scaled);
        if scaled > self.max_snd_wnd {
            self.max_snd_wnd = scaled;
        }
    }

    pub fn can_send(&self, bytes: u32) -> bool {
        self.effective_send_window() >= bytes && self.flow_control.can_send()
    }

    pub fn set_urgent(&mut self, urgent_offset: u32) {
        self.snd_up = self.snd_nxt.wrapping_add(urgent_offset);
        self.snd_urg = true;
    }

    pub fn clear_send_urgent(&mut self) {
        self.snd_urg = false;
    }

    pub fn should_send_urg(&self) -> bool {
        self.snd_urg && self.snd_up > self.snd_una
    }

    pub fn urgent_pointer_for_segment(&self, seg_seq: u32) -> u16 {
        if !self.snd_urg {
            return 0;
        }
        let offset = self.snd_up.wrapping_sub(seg_seq);
        if offset > 0xFFFF {
            0xFFFF
        } else {
            offset as u16
        }
    }

    pub fn on_urgent_received(&mut self, seg_seq: u32, urgent_ptr: u16) -> bool {
        let new_up = seg_seq.wrapping_add(urgent_ptr as u32);
        let is_newer = seq_after(new_up, self.rcv_up);
        if is_newer && new_up != self.rcv_up {
            self.rcv_up = new_up;
            self.rcv_urg = true;
            return true;
        }
        false
    }

    pub fn has_urgent_data(&self) -> bool {
        self.rcv_urg && seq_after(self.rcv_up, self.rcv_nxt)
    }

    pub fn urgent_data_offset(&self) -> Option<u32> {
        if !self.has_urgent_data() {
            return None;
        }
        let offset = self.rcv_up.wrapping_sub(self.rcv_nxt);
        if offset > 0 { Some(offset - 1) } else { None }
    }

    pub fn clear_recv_urgent(&mut self) {
        self.rcv_urg = false;
    }

    pub fn on_source_quench(&mut self) {
        self.congestion.on_timeout(self.last_send_tick);
    }

    pub fn on_icmp_error(&mut self, error: EndpointError) {
        self.pending_error = Some(error);
    }
}

const TCB_SHARD_COUNT: usize = 16;
const TCB_SHARD_MASK: usize = TCB_SHARD_COUNT - 1;

pub struct TcbTable {
    shards: [PoisonRwLock<BTreeMap<(EndpointAddr, EndpointAddr), TcpControlBlockEntry>>;
        TCB_SHARD_COUNT],
    seq_counter: AtomicU32,
    pub current_tick: AtomicU64,
    total_count: AtomicUsize,
    syn_recv_count: AtomicUsize,
    /// SYN Cookie 用のシークレットキー
    syncookie_secret: PoisonRwLock<[u8; 32]>,
    /// ISN 生成用の安定したシークレットキー (RFC 6528)
    isn_secret: PoisonRwLock<[u8; 32]>,
}

const MAX_TCB_ENTRIES: usize = 8192;
const MAX_SYN_RECEIVED_ENTRIES: usize = 4096;

#[inline(always)]
fn shard_index(local: &EndpointAddr, remote: &EndpointAddr) -> usize {
    (conn_key_hash(local, remote) as usize) & TCB_SHARD_MASK
}

impl TcbTable {
    pub const fn new() -> Self {
        const EMPTY_SHARD: PoisonRwLock<
            BTreeMap<(EndpointAddr, EndpointAddr), TcpControlBlockEntry>,
        > = PoisonRwLock::new(BTreeMap::new());
        Self {
            shards: [EMPTY_SHARD; TCB_SHARD_COUNT],
            seq_counter: AtomicU32::new(0),
            current_tick: AtomicU64::new(0),
            total_count: AtomicUsize::new(0),
            syn_recv_count: AtomicUsize::new(0),
            syncookie_secret: PoisonRwLock::new([0u8; 32]),
            isn_secret: PoisonRwLock::new([0u8; 32]),
        }
    }

    /// シークレットキーを初期化する
    pub fn init_syncookies(&self) {
        if let Ok(mut secret) = self.syncookie_secret.write() {
            let random_bytes = crate::net::security::tls::crypto::random::generate_random();
            secret.copy_from_slice(&random_bytes[0..32]);
        }
        if let Ok(mut secret) = self.isn_secret.write() {
            let random_bytes = crate::net::security::tls::crypto::random::generate_random();
            secret.copy_from_slice(&random_bytes[0..32]);
        }
        log::info!("[TCP] SYN Cookies and ISN secrets initialized.");
    }

    /// SYN Cookie を生成する (RFC 4987)
    pub fn generate_syncookie(
        &self,
        local: EndpointAddr,
        remote: EndpointAddr,
        client_isn: u32,
        mss_idx: u8,
    ) -> u32 {
        use crate::net::security::tls::crypto::hmac::hmac_sha256;

        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&local.as_bytes());
        data.extend_from_slice(&remote.as_bytes());
        data.extend_from_slice(&client_isn.to_be_bytes());

        // 5ビットのタイムスタンプ（分単位、32分でループ）
        let time_bits = ((self.current_tick.load(Ordering::Relaxed) / 60000) & 0x1F) as u32;
        data.extend_from_slice(&time_bits.to_be_bytes());

        // HMAC-SHA256 でハッシュ生成 (RFC 4987)
        let hash_val = if let Ok(secret) = self.syncookie_secret.read() {
            let h = hmac_sha256(&*secret, &data);
            u32::from_be_bytes([h[0], h[1], h[2], h[3]])
        } else {
            0 // フォールバック（通常は起こらない）
        };

        // Cookie 構造: [ Hash(24 bits) | Time(5 bits) | MSS Index(3 bits) ]
        (hash_val & 0xFFFFFF00) | (time_bits << 3) | (mss_idx as u32 & 0x07)
    }

    /// SYN Cookie を検証し、有効なら MSS インデックスを返す
    pub fn verify_syncookie(
        &self,
        local: EndpointAddr,
        remote: EndpointAddr,
        ack_num: u32,
        client_isn: u32,
    ) -> Option<u8> {
        use crate::net::security::tls::crypto::hmac::hmac_sha256;

        let cookie = ack_num.wrapping_sub(1);
        let mss_idx = (cookie & 0x07) as u8;
        let time_bits_received = (cookie >> 3) & 0x1F;

        let current_tick = self.current_tick.load(Ordering::Relaxed);
        let time_bits_now = (current_tick / 60000) & 0x1F;

        // タイムスタンプ有効期限チェック（最大数分間）
        let diff = (time_bits_now as i32 - time_bits_received as i32).rem_euclid(32);
        if diff > 4 {
            return None;
        }

        // ハッシュ再計算
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&local.as_bytes());
        data.extend_from_slice(&remote.as_bytes());
        data.extend_from_slice(&client_isn.to_be_bytes());
        data.extend_from_slice(&(time_bits_received as u32).to_be_bytes());

        let hash_val = if let Ok(secret) = self.syncookie_secret.read() {
            let h = hmac_sha256(&*secret, &data);
            u32::from_be_bytes([h[0], h[1], h[2], h[3]])
        } else {
            return None;
        };

        if (cookie & 0xFFFFFF00) == (hash_val & 0xFFFFFF00) {
            Some(mss_idx)
        } else {
            None
        }
    }

    /// RFC 6528 準拠の初期シーケンス番号 (ISN) 生成
    pub fn generate_isn(&self, local: EndpointAddr, remote: EndpointAddr) -> u32 {
        use crate::net::security::tls::crypto::hmac::hmac_sha256;

        // ISN = M + F(local, remote, secret)
        // M: 4マイクロ秒精度のタイマー (ここでは tick * 250 で近似)
        let m = (self.current_tick.load(Ordering::Relaxed) as u32).wrapping_mul(250);

        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&local.as_bytes());
        data.extend_from_slice(&remote.as_bytes());

        let hash_f = if let Ok(secret) = self.isn_secret.read() {
            let h = hmac_sha256(&*secret, &data);
            u32::from_be_bytes([h[0], h[1], h[2], h[3]])
        } else {
            0
        };

        let counter = self.seq_counter.fetch_add(1, Ordering::Relaxed);
        m.wrapping_add(hash_f).wrapping_add(counter)
    }

    pub fn tick(&self) {
        let tick = self.current_tick.fetch_add(1, Ordering::Relaxed);
        if tick % 100 == 0 {
            check_retransmit_timeouts();
            self.check_zero_window_probes(tick);
            self.scavenge_syn_received(tick);
            self.scavenge_time_wait(tick);
            self.scavenge_fin_wait_2(tick);
        }
    }

    fn scavenge_fin_wait_2(&self, current_tick: u64) {
        const FIN_WAIT_2_TIMEOUT_TICKS: u64 = 60_000;
        const MAX_SCAVENGE_PER_SHARD: usize = 8;
        for shard in &self.shards {
            let mut entries = shard.write().unwrap_or_else(|e| e.into_inner());
            let mut to_remove: Vec<(EndpointAddr, EndpointAddr)> = Vec::new();
            for (key, entry) in entries.iter() {
                if entry.state == TcpConnectionState::FinWait2
                    && current_tick.saturating_sub(entry.last_send_tick) > FIN_WAIT_2_TIMEOUT_TICKS
                {
                    to_remove.push(*key);
                    if to_remove.len() >= MAX_SCAVENGE_PER_SHARD {
                        break;
                    }
                }
            }
            for key in to_remove {
                entries.remove(&key);
                self.total_count.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    fn check_zero_window_probes(&self, current_tick: u64) {
        use crate::net::l4::socket::lookup_endpoint;
        use super::retransmit::retransmit_queue_push;
        use super::segment::{TcpSegmentBuilder, send_tcp_segment_payload};
        for shard in &self.shards {
            let mut entries = shard.write().unwrap_or_else(|e| e.into_inner());
            for (key, entry) in entries.iter_mut() {
                if entry.state == TcpConnectionState::Established {
                    if entry.is_outstanding() {
                        continue;
                    }
                    if entry.flow_control.should_send_probe(current_tick) {
                        if let Some(socket) = lookup_endpoint(entry.fd) {
                            let mut inner =
                                socket.inner().lock().unwrap_or_else(|e| e.into_inner());
                            if let Some(probe_payload) = inner.take_send_payload_prefix(1) {
                                drop(inner);
                                let seq = entry.snd_nxt;
                                let mut builder = TcpSegmentBuilder::new(key.0.port(), key.1.port())
                                    .seq(seq)
                                    .ack(entry.rcv_nxt)
                                    .ack_flag()
                                    .psh()
                                    .window(entry.advertised_recv_window())
                                    .payload_packet(probe_payload);
                                if entry.ts_enabled {
                                    let ts_val = (current_tick / 10) as u32;
                                    builder = builder.nop().nop().timestamp(ts_val, entry.ts_ecr);
                                }
                                let Ok(segment) = builder.build_checked_packet(key.0, key.1) else {
                                    continue;
                                };
                                let Some(retransmit_segment) =
                                    super::retransmit::materialize_retransmit_copy(&segment)
                                else {
                                    continue;
                                };
                                if send_tcp_segment_payload(key.0, key.1, segment) {
                                    retransmit_queue_push(
                                        key.0,
                                        key.1,
                                        seq,
                                        1,
                                        retransmit_segment,
                                    );
                                    entry.snd_nxt = entry.snd_nxt.wrapping_add(1);
                                    entry.flow_control.on_probe_sent(current_tick);
                                } else {
                                    let mut inner =
                                        socket.inner().lock().unwrap_or_else(|e| e.into_inner());
                                    if let Some(probe_body) =
                                        crate::net::payload::retain_payload_window_owned(
                                            retransmit_segment,
                                            crate::net::l4::tcp::TcpHeader::MIN_HEADER_LEN,
                                            1,
                                        )
                                    {
                                        inner.push_send_payload_front(probe_body);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn scavenge_time_wait(&self, current_tick: u64) {
        const TIME_WAIT_TIMEOUT_TICKS: u64 = 240_000;
        const MAX_SCAVENGE_PER_SHARD: usize = 16;
        for shard in &self.shards {
            let mut entries = shard.write().unwrap_or_else(|e| e.into_inner());
            let mut to_remove: Vec<(EndpointAddr, EndpointAddr)> = Vec::new();
            for (key, entry) in entries.iter() {
                if entry.state == TcpConnectionState::TimeWait
                    && current_tick.saturating_sub(entry.last_send_tick) > TIME_WAIT_TIMEOUT_TICKS
                {
                    to_remove.push(*key);
                    if to_remove.len() >= MAX_SCAVENGE_PER_SHARD {
                        break;
                    }
                }
            }
            for key in to_remove {
                entries.remove(&key);
            }
        }
    }

    fn scavenge_syn_received(&self, current_tick: u64) {
        // 通常のタイムアウト: 3秒
        const SYN_RECV_TIMEOUT_TICKS: u64 = 3000;
        // 圧迫時のタイムアウト: 500ms
        const AGGRESSIVE_TIMEOUT_TICKS: u64 = 500;

        let count = self.syn_recv_count.load(Ordering::Relaxed);
        if count < MAX_SYN_RECEIVED_ENTRIES / 4 {
            return;
        }

        // 負荷に応じてタイムアウトを短縮し、1回のスキャンで消去する数を増やす
        let (timeout, max_per_shard) = if count > (MAX_SYN_RECEIVED_ENTRIES * 3 / 4) {
            (AGGRESSIVE_TIMEOUT_TICKS, 32) // 高負荷時
        } else {
            (SYN_RECV_TIMEOUT_TICKS, 8) // 低・中負荷時
        };

        for shard in &self.shards {
            let mut entries = shard.write().unwrap_or_else(|e| e.into_inner());
            let mut to_remove: alloc::vec::Vec<(EndpointAddr, EndpointAddr)> =
                alloc::vec::Vec::with_capacity(max_per_shard);
            for (key, entry) in entries.iter() {
                if entry.state == TcpConnectionState::SynReceived
                    && current_tick.saturating_sub(entry.last_send_tick) > timeout
                {
                    to_remove.push(*key);
                    if to_remove.len() >= max_per_shard {
                        break;
                    }
                }
            }
            for key in to_remove {
                if let Some(entry) = entries.remove(&key) {
                    self.total_count.fetch_sub(1, Ordering::Relaxed);
                    if entry.state == TcpConnectionState::SynReceived {
                        self.syn_recv_count.fetch_sub(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    pub fn get_current_tick(&self) -> u64 {
        self.current_tick.load(Ordering::Relaxed)
    }

    /// 受信済みの SYN の数
    pub fn syn_recv_count(&self) -> usize {
        self.syn_recv_count.load(Ordering::Relaxed)
    }

    pub fn insert(&self, entry: TcpControlBlockEntry) -> Result<(), &'static str> {
        if self.total_count.load(Ordering::Relaxed) >= MAX_TCB_ENTRIES {
            return Err("TCB table full");
        }
        if entry.state == TcpConnectionState::SynReceived {
            if self.syn_recv_count.load(Ordering::Relaxed) >= MAX_SYN_RECEIVED_ENTRIES {
                return Err("Too many SYN-RECV connections");
            }
        }
        let idx = shard_index(&entry.local, &entry.remote);
        let key = (entry.local, entry.remote);
        let mut shard = self.shards[idx].write().unwrap_or_else(|e| e.into_inner());
        let is_syn_recv = entry.state == TcpConnectionState::SynReceived;
        if shard.insert(key, entry).is_none() {
            self.total_count.fetch_add(1, Ordering::Relaxed);
            if is_syn_recv {
                self.syn_recv_count.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    pub fn read<R, F>(&self, local: EndpointAddr, remote: EndpointAddr, f: F) -> Option<R>
    where
        F: FnOnce(&TcpControlBlockEntry) -> R,
    {
        let idx = shard_index(&local, &remote);
        let shard = self.shards[idx].read().unwrap_or_else(|e| e.into_inner());
        shard.get(&(local, remote)).map(f)
    }

    pub fn update<F>(&self, local: EndpointAddr, remote: EndpointAddr, f: F) -> bool
    where
        F: FnOnce(&mut TcpControlBlockEntry),
    {
        let idx = shard_index(&local, &remote);
        let mut shard = self.shards[idx].write().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = shard.get_mut(&(local, remote)) {
            let old_state = entry.state;
            f(entry);
            let new_state = entry.state;
            if old_state != new_state {
                if old_state == TcpConnectionState::SynReceived {
                    self.syn_recv_count.fetch_sub(1, Ordering::Relaxed);
                }
                if new_state == TcpConnectionState::SynReceived {
                    self.syn_recv_count.fetch_add(1, Ordering::Relaxed);
                }
            }
            true
        } else {
            false
        }
    }

    pub fn remove(
        &self,
        local: EndpointAddr,
        remote: EndpointAddr,
    ) -> Option<TcpControlBlockEntry> {
        let idx = shard_index(&local, &remote);
        let mut shard = self.shards[idx].write().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = shard.remove(&(local, remote)) {
            self.total_count.fetch_sub(1, Ordering::Relaxed);
            if entry.state == TcpConnectionState::SynReceived {
                self.syn_recv_count.fetch_sub(1, Ordering::Relaxed);
            }
            Some(entry)
        } else {
            None
        }
    }

    pub fn read_by_fd<R, F>(&self, fd: EndpointFd, f: F) -> Option<R>
    where
        F: FnOnce(&TcpControlBlockEntry) -> R,
    {
        for shard in &self.shards {
            let guard = shard.read().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = guard.values().find(|e| e.fd == fd) {
                return Some(f(entry));
            }
        }
        None
    }

    pub fn remove_by_fd(&self, fd: EndpointFd) -> Option<TcpControlBlockEntry> {
        for shard in &self.shards {
            let mut guard = shard.write().unwrap_or_else(|e| e.into_inner());
            let key = guard.iter().find(|(_, e)| e.fd == fd).map(|(k, _)| *k);
            if let Some(k) = key {
                if let Some(entry) = guard.remove(&k) {
                    self.total_count.fetch_sub(1, Ordering::Relaxed);
                    if entry.state == TcpConnectionState::SynReceived {
                        self.syn_recv_count.fetch_sub(1, Ordering::Relaxed);
                    }
                    return Some(entry);
                }
            }
        }
        None
    }

    pub fn lookup_mut<R, F>(&self, local: EndpointAddr, remote: EndpointAddr, f: F) -> Option<R>
    where
        F: FnOnce(&mut TcpControlBlockEntry) -> R,
    {
        let idx = shard_index(&local, &remote);
        let mut shard = self.shards[idx].write().unwrap_or_else(|e| e.into_inner());
        shard.get_mut(&(local, remote)).map(f)
    }

    pub fn list_connections(&self) -> alloc::vec::Vec<TcpConnectionSnapshot> {
        let mut result = alloc::vec::Vec::new();
        for shard in &self.shards {
            let guard = shard.read().unwrap_or_else(|e| e.into_inner());
            result.extend(guard.values().map(|entry| TcpConnectionSnapshot {
                local: entry.local,
                remote: entry.remote,
                state: entry.state,
                snd_nxt: entry.snd_nxt,
                snd_una: entry.snd_una,
                rcv_nxt: entry.rcv_nxt,
                snd_wnd: entry.snd_wnd,
                rcv_wnd: entry.rcv_wnd,
            }));
        }
        result
    }

    pub fn connection_count(&self) -> usize {
        self.total_count.load(Ordering::Relaxed)
    }

    pub fn validate_icmp_sequence(
        &self,
        local: EndpointAddr,
        remote: EndpointAddr,
        seq: u32,
    ) -> bool {
        if let Some(snapshot) = self.read(local, remote, |entry| TcpControlBlockSnapshot::from(entry)) {
            if snapshot.state == TcpConnectionState::SynSent {
                return seq == snapshot.snd_una;
            }
            match snapshot.state {
                TcpConnectionState::Closed | TcpConnectionState::Listen => return false,
                _ => {}
            }
            let una = snapshot.snd_una;
            let nxt = snapshot.snd_nxt;
            let diff_una = seq.wrapping_sub(una);
            let diff_nxt = nxt.wrapping_sub(una);
            return diff_una <= diff_nxt;
        }
        false
    }

    pub fn for_each_established<F>(&self, mut f: F)
    where
        F: FnMut(&TcpControlBlockEntry),
    {
        for shard in &self.shards {
            let guard = shard.read().unwrap_or_else(|e| e.into_inner());
            for entry in guard.values() {
                if entry.state == TcpConnectionState::Established {
                    f(entry);
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpConnectionSnapshot {
    pub local: EndpointAddr,
    pub remote: EndpointAddr,
    pub state: TcpConnectionState,
    pub snd_nxt: u32,
    pub snd_una: u32,
    pub rcv_nxt: u32,
    pub snd_wnd: u16,
    pub rcv_wnd: u16,
}

pub static TCB_TABLE: TcbTable = TcbTable::new();

pub fn tcb_table() -> &'static TcbTable {
    &TCB_TABLE
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests {
    use super::*;

    #[cfg_attr(test, test_case)]
    pub fn test_tcp_connection_state() {
        let state = TcpConnectionState::Closed;
        assert!(matches!(state, TcpConnectionState::Closed));
        let state = TcpConnectionState::Established;
        assert!(matches!(state, TcpConnectionState::Established));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_tcp_control_block_entry() {
        let fd = EndpointFd::from_raw(1);
        let local = EndpointAddr::new([192, 168, 1, 1], 12345);
        let remote = EndpointAddr::new([192, 168, 1, 2], 80);
        let mut tcb = TcpControlBlockEntry::new(fd, local, remote);
        assert_eq!(tcb.state, TcpConnectionState::Closed);
        tcb.initialize_seq(1000);
        assert_eq!(tcb.snd_nxt, 1000);
        assert_eq!(tcb.snd_una, 1000);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_tcp_flags() {
        assert_eq!(tcp_flags::FIN, 0x01);
        assert_eq!(tcp_flags::SYN, 0x02);
        assert_eq!(tcp_flags::RST, 0x04);
        assert_eq!(tcp_flags::PSH, 0x08);
        assert_eq!(tcp_flags::ACK, 0x10);
        let syn_ack = tcp_flags::SYN | tcp_flags::ACK;
        assert_eq!(syn_ack, 0x12);
    }
}

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;
    pub fn tcp_connection_state_smoke() -> bool {
        let state = TcpConnectionState::Closed;
        if !matches!(state, TcpConnectionState::Closed) {
            return false;
        }
        let state = TcpConnectionState::Established;
        matches!(state, TcpConnectionState::Established)
    }
    pub fn tcp_control_block_entry_smoke() -> bool {
        let fd = EndpointFd::from_raw(1);
        let local = EndpointAddr::new([192, 168, 1, 1], 12345);
        let remote = EndpointAddr::new([192, 168, 1, 2], 80);
        let mut tcb = TcpControlBlockEntry::new(fd, local, remote);
        if tcb.state != TcpConnectionState::Closed {
            return false;
        }
        tcb.initialize_seq(1000);
        tcb.snd_nxt == 1000 && tcb.snd_una == 1000
    }
    pub fn tcp_flags_smoke() -> bool {
        if tcp_flags::FIN != 0x01 || tcp_flags::SYN != 0x02 {
            return false;
        }
        let syn_ack = tcp_flags::SYN | tcp_flags::ACK;
        syn_ack == 0x12
    }
}
