// ============================================================================
// kernel/src/net/endpoint/tcb.rs
// ============================================================================
//! # TCP Control Block - 接続状態管理
//!
//! TcpConnectionState, TcpControlBlockEntry, TcbTable, tcp_flags


use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use spin::RwLock;

use super::congestion::{CongestionAlgorithm, CongestionControllerVariant};
use super::flow_control::FlowController;
use super::retransmit::check_retransmit_timeouts;
use super::types::{EndpointAddr, EndpointFd, EndpointError, seq_after, conn_key_hash};
use super::window_scale::WindowScaleOption;

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
///
/// `crate::net::l4::tcp::TcpState` の統一エイリアス。
/// 以前は独立した列挙型として定義されていたが、
/// tcp/mod.rs の `TcpState` と完全に同一のため統合。
pub use crate::net::l4::tcp::TcpState as TcpConnectionState;

/// TCP制御ブロック（RFC 5681/7323準拠）
#[derive(Debug, Clone)]
pub struct TcpControlBlockEntry {
    /// ソケットFD
    pub fd: EndpointFd,
    /// ローカルアドレス
    pub local: EndpointAddr,
    /// リモートアドレス
    pub remote: EndpointAddr,
    /// 現在の状態
    pub state: TcpConnectionState,
    /// 送信シーケンス番号（次に送信するバイト）
    pub snd_nxt: u32,
    /// 未確認の最古のシーケンス番号
    pub snd_una: u32,
    /// 受信シーケンス番号（次に期待するバイト）
    pub rcv_nxt: u32,
    /// 送信ウィンドウサイズ (legacy - 16bit)
    pub snd_wnd: u16,
    /// 最大送信ウィンドウサイズ (SWS回避用, RFC 1122)
    pub max_snd_wnd: u32,
    /// 受信ウィンドウサイズ (legacy - 16bit)
    pub rcv_wnd: u16,
    /// 再送回数
    pub retransmit_count: u8,
    /// 最終送信時刻（tick）
    pub last_send_tick: u64,
    /// 輻輳制御コントローラ（NewReno / CUBIC / BBR選択可能）
    pub congestion: CongestionControllerVariant,
    /// ウィンドウスケーリングオプション
    pub window_scale: WindowScaleOption,
    /// フロー制御コントローラ
    pub flow_control: FlowController,
    /// Maximum Segment Size (peer's)
    pub mss: u32,
    // === Urgent Data (RFC 793/6093) ===
    /// Urgent pointer (send side) - offset from SND.NXT
    pub snd_up: u32,
    /// Urgent mode active (send side)
    pub snd_urg: bool,
    /// Urgent pointer (receive side) - sequence number of last urgent byte + 1
    pub rcv_up: u32,
    /// Urgent mode active (receive side)
    pub rcv_urg: bool,
    // === TCP Timestamps (RFC 7323) ===
    /// SACK negotiated (SACK-Permitted seen in SYN from peer)
    pub sack_enabled: bool,
    /// Timestamps negotiated (TSopt seen in SYN from peer)
    pub ts_enabled: bool,
    /// Our timestamp value (monotonic, incremented per tick)
    pub ts_val: u32,
    /// Last received TSval from peer (echoed back as TSecr)
    pub ts_ecr: u32,
    /// Nagle's algorithm enabled (delays small packets until ACK received)
    pub nagle_enabled: bool,
    /// QoS priority (DSCP)
    pub priority: u8,
    /// Delayed ACK: 保留中のACKセグメント数
    /// ファストパスでデータを受信するたびにインクリメントされ、
    /// DELAYED_ACK_SEGMENTS (2) に達するか、タイムアウトでACK送信後にリセット。
    pub delayed_ack_pending: u8,
    /// 保留中のエラー (RFC 1122: ICMPエラー等を次回の操作で返すために保持)
    pub pending_error: Option<EndpointError>,
}

impl TcpControlBlockEntry {
    /// 新規作成（デフォルト: NewReno）
    pub fn new(fd: EndpointFd, local: EndpointAddr, remote: EndpointAddr) -> Self {
        Self::with_algorithm(fd, local, remote, CongestionAlgorithm::NewReno)
    }

    /// アルゴリズム指定で新規作成
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
            mss: 536, // Default MSS (RFC 1122 compliant)
            snd_up: 0,
            snd_urg: false,
            rcv_up: 0,
            rcv_urg: false,
            sack_enabled: false,
            ts_enabled: false,
            ts_val: 0,
            ts_ecr: 0,
            nagle_enabled: true, // デフォルトで有効
            priority: 0,
            delayed_ack_pending: 0,
            pending_error: None,
        }
    }

    /// TCP_NODELAY (Nagle無効化) を設定
    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.nagle_enabled = !nodelay;
    }

    /// QoS優先度を設定
    pub fn set_priority(&mut self, priority: u8) {
        self.priority = priority & 0x3F;
    }

    /// Nagleアルゴリズムが有効か確認
    pub fn is_nodelay_enabled(&self) -> bool {
        !self.nagle_enabled
    }

    /// 送信を遅延させるべきか判定 (Nagleアルゴリズム + Sender SWS avoidance)
    /// 
    /// Following RFC 1122 Section 4.2.3.4 (Sender SWS Avoidance) and Section 4.2.3.2 (Nagle's).
    pub fn should_delay_send(&self, data_len: usize) -> bool {
        // --- 1. Maximum-sized segment can be sent ---
        if data_len >= self.mss as usize {
            return false; // Send immediately
        }

        // --- 2. Sender SWS Avoidance: Window is large enough ---
        // "at least half of the maximum window size seen so far on this connection"
        let sws_threshold = self.max_snd_wnd / 2;
        let scaled_rwnd = self.window_scale.scale_snd_window(self.snd_wnd);
        if scaled_rwnd >= sws_threshold && scaled_rwnd > 0 && data_len > 0 {
            // Window is large enough to avoid SWS.
        } else if self.is_outstanding() {
            // SWS avoidance: Window is small and we already have data in flight.
            return true; // Delay
        }

        // --- 3. Nagle's Algorithm ---
        if !self.nagle_enabled {
            return false; // NODELAY enabled: send immediately
        }

        // If there is unacknowledged data, delay small segments
        if self.is_outstanding() {
            return true; // Delay
        }

        false // No outstanding data: send immediately
    }

    /// 未確認データがあるか確認
    pub fn is_outstanding(&self) -> bool {
        self.snd_nxt != self.snd_una
    }

    /// 初期シーケンス番号を設定
    pub fn initialize_seq(&mut self, isn: u32) {
        self.snd_nxt = isn;
        self.snd_una = isn;
    }

    /// 実効送信ウィンドウを計算 (cwnd, rwnd, flow control考慮)
    pub fn effective_send_window(&self) -> u32 {
        let scaled_rwnd = self.window_scale.scale_snd_window(self.snd_wnd);
        self.congestion.available_window(scaled_rwnd)
    }

    /// 実効受信ウィンドウを取得
    pub fn effective_recv_window(&self) -> u32 {
        self.flow_control.advertised_window()
    }

    /// 広告用ウィンドウ値を取得 (16bit, スケールダウン済み)
    pub fn advertised_recv_window(&self) -> u16 {
        self.window_scale
            .advertised_window(self.flow_control.advertised_window())
    }

    /// ACK受信時の処理
    ///
    /// `current_time_ms`: 現在時刻（ミリ秒）。CUBICやBBRが正確な時刻を必要とする。
    /// `rtt_sample_ms`: RTTサンプル（ミリ秒）。BBRが帯域推定に使用。0なら無効。
    pub fn on_ack_received(&mut self, ack_num: u32, is_dup: bool, current_time_ms: u64, rtt_sample_ms: u64) {
        // RFC 793 validation: SND.UNA < SEG.ACK =< SND.NXT
        let is_valid_ack = (ack_num.wrapping_sub(self.snd_una) as i32) > 0 
            && (ack_num.wrapping_sub(self.snd_nxt) as i32) <= 0;

        let bytes_acked = if is_valid_ack && !is_dup {
            ack_num.wrapping_sub(self.snd_una)
        } else {
            0
        };

        self.congestion
            .on_ack(bytes_acked, is_dup, self.snd_una, current_time_ms, rtt_sample_ms);

        if !is_dup && is_valid_ack {
            self.snd_una = ack_num;
        }
    }

    /// データ受信時の処理
    pub fn on_data_received(&mut self, bytes: u32) {
        self.flow_control.on_receive(bytes);
        self.rcv_wnd = self.advertised_recv_window();
    }

    /// アプリケーションがデータを消費
    pub fn on_data_consumed(&mut self, bytes: u32) {
        self.flow_control.on_consume(bytes);
        self.rcv_wnd = self.advertised_recv_window();
    }

    /// 送信時の処理
    pub fn on_send(&mut self, bytes: u32) {
        let tick = self.last_send_tick;
        self.congestion.on_send(bytes, tick);
    }

    /// タイムアウト時の処理
    pub fn on_timeout(&mut self) {
        let tick = self.last_send_tick;
        self.congestion.on_timeout(tick);
        self.retransmit_count = self.retransmit_count.saturating_add(1);
    }

    /// 相手のウィンドウ更新
    pub fn update_peer_window(&mut self, window: u16) {
        self.snd_wnd = window;
        let scaled = self.window_scale.scale_snd_window(window);
        self.flow_control.update_peer_window(scaled);
        if scaled > self.max_snd_wnd {
            self.max_snd_wnd = scaled;
        }
    }

    /// 送信可能かどうか
    pub fn can_send(&self, bytes: u32) -> bool {
        self.effective_send_window() >= bytes && self.flow_control.can_send()
    }

    // === Urgent Data Handling (RFC 793/6093) ===

    /// Set urgent pointer for sending urgent data
    /// 
    /// The urgent pointer points to the sequence number of the last byte
    /// of urgent data + 1 (per RFC 6093 clarification).
    pub fn set_urgent(&mut self, urgent_offset: u32) {
        self.snd_up = self.snd_nxt.wrapping_add(urgent_offset);
        self.snd_urg = true;
    }

    /// Clear send urgent mode
    pub fn clear_send_urgent(&mut self) {
        self.snd_urg = false;
    }

    /// Check if we should set URG flag in outgoing segment
    pub fn should_send_urg(&self) -> bool {
        self.snd_urg && self.snd_up > self.snd_una
    }

    /// Calculate urgent pointer value for segment header
    /// Returns the offset from segment sequence number to urgent pointer
    pub fn urgent_pointer_for_segment(&self, seg_seq: u32) -> u16 {
        if !self.snd_urg {
            return 0;
        }
        // Urgent pointer is offset from beginning of segment to urgent byte
        let offset = self.snd_up.wrapping_sub(seg_seq);
        // Clamp to u16 max
        if offset > 0xFFFF {
            0xFFFF
        } else {
            offset as u16
        }
    }

    /// Process incoming URG flag and urgent pointer
    /// 
    /// Returns true if there is new urgent data to process
    pub fn on_urgent_received(&mut self, seg_seq: u32, urgent_ptr: u16) -> bool {
        // Calculate absolute urgent pointer position
        // RFC 6093: urgent_ptr points to the sequence number immediately
        // following the last byte of urgent data
        let new_up = seg_seq.wrapping_add(urgent_ptr as u32);

        // Check if this is newer urgent data
        // Use unified seq utility for wraparound handling
        let is_newer = seq_after(new_up, self.rcv_up);

        if is_newer && new_up != self.rcv_up {
            self.rcv_up = new_up;
            self.rcv_urg = true;
            return true;
        }
        false
    }

    /// Check if we have pending urgent data to read
    pub fn has_urgent_data(&self) -> bool {
        // Urgent data exists if rcv_urg is set and urgent pointer is ahead of rcv_nxt
        self.rcv_urg && seq_after(self.rcv_up, self.rcv_nxt)
    }

    /// Get the position of urgent data in receive buffer
    /// Returns offset from rcv_nxt to the urgent byte
    pub fn urgent_data_offset(&self) -> Option<u32> {
        if !self.has_urgent_data() {
            return None;
        }
        // Offset to the byte immediately before the urgent pointer
        let offset = self.rcv_up.wrapping_sub(self.rcv_nxt);
        if offset > 0 {
            Some(offset - 1)
        } else {
            None
        }
    }

    /// Clear receive urgent mode after processing
    pub fn clear_recv_urgent(&mut self) {
        self.rcv_urg = false;
    }

    /// Handle ICMP Source Quench (RFC 1122 Section 4.2.3.9)
    pub fn on_source_quench(&mut self) {
        // Reduce amount of data in flight by reducing congestion window.
        // Similar to Fast Retransmit (RFC 5681).
        // TCB level quench just informs congestion controller.
        self.congestion.on_timeout(self.last_send_tick);
    }

    /// Handle ICMP Error (RFC 1122 Section 4.2.3.9)
    pub fn on_icmp_error(&mut self, error: EndpointError) {
        // RFC 1122: "A TCP SHOULD notify the user of the error, but it SHOULD NOT
        // close the connection." (except for SYN-SENT)
        self.pending_error = Some(error);
    }
}

/// シャード数（2のべき乗にすることで高速モジュロ演算が可能）
const TCB_SHARD_COUNT: usize = 16;
const TCB_SHARD_MASK: usize = TCB_SHARD_COUNT - 1;

/// シャード化されたTCBテーブル（接続管理）
///
/// 従来の単一 `RwLock<BTreeMap>` をシャード分割し、
/// 異なるコネクションへの並行アクセス時のロック競合を大幅に低減する。
/// シャードインデックスは (local, remote) の FNV-1a ハッシュで決定。
pub struct TcbTable {
    /// シャード化されたエントリテーブル
    shards: [RwLock<BTreeMap<(EndpointAddr, EndpointAddr), TcpControlBlockEntry>>; TCB_SHARD_COUNT],
    /// シーケンス番号カウンタ
    seq_counter: AtomicU32,
    /// 現在のtick（再送タイマー用）
    pub current_tick: AtomicU64,
    /// 現在のTCBエントリ合計数
    total_count: AtomicUsize,
    /// 現在のSynReceived状態のエントリ数
    syn_recv_count: AtomicUsize,
}

/// 最大TCBエントリ数 (DoS防止) — 全シャード合計
const MAX_TCB_ENTRIES: usize = 4096;
/// SynReceived状態の最大エントリ数 (SYN Flood防止) — 全シャード合計
const MAX_SYN_RECEIVED_ENTRIES: usize = 1024;

/// 接続キーからシャードインデックスを算出
#[inline(always)]
fn shard_index(local: &EndpointAddr, remote: &EndpointAddr) -> usize {
    (conn_key_hash(local, remote) as usize) & TCB_SHARD_MASK
}

impl TcbTable {
    /// 新規作成
    pub const fn new() -> Self {
        // const context で配列を初期化
        const EMPTY_SHARD: RwLock<BTreeMap<(EndpointAddr, EndpointAddr), TcpControlBlockEntry>> =
            RwLock::new(BTreeMap::new());
        Self {
            shards: [EMPTY_SHARD; TCB_SHARD_COUNT],
            seq_counter: AtomicU32::new(0),
            current_tick: AtomicU64::new(0),
            total_count: AtomicUsize::new(0),
            syn_recv_count: AtomicUsize::new(0),
        }
    }

    /// 初期シーケンス番号生成（RFC 6528準拠）
    /// 
    /// 以前の実装はRDTSCのみに依存しており予測可能でしたが、
    /// この実装は暗号論的に安全な乱数（generate_random）と
    /// 5-tuple情報を組み合わせることで、シーケンス番号予測攻撃を防ぎます。
    pub fn generate_isn(&self, local: EndpointAddr, remote: EndpointAddr) -> u32 {
        // 暗号論的に安全な乱数を取得
        let random_bytes = crate::net::security::tls::generate_random();
        
        // FNV-1aハッシュで5-tupleと乱数を混合
        let mut hash: u32 = 0x811c9dc5;
        const FNV_PRIME: u32 = 0x01000193;

        // 乱数全体を混合
        for byte in random_bytes {
            hash ^= byte as u32;
            hash = hash.wrapping_mul(FNV_PRIME);
        }

        // アドレスとポートを混合 (RFC 6528)
        let mix_addr = |h: &mut u32, addr: EndpointAddr| {
            match addr {
                EndpointAddr::V4 { ip, port } => {
                    // ip is a [u8;4] array so iterate directly
                    for &byte in &ip {
                        *h ^= byte as u32;
                        *h = h.wrapping_mul(FNV_PRIME);
                    }
                    for byte in port.to_le_bytes() {
                        *h ^= byte as u32;
                        *h = h.wrapping_mul(FNV_PRIME);
                    }
                }
                EndpointAddr::V6 { ip, port } => {
                    // ip is a [u8;16]
                    for &byte in &ip {
                        *h ^= byte as u32;
                        *h = h.wrapping_mul(FNV_PRIME);
                    }
                    for byte in port.to_le_bytes() {
                        *h ^= byte as u32;
                        *h = h.wrapping_mul(FNV_PRIME);
                    }
                }
            }
        };

        mix_addr(&mut hash, local);
        mix_addr(&mut hash, remote);

        // カウンタをインクリメントして混合
        let counter = self.seq_counter.fetch_add(1, Ordering::Relaxed);
        for byte in counter.to_le_bytes() {
            hash ^= byte as u32;
            hash = hash.wrapping_mul(FNV_PRIME);
        }

        hash
    }

    /// tick更新（タイマー割り込みから呼ばれる）
    /// 一定間隔で再送タイムアウトもチェック
    pub fn tick(&self) {
        let tick = self.current_tick.fetch_add(1, Ordering::Relaxed);

        // 100tickごとに再送チェック（パフォーマンス最適化）
        if tick % 100 == 0 {
            check_retransmit_timeouts();
            // RFC 1122: ゼロウィンドウプローブの周期チェック
            self.check_zero_window_probes(tick);
            // SYN flood対策: 定期的に古いSynReceivedエントリを掃除する
            self.scavenge_syn_received(tick);
            // TIME_WAIT対策: 定期的に期限切れのTIME_WAITエントリを掃除する
            self.scavenge_time_wait(tick);
        }
    }

    /// ゼロウィンドウプローブの周期チェック
    ///
    /// 全ての確立済み接続をスキャンし、相手のウィンドウが0でデータ送信待ちがある場合、
    /// 定期的に1バイトのプローブパケットを送信する。
    fn check_zero_window_probes(&self, current_tick: u64) {
        use super::segment::{TcpSegmentBuilder, send_tcp_segment};
        use super::retransmit::retransmit_queue_push;
        use super::manager::ENDPOINT_MANAGER;

        for shard in &self.shards {
            let mut entries = shard.write();
            for (key, entry) in entries.iter_mut() {
                if entry.state == TcpConnectionState::Established {
                    // RFC 1122: Only explicitly probe if nothing is currently outstanding.
                    // If something is in flight, it acts as a probe.
                    if entry.is_outstanding() {
                        continue;
                    }

                    if entry.flow_control.should_send_probe(current_tick) {
                        // プローブ送信が必要。ソケットの送信バッファから1バイト取得。
                        let manager = ENDPOINT_MANAGER.read();
                        if let Some(ref mgr) = *manager {
                            if let Some(socket) = mgr.get(entry.fd) {
                                let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
                                if !inner.send_buffer.is_empty() {
                                    // 1バイト取得 (SWS回避ルールにより、通常は here に到達するのは snd_wnd=0 の時のみ)
                                    let probe_byte = inner.send_buffer.pop_front().unwrap();
                                    drop(inner); // ロックを早期解放
                                    drop(manager);

                                    let payload = alloc::vec![probe_byte];
                                    let seq = entry.snd_nxt;

                                    // セグメント構築 (ACKフラグ付きデータパケット)
                                    let mut builder = TcpSegmentBuilder::new(key.0.port(), key.1.port())
                                        .seq(seq)
                                        .ack(entry.rcv_nxt)
                                        .ack_flag()
                                        .psh() // 通常データと同様にPSHを立てる
                                        .window(entry.advertised_recv_window())
                                        .data(payload.clone());
                                    
                                    if entry.ts_enabled {
                                        let ts_val = (current_tick / 10) as u32;
                                        builder = builder.nop().nop().timestamp(ts_val, entry.ts_ecr);
                                    }

                                    let mut segment = builder.build();
                                    if let (Some(lv4), Some(rv4)) = (key.0.as_ipv4(), key.1.as_ipv4()) {
                                        TcpSegmentBuilder::calculate_checksum(&mut segment, lv4, rv4);
                                    } else {
                                        TcpSegmentBuilder::calculate_checksum_v6(
                                            &mut segment,
                                            crate::net::l3::ipv6::Ipv6Address::new(key.0.as_ipv6()),
                                            crate::net::l3::ipv6::Ipv6Address::new(key.1.as_ipv6()),
                                        );
                                    }

                                    // 送信
                                    if send_tcp_segment(key.0, key.1, segment) {
                                        // 再送キューに追加（1バイト消費）
                                        retransmit_queue_push(key.0, key.1, seq, payload);
                                        entry.snd_nxt = entry.snd_nxt.wrapping_add(1);
                                        entry.flow_control.on_probe_sent(current_tick);
                                    } else {
                                        // 送信失敗（ARP未解決等）。バッファに戻す。
                                        let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
                                        inner.send_buffer.push_front(probe_byte);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// TIME_WAIT状態の期限切れエントリを掃除する
    /// 
    /// 2MSL（Maximum Segment Lifetime）の待機時間を経過した接続を完全に削除する。
    /// RFC 793 では 2MSL = 4分（240秒）を推奨。
    fn scavenge_time_wait(&self, current_tick: u64) {
        /// TIME_WAIT のタイムアウト閾値 (240秒, RFC 793)
        const TIME_WAIT_TIMEOUT_TICKS: u64 = 240_000;
        /// 1回の掃除で各シャードから削除するエントリの最大数
        const MAX_SCAVENGE_PER_SHARD: usize = 16;

        for shard in &self.shards {
            let mut entries = shard.write();
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

    /// SynReceived状態の古いエントリを掃除する（SYN Flood対策）
    ///
    /// 改善: ソートや動的アロケーション (`Vec::collect`) を行わず、
    /// Writeロック保持中の処理をO(n)線形探索に限定する。
    /// 閾値（SYN_RECV_TIMEOUT_TICKS = 3000）を超えたエントリを直接削除し、
    /// 1回あたりの削除数を `MAX_SCAVENGE_PER_TICK` で制限することで
    /// ロック保持時間を最小化する。各シャードを個別にロックして処理する。
    fn scavenge_syn_received(&self, current_tick: u64) {
        /// SynReceived のタイムアウト閾値（tick ≒ ms）
        const SYN_RECV_TIMEOUT_TICKS: u64 = 3000;
        /// 1回の掃除で各シャードから削除するエントリの最大数
        const MAX_SCAVENGE_PER_SHARD: usize = 8;

        if self.syn_recv_count.load(Ordering::Relaxed) < MAX_SYN_RECEIVED_ENTRIES / 2 {
            return;
        }

        // 各シャードを個別に Write ロックして掃除
        for shard in &self.shards {
            let mut entries = shard.write();

            let mut to_remove: [Option<(EndpointAddr, EndpointAddr)>; 8] = [None; 8];
            let mut remove_count = 0;

            for (key, entry) in entries.iter() {
                if entry.state == TcpConnectionState::SynReceived
                    && current_tick.saturating_sub(entry.last_send_tick) > SYN_RECV_TIMEOUT_TICKS
                {
                    to_remove[remove_count] = Some(*key);
                    remove_count += 1;
                    if remove_count >= MAX_SCAVENGE_PER_SHARD {
                        break;
                    }
                }
            }

            for i in 0..remove_count {
                if let Some(key) = to_remove[i] {
                    if let Some(entry) = entries.remove(&key) {
                        self.total_count.fetch_sub(1, Ordering::Relaxed);
                        if entry.state == TcpConnectionState::SynReceived {
                            self.syn_recv_count.fetch_sub(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
    }

    /// 現在のtick取得
    pub fn get_current_tick(&self) -> u64 {
        self.current_tick.load(Ordering::Relaxed)
    }

    /// 接続追加
    /// 
    /// # Returns
    /// - `Ok(())` : 成功
    /// - `Err(&'static str)` : テーブル満杯などのエラー
    pub fn insert(&self, entry: TcpControlBlockEntry) -> Result<(), &'static str> {
        // 全シャード合計数で制限チェック
        if self.total_count.load(Ordering::Relaxed) >= MAX_TCB_ENTRIES {
            return Err("TCB table full");
        }

        // SYN-RECV制限 (SYN Flood攻撃対策)
        if entry.state == TcpConnectionState::SynReceived {
            if self.syn_recv_count.load(Ordering::Relaxed) >= MAX_SYN_RECEIVED_ENTRIES {
                return Err("Too many SYN-RECV connections");
            }
        }

        let idx = shard_index(&entry.local, &entry.remote);
        let key = (entry.local, entry.remote);
        let mut shard = self.shards[idx].write();
        
        // すでに存在するかチェック
        let is_syn_recv = entry.state == TcpConnectionState::SynReceived;
        if shard.insert(key, entry).is_none() {
            self.total_count.fetch_add(1, Ordering::Relaxed);
            if is_syn_recv {
                self.syn_recv_count.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    /// 接続取得
    pub fn get(&self, local: EndpointAddr, remote: EndpointAddr) -> Option<TcpControlBlockEntry> {
        let idx = shard_index(&local, &remote);
        self.shards[idx].read().get(&(local, remote)).cloned()
    }

    /// 接続更新
    pub fn update<F>(&self, local: EndpointAddr, remote: EndpointAddr, f: F) -> bool
    where
        F: FnOnce(&mut TcpControlBlockEntry),
    {
        let idx = shard_index(&local, &remote);
        let mut shard = self.shards[idx].write();
        if let Some(entry) = shard.get_mut(&(local, remote)) {
            let old_state = entry.state;
            f(entry);
            let new_state = entry.state;
            
            // 状態が変化した場合、SynReceivedカウンタを更新
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

    /// 接続削除
    pub fn remove(&self, local: EndpointAddr, remote: EndpointAddr) -> Option<TcpControlBlockEntry> {
        let idx = shard_index(&local, &remote);
        let mut shard = self.shards[idx].write();
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

    /// FDで接続検索（全シャードを探索）
    pub fn find_by_fd(&self, fd: EndpointFd) -> Option<TcpControlBlockEntry> {
        for shard in &self.shards {
            let guard = shard.read();
            if let Some(entry) = guard.values().find(|e| e.fd == fd) {
                return Some(entry.clone());
            }
        }
        None
    }

    /// FDで接続削除（全シャードを探索）
    pub fn remove_by_fd(&self, fd: EndpointFd) -> Option<TcpControlBlockEntry> {
        for shard in &self.shards {
            let mut guard = shard.write();
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

    /// 接続参照取得（イミュータブル）
    pub fn lookup(&self, local: EndpointAddr, remote: EndpointAddr) -> Option<TcpControlBlockEntry> {
        let idx = shard_index(&local, &remote);
        self.shards[idx].read().get(&(local, remote)).cloned()
    }

    /// 接続参照取得して更新（クロージャ版）
    pub fn lookup_mut<R, F>(&self, local: EndpointAddr, remote: EndpointAddr, f: F) -> Option<R>
    where
        F: FnOnce(&mut TcpControlBlockEntry) -> R,
    {
        let idx = shard_index(&local, &remote);
        let mut shard = self.shards[idx].write();
        shard.get_mut(&(local, remote)).map(f)
    }

    /// 全接続のスナップショットを取得（netstat用）
    pub fn list_connections(&self) -> alloc::vec::Vec<TcpConnectionSnapshot> {
        let mut result = alloc::vec::Vec::new();
        for shard in &self.shards {
            let guard = shard.read();
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

    /// アクティブな接続数を取得
    pub fn connection_count(&self) -> usize {
        self.total_count.load(Ordering::Relaxed)
    }

    /// ICMPエラーメッセージに含まれるシーケンス番号が妥当か検証（RFC 5927）
    ///
    /// オフパス攻撃者による PMTU 毒入れ攻撃を防ぐため、引用されたパケットの
    /// シーケンス番号が現在の送信ウィンドウ内にあることを確認します。
    pub fn validate_icmp_sequence(&self, local: EndpointAddr, remote: EndpointAddr, seq: u32) -> bool {
        if let Some(tcb) = self.get(local, remote) {
            // RFC 5927 Section 4.1: "The TCP sequence number should be checked
            // to see if it's within the current window"

            // For SYN-SENT, the sequence must be exactly the ISN
            if tcb.state == TcpConnectionState::SynSent {
                return seq == tcb.snd_una;
            }

            // 接続が確立済み（または終了処理中）であることを確認
            match tcb.state {
                TcpConnectionState::Closed | TcpConnectionState::Listen => return false,
                _ => {}
            }

            // 送信済みで未確認の範囲 [SND.UNA, SND.NXT] に seq が含まれるかチェック
            let una = tcb.snd_una;
            let nxt = tcb.snd_nxt;

            // una <= seq <= nxt (wrapping handling)
            let diff_una = seq.wrapping_sub(una);
            let diff_nxt = nxt.wrapping_sub(una);

            return diff_una <= diff_nxt;
        }
        false
    }

    /// ESTABLISHED状態の全接続に対してクロージャを実行
    ///
    /// Delayed ACKフラッシュ等の定期処理で使用。
    /// ロック取得中にクロージャを呼ぶため、
    /// クロージャ内でTcbTableのメソッドを呼ばないこと（デッドロック防止）。
    pub fn for_each_established<F>(&self, mut f: F)
    where
        F: FnMut(&TcpControlBlockEntry),
    {
        for shard in &self.shards {
            let guard = shard.read();
            for entry in guard.values() {
                if entry.state == TcpConnectionState::Established {
                    f(entry);
                }
            }
        }
    }
}

/// TCP接続のスナップショット（統計・モニタリング用）
#[derive(Debug, Clone)]
pub struct TcpConnectionSnapshot {
    /// ローカルアドレス
    pub local: EndpointAddr,
    /// リモートアドレス
    pub remote: EndpointAddr,
    /// 接続状態
    pub state: TcpConnectionState,
    /// 送信シーケンス番号
    pub snd_nxt: u32,
    /// 未確認シーケンス番号
    pub snd_una: u32,
    /// 受信シーケンス番号
    pub rcv_nxt: u32,
    /// 送信ウィンドウ
    pub snd_wnd: u16,
    /// 受信ウィンドウ
    pub rcv_wnd: u16,
}

/// グローバルTCBテーブル
pub static TCB_TABLE: TcbTable = TcbTable::new();

/// TCBテーブルへの参照取得
pub fn tcb_table() -> &'static TcbTable {
    &TCB_TABLE
}

// =====================================================
// テスト
// =====================================================

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests {
    use super::*;

    #[cfg_attr(test, test_case)]
    pub fn test_tcp_connection_state() {
        // 状態遷移の検証
        let state = TcpConnectionState::Closed;
        assert!(matches!(state, TcpConnectionState::Closed));

        // Established状態
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
        assert_eq!(tcb.snd_nxt, 0);
        assert_eq!(tcb.snd_una, 0);

        // ISN初期化
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
        assert_eq!(tcp_flags::URG, 0x20);

        // 複合フラグ
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
        if tcb.state != TcpConnectionState::Closed || tcb.snd_nxt != 0 || tcb.snd_una != 0 {
            return false;
        }

        tcb.initialize_seq(1000);
        tcb.snd_nxt == 1000 && tcb.snd_una == 1000
    }

    pub fn tcp_flags_smoke() -> bool {
        if tcp_flags::FIN != 0x01
            || tcp_flags::SYN != 0x02
            || tcp_flags::RST != 0x04
            || tcp_flags::PSH != 0x08
            || tcp_flags::ACK != 0x10
            || tcp_flags::URG != 0x20
        {
            return false;
        }

        let syn_ack = tcp_flags::SYN | tcp_flags::ACK;
        syn_ack == 0x12
    }
}
