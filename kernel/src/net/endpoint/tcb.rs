// ============================================================================
// kernel/src/net/endpoint/tcb.rs
// ============================================================================
//! # TCP Control Block - 接続状態管理
//!
//! TcpConnectionState, TcpControlBlockEntry, TcbTable, tcp_flags


use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::RwLock;

use super::congestion::{CongestionAlgorithm, CongestionControllerVariant};
use super::flow_control::FlowController;
use super::retransmit::check_retransmit_timeouts;
use super::types::{SocketAddr, SocketFd};
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

/// TCP制御ブロック（RFC 5681/7323準拠）
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
    /// 送信ウィンドウサイズ (legacy - 16bit)
    pub snd_wnd: u16,
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
}

impl TcpControlBlockEntry {
    /// 新規作成（デフォルト: NewReno）
    pub fn new(fd: SocketFd, local: SocketAddr, remote: SocketAddr) -> Self {
        Self::with_algorithm(fd, local, remote, CongestionAlgorithm::NewReno)
    }

    /// アルゴリズム指定で新規作成
    pub fn with_algorithm(
        fd: SocketFd,
        local: SocketAddr,
        remote: SocketAddr,
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
            rcv_wnd: 65535,
            retransmit_count: 0,
            last_send_tick: 0,
            congestion: CongestionControllerVariant::from_algorithm(algorithm),
            window_scale: WindowScaleOption::default_enabled(),
            flow_control: FlowController::new(),
            mss: 1460, // Default MSS
            snd_up: 0,
            snd_urg: false,
            rcv_up: 0,
            rcv_urg: false,
            sack_enabled: false,
            ts_enabled: false,
            ts_val: 0,
            ts_ecr: 0,
        }
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
        let bytes_acked = if ack_num > self.snd_una && !is_dup {
            ack_num.wrapping_sub(self.snd_una)
        } else {
            0
        };

        self.congestion
            .on_ack(bytes_acked, is_dup, self.snd_una, current_time_ms, rtt_sample_ms);

        if !is_dup && ack_num > self.snd_una {
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
        // Use sequence number arithmetic for wraparound handling
        let is_newer = new_up.wrapping_sub(self.rcv_up) < 0x80000000;

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
        self.rcv_urg && self.rcv_up.wrapping_sub(self.rcv_nxt) < 0x80000000
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
}

/// TCBテーブル（接続管理）
pub struct TcbTable {
    /// アクティブな接続
    entries: RwLock<BTreeMap<(SocketAddr, SocketAddr), TcpControlBlockEntry>>,
    /// シーケンス番号カウンタ
    seq_counter: AtomicU32,
    /// 現在のtick（再送タイマー用）
    pub current_tick: AtomicU64,
}

/// 最大TCBエントリ数 (DoS防止)
const MAX_TCB_ENTRIES: usize = 4096;
/// SynReceived状態の最大エントリ数 (SYN Flood防止)
const MAX_SYN_RECEIVED_ENTRIES: usize = 1024;

impl TcbTable {
    /// 新規作成
    pub const fn new() -> Self {
        Self {
            entries: RwLock::new(BTreeMap::new()),
            seq_counter: AtomicU32::new(0),
            current_tick: AtomicU64::new(0),
        }
    }

    /// 初期シーケンス番号生成（RFC 6528準拠）
    /// 
    /// 以前の実装はRDTSCのみに依存しており予測可能でしたが、
    /// この実装は暗号論的に安全な乱数（generate_random）と
    /// 5-tuple情報を組み合わせることで、シーケンス番号予測攻撃を防ぎます。
    pub fn generate_isn(&self, local: SocketAddr, remote: SocketAddr) -> u32 {
        // 暗号論的に安全な乱数を取得
        let random_bytes = crate::net::tls::generate_random();
        
        // FNV-1aハッシュで5-tupleと乱数を混合
        let mut hash: u32 = 0x811c9dc5;
        const FNV_PRIME: u32 = 0x01000193;

        // 乱数全体を混合
        for byte in random_bytes {
            hash ^= byte as u32;
            hash = hash.wrapping_mul(FNV_PRIME);
        }

        // アドレスとポートを混合 (RFC 6528)
        let mix_addr = |h: &mut u32, addr: SocketAddr| {
            match addr {
                SocketAddr::V4 { ip, port } => {
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
                SocketAddr::V6 { ip, port } => {
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
        let mut entries = self.entries.write();
        
        // 全体リソース制限
        if entries.len() >= MAX_TCB_ENTRIES {
            return Err("TCB table full");
        }

        // SYN-RECV制限 (SYN Flood攻撃対策)
        if entry.state == TcpConnectionState::SynReceived {
            let syn_recv_count = entries.values().filter(|e| e.state == TcpConnectionState::SynReceived).count();
            if syn_recv_count >= MAX_SYN_RECEIVED_ENTRIES {
                return Err("Too many SYN-RECV connections");
            }
        }

        let key = (entry.local, entry.remote);
        entries.insert(key, entry);
        Ok(())
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

    /// FDで接続削除
    pub fn remove_by_fd(&self, fd: SocketFd) -> Option<TcpControlBlockEntry> {
        let mut entries = self.entries.write();
        let key = entries.iter().find(|(_, e)| e.fd == fd).map(|(k, _)| *k);
        key.and_then(|k| entries.remove(&k))
    }

    /// 接続参照取得（イミュータブル）
    /// 注: RwLockGuardを返すため、短時間でのアクセスに限定すること
    pub fn lookup(&self, local: SocketAddr, remote: SocketAddr) -> Option<TcpControlBlockEntry> {
        self.entries.read().get(&(local, remote)).cloned()
    }

    /// 接続参照取得して更新（クロージャ版）
    pub fn lookup_mut<R, F>(&self, local: SocketAddr, remote: SocketAddr, f: F) -> Option<R>
    where
        F: FnOnce(&mut TcpControlBlockEntry) -> R,
    {
        let mut entries = self.entries.write();
        entries.get_mut(&(local, remote)).map(f)
    }

    /// 全接続のスナップショットを取得（netstat用）
    pub fn list_connections(&self) -> alloc::vec::Vec<TcpConnectionSnapshot> {
        self.entries
            .read()
            .values()
            .map(|entry| TcpConnectionSnapshot {
                local: entry.local,
                remote: entry.remote,
                state: entry.state,
                snd_nxt: entry.snd_nxt,
                snd_una: entry.snd_una,
                rcv_nxt: entry.rcv_nxt,
                snd_wnd: entry.snd_wnd,
                rcv_wnd: entry.rcv_wnd,
            })
            .collect()
    }

    /// アクティブな接続数を取得
    pub fn connection_count(&self) -> usize {
        self.entries.read().len()
    }
}

/// TCP接続のスナップショット（統計・モニタリング用）
#[derive(Debug, Clone)]
pub struct TcpConnectionSnapshot {
    /// ローカルアドレス
    pub local: SocketAddr,
    /// リモートアドレス
    pub remote: SocketAddr,
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
        let fd = SocketFd::from_raw(1);
        let local = SocketAddr::new([192, 168, 1, 1], 12345);
        let remote = SocketAddr::new([192, 168, 1, 2], 80);

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
        let fd = SocketFd::from_raw(1);
        let local = SocketAddr::new([192, 168, 1, 1], 12345);
        let remote = SocketAddr::new([192, 168, 1, 2], 80);

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
