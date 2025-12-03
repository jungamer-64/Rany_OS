//! # TCP Control Block - 接続状態管理
//!
//! TcpConnectionState, TcpControlBlockEntry, TcbTable, tcp_flags

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::RwLock;

use super::types::{SocketFd, SocketAddr};
use super::retransmit::check_retransmit_timeouts;
use super::congestion::CongestionController;
use super::window_scale::WindowScaleOption;
use super::flow_control::FlowController;

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
    /// 輻輳制御コントローラ
    pub congestion: CongestionController,
    /// ウィンドウスケーリングオプション
    pub window_scale: WindowScaleOption,
    /// フロー制御コントローラ
    pub flow_control: FlowController,
    /// Maximum Segment Size (peer's)
    pub mss: u32,
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
            congestion: CongestionController::new(),
            window_scale: WindowScaleOption::default_enabled(),
            flow_control: FlowController::new(),
            mss: 1460, // Default MSS
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
        self.window_scale.advertised_window(self.flow_control.advertised_window())
    }
    
    /// ACK受信時の処理
    pub fn on_ack_received(&mut self, ack_num: u32, is_dup: bool) {
        let bytes_acked = if ack_num > self.snd_una && !is_dup {
            ack_num.wrapping_sub(self.snd_una)
        } else {
            0
        };
        
        self.congestion.on_ack(bytes_acked, is_dup, self.snd_una);
        
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
        self.congestion.on_send(bytes);
    }
    
    /// タイムアウト時の処理
    pub fn on_timeout(&mut self) {
        self.congestion.on_timeout();
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
pub static TCB_TABLE: TcbTable = TcbTable::new();

/// TCBテーブルへの参照取得
pub fn tcb_table() -> &'static TcbTable {
    &TCB_TABLE
}

// =====================================================
// テスト
// =====================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tcp_connection_state() {
        // 状態遷移の検証
        let state = TcpConnectionState::Closed;
        assert!(matches!(state, TcpConnectionState::Closed));
        
        // Established状態
        let state = TcpConnectionState::Established;
        assert!(matches!(state, TcpConnectionState::Established));
    }
    
    #[test]
    fn test_tcp_control_block_entry() {
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
    
    #[test]
    fn test_tcp_flags() {
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
