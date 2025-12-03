//! # 再送タイマー・キュー
//!
//! RtoCalculator, RetransmitQueue, UnackedSegment

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use spin::RwLock;

use super::types::SocketAddr;
use super::tcb::tcb_table;
use super::segment::send_tcp_segment;

/// 未確認セグメント（再送用）
#[derive(Debug, Clone)]
pub struct UnackedSegment {
    /// シーケンス番号
    pub seq: u32,
    /// セグメントデータ（ヘッダ含む）
    pub data: Vec<u8>,
    /// 送信時刻（tick）
    pub send_tick: u64,
    /// 再送回数
    pub retransmit_count: u8,
    /// RTOサンプル用フラグ（再送済みはRTTサンプルに使わない）
    pub is_retransmit: bool,
}

/// RTO（Retransmission Timeout）計算器
/// RFC 6298準拠
#[derive(Debug)]
pub struct RtoCalculator {
    /// 平滑化RTT (Smoothed RTT)
    srtt: Option<u64>,
    /// RTT偏差 (RTT Variation)
    rttvar: Option<u64>,
    /// 現在のRTO（ミリ秒相当tick）
    rto: u64,
    /// 最小RTO
    rto_min: u64,
    /// 最大RTO
    rto_max: u64,
}

impl RtoCalculator {
    /// 新規作成
    pub const fn new() -> Self {
        Self {
            srtt: None,
            rttvar: None,
            rto: 1000,      // 初期値: 1秒 (1000 tick ≒ 1秒)
            rto_min: 200,   // 最小: 200ms
            rto_max: 60000, // 最大: 60秒
        }
    }
    
    /// RTTサンプルからRTOを更新（RFC 6298）
    pub fn update(&mut self, rtt: u64) {
        const ALPHA: u64 = 8;  // 1/8
        const BETA: u64 = 4;   // 1/4
        
        match (self.srtt, self.rttvar) {
            (None, None) => {
                // 初回測定
                self.srtt = Some(rtt);
                self.rttvar = Some(rtt / 2);
            }
            (Some(srtt), Some(rttvar)) => {
                // 更新
                let diff = if rtt > srtt { rtt - srtt } else { srtt - rtt };
                let new_rttvar = ((BETA - 1) * rttvar + diff) / BETA;
                let new_srtt = ((ALPHA - 1) * srtt + rtt) / ALPHA;
                self.srtt = Some(new_srtt);
                self.rttvar = Some(new_rttvar);
            }
            _ => unreachable!(),
        }
        
        // RTO = SRTT + max(G, 4*RTTVAR) where G ≒ 1
        if let (Some(srtt), Some(rttvar)) = (self.srtt, self.rttvar) {
            self.rto = srtt + core::cmp::max(1, 4 * rttvar);
            self.rto = self.rto.clamp(self.rto_min, self.rto_max);
        }
    }
    
    /// 再送時のバックオフ（指数バックオフ）
    pub fn backoff(&mut self) {
        self.rto = (self.rto * 2).min(self.rto_max);
    }
    
    /// 現在のRTO取得
    pub fn get_rto(&self) -> u64 {
        self.rto
    }
    
    /// リセット
    pub fn reset(&mut self) {
        self.srtt = None;
        self.rttvar = None;
        self.rto = 1000;
    }
}

/// 再送キュー（接続ごと）
#[derive(Debug)]
pub struct RetransmitQueue {
    /// 未確認セグメントのリスト（シーケンス番号順）
    unacked: VecDeque<UnackedSegment>,
    /// RTO計算器
    rto_calc: RtoCalculator,
    /// 最大再送回数
    max_retries: u8,
}

impl RetransmitQueue {
    /// 新規作成
    pub fn new() -> Self {
        Self {
            unacked: VecDeque::new(),
            rto_calc: RtoCalculator::new(),
            max_retries: 5,
        }
    }
    
    /// セグメントを追加
    pub fn push(&mut self, seq: u32, data: Vec<u8>, current_tick: u64) {
        self.unacked.push_back(UnackedSegment {
            seq,
            data,
            send_tick: current_tick,
            retransmit_count: 0,
            is_retransmit: false,
        });
    }
    
    /// ACK受信時の処理（累積ACK）
    /// 確認されたセグメントを削除し、RTTサンプルを収集
    pub fn ack_received(&mut self, ack_num: u32, current_tick: u64) {
        // 累積ACKより前のセグメントを全て削除
        while let Some(seg) = self.unacked.front() {
            // seqがack_numより前なら確認済み
            if Self::seq_before(seg.seq, ack_num) {
                let seg = self.unacked.pop_front().unwrap();
                // 再送でないセグメントのみRTTサンプルとして使用（Karnのアルゴリズム）
                if !seg.is_retransmit {
                    let rtt = current_tick.saturating_sub(seg.send_tick);
                    if rtt > 0 {
                        self.rto_calc.update(rtt);
                    }
                }
            } else {
                break;
            }
        }
    }
    
    /// タイムアウトチェック
    /// 再送が必要なセグメントがあるかチェック
    pub fn check_timeout(&self, current_tick: u64) -> Option<&UnackedSegment> {
        self.unacked.front().filter(|seg| {
            let elapsed = current_tick.saturating_sub(seg.send_tick);
            elapsed >= self.rto_calc.get_rto()
        })
    }
    
    /// 再送処理
    /// 戻り値: 再送するセグメントデータ、Noneの場合は最大再送回数超過
    pub fn retransmit(&mut self, current_tick: u64) -> Option<Vec<u8>> {
        if let Some(seg) = self.unacked.front_mut() {
            if seg.retransmit_count >= self.max_retries {
                // 最大再送回数超過
                return None;
            }
            
            seg.retransmit_count += 1;
            seg.send_tick = current_tick;
            seg.is_retransmit = true;
            self.rto_calc.backoff();
            
            return Some(seg.data.clone());
        }
        None
    }
    
    /// キューが空かどうか
    pub fn is_empty(&self) -> bool {
        self.unacked.is_empty()
    }
    
    /// 現在のRTO取得
    pub fn get_rto(&self) -> u64 {
        self.rto_calc.get_rto()
    }
    
    /// シーケンス番号比較（wrapping考慮）
    pub fn seq_before(a: u32, b: u32) -> bool {
        // aがbより前かどうか（wrapping考慮）
        // a < b かつ (b - a) < 2^31
        let diff = b.wrapping_sub(a);
        diff > 0 && diff < (1 << 31)
    }
    
    /// シーケンス番号比較（以下）
    #[allow(dead_code)]
    pub fn seq_leq(a: u32, b: u32) -> bool {
        a == b || Self::seq_before(a, b)
    }
}

impl Default for RetransmitQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// グローバル再送キューテーブル
static RETRANSMIT_QUEUES: RwLock<BTreeMap<(SocketAddr, SocketAddr), RetransmitQueue>> = 
    RwLock::new(BTreeMap::new());

/// 再送キュー取得または作成
pub fn get_or_create_retransmit_queue(local: SocketAddr, remote: SocketAddr) -> bool {
    let mut queues = RETRANSMIT_QUEUES.write();
    if !queues.contains_key(&(local, remote)) {
        queues.insert((local, remote), RetransmitQueue::new());
        true
    } else {
        false
    }
}

/// 再送キューにセグメント追加
pub fn retransmit_queue_push(local: SocketAddr, remote: SocketAddr, seq: u32, data: Vec<u8>) {
    let current_tick = tcb_table().current_tick.load(Ordering::Relaxed);
    let mut queues = RETRANSMIT_QUEUES.write();
    if let Some(queue) = queues.get_mut(&(local, remote)) {
        queue.push(seq, data, current_tick);
    }
}

/// ACK受信時の再送キュー更新
pub fn retransmit_queue_ack(local: SocketAddr, remote: SocketAddr, ack_num: u32) {
    let current_tick = tcb_table().current_tick.load(Ordering::Relaxed);
    let mut queues = RETRANSMIT_QUEUES.write();
    if let Some(queue) = queues.get_mut(&(local, remote)) {
        queue.ack_received(ack_num, current_tick);
    }
}

/// 再送キュー削除
pub fn retransmit_queue_remove(local: SocketAddr, remote: SocketAddr) {
    RETRANSMIT_QUEUES.write().remove(&(local, remote));
}

/// タイマー駆動の再送チェック（定期的に呼ばれる）
pub fn check_retransmit_timeouts() {
    let current_tick = tcb_table().current_tick.load(Ordering::Relaxed);
    let mut queues = RETRANSMIT_QUEUES.write();
    let mut to_remove = Vec::new();
    
    for ((local, remote), queue) in queues.iter_mut() {
        if queue.check_timeout(current_tick).is_some() {
            if let Some(segment_data) = queue.retransmit(current_tick) {
                // 再送実行
                send_tcp_segment(*local, *remote, segment_data);
            } else {
                // 最大再送回数超過 - 接続をリセット
                crate::serial_println!(
                    "TCP: Max retransmit exceeded for {:?} -> {:?}", 
                    local, remote
                );
                to_remove.push((*local, *remote));
                
                // TCBも削除
                tcb_table().remove(*local, *remote);
            }
        }
    }
    
    // 削除対象をクリーンアップ
    for key in to_remove {
        queues.remove(&key);
    }
}

// =====================================================
// テスト
// =====================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rto_calculator_initial() {
        let calc = RtoCalculator::new();
        assert_eq!(calc.get_rto(), 1000); // 初期値1秒
    }
    
    #[test]
    fn test_rto_calculator_update() {
        let mut calc = RtoCalculator::new();
        
        // 最初のRTTサンプル
        calc.update(100);
        let rto1 = calc.get_rto();
        
        // RTT=100, SRTT=100, RTTVAR=50
        // RTO = SRTT + 4*RTTVAR = 100 + 200 = 300
        // ただしrto_min=200なので200-300の範囲
        assert!(rto1 >= 200 && rto1 <= 1000);
        
        // 2回目のRTTサンプル（安定）
        calc.update(100);
        let rto2 = calc.get_rto();
        assert!(rto2 <= rto1); // 安定してきたらRTOは下がる傾向
    }
    
    #[test]
    fn test_rto_calculator_backoff() {
        let mut calc = RtoCalculator::new();
        calc.update(100);
        let rto_before = calc.get_rto();
        
        // バックオフ（再送時）
        calc.backoff();
        let rto_after = calc.get_rto();
        
        // 指数バックオフで倍増
        assert!(rto_after >= rto_before);
    }
    
    #[test]
    fn test_retransmit_queue_push_and_ack() {
        let mut queue = RetransmitQueue::new();
        assert!(queue.is_empty());
        
        // セグメント追加
        queue.push(1000, alloc::vec![1, 2, 3], 100);
        queue.push(1003, alloc::vec![4, 5, 6], 110);
        assert!(!queue.is_empty());
        
        // ACK受信（最初のセグメントのみ確認）
        queue.ack_received(1003, 150);
        
        // 2番目のセグメントはまだ残っている
        assert!(!queue.is_empty());
        
        // 全て確認
        queue.ack_received(1006, 160);
        assert!(queue.is_empty());
    }
    
    #[test]
    fn test_retransmit_queue_timeout() {
        let mut queue = RetransmitQueue::new();
        
        // セグメント追加（tick=0で送信）
        queue.push(1000, alloc::vec![1, 2, 3], 0);
        
        // タイムアウト前
        assert!(queue.check_timeout(500).is_none());
        
        // タイムアウト後（初期RTO=1000）
        let timed_out = queue.check_timeout(1500);
        assert!(timed_out.is_some());
    }
    
    #[test]
    fn test_retransmit_queue_retransmit() {
        let mut queue = RetransmitQueue::new();
        let original_data = alloc::vec![1, 2, 3, 4, 5];
        
        queue.push(1000, original_data.clone(), 0);
        
        // 再送
        let retransmitted = queue.retransmit(1500).unwrap();
        assert_eq!(retransmitted, original_data);
        
        // 再送カウント増加を確認
        let seg = queue.check_timeout(3000).unwrap();
        assert_eq!(seg.retransmit_count, 1);
        assert!(seg.is_retransmit);
    }
    
    #[test]
    fn test_seq_comparison() {
        // シーケンス番号の比較（wrapping考慮）
        assert!(RetransmitQueue::seq_before(1000, 2000));
        assert!(!RetransmitQueue::seq_before(2000, 1000));
        
        // wrappingケース
        assert!(RetransmitQueue::seq_before(0xFFFF_FFF0, 0x0000_0010));
    }
}
