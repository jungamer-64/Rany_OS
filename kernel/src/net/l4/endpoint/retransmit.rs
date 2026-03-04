// ============================================================================
// kernel/src/net/l4/endpoint/retransmit.rs
// ============================================================================
//! # 再送タイマー・キュー
//!
//! RtoCalculator, RetransmitQueue, UnackedSegment

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use spin::RwLock;

use super::segment::send_tcp_segment;
use super::tcb::tcb_table;
use super::timer_wheel::TimingWheel;
use super::types::{EndpointAddr, conn_key_hash, seq_before as seq_before_fn, seq_leq as seq_leq_fn};

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
    /// SACK（Selective ACK）済みフラグ (RFC 2018)
    /// 受信側からSACKで通知されたが、累積ACKはまだ届いていない状態。
    pub is_sacked: bool,
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
        const ALPHA: u64 = 8; // 1/8
        const BETA: u64 = 4; // 1/4

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
            is_sacked: false,
        });
    }

    /// ACK受信時の処理（累積ACK）
    /// 確認されたセグメントを削除し、RTTサンプルを収集
    pub fn ack_received(&mut self, ack_num: u32, current_tick: u64) {
        // 累積ACKによって完全に確認されたセグメントを全て削除
        while let Some(seg) = self.unacked.front() {
            let seg_len = seg.data.len() as u32;
            let seg_end = seg.seq.wrapping_add(seg_len);

            // セグメントの末尾まで確認されているか？
            // seq_leq(seg_end, ack_num) を使用
            if Self::seq_leq(seg_end, ack_num) {
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
        // SACK済みのセグメントは再送不要 (RFC 2018/6675)
        self.unacked.iter().find(|seg| !seg.is_sacked).filter(|seg| {
            let elapsed = current_tick.saturating_sub(seg.send_tick);
            elapsed >= self.rto_calc.get_rto()
        })
    }

    /// 再送処理
    /// 戻り値: 再送するセグメントデータ、Noneの場合は最大再送回数超過
    pub fn retransmit(&mut self, current_tick: u64) -> Option<Vec<u8>> {
        // SACKされていない最古のセグメントを探す
        if let Some(seg) = self.unacked.iter_mut().find(|s| !s.is_sacked) {
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
    /// typesモジュールの統一実装へ委譲
    pub fn seq_before(a: u32, b: u32) -> bool {
        seq_before_fn(a, b)
    }

    /// シーケンス番号比較（以下）
    #[allow(dead_code)]
    pub fn seq_leq(a: u32, b: u32) -> bool {
        seq_leq_fn(a, b)
    }
}

impl Default for RetransmitQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// シャード数
const RETRANSMIT_SHARD_COUNT: usize = 16;
const RETRANSMIT_SHARD_MASK: usize = RETRANSMIT_SHARD_COUNT - 1;

/// シャードインデックスを算出
#[inline(always)]
fn retransmit_shard_index(local: &EndpointAddr, remote: &EndpointAddr) -> usize {
    (conn_key_hash(local, remote) as usize) & RETRANSMIT_SHARD_MASK
}

/// シャード化されたグローバル再送キューテーブル
static RETRANSMIT_SHARDS: [RwLock<BTreeMap<(EndpointAddr, EndpointAddr), RetransmitQueue>>; RETRANSMIT_SHARD_COUNT] = {
    const EMPTY: RwLock<BTreeMap<(EndpointAddr, EndpointAddr), RetransmitQueue>> =
        RwLock::new(BTreeMap::new());
    [EMPTY; RETRANSMIT_SHARD_COUNT]
};

/// グローバルタイミングホイール
///
/// 再送タイマーの満了検知を $O(1)$ amortized で行う。
/// `retransmit_queue_push` 時にタイマーを登録し、
/// `check_retransmit_timeouts` で満了した接続のみを処理する。
static TIMER_WHEEL: spin::Mutex<Option<TimingWheel>> = spin::Mutex::new(None);

/// タイミングホイールを初期化する（ネットワークスタック初期化時に呼ぶ）
pub fn init_timer_wheel() {
    let mut tw = TIMER_WHEEL.lock();
    *tw = Some(TimingWheel::new());
}

/// タイミングホイールにタイマーを登録する内部ヘルパー
fn schedule_retransmit_timer(local: EndpointAddr, remote: EndpointAddr, deadline: u64) {
    if let Some(ref mut tw) = *TIMER_WHEEL.lock() {
        tw.reschedule(local, remote, deadline);
    }
}

/// タイミングホイールからタイマーをキャンセルする内部ヘルパー
fn cancel_retransmit_timer(local: &EndpointAddr, remote: &EndpointAddr) {
    if let Some(ref mut tw) = *TIMER_WHEEL.lock() {
        tw.cancel(local, remote);
    }
}

/// 再送キュー取得または作成
pub fn get_or_create_retransmit_queue(local: EndpointAddr, remote: EndpointAddr) -> bool {
    let idx = retransmit_shard_index(&local, &remote);
    let mut queues = RETRANSMIT_SHARDS[idx].write();
    if !queues.contains_key(&(local, remote)) {
        queues.insert((local, remote), RetransmitQueue::new());
        true
    } else {
        false
    }
}

/// 再送キューにセグメント追加
pub fn retransmit_queue_push(local: EndpointAddr, remote: EndpointAddr, seq: u32, data: Vec<u8>) {
    let current_tick = tcb_table().current_tick.load(Ordering::Relaxed);
    let idx = retransmit_shard_index(&local, &remote);
    let mut queues = RETRANSMIT_SHARDS[idx].write();
    if let Some(queue) = queues.get_mut(&(local, remote)) {
        // キューが空だった場合、タイミングホイールにタイマーを登録
        let was_empty = queue.is_empty();
        queue.push(seq, data, current_tick);
        if was_empty {
            let deadline = current_tick + queue.get_rto();
            schedule_retransmit_timer(local, remote, deadline);
        }
    }
}

/// ACK受信時の再送キュー更新
pub fn retransmit_queue_ack(local: EndpointAddr, remote: EndpointAddr, ack_num: u32) {
    let current_tick = tcb_table().current_tick.load(Ordering::Relaxed);
    let idx = retransmit_shard_index(&local, &remote);
    let mut queues = RETRANSMIT_SHARDS[idx].write();
    if let Some(queue) = queues.get_mut(&(local, remote)) {
        queue.ack_received(ack_num, current_tick);
        if queue.is_empty() {
            // 全セグメント確認済み → タイマーキャンセル
            cancel_retransmit_timer(&local, &remote);
        } else {
            // まだ未確認セグメントがある → タイマーを再スケジュール
            let deadline = current_tick + queue.get_rto();
            schedule_retransmit_timer(local, remote, deadline);
        }
    }
}

/// SACKオプションで通知された領域を再送キューから取り除く
pub fn retransmit_queue_process_sack(local: EndpointAddr, remote: EndpointAddr, blocks: &[(u32, u32)]) {
    let idx = retransmit_shard_index(&local, &remote);
    let mut queues = RETRANSMIT_SHARDS[idx].write();
    if let Some(queue) = queues.get_mut(&(local, remote)) {
        // RFC 2018: "The sender SHOULD NOT drop data that has been SACKed until the 
        // data has been acknowledged by a cumulative acknowledgment."
        // We mark is_sacked = true instead of removing the segment.
        for seg in queue.unacked.iter_mut() {
            let seg_end = seg.seq.wrapping_add(seg.data.len() as u32);
            for &(l, r) in blocks {
                // シーケンスレンジがブロック内に完全に含まれるか
                let in_left = (seg.seq.wrapping_sub(l) as i32) >= 0;
                let in_right = (r.wrapping_sub(seg_end) as i32) >= 0;
                if in_left && in_right {
                    seg.is_sacked = true;
                    break;
                }
            }
        }
    }
}

/// 再送キュー削除
pub fn retransmit_queue_remove(local: EndpointAddr, remote: EndpointAddr) {
    let idx = retransmit_shard_index(&local, &remote);
    RETRANSMIT_SHARDS[idx].write().remove(&(local, remote));
    cancel_retransmit_timer(&local, &remote);
}

/// タイマー駆動の再送チェック（定期的に呼ばれる）
///
/// タイミングホイールを使って、満了した接続のみを $O(1)$ amortized で取得し、
/// 対象のシャードのみをロックして再送処理を行う。
/// タイミングホイールが未初期化の場合はフォールバックとして全シャードを探索する。
pub fn check_retransmit_timeouts() {
    let current_tick = tcb_table().current_tick.load(Ordering::Relaxed);

    // タイミングホイールから満了した接続を取得
    let expired: Vec<(EndpointAddr, EndpointAddr)> = {
        let mut tw_guard = TIMER_WHEEL.lock();
        if let Some(ref mut tw) = *tw_guard {
            tw.advance(current_tick)
        } else {
            // フォールバック: 全シャードを探索（ホイール未初期化時）
            let mut result = Vec::new();
            for shard in &RETRANSMIT_SHARDS {
                let queues = shard.read();
                for ((local, remote), queue) in queues.iter() {
                    if queue.check_timeout(current_tick).is_some() {
                        result.push((*local, *remote));
                    }
                }
            }
            result
        }
    };

    // 満了した各接続を処理
    for (local, remote) in expired {
        let idx = retransmit_shard_index(&local, &remote);
        let mut queues = RETRANSMIT_SHARDS[idx].write();

        if let Some(queue) = queues.get_mut(&(local, remote)) {
            // 実際にタイムアウトしているか再確認（ホイールのスロット粒度による誤差対策）
            if queue.check_timeout(current_tick).is_some() {
                if let Some(segment_data) = queue.retransmit(current_tick) {
                    // 再送実行
                    send_tcp_segment(local, remote, segment_data);
                    // 次のタイムアウトをスケジュール
                    let deadline = current_tick + queue.get_rto();
                    schedule_retransmit_timer(local, remote, deadline);
                } else {
                    // 最大再送回数超過 - 接続をリセット
                    log::info!(
                        "TCP: Max retransmit exceeded for {:?} -> {:?}",
                        local,
                        remote
                    );
                    queues.remove(&(local, remote));
                    tcb_table().remove(local, remote);
                }
            } else if !queue.is_empty() {
                // まだタイムアウトしていない → 再スケジュール
                let deadline = current_tick + queue.get_rto();
                schedule_retransmit_timer(local, remote, deadline);
            }
        }
    }
}

// =====================================================
// テスト
// =====================================================

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests {
    use super::*;

    #[cfg_attr(test, test_case)]
    pub fn test_rto_calculator_initial() {
        let calc = RtoCalculator::new();
        assert_eq!(calc.get_rto(), 1000); // 初期値1秒
    }

    #[cfg_attr(test, test_case)]
    pub fn test_rto_calculator_update() {
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

    #[cfg_attr(test, test_case)]
    pub fn test_rto_calculator_backoff() {
        let mut calc = RtoCalculator::new();
        calc.update(100);
        let rto_before = calc.get_rto();

        // バックオフ（再送時）
        calc.backoff();
        let rto_after = calc.get_rto();

        // 指数バックオフで倍増
        assert!(rto_after >= rto_before);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_retransmit_queue_push_and_ack() {
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

    #[cfg_attr(test, test_case)]
    pub fn test_retransmit_queue_timeout() {
        let mut queue = RetransmitQueue::new();

        // セグメント追加（tick=0で送信）
        queue.push(1000, alloc::vec![1, 2, 3], 0);

        // タイムアウト前
        assert!(queue.check_timeout(500).is_none());

        // タイムアウト後（初期RTO=1000）
        let timed_out = queue.check_timeout(1500);
        assert!(timed_out.is_some());
    }

    #[cfg_attr(test, test_case)]
    pub fn test_retransmit_queue_retransmit() {
        let mut queue = RetransmitQueue::new();
        let original_data = alloc::vec![1, 2, 3, 4, 5];

        queue.push(1000, original_data.clone(), 0);

        // 再送
        let retransmitted = queue.retransmit(1500).unwrap();
        assert_eq!(retransmitted, original_data);

        // 再送カウント増加を確認
        let seg = queue.check_timeout(1500 + queue.get_rto()).unwrap();
        assert_eq!(seg.retransmit_count, 1);
        assert!(seg.is_retransmit);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_retransmit_queue_process_sack() {
        use super::EndpointAddr;
        let local = EndpointAddr::new([192,168,0,1], 10000);
        let remote = EndpointAddr::new([192,168,0,2], 20000);

        // 再送キュー作成とセグメント追加
        get_or_create_retransmit_queue(local, remote);
        retransmit_queue_push(local, remote, 1000, alloc::vec![1,2,3]);
        retransmit_queue_push(local, remote, 1003, alloc::vec![4,5,6]);

        // SACKで最初のセグメント(1000..1003)が通知される
        retransmit_queue_process_sack(local, remote, &[(1000, 1003)]);

        // 内部状態を確認（RFC 2018: 累積ACKが来るまで削除はしないが、is_sackedフラグが立つ）
        let idx = retransmit_shard_index(&local, &remote);
        let qs = RETRANSMIT_SHARDS[idx].read();
        let q = qs.get(&(local, remote)).unwrap();
        assert_eq!(q.unacked.len(), 2);
        assert!(q.unacked.front().unwrap().is_sacked);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_seq_comparison() {
        // シーケンス番号の比較（wrapping考慮）
        assert!(RetransmitQueue::seq_before(1000, 2000));
        assert!(!RetransmitQueue::seq_before(2000, 1000));

        // wrappingケース
        assert!(RetransmitQueue::seq_before(0xFFFF_FFF0, 0x0000_0010));
    }
}


#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;

    pub fn rto_calculator_initial_smoke() -> bool {
        let calc = RtoCalculator::new();
        calc.get_rto() == 1000
    }

    pub fn rto_calculator_update_smoke() -> bool {
        let mut calc = RtoCalculator::new();
        calc.update(100);
        let rto1 = calc.get_rto();
        if !(200..=1000).contains(&rto1) {
            return false;
        }

        calc.update(100);
        let rto2 = calc.get_rto();
        rto2 <= rto1
    }

    pub fn rto_calculator_backoff_smoke() -> bool {
        let mut calc = RtoCalculator::new();
        calc.update(100);
        let rto_before = calc.get_rto();
        calc.backoff();
        let rto_after = calc.get_rto();
        rto_after >= rto_before
    }

    pub fn retransmit_queue_push_and_ack_smoke() -> bool {
        let mut queue = RetransmitQueue::new();
        if !queue.is_empty() {
            return false;
        }

        queue.push(1000, alloc::vec![1, 2, 3], 100);
        queue.push(1003, alloc::vec![4, 5, 6], 110);
        if queue.is_empty() {
            return false;
        }

        queue.ack_received(1003, 150);
        if queue.is_empty() {
            return false;
        }

        queue.ack_received(1006, 160);
        queue.is_empty()
    }

    pub fn retransmit_queue_timeout_smoke() -> bool {
        let mut queue = RetransmitQueue::new();
        queue.push(1000, alloc::vec![1, 2, 3], 0);

        if queue.check_timeout(500).is_some() {
            return false;
        }

        queue.check_timeout(1500).is_some()
    }

    pub fn retransmit_queue_retransmit_smoke() -> bool {
        let mut queue = RetransmitQueue::new();
        let original_data = alloc::vec![1, 2, 3, 4, 5];
        queue.push(1000, original_data.clone(), 0);

        let Some(retransmitted) = queue.retransmit(1500) else {
            return false;
        };
        if retransmitted != original_data {
            return false;
        }

        let Some(seg) = queue.check_timeout(1500 + queue.get_rto()) else {
            return false;
        };

        seg.retransmit_count == 1 && seg.is_retransmit
    }

    pub fn retransmit_queue_process_sack_smoke() -> bool {
        let local = EndpointAddr::new([192, 168, 0, 1], 10000);
        let remote = EndpointAddr::new([192, 168, 0, 2], 20000);

        retransmit_queue_remove(local, remote);

        get_or_create_retransmit_queue(local, remote);
        retransmit_queue_push(local, remote, 1000, alloc::vec![1, 2, 3]);
        retransmit_queue_push(local, remote, 1003, alloc::vec![4, 5, 6]);

        retransmit_queue_process_sack(local, remote, &[(1000, 1003)]);

        let ok = {
            let idx = retransmit_shard_index(&local, &remote);
            let qs = RETRANSMIT_SHARDS[idx].read();
            let Some(q) = qs.get(&(local, remote)) else {
                return false;
            };
            q.unacked.len() == 2 && q.unacked.front().map(|x| x.is_sacked) == Some(true)
        };

        retransmit_queue_remove(local, remote);
        ok
    }

    pub fn seq_comparison_smoke() -> bool {
        RetransmitQueue::seq_before(1000, 2000)
            && !RetransmitQueue::seq_before(2000, 1000)
            && RetransmitQueue::seq_before(0xFFFF_FFF0, 0x0000_0010)
    }
}
