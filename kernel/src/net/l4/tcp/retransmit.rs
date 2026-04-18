// ============================================================================
// kernel/src/net/l4/endpoint/retransmit.rs
// ============================================================================
//! # 再送タイマー・キュー
//!
//! RtoCalculator, RetransmitQueue, UnackedSegment

use crate::sync::PoisonLock;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use kernel_api::resource::net::PacketPayload;

use super::segment::send_tcp_segment_payload;
use super::tcb::tcb_table;
use super::timer_wheel::TimingWheel;
use crate::net::l4::types::{
    EndpointAddr, conn_key_hash, seq_before as seq_before_fn, seq_leq as seq_leq_fn,
};

/// 未確認セグメント（再送用）
#[derive(Debug)]
pub struct UnackedSegment {
    /// シーケンス番号
    pub seq: u32,
    /// TCP sequence space consumed by this segment body/control flags.
    pub seq_len: u32,
    /// セグメントデータ（ヘッダ含む）
    pub data: PacketPayload,
    /// 送信時刻（tick）
    pub send_tick: u64,
    /// 再送回数
    pub retransmit_count: u8,
    /// RTOサンプル用フラグ（再送済みはRTTサンプルに使わない）
    pub is_retransmit: bool,
    /// SACK（Selective ACK）済みフラグ (RFC 2018)
    /// 受信側からSACKで通知されたが、累積ACKは届いていない状態。
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
    pub fn push(&mut self, seq: u32, seq_len: u32, data: PacketPayload, current_tick: u64) {
        self.unacked.push_back(UnackedSegment {
            seq,
            seq_len,
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
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while let Some(seg) = self.unacked.front() {
            let seg_end = seg.seq.wrapping_add(seg.seq_len);

            // セグメントの末尾まで確認されているか？
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
        // SACK済みのセグメントは再送不要
        self.unacked
            .iter()
            .find(|seg| !seg.is_sacked)
            .filter(|seg| {
                let elapsed = current_tick.saturating_sub(seg.send_tick);
                elapsed >= self.rto_calc.get_rto()
            })
    }

    /// 再送処理
    /// 戻り値: 再送するセグメントデータ、Noneの場合は最大再送回数超過
    pub fn retransmit(&mut self, current_tick: u64) -> Option<PacketPayload> {
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

            return materialize_retransmit_copy(&seg.data);
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
static RETRANSMIT_SHARDS: [PoisonLock<BTreeMap<(EndpointAddr, EndpointAddr), RetransmitQueue>>;
    RETRANSMIT_SHARD_COUNT] = {
    const EMPTY: PoisonLock<BTreeMap<(EndpointAddr, EndpointAddr), RetransmitQueue>> =
        PoisonLock::new(BTreeMap::new());
    [EMPTY; RETRANSMIT_SHARD_COUNT]
};

/// グローバルタイミングホイール
static TIMER_WHEEL: PoisonLock<Option<TimingWheel>> = PoisonLock::new(None);

/// タイミングホイールを初期化する
pub fn init_timer_wheel() {
    let mut tw = TIMER_WHEEL.lock().unwrap_or_else(|e| e.into_inner());
    *tw = Some(TimingWheel::new());
}

/// タイミングホイールにタイマーを登録する
fn schedule_retransmit_timer(local: EndpointAddr, remote: EndpointAddr, deadline: u64) {
    if let Some(ref mut tw) = *TIMER_WHEEL.lock().unwrap_or_else(|e| e.into_inner()) {
        tw.reschedule(local, remote, deadline);
    }
}

/// タイミングホイールからタイマーをキャンセルする
fn cancel_retransmit_timer(local: &EndpointAddr, remote: &EndpointAddr) {
    if let Some(ref mut tw) = *TIMER_WHEEL.lock().unwrap_or_else(|e| e.into_inner()) {
        tw.cancel(local, remote);
    }
}

/// 再送キュー取得または作成
pub fn get_or_create_retransmit_queue(local: EndpointAddr, remote: EndpointAddr) -> bool {
    let idx = retransmit_shard_index(&local, &remote);
    let mut queues = RETRANSMIT_SHARDS[idx]
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if !queues.contains_key(&(local, remote)) {
        queues.insert((local, remote), RetransmitQueue::new());
        true
    } else {
        false
    }
}

/// 再送キューにセグメント追加
pub fn retransmit_queue_push(
    local: EndpointAddr,
    remote: EndpointAddr,
    seq: u32,
    seq_len: u32,
    data: PacketPayload,
) {
    let current_tick = tcb_table().current_tick.load(Ordering::Relaxed);
    let idx = retransmit_shard_index(&local, &remote);
    let mut queues = RETRANSMIT_SHARDS[idx]
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(queue) = queues.get_mut(&(local, remote)) {
        let was_empty = queue.is_empty();
        queue.push(seq, seq_len, data, current_tick);
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
    let mut queues = RETRANSMIT_SHARDS[idx]
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(queue) = queues.get_mut(&(local, remote)) {
        queue.ack_received(ack_num, current_tick);
        if queue.is_empty() {
            cancel_retransmit_timer(&local, &remote);
        } else {
            let deadline = current_tick + queue.get_rto();
            schedule_retransmit_timer(local, remote, deadline);
        }
    }
}

/// SACKオプションで通知された領域をマーク
pub fn retransmit_queue_process_sack(
    local: EndpointAddr,
    remote: EndpointAddr,
    blocks: &[(u32, u32)],
) {
    let idx = retransmit_shard_index(&local, &remote);
    let mut queues = RETRANSMIT_SHARDS[idx]
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(queue) = queues.get_mut(&(local, remote)) {
        for seg in queue.unacked.iter_mut() {
            let seg_end = seg.seq.wrapping_add(seg.seq_len);
            for &(l, r) in blocks {
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

pub(crate) fn materialize_retransmit_copy(payload: &PacketPayload) -> Option<PacketPayload> {
    let mut builder = crate::net::payload::PacketPayloadBuilder::new();
    let view = crate::net::payload::PacketPayloadView::new(payload);
    let mut copied = 0usize;
    let total_len = view.total_len();
    view.for_each_chunk(|chunk| {
        if copied >= total_len {
            return;
        }
        if !chunk.is_empty() && builder.push_bytes(chunk).is_some() {
            copied += chunk.len();
        }
    });
    (copied == total_len).then(|| builder.build())
}

/// 再送キュー削除
pub fn retransmit_queue_remove(local: EndpointAddr, remote: EndpointAddr) {
    let idx = retransmit_shard_index(&local, &remote);
    RETRANSMIT_SHARDS[idx]
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&(local, remote));
    cancel_retransmit_timer(&local, &remote);
}

/// タイマー駆動の再送チェック
pub fn check_retransmit_timeouts() {
    let current_tick = tcb_table().current_tick.load(Ordering::Relaxed);

    let expired: Vec<(EndpointAddr, EndpointAddr)> = {
        let mut tw_guard = TIMER_WHEEL.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref mut tw) = *tw_guard {
            tw.advance(current_tick)
        } else {
            let mut result = Vec::new();
            for shard in &RETRANSMIT_SHARDS {
                let queues = shard.lock().unwrap_or_else(|e| e.into_inner());
                for ((local, remote), queue) in queues.iter() {
                    if queue.check_timeout(current_tick).is_some() {
                        result.push((*local, *remote));
                    }
                }
            }
            result
        }
    };

    for (local, remote) in expired {
        let idx = retransmit_shard_index(&local, &remote);
        let mut queues = RETRANSMIT_SHARDS[idx]
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        if let Some(queue) = queues.get_mut(&(local, remote)) {
            if queue.check_timeout(current_tick).is_some() {
                if let Some(segment_data) = queue.retransmit(current_tick) {
                    send_tcp_segment_payload(local, remote, segment_data);
                    let deadline = current_tick + queue.get_rto();
                    schedule_retransmit_timer(local, remote, deadline);
                } else {
                    log::info!(
                        "TCP: Max retransmit exceeded for {:?} -> {:?}",
                        local,
                        remote
                    );
                    queues.remove(&(local, remote));
                    tcb_table().remove(local, remote);
                }
            } else if !queue.is_empty() {
                let deadline = current_tick + queue.get_rto();
                schedule_retransmit_timer(local, remote, deadline);
            }
        }
    }
}
