// ============================================================================
// kernel/src/net/l4/tcp/retransmit.rs - 再送タイマー・キュー
// ============================================================================
//! # 再送タイマー・キュー
//!
//! RtoCalculator, RetransmitQueue, UnackedSegment

use crate::sync::PoisonLock;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use kernel_api::resource::net::{PacketChain, PacketPayload, PacketRef};

use super::segment::send_tcp_segment_payload_with_completion_in;
use super::tcb::TcpFlowKey;
use super::timer_wheel::TimingWheel;
use crate::net::l4::types::{EndpointAddr, conn_key_hash, seq_leq as seq_leq_fn};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::manager::NetIfId;
use crate::net::runtime::transport::{tcp_runtime_in, tcp_table_in};

#[derive(Debug)]
pub enum RetransmitPayloadState {
    Ready(PacketPayload),
    InFlight { completion_id: u64, acked: bool },
}

/// 未確認セグメント（再送用）
#[derive(Debug)]
pub struct UnackedSegment {
    /// シーケンス番号
    pub seq: u32,
    /// TCP sequence space consumed by this segment body/control flags.
    pub seq_len: u32,
    /// セグメントデータ（ヘッダ含む）
    pub data: RetransmitPayloadState,
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
            // NOTE: RFC 6298 §2.4 SHOULD round up to 1 second, but many implementations
            // (including Linux) use a lower minimum. 200ms is chosen for responsiveness,
            // intentionally deviating from the SHOULD.
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
            data: RetransmitPayloadState::Ready(data),
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
        while let Some(seg) = self.unacked.front_mut() {
            let seg_end = seg.seq.wrapping_add(seg.seq_len);

            // セグメントの末尾まで確認されているか？
            if Self::seq_leq(seg_end, ack_num) {
                if let RetransmitPayloadState::InFlight { acked, .. } = &mut seg.data {
                    *acked = true;
                    break;
                }
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
            .filter(|seg| matches!(seg.data, RetransmitPayloadState::Ready(_)))
            .filter(|seg| {
                let elapsed = current_tick.saturating_sub(seg.send_tick);
                elapsed >= self.rto_calc.get_rto()
            })
    }

    pub fn transmit_ready(
        &mut self,
        runtime: NetRuntimeHandle,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
        seq: u32,
    ) -> bool {
        let current_tick = tcp_table_in(runtime).current_tick.load(Ordering::Relaxed);
        self.transmit_ready_inner(runtime, if_id, local, remote, seq, current_tick, false)
    }

    fn transmit_ready_inner(
        &mut self,
        runtime: NetRuntimeHandle,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
        seq: u32,
        current_tick: u64,
        is_retransmit: bool,
    ) -> bool {
        let Some(seg) = self.unacked.iter_mut().find(|seg| seg.seq == seq) else {
            return false;
        };
        let (completion_id, _completion) =
            crate::net::runtime::device::register_tx_completion_in(runtime);
        register_tcp_tx_return_target(
            runtime,
            completion_id,
            TcpFlowKey::new(if_id, local, remote),
        );
        let state = core::mem::replace(
            &mut seg.data,
            RetransmitPayloadState::InFlight {
                completion_id,
                acked: false,
            },
        );
        let data = match state {
            RetransmitPayloadState::Ready(data) => data,
            other => {
                unregister_tcp_tx_return_target(runtime, completion_id);
                seg.data = other;
                return false;
            }
        };
        seg.send_tick = current_tick;
        seg.is_retransmit = is_retransmit;
        send_tcp_segment_payload_with_completion_in(
            runtime,
            if_id,
            local,
            remote,
            data,
            Some(completion_id),
        )
    }

    /// 再送処理
    /// 戻り値: 再送するセグメントデータ、Noneの場合は最大再送回数超過
    pub fn retransmit(
        &mut self,
        runtime: NetRuntimeHandle,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
        current_tick: u64,
    ) -> RetransmitAttempt {
        // SACKされていない最古のセグメントを探す
        if let Some(seg) = self
            .unacked
            .iter_mut()
            .find(|s| !s.is_sacked && matches!(s.data, RetransmitPayloadState::Ready(_)))
        {
            if seg.retransmit_count >= self.max_retries {
                // 最大再送回数超過
                return RetransmitAttempt::MaxRetriesExceeded;
            }

            seg.retransmit_count += 1;
            let seq = seg.seq;
            self.rto_calc.backoff();

            return if self.transmit_ready_inner(
                runtime,
                if_id,
                local,
                remote,
                seq,
                current_tick,
                true,
            ) {
                RetransmitAttempt::Sent
            } else {
                RetransmitAttempt::NoReadySegment
            };
        }
        RetransmitAttempt::NoReadySegment
    }

    /// Fast Retransmit (RFC 5681 / RFC 6582)
    /// 3重複ACKまたはPartial ACK受信時に、最古の未確認セグメントを即座に再送する。
    /// （RTOの指数バックオフは行わない）
    pub fn fast_retransmit(
        &mut self,
        runtime: NetRuntimeHandle,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
        current_tick: u64,
    ) -> RetransmitAttempt {
        // SACKされていない最古の未確認セグメントを即座に再送
        if let Some(seg) = self
            .unacked
            .iter_mut()
            .find(|s| !s.is_sacked && matches!(s.data, RetransmitPayloadState::Ready(_)))
        {
            if seg.retransmit_count >= self.max_retries {
                return RetransmitAttempt::MaxRetriesExceeded;
            }

            seg.retransmit_count += 1;
            let seq = seg.seq;

            return if self.transmit_ready_inner(
                runtime,
                if_id,
                local,
                remote,
                seq,
                current_tick,
                true,
            ) {
                RetransmitAttempt::Sent
            } else {
                RetransmitAttempt::NoReadySegment
            };
        }
        RetransmitAttempt::NoReadySegment
    }

    fn complete_inflight(
        &mut self,
        completion_id: u64,
        payload: PacketPayload,
        result: Result<(), &'static str>,
        current_tick: u64,
    ) {
        let Some(index) = self.unacked.iter().position(|seg| {
            matches!(
                seg.data,
                RetransmitPayloadState::InFlight {
                    completion_id: in_flight_id,
                    ..
                } if in_flight_id == completion_id
            )
        }) else {
            return;
        };
        let acked = matches!(
            self.unacked[index].data,
            RetransmitPayloadState::InFlight { acked: true, .. }
        );
        if result.is_ok() && acked {
            let seg = self
                .unacked
                .remove(index)
                .expect("in-flight segment index disappeared");
            if !seg.is_retransmit {
                let rtt = current_tick.saturating_sub(seg.send_tick);
                if rtt > 0 {
                    self.rto_calc.update(rtt);
                }
            }
            return;
        }
        self.unacked[index].data = RetransmitPayloadState::Ready(payload);
    }

    /// キューが空かどうか
    pub fn is_empty(&self) -> bool {
        self.unacked.is_empty()
    }

    /// 現在のRTO取得
    pub fn get_rto(&self) -> u64 {
        self.rto_calc.get_rto()
    }

    /// シーケンス番号比較（以下）
    pub fn seq_leq(a: u32, b: u32) -> bool {
        seq_leq_fn(a, b)
    }
}

pub enum RetransmitAttempt {
    Sent,
    NoReadySegment,
    MaxRetriesExceeded,
}

impl Default for RetransmitQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// シャード数
const RETRANSMIT_SHARDS: usize = 16;

/// シャードインデックスを算出
fn retransmit_shard_index(key: TcpFlowKey) -> usize {
    ((conn_key_hash(&key.local, &key.remote) ^ u32::from(key.if_id.0)) as usize) % RETRANSMIT_SHARDS
}

pub(crate) struct RetransmitRuntimeState {
    queues: [PoisonLock<BTreeMap<TcpFlowKey, RetransmitQueue>>; RETRANSMIT_SHARDS],
    return_targets: PoisonLock<BTreeMap<u64, TcpFlowKey>>,
    timer_wheel: PoisonLock<Option<TimingWheel>>,
}

impl RetransmitRuntimeState {
    pub(crate) const fn new() -> Self {
        Self {
            queues: [const { PoisonLock::new(BTreeMap::new()) }; RETRANSMIT_SHARDS],
            return_targets: PoisonLock::new(BTreeMap::new()),
            timer_wheel: PoisonLock::new(None),
        }
    }

    pub(crate) fn init_timer_wheel(&self) {
        let mut timer_wheel = self.timer_wheel.lock().unwrap_or_else(|e| e.into_inner());
        *timer_wheel = Some(TimingWheel::new());
    }
}

fn build_payload_from_segments(mut segments: Vec<PacketRef>) -> PacketPayload {
    match segments.len() {
        0 => PacketPayload::default(),
        1 => PacketPayload::single(segments.remove(0)),
        _ => PacketPayload::chain(PacketChain::from_segments(segments)),
    }
}

fn register_tcp_tx_return_target(runtime: NetRuntimeHandle, completion_id: u64, key: TcpFlowKey) {
    tcp_runtime_in(runtime)
        .retransmit()
        .return_targets
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(completion_id, key);
}

fn unregister_tcp_tx_return_target(
    runtime: NetRuntimeHandle,
    completion_id: u64,
) -> Option<TcpFlowKey> {
    tcp_runtime_in(runtime)
        .retransmit()
        .return_targets
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&completion_id)
}

/// タイミングホイールを初期化する
pub fn init_timer_wheel_in(runtime: NetRuntimeHandle) {
    tcp_runtime_in(runtime).retransmit().init_timer_wheel();
}

/// タイミングホイールにタイマーを登録する
fn schedule_retransmit_timer(runtime: NetRuntimeHandle, key: TcpFlowKey, deadline: u64) {
    if let Some(ref mut tw) = *tcp_runtime_in(runtime)
        .retransmit()
        .timer_wheel
        .lock()
        .unwrap_or_else(|e| e.into_inner())
    {
        tw.reschedule(key, deadline);
    }
}

/// タイミングホイールからタイマーをキャンセルする
fn cancel_retransmit_timer(runtime: NetRuntimeHandle, key: TcpFlowKey) {
    if let Some(ref mut tw) = *tcp_runtime_in(runtime)
        .retransmit()
        .timer_wheel
        .lock()
        .unwrap_or_else(|e| e.into_inner())
    {
        tw.cancel(key);
    }
}

/// 再送キュー取得または作成
pub fn get_or_create_retransmit_queue(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
) -> bool {
    let key = TcpFlowKey::new(if_id, local, remote);
    let idx = retransmit_shard_index(key);
    let state = tcp_runtime_in(runtime).retransmit();
    let mut queues = state.queues[idx].lock().unwrap_or_else(|e| e.into_inner());
    if let alloc::collections::btree_map::Entry::Vacant(entry) = queues.entry(key) {
        entry.insert(RetransmitQueue::new());
        true
    } else {
        false
    }
}

/// 再送キューにセグメント追加
pub fn retransmit_queue_push(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
    seq: u32,
    seq_len: u32,
    data: PacketPayload,
) {
    let key = TcpFlowKey::new(if_id, local, remote);
    let idx = retransmit_shard_index(key);
    let current_tick = tcp_table_in(runtime).current_tick.load(Ordering::Relaxed);
    let state = tcp_runtime_in(runtime).retransmit();
    let mut queues = state.queues[idx].lock().unwrap_or_else(|e| e.into_inner());
    if let Some(queue) = queues.get_mut(&key) {
        let was_empty = queue.is_empty();
        queue.push(seq, seq_len, data, current_tick);
        if was_empty {
            let deadline = current_tick + queue.get_rto();
            schedule_retransmit_timer(runtime, key, deadline);
        }
    }
}

pub fn retransmit_queue_transmit_ready(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
    seq: u32,
) -> bool {
    let key = TcpFlowKey::new(if_id, local, remote);
    let idx = retransmit_shard_index(key);
    let state = tcp_runtime_in(runtime).retransmit();
    let mut queues = state.queues[idx].lock().unwrap_or_else(|e| e.into_inner());
    queues
        .get_mut(&key)
        .is_some_and(|queue| queue.transmit_ready(runtime, if_id, local, remote, seq))
}

pub(crate) fn complete_tx_owner(
    runtime: NetRuntimeHandle,
    completion_id: u64,
    keepalive: Vec<PacketRef>,
    result: Result<(), &'static str>,
) -> bool {
    let Some(key) = unregister_tcp_tx_return_target(runtime, completion_id) else {
        return false;
    };
    let idx = retransmit_shard_index(key);
    let payload = build_payload_from_segments(keepalive);
    let current_tick = tcp_table_in(runtime).current_tick.load(Ordering::Relaxed);
    let state = tcp_runtime_in(runtime).retransmit();
    let mut queues = state.queues[idx].lock().unwrap_or_else(|e| e.into_inner());
    if let Some(queue) = queues.get_mut(&key) {
        queue.complete_inflight(completion_id, payload, result, current_tick);
        if queue.is_empty() {
            queues.remove(&key);
            cancel_retransmit_timer(runtime, key);
        } else {
            let deadline = current_tick + queue.get_rto();
            schedule_retransmit_timer(runtime, key, deadline);
        }
        return true;
    }
    false
}

/// ACK受信時の再送キュー更新
pub fn retransmit_queue_ack(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
    ack_num: u32,
) {
    let key = TcpFlowKey::new(if_id, local, remote);
    let idx = retransmit_shard_index(key);
    let current_tick = tcp_table_in(runtime).current_tick.load(Ordering::Relaxed);
    let state = tcp_runtime_in(runtime).retransmit();
    let mut queues = state.queues[idx].lock().unwrap_or_else(|e| e.into_inner());
    if let Some(queue) = queues.get_mut(&key) {
        queue.ack_received(ack_num, current_tick);
        if queue.is_empty() {
            cancel_retransmit_timer(runtime, key);
        } else {
            let deadline = current_tick + queue.get_rto();
            schedule_retransmit_timer(runtime, key, deadline);
        }
    }
}

/// SACKオプションで通知された領域をマーク
pub fn retransmit_queue_process_sack(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
    blocks: &[(u32, u32)],
) {
    let key = TcpFlowKey::new(if_id, local, remote);
    let idx = retransmit_shard_index(key);
    let state = tcp_runtime_in(runtime).retransmit();
    let mut queues = state.queues[idx].lock().unwrap_or_else(|e| e.into_inner());
    if let Some(queue) = queues.get_mut(&key) {
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

/// 再送キュー削除
pub fn retransmit_queue_remove(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
) {
    let key = TcpFlowKey::new(if_id, local, remote);
    let idx = retransmit_shard_index(key);
    let state = tcp_runtime_in(runtime).retransmit();
    state.queues[idx]
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&key);
    cancel_retransmit_timer(runtime, key);
}

/// Fast Retransmit 即時再送実行 (RFC 5681 / RFC 6582)
pub fn retransmit_queue_fast_retransmit(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
) -> RetransmitAttempt {
    let key = TcpFlowKey::new(if_id, local, remote);
    let queue_lock = get_or_create_retransmit_queue(runtime, key);
    let mut queue = queue_lock.lock();
    let current_tick = tcp_runtime_in(runtime).get_current_tick();
    queue.fast_retransmit(runtime, if_id, local, remote, current_tick)
}

/// タイマー駆動の再送チェック
pub fn check_retransmit_timeouts(runtime: NetRuntimeHandle) {
    let current_tick = tcp_table_in(runtime).current_tick.load(Ordering::Relaxed);

    let expired: Vec<TcpFlowKey> = {
        let state = tcp_runtime_in(runtime).retransmit();
        let mut tw_guard = state.timer_wheel.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref mut tw) = *tw_guard {
            tw.advance(current_tick)
        } else {
            let mut result = Vec::new();
            for i in 0..RETRANSMIT_SHARDS {
                let queues = state.queues[i].lock().unwrap_or_else(|e| e.into_inner());
                for (key, queue) in queues.iter() {
                    if queue.check_timeout(current_tick).is_some() {
                        result.push(*key);
                    }
                }
            }
            result
        }
    };

    for key in expired {
        let idx = retransmit_shard_index(key);
        let state = tcp_runtime_in(runtime).retransmit();
        let mut queues = state.queues[idx].lock().unwrap_or_else(|e| e.into_inner());

        if let Some(queue) = queues.get_mut(&key) {
            if queue.check_timeout(current_tick).is_some() {
                match queue.retransmit(runtime, key.if_id, key.local, key.remote, current_tick) {
                    RetransmitAttempt::Sent => {
                        let deadline = current_tick + queue.get_rto();
                        schedule_retransmit_timer(runtime, key, deadline);
                    }
                    RetransmitAttempt::NoReadySegment => {}
                    RetransmitAttempt::MaxRetriesExceeded => {
                        log::info!(
                            "TCP: Max retransmit exceeded for {:?} -> {:?}",
                            key.local,
                            key.remote
                        );
                        queues.remove(&key);
                        tcp_table_in(runtime).remove(key.if_id, key.local, key.remote);
                    }
                }
            } else if !queue.is_empty() {
                let deadline = current_tick + queue.get_rto();
                schedule_retransmit_timer(runtime, key, deadline);
            }
        }
    }
}
