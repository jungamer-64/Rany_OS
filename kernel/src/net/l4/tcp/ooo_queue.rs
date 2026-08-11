// ============================================================================
// kernel/src/net/l4/tcp/ooo_queue.rs - TCP Out-of-Order (OOO) 受信キュー
// ============================================================================
//! # TCP Out-of-Order (OOO) 受信キュー
//!
//! 順序外で到着したTCPセグメントを一時保持し、
//! rcv_nxtが進んだ時に連続データをドレインする。
//!
//! ## 設計
//! - 接続ごとに独立したOOOキューを管理
//! - BTreeMapでシーケンス番号順にソート済み
//! - 最大セグメント数制限でメモリ枯渇を防止
//! - SACKブロック生成をサポート

// Building block: Out-of-order queue implementation

use crate::net::l4::tcp::tcb::TcpFlowKey;
use crate::net::l4::types::{EndpointAddr, conn_key_hash, seq_before};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::manager::NetIfId;
use crate::net::runtime::transport::tcp_runtime_in;
use crate::sync::PoisonLock;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use kernel_api::resource::net::PacketPayload;

/// OOOセグメントの最大保持数（接続あたり）
const MAX_OOO_SEGMENTS: usize = 16;

/// OOOキューの最大接続数
const MAX_OOO_CONNECTIONS: usize = 128;

/// 全接続での最大合計OOOセグメント数 (Mempool 4096 の 1/8)
/// これにより、攻撃者がOOOセグメントでMempoolを使い果たすことを防ぐ。
const GLOBAL_MAX_OOO_SEGMENTS: usize = 512;

/// 接続ごとのOOOキュー
struct ConnectionOooQueue {
    /// シーケンス番号順（wrapping-aware）にソートされたセグメント
    segments: Vec<(u32, PacketPayload)>,
    /// FINビットが設定されていたシーケンス番号（存在する場合）
    fin_seq: Option<u32>,
}

impl ConnectionOooQueue {
    fn new() -> Self {
        Self {
            segments: Vec::new(),
            fin_seq: None,
        }
    }

    /// セグメントを挿入
    fn insert(&mut self, total_count: &AtomicUsize, seq: u32, data: PacketPayload, fin: bool) {
        if fin {
            let seg_end = seq.wrapping_add(data.total_len() as u32);
            self.fin_seq = Some(seg_end);
        }

        let fragment_len = data.total_len() as u32;
        let fragment_end = seq.wrapping_add(fragment_len);

        // SECURITY: OOO queue 内の重複 segment を検出する。
        // RFC 5722 (for IPv6) and general security best practices recommend
        // discarding overlapping fragments to prevent IDS evasion and state
        // inconsistency. We apply this policy here to the OOO queue.
        for (s, p) in &self.segments {
            let existing_seq = *s;
            let existing_end = existing_seq.wrapping_add(p.total_len() as u32);

            // Check if [seq, fragment_end) overlaps with [existing_seq, existing_end).
            // Adjacent half-open ranges share no bytes and must remain queueable.
            let overlap = seq_before(seq, existing_end) && seq_before(existing_seq, fragment_end);
            if overlap {
                log::warn!(
                    "[NET-TCP] Overlapping OOO segment detected at seq {}, dropping entire OOO queue for connection",
                    seq
                );
                self.clear(total_count); // Drop everything to be safe
                return;
            }
        }

        if self.segments.len() >= MAX_OOO_SEGMENTS {
            // キュー満杯: 最も遠いセグメントを破棄
            if let Some(&(last_seq, _)) = self.segments.last() {
                if seq_before(seq, last_seq) {
                    self.segments.pop();
                    total_count.fetch_sub(1, Ordering::Relaxed);
                } else {
                    return; // 新しいセグメントがさらに遠いので破棄
                }
            }
        }

        // グローバル制限チェック
        if total_count.load(Ordering::Relaxed) >= GLOBAL_MAX_OOO_SEGMENTS {
            return;
        }

        // 挿入位置を探す
        let pos = self
            .segments
            .iter()
            .position(|(s, _)| seq_before(seq, *s))
            .unwrap_or(self.segments.len());
        self.segments.insert(pos, (seq, data));
        total_count.fetch_add(1, Ordering::Relaxed);
    }

    /// rcv_nxtより前のセグメントを削除、または部分的な重複をトリム
    fn prune_outdated(&mut self, total_count: &AtomicUsize, rcv_nxt: u32) {
        let mut to_reinsert = Vec::new();
        let mut i = 0;

        // LOOP_PROOF: mode=condition; reason=i is incremented and checked against segments.len().;
        while i < self.segments.len() {
            let (seq, _packet) = &self.segments[i];
            if seq_before(*seq, rcv_nxt) {
                let (seq, packet) = self.segments.remove(i);
                let seg_end = seq.wrapping_add(packet.total_len() as u32);

                if seq_before(rcv_nxt, seg_end) {
                    // 部分的な重複: rcv_nxtより前の部分をカットして再挿入候補にする
                    let overlap = rcv_nxt.wrapping_sub(seq) as usize;
                    let Some(bounds) = crate::net::payload::OwnedPayloadBounds::checked(
                        &packet,
                        overlap,
                        seg_end.wrapping_sub(rcv_nxt) as usize,
                    ) else {
                        total_count.fetch_sub(1, Ordering::Relaxed);
                        continue;
                    };
                    let Some(trimmed) = bounds
                        .take_from(packet)
                        .and_then(|window| window.into_payload().ok())
                    else {
                        total_count.fetch_sub(1, Ordering::Relaxed);
                        continue;
                    };
                    to_reinsert.push((rcv_nxt, trimmed));
                    // total_count remains the same because this segment is
                    // essentially replaced by a trimmed version.
                } else {
                    // 完全に受信済み、または重複部分のみだった
                    total_count.fetch_sub(1, Ordering::Relaxed);
                }
                // Don't increment i, next element shifted here
            } else {
                i += 1;
            }
        }

        for (seq, packet) in to_reinsert {
            // Re-inserting at the beginning (since seq == rcv_nxt and others are >= rcv_nxt)
            if self.segments.iter().any(|(s, _)| *s == seq) {
                // If it already exists (e.g. from a concurrent process or overlap),
                // just drop the trimmed version.
                total_count.fetch_sub(1, Ordering::Relaxed);
                continue;
            }

            let pos = self
                .segments
                .iter()
                .position(|(s, _)| seq_before(seq, *s))
                .unwrap_or(self.segments.len());
            self.segments.insert(pos, (seq, packet));
            // No fetch_add(1) here because it was already counted before removal
        }
    }

    /// rcv_nxtから連続するデータをドレイン
    fn drain_contiguous_with<F>(
        &mut self,
        total_count: &AtomicUsize,
        mut rcv_nxt: u32,
        mut f: F,
    ) -> (u32, bool)
    where
        F: FnMut(u32, PacketPayload) -> (usize, Option<PacketPayload>),
    {
        self.prune_outdated(total_count, rcv_nxt);
        let mut fin_encountered = false;

        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
        loop {
            // Find segment starting at rcv_nxt
            let pos = self.segments.iter().position(|(s, _)| *s == rcv_nxt);
            if let Some(i) = pos {
                let (_, payload) = self.segments.remove(i);
                total_count.fetch_sub(1, Ordering::Relaxed);
                let payload_len = payload.total_len();
                let (pushed, remainder) = f(rcv_nxt, payload);
                let pushed = pushed.min(payload_len);
                if pushed < payload_len {
                    if pushed > 0 {
                        rcv_nxt = rcv_nxt.wrapping_add(pushed as u32);
                    }

                    if let Some(remainder) = remainder {
                        let pos = self
                            .segments
                            .iter()
                            .position(|(s, _)| seq_before(rcv_nxt, *s))
                            .unwrap_or(self.segments.len());
                        self.segments.insert(pos, (rcv_nxt, remainder));
                        total_count.fetch_add(1, Ordering::Relaxed);
                    }
                    break;
                }
                rcv_nxt = rcv_nxt.wrapping_add(payload_len as u32);

                if let Some(fs) = self.fin_seq {
                    if fs == rcv_nxt {
                        fin_encountered = true;
                        break;
                    }
                }
                self.prune_outdated(total_count, rcv_nxt);
            } else {
                if let Some(fs) = self.fin_seq {
                    if fs == rcv_nxt {
                        fin_encountered = true;
                    }
                }
                break;
            }
        }
        (rcv_nxt, fin_encountered)
    }

    fn is_empty(&self) -> bool {
        self.segments.is_empty() && self.fin_seq.is_none()
    }

    fn clear(&mut self, total_count: &AtomicUsize) {
        let count = self.segments.len();
        self.segments.clear();
        self.fin_seq = None;
        total_count.fetch_sub(count, Ordering::Relaxed);
    }
}

/// 接続キー
const OOO_SHARDS: usize = 16;

fn ooo_shard_index(key: TcpFlowKey) -> usize {
    ((conn_key_hash(&key.local, &key.remote) ^ u32::from(key.if_id.0)) as usize) % OOO_SHARDS
}

pub(crate) struct OooRuntimeState {
    total_count: AtomicUsize,
    queues: [PoisonLock<Option<BTreeMap<TcpFlowKey, ConnectionOooQueue>>>; OOO_SHARDS],
}

impl OooRuntimeState {
    pub(crate) const fn new() -> Self {
        Self {
            total_count: AtomicUsize::new(0),
            queues: [const { PoisonLock::new(None) }; OOO_SHARDS],
        }
    }

    pub(crate) fn reset(&self) {
        self.total_count.store(0, Ordering::SeqCst);
        for i in 0..OOO_SHARDS {
            if let Ok(mut guard) = self.queues[i].lock() {
                *guard = Some(BTreeMap::new());
            }
        }
    }
}

/// OOOキューを初期化
pub fn init_ooo_queues_in(runtime: NetRuntimeHandle) {
    tcp_runtime_in(runtime).ooo().reset();
}

/// OOOセグメントを挿入
pub fn insert_ooo_segment(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
    seq: u32,
    data: PacketPayload,
    fin: bool,
) {
    if data.is_empty() && !fin {
        return;
    }

    // まずグローバル上限チェック
    let state = tcp_runtime_in(runtime).ooo();
    if state.total_count.load(Ordering::Relaxed) >= GLOBAL_MAX_OOO_SEGMENTS {
        return;
    }

    let key = TcpFlowKey::new(if_id, local, remote);
    let idx = ooo_shard_index(key);
    let Ok(mut guard) = state.queues[idx].lock() else {
        return;
    };
    let queues = guard.get_or_insert_with(BTreeMap::new);

    // 接続数制限チェック
    if !queues.contains_key(&key) && queues.len() >= MAX_OOO_CONNECTIONS {
        return;
    }

    let conn_queue = queues.entry(key).or_insert_with(ConnectionOooQueue::new);

    conn_queue.insert(&state.total_count, seq, data, fin);
}

/// OOOキューから連続データをクロージャにプッシュしてドレイン
/// 戻り値: (新rcv_nxt, fin_encountered)
pub fn drain_ooo_contiguous<F>(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
    mut rcv_nxt: u32,
    f: F,
) -> (u32, bool)
where
    F: FnMut(u32, PacketPayload) -> (usize, Option<PacketPayload>),
{
    let key = TcpFlowKey::new(if_id, local, remote);
    let idx = ooo_shard_index(key);
    let state = tcp_runtime_in(runtime).ooo();
    let Ok(mut guard) = state.queues[idx].lock() else {
        return (rcv_nxt, false);
    };
    let Some(queues) = guard.as_mut() else {
        return (rcv_nxt, false);
    };

    if let Some(conn_queue) = queues.get_mut(&key) {
        let (new_rcv_nxt, fin) = conn_queue.drain_contiguous_with(&state.total_count, rcv_nxt, f);
        rcv_nxt = new_rcv_nxt;
        // 空になったキューを削除
        if conn_queue.is_empty() {
            queues.remove(&key);
        }
        (rcv_nxt, fin)
    } else {
        (rcv_nxt, false)
    }
}

/// 接続のOOOキューを削除
pub fn remove_ooo_queue(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
) {
    let key = TcpFlowKey::new(if_id, local, remote);
    let idx = ooo_shard_index(key);
    let state = tcp_runtime_in(runtime).ooo();
    let Ok(mut guard) = state.queues[idx].lock() else {
        return;
    };
    if let Some(queues) = guard.as_mut() {
        if let Some(mut conn_queue) = queues.remove(&key) {
            conn_queue.clear(&state.total_count);
        }
    }
}

/// 指定接続にOOOセグメントが存在するか確認
///
/// TCP Fast Path のガード条件に使用。
/// OOOセグメントが存在する場合、ファストパスでは正しい順序
/// のドレインができないため、スローパスへフォールバックする。
#[inline]
pub fn has_ooo_segments(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
) -> bool {
    let key = TcpFlowKey::new(if_id, local, remote);
    let idx = ooo_shard_index(key);
    let state = tcp_runtime_in(runtime).ooo();
    let Ok(guard) = state.queues[idx].lock() else {
        return false; // ロック取得失敗 → 安全側でfalse
    };
    guard
        .as_ref()
        .and_then(|queues| queues.get(&key))
        .map(|q| !q.is_empty())
        .unwrap_or(false)
}
