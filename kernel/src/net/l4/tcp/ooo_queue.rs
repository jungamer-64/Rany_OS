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

use crate::net::l4::types::{EndpointAddr, conn_key_hash, seq_before};
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

/// 現在のグローバルなOOOセグメント合計数
static GLOBAL_OOO_COUNT: AtomicUsize = AtomicUsize::new(0);

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
    fn insert(&mut self, seq: u32, data: PacketPayload, fin: bool) {
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

            // Check if [seq, fragment_end) overlaps with [existing_seq, existing_end)
            let overlap = !seq_before(existing_end, seq) && !seq_before(fragment_end, existing_seq);
            if overlap {
                log::warn!(
                    "[NET-TCP] Overlapping OOO segment detected at seq {}, dropping entire OOO queue for connection",
                    seq
                );
                self.clear(); // Drop everything to be safe
                return;
            }
        }

        if self.segments.len() >= MAX_OOO_SEGMENTS {
            // キュー満杯: 最も遠いセグメントを破棄
            if let Some(&(last_seq, _)) = self.segments.last() {
                if seq_before(seq, last_seq) {
                    self.segments.pop();
                    GLOBAL_OOO_COUNT.fetch_sub(1, Ordering::Relaxed);
                } else {
                    return; // 新しいセグメントがさらに遠いので破棄
                }
            }
        }

        // グローバル制限チェック
        if GLOBAL_OOO_COUNT.load(Ordering::Relaxed) >= GLOBAL_MAX_OOO_SEGMENTS {
            return;
        }

        // 挿入位置を探す
        let pos = self
            .segments
            .iter()
            .position(|(s, _)| seq_before(seq, *s))
            .unwrap_or(self.segments.len());
        self.segments.insert(pos, (seq, data));
        GLOBAL_OOO_COUNT.fetch_add(1, Ordering::Relaxed);
    }

    /// rcv_nxtより前のセグメントを削除、または部分的な重複をトリム
    fn prune_outdated(&mut self, rcv_nxt: u32) {
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
                    let Some(trimmed) = crate::net::payload::move_payload_window_owned(
                        packet,
                        overlap,
                        seg_end.wrapping_sub(rcv_nxt) as usize,
                    ) else {
                        GLOBAL_OOO_COUNT.fetch_sub(1, Ordering::Relaxed);
                        continue;
                    };
                    to_reinsert.push((rcv_nxt, trimmed));
                    // GLOBAL_OOO_COUNT remains the same because this segment is
                    // essentially replaced by a trimmed version.
                } else {
                    // 完全に受信済み、または重複部分のみだった
                    GLOBAL_OOO_COUNT.fetch_sub(1, Ordering::Relaxed);
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
                GLOBAL_OOO_COUNT.fetch_sub(1, Ordering::Relaxed);
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
    fn drain_contiguous_with<F>(&mut self, mut rcv_nxt: u32, mut f: F) -> (u32, bool)
    where
        F: FnMut(u32, PacketPayload) -> (usize, Option<PacketPayload>),
    {
        self.prune_outdated(rcv_nxt);
        let mut fin_encountered = false;

        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
        loop {
            // Find segment starting at rcv_nxt
            let pos = self.segments.iter().position(|(s, _)| *s == rcv_nxt);
            if let Some(i) = pos {
                let (_, payload) = self.segments.remove(i);
                GLOBAL_OOO_COUNT.fetch_sub(1, Ordering::Relaxed);
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
                        GLOBAL_OOO_COUNT.fetch_add(1, Ordering::Relaxed);
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
                self.prune_outdated(rcv_nxt);
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

    fn clear(&mut self) {
        let count = self.segments.len();
        self.segments.clear();
        self.fin_seq = None;
        GLOBAL_OOO_COUNT.fetch_sub(count, Ordering::Relaxed);
    }
}

/// 接続キー
type ConnKey = (EndpointAddr, EndpointAddr);

/// シャード数
const OOO_SHARD_COUNT: usize = 16;
const OOO_SHARD_MASK: usize = OOO_SHARD_COUNT - 1;

/// シャードインデックスを算出
#[inline(always)]
fn ooo_shard_index(local: &EndpointAddr, remote: &EndpointAddr) -> usize {
    (conn_key_hash(local, remote) as usize) & OOO_SHARD_MASK
}

/// シャード化されたグローバルOOOキューマップ
static OOO_SHARDS: [PoisonLock<Option<BTreeMap<ConnKey, ConnectionOooQueue>>>; OOO_SHARD_COUNT] = {
    const EMPTY: PoisonLock<Option<BTreeMap<ConnKey, ConnectionOooQueue>>> = PoisonLock::new(None);
    [EMPTY; OOO_SHARD_COUNT]
};

/// OOOキューを初期化
pub fn init_ooo_queues() {
    GLOBAL_OOO_COUNT.store(0, Ordering::SeqCst);
    for shard in &OOO_SHARDS {
        match shard.lock() {
            Ok(mut g) => {
                *g = Some(BTreeMap::new());
            }
            Err(_) => {}
        }
    }
}

/// OOOセグメントを挿入
pub fn insert_ooo_segment(
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
    if GLOBAL_OOO_COUNT.load(Ordering::Relaxed) >= GLOBAL_MAX_OOO_SEGMENTS {
        return;
    }

    let idx = ooo_shard_index(&local, &remote);
    let Ok(mut guard) = OOO_SHARDS[idx].lock() else {
        return;
    };
    let queues = guard.get_or_insert_with(BTreeMap::new);

    // 接続数制限チェック
    let per_shard_limit = MAX_OOO_CONNECTIONS / OOO_SHARD_COUNT;
    if !queues.contains_key(&(local, remote)) && queues.len() >= per_shard_limit.max(8) {
        return;
    }

    let conn_queue = queues
        .entry((local, remote))
        .or_insert_with(ConnectionOooQueue::new);

    conn_queue.insert(seq, data, fin);
}

/// OOOキューから連続データをクロージャにプッシュしてドレイン
/// 戻り値: (新rcv_nxt, fin_encountered)
pub fn drain_ooo_contiguous<F>(
    local: EndpointAddr,
    remote: EndpointAddr,
    mut rcv_nxt: u32,
    f: F,
) -> (u32, bool)
where
    F: FnMut(u32, PacketPayload) -> (usize, Option<PacketPayload>),
{
    let idx = ooo_shard_index(&local, &remote);
    let Ok(mut guard) = OOO_SHARDS[idx].lock() else {
        return (rcv_nxt, false);
    };
    let Some(queues) = guard.as_mut() else {
        return (rcv_nxt, false);
    };

    if let Some(conn_queue) = queues.get_mut(&(local, remote)) {
        let (new_rcv_nxt, fin) = conn_queue.drain_contiguous_with(rcv_nxt, f);
        rcv_nxt = new_rcv_nxt;
        // 空になったキューを削除
        if conn_queue.is_empty() {
            queues.remove(&(local, remote));
        }
        (rcv_nxt, fin)
    } else {
        (rcv_nxt, false)
    }
}

/// 接続のOOOキューを削除
pub fn remove_ooo_queue(local: EndpointAddr, remote: EndpointAddr) {
    let idx = ooo_shard_index(&local, &remote);
    let Ok(mut guard) = OOO_SHARDS[idx].lock() else {
        return;
    };
    if let Some(queues) = guard.as_mut() {
        if let Some(mut conn_queue) = queues.remove(&(local, remote)) {
            conn_queue.clear();
        }
    }
}

/// 指定接続にOOOセグメントが存在するか確認
///
/// TCP Fast Path のガード条件に使用。
/// OOOセグメントが存在する場合、ファストパスでは正しい順序
/// のドレインができないため、スローパスへフォールバックする。
#[inline]
pub fn has_ooo_segments(local: EndpointAddr, remote: EndpointAddr) -> bool {
    let idx = ooo_shard_index(&local, &remote);
    let Ok(guard) = OOO_SHARDS[idx].lock() else {
        return false; // ロック取得失敗 → 安全側でfalse
    };
    guard
        .as_ref()
        .and_then(|queues| queues.get(&(local, remote)))
        .map(|q| !q.is_empty())
        .unwrap_or(false)
}
