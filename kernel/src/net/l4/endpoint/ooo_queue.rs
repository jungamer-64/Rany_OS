// ============================================================================
// kernel/src/net/endpoint/ooo_queue.rs
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


use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::net::datapath::mempool::{PacketRef, alloc_packet};
use crate::sync::PoisonLock;
use super::types::{SocketAddr, conn_key_hash, seq_before};

/// OOOセグメントの最大保持数（接続あたり）
const MAX_OOO_SEGMENTS: usize = 16;

/// OOOキューの最大接続数
const MAX_OOO_CONNECTIONS: usize = 128;

/// 全接続での最大合計OOOセグメント数 (Mempool 4096 の 1/8)
/// これにより、攻撃者がOOOセグメントでMempoolを使い果たすことを防ぐ。
const GLOBAL_MAX_OOO_SEGMENTS: usize = 512;

/// 現在のグローバルなOOOセグメント合計数
static GLOBAL_OOO_COUNT: AtomicUsize = AtomicUsize::new(0);

/// 順序外セグメント
#[derive(Clone)]
struct OooSegment {
    /// シーケンス番号
    seq: u32,
    /// データ
    data: Vec<u8>,
}

/// 接続ごとのOOOキュー
struct ConnectionOooQueue {
    /// シーケンス番号順にソートされたセグメント
    segments: BTreeMap<u32, PacketRef>,
}

impl ConnectionOooQueue {
    fn new() -> Self {
        Self {
            segments: BTreeMap::new(),
        }
    }

    /// セグメントを挿入
    fn insert(&mut self, seq: u32, data: PacketRef) {
        if self.segments.len() >= MAX_OOO_SEGMENTS {
            // キュー満杯: 最も遠いセグメントを破棄
            if let Some((&last_key, _)) = self.segments.iter().next_back() {
                // 新しいセグメントが既存の最後より前であれば挿入、そうでなければ破棄
                if seq_before(seq, last_key) {
                    if self.segments.remove(&last_key).is_some() {
                        GLOBAL_OOO_COUNT.fetch_sub(1, Ordering::Relaxed);
                    }
                } else {
                    return; // 新しいセグメントが最も遠いので破棄
                }
            }
        }
        
        // グローバル制限チェック
        if GLOBAL_OOO_COUNT.load(Ordering::Relaxed) >= GLOBAL_MAX_OOO_SEGMENTS {
            // すでに上限に達している場合は新しいセグメントを破棄
            return;
        }

        if self.segments.insert(seq, data).is_none() {
            GLOBAL_OOO_COUNT.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// rcv_nxtより前のセグメントを削除、または部分的な重複をトリム
    fn prune_outdated(&mut self, rcv_nxt: u32) {
        let mut to_reinsert = Vec::new();
        let outdated_keys: Vec<u32> = self.segments.keys()
            .filter(|&&seq| seq_before(seq, rcv_nxt))
            .cloned()
            .collect();
            
        for key in outdated_keys {
            if let Some(mut packet) = self.segments.remove(&key) {
                let seg_end = key.wrapping_add(packet.len() as u32);
                if seq_before(rcv_nxt, seg_end) {
                    // 部分的な重複: すでに受信済みの部分を切り捨てて再挿入
                    let overlap = rcv_nxt.wrapping_sub(key) as usize;
                    packet.advance(overlap);
                    to_reinsert.push((rcv_nxt, packet));
                } else {
                    // 完全に受信済み
                    GLOBAL_OOO_COUNT.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
        
        for (seq, packet) in to_reinsert {
            self.segments.insert(seq, packet);
            // GLOBAL_OOO_COUNT は remove 時にも減らしていないため、再挿入時にも増やさない
        }
    }

    /// rcv_nxtから連続するデータをドレイン
    fn drain_contiguous_with<F>(&mut self, mut rcv_nxt: u32, mut f: F) -> u32
    where
        F: FnMut(u32, &[u8]),
    {
        // まず古いセグメントを掃除・トリム
        self.prune_outdated(rcv_nxt);

        loop {
            if let Some(packet) = self.segments.remove(&rcv_nxt) {
                GLOBAL_OOO_COUNT.fetch_sub(1, Ordering::Relaxed);
                let data = packet.data();
                let data_len = data.len() as u32;
                f(rcv_nxt, data);
                rcv_nxt = rcv_nxt.wrapping_add(data_len);
                
                // 次のセグメントとの重複をトリムするために再度 prune
                self.prune_outdated(rcv_nxt);
            } else {
                break;
            }
        }
        rcv_nxt
    }

    /// SACKブロックを生成（最大4ブロック、RFC 2018）
    fn sack_blocks(&self) -> SackBlocks {
        let mut sack = SackBlocks::new();
        let mut block_start: Option<u32> = None;
        let mut block_end = 0u32;

        for (&seq, packet) in &self.segments {
            let seg_end = seq.wrapping_add(packet.len() as u32);

            match block_start {
                None => {
                    block_start = Some(seq);
                    block_end = seg_end;
                }
                Some(start) => {
                    if !seq_before(block_end, seq) {
                        // 連続または重複 → ブロック拡張
                        if seq_before(block_end, seg_end) {
                            block_end = seg_end;
                        }
                    } else {
                        // 非連続 → 現在のブロックを確定
                        sack.push((start, block_end));
                        if sack.is_full() {
                            return sack;
                        }
                        block_start = Some(seq);
                        block_end = seg_end;
                    }
                }
            }
        }

        if let Some(start) = block_start {
            sack.push((start, block_end));
        }

        sack
    }

    fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    fn clear(&mut self) {
        let count = self.segments.len();
        self.segments.clear();
        GLOBAL_OOO_COUNT.fetch_sub(count, Ordering::Relaxed);
    }
}

/// 固定サイズのSACKブロック構造体
#[derive(Clone, Copy)]
pub struct SackBlocks {
    pub blocks: [(u32, u32); 4],
    pub count: usize,
}

impl SackBlocks {
    pub fn new() -> Self {
        Self {
            blocks: [(0, 0); 4],
            count: 0,
        }
    }

    pub fn push(&mut self, block: (u32, u32)) {
        if self.count < 4 {
            self.blocks[self.count] = block;
            self.count += 1;
        }
    }

    pub fn as_slice(&self) -> &[(u32, u32)] {
        &self.blocks[..self.count]
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn is_full(&self) -> bool {
        self.count == 4
    }
}

/// 接続キー
type ConnKey = (SocketAddr, SocketAddr);

/// シャード数
const OOO_SHARD_COUNT: usize = 16;
const OOO_SHARD_MASK: usize = OOO_SHARD_COUNT - 1;

/// シャードインデックスを算出
#[inline(always)]
fn ooo_shard_index(local: &SocketAddr, remote: &SocketAddr) -> usize {
    (conn_key_hash(local, remote) as usize) & OOO_SHARD_MASK
}

/// シャード化されたグローバルOOOキューマップ
static OOO_SHARDS: [PoisonLock<Option<BTreeMap<ConnKey, ConnectionOooQueue>>>; OOO_SHARD_COUNT] = {
    const EMPTY: PoisonLock<Option<BTreeMap<ConnKey, ConnectionOooQueue>>> =
        PoisonLock::new(None);
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
    local: SocketAddr,
    remote: SocketAddr,
    seq: u32,
    data: &[u8],
) {
    if data.is_empty() { return; }

    // まずグローバル上限チェック
    if GLOBAL_OOO_COUNT.load(Ordering::Relaxed) >= GLOBAL_MAX_OOO_SEGMENTS {
        return;
    }

    let mut packet = match alloc_packet() {
        Some(p) => p,
        None => return, // Mempool枯渇
    };

    let len = data.len().min(packet.data_mut().len());
    packet.data_mut()[..len].copy_from_slice(&data[..len]);
    packet.set_len(len);

    let idx = ooo_shard_index(&local, &remote);
    let Ok(mut guard) = OOO_SHARDS[idx].lock() else { return };
    let queues = guard.get_or_insert_with(BTreeMap::new);

    // 接続数制限チェック
    let per_shard_limit = MAX_OOO_CONNECTIONS / OOO_SHARD_COUNT;
    if !queues.contains_key(&(local, remote)) && queues.len() >= per_shard_limit.max(8) {
        return;
    }

    let conn_queue = queues
        .entry((local, remote))
        .or_insert_with(ConnectionOooQueue::new);

    conn_queue.insert(seq, packet);
}

/// OOOキューから連続データをクロージャにプッシュしてドレイン
pub fn drain_ooo_contiguous<F>(
    local: SocketAddr,
    remote: SocketAddr,
    mut rcv_nxt: u32,
    f: F,
) -> u32
where
    F: FnMut(u32, &[u8]),
{
    let idx = ooo_shard_index(&local, &remote);
    let Ok(mut guard) = OOO_SHARDS[idx].lock() else {
        return rcv_nxt;
    };
    let Some(queues) = guard.as_mut() else {
        return rcv_nxt;
    };

    if let Some(conn_queue) = queues.get_mut(&(local, remote)) {
        rcv_nxt = conn_queue.drain_contiguous_with(rcv_nxt, f);
        // 空になったキューを削除
        if conn_queue.is_empty() {
            queues.remove(&(local, remote));
        }
        rcv_nxt
    } else {
        rcv_nxt
    }
}

/// SACKブロックを取得
pub fn get_sack_blocks(
    local: SocketAddr,
    remote: SocketAddr,
) -> SackBlocks {
    let idx = ooo_shard_index(&local, &remote);
    let Ok(guard) = OOO_SHARDS[idx].lock() else {
        return SackBlocks::new();
    };
    let Some(queues) = guard.as_ref() else {
        return SackBlocks::new();
    };

    if let Some(conn_queue) = queues.get(&(local, remote)) {
        conn_queue.sack_blocks()
    } else {
        SackBlocks::new()
    }
}

/// 接続のOOOキューを削除
pub fn remove_ooo_queue(local: SocketAddr, remote: SocketAddr) {
    let idx = ooo_shard_index(&local, &remote);
    let Ok(mut guard) = OOO_SHARDS[idx].lock() else { return };
    if let Some(queues) = guard.as_mut() {
        if let Some(mut conn_queue) = queues.remove(&(local, remote)) {
            conn_queue.clear();
        }
    }
}
