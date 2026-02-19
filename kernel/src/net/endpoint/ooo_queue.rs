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

#![allow(dead_code)]

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use crate::sync::PoisonLock;
use super::types::SocketAddr;

/// OOOセグメントの最大保持数（接続あたり）
const MAX_OOO_SEGMENTS: usize = 32;

/// OOOキューの最大接続数
const MAX_OOO_CONNECTIONS: usize = 256;

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
    segments: BTreeMap<u32, Vec<u8>>,
}

impl ConnectionOooQueue {
    fn new() -> Self {
        Self {
            segments: BTreeMap::new(),
        }
    }

    /// セグメントを挿入
    fn insert(&mut self, seq: u32, data: &[u8]) {
        if self.segments.len() >= MAX_OOO_SEGMENTS {
            // キュー満杯: 最も遠いセグメントを破棄
            if let Some((&last_key, _)) = self.segments.iter().next_back() {
                // 新しいセグメントが既存の最後より前であれば挿入、そうでなければ破棄
                if seq_before(seq, last_key) {
                    self.segments.remove(&last_key);
                } else {
                    return; // 新しいセグメントが最も遠いので破棄
                }
            }
        }
        self.segments.insert(seq, data.to_vec());
    }

    /// rcv_nxtから連続するデータをドレイン
    ///
    /// 返却: (ドレインされたデータ列, 新しいrcv_nxt)
    fn drain_contiguous(&mut self, mut rcv_nxt: u32) -> (Vec<(u32, Vec<u8>)>, u32) {
        let mut drained = Vec::new();

        loop {
            if let Some(data) = self.segments.remove(&rcv_nxt) {
                let data_len = data.len() as u32;
                drained.push((rcv_nxt, data));
                rcv_nxt = rcv_nxt.wrapping_add(data_len);
            } else {
                break;
            }
        }

        (drained, rcv_nxt)
    }

    /// SACKブロックを生成（最大4ブロック、RFC 2018）
    fn sack_blocks(&self) -> Vec<(u32, u32)> {
        let mut blocks = Vec::new();
        let iter = self.segments.iter();

        let mut block_start = None;
        let mut block_end = 0u32;

        for (&seq, data) in &self.segments {
            let seg_end = seq.wrapping_add(data.len() as u32);

            match block_start {
                None => {
                    block_start = Some(seq);
                    block_end = seg_end;
                }
                Some(start) => {
                    if seq == block_end {
                        // 連続 → ブロック拡張
                        block_end = seg_end;
                    } else {
                        // 非連続 → 現在のブロックを確定
                        blocks.push((start, block_end));
                        if blocks.len() >= 4 {
                            return blocks;
                        }
                        block_start = Some(seq);
                        block_end = seg_end;
                    }
                }
            }
        }

        if let Some(start) = block_start {
            blocks.push((start, block_end));
        }

        blocks
    }

    fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    fn len(&self) -> usize {
        self.segments.len()
    }
}

/// シーケンス番号の前後比較（ラップアラウンド対応）
fn seq_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// 接続キー
type ConnKey = (SocketAddr, SocketAddr);

/// グローバルOOOキューマップ
static OOO_QUEUES: PoisonLock<Option<BTreeMap<ConnKey, ConnectionOooQueue>>> =
    PoisonLock::new(None);

/// OOOキューを初期化（ネットワークスタック初期化時に呼ぶ）
pub fn init_ooo_queues() {
    match OOO_QUEUES.lock() {
        Ok(mut g) => {
            *g = Some(BTreeMap::new());
        }
        Err(_) => {}
    }
}

/// OOOセグメントを挿入
///
/// 順序外で到着したセグメントを保存する。
pub fn insert_ooo_segment(
    local: SocketAddr,
    remote: SocketAddr,
    seq: u32,
    data: &[u8],
) {
    let Ok(mut guard) = OOO_QUEUES.lock() else { return };
    let queues = guard.get_or_insert_with(BTreeMap::new);

    // 接続数制限チェック
    if !queues.contains_key(&(local, remote)) && queues.len() >= MAX_OOO_CONNECTIONS {
        return;
    }

    let conn_queue = queues
        .entry((local, remote))
        .or_insert_with(ConnectionOooQueue::new);

    conn_queue.insert(seq, data);
}

/// OOOキューから連続データをドレイン
///
/// rcv_nxtが進んだ後に呼び出して、連続するセグメントを回収する。
/// 返却: (各セグメントの(seq, data), 更新後のrcv_nxt)
pub fn drain_ooo_contiguous(
    local: SocketAddr,
    remote: SocketAddr,
    rcv_nxt: u32,
) -> (Vec<(u32, Vec<u8>)>, u32) {
    let Ok(mut guard) = OOO_QUEUES.lock() else {
        return (Vec::new(), rcv_nxt);
    };
    let Some(queues) = guard.as_mut() else {
        return (Vec::new(), rcv_nxt);
    };

    if let Some(conn_queue) = queues.get_mut(&(local, remote)) {
        let result = conn_queue.drain_contiguous(rcv_nxt);
        // 空になったキューを削除
        if conn_queue.is_empty() {
            queues.remove(&(local, remote));
        }
        result
    } else {
        (Vec::new(), rcv_nxt)
    }
}

/// SACKブロックを取得
pub fn get_sack_blocks(
    local: SocketAddr,
    remote: SocketAddr,
) -> Vec<(u32, u32)> {
    let Ok(guard) = OOO_QUEUES.lock() else {
        return Vec::new();
    };
    let Some(queues) = guard.as_ref() else {
        return Vec::new();
    };

    if let Some(conn_queue) = queues.get(&(local, remote)) {
        conn_queue.sack_blocks()
    } else {
        Vec::new()
    }
}

/// 接続のOOOキューを削除（接続クローズ時）
pub fn remove_ooo_queue(local: SocketAddr, remote: SocketAddr) {
    let Ok(mut guard) = OOO_QUEUES.lock() else { return };
    if let Some(queues) = guard.as_mut() {
        queues.remove(&(local, remote));
    }
}
