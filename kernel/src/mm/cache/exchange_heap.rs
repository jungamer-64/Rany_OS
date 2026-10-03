// ============================================================================
// src/mm/exchange_heap.rs - Exchange Heap for Zero-Copy IPC
// 設計書 5.3: 線形型と交換ヒープ（RedLeaf OS参照）
//
// v0.3.0: linked_list_allocator から内蔵Buddy Allocatorへ移行
// v0.4.0: Segregated Free Lists (区分フリーリスト) 導入
//         - O(n) First-Fit から O(1) サイズクラス探索へ
//         - IPCの頻繁な割り当て/解放のボトルネックを解消
// v0.5.0: Per-CPU Caching 導入
//         - ロック競合を削減
//         - IPCホットパスでのスケーラビリティ向上
// v0.6.0: Victim Cache (Work-Stealing) 導入
//         - Per-CPU cache miss時に隣接CPUからスティール
//         - グローバルロックへのフォールバック頻度削減
// ============================================================================
use crate::heap::{CacheClass, CachedAllocation, ExchangeBlocks};
use crate::sync::PoisonLock;
use alloc::alloc::{GlobalAlloc, Layout};
use alloc::sync::Arc;
use core::ptr::NonNull;

#[path = "exchange_heap/stats_and_compat.rs"]
mod stats_and_compat;
pub use stats_and_compat::*;
