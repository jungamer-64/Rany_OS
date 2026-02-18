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
#![allow(dead_code)]

use crate::sync::{IrqMutex, PoisonLock};
use alloc::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Per-CPU Caching Constants
// ============================================================================

/// Maximum CPUs supported
mod stats_and_compat;
pub use stats_and_compat::*;
mod heap_impl;
const MAX_CPUS: usize = crate::per_cpu::MAX_CPUS;

/// Per-CPU cache capacity (number of cached blocks per size class)
const PER_CPU_CACHE_CAPACITY: usize = 32;

/// Number of size classes to cache per-CPU (small allocations only)
/// Classes 0-5: 8B, 16B, 32B, 64B, 128B, 256B
const CACHED_SIZE_CLASSES: usize = 6;

// ============================================================================
// Per-CPU Exchange Cache
// ============================================================================

/// Per-CPU cached block entry
struct CachedBlock {
    addr: usize,
    size: usize,
}

/// Per-CPU cache for small allocations
#[repr(C, align(128))] // Cache line aligned to avoid false sharing
struct PerCpuExchangeCache {
    /// Cached blocks indexed by size class
    caches: [[Option<CachedBlock>; PER_CPU_CACHE_CAPACITY]; CACHED_SIZE_CLASSES],
    /// Number of cached blocks per class
    counts: [usize; CACHED_SIZE_CLASSES],
    /// Statistics: cache hits
    cache_hits: AtomicU64,
    /// Statistics: cache misses
    cache_misses: AtomicU64,
    /// Statistics: steal attempts
    steal_attempts: AtomicU64,
    /// Statistics: steal successes
    steal_successes: AtomicU64,
}

impl PerCpuExchangeCache {
    const fn new() -> Self {
        const EMPTY_BLOCK: Option<CachedBlock> = None;
        const EMPTY_CACHE: [Option<CachedBlock>; PER_CPU_CACHE_CAPACITY] = [EMPTY_BLOCK; PER_CPU_CACHE_CAPACITY];
        Self {
            caches: [EMPTY_CACHE; CACHED_SIZE_CLASSES],
            counts: [0; CACHED_SIZE_CLASSES],
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            steal_attempts: AtomicU64::new(0),
            steal_successes: AtomicU64::new(0),
        }
    }

    /// Try to allocate from cache
    #[inline]
    fn try_alloc(&mut self, size_class: usize) -> Option<(usize, usize)> {
        if size_class >= CACHED_SIZE_CLASSES {
            return None;
        }
        
        let count = self.counts[size_class];
        if count == 0 {
            self.cache_misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        
        let idx = count - 1;
        if let Some(block) = self.caches[size_class][idx].take() {
            self.counts[size_class] = idx;
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Some((block.addr, block.size));
        }
        
        None
    }

    /// Try to cache a freed block
    #[inline]
    fn try_cache(&mut self, addr: usize, size: usize, size_class: usize) -> bool {
        if size_class >= CACHED_SIZE_CLASSES {
            return false;
        }
        
        let count = self.counts[size_class];
        if count >= PER_CPU_CACHE_CAPACITY {
            return false;
        }
        
        self.caches[size_class][count] = Some(CachedBlock { addr, size });
        self.counts[size_class] = count + 1;
        true
    }
    
    /// Flush cache back to global heap
    fn flush_to_global(&mut self, heap: &mut SegregatedFreeListHeap) {
        for class in 0..CACHED_SIZE_CLASSES {
            for i in 0..self.counts[class] {
                if let Some(block) = self.caches[class][i].take() {
                    heap.add_free_block(block.addr, block.size);
                }
            }
            self.counts[class] = 0;
        }
    }
    
    /// Try to steal one block from this cache (called by victim)
    /// 
    /// Returns Some((addr, size)) if a block was available to steal.
    /// This is called by other CPUs when their local cache is empty.
    #[inline]
    fn try_steal_one(&mut self, size_class: usize) -> Option<(usize, usize)> {
        if size_class >= CACHED_SIZE_CLASSES {
            return None;
        }
        
        let count = self.counts[size_class];
        // Only steal if victim has more than half capacity (avoid thrashing)
        if count <= PER_CPU_CACHE_CAPACITY / 2 {
            return None;
        }
        
        let idx = count - 1;
        if let Some(block) = self.caches[size_class][idx].take() {
            self.counts[size_class] = idx;
            return Some((block.addr, block.size));
        }
        
        None
    }
}

/// Global per-CPU caches
static PER_CPU_CACHES: [IrqMutex<PerCpuExchangeCache>; MAX_CPUS] = {
    const INIT: IrqMutex<PerCpuExchangeCache> = IrqMutex::new(PerCpuExchangeCache::new());
    [INIT; MAX_CPUS]
};

// ============================================================================
// RRef Memory Pool - Zero-Copy IPC Optimization (v0.6.0)
// ============================================================================
//
// RRef (Remote Reference) プールは、IPC経由でドメイン間を移動する
// オブジェクトのための専用メモリプールを提供する。
//
// ## 目的
//
// - **プリアロケーション**: 頻繁に使用されるサイズのブロックを事前確保
// - **参照カウント**: 複数ドメインからの参照を安全にトラッキング
// - **スラブ分離**: IPC専用領域でキャッシュ効率を向上
//
// ## RedLeaf OS参考
//
// RRefは線形型の概念に基づき、所有権が一意であることを保証する。
// プールはこれらのRRefの効率的な割り当てと解放を担当する。
//
// ============================================================================

/// RRef Memory Pool設定
#[derive(Debug, Clone, Copy)]
pub struct RRefPoolConfig {
    /// プリアロケーションするブロック数
    pub prealloc_count: usize,
    /// ブロックサイズ（バイト）
    pub block_size: usize,
    /// 最大プールサイズ
    pub max_pool_size: usize,
    /// 動的拡張を許可するか
    pub allow_growth: bool,
}

impl RRefPoolConfig {
    /// デフォルト設定（小さいIPC向け）
    pub const fn small_ipc() -> Self {
        Self {
            prealloc_count: 64,
            block_size: 64,
            max_pool_size: 256,
            allow_growth: true,
        }
    }
    
    /// 中サイズIPC向け
    pub const fn medium_ipc() -> Self {
        Self {
            prealloc_count: 32,
            block_size: 256,
            max_pool_size: 128,
            allow_growth: true,
        }
    }
    
    /// 大きいIPC向け（バッファ転送等）
    pub const fn large_ipc() -> Self {
        Self {
            prealloc_count: 8,
            block_size: 4096,
            max_pool_size: 32,
            allow_growth: false,
        }
    }
}

impl Default for RRefPoolConfig {
    fn default() -> Self {
        Self::small_ipc()
    }
}

/// RRefブロック状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RRefBlockState {
    /// 空き（プール内）
    Free = 0,
    /// 割り当て済み（ドメインが所有）
    Allocated = 1,
    /// 転送中（IPC経由で移動中）
    InTransfer = 2,
}

/// RRefブロックヘッダ
/// 
/// 各ブロックの先頭に配置され、参照カウントと状態を管理。
#[repr(C, align(8))]
pub struct RRefBlockHeader {
    /// 参照カウント（通常は1、shared時は>1）
    pub ref_count: core::sync::atomic::AtomicU32,
    /// 現在の状態
    pub state: core::sync::atomic::AtomicU8,
    /// 所有ドメインID
    pub owner_domain: u16,
    /// パディング
    _pad: u8,
    /// データサイズ（ヘッダを除く）
    pub data_size: u32,
    /// 次の空きブロックへのポインタ（Free時のみ有効）
    pub next_free: usize,
}

impl RRefBlockHeader {
    /// 新しいヘッダを作成
    pub const fn new(data_size: u32) -> Self {
        Self {
            ref_count: core::sync::atomic::AtomicU32::new(1),
            state: core::sync::atomic::AtomicU8::new(RRefBlockState::Allocated as u8),
            owner_domain: 0,
            _pad: 0,
            data_size,
            next_free: 0,
        }
    }
    
    /// 参照カウントをインクリメント
    #[inline]
    pub fn inc_ref(&self) -> u32 {
        self.ref_count.fetch_add(1, core::sync::atomic::Ordering::AcqRel)
    }
    
    /// 参照カウントをデクリメント、0になったらtrueを返す
    #[inline]
    pub fn dec_ref(&self) -> bool {
        self.ref_count.fetch_sub(1, core::sync::atomic::Ordering::AcqRel) == 1
    }
    
    /// 転送開始
    #[inline]
    pub fn start_transfer(&self) {
        self.state.store(RRefBlockState::InTransfer as u8, core::sync::atomic::Ordering::Release);
    }
    
    /// 転送完了
    #[inline]
    pub fn complete_transfer(&self, _new_domain: u16) {
        // Note: owner_domainはAtomic操作ではないので、転送中に呼び出し側が適切に同期すること
        self.state.store(RRefBlockState::Allocated as u8, core::sync::atomic::Ordering::Release);
    }
}

/// RRef Memory Pool統計
#[derive(Debug, Clone, Copy)]
pub struct RRefPoolStats {
    /// 総ブロック数
    pub total_blocks: usize,
    /// 空きブロック数
    pub free_blocks: usize,
    /// 割り当て数
    pub allocations: u64,
    /// 解放数
    pub deallocations: u64,
    /// IPC転送数
    pub transfers: u64,
}

/// RRef Memory Pool
/// 
/// 固定サイズブロックのプールを管理。
/// スレッドセーフなフリーリストを使用。
pub struct RRefPool {
    /// 設定
    config: RRefPoolConfig,
    /// フリーリストの先頭
    free_head: core::sync::atomic::AtomicUsize,
    /// 空きブロック数
    free_count: core::sync::atomic::AtomicUsize,
    /// 総ブロック数
    total_count: core::sync::atomic::AtomicUsize,
    /// 統計: 割り当て数
    alloc_count: core::sync::atomic::AtomicU64,
    /// 統計: 解放数
    dealloc_count: core::sync::atomic::AtomicU64,
    /// 統計: 転送数
    transfer_count: core::sync::atomic::AtomicU64,
}

impl RRefPool {
    /// 新しいプールを作成
    pub const fn new(config: RRefPoolConfig) -> Self {
        Self {
            config,
            free_head: core::sync::atomic::AtomicUsize::new(0),
            free_count: core::sync::atomic::AtomicUsize::new(0),
            total_count: core::sync::atomic::AtomicUsize::new(0),
            alloc_count: core::sync::atomic::AtomicU64::new(0),
            dealloc_count: core::sync::atomic::AtomicU64::new(0),
            transfer_count: core::sync::atomic::AtomicU64::new(0),
        }
    }
    
    /// ブロックを割り当て
    /// 
    /// フリーリストから取得、なければNoneを返す
    pub fn allocate(&self) -> Option<*mut RRefBlockHeader> {
        loop {
            let head = self.free_head.load(core::sync::atomic::Ordering::Acquire);
            if head == 0 {
                return None;
            }
            
            let header = head as *mut RRefBlockHeader;
            let next = unsafe { (*header).next_free };
            
            if self.free_head.compare_exchange(
                head,
                next,
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Relaxed,
            ).is_ok() {
                unsafe {
                    (*header).state.store(RRefBlockState::Allocated as u8, core::sync::atomic::Ordering::Release);
                    (*header).ref_count.store(1, core::sync::atomic::Ordering::Release);
                    (*header).next_free = 0;
                }
                self.free_count.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
                self.alloc_count.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                return Some(header);
            }
        }
    }
    
    /// ブロックを解放
    /// 
    /// # Safety
    /// 
    /// - headerが有効なRRefBlockHeaderを指していること
    /// - 参照カウントが0であること
    pub unsafe fn deallocate(&self, header: *mut RRefBlockHeader) {
        if header.is_null() {
            return;
        }
        
        (*header).state.store(RRefBlockState::Free as u8, core::sync::atomic::Ordering::Release);
        
        loop {
            let head = self.free_head.load(core::sync::atomic::Ordering::Acquire);
            (*header).next_free = head;
            
            if self.free_head.compare_exchange(
                head,
                header as usize,
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Relaxed,
            ).is_ok() {
                break;
            }
        }
        
        self.free_count.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        self.dealloc_count.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    
    /// 転送を記録
    pub fn record_transfer(&self) {
        self.transfer_count.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    
    /// 統計を取得
    pub fn stats(&self) -> RRefPoolStats {
        RRefPoolStats {
            total_blocks: self.total_count.load(core::sync::atomic::Ordering::Relaxed),
            free_blocks: self.free_count.load(core::sync::atomic::Ordering::Relaxed),
            allocations: self.alloc_count.load(core::sync::atomic::Ordering::Relaxed),
            deallocations: self.dealloc_count.load(core::sync::atomic::Ordering::Relaxed),
            transfers: self.transfer_count.load(core::sync::atomic::Ordering::Relaxed),
        }
    }
}

/// グローバルRRefプール（小サイズIPC用）
pub static RREF_POOL_SMALL: RRefPool = RRefPool::new(RRefPoolConfig::small_ipc());

/// グローバルRRefプール（中サイズIPC用）
pub static RREF_POOL_MEDIUM: RRefPool = RRefPool::new(RRefPoolConfig::medium_ipc());

/// グローバルRRefプール（大サイズIPC用）
pub static RREF_POOL_LARGE: RRefPool = RRefPool::new(RRefPoolConfig::large_ipc());

// ============================================================================
// Segregated Free Lists アロケータ
// ============================================================================

/// サイズクラスの数 (8B, 16B, 32B, ... 最大 2^31 B)
/// インデックス i のリストは 2^(i+3) バイトのブロックを管理
const SIZE_CLASS_COUNT: usize = 29;

/// 最小ブロックサイズ (8 bytes = 2^3)
const MIN_BLOCK_SIZE: usize = 8;

/// 最小ブロックサイズのlog2
const MIN_BLOCK_SIZE_LOG2: usize = 3;

/// 空きブロックヘッダ
#[repr(C)]
struct FreeBlock {
    /// ブロックサイズ（ヘッダを含む）
    size: usize,
    /// 同一サイズクラス内の次の空きブロック
    next: Option<NonNull<FreeBlock>>,
}

/// ブロックフッター（Boundary Tag）
/// 隣接ブロックの結合を可能にするため、各ブロックの末尾にサイズを記録
#[repr(C)]
struct BlockFooter {
    /// ブロックサイズ（ヘッダと同じ値）
    size: usize,
    /// このブロックが空いているかどうか
    is_free: bool,
}

/// 最小ブロックサイズ (ヘッダ + フッター + 最小データ)
const MIN_BLOCK_WITH_FOOTER: usize = core::mem::size_of::<FreeBlock>() + core::mem::size_of::<BlockFooter>();

/// Segregated Free Lists アロケータ
///
/// TLSFアロケータに類似したアプローチで、サイズクラスごとに
/// 別々のフリーリストを管理する。
///
/// ## サイズクラス
/// - クラス 0: 8-15 bytes
/// - クラス 1: 16-31 bytes
/// - クラス 2: 32-63 bytes
/// - ...
/// - クラス n: 2^(n+3) - 2^(n+4)-1 bytes
///
/// ## 割り当て計算量
/// - O(1): ビット探索命令でサイズクラスを特定
/// - ベストケース: 対応クラスに空きがあれば即座に返却
/// - ワーストケース: より大きいクラスから分割（小さい定数）
#[derive(Debug)]
pub(crate) struct SegregatedFreeListHeap {
    /// ヒープ開始アドレス
    heap_start: usize,
    /// ヒープ終了アドレス
    heap_end: usize,
    /// サイズクラスごとのフリーリスト
    free_lists: [Option<NonNull<FreeBlock>>; SIZE_CLASS_COUNT],
    /// 空きブロックが存在するサイズクラスのビットマップ
    /// bit i が 1 なら free_lists[i] に空きブロックがある
    free_bitmap: u32,
    /// 使用中のバイト数
    allocated_bytes: usize,
    /// 統計: 割り当て回数
    alloc_count: u64,
    /// 統計: 解放回数
    dealloc_count: u64,
    /// 統計: ブロック分割回数
    split_count: u64,
    /// 統計: ブロック結合回数
    coalesce_count: u64,
}
