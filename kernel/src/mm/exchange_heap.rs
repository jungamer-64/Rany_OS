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
const MAX_CPUS: usize = crate::mm::MAX_CPUS;

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
struct SegregatedFreeListHeap {
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

// SegregatedFreeListHeap は PoisonLock で保護されるため Send/Sync は安全
unsafe impl Send for SegregatedFreeListHeap {}
unsafe impl Sync for SegregatedFreeListHeap {}

impl SegregatedFreeListHeap {
    const fn empty() -> Self {
        Self {
            heap_start: 0,
            heap_end: 0,
            free_lists: [None; SIZE_CLASS_COUNT],
            free_bitmap: 0,
            allocated_bytes: 0,
            alloc_count: 0,
            dealloc_count: 0,
            split_count: 0,
            coalesce_count: 0,
        }
    }

    /// サイズからサイズクラスインデックスを計算（切り上げ）
    ///
    /// # Returns
    /// サイズを収容できる最小のクラスインデックス
    #[inline]
    fn size_to_class(size: usize) -> usize {
        if size <= MIN_BLOCK_SIZE {
            return 0;
        }
        // size > MIN_BLOCK_SIZE の場合
        // 必要なクラス = ceil(log2(size)) - MIN_BLOCK_SIZE_LOG2
        let bits_needed = usize::BITS - (size - 1).leading_zeros();
        let class = (bits_needed as usize).saturating_sub(MIN_BLOCK_SIZE_LOG2);
        class.min(SIZE_CLASS_COUNT - 1)
    }

    /// サイズクラスからブロックサイズを計算
    #[inline]
    fn class_to_size(class: usize) -> usize {
        MIN_BLOCK_SIZE << class
    }

    /// ヒープを初期化
    ///
    /// # Safety
    /// - `heap_start` は有効なメモリ領域を指す
    /// - `size` バイトがアクセス可能
    unsafe fn init(&mut self, heap_start: *mut u8, size: usize) {
        crate::io::log::early_print("[ExHeap] init heap_start=");
        crate::io::log::early_print_hex(heap_start as u64);
        crate::io::log::early_print(" size=");
        crate::io::log::early_print_hex(size as u64);
        crate::io::log::early_print("\n");

        self.heap_start = heap_start as usize;
        self.heap_end = self.heap_start + size;
        self.allocated_bytes = 0;
        self.free_bitmap = 0;
        self.alloc_count = 0;
        self.dealloc_count = 0;
        self.split_count = 0;
        self.coalesce_count = 0;

        // フリーリストをクリア
        for list in self.free_lists.iter_mut() {
            *list = None;
        }

        // 初期状態: 全体を最大サイズのブロックとして登録
        if size >= core::mem::size_of::<FreeBlock>() {
            self.add_free_block(heap_start as usize, size);
        }
    }

    /// 空きブロックを適切なサイズクラスに追加（結合を試みる）
    fn add_free_block(&mut self, addr: usize, size: usize) {
        let min_size = MIN_BLOCK_WITH_FOOTER;
        if size < min_size {
            return;
        }

        // Try to coalesce with previous block
        let (final_addr, final_size) = self.try_coalesce_prev(addr, size);
        
        // Try to coalesce with next block
        let (final_addr, final_size) = self.try_coalesce_next(final_addr, final_size);

        let class = Self::size_to_class(final_size);
        let block_ptr = final_addr as *mut FreeBlock;

        crate::io::log::early_print("[ExHeap] add_free_block final_addr=");
        crate::io::log::early_print_hex(final_addr as u64);
        crate::io::log::early_print(" final_size=");
        crate::io::log::early_print_hex(final_size as u64);
        crate::io::log::early_print(" class=");
        crate::io::log::early_print_dec(class as u64);
        crate::io::log::early_print("\n");

        unsafe {
            let old_head = self.free_lists[class].map_or(0usize, |nn| nn.as_ptr() as usize);
            crate::io::log::early_print("[ExHeap] add_free_block old_head=");
            crate::io::log::early_print_hex(old_head as u64);
            crate::io::log::early_print("\n");

            // Set header
            (*block_ptr).size = final_size;
            (*block_ptr).next = self.free_lists[class];

            // Dump next after set
            let next_val = match (*block_ptr).next { Some(nn) => nn.as_ptr() as usize, None => 0usize };
            crate::io::log::early_print("[ExHeap] add_free_block set_next=");
            crate::io::log::early_print_hex(next_val as u64);
            crate::io::log::early_print("\n");

            // Set footer (boundary tag)
            let footer_addr = final_addr + final_size - core::mem::size_of::<BlockFooter>();
            let footer_ptr = footer_addr as *mut BlockFooter;
            (*footer_ptr).size = final_size;
            (*footer_ptr).is_free = true;
        }

        self.free_lists[class] = NonNull::new(block_ptr);
        self.free_bitmap |= 1u32 << class;
    }
    
    /// Try to coalesce with the previous block (using its footer)
    fn try_coalesce_prev(&mut self, addr: usize, size: usize) -> (usize, usize) {
        if addr <= self.heap_start + core::mem::size_of::<BlockFooter>() {
            return (addr, size);
        }
        
        let prev_footer_addr = addr - core::mem::size_of::<BlockFooter>();
        if prev_footer_addr < self.heap_start {
            return (addr, size);
        }
        
        let prev_footer = unsafe { &*(prev_footer_addr as *const BlockFooter) };
        
        if !prev_footer.is_free {
            return (addr, size);
        }
        
        let prev_size = prev_footer.size;
        if prev_size == 0 || prev_size > addr - self.heap_start {
            return (addr, size);
        }
        
        let prev_addr = addr - prev_size;
        if prev_addr < self.heap_start {
            return (addr, size);
        }
        
        // Remove previous block from its free list
        if self.remove_from_free_list(prev_addr, prev_size) {
            self.coalesce_count += 1;
            return (prev_addr, prev_size + size);
        }
        
        (addr, size)
    }
    
    /// Try to coalesce with the next block
    fn try_coalesce_next(&mut self, addr: usize, size: usize) -> (usize, usize) {
        let next_addr = addr + size;
        if next_addr >= self.heap_end {
            return (addr, size);
        }
        
        let next_block = unsafe { &*(next_addr as *const FreeBlock) };
        let next_size = next_block.size;
        
        if next_size == 0 || next_addr + next_size > self.heap_end {
            return (addr, size);
        }
        
        // Check if next block is free by checking its footer
        let next_footer_addr = next_addr + next_size - core::mem::size_of::<BlockFooter>();
        if next_footer_addr >= self.heap_end {
            return (addr, size);
        }
        
        let next_footer = unsafe { &*(next_footer_addr as *const BlockFooter) };
        if !next_footer.is_free {
            return (addr, size);
        }
        
        // Remove next block from its free list
        if self.remove_from_free_list(next_addr, next_size) {
            self.coalesce_count += 1;
            return (addr, size + next_size);
        }
        
        (addr, size)
    }
    
    /// Remove a block from its free list
    fn remove_from_free_list(&mut self, addr: usize, size: usize) -> bool {
        let class = Self::size_to_class(size);
        let target_ptr = addr as *mut FreeBlock;
        
        let mut prev: Option<NonNull<FreeBlock>> = None;
        let mut current = self.free_lists[class];
        
        while let Some(block) = current {
            if block.as_ptr() == target_ptr {
                // Found the block, remove it
                let next = unsafe { (*block.as_ptr()).next };
                
                match prev {
                    Some(p) => unsafe { (*p.as_ptr()).next = next },
                    None => self.free_lists[class] = next,
                }
                
                if self.free_lists[class].is_none() {
                    self.free_bitmap &= !(1u32 << class);
                }
                
                return true;
            }
            
            prev = current;
            current = unsafe { (*block.as_ptr()).next };
        }
        
        false
    }

    /// 指定サイズクラスから空きブロックを取得
    fn pop_free_block(&mut self, class: usize) -> Option<NonNull<FreeBlock>> {
        let block = self.free_lists[class]?;

        unsafe {
            self.free_lists[class] = (*block.as_ptr()).next;
        }

        // リストが空になったらビットマップをクリア
        if self.free_lists[class].is_none() {
            self.free_bitmap &= !(1u32 << class);
        }

        Some(block)
    }

    /// メモリを割り当て（O(1) Segregated Fit）
    fn allocate(&mut self, layout: Layout) -> Result<NonNull<u8>, ()> {
        let align = layout.align().max(core::mem::align_of::<FreeBlock>());
        let size = layout.size().max(core::mem::size_of::<FreeBlock>());

        // 要求サイズに対応するクラスを計算
        let required_class = Self::size_to_class(size);

        // このクラス以上で空きがあるクラスをビットマップで O(1) 探索
        let available_mask = self.free_bitmap & !((1u32 << required_class) - 1);
        if available_mask == 0 {
            return Err(());
        }

        // 最小の空きクラスを取得 (trailing_zeros = tzcnt/bsf 命令)
        let found_class = available_mask.trailing_zeros() as usize;

        // そのクラスからブロックを取得
        let block = self.pop_free_block(found_class).ok_or(())?;
        let block_ptr = block.as_ptr();
        let block_size = unsafe { (*block_ptr).size };
        let block_addr = block_ptr as usize;

        // アライメント調整
        let aligned_addr = (block_addr + align - 1) & !(align - 1);
        let padding = aligned_addr - block_addr;

        // 必要な総サイズ
        let total_needed = padding + size;

        if block_size < total_needed {
            // サイズ不足（通常起こらないが安全のため）
            self.add_free_block(block_addr, block_size);
            return Err(());
        }

        let remaining = block_size - total_needed;

        // 残りが十分大きければ分割して別クラスに戻す
        let min_split_size = core::mem::size_of::<FreeBlock>();
        if remaining >= min_split_size {
            let new_block_addr = aligned_addr + size;
            self.add_free_block(new_block_addr, remaining);
            self.split_count += 1;
        }

        self.allocated_bytes += total_needed;
        self.alloc_count += 1;
        
        // Mark block as allocated in footer
        let footer_addr = aligned_addr + size - core::mem::size_of::<BlockFooter>();
        if footer_addr >= aligned_addr && footer_addr + core::mem::size_of::<BlockFooter>() <= self.heap_end {
            unsafe {
                let footer_ptr = footer_addr as *mut BlockFooter;
                (*footer_ptr).size = size;
                (*footer_ptr).is_free = false;
            }
        }

        Ok(NonNull::new(aligned_addr as *mut u8).expect("aligned addr null"))
    }

    /// メモリを解放
    ///
    /// # Safety
    /// - `ptr` は以前に `allocate` で取得したポインタ
    unsafe fn deallocate(&mut self, ptr: NonNull<u8>, layout: Layout) {
        let size = layout.size().max(core::mem::size_of::<FreeBlock>());
        let addr = ptr.as_ptr() as usize;

        // 境界チェック
        if addr < self.heap_start || addr >= self.heap_end {
            return;
        }

        self.allocated_bytes = self.allocated_bytes.saturating_sub(size);
        self.dealloc_count += 1;

        // 空きブロックとして追加（隣接結合は将来の最適化として保留）
        // Note: 完全な隣接結合にはブロック境界情報の追跡が必要
        // 現時点ではシンプルにサイズクラスに追加
        // self.try_coalesce(addr, size); // TODO: Implement coalescing
        self.add_free_block(addr, size);
    }

    /// Try to coalesce adjacent free blocks
    ///
    /// Now implemented via boundary tags in add_free_block

    fn used(&self) -> usize {
        self.allocated_bytes
    }

    fn free(&self) -> usize {
        (self.heap_end - self.heap_start).saturating_sub(self.allocated_bytes)
    }

    /// 拡張統計情報を取得
    fn extended_stats(&self) -> ExtendedHeapStats {
        let mut non_empty_classes = 0u32;
        for i in 0..SIZE_CLASS_COUNT {
            if self.free_lists[i].is_some() {
                non_empty_classes |= 1u32 << i;
            }
        }

        ExtendedHeapStats {
            allocated: self.allocated_bytes,
            free: self.free(),
            alloc_count: self.alloc_count,
            dealloc_count: self.dealloc_count,
            split_count: self.split_count,
            coalesce_count: self.coalesce_count,
            non_empty_classes,
        }
    }
}

// ============================================================================
// 後方互換性のための型エイリアス（内部実装が変わっても外部APIは同じ）
// ============================================================================
type SimpleFreeListHeap = SegregatedFreeListHeap;

/// 拡張ヒープ統計情報
#[derive(Debug, Clone, Copy)]
pub struct ExtendedHeapStats {
    pub allocated: usize,
    pub free: usize,
    pub alloc_count: u64,
    pub dealloc_count: u64,
    pub split_count: u64,
    pub coalesce_count: u64,
    /// 空きブロックが存在するサイズクラス（ビットマップ）
    pub non_empty_classes: u32,
}

// ============================================================================
// 旧API互換のSimpleFreeListHeap実装（削除済み、上記で置換）
// ============================================================================

impl SegregatedFreeListHeap {
    /// 旧API互換: allocate_first_fit
    fn allocate_first_fit(&mut self, layout: Layout) -> Result<NonNull<u8>, ()> {
        self.allocate(layout)
    }
}

/// Exchange Heap: ドメイン間でゼロコピー通信するためのヒープ
/// プライベートヒープとは別に管理される
pub struct ExchangeHeap {
    heap: PoisonLock<SimpleFreeListHeap>,
}

impl ExchangeHeap {
    /// 新しいExchange Heapを作成（未初期化）
    pub const fn new() -> Self {
        Self {
            heap: PoisonLock::new(SimpleFreeListHeap::empty()),
        }
    }

    /// Exchange Heapを指定アドレスとサイズで初期化
    ///
    /// # Safety
    /// - `heap_start` は有効なメモリ領域を指している必要がある
    /// - `size` はそのメモリ領域のサイズと一致する必要がある
    /// - このメモリ領域は他のアロケータと重複してはならない
    pub unsafe fn init(&self, heap_start: usize, size: usize) {
        // SAFETY: 呼び出し元がメモリ領域の有効性を保証
        unsafe {
            // Initialization-time best-effort recovery: proceed with initialization even if the lock
        // appears poisoned to avoid blocking boot.
        let mut guard = self.heap.lock_for_init("[MEM] Exchange Heap init");
        guard.init(heap_start as *mut u8, size);
        }
    }

    /// Exchange Heap上にメモリを割り当て
pub fn allocate(&self, layout: Layout) -> Option<NonNull<u8>> {
    crate::io::log::early_print("[ExHeap] allocate: enter\n");
    let size = layout.size().max(core::mem::size_of::<FreeBlock>());
    let size_class = SegregatedFreeListHeap::size_to_class(size);
    
    // Fast path: try per-CPU cache first
    if size_class < CACHED_SIZE_CLASSES {
        if let Some(cpu_id) = crate::mm::per_cpu::try_current_cpu_id() {
            if cpu_id < MAX_CPUS {
                // crate::io::log::early_print("[ExHeap] allocate: try per-cpu\n");
                let mut cache = PER_CPU_CACHES[cpu_id].lock();
                if let Some((addr, _cached_size)) = cache.try_alloc(size_class) {
                     crate::io::log::early_print("[ExHeap] allocate: per-cpu success\n");
                    return NonNull::new(addr as *mut u8);
                }
                
                // Record steal attempt
                cache.steal_attempts.fetch_add(1, Ordering::Relaxed);
                drop(cache); // Release local lock before stealing
                
                // Medium path: try to steal from neighbor CPUs (Victim Cache)
                // Round-robin through other CPUs to find one with spare blocks
                for offset in 1..MAX_CPUS {
                    let victim_id = (cpu_id + offset) % MAX_CPUS;
                    if let Some(mut victim_cache) = PER_CPU_CACHES[victim_id].try_lock() {
                        if let Some((addr, _stolen_size)) = victim_cache.try_steal_one(size_class) {
                            // Record successful steal
                            let local = PER_CPU_CACHES[cpu_id].lock();
                            local.steal_successes.fetch_add(1, Ordering::Relaxed);
                             crate::io::log::early_print("[ExHeap] allocate: steal success\n");
                            return NonNull::new(addr as *mut u8);
                        }
                    }
                }
            }
        }
    }
    
    // Slow path: global heap
    crate::io::log::early_print("[ExHeap] allocate: global heap lock...\n");
    match self.heap.lock() {
        Ok(mut guard) => {
            crate::io::log::early_print("[ExHeap] allocate: global heap locked\n");
            let res = guard.allocate_first_fit(layout).ok();
            if res.is_some() {
                crate::io::log::early_print("[ExHeap] allocate: global success\n");
            } else {
                crate::io::log::early_print("[ExHeap] allocate: global failed\n");
            }
            res
        },
        Err(_) => {
            crate::io::log::early_print("[ExHeap] allocate: poisoned\n");
            log::error!("[MEM] Exchange Heap poisoned - allocation failed");
            None
        }
    }
}

    /// Exchange Heap上のメモリを解放
    ///
    /// # Safety
    /// - `ptr` は以前に `allocate` で取得したポインタである必要がある
    /// - `layout` は `allocate` 時と同じである必要がある
    pub unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        let size = layout.size().max(core::mem::size_of::<FreeBlock>());
        let size_class = SegregatedFreeListHeap::size_to_class(size);
        let addr = ptr.as_ptr() as usize;
        
        // Fast path: try per-CPU cache first
        if size_class < CACHED_SIZE_CLASSES {
            if let Some(cpu_id) = crate::mm::per_cpu::try_current_cpu_id() {
                if cpu_id < MAX_CPUS {
                    let mut cache = PER_CPU_CACHES[cpu_id].lock();
                    if cache.try_cache(addr, size, size_class) {
                        return;
                    }
                }
            }
        }
        
        // Slow path: global heap
        // SAFETY: 呼び出し元がポインタとレイアウトの有効性を保証
        match self.heap.lock() {
            Ok(mut guard) => unsafe { guard.deallocate(ptr, layout) },
            Err(_) => {
                log::error!("[MEM] Exchange Heap poisoned - deallocate ignored");
            }
        }
    }

    /// ヒープ使用統計を取得（デバッグ用）
    pub fn stats(&self) -> HeapStats {
        match self.heap.lock() {
            Ok(guard) => HeapStats {
                allocated: guard.used(),
                free: guard.free(),
            },
            Err(_) => {
                log::error!("[MEM] Exchange Heap poisoned - returning zero stats");
                HeapStats { allocated: 0, free: 0 }
            }
        }
    }

    /// 拡張統計情報を取得（デバッグ/性能分析用）
    pub fn extended_stats(&self) -> Option<ExtendedHeapStats> {
        match self.heap.lock() {
            Ok(guard) => Some(guard.extended_stats()),
            Err(_) => {
                log::error!("[MEM] Exchange Heap poisoned - returning None for extended stats");
                None
            }
        }
    }
}

unsafe impl GlobalAlloc for ExchangeHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.allocate(layout)
            .map(|p| p.as_ptr())
            .unwrap_or(core::ptr::null_mut())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let Some(non_null) = NonNull::new(ptr) {
            // SAFETY: GlobalAllocの契約でptrは以前にallocで取得したもの
            unsafe {
                self.deallocate(non_null, layout);
            }
        }
    }
}

/// ヒープ統計情報
#[derive(Debug, Clone, Copy)]
pub struct HeapStats {
    pub allocated: usize,
    pub free: usize,
}

/// Exchange Heap インスタンス（グローバルアロケータではない）
/// RRefで使用する専用のヒープ
static EXCHANGE_HEAP: ExchangeHeap = ExchangeHeap::new();

/// Exchange Heapが初期化済みかどうか
static INITIALIZED: spin::Once<()> = spin::Once::new();

/// Exchange Heapの初期化関数
///
/// # Safety
/// カーネル初期化時に一度だけ呼ばれる必要がある
pub unsafe fn init_exchange_heap(heap_start: usize, size: usize) {
    INITIALIZED.call_once(|| {
        // SAFETY: 呼び出し元がメモリ領域の有効性を保証
        unsafe {
            EXCHANGE_HEAP.init(heap_start, size);
        }
    });
}

/// Exchange Heap経由でメモリを割り当て（RRefで使用）
pub fn allocate_on_exchange<T>(value: T) -> Option<NonNull<T>> {
    let layout = Layout::new::<T>();
    EXCHANGE_HEAP.allocate(layout).map(|ptr| {
        let typed_ptr = ptr.as_ptr() as *mut T;
        unsafe {
            typed_ptr.write(value);
        }
        NonNull::new(typed_ptr).expect("typed_ptr null")
    })
}

/// Exchange Heap上のメモリを解放
///
/// # Safety
/// - `ptr` はExchange Heap上に割り当てられたメモリである必要がある
pub unsafe fn deallocate_on_exchange<T>(ptr: NonNull<T>) {
    let layout = Layout::new::<T>();
    // SAFETY: 呼び出し元がポインタの有効性を保証
    unsafe {
        ptr.as_ptr().drop_in_place();
        EXCHANGE_HEAP.deallocate(ptr.cast(), layout);
    }
}

/// 生のポインタとレイアウトを指定してExchange Heapから解放
///
/// # Safety
/// - `ptr` はExchange Heap上に割り当てられたメモリである必要がある
/// - `layout` は割り当て時と同じである必要がある
pub unsafe fn deallocate_raw(ptr: NonNull<u8>, layout: Layout) {
    // SAFETY: 呼び出し元がポインタとレイアウトの有効性を保証
    unsafe {
        EXCHANGE_HEAP.deallocate(ptr, layout);
    }
}

/// 生のレイアウトを指定してExchange Heapからメモリを割り当て
pub fn allocate_raw(layout: Layout) -> Option<NonNull<u8>> {
    EXCHANGE_HEAP.allocate(layout)
}

/// Exchange Heapの統計を取得
pub fn exchange_heap_stats() -> HeapStats {
    EXCHANGE_HEAP.stats()
}

// ============================================================================
// 安全なスライス割り当て API
// 未初期化メモリの問題を型レベルで防ぐ
// ============================================================================

use core::marker::PhantomData;
use core::mem::MaybeUninit;

/// Exchange Heap上にゼロ初期化されたスライスを割り当て
///
/// # Arguments
/// * `len` - スライスの要素数
///
/// # Returns
/// 初期化済みスライスへのポインタとレイアウト
///
/// # Safety Guarantee
/// 返されるメモリは必ずゼロ初期化されている
pub fn allocate_zeroed_slice<T: Sized>(len: usize) -> Option<(NonNull<T>, Layout)> {
    if len == 0 {
        return None;
    }

    let layout = Layout::array::<T>(len).ok()?;
    let ptr = EXCHANGE_HEAP.allocate(layout)?;

    // ゼロ初期化
    unsafe {
        core::ptr::write_bytes(ptr.as_ptr(), 0, layout.size());
    }

    Some((ptr.cast(), layout))
}

/// Exchange Heap上に未初期化スライスを割り当て
///
/// MaybeUninit<T> の配列として返すことで、
/// 未初期化メモリへのアクセスを型レベルで防ぐ
///
/// # Arguments
/// * `len` - スライスの要素数
///
/// # Returns
/// 未初期化スライスへのポインタとレイアウト
pub fn allocate_uninit_slice<T: Sized>(len: usize) -> Option<(NonNull<MaybeUninit<T>>, Layout)> {
    if len == 0 {
        return None;
    }

    let layout = Layout::array::<MaybeUninit<T>>(len).ok()?;
    let ptr = EXCHANGE_HEAP.allocate(layout)?;

    Some((ptr.cast(), layout))
}

/// 初期化関数を使ってスライスを割り当て・初期化
///
/// # Arguments
/// * `len` - スライスの要素数
/// * `init` - 各要素を初期化する関数 (インデックスを受け取る)
///
/// # Returns
/// 初期化済みスライスへのポインタとレイアウト
pub fn allocate_slice_with<T: Sized, F>(len: usize, mut init: F) -> Option<(NonNull<T>, Layout)>
where
    F: FnMut(usize) -> T,
{
    if len == 0 {
        return None;
    }

    let layout = Layout::array::<T>(len).ok()?;
    let ptr = EXCHANGE_HEAP.allocate(layout)?;
    let typed_ptr = ptr.as_ptr() as *mut T;

    // 各要素を初期化
    unsafe {
        for i in 0..len {
            typed_ptr.add(i).write(init(i));
        }
    }

    Some((NonNull::new(typed_ptr)?, layout))
}

/// デフォルト値でスライスを割り当て・初期化
///
/// # Arguments
/// * `len` - スライスの要素数
///
/// # Returns
/// 初期化済みスライスへのポインタとレイアウト
pub fn allocate_slice_default<T: Sized + Default>(len: usize) -> Option<(NonNull<T>, Layout)> {
    allocate_slice_with(len, |_| T::default())
}

/// スライスを解放
///
/// # Safety
/// - `ptr` は `allocate_*_slice` で取得したポインタである必要がある
/// - `layout` は割り当て時と同じである必要がある
/// - 解放後にポインタを使用してはならない
pub unsafe fn deallocate_slice<T>(ptr: NonNull<T>, len: usize) {
    if len == 0 {
        return;
    }

    // 各要素のデストラクタを呼ぶ
    unsafe {
        for i in 0..len {
            ptr.as_ptr().add(i).drop_in_place();
        }
    }

    // メモリを解放
    if let Ok(layout) = Layout::array::<T>(len) {
        // SAFETY: ptrは有効なExchange Heap上のメモリ
        unsafe {
            EXCHANGE_HEAP.deallocate(ptr.cast(), layout);
        }
    }
}

// ============================================================================
// 型安全なスライスラッパー（改善案5: Exchange Heap型安全性強化）
// ============================================================================

/// 初期化済みスライス
///
/// 型レベルで初期化状態を追跡し、未初期化メモリへの
/// 不正アクセスを防止する。
pub struct InitializedSlice<T: Sized> {
    ptr: NonNull<T>,
    len: usize,
    layout: Layout,
    _marker: PhantomData<T>,
}

impl<T: Sized> InitializedSlice<T> {
    /// スライスを作成（内部使用のみ）
    fn new(ptr: NonNull<T>, len: usize, layout: Layout) -> Self {
        Self {
            ptr,
            len,
            layout,
            _marker: PhantomData,
        }
    }

    /// ゼロ初期化されたスライスを作成
    pub fn zeroed(len: usize) -> Option<Self> {
        let (ptr, layout) = allocate_zeroed_slice::<T>(len)?;
        Some(Self::new(ptr, len, layout))
    }

    /// 初期化関数でスライスを作成
    pub fn with_init<F>(len: usize, init: F) -> Option<Self>
    where
        F: FnMut(usize) -> T,
    {
        let (ptr, layout) = allocate_slice_with(len, init)?;
        Some(Self::new(ptr, len, layout))
    }

    /// デフォルト値でスライスを作成
    pub fn with_default(len: usize) -> Option<Self>
    where
        T: Default,
    {
        let (ptr, layout) = allocate_slice_default(len)?;
        Some(Self::new(ptr, len, layout))
    }

    /// スライスへの参照を取得
    pub fn as_slice(&self) -> &[T] {
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// 可変スライスへの参照を取得
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    /// 長さを取得
    pub fn len(&self) -> usize {
        self.len
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// ポインタを取得（危険）
    pub fn as_ptr(&self) -> *const T {
        self.ptr.as_ptr()
    }

    /// 可変ポインタを取得（危険）
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.ptr.as_ptr()
    }
}

impl<T: Sized> Drop for InitializedSlice<T> {
    fn drop(&mut self) {
        if self.len > 0 {
            unsafe {
                // 各要素のデストラクタを呼ぶ
                for i in 0..self.len {
                    self.ptr.as_ptr().add(i).drop_in_place();
                }
                // メモリを解放
                EXCHANGE_HEAP.deallocate(self.ptr.cast(), self.layout);
            }
        }
    }
}

impl<T: Sized> core::ops::Deref for InitializedSlice<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<T: Sized> core::ops::DerefMut for InitializedSlice<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

// Send/Sync は T に依存
unsafe impl<T: Sized + Send> Send for InitializedSlice<T> {}
unsafe impl<T: Sized + Sync> Sync for InitializedSlice<T> {}

/// 未初期化スライス
///
/// MaybeUninitのラッパーとして、安全な初期化パターンを強制する。
/// 一度初期化したら InitializedSlice に変換する必要がある。
pub struct UninitializedSlice<T: Sized> {
    ptr: NonNull<MaybeUninit<T>>,
    len: usize,
    layout: Layout,
    /// 初期化済み要素数
    initialized_count: usize,
    _marker: PhantomData<T>,
}

impl<T: Sized> UninitializedSlice<T> {
    /// 未初期化スライスを作成
    pub fn new(len: usize) -> Option<Self> {
        let (ptr, layout) = allocate_uninit_slice::<T>(len)?;
        Some(Self {
            ptr,
            len,
            layout,
            initialized_count: 0,
            _marker: PhantomData,
        })
    }

    /// 長さを取得
    pub fn len(&self) -> usize {
        self.len
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 初期化済み要素数を取得
    pub fn initialized_count(&self) -> usize {
        self.initialized_count
    }

    /// 完全に初期化されているか
    pub fn is_fully_initialized(&self) -> bool {
        self.initialized_count == self.len
    }

    /// 要素を初期化（インデックス指定）
    ///
    /// # Safety
    /// 同じインデックスを2回初期化しないこと
    pub unsafe fn init_at(&mut self, index: usize, value: T) {
        debug_assert!(index < self.len);
        unsafe {
            self.ptr.as_ptr().add(index).write(MaybeUninit::new(value));
        }
        // 注: この実装では厳密な追跡は行わない
        // より正確な追跡が必要な場合はビットマップを使用
        self.initialized_count = self.initialized_count.max(index + 1);
    }

    /// 連続して要素を初期化
    pub fn init_next(&mut self, value: T) -> Result<(), ExchangeHeapError> {
        if self.initialized_count >= self.len {
            return Err(ExchangeHeapError::SliceFull);
        }

        unsafe {
            self.init_at(self.initialized_count, value);
        }
        self.initialized_count += 1;
        Ok(())
    }

    /// 初期化済みスライスに変換
    ///
    /// # Safety
    /// 全要素が初期化されている必要がある
    pub unsafe fn assume_init(self) -> InitializedSlice<T> {
        let slice = InitializedSlice::new(self.ptr.cast(), self.len, self.layout);

        // selfのDropを防ぐ
        core::mem::forget(self);

        slice
    }

    /// 安全に初期化済みスライスに変換（全要素初期化済みの場合のみ）
    pub fn try_into_initialized(self) -> Result<InitializedSlice<T>, Self> {
        if self.is_fully_initialized() {
            Ok(unsafe { self.assume_init() })
        } else {
            Err(self)
        }
    }

    /// イテレータを使って初期化
    pub fn init_from_iter<I>(mut self, iter: I) -> Result<InitializedSlice<T>, Self>
    where
        I: IntoIterator<Item = T>,
    {
        for (i, value) in iter.into_iter().enumerate() {
            if i >= self.len {
                break;
            }
            unsafe {
                self.init_at(i, value);
            }
        }

        self.try_into_initialized()
    }
}

impl<T: Sized> Drop for UninitializedSlice<T> {
    fn drop(&mut self) {
        // 初期化済み要素のデストラクタを呼ぶ
        unsafe {
            for i in 0..self.initialized_count {
                let ptr = self.ptr.as_ptr().add(i);
                core::ptr::drop_in_place((*ptr).as_mut_ptr());
            }
            // メモリを解放
            EXCHANGE_HEAP.deallocate(self.ptr.cast(), self.layout);
        }
    }
}

/// Exchange Heapエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeHeapError {
    /// メモリ不足
    OutOfMemory,
    /// スライスが満杯
    SliceFull,
    /// 不完全な初期化
    PartiallyInitialized,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exchange_heap_poisoned_allocation_fails() {
        use crate::sync::set_panicking;

        let heap = ExchangeHeap::new();
        unsafe { heap.init(0x1000, 4096) }

        // Poison the lock by simulating a panic while holding the guard
        set_panicking(true);
        {
            let _guard = heap.heap.lock().unwrap();
            // dropping _guard while panicking will mark the lock as poisoned
        }
        set_panicking(false);

        let layout = core::alloc::Layout::from_size_align(64, 8).unwrap();
        assert!(heap.allocate(layout).is_none());
    }

    #[test]
    fn test_exchange_heap() {
        // メモリ領域を確保（テスト用）
        const HEAP_SIZE: usize = 4096;
        static mut HEAP_MEM: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

        unsafe {
            // Use addr_of_mut! to avoid creating a shared reference to a mutable static
            EXCHANGE_HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE);
        }

        // アロケーション
        let layout = Layout::from_size_align(64, 8).unwrap();
        let ptr = EXCHANGE_HEAP.allocate(layout).expect("Allocation failed");

        // 統計確認
        let stats = EXCHANGE_HEAP.stats();
        assert!(stats.allocated > 0);

        // デアロケーション
        unsafe {
            EXCHANGE_HEAP.deallocate(ptr, layout);
        }
    }

    #[test]
    fn test_block_coalescing() {
        // Test that adjacent freed blocks are coalesced
        const HEAP_SIZE: usize = 8192;
        static mut HEAP_MEM2: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

        let heap = ExchangeHeap::new();
        unsafe {
            heap.init(core::ptr::addr_of_mut!(HEAP_MEM2) as usize, HEAP_SIZE);
        }

        // Allocate three blocks
        let layout = Layout::from_size_align(128, 8).unwrap();
        let ptr1 = heap.allocate(layout).expect("Allocation 1 failed");
        let ptr2 = heap.allocate(layout).expect("Allocation 2 failed");
        let ptr3 = heap.allocate(layout).expect("Allocation 3 failed");

        // Get initial stats
        let stats_before = heap.extended_stats().unwrap();
        let coalesce_before = stats_before.coalesce_count;

        // Free middle block first
        unsafe { heap.deallocate(ptr2, layout); }
        
        // Free first block - should coalesce with ptr2's freed block
        unsafe { heap.deallocate(ptr1, layout); }
        
        // Free third block - should coalesce with the combined block
        unsafe { heap.deallocate(ptr3, layout); }

        // Check that coalescing occurred
        let stats_after = heap.extended_stats().unwrap();
        assert!(
            stats_after.coalesce_count > coalesce_before,
            "Expected coalescing to occur: before={}, after={}",
            coalesce_before,
            stats_after.coalesce_count
        );
    }
}
