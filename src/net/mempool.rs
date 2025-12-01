// ============================================================================
// src/net/mempool.rs - Zero-Copy Network Buffer Pool
// 設計書 6.2: Mempool によるゼロコピーネットワークバッファ管理
// ============================================================================
#![allow(dead_code)]

use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use alloc::vec::Vec;
use spin::Mutex;
use x86_64::PhysAddr;

/// デフォルトのパケットバッファサイズ
const DEFAULT_BUFFER_SIZE: usize = 2048;

/// デフォルトのプール容量
const DEFAULT_POOL_CAPACITY: usize = 4096;

/// キャッシュラインサイズ
const CACHE_LINE_SIZE: usize = 64;

/// パケットバッファ
/// 設計書 6.2: NICのDMAエンジンは、事前に割り当てられた固定サイズのバッファプールに直接パケットを書き込む
#[repr(C, align(64))] // キャッシュラインにアライン
pub struct PacketBuffer {
    /// データ領域
    data: [u8; DEFAULT_BUFFER_SIZE],
    /// 使用中のデータ長
    len: AtomicUsize,
    /// 物理アドレス（DMA用）
    phys_addr: PhysAddr,
    /// 所属するプールへの参照（デバッグ用）
    pool_id: u32,
    /// バッファインデックス
    index: u32,
    /// 参照カウント
    ref_count: AtomicU64,
    /// パディング（キャッシュライン境界）
    _padding: [u8; 8],
}

impl PacketBuffer {
    /// データスライスを取得
    pub fn data(&self) -> &[u8] {
        let len = self.len.load(Ordering::Acquire);
        &self.data[..len]
    }
    
    /// 可変データスライスを取得
    pub fn data_mut(&mut self) -> &mut [u8] {
        let len = self.len.load(Ordering::Acquire);
        &mut self.data[..len]
    }
    
    /// 生データポインタを取得
    pub fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }
    
    /// 可変生データポインタを取得
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }
    
    /// 容量を取得
    pub fn capacity(&self) -> usize {
        DEFAULT_BUFFER_SIZE
    }
    
    /// データ長を取得
    pub fn len(&self) -> usize {
        self.len.load(Ordering::Acquire)
    }
    
    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    
    /// データ長を設定
    pub fn set_len(&self, len: usize) {
        self.len.store(len.min(DEFAULT_BUFFER_SIZE), Ordering::Release);
    }
    
    /// 物理アドレスを取得
    pub fn phys_addr(&self) -> PhysAddr {
        self.phys_addr
    }
    
    /// 参照カウントをインクリメント
    pub fn add_ref(&self) {
        self.ref_count.fetch_add(1, Ordering::Relaxed);
    }
    
    /// 参照カウントをデクリメント
    /// 0になったらtrueを返す
    pub fn release(&self) -> bool {
        self.ref_count.fetch_sub(1, Ordering::Release) == 1
    }
}

/// パケットバッファへの参照
/// 設計書 6.2: 所有権の連鎖
pub struct PacketRef {
    buffer: NonNull<PacketBuffer>,
    pool: &'static Mempool,
}

impl PacketRef {
    /// データスライスを取得
    pub fn data(&self) -> &[u8] {
        unsafe { self.buffer.as_ref().data() }
    }
    
    /// 可変データスライスを取得（排他的所有時のみ）
    pub fn data_mut(&mut self) -> &mut [u8] {
        unsafe { self.buffer.as_mut().data_mut() }
    }
    
    /// データ長を設定
    pub fn set_len(&self, len: usize) {
        unsafe { self.buffer.as_ref().set_len(len); }
    }
    
    /// 物理アドレスを取得
    pub fn phys_addr(&self) -> PhysAddr {
        unsafe { self.buffer.as_ref().phys_addr() }
    }
    
    /// クローン（参照カウントをインクリメント）
    pub fn clone_ref(&self) -> Self {
        unsafe {
            self.buffer.as_ref().add_ref();
        }
        Self {
            buffer: self.buffer,
            pool: self.pool,
        }
    }
}

impl Drop for PacketRef {
    fn drop(&mut self) {
        unsafe {
            if self.buffer.as_ref().release() {
                // 参照カウントが0になったらプールに返却
                self.pool.return_buffer(self.buffer);
            }
        }
    }
}

// PacketRefはSend可能（別のスレッド/コアに移動可能）
unsafe impl Send for PacketRef {}

/// メモリプール
/// 設計書 6.2: バッファ管理
pub struct Mempool {
    /// プールID
    id: u32,
    /// バッファストレージ
    buffers: Mutex<Vec<NonNull<PacketBuffer>>>,
    /// 空きバッファリスト
    free_list: Mutex<Vec<NonNull<PacketBuffer>>>,
    /// 統計: 割り当て回数
    alloc_count: AtomicU64,
    /// 統計: 返却回数
    free_count: AtomicU64,
    /// 統計: 割り当て失敗回数
    alloc_failed: AtomicU64,
}

// MempoolはSend + Sync可能（NonNullはスレッドセーフに管理される）
unsafe impl Send for Mempool {}
unsafe impl Sync for Mempool {}

impl Mempool {
    /// 新しいメモリプールを作成
    pub fn new(id: u32) -> Self {
        Self {
            id,
            buffers: Mutex::new(Vec::new()),
            free_list: Mutex::new(Vec::new()),
            alloc_count: AtomicU64::new(0),
            free_count: AtomicU64::new(0),
            alloc_failed: AtomicU64::new(0),
        }
    }
    
    /// プールを初期化（バッファを事前割り当て）
    pub fn init(&self, capacity: usize) -> Result<(), &'static str> {
        let mut buffers = self.buffers.lock();
        let mut free_list = self.free_list.lock();
        
        for i in 0..capacity {
            // バッファを割り当て
            let layout = alloc::alloc::Layout::new::<PacketBuffer>();
            let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
            
            if ptr.is_null() {
                return Err("Failed to allocate buffer");
            }
            
            let buffer = ptr as *mut PacketBuffer;
            
            // バッファを初期化
            unsafe {
                (*buffer).pool_id = self.id;
                (*buffer).index = i as u32;
                (*buffer).len = AtomicUsize::new(0);
                (*buffer).ref_count = AtomicU64::new(0);
                (*buffer).phys_addr = PhysAddr::new(ptr as u64); // TODO: 実際の物理アドレス変換
            }
            
            let non_null = unsafe { NonNull::new_unchecked(buffer) };
            buffers.push(non_null);
            free_list.push(non_null);
        }
        
        Ok(())
    }
    
    /// バッファを割り当て
    pub fn alloc(&'static self) -> Option<PacketRef> {
        let buffer = self.free_list.lock().pop()?;
        
        unsafe {
            // 初期化
            buffer.as_ref().len.store(0, Ordering::Release);
            buffer.as_ref().ref_count.store(1, Ordering::Release);
        }
        
        self.alloc_count.fetch_add(1, Ordering::Relaxed);
        
        Some(PacketRef {
            buffer,
            pool: self,
        })
    }
    
    /// バッファを返却
    fn return_buffer(&self, buffer: NonNull<PacketBuffer>) {
        self.free_list.lock().push(buffer);
        self.free_count.fetch_add(1, Ordering::Relaxed);
    }
    
    /// 統計を取得
    pub fn stats(&self) -> MempoolStats {
        let total = self.buffers.lock().len();
        let free = self.free_list.lock().len();
        
        MempoolStats {
            total_buffers: total,
            free_buffers: free,
            used_buffers: total - free,
            alloc_count: self.alloc_count.load(Ordering::Relaxed),
            free_count: self.free_count.load(Ordering::Relaxed),
            alloc_failed: self.alloc_failed.load(Ordering::Relaxed),
        }
    }
}

/// メモリプール統計
#[derive(Debug, Clone)]
pub struct MempoolStats {
    pub total_buffers: usize,
    pub free_buffers: usize,
    pub used_buffers: usize,
    pub alloc_count: u64,
    pub free_count: u64,
    pub alloc_failed: u64,
}

// ============================================================================
// Per-Core Mempool Cache
// ============================================================================

/// コアローカルなメモリプールキャッシュ
/// 設計書 4.3: コアごとの独立性
pub struct PerCoreMempoolCache {
    /// ローカルキャッシュ
    local_cache: Mutex<Vec<NonNull<PacketBuffer>>>,
    /// キャッシュ容量
    cache_capacity: usize,
    /// 親プール
    parent: &'static Mempool,
}

impl PerCoreMempoolCache {
    /// 新しいキャッシュを作成
    pub fn new(parent: &'static Mempool, capacity: usize) -> Self {
        Self {
            local_cache: Mutex::new(Vec::with_capacity(capacity)),
            cache_capacity: capacity,
            parent,
        }
    }
    
    /// バッファを割り当て（ローカルキャッシュから優先）
    pub fn alloc(&'static self) -> Option<PacketRef> {
        // まずローカルキャッシュから試みる
        if let Some(buffer) = self.local_cache.lock().pop() {
            unsafe {
                buffer.as_ref().len.store(0, Ordering::Release);
                buffer.as_ref().ref_count.store(1, Ordering::Release);
            }
            return Some(PacketRef {
                buffer,
                pool: self.parent,
            });
        }
        
        // キャッシュが空なら親プールから取得
        self.parent.alloc()
    }
    
    /// バッファを返却（ローカルキャッシュに優先）
    pub fn free(&self, buffer: NonNull<PacketBuffer>) {
        let mut cache = self.local_cache.lock();
        
        if cache.len() < self.cache_capacity {
            // ローカルキャッシュに空きがあれば追加
            cache.push(buffer);
        } else {
            // キャッシュが満杯なら親プールに返却
            drop(cache);
            self.parent.return_buffer(buffer);
        }
    }
}

// ============================================================================
// Global Mempool
// ============================================================================

/// グローバルネットワークメモリプール
static NET_MEMPOOL: spin::Once<Mempool> = spin::Once::new();

/// グローバルメモリプールを初期化
pub fn init_net_mempool(capacity: usize) -> Result<(), &'static str> {
    let pool = NET_MEMPOOL.call_once(|| Mempool::new(0));
    pool.init(capacity)
}

/// ネットワークメモリプールを取得
pub fn net_mempool() -> Option<&'static Mempool> {
    NET_MEMPOOL.get()
}

/// パケットバッファを割り当て
pub fn alloc_packet() -> Option<PacketRef> {
    NET_MEMPOOL.get()?.alloc()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mempool_stats() {
        let pool = Mempool::new(1);
        let stats = pool.stats();
        assert_eq!(stats.total_buffers, 0);
        assert_eq!(stats.free_buffers, 0);
    }
}
