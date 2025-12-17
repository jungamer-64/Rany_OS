// ============================================================================
// src/net/mempool.rs - Zero-Copy Network Buffer Pool
// 設計書 6.2: Mempool によるゼロコピーネットワークバッファ管理
// ============================================================================
#![allow(dead_code)]

use crate::domain_system::DomainId;
use crate::ipc::rref::RRef;
use crate::sync::PoisonLock;
use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
        self.len
            .store(len.min(DEFAULT_BUFFER_SIZE), Ordering::Release);
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
    offset: usize,
    len: usize,
}

impl PacketRef {
    /// Create new PacketRef (internal)
    fn new(buffer: NonNull<PacketBuffer>, pool: &'static Mempool) -> Self {
        let len = unsafe { buffer.as_ref().len() };
        Self {
            buffer,
            pool,
            offset: 0,
            len,
        }
    }

    /// データスライスを取得
    pub fn data(&self) -> &[u8] {
        unsafe {
            let slice = self.buffer.as_ref().data();
            if self.offset >= slice.len() {
                return &[];
            }
            let end = (self.offset + self.len).min(slice.len());
            &slice[self.offset..end]
        }
    }

    /// 可変データスライスを取得（排他的所有時のみ）
    pub fn data_mut(&mut self) -> &mut [u8] {
        unsafe {
            let slice = self.buffer.as_mut().data_mut();
            if self.offset >= slice.len() {
                return &mut [];
            }
            let end = (self.offset + self.len).min(slice.len());
            &mut slice[self.offset..end]
        }
    }

    /// データ長を設定
    pub fn set_len(&mut self, len: usize) {
        // Only updates the view length, not the underlying buffer content length unless we want to?
        // Actually, for RX, set_len usually sets the total valid data.
        // But here PacketRef is a view.
        // Let's assume set_len updates the view length.
        self.len = len;
    }

    /// データ長を取得
    pub fn len(&self) -> usize {
        self.len
    }

    /// 容量を取得
    pub fn capacity(&self) -> usize {
        DEFAULT_BUFFER_SIZE
    }

    /// 物理アドレスを取得
    pub fn phys_addr(&self) -> PhysAddr {
        unsafe { self.buffer.as_ref().phys_addr() + self.offset as u64 }
    }

    /// ヘッドルームを消費（オフセットを進める）
    pub fn advance(&mut self, size: usize) {
        self.offset += size;
        if self.len >= size {
            self.len -= size;
        } else {
            self.len = 0;
        }
    }

    /// クローン（参照カウントをインクリメント）
    pub fn clone_ref(&self) -> Self {
        unsafe {
            self.buffer.as_ref().add_ref();
        }
        Self {
            buffer: self.buffer,
            pool: self.pool,
            offset: self.offset,
            len: self.len,
        }
    }

    /// Convert to RRef for zero-copy IPC
    /// Consumes the PacketRef and returns an RRef owned by target_domain.
    /// Requires exclusive access (ref_count == 1).
    pub fn into_rref(self, target_domain: DomainId) -> Result<RRef<PacketBuffer>, Self> {
        // Enforce exclusive ownership
        unsafe {
            if self.buffer.as_ref().ref_count.load(Ordering::Acquire) != 1 {
                return Err(self);
            }

            // Transfer ownership from Kernel(0) to target_domain
            // Assume current owner is Kernel (0) because PacketRef implies pool ownership
            // and checking owner via SAS might be expensive.
            match crate::sas::transfer_ownership(
                self.buffer.as_ptr() as usize,
                DomainId::new(0),
                target_domain,
            ) {
                Ok(_) => {}
                Err(e) => {
                    log::error!("Failed to transfer packet ownership: {:?}", e);
                    return Err(self);
                }
            }
        }

        let ptr = self.buffer;

        // Forget self to prevent Drop (which would return to pool)
        core::mem::forget(self);

        unsafe { Ok(RRef::from_raw(ptr, target_domain)) }
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
    buffers: PoisonLock<Vec<NonNull<PacketBuffer>>>,
    /// 空きバッファリスト
    free_list: PoisonLock<Vec<NonNull<PacketBuffer>>>,
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
            buffers: PoisonLock::new(Vec::new()),
            free_list: PoisonLock::new(Vec::new()),
            alloc_count: AtomicU64::new(0),
            free_count: AtomicU64::new(0),
            alloc_failed: AtomicU64::new(0),
        }
    }

    /// プールを初期化（バッファを事前割り当て）
    pub fn init(&self, capacity: usize) -> Result<(), &'static str> {
        let mut buffers = match self.buffers.lock() {
            Ok(b) => b,
            Err(_) => {
                log::error!("[NET] Mempool buffers poisoned during init");
                return Err("Mempool buffers poisoned");
            }
        };

        let mut free_list = match self.free_list.lock() {
            Ok(f) => f,
            Err(_) => {
                log::error!("[NET] Mempool free_list poisoned during init");
                return Err("Mempool free_list poisoned");
            }
        };

        for i in 0..capacity {
            // バッファを割り当て (Exchange Heap for RRef compatibility)
            let layout = alloc::alloc::Layout::new::<PacketBuffer>();
            let nn = crate::mm::exchange_heap::allocate_raw(layout)
                .ok_or("Failed to allocate buffer")?;
            let non_null = nn.cast::<PacketBuffer>();

            // Heap Registryに登録（Kernel所有として）
            crate::sas::register_object(
                non_null.as_ptr() as usize,
                layout.size(),
                DomainId::new(0),
            );

            // バッファを初期化
            unsafe {
                let buffer_ptr = non_null.as_ptr();
                (*buffer_ptr).pool_id = self.id;
                (*buffer_ptr).index = i as u32;
                (*buffer_ptr).len = AtomicUsize::new(0);
                (*buffer_ptr).ref_count = AtomicU64::new(0);
                // 仮想アドレスから物理アドレスへ変換
                // カーネルヒープはリニアマッピングされているため、
                // PHYSICAL_MEMORY_OFFSETを引くことで物理アドレスを得る
                let virt_addr = buffer_ptr as u64;
                let phys = if virt_addr >= crate::mm::mapping::PHYSICAL_MEMORY_OFFSET {
                    virt_addr - crate::mm::mapping::PHYSICAL_MEMORY_OFFSET
                } else {
                    // PHYSICAL_MEMORY_OFFSET未満の場合はそのままとする
                    // （カーネルイメージ内のアドレスなど）
                    virt_addr
                };
                (*buffer_ptr).phys_addr = PhysAddr::new(phys);
            }

            buffers.push(non_null);
            free_list.push(non_null);
        }

        Ok(())
    }

    /// バッファを割り当て
    pub fn alloc(&'static self) -> Option<PacketRef> {
        let buffer = match self.free_list.lock() {
            Ok(mut free_list) => free_list.pop(),
            Err(_) => {
                log::error!("[NET] Mempool free_list poisoned - allocation failed");
                self.alloc_failed.fetch_add(1, Ordering::Relaxed);
                None
            }
        }?;

        unsafe {
            // 初期化
            buffer.as_ref().len.store(0, Ordering::Release);
            buffer.as_ref().ref_count.store(1, Ordering::Release);
        }

        self.alloc_count.fetch_add(1, Ordering::Relaxed);

        Some(PacketRef::new(buffer, self))
    }

    /// バッファを返却
    fn return_buffer(&self, buffer: NonNull<PacketBuffer>) {
        match self.free_list.lock() {
            Ok(mut free_list) => free_list.push(buffer),
            Err(_) => {
                log::error!("[NET] Mempool free_list poisoned - return ignored");
                return;
            }
        }
        self.free_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Return an RRef to the pool (recycling)
    /// Converts RRef back to a free buffer.
    pub fn return_rref(&self, rref: RRef<PacketBuffer>) {
        let (ptr, owner) = rref.into_raw();

        unsafe {
            // Transfer ownership back to Kernel(0)
            if let Err(e) =
                crate::sas::transfer_ownership(ptr.as_ptr() as usize, owner, DomainId::new(0))
            {
                log::error!("Failed to reclaim RRef ownership: {:?}", e);
                // Do not reuse potentially corrupted buffer
                return;
            }

            // Reset state
            ptr.as_ref().len.store(0, Ordering::Release);
            ptr.as_ref().ref_count.store(0, Ordering::Release);

            self.return_buffer(ptr);
        }
    }

    /// 統計を取得
    pub fn stats(&self) -> MempoolStats {
        let total = match self.buffers.lock() {
            Ok(b) => b.len(),
            Err(_) => {
                log::error!("[NET] Mempool buffers poisoned - returning zeros");
                0
            }
        };

        let free = match self.free_list.lock() {
            Ok(f) => f.len(),
            Err(_) => {
                log::error!("[NET] Mempool free_list poisoned - returning zeros");
                0
            }
        };

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
    local_cache: PoisonLock<Vec<NonNull<PacketBuffer>>>,
    /// キャッシュ容量
    cache_capacity: usize,
    /// 親プール
    parent: &'static Mempool,
}

impl PerCoreMempoolCache {
    /// 新しいキャッシュを作成
    pub fn new(parent: &'static Mempool, capacity: usize) -> Self {
        Self {
            local_cache: PoisonLock::new(Vec::with_capacity(capacity)),
            cache_capacity: capacity,
            parent,
        }
    }

    /// バッファを割り当て（ローカルキャッシュから優先）
    pub fn alloc(&'static self) -> Option<PacketRef> {
        // まずローカルキャッシュから試みる
        if let Ok(mut cache) = self.local_cache.lock() {
            if let Some(buffer) = cache.pop() {
                unsafe {
                    buffer.as_ref().len.store(0, Ordering::Release);
                    buffer.as_ref().ref_count.store(1, Ordering::Release);
                }
                return Some(PacketRef::new(buffer, self.parent));
            }
        } else {
            log::error!("[NET] LocalCache lock poisoned (alloc) - falling back to parent pool");
        }

        // キャッシュが空なら親プールから取得
        self.parent.alloc()
    }

    /// バッファを返却（ローカルキャッシュに優先）
    pub fn free(&self, buffer: NonNull<PacketBuffer>) {
        match self.local_cache.lock() {
            Ok(mut cache) => {
                if cache.len() < self.cache_capacity {
                    // ローカルキャッシュに空きがあれば追加
                    cache.push(buffer);
                    return;
                }
                // キャッシュが満杯なら親プールに返却
            }
            Err(_) => {
                log::error!("[NET] LocalCache lock poisoned (free) - returning to parent pool");
                self.parent.return_buffer(buffer);
                return;
            }
        }

        self.parent.return_buffer(buffer);
    }
}

// ============================================================================
// PacketPool - Simple packet buffer pool for transmit
// ============================================================================

/// Simple packet pool for transmit buffers
/// Used by the network stack for building outgoing packets
pub struct PacketPool {
    /// Pre-allocated buffers
    buffers: PoisonLock<Vec<Vec<u8>>>,
    /// Buffer size
    buffer_size: usize,
    /// Pool capacity
    capacity: usize,
}

impl PacketPool {
    /// Create a new packet pool
    pub fn new(capacity: usize, buffer_size: usize) -> Self {
        let mut buffers = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            buffers.push(alloc::vec![0u8; buffer_size]);
        }

        PacketPool {
            buffers: PoisonLock::new(buffers),
            buffer_size,
            capacity,
        }
    }

    /// Allocate a buffer from the pool
    pub fn alloc(&self) -> Option<Vec<u8>> {
        match self.buffers.lock() {
            Ok(mut buffers) => buffers.pop(),
            Err(_) => {
                log::error!("[NET] PacketPool buffers lock poisoned (alloc) - allocation failed");
                None
            }
        }
    }

    /// Return a buffer to the pool
    pub fn free(&self, mut buffer: Vec<u8>) {
        // Clear the buffer
        buffer.fill(0);
        match self.buffers.lock() {
            Ok(mut buffers) => {
                if buffers.len() < self.capacity {
                    buffers.push(buffer);
                }
            }
            Err(_) => log::error!("[NET] PacketPool buffers lock poisoned (free) - dropping buffer"),
        }
        // Otherwise drop the buffer
    }

    /// Get buffer size
    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    /// Get available buffer count
    pub fn available(&self) -> usize {
        match self.buffers.lock() {
            Ok(b) => b.len(),
            Err(_) => {
                log::error!("[NET] PacketPool buffers lock poisoned (available) - returning 0");
                0
            }
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
    use crate::sync::set_panicking;
    use core::sync::atomic::Ordering;

    #[test]
    fn test_mempool_poisoned_alloc_fails() {
        let pool = Mempool::new(1);
        pool.init(1).expect("init should succeed");

        // Poison the free_list by simulating a panic while holding the lock
        set_panicking(true);
        {
            let _guard = pool.free_list.lock().unwrap();
        }
        set_panicking(false);

        // Allocation should fail and increment alloc_failed
        assert!(pool.alloc().is_none());
        assert!(pool.alloc_failed.load(Ordering::Relaxed) > 0);
    }


    #[test]
    fn test_mempool_stats() {
        let pool = Mempool::new(1);
        let stats = pool.stats();
        assert_eq!(stats.total_buffers, 0);
        assert_eq!(stats.free_buffers, 0);
    }
}
