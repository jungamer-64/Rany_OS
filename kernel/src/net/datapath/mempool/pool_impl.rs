use super::*;


impl PacketPool {
    /// Create a new packet pool
    pub fn new(capacity: usize, buffer_size: usize) -> Self {
        // NOTE: the original implementation allocated `capacity` separate
        // vectors, which may end up scattered across the heap and defeat
        // cache locality.  A proper slab allocator (single large allocation
        // split into fixed-size chunks) would be ideal; this is left as a
        // TODO for a future refactor.  For now we at least reserve each
        // individual buffer ahead of time to avoid re‑allocations.
        let mut buffers = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            // start with zero-length vector but pre‑allocate capacity
            // clients will set `len` to the amount of data they write themselves.
            let buf = Vec::with_capacity(buffer_size);
            buffers.push(buf);
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
        // Security: Zero out the buffer content to prevent information leaks
        // between different connections or users of the pool.
        unsafe {
            let cap = buffer.capacity();
            let ptr = buffer.as_mut_ptr();
            core::ptr::write_bytes(ptr, 0, cap);
        }

        if buffer.capacity() != self.buffer_size {
            // drop whatever the caller gave us and create a fresh one
            buffer = Vec::with_capacity(self.buffer_size);
        } else {
            // simply reset length to zero; existing capacity stays intact
            buffer.clear();
        }

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

    /// Allocate multiple buffers at once (batch allocation)
    ///
    /// 一度のロック取得で最大 `count` 個のバッファを取得する。
    /// 返り値の Vec は実際に取得できた分のみ含む。
    pub fn alloc_batch(&self, count: usize) -> Vec<Vec<u8>> {
        match self.buffers.lock() {
            Ok(mut buffers) => {
                let to_take = count.min(buffers.len());
                let split_at = buffers.len() - to_take;
                buffers.split_off(split_at)
            }
            Err(_) => {
                log::error!("[NET] PacketPool buffers lock poisoned (alloc_batch)");
                Vec::new()
            }
        }
    }

    /// Return multiple buffers at once (batch free)
    ///
    /// 一度のロック取得で複数バッファを返却する。
    pub fn free_batch(&self, batch: Vec<Vec<u8>>) {
        match self.buffers.lock() {
            Ok(mut buffers) => {
                for mut buffer in batch {
                    // Security: Zero out buffer content
                    unsafe {
                        let cap = buffer.capacity();
                        let ptr = buffer.as_mut_ptr();
                        core::ptr::write_bytes(ptr, 0, cap);
                    }

                    if buffer.capacity() != self.buffer_size {
                        buffer = Vec::with_capacity(self.buffer_size);
                    } else {
                        buffer.clear();
                    }

                    if buffers.len() < self.capacity {
                        buffers.push(buffer);
                    }
                }
            }
            Err(_) => log::error!("[NET] PacketPool buffers lock poisoned (free_batch)"),
        }
    }
}

// ============================================================================
// Per-Core TX Buffer Cache
// ============================================================================

/// コアローカルな TX バッファキャッシュ
///
/// `PacketPool` の alloc/free 時のロック競合を排除するため、
/// 各 CPU コアに独立したキャッシュを持たせる。
/// ExoRust ガイドライン: Per-Core Cache を活用しロックフリー割り当てを実現
pub struct PerCoreTxCache {
    /// CPU ごとのバッファキャッシュ
    caches: Vec<spin::Mutex<Vec<Vec<u8>>>>,
    /// キャッシュあたりの最大バッファ数
    per_core_capacity: usize,
    /// 親プール
    parent: &'static PacketPool,
    /// バッチリフィル数
    refill_count: usize,
}

/// Per-Core TX キャッシュのデフォルトサイズ
const TX_PER_CORE_CACHE_SIZE: usize = 8;
/// Per-Core TX バッチリフィル数
const TX_BATCH_REFILL: usize = 4;

impl PerCoreTxCache {
    /// 新しい Per-Core TX キャッシュを作成
    pub fn new(parent: &'static PacketPool, cpu_count: usize) -> Self {
        let count = cpu_count.max(1);
        let mut caches = Vec::with_capacity(count);
        for _ in 0..count {
            caches.push(spin::Mutex::new(Vec::with_capacity(TX_PER_CORE_CACHE_SIZE)));
        }
        Self {
            caches,
            per_core_capacity: TX_PER_CORE_CACHE_SIZE,
            parent,
            refill_count: TX_BATCH_REFILL,
        }
    }

    /// バッファを割り当て（ローカルキャッシュ優先）
    pub fn alloc(&self) -> Option<Vec<u8>> {
        let cpu_id = crate::per_cpu::try_current_cpu_id().unwrap_or(0);
        let idx = cpu_id % self.caches.len();

        let mut cache = self.caches[idx].lock();
        if let Some(buf) = cache.pop() {
            return Some(buf);
        }

        // キャッシュ空 → 親プールからバッチリフィル
        let refilled = self.parent.alloc_batch(self.refill_count);
        let mut iter = refilled.into_iter();
        let first = iter.next();
        for buf in iter {
            if cache.len() < self.per_core_capacity {
                cache.push(buf);
            }
        }
        first
    }

    /// バッファを返却（ローカルキャッシュ優先）
    pub fn free(&self, mut buffer: Vec<u8>) {
        // Security: Zero out buffer content
        unsafe {
            let cap = buffer.capacity();
            let ptr = buffer.as_mut_ptr();
            core::ptr::write_bytes(ptr, 0, cap);
        }
        buffer.clear();

        let cpu_id = crate::per_cpu::try_current_cpu_id().unwrap_or(0);
        let idx = cpu_id % self.caches.len();

        let mut cache = self.caches[idx].lock();
        if cache.len() < self.per_core_capacity {
            cache.push(buffer);
        } else {
            // キャッシュ満杯 → 親に返却
            drop(cache);
            self.parent.free(buffer);
        }
    }
}

// ============================================================================
// Global Mempool
// ============================================================================

/// グローバルネットワークメモリプール
pub(crate) static NET_MEMPOOL: spin::Once<Mempool> = spin::Once::new();

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
mod tests;

