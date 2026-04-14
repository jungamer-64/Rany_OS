use super::*;
use crate::sync::PoisonLock;

impl PacketPool {
    /// Create a new packet pool
    pub fn new(capacity: usize, buffer_size: usize) -> Self {
        let mut buffers = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            let buf = Vec::with_capacity(buffer_size);
            buffers.push(buf);
        }

        PacketPool {
            buffers: PoisonLock::new(buffers),
            buffer_size,
            capacity,
        }
    }

    /// Return a buffer to the pool
    pub fn free(&self, mut buffer: Vec<u8>) {
        // Security: Zero out the buffer content
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

        let mut buffers = self.buffers.lock().unwrap_or_else(|e| e.into_inner());
        if buffers.len() < self.capacity {
            buffers.push(buffer);
        }
    }

    /// Get buffer size
    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    /// Get available buffer count
    pub fn available(&self) -> usize {
        self.buffers.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Allocate multiple buffers at once (batch allocation)
    pub fn alloc_batch(&self, count: usize) -> Vec<Vec<u8>> {
        let mut buffers = self.buffers.lock().unwrap_or_else(|e| e.into_inner());
        let to_take = count.min(buffers.len());
        let split_at = buffers.len() - to_take;
        buffers.split_off(split_at)
    }

    /// Return multiple buffers at once (batch free)
    pub fn free_batch(&self, batch: Vec<Vec<u8>>) {
        let mut buffers = self.buffers.lock().unwrap_or_else(|e| e.into_inner());
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
}

// ============================================================================
// Per-Core TX Buffer Cache
// ============================================================================

/// コアローカルな TX バッファキャッシュ
pub struct PerCoreTxCache {
    /// CPU ごとのバッファキャッシュ
    caches: Vec<PoisonLock<Vec<Vec<u8>>>>,
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
            caches.push(PoisonLock::new(Vec::with_capacity(TX_PER_CORE_CACHE_SIZE)));
        }
        Self {
            caches,
            per_core_capacity: TX_PER_CORE_CACHE_SIZE,
            parent,
            refill_count: TX_BATCH_REFILL,
        }
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

        let cpu_id = crate::cpu::try_current_id().unwrap_or(0);
        let idx = cpu_id % self.caches.len();

        let mut cache = self.caches[idx].lock().unwrap_or_else(|e| e.into_inner());
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
    if let Some(packet) = super::alloc_packet_for_active_dma_device() {
        return Some(packet);
    }

    NET_MEMPOOL.get()?.alloc()
}

#[cfg(test)]
mod tests;
