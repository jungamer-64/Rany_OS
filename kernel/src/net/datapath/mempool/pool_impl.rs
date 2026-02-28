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
        // For performance we intentionally avoid zeroing here; callers are
        // expected to overwrite the contents when they reuse the buffer.
        // The only invariant we maintain is that returned vectors have
        // `capacity() == self.buffer_size` and `len() == 0`.
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
#[path = "tests.rs"]
mod tests;

