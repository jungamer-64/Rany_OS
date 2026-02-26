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
            let mut buf = Vec::with_capacity(buffer_size);
            // initialize length so consumers can treat it as writable
            unsafe { buf.set_len(buffer_size) }; // safe: capacity >= buffer_size
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
        // For performance we no longer zero the entire buffer on every free;
        // callers are responsible for writing the bytes they need when the
        // buffer is reallocated.  Clearing would have been a major hotspot
        // for MTU‑sized packets.
        if buffer.capacity() != self.buffer_size {
            // if the caller resized the vector, shrink it back to the pool size
            buffer.truncate(self.buffer_size);
            buffer.reserve(self.buffer_size - buffer.len());
            unsafe { buffer.set_len(self.buffer_size) };
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

