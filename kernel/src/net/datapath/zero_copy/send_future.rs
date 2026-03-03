// ============================================================================
// kernel/src/net/datapath/zero_copy/send_future.rs
// ============================================================================
use super::*;


impl<'a> Future for ZeroCopySendFuture<'a> {
    type Output = Result<(), &'static str>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(buffer) = self.buffer.take() {
            // ZeroCopyBuffer → PacketRef に変換してドライバへ委譲
            let data = buffer.as_slice();
            if data.is_empty() {
                return Poll::Ready(Ok(()));
            }

            // PacketRef を確保してデータをコピー（DMAバッファ経由のゼロコピー送信）
            if let Some(mut packet) = crate::net::datapath::mempool::alloc_packet() {
                let copy_len = data.len().min(packet.capacity());
                packet.data_mut()[..copy_len].copy_from_slice(&data[..copy_len]);
                packet.set_len(copy_len);

                // VirtIO ゼロコピー送信を試行
                match ZeroCopyWriter::enqueue_via_virtio(packet) {
                    Ok(()) => {
                        return Poll::Ready(Ok(()));
                    }
                    Err(_) => {
                        // デバイス未初期化 or キュー満杯 → TX キューへフォールバック
                        crate::net::l4::endpoint::event::send_event_ignore(
                            crate::net::l4::endpoint::event::NetworkEvent::TxAvailable,
                        );
                        return Poll::Ready(Err("VirtIO enqueue failed, packet dropped"));
                    }
                }
            } else {
                // PacketRef 割り当て失敗: Waker を登録して TxAvailable で再試行
                self.buffer = Some(buffer);
                self.writer.waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
        } else {
            self.writer.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

// ============================================================================
// Global Pool Manager
// ============================================================================

/// グローバルプールマネージャー
pub(crate) static POOL_MANAGER: crate::sync::PoisonLock<Option<PoolManager>> = crate::sync::PoisonLock::new(None);

pub struct PoolManager {
    pools: Vec<Arc<MemoryPool>>,
    next_id: u32,
}

impl PoolManager {
    pub fn new() -> Self {
        Self {
            pools: Vec::new(),
            next_id: 0,
        }
    }

    /// プールを作成
    pub fn create_pool(&mut self, buffer_size: usize, count: usize) -> Arc<MemoryPool> {
        let id = PoolId::new(self.next_id);
        self.next_id += 1;

        let pool = Arc::new(MemoryPool::new(id, buffer_size, count));
        self.pools.push(pool.clone());
        pool
    }

    /// プールを取得
    pub fn get_pool(&self, id: PoolId) -> Option<Arc<MemoryPool>> {
        self.pools.iter().find(|p| p.id() == id).cloned()
    }

    /// デフォルトプールを取得
    pub fn default_pool(&self) -> Option<Arc<MemoryPool>> {
        self.pools.first().cloned()
    }
}

impl Default for PoolManager {
    fn default() -> Self {
        Self::new()
    }
}

/// プールマネージャーを初期化
pub fn init() {
    let mut manager = PoolManager::new();
    // デフォルトプールを作成
    manager.create_pool(DEFAULT_BUFFER_SIZE, 1024);
    if let Ok(mut guard) = POOL_MANAGER.lock() {
        *guard = Some(manager);
    }
}

/// プールマネージャーにアクセス
pub fn with_pool_manager<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut PoolManager) -> R,
{
    if let Ok(mut guard) = POOL_MANAGER.lock() {
        guard.as_mut().map(f)
    } else {
        None
    }
}

/// デフォルトプールからバッファを割り当て
pub fn alloc_buffer() -> Option<ZeroCopyBuffer> {
    with_pool_manager(|mgr| mgr.default_pool().and_then(|pool| pool.alloc())).flatten()
}
