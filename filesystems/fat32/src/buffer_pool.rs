use crate::{
    Arc,
    Box,
    BLOCK_SIZE,
    FsError,
    FsResult,
    IrqPoisonLock,
    Vec,
    try_alloc_vec,
};

// ============================================================================
// Cluster Buffer Pooling (Performance Optimization)
// ============================================================================

pub trait ClusterBuffer: Send {
    fn len(&self) -> usize;
    fn as_slice(&self) -> &[u8];
    fn as_mut_slice(&mut self) -> &mut [u8];
}

impl ClusterBuffer for Vec<u8> {
    fn len(&self) -> usize {
        Vec::len(self)
    }

    fn as_slice(&self) -> &[u8] {
        Vec::as_slice(self)
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        Vec::as_mut_slice(self)
    }
}

pub trait ClusterBufferAllocator: Send + Sync {
    fn alloc(&self, size: usize) -> FsResult<Box<dyn ClusterBuffer>>;
}

pub struct VecClusterBufferAllocator;

impl ClusterBufferAllocator for VecClusterBufferAllocator {
    fn alloc(&self, size: usize) -> FsResult<Box<dyn ClusterBuffer>> {
        Ok(Box::new(try_alloc_vec(size, 0u8)?))
    }
}

/// クラスタバッチ処理やディレクトリ走査用のバッファプール
///
/// ヒープアロケーションを削減し、Per-CPU的なキャッシュ効果を狙う。
pub struct ClusterBufferPool {
    allocator: Arc<dyn ClusterBufferAllocator>,
    /// バッファのスロット群。
    /// 本来は Per-CPU にすべきだが、ドライバの独立性を保つため Mutex 配列で代用。
    buffers: Vec<IrqPoisonLock<Option<Box<dyn ClusterBuffer>>>>,
}

impl ClusterBufferPool {
    /// 指定されたスロット数でバッファプールを作成
    pub fn new(slots: usize) -> FsResult<Self> {
        Self::with_allocator(slots, Arc::new(VecClusterBufferAllocator))
    }

    /// 指定されたアロケータでバッファプールを作成
    pub fn with_allocator(
        slots: usize,
        allocator: Arc<dyn ClusterBufferAllocator>,
    ) -> FsResult<Self> {
        let mut buffers = Vec::new();
        if buffers.try_reserve_exact(slots).is_err() {
            return Err(FsError::Other);
        }
        for _ in 0..slots {
            buffers.push(IrqPoisonLock::new(None));
        }
        Ok(Self { allocator, buffers })
    }

    /// バッファを取得
    pub fn get(&self, size: usize) -> FsResult<Box<dyn ClusterBuffer>> {
        // 簡易的な Per-CPU 的アクセス（現在はCPU ID取得APIがないためスロット0を優先）
        // TODO: current_cpu_id() を取得できる場合はそれを使用
        for slot in &self.buffers {
            if let Some(mut guard) = slot.try_lock() {
                if let Some(buf) = guard.take() {
                    if buf.len() >= size {
                        return Ok(buf);
                    }
                }
            }
        }
        self.allocator.alloc(size)
    }

    /// バッファを返却
    pub fn put(&self, buf: Box<dyn ClusterBuffer>) {
        if buf.len() < BLOCK_SIZE {
            return; // 小さすぎるバッファはプールしない
        }
        for slot in &self.buffers {
            if let Some(mut guard) = slot.try_lock() {
                if guard.is_none() {
                    *guard = Some(buf);
                    return;
                }
            }
        }
    }
}

/// RAII形式のバッファ管理
pub struct PooledClusterBuffer<'a> {
    pool: &'a ClusterBufferPool,
    buffer: Option<Box<dyn ClusterBuffer>>,
}

impl<'a> PooledClusterBuffer<'a> {
    pub fn new(pool: &'a ClusterBufferPool, size: usize) -> FsResult<Self> {
        Ok(Self {
            pool,
            buffer: Some(pool.get(size)?),
        })
    }
}

impl<'a> core::ops::Deref for PooledClusterBuffer<'a> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.buffer.as_ref().unwrap().as_slice()
    }
}

impl<'a> core::ops::DerefMut for PooledClusterBuffer<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer.as_mut().unwrap().as_mut_slice()
    }
}

impl<'a> Drop for PooledClusterBuffer<'a> {
    fn drop(&mut self) {
        if let Some(buf) = self.buffer.take() {
            self.pool.put(buf);
        }
    }
}
