use super::*;


impl CachedBlock {
    /// Create a new cached block
    pub fn new(key: BlockCacheKey, data: Vec<u8>, block_size: usize) -> Self {
        let boxed: Box<[u8]> = data.into_boxed_slice();
        Self {
            key,
            data: Arc::new(RwLock::new(boxed)),
            block_size,
            state: Mutex::new(PageState::Clean),
            last_access: AtomicU64::new(0),
            dirty: AtomicBool::new(false),
        }
    }

    /// Create an empty block
    pub fn new_empty(key: BlockCacheKey, block_size: usize) -> Self {
        Self::new(key, vec![0u8; block_size], block_size)
    }

    /// Get block data (Arc clone)
    #[inline]
    pub fn data(&self) -> Arc<RwLock<Box<[u8]>>> {
        Arc::clone(&self.data)
    }

    /// Read with callback (safe access)
    #[inline]
    pub fn read_with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let guard = self.data.read();
        f(&guard)
    }

    /// Get block data for sync operations
    pub fn data_for_sync(&self) -> Vec<u8> {
        let guard = self.data.read();
        guard.to_vec()
    }

    /// Get block key
    pub fn key(&self) -> BlockCacheKey {
        self.key
    }

    /// Get block size
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Check if block is dirty
    pub fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::Acquire)
    }

    /// Mark block as dirty
    pub fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::Release);
        *self.state.lock() = PageState::Dirty;
    }

    /// Mark block as clean
    pub fn mark_clean(&self) {
        self.dirty.store(false, Ordering::Release);
        *self.state.lock() = PageState::Clean;
    }

    /// Update last access time
    pub fn touch(&self, time: u64) {
        self.last_access.store(time, Ordering::Release);
    }

    /// Get last access time
    pub fn last_access(&self) -> u64 {
        self.last_access.load(Ordering::Acquire)
    }

    /// Read from block at offset (safe version)
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> usize {
        let guard = self.data.read();
        let available = guard.len().saturating_sub(offset);
        let to_read = buf.len().min(available);

        if to_read > 0 {
            buf[..to_read].copy_from_slice(&guard[offset..offset + to_read]);
        }

        to_read
    }

    /// Write to block at offset (safe version with RwLock)
    ///
    /// ## 安全性
    /// 書き込みロックを取得してから書き込みを行うため、
    /// 読み取り操作との競合が発生しない。
    pub fn write(&self, offset: usize, buf: &[u8]) -> usize {
        let mut guard = self.data.write();
        let available = guard.len().saturating_sub(offset);
        let to_write = buf.len().min(available);

        if to_write == 0 {
            return 0;
        }

        let end = offset + to_write;
        guard[offset..end].copy_from_slice(&buf[..to_write]);
        drop(guard);

        self.mark_dirty();

        to_write
    }
}

/// LRU Block Cache statistics
#[derive(Clone, Debug, Default)]
pub struct BlockCacheStats {
    /// Total cache hits
    pub hits: u64,
    /// Total cache misses
    pub misses: u64,
    /// Total blocks in cache
    pub blocks: u64,
    /// Total bytes in cache
    pub bytes: u64,
    /// Total dirty blocks
    pub dirty_blocks: u64,
    /// Total evictions
    pub evictions: u64,
    /// Total write-backs
    pub writebacks: u64,
}

// ============================================================================
// O(1) LRU Implementation using Index-based Doubly Linked List
// ============================================================================

/// 無効なインデックスを表す定数
pub(crate) const INVALID_INDEX: usize = usize::MAX;

/// LRUリストのノード
#[derive(Clone, Copy)]
pub(crate) struct LruNode {
    /// 前のノードのインデックス（INVALID_INDEXは先頭を示す）
    prev: usize,
    /// 次のノードのインデックス（INVALID_INDEXは末尾を示す）
    next: usize,
    /// キャッシュキー
    key: BlockCacheKey,
    /// このノードが有効か（削除済みでないか）
    valid: bool,
}

impl Default for LruNode {
    fn default() -> Self {
        Self {
            prev: INVALID_INDEX,
            next: INVALID_INDEX,
            key: BlockCacheKey::new(0, 0),
            valid: false,
        }
    }
}

/// O(1) LRUリスト
///
/// ## 設計
/// - Arena (Vec<LruNode>): ノードを連続メモリに格納
/// - HashMap (BTreeMap<Key, Index>): キーからノードインデックスへのマッピング
/// - head/tail: リストの先頭/末尾インデックス
/// - free_list: 再利用可能なノードのリスト
///
/// ## 計算量
/// - `insert`: O(1)
/// - `remove`: O(1)
/// - `touch` (move to front): O(1)
/// - `evict_lru` (remove from back): O(1)
pub(crate) struct LruList {
    /// ノードのArena
    nodes: Vec<LruNode>,
    /// キー → ノードインデックス
    key_to_index: BTreeMap<BlockCacheKey, usize>,
    /// リストの先頭（最近使用）
    head: usize,
    /// リストの末尾（LRU候補）
    tail: usize,
    /// 空きノードのインデックス
    free_list: Vec<usize>,
}

impl LruList {
    /// 新しいLRUリストを作成
    fn new() -> Self {
        Self {
            nodes: Vec::new(),
            key_to_index: BTreeMap::new(),
            head: INVALID_INDEX,
            tail: INVALID_INDEX,
            free_list: Vec::new(),
        }
    }

    /// ノードを先頭に挿入（O(1)）
    fn insert(&mut self, key: BlockCacheKey) {
        // 既に存在する場合は先頭に移動
        if self.key_to_index.contains_key(&key) {
            self.touch(&key);
            return;
        }

        // 新しいノードのインデックスを取得（空きリストから or 新規追加）
        let new_idx = if let Some(idx) = self.free_list.pop() {
            idx
        } else {
            let idx = self.nodes.len();
            self.nodes.push(LruNode::default());
            idx
        };

        // ノードを初期化
        self.nodes[new_idx] = LruNode {
            prev: INVALID_INDEX,
            next: self.head,
            key,
            valid: true,
        };

        // 先頭に挿入
        if self.head != INVALID_INDEX {
            self.nodes[self.head].prev = new_idx;
        }
        self.head = new_idx;

        // 最初のノードなら末尾も設定
        if self.tail == INVALID_INDEX {
            self.tail = new_idx;
        }

        // インデックスマップに追加
        self.key_to_index.insert(key, new_idx);
    }

    /// キーを先頭に移動（O(1)）
    fn touch(&mut self, key: &BlockCacheKey) {
        let Some(&idx) = self.key_to_index.get(key) else {
            return;
        };

        // 既に先頭なら何もしない
        if idx == self.head {
            return;
        }

        // リストから削除
        self.unlink(idx);

        // 先頭に挿入
        self.nodes[idx].prev = INVALID_INDEX;
        self.nodes[idx].next = self.head;

        if self.head != INVALID_INDEX {
            self.nodes[self.head].prev = idx;
        }
        self.head = idx;

        // 末尾が無効になった場合は復元
        if self.tail == INVALID_INDEX {
            self.tail = idx;
        }
    }

    /// キーを削除（O(1)）
    fn remove(&mut self, key: &BlockCacheKey) -> bool {
        let Some(idx) = self.key_to_index.remove(key) else {
            return false;
        };

        self.unlink(idx);
        self.nodes[idx].valid = false;
        self.free_list.push(idx);
        true
    }

    /// ノードをリストから切り離す（内部関数）
    fn unlink(&mut self, idx: usize) {
        let node = &self.nodes[idx];
        let prev = node.prev;
        let next = node.next;

        if prev != INVALID_INDEX {
            self.nodes[prev].next = next;
        } else {
            // 先頭だった
            self.head = next;
        }

        if next != INVALID_INDEX {
            self.nodes[next].prev = prev;
        } else {
            // 末尾だった
            self.tail = prev;
        }
    }

    /// LRU（末尾）のキーを取得して削除（O(1)）
    fn evict_lru(&mut self) -> Option<BlockCacheKey> {
        if self.tail == INVALID_INDEX {
            return None;
        }

        let tail_idx = self.tail;
        let key = self.nodes[tail_idx].key;
        self.remove(&key);
        Some(key)
    }

    /// キーが存在するか確認
    fn contains(&self, key: &BlockCacheKey) -> bool {
        self.key_to_index.contains_key(key)
    }

    /// 要素数を取得
    fn len(&self) -> usize {
        self.key_to_index.len()
    }

    /// 空かどうか
    fn is_empty(&self) -> bool {
        self.key_to_index.is_empty()
    }
}

/// LRU Block Cache implementation
///
/// ## 設計 (v2.0 - O(1) LRU)
/// - O(1) LRUリスト: Index-based Doubly Linked List + HashMap
/// - 安全なデータアクセス: RwLockによる排他制御
/// - Write-back: ダーティブロックは明示的にフラッシュ
///
/// ## LRU操作の計算量
/// - `get`: O(1) - HashMap検索 + リストの先頭移動
/// - `insert`: O(1) - HashMap挿入 + リスト先頭追加
/// - `evict`: O(1) - リスト末尾削除
pub struct LRUBlockCache {
    /// Cached blocks (key -> block)
    blocks: Mutex<BTreeMap<BlockCacheKey, Arc<CachedBlock>>>,
    /// O(1) LRU list
    lru_list: Mutex<LruList>,
    /// Block size
    block_size: usize,
    /// Cache size limit in bytes
    limit: usize,
    /// Current cache size in bytes
    current_size: AtomicU64,
    /// Statistics
    stats: Mutex<BlockCacheStats>,
    /// Global time counter for LRU
    time: AtomicU64,
}

impl LRUBlockCache {
    /// Create a new LRU block cache
    pub fn new(block_size: usize, limit: usize) -> Self {
        Self {
            blocks: Mutex::new(BTreeMap::new()),
            lru_list: Mutex::new(LruList::new()),
            block_size,
            limit,
            current_size: AtomicU64::new(0),
            stats: Mutex::new(BlockCacheStats::default()),
            time: AtomicU64::new(0),
        }
    }

    /// Create with default settings
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_BLOCK_SIZE, DEFAULT_BLOCK_CACHE_LIMIT)
    }

    /// Get current time and increment
    fn tick(&self) -> u64 {
        self.time.fetch_add(1, Ordering::AcqRel)
    }

    /// Move a key to the front of LRU list (most recently used) - O(1)
    fn touch_lru(&self, key: BlockCacheKey) {
        let mut lru_list = self.lru_list.lock();
        lru_list.touch(&key);
    }

    /// Get a block from cache
    pub fn get(&self, device_id: u64, block_num: u64) -> Option<Arc<CachedBlock>> {
        let key = BlockCacheKey::new(device_id, block_num);
        let time = self.tick();

        let blocks = self.blocks.lock();

        if let Some(block) = blocks.get(&key) {
            // Cache hit
            let block_clone = Arc::clone(block);
            block_clone.touch(time);
            drop(blocks); // Release lock before touching LRU

            self.touch_lru(key);

            let mut stats = self.stats.lock();
            stats.hits += 1;

            return Some(block_clone);
        }

        // Cache miss
        drop(blocks);
        let mut stats = self.stats.lock();
        stats.misses += 1;

        None
    }

    /// Insert a block into cache
    pub fn insert(&self, device_id: u64, block_num: u64, data: Vec<u8>) {
        let key = BlockCacheKey::new(device_id, block_num);

        // Check if we need to evict
        let current = self.current_size.load(Ordering::Acquire) as usize;
        if current + self.block_size > self.limit {
            self.evict_blocks(self.block_size);
        }

        let block = Arc::new(CachedBlock::new(key, data, self.block_size));
        block.touch(self.tick());

        let mut blocks = self.blocks.lock();
        blocks.insert(key, block);
        drop(blocks);

        // Add to LRU list (O(1))
        {
            let mut lru_list = self.lru_list.lock();
            lru_list.insert(key);
        }

        self.current_size
            .fetch_add(self.block_size as u64, Ordering::AcqRel);

        let mut stats = self.stats.lock();
        stats.blocks += 1;
        stats.bytes = self.current_size.load(Ordering::Acquire);
    }

    /// Read from cache
    pub fn read(
        &self,
        device_id: u64,
        block_num: u64,
        offset: usize,
        buf: &mut [u8],
    ) -> Option<usize> {
        let block = self.get(device_id, block_num)?;
        Some(block.read(offset, buf))
    }

    /// Write to cache (marks block as dirty)
    pub fn write(
        &self,
        device_id: u64,
        block_num: u64,
        offset: usize,
        buf: &[u8],
    ) -> Option<usize> {
        let block = self.get(device_id, block_num)?;
        let written = block.write(offset, buf);

        if written > 0 {
            let mut stats = self.stats.lock();
            stats.dirty_blocks += 1;
        }

        Some(written)
    }

    /// Evict blocks to free space - O(1) per eviction
    fn evict_blocks(&self, needed: usize) {
        let mut freed = 0;
        let mut lru_list = self.lru_list.lock();
        let mut blocks = self.blocks.lock();
        let mut dirty_keys = Vec::new();

        while freed < needed && !lru_list.is_empty() {
            // Get LRU block (from back of list) - O(1)
            if let Some(key) = lru_list.evict_lru() {
                // Skip dirty blocks during eviction
                if let Some(block) = blocks.get(&key) {
                    if block.is_dirty() {
                        // Remember dirty key to re-add later
                        dirty_keys.push(key);
                        continue;
                    }
                }

                // Remove clean block
                if blocks.remove(&key).is_some() {
                    freed += self.block_size;
                    self.current_size
                        .fetch_sub(self.block_size as u64, Ordering::AcqRel);

                    let mut stats = self.stats.lock();
                    stats.evictions += 1;
                    stats.blocks = stats.blocks.saturating_sub(1);
                    stats.bytes = self.current_size.load(Ordering::Acquire);
                }
            } else {
                break;
            }
        }

        // Re-add dirty keys that were skipped
        for key in dirty_keys {
            lru_list.insert(key);
        }
    }

    /// Flush all dirty blocks for a device
    pub fn flush_device<F>(&self, device_id: u64, mut writer: F) -> Result<usize, ()>
    where
        F: FnMut(u64, &[u8]) -> Result<(), ()>,
    {
        let blocks = self.blocks.lock();
        let mut flushed = 0;

        for (key, block) in blocks.iter() {
            if key.device_id == device_id && block.is_dirty() {
                let data = block.data_for_sync();
                writer(key.block_num, &data)?;
                block.mark_clean();
                flushed += 1;

                let mut stats = self.stats.lock();
                stats.writebacks += 1;
                stats.dirty_blocks = stats.dirty_blocks.saturating_sub(1);
            }
        }

        Ok(flushed)
    }

    /// Flush a specific block
    pub fn flush_block<F>(&self, device_id: u64, block_num: u64, mut writer: F) -> Result<bool, ()>
    where
        F: FnMut(&[u8]) -> Result<(), ()>,
    {
        let key = BlockCacheKey::new(device_id, block_num);
        let blocks = self.blocks.lock();

        if let Some(block) = blocks.get(&key) {
            if block.is_dirty() {
                let data = block.data_for_sync();
                writer(&data)?;
                block.mark_clean();

                let mut stats = self.stats.lock();
                stats.writebacks += 1;
                stats.dirty_blocks = stats.dirty_blocks.saturating_sub(1);

                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Flush all dirty blocks
    pub fn flush_all<F>(&self, mut writer: F) -> Result<usize, ()>
    where
        F: FnMut(u64, u64, &[u8]) -> Result<(), ()>,
    {
        let blocks = self.blocks.lock();
        let mut flushed = 0;

        for (key, block) in blocks.iter() {
            if block.is_dirty() {
                let data = block.data_for_sync();
                writer(key.device_id, key.block_num, &data)?;
                block.mark_clean();
                flushed += 1;

                let mut stats = self.stats.lock();
                stats.writebacks += 1;
                stats.dirty_blocks = stats.dirty_blocks.saturating_sub(1);
            }
        }

        Ok(flushed)
    }

    /// Invalidate all blocks for a device
    pub fn invalidate_device(&self, device_id: u64) {
        let mut blocks = self.blocks.lock();
        let mut lru_list = self.lru_list.lock();

        // Remove all blocks for this device
        let keys_to_remove: Vec<_> = blocks
            .keys()
            .filter(|k| k.device_id == device_id)
            .copied()
            .collect();

        for key in keys_to_remove {
            if blocks.remove(&key).is_some() {
                // Remove from LRU list - O(1)
                lru_list.remove(&key);

                self.current_size
                    .fetch_sub(self.block_size as u64, Ordering::AcqRel);

                let mut stats = self.stats.lock();
                stats.blocks = stats.blocks.saturating_sub(1);
                stats.bytes = self.current_size.load(Ordering::Acquire);
            }
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> BlockCacheStats {
        self.stats.lock().clone()
    }

    /// Get current cache size in bytes
    pub fn current_size(&self) -> usize {
        self.current_size.load(Ordering::Acquire) as usize
    }

    /// Get cache limit in bytes
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Get block size
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Get hit ratio
    pub fn hit_ratio(&self) -> f64 {
        let stats = self.stats.lock();
        let total = stats.hits + stats.misses;
        if total == 0 {
            0.0
        } else {
            stats.hits as f64 / total as f64
        }
    }

    /// Get number of cached blocks
    pub fn block_count(&self) -> usize {
        self.blocks.lock().len()
    }
}

// ============================================================================
// Global Block Cache Instance
// ============================================================================

pub(crate) static BLOCK_CACHE: spin::Once<LRUBlockCache> = spin::Once::new();

/// Initialize the global block cache
pub fn init_block_cache(block_size: usize, limit: usize) {
    BLOCK_CACHE.call_once(|| LRUBlockCache::new(block_size, limit));
}

/// Get the global block cache
pub fn block_cache() -> &'static LRUBlockCache {
    BLOCK_CACHE.get().expect("Block cache not initialized")
}

// ============================================================================
// Block Cache Tests
// ============================================================================

#[cfg(test)]
mod block_cache_tests {
    use super::*;

    #[test_case]
    fn test_block_cache_basic() {
        let cache = LRUBlockCache::new(512, 4096); // 4KB cache, 512B blocks

        // Insert blocks
        let data1 = alloc::vec![0x11u8; 512];
        let data2 = alloc::vec![0x22u8; 512];

        cache.insert(0, 0, data1);
        cache.insert(0, 1, data2);

        // Read from cache
        let mut buf = [0u8; 10];
        let result = cache.read(0, 0, 0, &mut buf);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 10);
        assert_eq!(buf, [0x11u8; 10]);

        // Check stats
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.blocks, 2);
    }

    #[test_case]
    fn test_block_cache_lru_eviction() {
        let cache = LRUBlockCache::new(512, 1024); // 1KB cache, 512B blocks (max 2 blocks)

        // Insert 3 blocks (should evict first block)
        cache.insert(0, 0, alloc::vec![0x11u8; 512]);
        cache.insert(0, 1, alloc::vec![0x22u8; 512]);
        cache.insert(0, 2, alloc::vec![0x33u8; 512]); // Should evict block 0

        // Block 0 should be evicted
        assert!(cache.get(0, 0).is_none());

        // Blocks 1 and 2 should still be in cache
        assert!(cache.get(0, 1).is_some());
        assert!(cache.get(0, 2).is_some());
    }

    #[test_case]
    fn test_block_cache_dirty_tracking() {
        let cache = LRUBlockCache::new(512, 4096);

        cache.insert(0, 0, alloc::vec![0x11u8; 512]);

        // Write to block (marks as dirty)
        let buf = [0xFFu8; 10];
        let result = cache.write(0, 0, 0, &buf);
        assert!(result.is_some());

        // Verify block is dirty
        let block = cache.get(0, 0).unwrap();
        assert!(block.is_dirty());
    }

    #[test_case]
    fn test_block_cache_flush() {
        let cache = LRUBlockCache::new(512, 4096);

        cache.insert(0, 0, alloc::vec![0x11u8; 512]);
        cache.write(0, 0, 0, &[0xFFu8; 10]);

        // Flush the block
        let mut flushed_data = Vec::new();
        let result = cache.flush_block(0, 0, |data| {
            flushed_data = data.to_vec();
            Ok(())
        });

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
        assert_eq!(flushed_data[0], 0xFF);

        // Block should now be clean
        let block = cache.get(0, 0).unwrap();
        assert!(!block.is_dirty());
    }
}

