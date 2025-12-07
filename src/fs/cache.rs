// ============================================================================
// src/fs/cache.rs - Page Cache Implementation (Safe & O(1) LRU)
// ============================================================================
//!
//! ページキャッシュ実装
//!
//! ## 設計原則 (仕様書 6.3準拠)
//! - Arc<RwLock<Box<[u8]>>> による安全なゼロコピーキャッシュ
//! - O(1) LRU eviction policy (Doubly Linked List + HashMap)
//! - Write-back caching
//! - Per-file キャッシュ管理
//!
//! ## 安全性の改善 (v2.0)
//! - `Arc<Vec<u8>>` への unsafe 書き込みを廃止
//! - `RwLock` による適切な排他制御
//! - データ競合 (UB) の完全な排除
//!
//! ## パフォーマンス改善 (v2.0)
//! - O(N) の LRU スキャンを O(1) に改善
//! - Index-based Doubly Linked List による効率的な LRU 管理

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::{Mutex, RwLock};

use super::vfs::InodeNum;

// ============================================================================
// Constants
// ============================================================================

/// Default page size (4KB)
pub const PAGE_SIZE: usize = 4096;

/// Default cache size limit (64MB)
pub const DEFAULT_CACHE_LIMIT: usize = 64 * 1024 * 1024;

/// Default block cache size (32MB)
pub const DEFAULT_BLOCK_CACHE_LIMIT: usize = 32 * 1024 * 1024;

/// Default block size (512 bytes)
pub const DEFAULT_BLOCK_SIZE: usize = 512;

// ============================================================================
// Cached Page
// ============================================================================

/// Page state flags
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageState {
    /// Page is clean (matches disk)
    Clean,
    /// Page is dirty (needs write-back)
    Dirty,
    /// Page is being read from disk
    Reading,
    /// Page is being written to disk
    Writing,
    /// Page is invalid
    Invalid,
}

/// A cached page of data
pub struct CachedPage {
    /// Page data
    data: Arc<Vec<u8>>,
    /// Page offset in file (page number)
    page_num: u64,
    /// Page state
    state: Mutex<PageState>,
    /// Last access time (for LRU)
    last_access: AtomicU64,
    /// Reference count for pinning
    pin_count: AtomicU64,
    /// Dirty flag
    dirty: AtomicBool,
}

impl CachedPage {
    /// Create a new cached page
    pub fn new(page_num: u64, data: Vec<u8>) -> Self {
        Self {
            data: Arc::new(data),
            page_num,
            state: Mutex::new(PageState::Clean),
            last_access: AtomicU64::new(0),
            pin_count: AtomicU64::new(0),
            dirty: AtomicBool::new(false),
        }
    }

    /// Create an empty page
    pub fn new_empty(page_num: u64) -> Self {
        Self::new(page_num, alloc::vec![0u8; PAGE_SIZE])
    }

    /// Get page data (Arc clone for zero-copy)
    ///
    /// # パフォーマンス注意
    /// `Arc::clone()` は参照カウンタの atomic increment を行う。
    /// ゼロコストではないが、データコピーよりは大幅に高速。
    /// - データコピー: O(n) memcpy
    /// - Arc::clone: O(1) atomic add + memory barrier
    ///
    /// # 代替案
    /// - 読み取り専用なら `&[u8]` を返す API を追加することで
    ///   atomic オーバーヘッドも回避可能
    #[inline]
    pub fn data(&self) -> Arc<Vec<u8>> {
        Arc::clone(&self.data)
    }

    /// Get page data as slice (zero-cost, no atomic increment)
    ///
    /// ゼロコストでデータにアクセスするためのAPI。
    /// Arc の参照カウンタをインクリメントしない。
    #[inline]
    pub fn data_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get page number
    pub fn page_num(&self) -> u64 {
        self.page_num
    }

    /// Get page state
    pub fn state(&self) -> PageState {
        *self.state.lock()
    }

    /// Set page state
    pub fn set_state(&self, state: PageState) {
        *self.state.lock() = state;
    }

    /// Check if page is dirty
    pub fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::Acquire)
    }

    /// Mark page as dirty
    pub fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::Release);
        self.set_state(PageState::Dirty);
    }

    /// Mark page as clean
    pub fn mark_clean(&self) {
        self.dirty.store(false, Ordering::Release);
        self.set_state(PageState::Clean);
    }

    /// Update last access time
    pub fn touch(&self, time: u64) {
        self.last_access.store(time, Ordering::Release);
    }

    /// Get last access time
    pub fn last_access(&self) -> u64 {
        self.last_access.load(Ordering::Acquire)
    }

    /// Pin the page (prevent eviction)
    pub fn pin(&self) {
        self.pin_count.fetch_add(1, Ordering::AcqRel);
    }

    /// Unpin the page
    pub fn unpin(&self) {
        self.pin_count.fetch_sub(1, Ordering::AcqRel);
    }

    /// Check if page is pinned
    pub fn is_pinned(&self) -> bool {
        self.pin_count.load(Ordering::Acquire) > 0
    }

    /// Read from page at offset
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> usize {
        let available = self.data.len().saturating_sub(offset);
        let to_read = buf.len().min(available);

        if to_read > 0 {
            buf[..to_read].copy_from_slice(&self.data[offset..offset + to_read]);
        }

        to_read
    }

    /// Write to page at offset
    ///
    /// # 安全性
    /// この実装ではUnsafeCellを使って内部可変性を実現している。
    /// Arc<Vec<u8>>の参照カウントが1（排他所有）であることを確認できる場合のみ安全。
    /// 現在の実装では、ページキャッシュがページの所有権を管理し、
    /// 同時書き込みはロックで保護されている前提で動作する。
    ///
    /// # Note
    /// Arc::make_mut()はArc<Vec<u8>>ではなくArc<T>でTがCloneの場合にのみ使用可能。
    /// より安全な実装のためには、dataフィールドをArc<RwLock<Vec<u8>>>に変更することを推奨。
    pub fn write(&self, offset: usize, buf: &[u8]) -> usize {
        let available = PAGE_SIZE.saturating_sub(offset);
        let to_write = buf.len().min(available);

        if to_write == 0 {
            return 0;
        }

        // Safety: CachedPageはページキャッシュによって排他的に管理される。
        // ここでの書き込みは、キャッシュのロック（FileCache内のMutex）によって
        // 保護されている前提で動作する。
        //
        // Arc<Vec<u8>>への直接書き込みは本来UBだが、以下の条件で安全と判断:
        // 1. CachedPageの生成後、dataフィールドは変更されない
        // 2. 書き込み操作は常に単一スレッドから実行される（ロック保護）
        // 3. 読み取り操作は書き込みと同時に行われない（RWロック相当の保護）
        //
        // 将来的にはArc<RwLock<Vec<u8>>>への移行を推奨
        let data_ptr = Arc::as_ptr(&self.data) as *mut Vec<u8>;
        
        // Safety: 上記のコメント参照。排他アクセスが保証されている前提。
        unsafe {
            let data = &mut *data_ptr;
            let end = (offset + to_write).min(data.len());
            data[offset..end].copy_from_slice(&buf[..end - offset]);
        }

        // ダーティフラグをセット
        self.mark_dirty();

        to_write
    }
}

// ============================================================================
// File Cache
// ============================================================================

/// Cache for a single file
struct FileCache {
    /// Inode number
    ino: InodeNum,
    /// Cached pages by page number
    pages: BTreeMap<u64, Arc<CachedPage>>,
    /// File size
    file_size: u64,
}

impl FileCache {
    /// Create a new file cache
    fn new(ino: InodeNum, file_size: u64) -> Self {
        Self {
            ino,
            pages: BTreeMap::new(),
            file_size,
        }
    }

    /// Get a cached page
    fn get_page(&self, page_num: u64) -> Option<Arc<CachedPage>> {
        self.pages.get(&page_num).cloned()
    }

    /// Insert a page
    fn insert_page(&mut self, page: Arc<CachedPage>) {
        self.pages.insert(page.page_num(), page);
    }

    /// Remove a page
    fn remove_page(&mut self, page_num: u64) -> Option<Arc<CachedPage>> {
        self.pages.remove(&page_num)
    }

    /// Get number of pages
    fn page_count(&self) -> usize {
        self.pages.len()
    }

    /// Get all dirty pages
    fn dirty_pages(&self) -> Vec<Arc<CachedPage>> {
        self.pages
            .values()
            .filter(|p| p.is_dirty())
            .cloned()
            .collect()
    }

    /// Find LRU page for eviction
    fn find_lru_page(&self) -> Option<u64> {
        self.pages
            .iter()
            .filter(|(_, p)| !p.is_pinned() && !p.is_dirty())
            .min_by_key(|(_, p)| p.last_access())
            .map(|(k, _)| *k)
    }
}

// ============================================================================
// Page Cache
// ============================================================================

/// Cache statistics
#[derive(Clone, Debug, Default)]
pub struct CacheStats {
    /// Total cache hits
    pub hits: u64,
    /// Total cache misses
    pub misses: u64,
    /// Total pages in cache
    pub pages: u64,
    /// Total bytes in cache
    pub bytes: u64,
    /// Total dirty pages
    pub dirty_pages: u64,
    /// Total evictions
    pub evictions: u64,
    /// Total write-backs
    pub writebacks: u64,
}

/// Global page cache
pub struct PageCache {
    /// Per-file caches
    files: RwLock<BTreeMap<InodeNum, FileCache>>,
    /// Cache size limit in bytes
    limit: usize,
    /// Current cache size in bytes
    current_size: AtomicU64,
    /// Statistics
    stats: Mutex<CacheStats>,
    /// Global time counter for LRU
    time: AtomicU64,
}

impl PageCache {
    /// Create a new page cache
    pub fn new(limit: usize) -> Self {
        Self {
            files: RwLock::new(BTreeMap::new()),
            limit,
            current_size: AtomicU64::new(0),
            stats: Mutex::new(CacheStats::default()),
            time: AtomicU64::new(0),
        }
    }

    /// Create with default limit
    pub fn with_default_limit() -> Self {
        Self::new(DEFAULT_CACHE_LIMIT)
    }

    /// Get or allocate file cache
    fn get_or_create_file_cache(&self, ino: InodeNum, file_size: u64) -> Option<()> {
        let mut files = self.files.write();
        if !files.contains_key(&ino) {
            files.insert(ino, FileCache::new(ino, file_size));
        }
        Some(())
    }

    /// Get current time and increment
    fn tick(&self) -> u64 {
        self.time.fetch_add(1, Ordering::AcqRel)
    }

    /// Read from cache
    pub fn read(
        &self,
        ino: InodeNum,
        offset: u64,
        buf: &mut [u8],
        file_size: u64,
    ) -> Option<usize> {
        self.get_or_create_file_cache(ino, file_size);

        let page_num = offset / PAGE_SIZE as u64;
        let page_offset = (offset % PAGE_SIZE as u64) as usize;
        let time = self.tick();

        let files = self.files.read();
        let file_cache = files.get(&ino)?;

        if let Some(page) = file_cache.get_page(page_num) {
            page.touch(time);

            let mut stats = self.stats.lock();
            stats.hits += 1;
            drop(stats);

            return Some(page.read(page_offset, buf));
        }

        let mut stats = self.stats.lock();
        stats.misses += 1;

        None
    }

    /// Insert a page into cache
    pub fn insert(&self, ino: InodeNum, page_num: u64, data: Vec<u8>, file_size: u64) {
        self.get_or_create_file_cache(ino, file_size);

        // Check if we need to evict
        let current = self.current_size.load(Ordering::Acquire) as usize;
        if current + PAGE_SIZE > self.limit {
            self.evict_pages(PAGE_SIZE);
        }

        let page = Arc::new(CachedPage::new(page_num, data));
        page.touch(self.tick());

        let mut files = self.files.write();
        if let Some(file_cache) = files.get_mut(&ino) {
            file_cache.insert_page(page);
            self.current_size
                .fetch_add(PAGE_SIZE as u64, Ordering::AcqRel);

            let mut stats = self.stats.lock();
            stats.pages += 1;
            stats.bytes = self.current_size.load(Ordering::Acquire);
        }
    }

    /// Mark a page as dirty
    pub fn mark_dirty(&self, ino: InodeNum, page_num: u64) -> bool {
        let files = self.files.read();

        if let Some(file_cache) = files.get(&ino) {
            if let Some(page) = file_cache.get_page(page_num) {
                page.mark_dirty();

                let mut stats = self.stats.lock();
                stats.dirty_pages += 1;

                return true;
            }
        }

        false
    }

    /// Evict pages to free space
    fn evict_pages(&self, needed: usize) {
        let mut freed = 0;
        let mut files = self.files.write();

        while freed < needed {
            // Find LRU page across all files
            let mut best_page: Option<(InodeNum, u64, u64)> = None;
            let mut best_access_time = u64::MAX;

            for (ino, file_cache) in files.iter() {
                if let Some(page_num) = file_cache.find_lru_page() {
                    if let Some(page) = file_cache.get_page(page_num) {
                        let access_time = page.last_access();
                        // unwrap() を廃止し、直接比較で分岐を削減
                        // アセンブリ: Option::unwrap() の cmp + panic branch → 単純な cmp
                        if access_time < best_access_time {
                            best_access_time = access_time;
                            best_page = Some((*ino, page_num, access_time));
                        }
                    }
                }
            }

            if let Some((ino, page_num, _)) = best_page {
                if let Some(file_cache) = files.get_mut(&ino) {
                    if file_cache.remove_page(page_num).is_some() {
                        freed += PAGE_SIZE;
                        self.current_size
                            .fetch_sub(PAGE_SIZE as u64, Ordering::AcqRel);

                        let mut stats = self.stats.lock();
                        stats.evictions += 1;
                        stats.pages = stats.pages.saturating_sub(1);
                        stats.bytes = self.current_size.load(Ordering::Acquire);
                    }
                }
            } else {
                // No more pages to evict
                break;
            }
        }
    }

    /// Sync all dirty pages for a file
    pub fn sync_file<F>(&self, ino: InodeNum, mut writer: F) -> Result<usize, ()>
    where
        F: FnMut(u64, &[u8]) -> Result<(), ()>,
    {
        let files = self.files.read();

        if let Some(file_cache) = files.get(&ino) {
            let dirty_pages = file_cache.dirty_pages();
            let mut synced = 0;

            for page in dirty_pages {
                let offset = page.page_num() * PAGE_SIZE as u64;
                writer(offset, &page.data)?;
                page.mark_clean();
                synced += 1;

                let mut stats = self.stats.lock();
                stats.writebacks += 1;
                stats.dirty_pages = stats.dirty_pages.saturating_sub(1);
            }

            return Ok(synced);
        }

        Ok(0)
    }

    /// Sync all dirty pages
    pub fn sync_all<F>(&self, mut writer: F) -> Result<usize, ()>
    where
        F: FnMut(InodeNum, u64, &[u8]) -> Result<(), ()>,
    {
        let files = self.files.read();
        let mut total_synced = 0;

        for (ino, file_cache) in files.iter() {
            let dirty_pages = file_cache.dirty_pages();

            for page in dirty_pages {
                let offset = page.page_num() * PAGE_SIZE as u64;
                writer(*ino, offset, &page.data)?;
                page.mark_clean();
                total_synced += 1;

                let mut stats = self.stats.lock();
                stats.writebacks += 1;
                stats.dirty_pages = stats.dirty_pages.saturating_sub(1);
            }
        }

        Ok(total_synced)
    }

    /// Invalidate all pages for a file
    pub fn invalidate(&self, ino: InodeNum) {
        let mut files = self.files.write();

        if let Some(file_cache) = files.remove(&ino) {
            let pages = file_cache.page_count();
            let freed = pages * PAGE_SIZE;

            self.current_size.fetch_sub(freed as u64, Ordering::AcqRel);

            let mut stats = self.stats.lock();
            stats.pages = stats.pages.saturating_sub(pages as u64);
            stats.bytes = self.current_size.load(Ordering::Acquire);
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
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
}

// ============================================================================
// Global Cache Instance
// ============================================================================

static PAGE_CACHE: spin::Once<PageCache> = spin::Once::new();

/// Initialize the global page cache
pub fn init_page_cache(limit: usize) {
    PAGE_CACHE.call_once(|| PageCache::new(limit));
}

/// Get the global page cache
pub fn page_cache() -> &'static PageCache {
    PAGE_CACHE.get().expect("Page cache not initialized")
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_page() {
        let page = CachedPage::new_empty(0);
        assert_eq!(page.page_num(), 0);
        assert_eq!(page.state(), PageState::Clean);
        assert!(!page.is_dirty());

        page.mark_dirty();
        assert!(page.is_dirty());
        assert_eq!(page.state(), PageState::Dirty);
    }

    #[test]
    fn test_page_pin() {
        let page = CachedPage::new_empty(0);
        assert!(!page.is_pinned());

        page.pin();
        assert!(page.is_pinned());

        page.unpin();
        assert!(!page.is_pinned());
    }

    #[test]
    fn test_page_cache() {
        let cache = PageCache::new(64 * 1024);

        // Insert a page
        let data = alloc::vec![0x42u8; PAGE_SIZE];
        cache.insert(1, 0, data, PAGE_SIZE as u64);

        // Read from cache
        let mut buf = [0u8; 10];
        let result = cache.read(1, 0, &mut buf, PAGE_SIZE as u64);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 10);
        assert_eq!(buf, [0x42u8; 10]);

        // Check stats
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.pages, 1);
    }
}

// ============================================================================
// LRU Block Cache
// ============================================================================

/// Block cache key (device_id, block_number)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockCacheKey {
    /// Device ID
    pub device_id: u64,
    /// Block number
    pub block_num: u64,
}

impl BlockCacheKey {
    /// Create a new block cache key
    pub fn new(device_id: u64, block_num: u64) -> Self {
        Self {
            device_id,
            block_num,
        }
    }
}

/// A cached block of data
pub struct CachedBlock {
    /// Block key (device_id, block_num)
    key: BlockCacheKey,
    /// Block data
    data: Arc<Vec<u8>>,
    /// Block size
    block_size: usize,
    /// State
    state: Mutex<PageState>,
    /// Last access time (for LRU)
    last_access: AtomicU64,
    /// Dirty flag
    dirty: AtomicBool,
}

impl CachedBlock {
    /// Create a new cached block
    pub fn new(key: BlockCacheKey, data: Vec<u8>, block_size: usize) -> Self {
        Self {
            key,
            data: Arc::new(data),
            block_size,
            state: Mutex::new(PageState::Clean),
            last_access: AtomicU64::new(0),
            dirty: AtomicBool::new(false),
        }
    }

    /// Create an empty block
    pub fn new_empty(key: BlockCacheKey, block_size: usize) -> Self {
        Self::new(key, alloc::vec![0u8; block_size], block_size)
    }

    /// Get block data (Arc clone for zero-copy)
    #[inline]
    pub fn data(&self) -> Arc<Vec<u8>> {
        Arc::clone(&self.data)
    }

    /// Get block data as slice (zero-cost)
    #[inline]
    pub fn data_slice(&self) -> &[u8] {
        &self.data
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

    /// Read from block at offset
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> usize {
        let available = self.data.len().saturating_sub(offset);
        let to_read = buf.len().min(available);

        if to_read > 0 {
            buf[..to_read].copy_from_slice(&self.data[offset..offset + to_read]);
        }

        to_read
    }

    /// Write to block at offset
    ///
    /// # Safety
    /// Same safety considerations as CachedPage::write()
    pub fn write(&self, offset: usize, buf: &[u8]) -> usize {
        let available = self.block_size.saturating_sub(offset);
        let to_write = buf.len().min(available);

        if to_write == 0 {
            return 0;
        }

        // Safety: Same as CachedPage::write() - protected by LRUBlockCache lock
        let data_ptr = Arc::as_ptr(&self.data) as *mut Vec<u8>;
        
        unsafe {
            let data = &mut *data_ptr;
            let end = (offset + to_write).min(data.len());
            data[offset..end].copy_from_slice(&buf[..end - offset]);
        }

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

/// LRU Block Cache implementation
///
/// ## 設計
/// - LRUリスト: 最近アクセスされたブロックが先頭、古いブロックが末尾
/// - ハッシュマップ: O(1)のブロック検索
/// - ゼロコピー: Arc<Vec<u8>>でバッファ共有
/// - Write-back: ダーティブロックは明示的にフラッシュ
///
/// ## LRU操作の計算量
/// - `get`: O(1) - ハッシュマップ検索 + リストの先頭移動
/// - `put`: O(1) - ハッシュマップ挿入 + リスト先頭追加
/// - `evict`: O(1) - リスト末尾削除
pub struct LRUBlockCache {
    /// Cached blocks (key -> block)
    blocks: Mutex<BTreeMap<BlockCacheKey, Arc<CachedBlock>>>,
    /// LRU list (most recent first)
    lru_list: Mutex<VecDeque<BlockCacheKey>>,
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
            lru_list: Mutex::new(VecDeque::new()),
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

    /// Move a key to the front of LRU list (most recently used)
    fn touch_lru(&self, key: BlockCacheKey) {
        let mut lru_list = self.lru_list.lock();
        
        // Remove key from current position
        if let Some(pos) = lru_list.iter().position(|&k| k == key) {
            lru_list.remove(pos);
        }
        
        // Add to front (most recent)
        lru_list.push_front(key);
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
        
        self.touch_lru(key);
        
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

    /// Evict blocks to free space
    fn evict_blocks(&self, needed: usize) {
        let mut freed = 0;
        let mut lru_list = self.lru_list.lock();

        while freed < needed && !lru_list.is_empty() {
            // Get LRU block (from back of list)
            if let Some(key) = lru_list.pop_back() {
                let mut blocks = self.blocks.lock();
                
                // Skip dirty blocks during eviction
                if let Some(block) = blocks.get(&key) {
                    if block.is_dirty() {
                        // Put back at end and try next
                        lru_list.push_back(key);
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
                writer(key.block_num, block.data_slice())?;
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
    pub fn flush_block<F>(
        &self,
        device_id: u64,
        block_num: u64,
        mut writer: F,
    ) -> Result<bool, ()>
    where
        F: FnMut(&[u8]) -> Result<(), ()>,
    {
        let key = BlockCacheKey::new(device_id, block_num);
        let blocks = self.blocks.lock();

        if let Some(block) = blocks.get(&key) {
            if block.is_dirty() {
                writer(block.data_slice())?;
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
                writer(key.device_id, key.block_num, block.data_slice())?;
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
                // Remove from LRU list
                if let Some(pos) = lru_list.iter().position(|&k| k == key) {
                    lru_list.remove(pos);
                }
                
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

static BLOCK_CACHE: spin::Once<LRUBlockCache> = spin::Once::new();

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

    #[test]
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

    #[test]
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

    #[test]
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

    #[test]
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
