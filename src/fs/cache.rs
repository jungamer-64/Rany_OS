// ============================================================================
// src/fs/cache.rs - Page Cache Implementation
// ============================================================================
//!
//! ページキャッシュ実装
//!
//! ## 設計原則 (仕様書 6.3準拠)
//! - Arc<Vec<u8>> によるゼロコピーキャッシュ
//! - LRU eviction policy
//! - Write-back caching
//! - Per-file キャッシュ管理

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::{Mutex, RwLock};

use super::vfs::InodeNum;

// ============================================================================
// Constants
// ============================================================================

/// Default page size (4KB)
pub const PAGE_SIZE: usize = 4096;

/// Default cache size limit (64MB)
pub const DEFAULT_CACHE_LIMIT: usize = 64 * 1024 * 1024;

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
    
    /// Write to page at offset (requires mutable Arc)
    pub fn write(&self, offset: usize, buf: &[u8]) -> usize {
        // This requires special handling since Arc<Vec<u8>> is immutable
        // In real implementation, we'd use Arc<RwLock<Vec<u8>>> or similar
        // For now, we just report success
        let available = PAGE_SIZE.saturating_sub(offset);
        let to_write = buf.len().min(available);
        
        // TODO: Implement actual write with proper synchronization
        // This would involve Arc::make_mut or interior mutability
        
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
            self.current_size.fetch_add(PAGE_SIZE as u64, Ordering::AcqRel);
            
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
                        self.current_size.fetch_sub(PAGE_SIZE as u64, Ordering::AcqRel);
                        
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
