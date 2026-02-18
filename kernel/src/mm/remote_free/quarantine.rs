use super::*;


impl QuarantineEntry {
    /// Create an empty/invalid entry
    #[inline]
    pub const fn empty() -> Self {
        Self {
            addr: 0,
            size_class: 0,
            epoch: 0,
        }
    }
    
    /// Create a new quarantine entry
    #[inline]
    pub const fn new(addr: u64, size_class: u8, epoch: u32) -> Self {
        Self {
            addr,
            size_class,
            epoch,
        }
    }
    
    /// Check if this is an empty/invalid entry
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.addr == 0 && self.size_class == 0
    }
    
    /// Get the page size for this entry's size class
    #[inline]
    pub const fn page_size(&self) -> u64 {
        match self.size_class {
            0 => PAGE_SIZE_4K as u64,
            1 => PAGE_SIZE_2M as u64,
            2 => PAGE_SIZE_1G as u64,
            _ => PAGE_SIZE_4K as u64,
        }
    }
}

impl Default for QuarantineEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// ============================================================================
// Quarantine Ring (Single-CPU FIFO with Epoch-Based Drain)
// ============================================================================

/// Per-CPU quarantine ring buffer for delayed reclamation
///
/// Addresses are not returned to the allocator immediately after free. Instead,
/// they are placed in a quarantine ring. After a certain epoch passes (e.g.,
/// IOTLB invalidation completes), quarantined entries are batch-returned.
///
/// # Benefits
/// - Prevents IOTLB stale entry issues (UAF via DMA)
/// - Reduces allocator write frequency (batch returns)
/// - Simple FIFO semantics (no lock-free complexity needed)
///
/// # Thread Safety
/// - Each CPU has its own quarantine ring (no contention)
/// - Protected by IRQ-off guard or caller synchronization
///
/// # Type Parameter
/// - `N`: Ring capacity
#[repr(C, align(128))]
pub struct QuarantineRing<const N: usize = DEFAULT_QUARANTINE_CAPACITY> {
    /// Ring buffer entries
    entries: [QuarantineEntry; N],
    /// Write position (head)
    head: usize,
    /// Read position (tail, for drain)
    tail: usize,
    /// Number of valid entries
    count: usize,
}

impl<const N: usize> QuarantineRing<N> {
    /// Create an empty quarantine ring
    pub const fn new() -> Self {
        Self {
            entries: [QuarantineEntry::empty(); N],
            head: 0,
            tail: 0,
            count: 0,
        }
    }
    
    /// Get the ring capacity
    #[inline]
    pub const fn capacity(&self) -> usize {
        N
    }
    
    /// Try to add an entry to quarantine (O(1))
    ///
    /// Returns false if the ring is full (caller should drain first).
    #[inline]
    pub fn push(&mut self, addr: u64, size_class: u8, epoch: u32) -> bool {
        if self.count >= N {
            return false;
        }
        
        self.entries[self.head] = QuarantineEntry {
            addr,
            size_class,
            epoch,
        };
        self.head = (self.head + 1) % N;
        self.count += 1;
        true
    }
    
    /// Push a QuarantineEntry directly
    #[inline]
    pub fn push_entry(&mut self, entry: QuarantineEntry) -> bool {
        self.push(entry.addr, entry.size_class, entry.epoch)
    }
    
    /// Pop entries that are older than the given epoch
    ///
    /// Returns up to `max` entries that have `epoch <= completed_epoch`.
    /// Entries are removed from the ring in FIFO order.
    ///
    /// # Epoch Wrap-around Handling
    /// Uses signed comparison to handle 32-bit epoch wrap-around correctly.
    pub fn drain_older_than(&mut self, completed_epoch: u32, max: usize, out: &mut [QuarantineEntry]) -> usize {
        let mut drained = 0;
        
        while drained < max && drained < out.len() && self.count > 0 {
            let entry = &self.entries[self.tail];
            
            // Only drain if epoch has passed
            // Handle wrap-around: completed_epoch - entry.epoch should be positive
            let age = completed_epoch.wrapping_sub(entry.epoch) as i32;
            if age < 0 {
                // Entry is from a future epoch, stop draining
                break;
            }
            
            out[drained] = *entry;
            self.tail = (self.tail + 1) % N;
            self.count -= 1;
            drained += 1;
        }
        
        drained
    }
    
    /// Drain with a closure (more efficient when you don't need to store entries)
    pub fn drain_older_than_with<F>(&mut self, completed_epoch: u32, max: usize, mut f: F) -> usize
    where
        F: FnMut(QuarantineEntry),
    {
        let mut drained = 0;
        
        while drained < max && self.count > 0 {
            let entry = &self.entries[self.tail];
            
            let age = completed_epoch.wrapping_sub(entry.epoch) as i32;
            if age < 0 {
                break;
            }
            
            f(*entry);
            self.tail = (self.tail + 1) % N;
            self.count -= 1;
            drained += 1;
        }
        
        drained
    }
    
    /// Force drain all entries (for shutdown or emergency)
    pub fn drain_all(&mut self, out: &mut [QuarantineEntry]) -> usize {
        let mut drained = 0;
        
        while drained < out.len() && self.count > 0 {
            out[drained] = self.entries[self.tail];
            self.tail = (self.tail + 1) % N;
            self.count -= 1;
            drained += 1;
        }
        
        drained
    }
    
    /// Force drain all entries with a closure
    pub fn drain_all_with<F>(&mut self, mut f: F) -> usize
    where
        F: FnMut(QuarantineEntry),
    {
        let mut drained = 0;
        
        while self.count > 0 {
            f(self.entries[self.tail]);
            self.tail = (self.tail + 1) % N;
            self.count -= 1;
            drained += 1;
        }
        
        drained
    }
    
    /// Peek at the oldest entry without removing it
    #[inline]
    pub fn peek(&self) -> Option<&QuarantineEntry> {
        if self.count > 0 {
            Some(&self.entries[self.tail])
        } else {
            None
        }
    }
    
    /// Get the epoch of the oldest entry (if any)
    #[inline]
    pub fn oldest_epoch(&self) -> Option<u32> {
        self.peek().map(|e| e.epoch)
    }
    
    /// Get current count
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }
    
    /// Check if empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    
    /// Check if full
    #[inline]
    pub fn is_full(&self) -> bool {
        self.count >= N
    }
    
    /// Get remaining capacity
    #[inline]
    pub fn remaining(&self) -> usize {
        N.saturating_sub(self.count)
    }
    
    /// Clear all entries
    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }
}

impl<const N: usize> Default for QuarantineRing<N> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// IOVA-Compatible Entry Types (for iova_bitmap.rs integration)
// ============================================================================

/// IOVA-specific remote free entry with `iova` field name for backward compatibility
///
/// This is a thin wrapper that provides the `iova` field name expected by
/// `iova_bitmap.rs` while internally using `RemoteFreeEntry`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct IovaFreeEntry {
    /// IOVA address to be freed (start of range)
    pub iova: u64,
    /// Number of contiguous pages (1 = single page, N = N pages)
    pub count: u16,
    /// Size class: 0 = 4KB, 1 = 2MB, 2 = 1GB
    pub size_class: u8,
}

impl IovaFreeEntry {
    /// Create an empty/invalid entry
    #[inline]
    pub const fn empty() -> Self {
        Self {
            iova: 0,
            count: 0,
            size_class: 0,
        }
    }
    
    /// Create a single-page entry
    #[inline]
    pub const fn single(iova: u64, size_class: u8) -> Self {
        Self {
            iova,
            count: 1,
            size_class,
        }
    }
    
    /// Create a range entry for multiple contiguous pages
    #[inline]
    pub const fn range(iova: u64, count: u16, size_class: u8) -> Self {
        Self {
            iova,
            count,
            size_class,
        }
    }
    
    /// Check if this is an empty/invalid entry
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
    
    /// Get the page size for this entry's size class
    #[inline]
    pub const fn page_size(&self) -> u64 {
        match self.size_class {
            0 => PAGE_SIZE_4K as u64,
            1 => PAGE_SIZE_2M as u64,
            2 => PAGE_SIZE_1G as u64,
            _ => PAGE_SIZE_4K as u64,
        }
    }
    
    /// Get total bytes covered by this entry
    #[inline]
    pub fn total_bytes(&self) -> u64 {
        self.page_size() * (self.count as u64)
    }
    
    /// Convert from generic RemoteFreeEntry
    #[inline]
    pub const fn from_generic(entry: RemoteFreeEntry) -> Self {
        Self {
            iova: entry.addr,
            count: entry.count,
            size_class: entry.size_class,
        }
    }
    
    /// Convert to generic RemoteFreeEntry
    #[inline]
    pub const fn to_generic(self) -> RemoteFreeEntry {
        RemoteFreeEntry {
            addr: self.iova,
            count: self.count,
            size_class: self.size_class,
        }
    }
}

impl Default for IovaFreeEntry {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<RemoteFreeEntry> for IovaFreeEntry {
    #[inline]
    fn from(entry: RemoteFreeEntry) -> Self {
        Self::from_generic(entry)
    }
}

impl From<IovaFreeEntry> for RemoteFreeEntry {
    #[inline]
    fn from(entry: IovaFreeEntry) -> Self {
        entry.to_generic()
    }
}

/// IOVA-specific quarantine entry with `iova` field name for backward compatibility
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct IovaQuarantineEntry {
    /// IOVA address to be freed
    pub iova: u64,
    /// Size class: 0 = 4KB, 1 = 2MB, 2 = 1GB
    pub size_class: u8,
    /// Epoch when this entry was quarantined
    pub epoch: u32,
}

impl IovaQuarantineEntry {
    /// Create an empty/invalid entry
    #[inline]
    pub const fn empty() -> Self {
        Self {
            iova: 0,
            size_class: 0,
            epoch: 0,
        }
    }
    
    /// Create a new quarantine entry
    #[inline]
    pub const fn new(iova: u64, size_class: u8, epoch: u32) -> Self {
        Self {
            iova,
            size_class,
            epoch,
        }
    }
    
    /// Check if this is an empty/invalid entry
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.iova == 0 && self.size_class == 0
    }
    
    /// Convert from generic QuarantineEntry
    #[inline]
    pub const fn from_generic(entry: QuarantineEntry) -> Self {
        Self {
            iova: entry.addr,
            size_class: entry.size_class,
            epoch: entry.epoch,
        }
    }
    
    /// Convert to generic QuarantineEntry
    #[inline]
    pub const fn to_generic(self) -> QuarantineEntry {
        QuarantineEntry {
            addr: self.iova,
            size_class: self.size_class,
            epoch: self.epoch,
        }
    }
}

impl Default for IovaQuarantineEntry {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<QuarantineEntry> for IovaQuarantineEntry {
    #[inline]
    fn from(entry: QuarantineEntry) -> Self {
        Self::from_generic(entry)
    }
}

impl From<IovaQuarantineEntry> for QuarantineEntry {
    #[inline]
    fn from(entry: IovaQuarantineEntry) -> Self {
        entry.to_generic()
    }
}

// ============================================================================
// Type Aliases for Common Use Cases
// ============================================================================

/// IOVA allocator remote free ring (512 entries)
pub type IovaRemoteFreeRing = RemoteFreeRing<512>;

/// IOVA allocator quarantine ring (256 entries)  
pub type IovaQuarantineRing = QuarantineRing<256>;

/// Physical frame allocator remote free ring (larger for higher throughput)
pub type FrameRemoteFreeRing = RemoteFreeRing<1024>;

/// Physical frame allocator quarantine ring
pub type FrameQuarantineRing = QuarantineRing<512>;

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

// ============================================================================
// Remote Free Drain Coalescing
// ============================================================================

/// ドレイン時の連続アドレス結合のためのヘルパー
///
/// Drain中に連続するアドレスを検出し、より大きなブロックとして
/// Buddyアロケータに返却することで、断片化を軽減する。
pub mod coalescing {
    use super::*;
    use alloc::vec::Vec;

    /// 結合結果
    #[derive(Debug, Clone)]
    pub struct CoalescedEntry {
        /// 開始アドレス
        pub addr: u64,
        /// ページ数（同サイズクラス内）
        pub count: u32,
        /// サイズクラス (0=4KB, 1=2MB, 2=1GB)
        pub size_class: u8,
    }

    impl CoalescedEntry {
        /// 1つのエントリから作成
        pub fn from_single(entry: &RemoteFreeEntry) -> Self {
            Self {
                addr: entry.addr,
                count: entry.count as u32,
                size_class: entry.size_class,
            }
        }

        /// ページサイズを取得
        #[inline]
        pub fn page_size(&self) -> u64 {
            match self.size_class {
                0 => PAGE_SIZE_4K as u64,
                1 => PAGE_SIZE_2M as u64,
                2 => PAGE_SIZE_1G as u64,
                _ => PAGE_SIZE_4K as u64,
            }
        }

        /// 終端アドレスを取得
        #[inline]
        pub fn end_addr(&self) -> u64 {
            self.addr + self.page_size() * (self.count as u64)
        }

        /// 別のエントリを結合可能かチェック
        #[inline]
        pub fn can_merge(&self, other: &RemoteFreeEntry) -> bool {
            // 同じサイズクラスで、連続していれば結合可能
            self.size_class == other.size_class && self.end_addr() == other.addr
        }

        /// 別のエントリを結合
        pub fn merge(&mut self, other: &RemoteFreeEntry) {
            debug_assert!(self.can_merge(other));
            self.count += other.count as u32;
        }
    }

    /// RemoteFreeEntryの配列を結合
    ///
    /// # 戦略
    /// 1. サイズクラスでソート
    /// 2. 同クラス内でアドレスでソート
    /// 3. 連続アドレスを結合
    pub fn coalesce_entries(entries: &[RemoteFreeEntry]) -> Vec<CoalescedEntry> {
        if entries.is_empty() {
            return Vec::new();
        }

        // エントリをコピーしてソート
        let mut sorted: Vec<_> = entries.iter()
            .filter(|e| !e.is_empty())
            .cloned()
            .collect();

        // サイズクラス→アドレス順でソート
        sorted.sort_by(|a, b| {
            a.size_class.cmp(&b.size_class)
                .then(a.addr.cmp(&b.addr))
        });

        let mut result = Vec::with_capacity(sorted.len());
        let mut current: Option<CoalescedEntry> = None;

        for entry in &sorted {
            match &mut current {
                Some(c) if c.can_merge(entry) => {
                    c.merge(entry);
                }
                Some(c) => {
                    result.push(c.clone());
                    current = Some(CoalescedEntry::from_single(entry));
                }
                None => {
                    current = Some(CoalescedEntry::from_single(entry));
                }
            }
        }

        if let Some(c) = current {
            result.push(c);
        }

        result
    }

    /// ドレインと結合を一度に実行
    ///
    /// RemoteFreeRingからエントリをドレインしながら、
    /// 連続アドレスを検出して結合する。
    pub fn drain_and_coalesce<const N: usize>(
        ring: &RemoteFreeRing<N>,
        max_entries: usize,
    ) -> Vec<CoalescedEntry> {
        let mut entries = alloc::vec![RemoteFreeEntry::empty(); max_entries.min(N)];
        let drained = ring.drain(&mut entries);
        
        if drained == 0 {
            return Vec::new();
        }

        coalesce_entries(&entries[..drained])
    }

    /// Buddyアロケータへ返却時の結合最適化
    ///
    /// 連続した4KBページがBuddyの上位オーダーに相当する場合、
    /// 上位オーダーとして一括解放可能かチェックする。
    pub fn can_promote_to_higher_order(entry: &CoalescedEntry) -> Option<(u64, usize)> {
        if entry.size_class != 0 {
            return None; // 4KB以外は対象外
        }

        let pages = entry.count as usize;
        
        // Order 0 = 1ページ, Order 1 = 2ページ, ... Order 9 = 512ページ (2MB)
        // 2のべき乗かつアラインされていれば上位オーダーで解放可能
        
        for order in (1..=9).rev() {
            let block_pages = 1usize << order;
            if pages >= block_pages {
                let block_size_bytes = block_pages * PAGE_SIZE_4K;
                // アラインメントチェック
                if entry.addr % (block_size_bytes as u64) == 0 {
                    return Some((entry.addr, order));
                }
            }
        }

        None
    }

    /// 結合統計
    #[derive(Debug, Default, Clone, Copy)]
    pub struct CoalesceStats {
        /// 入力エントリ数
        pub input_entries: u64,
        /// 出力エントリ数（結合後）
        pub output_entries: u64,
        /// 結合されたページ数
        pub pages_coalesced: u64,
        /// 上位オーダーへ昇格したブロック数
        pub order_promotions: u64,
    }

    impl CoalesceStats {
        /// 結合率を計算 (1.0 = 全て結合, 0.0 = 結合なし)
        pub fn coalesce_ratio(&self) -> f64 {
            if self.input_entries == 0 {
                return 0.0;
            }
            1.0 - (self.output_entries as f64 / self.input_entries as f64)
        }
    }

    /// グローバル結合統計
    pub(super) static COALESCE_STATS: core::sync::atomic::AtomicU64 = 
        core::sync::atomic::AtomicU64::new(0);

    /// 結合統計を更新
    pub fn update_stats(input: usize, output: usize) {
        // 簡易的な統計: 結合した数を記録
        let coalesced = input.saturating_sub(output) as u64;
        COALESCE_STATS.fetch_add(coalesced, core::sync::atomic::Ordering::Relaxed);
    }

    /// 総結合数を取得
    pub fn total_coalesced() -> u64 {
        COALESCE_STATS.load(core::sync::atomic::Ordering::Relaxed)
    }
}


