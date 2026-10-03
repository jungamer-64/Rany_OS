// ============================================================================
// src/mm/autonuma.rs - Automatic NUMA Page Migration
// ============================================================================
use crate::sync::PoisonLock;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use crate::mm::phys::frame_allocator::{self as pmm, FrameAllocError, PhysicalAllocation};
use crate::mm::types::{FixedVec, FrameIndex, NumaNodeId};
use crate::mm::virt::higher_half::{MapError, VirtAddr};

// ============================================================================
// NUMA Hint Fault 定数
// ============================================================================

const NUMA_MIGRATION_THRESHOLD: u32 = 4;
const NUMA_MIGRATION_COOLDOWN_MS: u64 = 10000;
const NUMA_SCAN_BATCH_SIZE: usize = 256;
const NUMA_SCAN_PERIOD_MS: u64 = 1000;
const SAS_SCAN_BASE: u64 = 0;

// ============================================================================
// ページアクセス統計
// ============================================================================

#[repr(C)]
pub struct PageNumaStats {
    node_access_counts: [AtomicU32; 8],
    last_access_time: AtomicU64,
    current_node: AtomicU8,
    migration_count: AtomicU8,
    last_migration_time: AtomicU64,
    flags: AtomicU32,
}

pub mod page_flags {
    pub const NUMA_HINT_FAULT_PENDING: u32 = 1 << 0;
    pub const NUMA_MIGRATION_HOT: u32 = 1 << 1;
    pub const NUMA_PINNED: u32 = 1 << 2;
    pub const NUMA_SHARED: u32 = 1 << 3;
}

impl PageNumaStats {
    pub const fn new() -> Self {
        const ZERO: AtomicU32 = AtomicU32::new(0);
        Self {
            node_access_counts: [ZERO; 8],
            last_access_time: AtomicU64::new(0),
            current_node: AtomicU8::new(0),
            migration_count: AtomicU8::new(0),
            last_migration_time: AtomicU64::new(0),
            flags: AtomicU32::new(0),
        }
    }

    #[inline]
    pub fn record_access(&self, node_id: usize, timestamp: u64) {
        if node_id < 8 {
            self.node_access_counts[node_id].fetch_add(1, Ordering::Relaxed);
        }
        self.last_access_time.store(timestamp, Ordering::Release);
    }

    pub fn get_hottest_node(&self) -> (usize, u32) {
        let mut max_node = 0;
        let mut max_count = 0;
        for (node, counter) in self.node_access_counts.iter().enumerate() {
            let count = counter.load(Ordering::Relaxed);
            if count > max_count {
                max_count = count;
                max_node = node;
            }
        }
        (max_node, max_count)
    }

    pub fn is_shared(&self) -> bool {
        let mut active_nodes = 0;
        for counter in &self.node_access_counts {
            if counter.load(Ordering::Relaxed) > 0 {
                active_nodes += 1;
            }
        }
        active_nodes > 1
    }

    pub fn reset_counts(&self) {
        for counter in &self.node_access_counts {
            counter.store(0, Ordering::Relaxed);
        }
    }

    pub fn can_migrate(&self, current_time: u64) -> bool {
        let flags = self.flags.load(Ordering::Acquire);
        if flags & page_flags::NUMA_PINNED != 0 {
            return false;
        }
        let last_migration = self.last_migration_time.load(Ordering::Acquire);
        if current_time.saturating_sub(last_migration) < NUMA_MIGRATION_COOLDOWN_MS {
            return false;
        }
        true
    }
}

static PAGE_NUMA_STATS: PoisonLock<BTreeMap<FrameIndex, Arc<PageNumaStats>>> =
    PoisonLock::new(BTreeMap::new());

pub fn get_page_numa_stats(frame: FrameIndex) -> Arc<PageNumaStats> {
    let mut guard = PAGE_NUMA_STATS.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .entry(frame)
        .or_insert_with(|| Arc::new(PageNumaStats::new()))
        .clone()
}

// ============================================================================
// NUMA Hint Fault ハンドラ
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumaFaultAction {
    RecordOnly,
    Migrate { from_node: u8, to_node: u8 },
    CannotMigrate,
}

pub fn handle_numa_fault(
    page_stats: &PageNumaStats,
    faulting_node: u8,
    current_time: u64,
) -> NumaFaultAction {
    page_stats.record_access(faulting_node as usize, current_time);
    let current_node = page_stats.current_node.load(Ordering::Acquire);
    if current_node == faulting_node {
        return NumaFaultAction::RecordOnly;
    }
    if !page_stats.can_migrate(current_time) {
        return NumaFaultAction::CannotMigrate;
    }
    let (hottest_node, access_count) = page_stats.get_hottest_node();
    if access_count < NUMA_MIGRATION_THRESHOLD {
        return NumaFaultAction::RecordOnly;
    }
    if page_stats.is_shared() {
        page_stats
            .flags
            .fetch_or(page_flags::NUMA_SHARED, Ordering::Release);
        return NumaFaultAction::CannotMigrate;
    }
    if hottest_node as u8 != current_node {
        NumaFaultAction::Migrate {
            from_node: current_node,
            to_node: hottest_node as u8,
        }
    } else {
        NumaFaultAction::RecordOnly
    }
}

// ============================================================================
// NUMA ページスキャナ
// ============================================================================

pub struct NumaScanner {
    enabled: AtomicU64,
    next_scan_time: AtomicU64,
    scan_period_ms: AtomicU64,
    scan_batch_size: AtomicU64,
    scan_cursor: AtomicU64,
    pages_scanned: AtomicU64,
    faults_set: AtomicU64,
}

impl NumaScanner {
    pub const fn new() -> Self {
        Self {
            enabled: AtomicU64::new(1),
            next_scan_time: AtomicU64::new(0),
            scan_period_ms: AtomicU64::new(NUMA_SCAN_PERIOD_MS),
            scan_batch_size: AtomicU64::new(NUMA_SCAN_BATCH_SIZE as u64),
            scan_cursor: AtomicU64::new(SAS_SCAN_BASE),
            pages_scanned: AtomicU64::new(0),
            faults_set: AtomicU64::new(0),
        }
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled
            .store(if enabled { 1 } else { 0 }, Ordering::Release);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire) != 0
    }

    pub fn set_scan_period(&self, period_ms: u64) {
        self.scan_period_ms.store(period_ms, Ordering::Release);
    }

    pub fn should_scan(&self, current_time: u64) -> bool {
        if !self.is_enabled() {
            return false;
        }
        let next_scan = self.next_scan_time.load(Ordering::Acquire);
        current_time >= next_scan
    }

    pub fn record_scan(&self, current_time: u64, pages_scanned: u64, faults_set: u64) {
        let period = self.scan_period_ms.load(Ordering::Relaxed);
        self.next_scan_time
            .store(current_time + period, Ordering::Release);
        self.pages_scanned
            .fetch_add(pages_scanned, Ordering::Relaxed);
        self.faults_set.fetch_add(faults_set, Ordering::Relaxed);
    }

    pub fn stats(&self) -> (u64, u64) {
        (
            self.pages_scanned.load(Ordering::Relaxed),
            self.faults_set.load(Ordering::Relaxed),
        )
    }

    pub fn scan_current_domain(&self) {
        if !self.is_enabled() {
            return;
        }
        let current_time = crate::time::current_time_ns();
        if !self.should_scan(current_time) {
            return;
        }
        let batch_size = self.scan_batch_size.load(Ordering::Relaxed);
        let _cursor = self.scan_cursor.load(Ordering::Relaxed);
        self.record_scan(current_time, batch_size, 0);
    }
}

pub fn try_scan_current_process() {
    NUMA_SCANNER.scan_current_domain();
}

pub static NUMA_SCANNER: NumaScanner = NumaScanner::new();

// ============================================================================
// NUMA マイグレーションエンジン
// ============================================================================

#[derive(Debug, Clone)]
pub struct MigrationRequest {
    pub address: VirtAddr,
    pub src_frame: FrameIndex,
    pub dest_node: u8,
    pub priority: u8,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationFailure {
    Allocation(FrameAllocError),
    Mapping(MapError),
    InvalidExtent,
    PageLocked,
    PagePinned,
}

/// Failed preparation/publication keeps the original mapping and RAM owner.
#[derive(Debug)]
pub struct PageMigrationError {
    pub cause: MigrationFailure,
    pub allocation: PhysicalAllocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationQueueRejection {
    Full,
    Poisoned,
}
const MAX_PENDING_MIGRATIONS: usize = 256;

pub struct MigrationEngine {
    pending_requests: PoisonLock<FixedVec<MigrationRequest, MAX_PENDING_MIGRATIONS>>,
    successful: AtomicU64,
    failed: AtomicU64,
    migrated_bytes: AtomicU64,
    batch_size: usize,
}

impl MigrationEngine {
    pub const fn new() -> Self {
        Self {
            pending_requests: PoisonLock::new(FixedVec::new()),
            successful: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            migrated_bytes: AtomicU64::new(0),
            batch_size: 32,
        }
    }

    /// Hints do not confer RAM authority. Admission is bounded and returns
    /// an unaccepted request, allowing its producer to defer or drop the hint.
    pub fn queue_migration(
        &self,
        request: MigrationRequest,
    ) -> Result<(), (MigrationQueueRejection, MigrationRequest)> {
        let Ok(mut pending) = self.pending_requests.lock() else {
            return Err((MigrationQueueRejection::Poisoned, request));
        };
        if pending.is_full() {
            return Err((MigrationQueueRejection::Full, request));
        }
        assert!(pending.push(request));
        // pop() selects highest priority then oldest timestamp without heap growth.
        pending.as_mut_slice().sort_unstable_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then_with(|| b.timestamp.cmp(&a.timestamp))
        });
        Ok(())
    }

    /// The mapping owner resolves each hint to its current allocation; a frame
    /// observation cannot recreate ownership after replacement or reuse. Work
    /// executes outside the queue lock and processes at most one fixed batch.
    pub fn process_batch<F>(&self, mut migrate_page: F) -> usize
    where
        F: FnMut(MigrationRequest) -> Result<(), MigrationFailure>,
    {
        let mut processed = 0;
        for _ in 0..self.batch_size {
            let request = self
                .pending_requests
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pop();
            let Some(request) = request else {
                break;
            };
            match migrate_page(request) {
                Ok(()) => {
                    self.successful.fetch_add(1, Ordering::Relaxed);
                    self.migrated_bytes.fetch_add(4096, Ordering::Relaxed);
                }
                Err(_) => {
                    self.failed.fetch_add(1, Ordering::Relaxed);
                }
            }
            processed += 1;
        }
        processed
    }

    pub fn stats(&self) -> MigrationStats {
        MigrationStats {
            successful: self.successful.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            migrated_bytes: self.migrated_bytes.load(Ordering::Relaxed),
            pending: self
                .pending_requests
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MigrationStats {
    pub successful: u64,
    pub failed: u64,
    pub migrated_bytes: u64,
    pub pending: usize,
}

pub static MIGRATION_ENGINE: MigrationEngine = MigrationEngine::new();

// ============================================================================
// Phase 7: NUMA Page Migration Implementation
// ============================================================================

/// Move one exclusively owned 4KiB mapping to the explicitly requested node.
/// Source RAM remains retained until one-leaf replacement and TLB completion.
/// Failure returns the original owner and leaves its mapping unchanged.
/// # Safety
/// The caller owns this mapping and excludes payload borrowers, DMA and other
/// aliases except the immutable HHDM. It must retain the returned owner for the
/// mapping's lifetime, including on failure, and validate queued hint identity
/// against its current owner before invoking this operation.
pub unsafe fn migrate_numa_page(
    allocation: PhysicalAllocation,
    address: VirtAddr,
    destination_node: NumaNodeId,
) -> Result<PhysicalAllocation, PageMigrationError> {
    if allocation.page_count() != 1 || !address.is_page_aligned() {
        return Err(PageMigrationError {
            cause: MigrationFailure::InvalidExtent,
            allocation,
        });
    }
    if allocation.node() == destination_node {
        return Ok(allocation);
    }
    let destination = match pmm::alloc_contiguous_frames_aligned_on_node(destination_node, 1, 4096)
    {
        Ok(destination) => destination,
        Err(cause) => {
            return Err(PageMigrationError {
                cause: MigrationFailure::Allocation(cause),
                allocation,
            });
        }
    };
    let source_pointer =
        crate::mm::virt::mapping::phys_to_virt(allocation.start_address()).as_ptr::<u8>();
    let destination_pointer =
        crate::mm::virt::mapping::phys_to_virt(destination.start_address()).as_mut_ptr::<u8>();
    // SAFETY: the two exclusive physical owners prove disjoint valid 4KiB RAM;
    // caller excludes all writers and retains their HHDM views for the copy.
    unsafe { core::ptr::copy_nonoverlapping(source_pointer, destination_pointer, 4096) };
    // SAFETY: caller owns this sole mutable mapping and both RAM allocations.
    // Success consumes the old RAM only after its translation is retired.
    match unsafe {
        crate::mm::virt::higher_half::global_replace_owned_page(address, allocation, &destination)
    } {
        Ok(()) => Ok(destination),
        Err((cause, allocation)) => {
            destination.release();
            Err(PageMigrationError {
                cause: MigrationFailure::Mapping(cause),
                allocation,
            })
        }
    }
}

pub fn suggest_migration(
    task_preferred_node: u8,
    page_stats: &PageNumaStats,
    frame: FrameIndex,
    address: VirtAddr,
    current_time: u64,
) -> Option<MigrationRequest> {
    let current_node = page_stats.current_node.load(Ordering::Acquire);
    if current_node == task_preferred_node {
        return None;
    }
    if !page_stats.can_migrate(current_time) {
        return None;
    }
    let (hottest_node, access_count) = page_stats.get_hottest_node();
    let priority = if access_count >= NUMA_MIGRATION_THRESHOLD * 2 {
        10
    } else if access_count >= NUMA_MIGRATION_THRESHOLD {
        5
    } else {
        return None;
    };
    let dest_node = if hottest_node as u8 == task_preferred_node {
        task_preferred_node
    } else {
        let from = NumaNodeId::new(current_node);
        match (
            pmm::node_distance(from, NumaNodeId::new(task_preferred_node)),
            pmm::node_distance(from, NumaNodeId::new(hottest_node as u8)),
        ) {
            (Some(task), Some(hot)) if task <= hot => task_preferred_node,
            (Some(_), None) => task_preferred_node,
            (_, Some(_)) => hottest_node as u8,
            (None, None) => return None,
        }
    };
    Some(MigrationRequest {
        address,
        src_frame: frame,
        dest_node,
        priority,
        timestamp: current_time,
    })
}

pub fn get_numa_migration_summary() -> NumaMigrationSummary {
    let engine_stats = MIGRATION_ENGINE.stats();
    let (pages_scanned, faults_set) = NUMA_SCANNER.stats();
    NumaMigrationSummary {
        pages_scanned,
        faults_set,
        migrations_successful: engine_stats.successful,
        migrations_failed: engine_stats.failed,
        migrated_bytes: engine_stats.migrated_bytes,
        pending_migrations: engine_stats.pending,
    }
}

#[derive(Debug, Clone)]
pub struct NumaMigrationSummary {
    pub pages_scanned: u64,
    pub faults_set: u64,
    pub migrations_successful: u64,
    pub migrations_failed: u64,
    pub migrated_bytes: u64,
    pub pending_migrations: usize,
}

// ============================================================================
// PTEヘルパー
// ============================================================================

pub trait NumaPteOps {
    unsafe fn set_numa_hint(&mut self);
    unsafe fn clear_numa_hint(&mut self);
    fn has_numa_hint(&self) -> bool;
}

pub mod pte_flags {
    pub const PRESENT: u64 = 1 << 0;
    pub const ACCESSED: u64 = 1 << 5;
    pub const NUMA_HINT: u64 = 1 << 62;
}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct RawPte(pub u64);

impl NumaPteOps for RawPte {
    unsafe fn set_numa_hint(&mut self) {
        self.0 = (self.0 & !pte_flags::PRESENT) | pte_flags::NUMA_HINT;
    }
    unsafe fn clear_numa_hint(&mut self) {
        self.0 = (self.0 | pte_flags::PRESENT) & !pte_flags::NUMA_HINT;
    }
    fn has_numa_hint(&self) -> bool {
        (self.0 & pte_flags::PRESENT) == 0 && (self.0 & pte_flags::NUMA_HINT) != 0
    }
}

// ============================================================================
// 設定
// ============================================================================

pub struct AutoNumaConfig {
    pub enabled: bool,
    pub migration_threshold: u32,
    pub cooldown_ms: u64,
    pub scan_period_ms: u64,
    pub scan_batch_size: usize,
}

impl Default for AutoNumaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            migration_threshold: NUMA_MIGRATION_THRESHOLD,
            cooldown_ms: NUMA_MIGRATION_COOLDOWN_MS,
            scan_period_ms: NUMA_SCAN_PERIOD_MS,
            scan_batch_size: NUMA_SCAN_BATCH_SIZE,
        }
    }
}

pub fn apply_config(config: &AutoNumaConfig) {
    NUMA_SCANNER.set_enabled(config.enabled);
    NUMA_SCANNER.set_scan_period(config.scan_period_ms);
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn bounded_hint_queue_preserves_priority_and_releases_lock_before_work() {
        let engine = MigrationEngine::new();
        for index in 0..MAX_PENDING_MIGRATIONS {
            engine
                .queue_migration(MigrationRequest {
                    address: VirtAddr::new((index as u64 + 1) * 4096),
                    src_frame: FrameIndex::new(index + 1),
                    dest_node: 1,
                    priority: (index % 4) as u8,
                    timestamp: index as u64,
                })
                .unwrap();
        }
        let extra = MigrationRequest {
            address: VirtAddr::new(0x1000),
            src_frame: FrameIndex::new(1),
            dest_node: 1,
            priority: 9,
            timestamp: 999,
        };
        let (reason, returned) = engine.queue_migration(extra).unwrap_err();
        assert_eq!(reason, MigrationQueueRejection::Full);
        assert_eq!(returned.timestamp, 999);
        let mut visited = 0;
        assert_eq!(
            engine.process_batch(|hint| {
                assert_eq!(hint.priority, 3);
                assert_eq!(hint.timestamp, 3 + visited * 4);
                assert_eq!(
                    engine.stats().pending,
                    MAX_PENDING_MIGRATIONS - visited as usize - 1
                );
                visited += 1;
                Ok(())
            }),
            32
        );
        assert_eq!(engine.stats().successful, 32);
        assert_eq!(engine.stats().migrated_bytes, 32 * 4096);
        assert_eq!(
            engine.process_batch(|_| Err(MigrationFailure::PagePinned)),
            32
        );
        assert_eq!(engine.stats().failed, 32);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_page_numa_stats_access() {
        let stats = PageNumaStats::new();
        stats.record_access(0, 1000);
        stats.record_access(0, 2000);
        stats.record_access(1, 3000);
        let (hottest, count) = stats.get_hottest_node();
        assert_eq!(hottest, 0);
        assert_eq!(count, 2);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_page_numa_stats_shared() {
        let stats = PageNumaStats::new();
        stats.record_access(0, 1000);
        assert!(!stats.is_shared());
        stats.record_access(1, 2000);
        assert!(stats.is_shared());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_numa_fault_action_local() {
        let stats = PageNumaStats::new();
        stats.current_node.store(0, Ordering::Relaxed);
        let action = handle_numa_fault(&stats, 0, 1000);
        assert_eq!(action, NumaFaultAction::RecordOnly);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_raw_pte_numa_hint() {
        let mut pte = RawPte(pte_flags::PRESENT);
        assert!(!pte.has_numa_hint());
        unsafe {
            pte.set_numa_hint();
        }
        assert!(pte.has_numa_hint());
        assert_eq!(pte.0 & pte_flags::PRESENT, 0);
        unsafe {
            pte.clear_numa_hint();
        }
        assert!(!pte.has_numa_hint());
        assert_ne!(pte.0 & pte_flags::PRESENT, 0);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_numa_fault_action_migrate() {
        let stats = PageNumaStats::new();
        stats.current_node.store(0, Ordering::Relaxed);
        let access_count = NUMA_MIGRATION_THRESHOLD + 1;
        for _ in 0..access_count {
            stats.record_access(1, 1000);
        }
        let current_time = NUMA_MIGRATION_COOLDOWN_MS + 1000;
        let (hottest, count) = stats.get_hottest_node();
        assert_eq!(hottest, 1);
        assert!(count >= access_count);
        let action = handle_numa_fault(&stats, 1, current_time);
        if let NumaFaultAction::Migrate { from_node, to_node } = action {
            assert_eq!(from_node, 0);
            assert_eq!(to_node, 1);
        } else {
            panic!("Expected Migrate action, got {:?}", action);
        }
    }
}
