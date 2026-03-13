// ============================================================================
// src/mm/autonuma.rs - Automatic NUMA Page Migration
// ============================================================================
#![allow(dead_code)]

use crate::sync::PoisonLock;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use crate::mm::types::{FrameIndex, NumaNodeId};

// ============================================================================
// NUMA Hint Fault 定数
// ============================================================================

const NUMA_HINT_FAULT_INTERVAL_MS: u64 = 1000;
const NUMA_MIGRATION_THRESHOLD: u32 = 4;
const NUMA_MIGRATION_COOLDOWN_MS: u64 = 10000;
const NUMA_SCAN_BATCH_SIZE: usize = 256;
const NUMA_SCAN_PERIOD_MS: u64 = 1000;

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
            scan_cursor: AtomicU64::new(crate::mm::virt::address_space::USER_SPACE_START),
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
        let address_space_manager = crate::mm::virt::address_space::address_space_manager();
        let scan_addr_val = self.scan_cursor.load(Ordering::Relaxed);
        let scan_addr = crate::mm::virt::higher_half::VirtAddr::new(scan_addr_val);
        let batch_size = self.scan_batch_size.load(Ordering::Relaxed) as usize;

        if let Some((scanned, faults, next_addr)) =
            address_space_manager.scan_current_address_space(scan_addr, batch_size)
        {
            let next_val = if next_addr.as_u64() >= crate::mm::virt::address_space::USER_SPACE_END {
                crate::mm::virt::address_space::USER_SPACE_START
            } else {
                next_addr.as_u64()
            };
            self.scan_cursor.store(next_val, Ordering::Release);
            self.record_scan(current_time, scanned as u64, faults as u64);
        }
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
    pub src_frame: FrameIndex,
    pub dest_node: u8,
    pub priority: u8,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationResult {
    Success,
    NoMemory,
    PageLocked,
    PagePinned,
    Failed,
}

pub struct MigrationEngine {
    pending_requests: PoisonLock<Vec<MigrationRequest>>,
    successful: AtomicU64,
    failed: AtomicU64,
    migrated_bytes: AtomicU64,
    batch_size: usize,
}

impl MigrationEngine {
    pub const fn new() -> Self {
        Self {
            pending_requests: PoisonLock::new(Vec::new()),
            successful: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            migrated_bytes: AtomicU64::new(0),
            batch_size: 32,
        }
    }

    pub fn queue_migration(&self, request: MigrationRequest) {
        let mut pending = self
            .pending_requests
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pending.push(request);
        pending.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| a.timestamp.cmp(&b.timestamp))
        });
    }

    pub unsafe fn process_batch<F>(&self, mut migrate_page: F) -> usize
    where
        F: FnMut(FrameIndex, u8) -> MigrationResult,
    {
        let mut processed = 0;
        let mut pending = self
            .pending_requests
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while processed < self.batch_size && !pending.is_empty() {
            let request = pending.remove(0);
            let result = migrate_page(request.src_frame, request.dest_node);
            match result {
                MigrationResult::Success => {
                    self.successful.fetch_add(1, Ordering::Relaxed);
                    self.migrated_bytes.fetch_add(4096, Ordering::Relaxed);
                }
                _ => {
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
// NUMA Distance Cache
// ============================================================================

pub const MAX_NUMA_NODES: usize = 8;
pub type NumaDistance = u8;

pub struct NumaDistanceCache {
    distance_table: [[AtomicU8; MAX_NUMA_NODES]; MAX_NUMA_NODES],
    sorted_nodes: [[AtomicU8; MAX_NUMA_NODES]; MAX_NUMA_NODES],
    num_nodes: AtomicU8,
    initialized: AtomicU8,
}

impl NumaDistanceCache {
    pub const fn new() -> Self {
        const ZERO_U8: AtomicU8 = AtomicU8::new(0);
        const ROW_ZERO: [AtomicU8; MAX_NUMA_NODES] = [ZERO_U8; MAX_NUMA_NODES];
        const NODE_ZERO: [AtomicU8; MAX_NUMA_NODES] = [ZERO_U8; MAX_NUMA_NODES];
        Self {
            distance_table: [ROW_ZERO; MAX_NUMA_NODES],
            sorted_nodes: [NODE_ZERO; MAX_NUMA_NODES],
            num_nodes: AtomicU8::new(1),
            initialized: AtomicU8::new(0),
        }
    }

    pub fn init_from_slit(&self, num_nodes: usize, distances: &[&[u8]]) {
        let num = num_nodes.min(MAX_NUMA_NODES);
        self.num_nodes.store(num as u8, Ordering::Relaxed);
        for from in 0..num {
            for to in 0..num {
                let dist = if from < distances.len() && to < distances[from].len() {
                    distances[from][to]
                } else if from == to {
                    10
                } else {
                    20
                };
                self.distance_table[from][to].store(dist, Ordering::Relaxed);
            }
        }
        self.compute_sorted_nodes(num);
        self.initialized.store(1, Ordering::Release);
    }

    fn compute_sorted_nodes(&self, num_nodes: usize) {
        for from in 0..num_nodes {
            let mut nodes_with_dist: [(u8, u8); MAX_NUMA_NODES] = [(0, 255); MAX_NUMA_NODES];
            for to in 0..num_nodes {
                let dist = self.distance_table[from][to].load(Ordering::Relaxed);
                nodes_with_dist[to] = (to as u8, dist);
            }
            for i in 1..num_nodes {
                let mut j = i;
                // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
                while j > 0 && nodes_with_dist[j - 1].1 > nodes_with_dist[j].1 {
                    nodes_with_dist.swap(j - 1, j);
                    j -= 1;
                }
            }
            for (idx, (node_id, _)) in nodes_with_dist.iter().enumerate().take(num_nodes) {
                self.sorted_nodes[from][idx].store(*node_id, Ordering::Relaxed);
            }
        }
    }

    #[inline]
    pub fn nodes_by_distance(&self, from_node: usize) -> &[AtomicU8; MAX_NUMA_NODES] {
        let from = from_node.min(MAX_NUMA_NODES - 1);
        &self.sorted_nodes[from]
    }

    #[inline]
    pub fn get_distance(&self, from: usize, to: usize) -> u8 {
        if from >= MAX_NUMA_NODES || to >= MAX_NUMA_NODES {
            return 255;
        }
        self.distance_table[from][to].load(Ordering::Relaxed)
    }

    #[inline]
    pub fn node_count(&self) -> usize {
        self.num_nodes.load(Ordering::Relaxed) as usize
    }

    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire) != 0
    }

    pub fn iter_by_distance(&self, from_node: usize) -> impl Iterator<Item = u8> + '_ {
        let num = self.node_count();
        let from = from_node.min(MAX_NUMA_NODES - 1);
        (0..num).map(move |idx| self.sorted_nodes[from][idx].load(Ordering::Relaxed))
    }
}

pub static NUMA_DISTANCE_CACHE: NumaDistanceCache = NumaDistanceCache::new();

// ============================================================================
// Phase 7: NUMA Page Migration Implementation
// ============================================================================

pub unsafe fn migrate_numa_page(src_frame: FrameIndex, dest_node: u8) -> MigrationResult {
    use crate::mm::phys::buddy_allocator;
    use crate::mm::types::PAGE_SIZE_4K;
    let dest_frame = match buddy_allocator::buddy_alloc_frame_on_node(NumaNodeId::new(dest_node)) {
        Some(frame) => frame,
        None => return MigrationResult::NoMemory,
    };
    let src_phys = (src_frame.as_usize() * PAGE_SIZE_4K) as u64;
    let dst_phys = dest_frame.start_address().as_u64();
    let offset = crate::mm::virt::mapping::physical_memory_offset();
    let src_virt = (src_phys + offset) as *const u8;
    let dst_virt = (dst_phys + offset) as *mut u8;

    #[cfg(all(target_arch = "x86_64", target_feature = "sse"))]
    {
        use core::arch::x86_64::{_mm_sfence, _mm_stream_si64};
        let src_ptr = src_virt as *const i64;
        let dst_ptr = dst_virt as *mut i64;
        for i in 0..512 {
            let val = core::ptr::read_volatile(src_ptr.add(i));
            _mm_stream_si64(dst_ptr.add(i), val);
        }
        _mm_sfence();
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "sse")))]
    {
        core::ptr::copy_nonoverlapping(src_virt, dst_virt, PAGE_SIZE_4K);
    }
    MIGRATION_ENGINE
        .migrated_bytes
        .fetch_add(PAGE_SIZE_4K as u64, Ordering::Relaxed);
    use x86_64::structures::paging::PhysFrame;
    let old_frame = PhysFrame::from_start_address(x86_64::PhysAddr::new(src_phys)).unwrap();
    buddy_allocator::buddy_dealloc_frame(old_frame);
    MigrationResult::Success
}

pub fn process_pending_migrations() -> usize {
    unsafe {
        MIGRATION_ENGINE
            .process_batch(|src_frame, dest_node| migrate_numa_page(src_frame, dest_node))
    }
}

pub fn suggest_migration(
    task_preferred_node: u8,
    page_stats: &PageNumaStats,
    frame: FrameIndex,
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
        let dist_to_task =
            NUMA_DISTANCE_CACHE.get_distance(current_node as usize, task_preferred_node as usize);
        let dist_to_hot = NUMA_DISTANCE_CACHE.get_distance(current_node as usize, hottest_node);
        if dist_to_task <= dist_to_hot {
            task_preferred_node
        } else {
            hottest_node as u8
        }
    };
    Some(MigrationRequest {
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
