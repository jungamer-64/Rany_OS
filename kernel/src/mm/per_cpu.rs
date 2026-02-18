// ============================================================================
// src/mm/per_cpu.rs - Per-CPU Data using GsBase Register
// 設計書 5.2: コアローカルな高速データアクセス
//
// GsBaseレジスタの活用:
// - x86_64ではGsBaseをPer-CPUデータのベースポインタとして使用
// - コンテキストスイッチ時に自動的に切り替わる（または手動設定）
// - cpu_id引数が不要になり、APIが簡素化
// ============================================================================
#![allow(dead_code)]
use alloc::vec::Vec;
use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

// IOVA_MM_MIGRATION_PLAN Phase 1.1: 汎用Magazineを使用
use super::magazine::Magazine;
// NUMA zonelist support
use super::types::NumaNodeId;
use super::numa::MAX_NUMA_NODES;
// Remote Free batch support
use super::remote_free::RemoteFreeEntry;
// Buddy Allocator Cache
use super::buddy_allocator::PerCpuFrameCache;
use crate::sync::IrqMutex;

/// Cache entry for device to domain mapping
mod _split_1;
pub use _split_1::*;
#[derive(Clone, Copy, Default)]
pub struct DomainCacheEntry {
    pub device_id: u16,
    pub domain_id: u16,
    pub controller_idx: u8,
    pub valid: bool,
}

/// Per-CPU cache to reduce lock contention on global IOMMU lock
///
/// Stores frequently accessed device-to-domain mappings.
/// A simple direct-mapped cache is sufficient as devices are usually fixed
/// to a specific core's workload.
#[derive(Clone, Copy)]
pub struct PerCpuDomainCache {
    /// Cache size (power of 2 for efficient modulo via bitmask)
    pub entries: [DomainCacheEntry; Self::CACHE_SIZE],
}

impl PerCpuDomainCache {
    /// Per-CPU domain cache size
    pub const CACHE_SIZE: usize = 64;

    #[allow(dead_code)]
    pub const fn new() -> Self {
        Self {
            entries: [DomainCacheEntry {
                device_id: 0,
                domain_id: 0,
                controller_idx: 0,
                valid: false,
            }; Self::CACHE_SIZE],
        }
    }

    pub fn lookup(&self, device_id: u16) -> Option<(u16, u8)> {
        let idx = (device_id as usize) % Self::CACHE_SIZE;
        let entry = self.entries[idx];
        if entry.valid && entry.device_id == device_id {
            Some((entry.domain_id, entry.controller_idx))
        } else {
            None
        }
    }

    pub fn insert(&mut self, device_id: u16, domain_id: u16, controller_idx: u8) {
        let idx = (device_id as usize) % Self::CACHE_SIZE;
        self.entries[idx] = DomainCacheEntry {
            device_id,
            domain_id,
            controller_idx,
            valid: true,
        };
    }

    pub fn invalidate(&mut self, device_id: u16) {
        let idx = (device_id as usize) % Self::CACHE_SIZE;
        if self.entries[idx].device_id == device_id {
            self.entries[idx].valid = false;
        }
    }
}

/// Per-Core IOVA Magazine (Cache)
/// 頻繁な確保/解放を行う4KBページのIOVAをキャッシュする
pub const IOVA_MAG_CAPACITY: usize = 256;

/// Max number of IOMMU controllers that can use per-core IOVA caches.
/// Controllers with indices >= this value skip the per-core fast path.
pub const MAX_IOMMU_CONTROLLERS: usize = 8;

/// Per-controller IOVA cache (per CPU).
/// IOVA_MM_MIGRATION_PLAN Phase 1.1: Magazine<T, N>の型エイリアスとして定義
pub type IovaMagazine = Magazine<u64, IOVA_MAG_CAPACITY>;


// ============================================================================
// Per-CPU Page Table Magazine (for PageTablePool fast path)
// ============================================================================

/// Per-CPU Page Table Magazine capacity
/// Smaller than IOVA magazine since page tables are larger (4KB each)
pub const PT_MAG_CAPACITY: usize = 8;

/// Lightweight page table entry for per-CPU magazine
/// Stores only the essential information needed for recycling
#[derive(Clone, Copy)]
pub struct PtMagEntry {
    /// Physical address of the page table
    pub phys: u64,
    /// Virtual address (as usize for pointer reconstruction)
    pub virt: usize,
    /// NUMA node where this page was allocated
    pub node: u8,
}

impl PtMagEntry {
    pub const fn empty() -> Self {
        Self {
            phys: 0,
            virt: 0,
            node: 0,
        }
    }

    pub const fn is_valid(&self) -> bool {
        self.phys != 0
    }
}

/// Per-CPU Page Table Magazine
///
/// Lock-free cache for page table allocation/deallocation.
/// Each CPU maintains its own magazine to avoid lock contention.
///
/// # Design
/// - Small capacity (8 entries) to limit memory overhead
/// - NUMA-aware: tracks allocation node for proper return
/// - LIFO order for cache locality
#[derive(Clone, Copy)]
pub struct PtMagazine {
    /// Cached page table entries
    entries: [PtMagEntry; PT_MAG_CAPACITY],
    /// Current fill level (0 = empty, PT_MAG_CAPACITY = full)
    len: usize,
    /// Preferred NUMA node for this CPU
    preferred_node: u8,
}

impl PtMagazine {
    pub const fn new() -> Self {
        Self {
            entries: [PtMagEntry::empty(); PT_MAG_CAPACITY],
            len: 0,
            preferred_node: 0,
        }
    }

    /// Set the preferred NUMA node (called during CPU initialization)
    pub fn set_preferred_node(&mut self, node: u8) {
        self.preferred_node = node;
    }

    /// Get the preferred NUMA node
    pub fn preferred_node(&self) -> u8 {
        self.preferred_node
    }

    /// Try to pop a page table from the magazine
    /// Returns None if empty
    #[inline]
    pub fn pop(&mut self) -> Option<PtMagEntry> {
        if self.len == 0 {
            None
        } else {
            self.len -= 1;
            let entry = self.entries[self.len];
            self.entries[self.len] = PtMagEntry::empty();
            Some(entry)
        }
    }

    /// Try to push a page table into the magazine
    /// Returns false if full (caller should return to depot)
    #[inline]
    pub fn push(&mut self, entry: PtMagEntry) -> bool {
        if self.len >= PT_MAG_CAPACITY {
            false
        } else {
            self.entries[self.len] = entry;
            self.len += 1;
            true
        }
    }

    /// Check if empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Check if full
    #[inline]
    pub fn is_full(&self) -> bool {
        self.len >= PT_MAG_CAPACITY
    }

    /// Current fill level
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Available capacity
    #[inline]
    pub fn available(&self) -> usize {
        PT_MAG_CAPACITY - self.len
    }
}

// ============================================================================
// Per-CPU Remote Free Batch Buffer
// ============================================================================

/// Capacity of the per-CPU remote free batch buffer
/// When buffer reaches this capacity, entries are flushed to the target ring
pub const REMOTE_FREE_BATCH_SIZE: usize = 32;

/// Maximum target CPUs to batch for
/// Limits memory overhead while covering most common cases
pub const MAX_REMOTE_FREE_TARGETS: usize = 8;

/// Per-target batch buffer entry
#[derive(Clone, Copy)]
pub struct RemoteFreeBatchEntry {
    /// Target CPU ID
    pub target_cpu: u16,
    /// Batch buffer for this target
    pub entries: [RemoteFreeEntry; REMOTE_FREE_BATCH_SIZE],
    /// Number of valid entries in the buffer
    pub len: u8,
}

impl RemoteFreeBatchEntry {
    pub const fn new() -> Self {
        Self {
            target_cpu: u16::MAX,  // Invalid - indicates unused slot
            entries: [const { RemoteFreeEntry::empty() }; REMOTE_FREE_BATCH_SIZE],
            len: 0,
        }
    }

    /// Check if this entry is in use (has a valid target CPU)
    #[inline]
    pub const fn is_active(&self) -> bool {
        self.target_cpu != u16::MAX
    }

    /// Reset this entry for reuse
    #[inline]
    pub fn reset(&mut self) {
        self.target_cpu = u16::MAX;
        self.len = 0;
    }

    /// Check if buffer is full
    #[inline]
    pub fn is_full(&self) -> bool {
        self.len as usize >= REMOTE_FREE_BATCH_SIZE
    }

    /// Add an entry to the buffer
    /// Returns true if added, false if buffer is full
    #[inline]
    pub fn push(&mut self, entry: RemoteFreeEntry) -> bool {
        if self.is_full() {
            return false;
        }
        self.entries[self.len as usize] = entry;
        self.len += 1;
        true
    }

    /// Get iterator over valid entries
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &RemoteFreeEntry> {
        self.entries[..self.len as usize].iter()
    }
}

/// Per-CPU Remote Free Batch Buffer
///
/// Batches remote free requests destined for different target CPUs.
/// When a buffer for a specific target fills up, all entries are
/// pushed to the target's RemoteFreeRing in a single batch, reducing
/// contention on the ring's head pointer.
///
/// # Design
/// - Per-target sub-buffers to batch requests by destination
/// - Amortizes CAS overhead: one batch push vs many individual pushes
/// - Falls back to immediate push if no buffer slot available
///
/// # Benefits
/// - Reduces lock contention on RemoteFreeRing head
/// - Better cache utilization (fewer ring accesses)
/// - Allows range coalescing in future versions
#[derive(Clone, Copy)]
pub struct RemoteFreeBatchBuffer {
    /// Per-target batch entries
    targets: [RemoteFreeBatchEntry; MAX_REMOTE_FREE_TARGETS],
    /// Statistics: total entries batched
    pub batched_count: u64,
    /// Statistics: total flushes performed
    pub flush_count: u64,
}

impl RemoteFreeBatchBuffer {
    pub const fn new() -> Self {
        Self {
            targets: [const { RemoteFreeBatchEntry::new() }; MAX_REMOTE_FREE_TARGETS],
            batched_count: 0,
            flush_count: 0,
        }
    }

    /// Find or allocate a slot for the given target CPU
    fn find_or_allocate_slot(&mut self, target_cpu: u16) -> Option<usize> {
        // First pass: find existing slot
        for i in 0..MAX_REMOTE_FREE_TARGETS {
            if self.targets[i].target_cpu == target_cpu {
                return Some(i);
            }
        }
        // Second pass: find empty slot
        for i in 0..MAX_REMOTE_FREE_TARGETS {
            if !self.targets[i].is_active() {
                self.targets[i].target_cpu = target_cpu;
                return Some(i);
            }
        }
        None
    }

    /// Add an entry to be freed on the target CPU.
    ///
    /// # Returns
    /// - `Ok(None)` - Entry was batched successfully
    /// - `Ok(Some(entries))` - Buffer is full, returns entries to flush
    /// - `Err(entry)` - No slot available, caller should push immediately
    pub fn add_entry(
        &mut self, 
        target_cpu: u16, 
        entry: RemoteFreeEntry
    ) -> Result<Option<(u16, &[RemoteFreeEntry])>, RemoteFreeEntry> {
        if let Some(slot_idx) = self.find_or_allocate_slot(target_cpu) {
            let slot = &mut self.targets[slot_idx];
            
            if slot.is_full() {
                // Return full buffer for flushing
                // Caller will flush and retry
                return Ok(Some((slot.target_cpu, &slot.entries[..slot.len as usize])));
            }
            
            slot.push(entry);
            self.batched_count += 1;
            Ok(None)
        } else {
            // No slot available - caller should push immediately
            Err(entry)
        }
    }

    /// Mark a slot as flushed (reset for reuse)
    pub fn mark_flushed(&mut self, target_cpu: u16) {
        for slot in &mut self.targets {
            if slot.target_cpu == target_cpu {
                slot.reset();
                self.flush_count += 1;
                break;
            }
        }
    }

    /// Flush all pending entries for a specific target
    /// Returns the entries to be pushed to the target's ring
    pub fn flush_target(&mut self, target_cpu: u16) -> Option<&[RemoteFreeEntry]> {
        for slot in &mut self.targets {
            if slot.target_cpu == target_cpu && slot.len > 0 {
                let entries = &slot.entries[..slot.len as usize];
                return Some(entries);
            }
        }
        None
    }

    /// Flush all pending entries for all targets
    /// Returns iterator over (target_cpu, entries) pairs
    pub fn flush_all(&mut self) -> impl Iterator<Item = (u16, &[RemoteFreeEntry])> {
        self.targets.iter().filter_map(|slot| {
            if slot.is_active() && slot.len > 0 {
                Some((slot.target_cpu, &slot.entries[..slot.len as usize]))
            } else {
                None
            }
        })
    }

    /// Reset all slots (called after flush_all)
    pub fn reset_all(&mut self) {
        for slot in &mut self.targets {
            slot.reset();
        }
        self.flush_count += 1;
    }

    /// Get statistics
    pub fn stats(&self) -> (u64, u64) {
        (self.batched_count, self.flush_count)
    }
}

// ============================================================================
// Hot/Cold Per-CPU Data Structures (Phase 3 Optimization)
// ============================================================================
//
// GSBase points to PerCpuHot (64 bytes, one cache line).
// Less-frequently accessed data lives in PerCpuCold, accessed via indirection.
// This reduces cache footprint for hot paths like current_cpu_id().
// ============================================================================

use core::ptr::NonNull;

/// Hot per-CPU data - GSBase points here directly
/// 
/// Must fit in a single cache line (64 bytes) for optimal performance.
/// Contains only the most frequently accessed fields.
#[repr(C, align(64))]
pub struct PerCpuHot {
    /// Self-validation pointer (must match address of this struct)
    pub self_ptr: usize,
    /// CPU ID (0-based logical index)
    pub cpu_id: usize,
    /// Interrupt nesting depth (incremented on ISR entry, decremented on exit)
    pub interrupt_depth: core::sync::atomic::AtomicU32,
    /// Padding to align current_task_ptr to 8 bytes
    _pad0: u32,
    /// Current task pointer (frequently accessed by scheduler)
    pub current_task_ptr: AtomicU64,
    /// Current task ID
    pub current_task_id: u64,
    /// Link to cold data (never null after initialization)
    cold: Option<NonNull<PerCpuCold>>,
}

// Compile-time size and alignment guarantee
const _: () = {
    assert!(core::mem::size_of::<PerCpuHot>() <= 64);
    assert!(core::mem::align_of::<PerCpuHot>() == 64);
};

impl PerCpuHot {
    /// Create a new PerCpuHot (cold pointer set separately)
    pub const fn new(cpu_id: usize) -> Self {
        Self {
            self_ptr: 0,
            cpu_id,
            interrupt_depth: core::sync::atomic::AtomicU32::new(0),
            _pad0: 0,
            current_task_ptr: AtomicU64::new(0),
            current_task_id: 0,
            cold: None,
        }
    }

    /// Set the self-pointer for validation
    pub fn set_self_ptr(&mut self) {
        self.self_ptr = self as *const _ as usize;
    }

    /// Link to cold data
    /// 
    /// # Safety
    /// cold_ptr must point to valid PerCpuCold that outlives this PerCpuHot
    pub unsafe fn set_cold(&mut self, cold_ptr: *mut PerCpuCold) {
        self.cold = NonNull::new(cold_ptr);
    }

    /// Get reference to cold data
    /// 
    /// # Panics
    /// Panics if cold is not set (should never happen after proper initialization)
    #[inline]
    pub fn cold(&self) -> &PerCpuCold {
        match self.cold {
            Some(ptr) => unsafe { ptr.as_ref() },
            None => panic!("PerCpuHot.cold not initialized"),
        }
    }

    /// Get mutable reference to cold data
    /// 
    /// # Safety
    /// Caller must ensure exclusive access
    #[inline]
    pub unsafe fn cold_mut(&mut self) -> &mut PerCpuCold {
        match self.cold {
            Some(mut ptr) => unsafe { ptr.as_mut() },
            None => panic!("PerCpuHot.cold not initialized"),
        }
    }

    /// Get cold data as Option (for early init checks)
    #[inline]
    pub fn cold_opt(&self) -> Option<&PerCpuCold> {
        self.cold.map(|ptr| unsafe { ptr.as_ref() })
    }

    /// Check if in interrupt context
    #[inline]
    pub fn in_interrupt(&self) -> bool {
        self.interrupt_depth.load(core::sync::atomic::Ordering::Relaxed) > 0
    }

    /// Enter interrupt context
    #[inline]
    pub fn enter_interrupt(&self) {
        self.interrupt_depth.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    /// Exit interrupt context
    #[inline]
    pub fn exit_interrupt(&self) {
        self.interrupt_depth.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Cold per-CPU data - accessed via indirection from PerCpuHot
/// 
/// Contains less-frequently accessed fields like caches and statistics.
pub struct PerCpuCold {
    /// Per-CPU heap statistics
    pub alloc_count: u64,
    pub dealloc_count: u64,
    /// IOMMU Domain Cache (True Per-CPU)
    pub iommu_domain_cache: PerCpuDomainCache,
    /// IOMMU IOVA Magazines (per-controller cache)
    pub iova_magazines: [IovaMagazine; MAX_IOMMU_CONTROLLERS],
    /// IOMMU Page Table Magazine (per-CPU cache for PageTablePool)
    pub pt_magazine: PtMagazine,
    /// NUMA Zonelist: pre-sorted list of NUMA nodes by distance from local node
    pub numa_zonelist: [NumaNodeId; MAX_NUMA_NODES],
    /// Number of valid entries in numa_zonelist
    pub numa_zonelist_len: u8,
    /// Local NUMA node ID for this CPU
    pub local_numa_node: NumaNodeId,
    /// Remote Free Batch Buffer
    pub remote_free_batch: RemoteFreeBatchBuffer,
    /// Per-CPU RCU State
    pub rcu_state: crate::mm::rcu::PerCpuRcuState,
    /// Per-CPU Frame Cache
    pub frame_cache: IrqMutex<PerCpuFrameCache>,
}

impl PerCpuCold {
    /// Create a new PerCpuCold
    pub const fn new(cpu_id: usize) -> Self {
        Self {
            alloc_count: 0,
            dealloc_count: 0,
            iommu_domain_cache: PerCpuDomainCache::new(),
            iova_magazines: [const { IovaMagazine::new() }; MAX_IOMMU_CONTROLLERS],
            pt_magazine: PtMagazine::new(),
            numa_zonelist: [const { NumaNodeId::new(0) }; MAX_NUMA_NODES],
            numa_zonelist_len: 1,
            local_numa_node: NumaNodeId::new(0),
            remote_free_batch: RemoteFreeBatchBuffer::new(),
            rcu_state: crate::mm::rcu::PerCpuRcuState::new(),
            frame_cache: IrqMutex::new(PerCpuFrameCache::new(cpu_id)),
        }
    }

    /// Initialize the NUMA zonelist
    pub fn setup_numa_zonelist(
        &mut self,
        local_node: NumaNodeId,
        sorted_nodes: &[NumaNodeId; MAX_NUMA_NODES],
        node_count: usize,
    ) {
        self.local_numa_node = local_node;
        self.numa_zonelist_len = (node_count as u8).min(MAX_NUMA_NODES as u8);
        for i in 0..self.numa_zonelist_len as usize {
            self.numa_zonelist[i] = sorted_nodes[i];
        }
    }

    /// Get the local NUMA node
    #[inline]
    pub fn get_local_numa_node(&self) -> NumaNodeId {
        self.local_numa_node
    }

    /// Get zonelist iterator
    #[inline]
    pub fn zonelist_iter(&self) -> impl Iterator<Item = NumaNodeId> + '_ {
        self.numa_zonelist[..self.numa_zonelist_len as usize].iter().copied()
    }

    /// Get nth zonelist node
    #[inline]
    pub fn get_zonelist_node(&self, index: usize) -> Option<NumaNodeId> {
        if index < self.numa_zonelist_len as usize {
            Some(self.numa_zonelist[index])
        } else {
            None
        }
    }
}

// ============================================================================
// Legacy PerCpuData (kept for backward compatibility during migration)
// ============================================================================

/// Per-CPUデータ構造
/// GsBaseからのオフセットでアクセス
#[repr(C, align(64))]
pub struct PerCpuData {
    /// 自己参照ポインタ（検証用）
    pub self_ptr: usize,
    /// CPU ID
    pub cpu_id: usize,
    /// 現在実行中のタスクID
    pub current_task_id: u64,
    /// 現在実行中のタスクポインタ (Raw Pointer)
    pub current_task_ptr: AtomicU64,
    /// Per-CPUヒープ統計
    pub alloc_count: u64,
    pub dealloc_count: u64,
    /// IOMMU Domain Cache (True Per-CPU)
    pub iommu_domain_cache: PerCpuDomainCache,
    /// IOMMU IOVA Magazines (per-controller cache)
    pub iova_magazines: [IovaMagazine; MAX_IOMMU_CONTROLLERS],
    /// IOMMU Page Table Magazine (per-CPU cache for PageTablePool)
    pub pt_magazine: PtMagazine,
    /// Interrupt nesting depth (incremented on ISR entry, decremented on exit)
    /// Used to detect if code is running in interrupt context.
    pub interrupt_depth: core::sync::atomic::AtomicU32,
    /// NUMA Zonelist: pre-sorted list of NUMA nodes by distance from local node
    /// Cached at CPU initialization to avoid repeated distance lookups during allocation.
    /// zonelist[0] is always the local node (closest), subsequent entries are sorted
    /// by increasing distance. This enables O(1) fallback node selection.
    pub numa_zonelist: [NumaNodeId; MAX_NUMA_NODES],
    /// Number of valid entries in numa_zonelist
    pub numa_zonelist_len: u8,
    /// Local NUMA node ID for this CPU (same as zonelist[0] when initialized)
    pub local_numa_node: NumaNodeId,
    /// Remote Free Batch Buffer: batches cross-CPU free requests to reduce contention
    pub remote_free_batch: RemoteFreeBatchBuffer,
    /// Per-CPU RCU State (Phase 9)
    pub rcu_state: crate::mm::rcu::PerCpuRcuState,
    /// Per-CPU Frame Cache (Lock-Free Memory Allocator Phase 1)
    pub frame_cache: IrqMutex<PerCpuFrameCache>,
}

impl PerCpuData {
    /// 新しいPer-CPUデータを作成
    pub const fn new(cpu_id: usize) -> Self {
        Self {
            self_ptr: 0,
            cpu_id,
            current_task_id: 0,
            current_task_ptr: AtomicU64::new(0),
            alloc_count: 0,
            dealloc_count: 0,
            iommu_domain_cache: PerCpuDomainCache::new(),
            // const fn内で配列初期化: const { expr }パターンを使用
            iova_magazines: [const { IovaMagazine::new() }; MAX_IOMMU_CONTROLLERS],
            pt_magazine: PtMagazine::new(),
            interrupt_depth: core::sync::atomic::AtomicU32::new(0),
            // NUMA zonelist: initialized with default (node 0) until setup_numa_zonelist is called
            numa_zonelist: [const { NumaNodeId::new(0) }; MAX_NUMA_NODES],
            numa_zonelist_len: 1, // At least one node (node 0)
            local_numa_node: NumaNodeId::new(0),
            // Remote free batch buffer for cross-CPU memory reclamation
            remote_free_batch: RemoteFreeBatchBuffer::new(),
            rcu_state: crate::mm::rcu::PerCpuRcuState::new(),
            frame_cache: IrqMutex::new(PerCpuFrameCache::new(cpu_id)),
        }
    }

    /// 自己参照ポインタを設定
    pub fn set_self_ptr(&mut self) {
        self.self_ptr = self as *const _ as usize;
    }

    /// Initialize the NUMA zonelist for this CPU based on its local NUMA node.
    ///
    /// This should be called once during CPU initialization after NUMA topology
    /// is known. The zonelist is sorted by distance from the local node,
    /// enabling fast fallback allocation without runtime distance lookups.
    ///
    /// # Arguments
    /// * `local_node` - The NUMA node ID where this CPU resides
    /// * `sorted_nodes` - Pre-sorted array of NUMA nodes by distance from local_node
    /// * `node_count` - Number of valid nodes in the sorted_nodes array
    pub fn setup_numa_zonelist(
        &mut self,
        local_node: NumaNodeId,
        sorted_nodes: &[NumaNodeId; MAX_NUMA_NODES],
        node_count: usize,
    ) {
        self.local_numa_node = local_node;
        self.numa_zonelist_len = (node_count as u8).min(MAX_NUMA_NODES as u8);
        
        // Copy the pre-sorted zonelist
        for i in 0..self.numa_zonelist_len as usize {
            self.numa_zonelist[i] = sorted_nodes[i];
        }
    }

    /// Get the local NUMA node for this CPU.
    #[inline]
    pub fn get_local_numa_node(&self) -> NumaNodeId {
        self.local_numa_node
    }

    /// Get the NUMA zonelist iterator for fallback allocation.
    ///
    /// Returns an iterator over NUMA nodes sorted by distance from the local node.
    /// This enables efficient fallback allocation without runtime distance lookups.
    #[inline]
    pub fn zonelist_iter(&self) -> impl Iterator<Item = NumaNodeId> + '_ {
        self.numa_zonelist[..self.numa_zonelist_len as usize].iter().copied()
    }

    /// Get the nth preferred NUMA node from the zonelist.
    ///
    /// Returns `None` if index is out of bounds.
    #[inline]
    pub fn get_zonelist_node(&self, index: usize) -> Option<NumaNodeId> {
        if index < self.numa_zonelist_len as usize {
            Some(self.numa_zonelist[index])
        } else {
            None
        }
    }

    /// Check if currently executing in interrupt context.
    ///
    /// Returns `true` if the current code is running inside an interrupt
    /// handler (ISR), `false` otherwise.
    #[inline]
    pub fn in_interrupt(&self) -> bool {
        self.interrupt_depth.load(core::sync::atomic::Ordering::Relaxed) > 0
    }

    /// Increment interrupt nesting depth.
    ///
    /// Must be called at the beginning of every interrupt handler.
    #[inline]
    pub fn enter_interrupt(&self) {
        self.interrupt_depth.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    /// Decrement interrupt nesting depth.
    ///
    /// Must be called at the end of every interrupt handler.
    #[inline]
    pub fn exit_interrupt(&self) {
        self.interrupt_depth.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
    }
}

/// 最大CPU数
pub const MAX_CPUS: usize = 64;

/// Hot per-CPU data (GSBase points here)
static mut PER_CPU_HOT: [PerCpuHot; MAX_CPUS] = {
    const INIT: PerCpuHot = PerCpuHot::new(0);
    [INIT; MAX_CPUS]
};

/// Cold per-CPU data (accessed via hot.cold())
static mut PER_CPU_COLD: [PerCpuCold; MAX_CPUS] = {
    const INIT: PerCpuCold = PerCpuCold::new(0);
    [INIT; MAX_CPUS]
};
