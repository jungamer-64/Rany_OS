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

/// 静的に確保されたPer-CPUデータ配列 (Legacy - for backward compatibility)
/// 各CPUに対応するデータが格納される
static mut PER_CPU_DATA: [PerCpuData; MAX_CPUS] = {
    const INIT: PerCpuData = PerCpuData::new(0);
    [INIT; MAX_CPUS]
};

/// Per-CPUデータが初期化済みかどうか
static INITIALIZED: spin::Once<()> = spin::Once::new();

/// 初期化済みCPU数
static ACTIVE_CPUS: Mutex<usize> = Mutex::new(0);
/// Online CPU bitmask (bit N set => CPU N online)
static ONLINE_CPU_MASK: AtomicU64 = AtomicU64::new(0);

/// Fastpath adoption flag: true = CPUID supports FSGSBASE and we adopt rdgsbase/wrgsbase
/// Note: This is a global adoption decision. Each CPU must still enable CR4.FSGSBASE before use.
static GSBASE_FASTPATH: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Check if FSGSBASE fastpath is adopted (CPUID supports it)
#[inline]
pub fn can_use_fsgsbase() -> bool {
    GSBASE_FASTPATH.load(Ordering::Relaxed)
}

/// Read GSBase using the appropriate method for this CPU
/// 
/// Uses rdgsbase if fastpath is adopted AND this CPU has CR4.FSGSBASE enabled,
/// otherwise falls back to MSR read. This prevents #UD on APs before their CR4 is set.
/// 
/// # Safety
/// Must be called in kernel mode
#[inline]
pub unsafe fn read_gsbase_any() -> u64 {
    if can_use_fsgsbase() && is_fsgsbase_enabled() {
        read_gs_base()
    } else {
        read_gs_base_msr()
    }
}

/// Write GSBase using the appropriate method for this CPU
/// 
/// Uses wrgsbase if fastpath is adopted AND this CPU has CR4.FSGSBASE enabled,
/// otherwise falls back to MSR write. This prevents #UD on APs before their CR4 is set.
/// 
/// # Safety
/// - Must be called in kernel mode
/// - Value must point to valid Per-CPU data
#[inline]
pub unsafe fn write_gsbase_any(value: u64) {
    if can_use_fsgsbase() && is_fsgsbase_enabled() {
        write_gs_base(value)
    } else {
        write_gs_base_msr(value)
    }
}

/// Get reference to Per-CPU data for a specific CPU ID
/// 
/// # Safety
/// Caller must ensure cpu_id is valid (< MAX_CPUS)
pub unsafe fn get_per_cpu_data(cpu_id: usize) -> &'static PerCpuData {
    &PER_CPU_DATA[cpu_id]
}

/// Get mutable reference to Per-CPU data for a specific CPU ID
/// 
/// # Safety
/// - Caller must ensure cpu_id is valid (< MAX_CPUS)
/// - Caller must ensure exclusive access (no concurrent mutable access)
pub unsafe fn get_per_cpu_data_mut(cpu_id: usize) -> &'static mut PerCpuData {
    &mut PER_CPU_DATA[cpu_id]
}

// ============================================================================
// Hot/Cold Per-CPU Accessors
// ============================================================================

/// Get reference to hot per-CPU data for a specific CPU ID
/// 
/// # Safety
/// Caller must ensure cpu_id is valid (< MAX_CPUS)
#[inline]
pub unsafe fn get_per_cpu_hot(cpu_id: usize) -> &'static PerCpuHot {
    &PER_CPU_HOT[cpu_id]
}

/// Get mutable reference to hot per-CPU data
/// 
/// # Safety
/// - cpu_id must be valid (< MAX_CPUS)
/// - Caller must ensure exclusive access
#[inline]
pub unsafe fn get_per_cpu_hot_mut(cpu_id: usize) -> &'static mut PerCpuHot {
    &mut PER_CPU_HOT[cpu_id]
}

/// Get reference to cold per-CPU data for a specific CPU ID
/// 
/// # Safety
/// Caller must ensure cpu_id is valid (< MAX_CPUS)
#[inline]
pub unsafe fn get_per_cpu_cold(cpu_id: usize) -> &'static PerCpuCold {
    &PER_CPU_COLD[cpu_id]
}

/// Get mutable reference to cold per-CPU data
/// 
/// # Safety
/// - cpu_id must be valid (< MAX_CPUS)
/// - Caller must ensure exclusive access
#[inline]
pub unsafe fn get_per_cpu_cold_mut(cpu_id: usize) -> &'static mut PerCpuCold {
    &mut PER_CPU_COLD[cpu_id]
}

/// Get the current CPU's hot data via GSBase
/// 
/// Returns None if GSBase is not initialized or validation fails
#[inline]
pub unsafe fn current_per_cpu_hot() -> Option<&'static PerCpuHot> {
    let gs_base = read_gsbase_any();
    if gs_base == 0 {
        return None;
    }
    let hot = &*(gs_base as *const PerCpuHot);
    // Validate self_ptr to ensure GSBase points to valid PerCpuHot
    if hot.self_ptr != gs_base as usize {
        return None;
    }
    Some(hot)
}

/// Get the current CPU's hot data (mutable) via GSBase
/// 
/// # Safety
/// Caller must ensure exclusive access
#[inline]
pub unsafe fn current_per_cpu_hot_mut() -> Option<&'static mut PerCpuHot> {
    let gs_base = read_gsbase_any();
    if gs_base == 0 {
        return None;
    }
    let hot = &mut *(gs_base as *mut PerCpuHot);
    // Validate self_ptr to ensure GSBase points to valid PerCpuHot
    if hot.self_ptr != gs_base as usize {
        return None;
    }
    Some(hot)
}


/// Check if a CPU is online
pub fn is_cpu_online(cpu_id: usize) -> bool {
    if cpu_id >= 64 { return false; }
    let mask = ONLINE_CPU_MASK.load(Ordering::Acquire);
    (mask & (1 << cpu_id)) != 0
}

/// GsBaseレジスタを読み取る
///
/// # Safety
/// GsBaseが有効なPer-CPUデータを指している必要がある
#[inline]
pub unsafe fn read_gs_base() -> u64 {
    let value: u64;
    // SAFETY: rdgsbaseはGsBaseレジスタの値を読み取る
    unsafe {
        asm!(
            "rdgsbase {0}",
            out(reg) value,
            options(nostack, preserves_flags)
        );
    }
    value
}

/// GsBaseレジスタに書き込む
///
/// # Safety
/// - 有効なPer-CPUデータへのポインタを渡す必要がある
/// - FSGSBASEが有効化されている必要がある（CR4.FSGSBASE）
#[inline]
pub unsafe fn write_gs_base(value: u64) {
    // SAFETY: wrgsbaseはGsBaseレジスタに値を書き込む
    unsafe {
        asm!(
            "wrgsbase {0}",
            in(reg) value,
            options(nostack, preserves_flags)
        );
    }
}

/// MSR経由でGsBaseを読み取る（FSGSBASEが無効な環境用）
///
/// # Safety
/// カーネルモードで実行される必要がある
#[inline]
pub unsafe fn read_gs_base_msr() -> u64 {
    const IA32_GS_BASE: u32 = 0xC000_0101;
    let low: u32;
    let high: u32;

    // SAFETY: MSR読み取りはカーネルモードで安全
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") IA32_GS_BASE,
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags)
        );
    }

    ((high as u64) << 32) | (low as u64)
}

/// MSR経由でGsBaseに書き込む（FSGSBASEが無効な環境用）
///
/// # Safety
/// - カーネルモードで実行される必要がある
/// - 有効なPer-CPUデータへのポインタを渡す必要がある
#[inline]
pub unsafe fn write_gs_base_msr(value: u64) {
    const IA32_GS_BASE: u32 = 0xC000_0101;
    let low = value as u32;
    let high = (value >> 32) as u32;

    // SAFETY: MSR書き込みはカーネルモードで安全
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") IA32_GS_BASE,
            in("eax") low,
            in("edx") high,
            options(nostack, preserves_flags)
        );
    }
}

// ============================================================================
// FS Base Functions (for Thread Local Storage)
// ============================================================================

/// FSBaseレジスタを読み取る
///
/// # Safety
/// FSBaseが有効なTLSデータを指している必要がある
#[inline]
pub unsafe fn read_fs_base() -> u64 {
    let value: u64;
    // SAFETY: rdfsbaseはFsBaseレジスタの値を読み取る
    unsafe {
        asm!(
            "rdfsbase {0}",
            out(reg) value,
            options(nostack, preserves_flags)
        );
    }
    value
}

/// FSBaseレジスタに書き込む
///
/// # Safety
/// - 有効なTLSデータへのポインタを渡す必要がある
/// - FSGSBASEが有効化されている必要がある（CR4.FSGSBASE）
#[inline]
pub unsafe fn write_fs_base(value: u64) {
    // SAFETY: wrfsbaseはFsBaseレジスタに値を書き込む
    unsafe {
        asm!(
            "wrfsbase {0}",
            in(reg) value,
            options(nostack, preserves_flags)
        );
    }
}

/// MSR経由でFSBaseを読み取る（FSGSBASEが無効な環境用）
///
/// # Safety
/// カーネルモードで実行される必要がある
#[inline]
pub unsafe fn read_fs_base_msr() -> u64 {
    const IA32_FS_BASE: u32 = 0xC000_0100;
    let low: u32;
    let high: u32;

    // SAFETY: MSR読み取りはカーネルモードで安全
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") IA32_FS_BASE,
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags)
        );
    }

    ((high as u64) << 32) | (low as u64)
}

/// MSR経由でFSBaseに書き込む（FSGSBASEが無効な環境用）
///
/// # Safety
/// - カーネルモードで実行される必要がある
/// - 有効なTLSデータへのポインタを渡す必要がある
#[inline]
pub unsafe fn write_fs_base_msr(value: u64) {
    const IA32_FS_BASE: u32 = 0xC000_0100;
    let low = value as u32;
    let high = (value >> 32) as u32;

    // SAFETY: MSR書き込みはカーネルモードで安全
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") IA32_FS_BASE,
            in("eax") low,
            in("edx") high,
            options(nostack, preserves_flags)
        );
    }
}

/// CR4.FSGSBASEを有効化
///
/// # Safety
/// カーネルの初期化時に一度だけ呼ぶ必要がある
pub unsafe fn enable_fsgsbase() {
    const CR4_FSGSBASE: u64 = 1 << 16;

    let cr4: u64;
    // SAFETY: CR4の読み取り
    unsafe {
        asm!(
            "mov {0}, cr4",
            out(reg) cr4,
            options(nostack, preserves_flags)
        );
    }

    // FSGSBASEビットを設定
    let new_cr4 = cr4 | CR4_FSGSBASE;

    // SAFETY: CR4への書き込み
    unsafe {
        asm!(
            "mov cr4, {0}",
            in(reg) new_cr4,
            options(nostack, preserves_flags)
        );
    }
}

/// FSGSBASEが有効かどうかをチェック
pub fn is_fsgsbase_enabled() -> bool {
    const CR4_FSGSBASE: u64 = 1 << 16;

    let cr4: u64;
    unsafe {
        asm!(
            "mov {0}, cr4",
            out(reg) cr4,
            options(nostack, preserves_flags)
        );
    }

    (cr4 & CR4_FSGSBASE) != 0
}

/// CPUがFSGSBASE命令をサポートしているかチェック
///
/// CPUID.07H.0H:EBX[0] = 1 の場合サポート
///
/// # Safety
/// CPUID命令を実行する
pub unsafe fn check_fsgsbase_support() -> bool {
    // まず最大拡張機能番号を確認
    let max_leaf: u32;
    unsafe {
        // ebx/rbxはLLVMが使用するため、xchgで退避
        asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 0u32 => max_leaf,
            out("ecx") _,
            out("edx") _,
            options(nostack, preserves_flags)
        );
    }

    // リーフ7が利用可能かチェック
    if max_leaf < 7 {
        return false;
    }

    // CPUID.07H.0H でFSGSBASEサポートを確認
    let ebx_result: u32;
    unsafe {
        // rbxを退避してcpuid実行、結果をrdiに移動してrbxを復元
        asm!(
            "push rbx",
            "cpuid",
            "mov {0:e}, ebx",
            "pop rbx",
            out(reg) ebx_result,
            inout("eax") 7u32 => _,
            inout("ecx") 0u32 => _,
            out("edx") _,
            options(nostack, preserves_flags)
        );
    }

    // EBX bit 0 = FSGSBASE
    (ebx_result & 1) != 0
}

/// Per-CPUシステムを初期化
///
/// # Safety
/// - カーネル初期化時に一度だけ呼ばれる必要がある
/// - BSP（ブートストラッププロセッサ）から呼ぶ
///
/// # 初期化順序
/// 1. FSGSBASEを有効化（サポートされている場合）
/// 2. BSPのGsBaseを先に設定（current_cpu_id()が使えるように）
/// 3. 各CPUのデータを初期化
///
/// これにより、初期化中でも `current_cpu_id()` や `try_current_cpu_id()` を
/// 安全に呼び出すことができる。
pub unsafe fn init_per_cpu(num_cpus: usize) {
    crate::io::log::early_print("[PCPU] init\n");
    INITIALIZED.call_once(|| {
        crate::io::log::early_print("[PCPU] once\n");
        let num_cpus = num_cpus.min(MAX_CPUS);

        // 1. FSGSBASEを有効化（サポートされている場合のみ）
        // SAFETY: 初期化時に一度だけ呼ばれる
        crate::io::log::early_print("[PCPU] fsgs\n");

        // CPUIDでFSGSBASEサポートを確認
        let fsgsbase_supported = unsafe { check_fsgsbase_support() };
        crate::io::log::early_print(if fsgsbase_supported {
            "[PCPU] fsgs supported\n"
        } else {
            "[PCPU] fsgs not supported, using MSR\n"
        });

        if fsgsbase_supported {
            unsafe {
                enable_fsgsbase();
            }
            // Set global adoption flag - each AP will still need to enable CR4 in setup_current_cpu
            GSBASE_FASTPATH.store(true, Ordering::Release);
            crate::io::log::early_print("[PCPU] fsgs enabled\n");
        }
        crate::io::log::early_print("[PCPU] fsgs ok\n");

        // 2. BSP（CPU 0）のデータを先に初期化してGsBaseを設定
        // これにより、以降の初期化コード内でcurrent_cpu_id()が使えるようになる
        crate::io::log::early_print("[PCPU] bsp setup\n");
        unsafe {
            // Initialize Hot/Cold structures (Phase 3)
            PER_CPU_HOT[0] = PerCpuHot::new(0);
            PER_CPU_COLD[0] = PerCpuCold::new(0);
            PER_CPU_HOT[0].set_self_ptr();
            PER_CPU_HOT[0].set_cold(&mut PER_CPU_COLD[0] as *mut PerCpuCold);

            // Legacy: Full initialization for backward compatibility
            PER_CPU_DATA[0] = PerCpuData::new(0);
            PER_CPU_DATA[0].set_self_ptr();

            // BSPのGsBaseを設定 - PER_CPU_HOT を使用（Phase 3 Hot/Cold最適化）
            let bsp_ptr = &PER_CPU_HOT[0] as *const _ as u64;
            // FSGSBASEが有効な場合は高速版、そうでなければMSR版を使用
            if fsgsbase_supported {
                write_gs_base(bsp_ptr);
            } else {
                write_gs_base_msr(bsp_ptr);
            }

            // 2.5. TLS (Thread Local Storage) の初期化
            // #[thread_local] 属性はFSレジスタを使用する
            // x86_64 TLS モデルでは、FS:0 が TCS (Thread Control Structure) を指し、
            // TLS変数は負のオフセット (FS:-8, FS:-16 など) でアクセスされる
            // そのため、FSベースはTLSセクションの**終端**に設定する
            crate::io::log::early_print("[PCPU] TLS init\n");

            // On unit tests (host builds) we may not have linker-provided TLS symbols
            // available. Skip TLS initialization in test builds to avoid linker errors
            // referring to `__tls_start` / `__tls_end`.
            #[cfg(all(not(test), not(target_os = "windows")))]
            {
                // リンカスクリプトから提供されるシンボル
                unsafe extern "C" {
                    static __tls_start: u8;
                    static __tls_end: u8;
                }

                let tls_start = &__tls_start as *const u8 as u64;
                let tls_end = &__tls_end as *const u8 as u64;
                let tls_size = tls_end.saturating_sub(tls_start);

                crate::io::log::early_print("[PCPU] TLS size=");
                // Print TLS size (simple hex output)
                if tls_size == 0 {
                    crate::io::log::early_print("0");
                } else {
                    crate::io::log::early_print("non-zero");
                }
                crate::io::log::early_print("\n");

                // x86_64 TLS では FS ベースは TLS ブロックの終端を指す
                // 変数は FS:(-offset) でアクセスされる
                let fs_base = tls_end;

                if fsgsbase_supported {
                    write_fs_base(fs_base);
                } else {
                    write_fs_base_msr(fs_base);
                }
                crate::io::log::early_print("[PCPU] TLS ok\n");
            }
            #[cfg(any(test, target_os = "windows"))]
            {
                crate::io::log::early_print("[PCPU] TLS skipped in test or Windows build\n");
            }
        }
        crate::io::log::early_print("[PCPU] bsp ok\n");

        // 3. 残りのCPU（AP）のデータを初期化
        crate::io::log::early_print("[PCPU] loop start\n");
        let mut i = 1usize; // CPU 0は既に初期化済み
        while i < num_cpus {
            crate::io::log::early_print("[PCPU] i=0x");
            // 2-digit hex output (supports CPU 0-63)
            let hi = (i >> 4) & 0xF;
            let lo = i & 0xF;
            let to_hex = |n: usize| if n < 10 { b'0' + n as u8 } else { b'a' + (n - 10) as u8 };
            crate::io::log::early_print_char(to_hex(hi));
            crate::io::log::early_print_char(to_hex(lo));
            crate::io::log::early_print("\n");

            // SAFETY: 初期化中は他のCPUからアクセスされない
            // Initialize Hot/Cold structures (Phase 3)
            unsafe {
                PER_CPU_HOT[i] = PerCpuHot::new(i);
                PER_CPU_COLD[i] = PerCpuCold::new(i);
                PER_CPU_HOT[i].set_self_ptr();
                PER_CPU_HOT[i].set_cold(&mut PER_CPU_COLD[i] as *mut PerCpuCold);

                // Legacy: Full init for backward compatibility
                PER_CPU_DATA[i] = PerCpuData::new(i);
                PER_CPU_DATA[i].set_self_ptr();
            }
            crate::io::log::early_print("[PCPU] ok\n");
            i += 1;
        }
        crate::io::log::early_print("[PCPU] cpus ok\n");

        *ACTIVE_CPUS.lock() = num_cpus;
        mark_cpu_online(0);
        crate::io::log::early_print("[PCPU] done\n");
    });
    crate::io::log::early_print("[PCPU] exit\n");
}

/// 現在のCPUのPer-CPUデータを設定（AP用）
///
/// BSP（CPU 0）のGsBaseは `init_per_cpu()` 内で自動的に設定されるため、
/// この関数は主にAP（Application Processor）の起動時に使用する。
/// BSPに対して呼んでも問題ない（冪等）。
///
/// # Safety
/// - 各CPUのブート時に一度だけ呼ばれる必要がある
/// - cpu_idは有効な範囲内である必要がある
/// - init_per_cpu() が先に呼ばれている必要がある
pub unsafe fn setup_current_cpu(cpu_id: usize) {
    if cpu_id >= MAX_CPUS {
        return;
    }

    // If fastpath is adopted globally, enable CR4.FSGSBASE on THIS CPU
    // (CR4 is per-core, so each AP must enable it independently)
    if can_use_fsgsbase() && !is_fsgsbase_enabled() {
        unsafe { enable_fsgsbase(); }
    }

    // Use addr_of! to avoid creating a reference to static mut
    let hot_slot_ptr = core::ptr::addr_of!(PER_CPU_HOT[cpu_id]) as usize;
    
    // Idempotent: only initialize if not already done (check self_ptr)
    if unsafe { PER_CPU_HOT[cpu_id].self_ptr } != hot_slot_ptr {
        unsafe {
            // Initialize Hot/Cold structures
            PER_CPU_HOT[cpu_id] = PerCpuHot::new(cpu_id);
            PER_CPU_COLD[cpu_id] = PerCpuCold::new(cpu_id);
            PER_CPU_HOT[cpu_id].set_self_ptr();
            PER_CPU_HOT[cpu_id].set_cold(&mut PER_CPU_COLD[cpu_id] as *mut PerCpuCold);

            // Legacy: also init PerCpuData for backward compatibility
            PER_CPU_DATA[cpu_id] = PerCpuData::new(cpu_id);
            PER_CPU_DATA[cpu_id].set_self_ptr();
        }
    }

    // Set GSBase to PER_CPU_HOT for this CPU (Phase 3 optimization)
    unsafe { write_gsbase_any(hot_slot_ptr as u64); }

    mark_cpu_online(cpu_id);
}

/// Mark a CPU as online (best-effort)
pub fn mark_cpu_online(cpu_id: usize) {
    if cpu_id >= MAX_CPUS {
        return;
    }
    let bit = 1u64 << cpu_id;
    ONLINE_CPU_MASK.fetch_or(bit, Ordering::Release);
    let mut active = ACTIVE_CPUS.lock();
    if cpu_id + 1 > *active {
        *active = cpu_id + 1;
    }
}

/// Get a list of online CPU IDs
pub fn online_cpu_ids() -> Vec<usize> {
    let mask = ONLINE_CPU_MASK.load(Ordering::Acquire);
    let mut ids = Vec::new();
    for cpu_id in 0..MAX_CPUS {
        if (mask & (1u64 << cpu_id)) != 0 {
            ids.push(cpu_id);
        }
    }
    if ids.is_empty() {
        ids.push(0);
    }
    ids
}

/// 現在のCPU IDを取得
///
/// GsBase経由でPerCpuHotからCPU IDを読み取る
/// 従来の引数渡しが不要になる
///
/// # Panics
/// GsBaseが未初期化（0または不正な値）の場合、panicする。
/// これにより setup_current_cpu() 呼び忘れを早期に検出できる。
#[inline]
pub fn current_cpu_id() -> usize {
    // Use unified helper that handles both FSGSBASE and MSR paths
    let gs_base = unsafe { read_gsbase_any() };

    // GsBaseが0の場合は setup_current_cpu() が呼ばれていない
    if gs_base == 0 {
        panic!(
            "CPU Local Storage not initialized: GsBase is null. Call setup_current_cpu() first."
        );
    }

    // GSBase now points to PerCpuHot (Phase 3)
    let hot_ptr = gs_base as *const PerCpuHot;

    // SAFETY: hot_ptrは有効なPerCpuHotを指す
    let hot = unsafe { &*hot_ptr };

    // self_ptrで検証：本当に有効なPerCpuHotを指しているか
    if hot.self_ptr != hot_ptr as usize {
        panic!("CPU Local Storage corrupted: self_ptr mismatch");
    }

    hot.cpu_id
}

/// 現在のCPU IDを取得（パニックしない版）
///
/// 初期化前の状態でも安全に呼べる。
/// 初期化されていない場合は None を返す。
#[inline]
pub fn try_current_cpu_id() -> Option<usize> {
    // Use unified helper - safe even before per-CPU init
    let gs_base = unsafe { read_gsbase_any() };
    if gs_base == 0 {
        return None;
    }

    // GSBase now points to PerCpuHot (Phase 3)
    let hot_ptr = gs_base as *const PerCpuHot;
    let hot = unsafe { &*hot_ptr };

    // 検証
    if hot.self_ptr != hot_ptr as usize {
        return None;
    }

    Some(hot.cpu_id)
}

/// 現在のCPUの Legacy Per-CPUデータへの参照を取得
///
/// GSBase は PerCpuHot を指すため、cpu_id 経由で PER_CPU_DATA を引く
///
/// # Safety
/// init_per_cpu() が呼ばれている必要がある
#[inline]
pub unsafe fn current_per_cpu() -> Option<&'static PerCpuData> {
    // Get cpu_id from Hot (GSBase -> PerCpuHot)
    let hot = current_per_cpu_hot()?;
    let cpu = hot.cpu_id;
    if cpu >= MAX_CPUS {
        return None;
    }

    // Access legacy PER_CPU_DATA via cpu_id
    let ptr = core::ptr::addr_of!(PER_CPU_DATA[cpu]);
    let pc = &*ptr;

    // Validate legacy self_ptr as well
    if pc.self_ptr != ptr as usize {
        return None;
    }

    Some(pc)
}

/// 現在のCPUの Legacy Per-CPUデータへの可変参照を取得
///
/// GSBase は PerCpuHot を指すため、cpu_id 経由で PER_CPU_DATA を引く
///
/// # Safety
/// - init_per_cpu() が呼ばれている必要がある
/// - 同時に複数の可変参照を取得してはならない
#[inline]
pub unsafe fn current_per_cpu_mut() -> Option<&'static mut PerCpuData> {
    // Get cpu_id from Hot (GSBase -> PerCpuHot)
    let hot = current_per_cpu_hot()?;
    let cpu = hot.cpu_id;
    if cpu >= MAX_CPUS {
        return None;
    }

    // Access legacy PER_CPU_DATA via cpu_id
    let ptr = core::ptr::addr_of_mut!(PER_CPU_DATA[cpu]);
    let pc = &mut *ptr;

    // Validate legacy self_ptr as well
    if pc.self_ptr != ptr as usize {
        return None;
    }

    Some(pc)
}

/// 特定のCPUのPer-CPUデータへの参照を取得
///
/// # Safety
/// cpu_idは有効な範囲内である必要がある
pub unsafe fn get_per_cpu(cpu_id: usize) -> Option<&'static PerCpuData> {
    if cpu_id >= MAX_CPUS {
        return None;
    }

    let active = *ACTIVE_CPUS.lock();
    if cpu_id >= active {
        return None;
    }

    // SAFETY: cpu_idは有効範囲内
    unsafe { Some(&PER_CPU_DATA[cpu_id]) }
}

/// アクティブなCPU数を取得
pub fn active_cpu_count() -> usize {
    *ACTIVE_CPUS.lock()
}

// ============================================================================
// Global Interrupt Context Helpers
// ============================================================================

/// Check if the current CPU is executing in interrupt context.
///
/// Uses PerCpuHot directly for fast access (Hot/Cold optimization).
///
/// # Returns
/// - `true` if running inside an interrupt handler (ISR)
/// - `false` if running in normal context or Per-CPU is not initialized
#[inline]
pub fn in_interrupt_context() -> bool {
    // Use PerCpuHot directly (Hot/Cold optimization)
    unsafe {
        current_per_cpu_hot()
            .map(|hot| hot.in_interrupt())
            .unwrap_or(false)
    }
}

/// Enter interrupt context (call at the start of every ISR).
///
/// Uses PerCpuHot directly for fast access (Hot/Cold optimization).
///
/// # Safety
/// Must only be called from actual interrupt handler entry points.
#[inline]
pub fn enter_interrupt() {
    // Use PerCpuHot directly (Hot/Cold optimization)
    unsafe {
        if let Some(hot) = current_per_cpu_hot() {
            hot.enter_interrupt();
        }
    }
}

/// Exit interrupt context (call at the end of every ISR).
///
/// Uses PerCpuHot directly for fast access (Hot/Cold optimization).
///
/// # Safety
/// Must only be called from actual interrupt handler exit points.
#[inline]
pub fn exit_interrupt() {
    // Use PerCpuHot directly (Hot/Cold optimization)
    unsafe {
        if let Some(hot) = current_per_cpu_hot() {
            hot.exit_interrupt();
        }
    }
}

#[cfg(test)]
mod tests;

