// ============================================================================
// kernel/src/io/iommu/common/dma/iova_allocator.rs - IOVA-Specific Allocator with Quarantine
// ============================================================================

//
// DESIGN: This module implements the IOVA-specific allocator that wraps the generic
// memory management `FastBitmapAllocator`. It adds:
//
// 1. **Per-CPU Quarantine**: Delayed reclamation for IOTLB consistency.
//    Frees are not applied immediately but queued until the IOMMU IOTLB is invalidated.
// 2. **Epoch Management**: Tracks IOTLB invalidation generations.
//    Quarantined pages are only freed after the global epoch advances.
// 3. **IOVA Granularity**: Strongly typed page sizes (4KB, 2MB, 1GB).
//
// ARCHITECTURE:
//
// ```text
// ┌─────────────────────────────────────────────────────────────┐
// │                       IovaAllocator                         │
// │                                                             │
// │  ┌──────────────────────┐   ┌────────────────────────────┐  │
// │  │  Quarantine Layer                     │   │      Epoch Manager         │  │
// │  │ (Per-CPU Rings)      │   │ (Atomic Sequence Counter)  │  │
// │  └──────────┬───────────┘   └──────────────┬─────────────┘  │
// │             │ Free (Delayed)               │ Advance        │
// │             ▼                              ▼                │
// │  ┌────────────────────────────────────────────────────────┐ │
// │  │             mm::FastBitmapAllocator                    │ │
// │  │          (Generic Bitmap + Magazine)                   │ │
// │  └────────────────────────────────────────────────────────┘ │
// └─────────────────────────────────────────────────────────────┘
// ```
// ============================================================================

use crate::sync::IrqMutex;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::mm::phys::fast_allocator::FastBitmapAllocator;
pub use crate::mm::phys::fast_allocator::PageGranularity;
use crate::mm::remote_free::{QuarantineEntry, QuarantineRing}; // Using generic QuarantineRing

use crate::io::iommu::types::IommuError;

/// Default capacity for quarantine ring (must be power of 2)
const QUARANTINE_CAPACITY: usize = 256;

// Batch size used to drain fallback ring
const FALLBACK_DRAIN_BATCH: usize = 32;

type IovaQuarantine = IrqMutex<QuarantineRing<QUARANTINE_CAPACITY>>;
type QuarantineSnapshot = Arc<[Arc<IovaQuarantine>]>;

// ============================================================================
// IovaAllocator
// ============================================================================

/// IOVA Allocator with Epoch-based Quarantine
#[derive(Debug)]
pub struct IovaAllocator {
    /// Generic Fast Bitmap Allocator (providing core allocation/free logic)
    inner: FastBitmapAllocator,

    /// Immutable snapshot of per-CPU quarantine rings. Entries remain at stable
    /// addresses while firmware discovery grows the slot set.
    quarantines: IrqMutex<QuarantineSnapshot>,

    /// Allocator-local quarantine for execution without a current CPU or when
    /// CPU-slot provisioning cannot allocate. It must not be shared between
    /// IOVA address spaces.
    fallback_quarantine: IovaQuarantine,

    /// Current global epoch (incremented *before* IOTLB invalidation)
    current_epoch: AtomicU32,

    /// Last completed epoch (updated *after* IOTLB invalidation completes)
    /// All quarantine entries with epoch <= completed_epoch are safe to free.
    completed_epoch: AtomicU32,

    // Statistics
    stats: IovaAllocatorStats,
}

/// IOVA Allocator Statistics
#[derive(Debug, Default)]
pub struct IovaAllocatorStats {
    pub quarantine_pushes: AtomicU64,
    pub quarantine_drains: AtomicU64,
}

impl IovaAllocator {
    /// Create a new IOVA Allocator
    ///
    /// # Arguments
    /// * `base` - Base IOVA address (must be 4KB aligned)
    /// * `size` - Size of the IOVA space (bytes)
    pub fn new(base: u64, size: u64) -> Self {
        // Initialize Inner Allocator
        let mut inner = FastBitmapAllocator::new(base, size);
        if let Some(runtime) = crate::cpu::try_runtime() {
            let online_ids = runtime
                .snapshot()
                .online()
                .iter()
                .map(crate::cpu::CpuId::as_usize)
                .collect::<Vec<_>>();
            inner.reconfigure_for_cpu_ids(&online_ids);
        }

        Self {
            inner,
            quarantines: IrqMutex::new(Arc::from([])),
            fallback_quarantine: IrqMutex::new(QuarantineRing::new()),
            current_epoch: AtomicU32::new(0),
            completed_epoch: AtomicU32::new(0),
            stats: IovaAllocatorStats::default(),
        }
    }

    fn quarantine_for(&self, cpu_id: crate::cpu::CpuId) -> Option<Arc<IovaQuarantine>> {
        let slot_count = crate::cpu::try_runtime()?.snapshot().slots().len();
        let required_slots = slot_count.max(cpu_id.as_usize().saturating_add(1));

        loop {
            let current = self.quarantines.lock().clone();
            if let Some(quarantine) = current.get(cpu_id.as_usize()) {
                return Some(Arc::clone(quarantine));
            }

            let mut expanded = Vec::new();
            expanded.try_reserve_exact(required_slots).ok()?;
            expanded.extend(current.iter().cloned());
            expanded.resize_with(required_slots, || {
                Arc::new(IrqMutex::new(QuarantineRing::new()))
            });
            let expanded: QuarantineSnapshot = Arc::from(expanded.into_boxed_slice());

            let mut published = self.quarantines.lock();
            if Arc::ptr_eq(&published, &current) {
                *published = expanded;
                return published.get(cpu_id.as_usize()).cloned();
            }
        }
    }

    // ========================================================================
    // Allocation API (Delegated to FastBitmapAllocator)
    // ========================================================================

    /// Allocate a 4KB page
    #[inline]
    pub fn allocate_4k(&self) -> Option<u64> {
        self.inner.allocate_4k()
    }

    /// Allocate a 2MB huge page
    #[inline]
    pub fn allocate_2m(&self) -> Option<u64> {
        self.inner.allocate_2m()
    }

    /// Allocate a 1GB huge page
    #[inline]
    pub fn allocate_1g(&self) -> Option<u64> {
        self.inner.allocate_1g()
    }

    /// Allocate a contiguous range
    #[inline]
    pub fn allocate_contiguous(&self, size: u64, align: u64) -> Option<u64> {
        self.inner.allocate_contiguous(size, align)
    }

    /// Allocate with a specific page granularity.
    #[inline]
    pub fn allocate(&self, size: u64, granularity: PageGranularity) -> Option<u64> {
        if size != granularity.size_bytes() {
            return None;
        }
        match granularity {
            PageGranularity::Page4K => self.allocate_4k(),
            PageGranularity::Page2M => self.allocate_2m(),
            PageGranularity::Page1G => self.allocate_1g(),
        }
    }

    /// Get base address
    #[inline]
    pub fn base(&self) -> u64 {
        self.inner.base()
    }

    /// Get total size
    #[inline]
    pub fn size(&self) -> u64 {
        self.inner.size()
    }

    /// Reserve a range of addresses
    pub fn reserve(&self, start: u64, size: u64) -> Result<(), IommuError> {
        self.inner
            .reserve(start, size)
            .map_err(|_| IommuError::InvalidAddress)
    }

    // ========================================================================
    // Deallocation API (With Quarantine)
    // ========================================================================

    /// Free a page/block with delayed reclamation (Quarantine)
    ///
    /// Use this for normal IOVA unmapping. The IOVA will be added to the
    /// current CPU's quarantine ring stamped with the current epoch.
    pub fn free_with_granularity(
        &self,
        addr: u64,
        granularity: PageGranularity,
    ) -> Result<(), IommuError> {
        let epoch = self.current_epoch.load(Ordering::Relaxed);
        let entry = QuarantineEntry {
            addr,
            epoch,
            size_class: match granularity {
                PageGranularity::Page4K => 0,
                PageGranularity::Page2M => 1,
                PageGranularity::Page1G => 2,
            },
        };

        let current_cpu = crate::cpu::CurrentCpu::acquire().map(|current| current.id());
        if let Some((cpu_id, quarantine)) = current_cpu.and_then(|cpu_id| {
            self.quarantine_for(cpu_id)
                .map(|quarantine| (cpu_id, quarantine))
        }) {
            let pushed = {
                let mut ring = quarantine.lock();
                ring.push(entry.addr, entry.size_class, entry.epoch)
            };

            if pushed {
                self.stats.quarantine_pushes.fetch_add(1, Ordering::Relaxed);
                Ok(())
            } else {
                // Ring full: Do NOT force drain here because it bypasses IOTLB consistency (Epochs).
                // Draining without a proper IOTLB flush creates a DMA Use-After-Free window.
                //
                // The caller (IOMMU driver/domain) must handle this Error by:
                // 1. Advancing the global epoch.
                // 2. Issuing a global IOTLB/Context flush.
                // 3. Completing the epoch (which will safely drain these rings).
                // 4. Retrying the free.

                log::warn!(
                    "[IOVA][SECURITY] Quarantine ring full for CPU {}. Rejecting free until IOTLB flush.",
                    cpu_id
                );
                Err(IommuError::OutOfMemory)
            }
        } else {
            self.free_via_fallback_quarantine(entry, addr)
        }
    }

    /// Fallback quarantine path when per-CPU quarantine is unavailable
    fn free_via_fallback_quarantine(
        &self,
        entry: QuarantineEntry,
        addr: u64,
    ) -> Result<(), IommuError> {
        let mut fb = self.fallback_quarantine.lock();
        if fb.push_entry(entry) {
            self.stats.quarantine_pushes.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        // Quarantine full: We MUST NOT force drain here because it bypasses IOTLB consistency (Epochs).
        // Draining without a proper IOTLB flush creates a DMA Use-After-Free window.
        //
        // The caller (IommuDomain) handles this Error by:
        // 1. Issuing a global IOTLB/Context flush for the domain.
        // 2. Advancing and completing the epoch (safely draining these rings).
        // 3. Retrying the free.

        log::warn!(
            "[IOVA][SECURITY] Fallback quarantine full. Rejecting free of 0x{:x} until IOTLB flush.",
            addr
        );
        Err(IommuError::OutOfMemory)
    }

    /// アドレスとサイズから最適な解放粒度とステップサイズを選択
    fn select_free_granularity(addr: u64, size: u64) -> (PageGranularity, u64) {
        use crate::mm::phys::fast_allocator::{PAGE_SIZE_1G, PAGE_SIZE_2M, PAGE_SIZE_4K};
        if size >= PAGE_SIZE_1G && addr % PAGE_SIZE_1G == 0 {
            (PageGranularity::Page1G, PAGE_SIZE_1G)
        } else if size >= PAGE_SIZE_2M && addr % PAGE_SIZE_2M == 0 {
            (PageGranularity::Page2M, PAGE_SIZE_2M)
        } else {
            (PageGranularity::Page4K, PAGE_SIZE_4K)
        }
    }

    /// Free an IOVA range (splits into granularity blocks)
    pub fn free(&self, mut addr: u64, mut size: u64) -> Result<(), IommuError> {
        use crate::mm::phys::fast_allocator::PAGE_SIZE_4K;

        // Ensure alignment
        if addr % PAGE_SIZE_4K != 0 || size % PAGE_SIZE_4K != 0 {
            return Err(IommuError::InvalidAlignment);
        }

        // LOOP_PROOF: mode=condition; reason=Free loop decreases remaining size by step each iteration until the requested range is fully released.;
        while size > 0 {
            let (granularity, step) = Self::select_free_granularity(addr, size);
            self.free_with_granularity(addr, granularity)?;
            addr += step;
            size -= step;
        }
        Ok(())
    }

    /// Allocate within a limit (e.g. 32-bit address space)
    pub fn allocate_with_limit(
        &self,
        size: u64,
        granularity: PageGranularity,
        limit: u64,
    ) -> Option<u64> {
        if size > granularity.size_bytes() {
            // Multi-page: use contiguous allocator with limit check
            let addr = self
                .inner
                .allocate_contiguous(size, granularity.size_bytes())?;
            if addr.checked_add(size)? <= limit {
                Some(addr)
            } else {
                // Over limit — free and fail
                // Some FastBitmapAllocator shims (test stubs) don't implement
                // `free_range_immediate`. Fall back to freeing page-by-page
                // using `free_immediate` (4K granularity) which is available
                // on both the test shim and the real allocator.
                {
                    use crate::mm::phys::fast_allocator::PAGE_SIZE_4K;
                    let mut p = addr;
                    let end = addr.saturating_add(size);
                    // LOOP_PROOF: mode=condition; reason=Fallback release loop advances p by PAGE_SIZE_4K each pass until it reaches end.;
                    while p < end {
                        let _ = self.inner.free_immediate(p, PageGranularity::Page4K);
                        p = p.saturating_add(PAGE_SIZE_4K);
                    }
                }
                None
            }
        } else {
            match granularity {
                PageGranularity::Page4K => self.inner.allocate_4k_below(limit),
                PageGranularity::Page2M => self.inner.allocate_2m_below(limit),
                PageGranularity::Page1G => self.inner.allocate_1g_below(limit),
            }
        }
    }

    /// Free immediately (Bypass Quarantine)
    ///
    /// Use this only during initialization or teardown when no IOTLB caching is active.
    pub fn free_immediate(&self, mut addr: u64, mut size: u64) -> Result<(), IommuError> {
        // LOOP_PROOF: mode=condition; reason=Immediate-free loop subtracts a positive step from size each pass until zero.;
        while size > 0 {
            let (granularity, step) = Self::select_free_granularity(addr, size);
            self.inner
                .free_immediate(addr, granularity)
                .map_err(|_| IommuError::NotMapped)?;
            addr += step;
            size -= step;
        }
        Ok(())
    }

    // ========================================================================
    // Epoch / Quarantine Management
    // ========================================================================

    /// Advance the global epoch (Start of IOTLB Invalidation)
    ///
    /// Call this *before* issuing IOTLB invalidation commands.
    /// Returns the epoch value that was active BEFORE advancing. Use this value
    /// with `complete_epoch` to safely reclaim only those entries that were
    /// quarantined prior to this invalidation.
    pub fn advance_epoch(&self) -> u32 {
        self.current_epoch.fetch_add(1, Ordering::AcqRel)
    }

    /// Complete an epoch (End of IOTLB Invalidation)
    ///
    /// Call this *after* generic IOTLB invalidation completion is confirmed.
    /// This allows quarantined items stamped with an epoch <= `epoch` to be freed.
    pub fn complete_epoch(&self, epoch: u32) {
        // Monotonic update: only forward (with wrap-around support)
        // Using compare_exchange loop because fetch_max uses unsigned comparison
        // which breaks when the 32-bit epoch wraps around.
        let mut current = self.completed_epoch.load(Ordering::Acquire);
        // LOOP_PROOF: mode=event; reason=Epoch CAS loop exits when update is no longer needed or compare_exchange successfully publishes epoch.;
        loop {
            // Check if 'epoch' is ahead of 'current' in a wrap-around safe way
            if (epoch.wrapping_sub(current) as i32) <= 0 {
                break;
            }
            match self.completed_epoch.compare_exchange_weak(
                current,
                epoch,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(new) => current = new,
            }
        }

        let completed = self.completed_epoch.load(Ordering::Acquire);
        let quarantines = self.quarantines.lock().clone();
        for quarantine in quarantines.iter() {
            self.drain_quarantine(quarantine, completed);
        }
        self.drain_fallback_for_epoch(completed);
    }

    /// Drain quarantine ring for a specific CPU
    ///
    /// Reclaims pages that have been safe-guarded long enough.
    fn drain_quarantine(&self, quarantine: &IovaQuarantine, completed_epoch: u32) {
        // We use a small on-stack buffer to batch frees
        // This minimizes lock hold time on the quarantine ring
        let mut entries = [QuarantineEntry::default(); 32];

        // LOOP_PROOF: mode=event; reason=Drain loop exits when no reclaimable entries remain or when batch count falls below buffer length.;
        loop {
            let count = {
                let mut ring = quarantine.lock();
                ring.drain_older_than(completed_epoch, entries.len(), &mut entries)
            };

            if count == 0 {
                break;
            }

            // Process batch free outside the lock
            for entry in entries.iter().take(count).copied() {
                self.reclaim_entry(entry);
            }

            self.stats
                .quarantine_drains
                .fetch_add(count as u64, Ordering::Relaxed);

            if count < entries.len() {
                break; // Ring drained enough
            }
        }
    }

    fn reclaim_entry(&self, entry: QuarantineEntry) {
        let granularity = match entry.size_class {
            0 => PageGranularity::Page4K,
            1 => PageGranularity::Page2M,
            2 => PageGranularity::Page1G,
            invalid => panic!("invalid IOVA quarantine size class {invalid}"),
        };
        if self.inner.free_immediate(entry.addr, granularity).is_err() {
            panic!(
                "IOVA quarantine reclaimed unallocated address {:#x}",
                entry.addr
            );
        }
    }

    /// Drain the allocator-local fallback quarantine.
    fn drain_fallback_for_epoch(&self, completed_epoch: u32) {
        let mut entries = [QuarantineEntry::default(); FALLBACK_DRAIN_BATCH];

        // LOOP_PROOF: mode=event; reason=Fallback drain loop exits when ring is empty or when drained batch is smaller than buffer capacity.;
        loop {
            let count = {
                let mut fallback = self.fallback_quarantine.lock();
                fallback.drain_older_than(completed_epoch, entries.len(), &mut entries)
            };

            if count == 0 {
                break;
            }

            for entry in entries.iter().take(count).copied() {
                self.reclaim_entry(entry);
            }

            self.stats
                .quarantine_drains
                .fetch_add(count as u64, Ordering::Relaxed);

            if count < entries.len() {
                break;
            }
        }
    }
}
