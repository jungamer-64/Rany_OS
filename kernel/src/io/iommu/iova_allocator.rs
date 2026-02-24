// ============================================================================
// kernel/src/io/iommu/iova_allocator.rs - IOVA-Specific Allocator with Quarantine
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

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::sync::IrqMutex;

use crate::mm::phys::fast_allocator::{FastBitmapAllocator, PageGranularity};
use crate::mm::remote_free::{QuarantineRing, QuarantineEntry}; // Using generic QuarantineRing
#[cfg(not(feature = "qemu-test-export"))]
use crate::per_cpu::MAX_CPUS;

use super::IommuError;

/// Backward compatibility alias
pub type IovaGranularity = PageGranularity;

/// Default capacity for quarantine ring (must be power of 2)
const QUARANTINE_CAPACITY: usize = 256;

#[cfg(feature = "qemu-test-export")]
const IOVA_ALLOCATOR_MAX_CPUS: usize = 1;
#[cfg(not(feature = "qemu-test-export"))]
const IOVA_ALLOCATOR_MAX_CPUS: usize = MAX_CPUS;

// Global fallback quarantine ring used when per-CPU quarantines cannot be allocated (early boot / OOM).
// This static ring does not require heap allocation and provides limited quarantine semantics to
// prevent immediate frees and potential UAF via DMA during early initialization.
static FALLBACK_QUARANTINE: IrqMutex<QuarantineRing<QUARANTINE_CAPACITY>> =
    IrqMutex::new(QuarantineRing::new());

// Batch size used to drain fallback ring
const FALLBACK_DRAIN_BATCH: usize = 32;

// ============================================================================
// IovaAllocator
// ============================================================================

/// IOVA Allocator with Epoch-based Quarantine
pub struct IovaAllocator {
    /// Generic Fast Bitmap Allocator (providing core allocation/free logic)
    inner: FastBitmapAllocator,

    /// Per-CPU Quarantine Rings (delayed free queue)
    /// Protected by IrqMutex to allow safe access from IRQ handlers
    ///
    /// Per-CPU quarantine storage (None = fallback to immediate free)
    quarantines: Option<Box<[IrqMutex<QuarantineRing<QUARANTINE_CAPACITY>>]>>,


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
    pub quarantine_forced_drains: AtomicU64,
}

impl IovaAllocator {
    /// Create a new IOVA Allocator
    ///
    /// # Arguments
    /// * `base` - Base IOVA address (must be 4KB aligned)
    /// * `size` - Size of the IOVA space (bytes)
    pub fn new(base: u64, size: u64) -> Self {
        // Initialize Inner Allocator
        let inner = FastBitmapAllocator::new(base, size);

        // Initialize Per-CPU Quarantine Rings (try to allocate, but avoid panic on OOM)
        crate::io::log::early_print("[IOVA] new: entering IovaAllocator::new\n");
        // Check heap/allocator state for diagnostics
        if let Some(initialized) = crate::memory::ALLOCATOR.is_initialized() {
            crate::io::log::early_print("[IOVA] heap_initialized=");
            crate::io::log::early_print_dec(if initialized { 1 } else { 0 });
            crate::io::log::early_print("\n");
        } else {
            crate::io::log::early_print("[IOVA] ALLOCATOR lock poisoned\n");
        }

        let quarantines = {
            let mut v: Vec<IrqMutex<QuarantineRing<QUARANTINE_CAPACITY>>> = Vec::new();
            crate::io::log::early_print("[IOVA] new: try_reserve(IOVA_ALLOCATOR_MAX_CPUS)\n");
            if v.try_reserve(IOVA_ALLOCATOR_MAX_CPUS).is_ok() {
                crate::io::log::early_print("[IOVA] try_reserve OK, allocating quarantines\n");
                for _ in 0..IOVA_ALLOCATOR_MAX_CPUS {
                    v.push(IrqMutex::new(QuarantineRing::new()));
                }
                crate::io::log::early_print("[IOVA] quarantines allocated\n");
                Some(v.into_boxed_slice())
            } else {
                // Heap not available or OOM during early boot: fall back to None and
                // perform immediate frees instead of quarantining.
                crate::io::log::early_print("[IOVA] try_reserve FAILED - falling back to immediate frees\n");
                None
            }
        };

        crate::io::log::early_print("[IOVA] new: done\n");

        Self {
            inner,
            quarantines,
            current_epoch: AtomicU32::new(0),
            completed_epoch: AtomicU32::new(0),
            stats: IovaAllocatorStats::default(),
        }
    }

    /// Configure arenas for specific CPU IDs (NUMA awareness)
    pub fn configure_arenas_for_cpu_ids(&mut self, cpu_ids: &[usize]) {
        self.inner.reconfigure_for_cpu_ids(cpu_ids);
    }

    /// Enable single-writer arena optimizations
    pub fn enable_single_writer_arenas(&self) {
        self.inner.enable_single_writer_arenas();
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

    /// Allocate with granularity (Backward Compatibility)
    #[inline]
    pub fn allocate(&self, size: u64, granularity: IovaGranularity) -> Option<u64> {
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
        self.inner.reserve(start, size)
            .map_err(|_| IommuError::InvalidAddress)
    }

    // ========================================================================
    // Deallocation API (With Quarantine)
    // ========================================================================

    /// Free a page/block with delayed reclamation (Quarantine)
    ///
    /// Use this for normal IOVA unmapping. The IOVA will be added to the
    /// current CPU's quarantine ring stamped with the current epoch.
    pub fn free_with_granularity(&self, addr: u64, granularity: PageGranularity) -> Result<(), IommuError> {
        let cpu_id = crate::per_cpu::try_current_cpu_id().unwrap_or(0);
        
        // Ensure CPU ID is valid
        if cpu_id >= IOVA_ALLOCATOR_MAX_CPUS {
            // Fallback for invalid CPU ID: behave as immediate free? 
            // Or just use CPU 0. Let's use CPU 0 for safety but this shouldn't happen.
            return self.free_immediate(addr, granularity);
        }

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

        // Try to push to quarantine ring (fall back to immediate free if quarantines unavailable)
        if let Some(ref qbox) = self.quarantines {
            // Try to push to quarantine ring
            let pushed = {
                let mut ring = qbox[cpu_id].lock();
                ring.push(entry.addr, entry.size_class, entry.epoch)
            };

            if pushed {
                self.stats.quarantine_pushes.fetch_add(1, Ordering::Relaxed);
                Ok(())
            } else {
                // Ring full: Force drain this ring to make space, then try push again
                // This is a "forced drain" - potentially expensive but prevents failure
                self.drain_quarantine_for_cpu(cpu_id, true);
                self.stats.quarantine_forced_drains.fetch_add(1, Ordering::Relaxed);

                // Retry push
                let mut ring = qbox[cpu_id].lock();
                if ring.push(entry.addr, entry.size_class, entry.epoch) {
                     self.stats.quarantine_pushes.fetch_add(1, Ordering::Relaxed);
                     Ok(())
                } else {
                    // Still full after drain? This is bad. Fallback to immediate free.
                    // NOTE: Immediate free bypasses quarantine safety! 
                    // Only safe if we assume IOTLB flush happens immediately after this call (which it usually doesn't).
                    // But dropping the free is worse (leak).
                    // A better approach might be to wait/spin, but we are in kernel context.
                    self.inner.free_immediate(addr, granularity)
                        .map_err(|_| IommuError::NotMapped)
                }
            }
        } else {
            self.free_via_fallback_quarantine(entry, addr, granularity)
        }
    }

    /// Fallback quarantine path when per-CPU quarantine is unavailable
    fn free_via_fallback_quarantine(&self, entry: QuarantineEntry, addr: u64, granularity: PageGranularity) -> Result<(), IommuError> {
        {
            let mut fb = FALLBACK_QUARANTINE.lock();
            if fb.push(entry.addr, entry.size_class, entry.epoch) {
                self.stats.quarantine_pushes.fetch_add(1, Ordering::Relaxed);
                crate::io::log::early_print("[IOVA] free_with_granularity: pushed to FALLBACK_QUARANTINE\n");
                return Ok(());
            }

            crate::io::log::early_print("[IOVA] free_with_granularity: FALLBACK_QUARANTINE full, forcing drain\n");
            let mut batch = [QuarantineEntry::default(); FALLBACK_DRAIN_BATCH];
            let drained = fb.drain_all(&mut batch);
            if drained > 0 {
                for i in 0..drained {
                    let e = batch[i];
                    let g = match e.size_class {
                        0 => PageGranularity::Page4K,
                        1 => PageGranularity::Page2M,
                        2 => PageGranularity::Page1G,
                        _ => PageGranularity::Page4K,
                    };
                    let _ = self.inner.free_immediate(e.addr, g);
                }
                self.stats.quarantine_forced_drains.fetch_add(drained as u64, Ordering::Relaxed);
            }

            if fb.push(entry.addr, entry.size_class, entry.epoch) {
                self.stats.quarantine_pushes.fetch_add(1, Ordering::Relaxed);
                crate::io::log::early_print("[IOVA] free_with_granularity: pushed to FALLBACK_QUARANTINE after drain\n");
                return Ok(());
            }
            crate::io::log::early_print("[IOVA] free_with_granularity: FALLBACK_QUARANTINE still full, will immediate free\n");
        }

        self.inner.free_immediate(addr, granularity)
            .map_err(|_| IommuError::NotMapped)
    }

    /// アドレスとサイズから最適な解放粒度とステップサイズを選択
    fn select_free_granularity(addr: u64, size: u64) -> (PageGranularity, u64) {
        use crate::mm::phys::fast_allocator::{PAGE_SIZE_4K, PAGE_SIZE_2M, PAGE_SIZE_1G};
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

        while size > 0 {
            let (granularity, step) = Self::select_free_granularity(addr, size);
            self.free_with_granularity(addr, granularity)?;
            addr += step;
            size -= step;
        }
        Ok(())
    }

    /// Allocate within a limit (e.g. 32-bit address space)
    pub fn allocate_with_limit(&self, size: u64, granularity: IovaGranularity, limit: u64) -> Option<u64> {
        if size > granularity.size_bytes() {
            // Multi-page: use contiguous allocator with limit check
            let addr = self.inner.allocate_contiguous(size, granularity.size_bytes())?;
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
                    while p < end {
                        let _ = self.inner.free_immediate(p, PageGranularity::Page4K);
                        p = p.saturating_add(PAGE_SIZE_4K);
                    }
                }
                None
            }
        } else {
            match granularity {
                IovaGranularity::Page4K => self.inner.allocate_4k_below(limit),
                IovaGranularity::Page2M => self.inner.allocate_2m_below(limit),
                IovaGranularity::Page1G => self.inner.allocate_1g_below(limit),
            }
        }
    }

    /// Free immediately (Bypass Quarantine)
    ///
    /// Use this only during initialization or teardown when no IOTLB caching is active.
    pub fn free_immediate(&self, addr: u64, granularity: PageGranularity) -> Result<(), IommuError> {
        self.inner.free_immediate(addr, granularity)
            .map_err(|_| IommuError::NotMapped)
    }

    // ========================================================================
    // Epoch / Quarantine Management
    // ========================================================================

    /// Advance the global epoch (Start of IOTLB Invalidation)
    ///
    /// Call this *before* issuing IOTLB invalidation commands.
    /// Returns the new epoch value.
    pub fn advance_epoch(&self) -> u32 {
        self.current_epoch.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Complete an epoch (End of IOTLB Invalidation)
    ///
    /// Call this *after* generic IOTLB invalidation completion is confirmed.
    /// This allows quarantined items from `epoch` to be freed.
    pub fn complete_epoch(&self, epoch: u32) {
        // Monotonic update: only forward
        let _ = self.completed_epoch.fetch_max(epoch, Ordering::Release);
        
        // Opportunistic drain: Try to reclaim memory from current CPU's ring
        if let Some(cpu_id) = crate::per_cpu::try_current_cpu_id() {
             if cpu_id < IOVA_ALLOCATOR_MAX_CPUS {
                 self.drain_quarantine_for_cpu(cpu_id, false);
             }
        }

        // Also attempt to reclaim from global fallback quarantine (if any)
        let completed = self.completed_epoch.load(Ordering::Acquire);
        self.drain_fallback_for_epoch(completed, false);
    }

    /// Drain quarantine ring for a specific CPU
    ///
    /// Reclaims pages that have been safe-guarded long enough.
    fn drain_quarantine_for_cpu(&self, cpu_id: usize, force: bool) {
        let completed_epoch = self.completed_epoch.load(Ordering::Acquire);
        
        // We use a small on-stack buffer to batch frees
        // This minimizes lock hold time on the quarantine ring
        let mut entries = [QuarantineEntry::default(); 32];
        
        loop {
            let count = if let Some(ref qbox) = self.quarantines {
                let mut ring = qbox[cpu_id].lock();
                if force {
                    // In force mode, we just take the oldest items regardless of epoch
                    // WARNING: potentially unsafe for IOTLB, but prevents OOM/deadlock
                    ring.drain_all(&mut entries)
                } else {
                    ring.drain_older_than(completed_epoch, entries.len(), &mut entries)
                }
            } else {
                0
            };

            if count == 0 {
                break;
            }

            // Process batch free outside the lock
            for i in 0..count {
                let entry = entries[i];
                let granularity = match entry.size_class {
                    0 => PageGranularity::Page4K,
                    1 => PageGranularity::Page2M,
                    2 => PageGranularity::Page1G,
                    _ => PageGranularity::Page4K,
                };
                
                // Free to the underlying allocator
                let _ = self.inner.free_immediate(entry.addr, granularity);
            }
           
            self.stats.quarantine_drains.fetch_add(count as u64, Ordering::Relaxed);
           
            if count < entries.len() {
                break; // Ring drained enough
            }
        }
    }

    /// Drain the global fallback quarantine (used when per-CPU rings were not alloc'd)
    fn drain_fallback_for_epoch(&self, completed_epoch: u32, force: bool) {
        let mut entries = [QuarantineEntry::default(); FALLBACK_DRAIN_BATCH];

        loop {
            let count = {
                let mut fb = FALLBACK_QUARANTINE.lock();
                if force {
                    fb.drain_all(&mut entries)
                } else {
                    fb.drain_older_than(completed_epoch, entries.len(), &mut entries)
                }
            };

            if count == 0 {
                break;
            }

            for i in 0..count {
                let entry = entries[i];
                let granularity = match entry.size_class {
                    0 => PageGranularity::Page4K,
                    1 => PageGranularity::Page2M,
                    2 => PageGranularity::Page1G,
                    _ => PageGranularity::Page4K,
                };
                let _ = self.inner.free_immediate(entry.addr, granularity);
            }

            self.stats.quarantine_drains.fetch_add(count as u64, Ordering::Relaxed);

            if count < entries.len() {
                break;
            }
        }
    }

    /// Per-CPU maintenance (call periodically, e.g. from timer or idle loop)
    pub fn poll(&self) {
        // Drain remote frees (cross-CPU frees)
        self.inner.drain_remote_frees();

        // Drain quarantine if needed
        if let Some(cpu_id) = crate::per_cpu::try_current_cpu_id() {
            if cpu_id < IOVA_ALLOCATOR_MAX_CPUS {
                 self.drain_quarantine_for_cpu(cpu_id, false);
            }
        }

        // Also attempt to drain global fallback quarantine
        let completed = self.completed_epoch.load(Ordering::Acquire);
        self.drain_fallback_for_epoch(completed, false);
    }
}
