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
// │  │          (Shared page occupancy)                   │ │
// │  └────────────────────────────────────────────────────────┘ │
// └─────────────────────────────────────────────────────────────┘
// ```
// ============================================================================

#![deny(unsafe_code)]

use crate::sync::IrqMutex;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

#[path = "flush_epoch.rs"]
mod flush_epoch;
use flush_epoch::{FlushBoundary, RetirementClock};

pub use crate::mm::phys::fast_allocator::PageGranularity;
use crate::mm::phys::fast_allocator::{AddressPoolError, FastBitmapAllocator};
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

    /// Retirement generations are advanced only around allocator-wide invalidation.
    clock: RetirementClock,

    // Statistics
    stats: IovaAllocatorStats,
}

/// IOVA Allocator Statistics
#[derive(Debug, Default)]
pub struct IovaAllocatorStats {
    pub quarantine_pushes: AtomicU64,
    pub quarantine_drains: AtomicU64,
}

/// Pending allocator-wide invalidation. Dropping it leaves every IOVA quarantined.
/// The Arc binds completion to the exact allocator even across replacement or await.
#[derive(Debug)]
pub(in crate::io::iommu) struct PendingGlobalIovaFlush {
    allocator: Arc<IovaAllocator>,
    boundary: FlushBoundary,
}

impl PendingGlobalIovaFlush {
    /// Release only IOVAs retired before this global invalidation began.
    ///
    /// # Safety
    /// Every translation cache using this allocator, including ATS Device-TLBs,
    /// must have completed global invalidation after this token was created.
    /// A domain/page/context flush or command submission alone is insufficient.
    #[expect(
        unsafe_code,
        reason = "hardware completion for the allocator-wide translation scope is established by the backend"
    )]
    pub(in crate::io::iommu) unsafe fn complete_after_global_invalidation(self) {
        self.allocator.reclaim_through(self.boundary);
    }
}

impl IovaAllocator {
    /// Create a new IOVA Allocator
    ///
    /// # Arguments
    /// * `base` - Base IOVA address (must be 4KB aligned)
    /// * `size` - Size of the IOVA space (bytes)
    pub fn new(base: u64, size: u64) -> Result<Self, IommuError> {
        // Initialize Inner Allocator
        let inner = FastBitmapAllocator::try_new(base, size).map_err(|error| match error {
            AddressPoolError::Alignment => IommuError::InvalidAlignment,
            AddressPoolError::InvalidRange => IommuError::InvalidAddress,
            AddressPoolError::MetadataAllocation => IommuError::OutOfMemory,
            AddressPoolError::Exhausted => IommuError::OutOfIova,
        })?;

        Ok(Self {
            inner,
            quarantines: IrqMutex::new(Arc::from([])),
            fallback_quarantine: IrqMutex::new(QuarantineRing::new()),
            clock: RetirementClock::new(),
            stats: IovaAllocatorStats::default(),
        })
    }

    fn quarantine_for(&self, cpu_id: crate::cpu::CpuId) -> Option<Arc<IovaQuarantine>> {
        let slot_count = crate::cpu::try_runtime()?.snapshot().slots().len();
        let required_slots = slot_count.max(cpu_id.as_usize().saturating_add(1));

        // LOOP_PROOF: mode=event; reason=Snapshot publication exits on capacity failure or once the monotonically growing CPU projection contains this owner.;
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
        let epoch = self.clock.retirement_epoch();
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
                // The rejected block remains allocated. The allocator owner
                // must complete an allocator-wide IOTLB + ATS flush before
                // retrying this block; a context or domain flush cannot drain it.

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
        // The rejected block remains allocated until its owner can complete
        // allocator-wide IOTLB + ATS invalidation and retry this block.

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
        // Enforce the limit before claiming occupancy. A partial page at the
        // limit is unavailable; no speculative allocation needs to be freed.
        self.inner
            .allocate_contiguous_below(
                size.max(granularity.size_bytes()),
                granularity.size_bytes(),
                limit,
            )
            .ok()
    }

    /// Free immediately (Bypass Quarantine)
    ///
    /// Use this only during initialization or teardown when no IOTLB caching is active.
    pub fn free_immediate(&self, addr: u64, size: u64) -> Result<(), IommuError> {
        // Validate the entire extent before publishing any page for reuse. A
        // size-step loop could free a prefix and then fail on its invalid tail.
        self.inner
            .free_range_immediate(addr, size)
            .map_err(|error| match error {
                AddressPoolError::Alignment => IommuError::InvalidAlignment,
                _ => IommuError::InvalidAddress,
            })
    }

    // ========================================================================
    // Epoch / Quarantine Management
    // ========================================================================

    /// Capture the retirement boundary before issuing allocator-wide invalidation.
    /// Capturing the token only clones an Arc; no lock must be held across I/O or await.
    ///
    /// # Errors
    /// Epoch exhaustion is terminal for this allocator's retirement protocol;
    /// existing quarantine remains intact and epochs are never reused.
    pub(in crate::io::iommu) fn begin_global_flush(
        self: &Arc<Self>,
    ) -> Result<PendingGlobalIovaFlush, IommuError> {
        let boundary = self.clock.begin().ok_or(IommuError::GenerationExhausted)?;
        Ok(PendingGlobalIovaFlush {
            allocator: Arc::clone(self),
            boundary,
        })
    }

    fn reclaim_through(&self, boundary: FlushBoundary) {
        // Every later completed token proves a later allocator-wide flush.
        // Epochs cannot wrap, so out-of-order completions only advance coverage.
        let completed = self.clock.confirm(boundary);
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
