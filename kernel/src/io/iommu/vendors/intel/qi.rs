// ============================================================================
// kernel/src/io/iommu/vendors/intel/qi.rs
// ============================================================================

use core::sync::atomic::{Ordering, fence};

use super::registers::cap_bits;
use crate::io::iommu::types::IommuError;

#[cfg(feature = "qemu-test-export")]
pub(crate) mod qemu_tests;

/// Mandatory for x2APIC interrupt remapping
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct InvalidationQueueEntry {
    /// Lower 64 bits - descriptor type and parameters
    pub lo: u64,
    /// Upper 64 bits - additional parameters
    pub hi: u64,
}

/// Invalidation descriptor types (bits 3:0 of lo)
pub mod qi_desc_type {
    /// Context-cache Invalidate Descriptor
    pub const CC_INV: u64 = 0x1;
    /// IOTLB Invalidate Descriptor
    pub const IOTLB_INV: u64 = 0x2;
    /// Device-TLB Invalidate Descriptor
    pub const DEV_TLB_INV: u64 = 0x3;
    /// Interrupt Entry Cache Invalidate Descriptor
    pub const IEC_INV: u64 = 0x4;
    /// Invalidation Wait Descriptor
    pub const WAIT: u64 = 0x5;
}

impl InvalidationQueueEntry {
    /// Create a Context-Cache Invalidation descriptor
    /// Granularity: 0=reserved, 1=global, 2=domain, 3=device
    pub fn context_cache_invalidate(granularity: u8, domain_id: u16, source_id: u16) -> Self {
        // Intel VT-d Spec §6.5.2.1: CC Invalidate Descriptor lo QWORD layout:
        //   [3:0] Type, [5:4] Granularity, [15:6] Rsvd, [31:16] DID, [47:32] SID, [49:48] FM
        let lo = qi_desc_type::CC_INV
            | ((granularity as u64 & 0x3) << 4)
            | ((domain_id as u64) << 16)
            | ((source_id as u64) << 32);
        let hi = 0; // hi QWORD is reserved
        Self { lo, hi }
    }

    /// Create a Global Context-Cache Invalidation descriptor
    pub fn context_cache_invalidate_global() -> Self {
        Self::context_cache_invalidate(1, 0, 0)
    }

    /// Globally invalidate the scalable-mode PASID cache.
    pub(crate) const fn pasid_cache_invalidate_global() -> Self {
        Self { lo: 0x37, hi: 0 }
    }

    fn iotlb(granularity: u64, domain_id: u16, address: u64, address_mask: u8) -> Self {
        // Drain remapped DMA before reporting completion. IH remains clear so
        // invalidation also covers paging-structure caches.
        let lo = qi_desc_type::IOTLB_INV | (granularity << 4) | 0xc0 | (u64::from(domain_id) << 16);
        let hi = (address & !0xfff) | u64::from(address_mask);
        Self { lo, hi }
    }

    pub fn iotlb_invalidate_global() -> Self {
        Self::iotlb(1, 0, 0, 0)
    }

    pub fn iotlb_invalidate_domain(domain_id: u16) -> Self {
        Self::iotlb(2, domain_id, 0, 0)
    }

    pub(super) fn iotlb_invalidate_pages(domain_id: u16, pages: PageInvalidation) -> Self {
        Self::iotlb(3, domain_id, pages.base, pages.address_mask)
    }

    /// Create an Interrupt Entry Cache Invalidation descriptor
    /// Granularity: 0=global, 1=index-selective
    pub fn iec_invalidate(granularity: u8, irte_index: u16, index_mask: u8) -> Self {
        let lo = qi_desc_type::IEC_INV
            | ((granularity as u64 & 0x1) << 4)
            | ((index_mask as u64 & 0x1F) << 27)
            | ((irte_index as u64) << 32);
        Self { lo, hi: 0 }
    }

    /// Create a Global IEC Invalidation descriptor
    pub fn iec_invalidate_global() -> Self {
        Self::iec_invalidate(0, 0, 0)
    }

    // PFSID is reserved on the controllers admitted for ATS. ATS admission
    // rejects DIT until a PCI physical-function identity can be established.
    fn device_tlb(source_id: u16, address: u64, range: bool) -> Self {
        let lo = qi_desc_type::DEV_TLB_INV | (u64::from(source_id) << 32);
        let hi = address | u64::from(range);
        Self { lo, hi }
    }

    pub(super) fn device_tlb_invalidate_all(source_id: u16) -> Self {
        Self::device_tlb(source_id, 0x7fff_ffff_ffff_f000, true)
    }

    pub(super) fn device_tlb_invalidate_pages(source_id: u16, pages: PageInvalidation) -> Self {
        if pages.address_mask == 0 {
            Self::device_tlb(source_id, pages.base, false)
        } else {
            // The first zero in the low-order page-number bits encodes the
            // naturally aligned range size. The caller selected its base.
            let size_bits = ((1u64 << (pages.address_mask - 1)) - 1) << 12;
            Self::device_tlb(source_id, pages.base | size_bits, true)
        }
    }

    fn wait(status_addr: u64, status_data: u32, notify: WaitNotification) -> Self {
        const STATUS_WRITE: u64 = 1 << 5;
        const FENCE: u64 = 1 << 6;
        // Each wait fences the subsequent batch, so an observed status store
        // certifies completion of every preceding batch as well.
        let lo = (u64::from(status_data) << 32)
            | qi_desc_type::WAIT
            | STATUS_WRITE
            | FENCE
            | notify.interrupt_flag();
        Self {
            lo,
            hi: status_addr,
        }
    }
}

/// A naturally aligned page range that covers the request and is encodable
/// both for this controller's IOTLB and for an endpoint Device-TLB.
#[derive(Clone, Copy)]
pub(super) struct PageInvalidation {
    base: u64,
    address_mask: u8,
}

impl PageInvalidation {
    pub(super) fn covering(cap: u64, base: u64, size: u64) -> Option<Self> {
        if cap & cap_bits::CAP_PSI == 0 || size == 0 {
            return None;
        }
        let page_bytes = crate::mm::types::PAGE_SIZE_4K as u64;
        let pages = size.div_ceil(page_bytes).checked_next_power_of_two()?;
        let bytes = pages.checked_mul(page_bytes)?;
        let address_mask = u8::try_from(pages.trailing_zeros()).ok()?;
        if !base.is_multiple_of(bytes) || address_mask > cap_bits::max_address_mask(cap) {
            return None;
        }
        Some(Self { base, address_mask })
    }
}

/// Status location and sequence of a published wait.
pub(super) struct WaitCompletion {
    status_virt: usize,
    sequence: u32,
}

impl WaitCompletion {
    /// # Safety
    /// The queue that produced this receipt must still retain its status allocation.
    pub(super) unsafe fn is_complete(&self) -> bool {
        // SAFETY: queue admission established the aligned coherent status word,
        // and the caller retains its backing.
        let observed = unsafe { core::ptr::read_volatile(self.status_virt as *const u32) };
        // Published waits are ordered by FN. The hardware ring's outstanding
        // submissions are bounded well below half of the serial number space.
        if observed.wrapping_sub(self.sequence) >= (1u32 << 31) {
            return false;
        }
        fence(Ordering::Acquire);
        true
    }
}

#[derive(Clone, Copy)]
pub(super) enum WaitNotification {
    Poll,
    Interrupt,
}

impl WaitNotification {
    const fn interrupt_flag(self) -> u64 {
        match self {
            Self::Poll => 0,
            Self::Interrupt => 1 << 4,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum DescriptorWidth {
    Bits128,
    Bits256,
}

#[repr(C, align(32))]
struct WideInvalidationQueueEntry {
    common: InvalidationQueueEntry,
    reserved: [u64; 2],
}

impl DescriptorWidth {
    const fn bytes(self) -> usize {
        match self {
            Self::Bits128 => core::mem::size_of::<InvalidationQueueEntry>(),
            Self::Bits256 => core::mem::size_of::<WideInvalidationQueueEntry>(),
        }
    }

    const fn iqa_flag(self) -> u64 {
        match self {
            Self::Bits128 => 0,
            Self::Bits256 => 1 << 11,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct QueueLayout {
    width: DescriptorWidth,
    page_order: u8,
}

impl QueueLayout {
    const PAGE_BYTES: usize = crate::mm::types::PAGE_SIZE_4K;

    fn new(width: DescriptorWidth, page_order: u8) -> Result<Self, IommuError> {
        if page_order > 7 {
            return Err(IommuError::InvalidAddress);
        }
        Ok(Self { width, page_order })
    }

    const fn bytes(self) -> usize {
        Self::PAGE_BYTES << self.page_order
    }

    const fn entries(self) -> usize {
        self.bytes() / self.width.bytes()
    }

    const fn iqa(self, base: u64) -> u64 {
        base | self.width.iqa_flag() | self.page_order as u64
    }

    const fn offset(self, index: usize) -> u64 {
        (index * self.width.bytes()) as u64
    }

    fn head_index(self, offset: u64) -> Result<usize, IommuError> {
        if offset >= self.bytes() as u64 || !offset.is_multiple_of(self.width.bytes() as u64) {
            return Err(IommuError::HardwareError);
        }
        Ok(offset as usize / self.width.bytes())
    }
}

/// QI runtime statistics
#[derive(Clone, Copy, Debug, Default)]
pub struct QiStats {
    /// Total descriptors submitted
    pub submits: u64,
    /// Times the queue was observed full before submit
    pub full_checks: u64,
    /// Times IQH was read to refresh cached head
    pub head_refreshes: u64,
    /// Times we had to wait for space
    pub waits: u64,
    /// Wait attempts that timed out
    pub wait_timeouts: u64,
}

/// Invalidation Queue Manager
#[derive(Debug)]
pub struct InvalidationQueue {
    queue_backing: Option<crate::mm::phys::frame_allocator::PhysicalAllocation>,
    status_backing: Option<crate::mm::phys::frame_allocator::PhysicalAllocation>,
    /// Queue base virtual address (CPU writes descriptors here)
    queue_virt: usize,
    /// Queue base physical address (programmed to IQA)
    queue_phys: u64,
    layout: QueueLayout,
    /// Current tail (next write position)
    tail: usize,
    /// Cached head (last IQH read, in entries)
    cached_head: usize,
    /// Wait status virtual address (CPU polls this value)
    status_virt: usize,
    /// Wait status physical address (descriptor writes here)
    status_phys: u64,
    /// Serial number of the next successful wait submission.
    next_wait_seq: u32,
    /// Runtime stats for queue pressure/latency
    stats: QiStats,
}

impl InvalidationQueue {
    /// Admits physically contiguous queue and status backing before IQA publication.
    pub(super) fn new(width: DescriptorWidth, page_order: u8) -> Result<Self, IommuError> {
        let layout = QueueLayout::new(width, page_order)?;
        let queue_bytes = layout.bytes();
        let queue = crate::mm::phys::frame_allocator::alloc_contiguous_frames_aligned(
            queue_bytes / QueueLayout::PAGE_BYTES,
            QueueLayout::PAGE_BYTES,
        )
        .map_err(IommuError::PhysicalAllocation)?;
        let status = match crate::mm::phys::frame_allocator::alloc_frame() {
            Ok(status) => status,
            Err(cause) => {
                crate::mm::phys::frame_allocator::dealloc_contiguous_frames(queue);
                return Err(IommuError::PhysicalAllocation(cause));
            }
        };
        let queue_phys = queue.as_u64();
        let status_phys = status.as_u64();
        let queue_virt = crate::io::iommu::common::tables::phys_to_virt_usize(queue_phys);
        let status_virt = crate::io::iommu::common::tables::phys_to_virt_usize(status_phys);
        // SAFETY: both PMM allocations retain exclusive physical ownership, the
        // direct map covers their complete spans, and no hardware pointer has
        // been published. The backing contains integer descriptors/status only.
        unsafe {
            core::ptr::write_bytes(queue_virt as *mut u8, 0, queue_bytes);
            core::ptr::write_bytes(status_virt as *mut u8, 0, 4096);
        }
        crate::security::dma::register_protected_range(queue_phys, queue_bytes as u64);
        crate::security::dma::register_protected_range(status_phys, 4096);
        Ok(Self {
            queue_backing: Some(queue),
            status_backing: Some(status),
            queue_virt,
            queue_phys,
            layout,
            tail: 0,
            cached_head: 0,
            status_virt,
            status_phys,
            next_wait_seq: 1,
            stats: QiStats::default(),
        })
    }
}

impl Drop for InvalidationQueue {
    fn drop(&mut self) {
        // Controllers remain registry-owned through every uncertain hardware
        // outcome. A published queue is not removed or replaced while enabled.
        crate::security::dma::unregister_protected_range(
            self.queue_phys,
            self.layout.bytes() as u64,
        );
        crate::security::dma::unregister_protected_range(self.status_phys, 4096);
        if let Some(status) = self.status_backing.take() {
            crate::mm::phys::frame_allocator::dealloc_frame(status);
        }
        if let Some(queue) = self.queue_backing.take() {
            crate::mm::phys::frame_allocator::dealloc_contiguous_frames(queue);
        }
    }
}

impl InvalidationQueue {
    pub(super) fn configuration_register(&self) -> u64 {
        self.layout.iqa(self.queue_phys)
    }

    pub(super) fn tail_offset(&self) -> u64 {
        self.layout.offset(self.tail)
    }

    pub(super) fn cached_head_offset(&self) -> u64 {
        self.layout.offset(self.cached_head)
    }

    pub(super) fn refresh_head(&mut self, hardware_offset: u64) -> Result<(), IommuError> {
        self.cached_head = self.layout.head_index(hardware_offset)?;
        Ok(())
    }

    #[inline]
    fn next_tail(&self) -> usize {
        (self.tail + 1) % self.layout.entries()
    }

    /// Check if the queue is full using cached head
    pub fn is_full(&self) -> bool {
        self.next_tail() == self.cached_head
    }

    pub fn stats(&self) -> QiStats {
        self.stats
    }

    pub fn reset_stats(&mut self) {
        self.stats = QiStats::default();
    }

    pub(crate) fn record_submit(&mut self) {
        self.stats.submits = self.stats.submits.saturating_add(1);
    }

    pub(crate) fn record_full_check(&mut self) {
        self.stats.full_checks = self.stats.full_checks.saturating_add(1);
    }

    pub(crate) fn record_head_refresh(&mut self) {
        self.stats.head_refreshes = self.stats.head_refreshes.saturating_add(1);
    }

    pub(crate) fn record_wait(&mut self) {
        self.stats.waits = self.stats.waits.saturating_add(1);
    }

    pub(crate) fn record_wait_timeout(&mut self) {
        self.stats.wait_timeouts = self.stats.wait_timeouts.saturating_add(1);
    }

    /// Publish one descriptor to the ring with the configured hardware stride.
    pub(super) fn submit(&mut self, entry: InvalidationQueueEntry) {
        assert!(
            !self.is_full(),
            "queue submission requires an available slot"
        );
        let address = self.queue_virt + self.tail_offset() as usize;
        // SAFETY: the queue retains the complete aligned allocation. The
        // hardware head and software tail exclude entries still in use.
        unsafe {
            match self.layout.width {
                DescriptorWidth::Bits128 => (address as *mut InvalidationQueueEntry).write(entry),
                DescriptorWidth::Bits256 => {
                    (address as *mut WideInvalidationQueueEntry).write(WideInvalidationQueueEntry {
                        common: entry,
                        reserved: [0; 2],
                    })
                }
            }
        }
        self.tail = self.next_tail();
    }

    pub(super) fn submit_wait(
        &mut self,
        notify: WaitNotification,
        publish: impl FnOnce(&mut Self, InvalidationQueueEntry) -> Result<(), IommuError>,
    ) -> Result<WaitCompletion, IommuError> {
        let sequence = self.next_wait_seq;
        publish(
            self,
            InvalidationQueueEntry::wait(self.status_phys, sequence, notify),
        )?;
        self.next_wait_seq = self.next_wait_seq.wrapping_add(1);
        Ok(WaitCompletion {
            status_virt: self.status_virt,
            sequence,
        })
    }
}

#[cfg(test)]
mod descriptor_tests {
    use super::*;

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn page_invalidation_requires_capability_and_a_covering_encoding() {
        const CAP: u64 = (1 << 39) | (2 << 48);
        let pages = PageInvalidation::covering(CAP, 0x8000, 0x3000)
            .expect("an aligned four-page invalidation covers three pages");
        let entry = InvalidationQueueEntry::iotlb_invalidate_pages(0x5678, pages);
        assert_eq!((entry.lo, entry.hi), (0x5678_00f2, 0x8002));
        assert!(PageInvalidation::covering(2 << 48, 0x8000, 0x1000).is_none());
        assert!(PageInvalidation::covering(CAP, 0x8000, 0x5000).is_none());
        assert!(PageInvalidation::covering(CAP, 0x9000, 0x2000).is_none());
        assert!(PageInvalidation::covering(CAP, 0, u64::MAX).is_none());
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn device_tlb_selects_the_requester_and_encodes_ats_size() {
        const CAP: u64 = (1 << 39) | (2 << 48);
        const SID: u16 = 0xabcd;
        for (size, high) in [(0x1000, 0x8000), (0x2000, 0x8001), (0x4000, 0x9001)] {
            let pages = PageInvalidation::covering(CAP, 0x8000, size).unwrap();
            let entry = InvalidationQueueEntry::device_tlb_invalidate_pages(SID, pages);
            assert_eq!((entry.lo, entry.hi), (0xabcd_0000_0003, high));
        }
        let entry = InvalidationQueueEntry::device_tlb_invalidate_all(SID);
        assert_eq!(
            (entry.lo, entry.hi),
            (0xabcd_0000_0003, 0x7fff_ffff_ffff_f001)
        );
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn global_pasid_cache_invalidation_has_no_domain_or_address_bits() {
        let descriptor = InvalidationQueueEntry::pasid_cache_invalidate_global();
        assert_eq!((descriptor.lo, descriptor.hi), (0x0037, 0));
    }
}
