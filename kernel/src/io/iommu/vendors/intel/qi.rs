// ============================================================================
// kernel/src/io/iommu/vendors/intel/qi.rs
// ============================================================================

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
    /// PASID-based IOTLB Invalidate
    pub const PASID_IOTLB_INV: u64 = 0x7;
    /// PASID-cache Invalidate
    pub const PASID_CACHE_INV: u64 = 0x8;
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

    /// Create an IOTLB Invalidation descriptor
    /// Granularity: 0=reserved, 1=global, 2=domain, 3=page
    pub fn iotlb_invalidate(
        granularity: u8,
        domain_id: u16,
        hint: bool,
        address: u64,
        am: u8,
    ) -> Self {
        let mut lo = qi_desc_type::IOTLB_INV
            | ((granularity as u64 & 0x3) << 4)
            | ((domain_id as u64) << 16)
            | ((am as u64 & 0x3F) << 48)
            | (if hint { 1u64 << 63 } else { 0 }); // IH (Invalidation Hint)

        // Security: Set DW (Drain Writes) and DR (Drain Reads) bits (Bits 6 and 7).
        // This ensures all pending memory operations are completed before invalidation finishes.
        lo |= (1 << 6) | (1 << 7);

        // Security: Ensure PSCP (Paging-Structure Cache Preserve) is 0 (Bit 9).
        // This ensures that intermediate page table caches are also invalidated,
        // preventing Use-After-Free attacks on page tables.
        lo &= !(1 << 9);

        let mut hi = address & !0xFFF; // Page-aligned address for page-selective
        if granularity == 3 && am > 0 {
            // Section 6.5.2.2: Address [11+AM:12] must be 1s for PS-within-domain invalidation.
            // This mask sets bits corresponding to the AM field to satisfy hardware requirement.
            let ps_mask = (1u64 << (am as u64 & 0x3F)) - 1;
            hi |= ps_mask << 12;
        }

        Self { lo, hi }
    }

    /// Create a Global IOTLB Invalidation descriptor
    pub fn iotlb_invalidate_global() -> Self {
        Self::iotlb_invalidate(1, 0, false, 0, 0)
    }

    /// Create a Domain IOTLB Invalidation descriptor
    pub fn iotlb_invalidate_domain(domain_id: u16) -> Self {
        Self::iotlb_invalidate(2, domain_id, false, 0, 0)
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

    /// Create a Device-TLB Invalidation descriptor
    /// Used to invalidate ATS translations cached in PCIe devices
    ///
    /// # Arguments
    /// * `source_id` - PCIe Requester ID (Bus/Device/Function)
    /// * `global` - If true, invalidates all entries for the device
    /// * `iova` - IOVA to invalidate (when not global)
    /// * `size` - Size of invalidation range in pages (when not global)
    /// * `domain_id` - Domain ID for domain-selective invalidation
    pub fn device_tlb_invalidate(source_id: u16, iova: u64, size_s: bool) -> Self {
        let lo = qi_desc_type::DEV_TLB_INV
            | ((source_id as u64) << 16)
            | if size_s { 1u64 << 48 } else { 0 }; // S bit
        let hi = iova & !0xFFF;
        Self { lo, hi }
    }

    /// Create a Global Device-TLB Invalidation for a specific device (all entries)
    pub fn device_tlb_invalidate_all(source_id: u16) -> Self {
        // To invalidate all, set S=1 and Address[63:12] = all 1s
        Self::device_tlb_invalidate(source_id, !0u64, true)
    }

    /// Create a Page-selective Device-TLB Invalidation
    pub fn device_tlb_invalidate_page(source_id: u16, iova: u64) -> Self {
        Self::device_tlb_invalidate(source_id, iova, false)
    }

    /// Create a Range-selective Device-TLB Invalidation
    pub fn device_tlb_invalidate_range(source_id: u16, iova: u64, am: u8) -> Self {
        if am == 0 {
            Self::device_tlb_invalidate_page(source_id, iova)
        } else {
            // PCIe ATS range encoding (Intel VT-d Spec Section 6.5.2.3):
            // Range size is 2^am pages (4KB * 2^am bytes).
            // Encoding: S=1, Address[63:12] has (am-1) least-significant bits as 1,
            // and bit (12+(am-1)) as 0.
            let page_addr = iova >> 12;
            let mask = (1u64 << (am - 1)) - 1;
            let encoded_page_addr = (page_addr & !((1u64 << am) - 1)) | mask;
            let addr = encoded_page_addr << 12;
            Self::device_tlb_invalidate(source_id, addr, true)
        }
    }

    /// Create a PASID Cache Invalidation descriptor (VT-d Spec §6.5.2.7)
    /// Granularity: 1=global, 2=domain, 3=device-selective
    pub fn pasid_cache_invalidate(granularity: u8, domain_id: u16, pasid: u32) -> Self {
        let lo = qi_desc_type::PASID_CACHE_INV
            | ((granularity as u64 & 0x7) << 4)
            | ((domain_id as u64) << 16);
        let hi = (pasid as u64) & 0xFFFFF; // PASID is 20 bits
        Self { lo, hi }
    }

    /// Create a Domain PASID Cache Invalidation descriptor
    pub fn pasid_cache_invalidate_domain(domain_id: u16) -> Self {
        Self::pasid_cache_invalidate(2, domain_id, 0)
    }

    /// Create a PASID-based IOTLB Invalidation descriptor (VT-d Spec §6.5.2.6)
    pub fn pasid_iotlb_invalidate(domain_id: u16, pasid: u32) -> Self {
        let lo = qi_desc_type::PASID_IOTLB_INV | ((domain_id as u64) << 16);
        let hi = (pasid as u64) & 0xFFFFF; // PASID is 20 bits
        Self { lo, hi }
    }

    /// Create an Invalidation Wait descriptor
    /// Used to signal completion of previous descriptors
    pub fn wait(status_addr: u64, status_data: u32, interrupt: bool, fence: bool) -> Self {
        let lo = qi_desc_type::WAIT |
                 (if fence { 1 << 4 } else { 0 }) |     // IF (Invalidation Fence)
                 (if interrupt { 1 << 6 } else { 0 }) | // FN (Fence Notify)
                 (1 << 5) |                              // SW (Status Write)
                 ((status_data as u64) << 32);
        let hi = status_addr;
        Self { lo, hi }
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
    /// Queue size in entries (power of 2, 256 to 64K)
    size: usize,
    /// Current tail (next write position)
    tail: usize,
    /// Cached head (last IQH read, in entries)
    cached_head: usize,
    /// Wait status virtual address (CPU polls this value)
    status_virt: usize,
    /// Wait status physical address (descriptor writes here)
    status_phys: u64,
    /// Current monotonically increasing sequence number for wait descriptors.
    /// Used instead of `tail` to prevent race conditions and wrap-around issues.
    next_wait_seq: u32,
    /// Runtime stats for queue pressure/latency
    stats: QiStats,
}

impl InvalidationQueue {
    /// Admits physically contiguous queue and status backing before IQA publication.
    /// Queue size encoding is three bits for 128-bit descriptors (256..32768).
    pub fn new(size_log2: u8) -> Result<Self, crate::io::iommu::types::IommuError> {
        use crate::io::iommu::types::IommuError;
        if !(8..=15).contains(&size_log2) {
            return Err(IommuError::InvalidAddress);
        }
        let size = 1usize << size_log2;
        let queue_bytes = size * core::mem::size_of::<InvalidationQueueEntry>();
        let queue = crate::mm::phys::frame_allocator::alloc_contiguous_frames_aligned(
            queue_bytes / 4096,
            4096,
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
            size,
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
            (self.size * core::mem::size_of::<InvalidationQueueEntry>()) as u64,
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
    /// Get the queue base address for IQA register
    pub fn base_address(&self) -> u64 {
        self.queue_phys
    }

    #[cfg(test)]
    pub(crate) fn queue_virtual_address(&self) -> usize {
        self.queue_virt
    }

    /// Get the status virtual address (for memory polling)
    pub(crate) fn status_virtual_address(&self) -> usize {
        self.status_virt
    }

    /// Get queue size in log2 form for IQA register (bits 2:0)
    pub fn size_log2(&self) -> u8 {
        (self.size.trailing_zeros() - 8) as u8
    }

    /// Get current tail index
    pub fn tail(&self) -> usize {
        self.tail
    }

    /// Get cached head index
    pub fn cached_head(&self) -> usize {
        self.cached_head
    }

    /// Update cached head (caller should pass IQH >> 4)
    pub fn update_head(&mut self, head: usize) {
        self.cached_head = head % self.size;
    }

    #[inline]
    fn next_tail(&self) -> usize {
        (self.tail + 1) % self.size
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

    /// Submit an invalidation descriptor
    ///
    /// Caller must ensure there is space (queue not full).
    pub fn submit(&mut self, entry: InvalidationQueueEntry) {
        let ptr = self.queue_virt as *mut InvalidationQueueEntry;
        unsafe {
            *ptr.add(self.tail) = entry;
        }
        self.tail = (self.tail + 1) % self.size;
    }

    /// Submit a wait descriptor and return the status address and expected sequence.
    #[cfg(test)]
    pub fn submit_wait(&mut self) -> (usize, u32) {
        let seq = self.next_wait_seq;
        self.next_wait_seq = self.next_wait_seq.wrapping_add(1);
        let entry = InvalidationQueueEntry::wait(self.status_phys, seq, false, true);
        self.submit(entry);
        (self.status_virt, seq)
    }

    /// Build a wait descriptor without submitting it.
    ///
    /// Returns (entry, expected_seq).
    /// Advances the internal sequence number.
    pub fn wait_entry(&mut self) -> (InvalidationQueueEntry, u32) {
        let seq = self.next_wait_seq;
        self.next_wait_seq = self.next_wait_seq.wrapping_add(1);
        (
            InvalidationQueueEntry::wait(self.status_phys, seq, false, true),
            seq,
        )
    }

    /// Check if a wait has completed (status address updated).
    ///
    /// Uses monotonic comparison to handle concurrent requests and wrap-around.
    #[cfg(test)]
    pub fn check_wait_complete(&self, expected: u32) -> bool {
        let status = unsafe { core::ptr::read_volatile(self.status_virt as *const u32) };
        // Use wrap-around safe comparison (distance in u32 space)
        status.wrapping_sub(expected) < (1u32 << 31)
    }
}
