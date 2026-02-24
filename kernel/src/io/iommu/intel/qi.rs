// ============================================================================
// kernel/src/io/iommu/qi.rs
// ============================================================================
use alloc::alloc::Layout;
use alloc::vec::Vec;
use crate::io::iommu::tables::virt_ptr_to_phys;

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
    /// Extended IOTLB Invalidate Descriptor
    pub const EXT_IOTLB_INV: u64 = 0x6;
    /// PASID-based IOTLB Invalidate
    pub const PASID_IOTLB_INV: u64 = 0x7;
    /// PASID-cache Invalidate
    pub const PASID_CACHE_INV: u64 = 0x8;
    /// Page Group Response Descriptor (VT-d Spec §6.5.2.9)
    pub const PAGE_GROUP_RESP: u64 = 0x9;
}

impl InvalidationQueueEntry {
    /// Create a Context-Cache Invalidation descriptor
    /// Granularity: 0=reserved, 1=global, 2=domain, 3=device
    pub fn context_cache_invalidate(granularity: u8, domain_id: u16, source_id: u16) -> Self {
        let lo =
            qi_desc_type::CC_INV | ((granularity as u64 & 0x3) << 4) | ((domain_id as u64) << 16);
        let hi = source_id as u64;
        Self { lo, hi }
    }

    /// Create a Global Context-Cache Invalidation descriptor
    pub fn context_cache_invalidate_global() -> Self {
        Self::context_cache_invalidate(1, 0, 0)
    }

    /// Create an IOTLB Invalidation descriptor
    /// Granularity: 0=reserved, 1=global, 2=domain, 3=page
    pub fn iotlb_invalidate(granularity: u8, domain_id: u16, drain: bool, address: u64) -> Self {
        let lo = qi_desc_type::IOTLB_INV |
                 ((granularity as u64 & 0x3) << 4) |
                 (if drain { 1 << 6 } else { 0 }) | // DW (Drain Writes)
                 (if drain { 1 << 7 } else { 0 }) | // DR (Drain Reads)
                 ((domain_id as u64) << 16);
        let hi = address & !0xFFF; // Page-aligned address for page-selective
        Self { lo, hi }
    }

    /// Create a Global IOTLB Invalidation descriptor
    pub fn iotlb_invalidate_global(drain: bool) -> Self {
        Self::iotlb_invalidate(1, 0, drain, 0)
    }

    /// Create a Domain IOTLB Invalidation descriptor
    pub fn iotlb_invalidate_domain(domain_id: u16, drain: bool) -> Self {
        Self::iotlb_invalidate(2, domain_id, drain, 0)
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
    pub fn device_tlb_invalidate(
        source_id: u16,
        global: bool,
        iova: u64,
        size: u8,
        domain_id: u16,
    ) -> Self {
        let lo = qi_desc_type::DEV_TLB_INV
            | ((source_id as u64) << 32)
            | ((domain_id as u64) << 16)
            | if global { 1 << 4 } else { 0 }; // G bit
        let hi = if global {
            0
        } else {
            (iova & !0xFFF) | ((size as u64) & 0x3F)
        };
        Self { lo, hi }
    }

    /// Create a Global Device-TLB Invalidation for a specific device
    pub fn device_tlb_invalidate_device(source_id: u16, domain_id: u16) -> Self {
        Self::device_tlb_invalidate(source_id, true, 0, 0, domain_id)
    }

    /// Create a Page-selective Device-TLB Invalidation
    pub fn device_tlb_invalidate_page(source_id: u16, domain_id: u16, iova: u64, size: u8) -> Self {
        Self::device_tlb_invalidate(source_id, false, iova, size, domain_id)
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

    /// Create a Global PASID Cache Invalidation descriptor
    pub fn pasid_cache_invalidate_global() -> Self {
        Self::pasid_cache_invalidate(1, 0, 0)
    }

    /// Create a Domain PASID Cache Invalidation descriptor
    pub fn pasid_cache_invalidate_domain(domain_id: u16) -> Self {
        Self::pasid_cache_invalidate(2, domain_id, 0)
    }

    /// Create a PASID-based IOTLB Invalidation descriptor (VT-d Spec §6.5.2.6)
    pub fn pasid_iotlb_invalidate(domain_id: u16, pasid: u32, drain: bool) -> Self {
        let lo = qi_desc_type::PASID_IOTLB_INV
            | (if drain { 1 << 6 } else { 0 }) // DW (Drain Writes)
            | (if drain { 1 << 7 } else { 0 }) // DR (Drain Reads)
            | ((domain_id as u64) << 16);
        let hi = (pasid as u64) & 0xFFFFF;
        Self { lo, hi }
    }

    /// Create a Page Group Response descriptor (VT-d Spec §6.5.2.9)
    ///
    /// Used to respond to page requests from devices via PRI.
    /// Hardware processes this descriptor to send a page response back to the
    /// requesting device.
    ///
    /// # Arguments
    /// * `source_id` - PCIe Requester ID of the requesting device
    /// * `pasid` - PASID if the original request was PASID-tagged
    /// * `prg_index` - Page Request Group Index from the original request
    /// * `response_code` - Response code (0=Success, 1=Invalid Request, 2=Failure)
    pub fn page_group_response(
        source_id: u16,
        pasid: Option<u32>,
        prg_index: u16,
        response_code: u8,
    ) -> Self {
        // lo: bits[3:0]=type(0x9), bits[7:4]=response_code, bits[31:16]=source_id,
        //     bits[47:32]=prg_index
        let lo = qi_desc_type::PAGE_GROUP_RESP
            | ((response_code as u64 & 0xF) << 4)
            | ((source_id as u64) << 16)
            | ((prg_index as u64) << 32);
        // hi: bits[19:0]=PASID, bit[63]=PASID present
        let hi = match pasid {
            Some(p) => ((p as u64) & 0xFFFFF) | (1u64 << 63),
            None => 0,
        };
        Self { lo, hi }
    }

    /// Create an Invalidation Wait descriptor
    /// Used to signal completion of previous descriptors
    pub fn wait(status_addr: u64, status_data: u32, interrupt: bool, fence: bool) -> Self {
        let lo = qi_desc_type::WAIT |
                 (if fence { 1 << 5 } else { 0 }) |     // IF (Invalidation Fence)
                 (if interrupt { 1 << 4 } else { 0 }) | // FN (Fence Notify)
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
    /// Runtime stats for queue pressure/latency
    stats: QiStats,
}

impl InvalidationQueue {
    /// Queue size must be power of 2 between 256 and 65536
    pub const MIN_SIZE: usize = 256;
    pub const MAX_SIZE: usize = 65536;

    /// Create a new Invalidation Queue
    pub fn new(size_log2: u8) -> Option<Self> {
        #[cfg(test)]
        log::info!(
            "[test][IOMMU] InvalidationQueue::new start: size_log2={}",
            size_log2
        );

        let size = 1usize << (size_log2.clamp(8, 16) as usize);
        let total_bytes = size * core::mem::size_of::<InvalidationQueueEntry>();

        #[cfg(test)]
        log::info!(
            "[test][IOMMU] allocating queue: total_bytes={} entries={}",
            total_bytes, size
        );

        // Allocate 4KB-aligned queue
        let layout = Layout::from_size_align(total_bytes, 4096).ok()?;
        let base_ptr = crate::util::allocate_zeroed(layout);
        #[cfg(test)]
        log::info!(
            "[test][IOMMU] allocate_zeroed(queue_layout) returned: {:?}",
            base_ptr.map(|p| p.as_ptr() as usize)
        );
        let queue_virt = base_ptr?.as_ptr() as usize;
        let queue_phys = virt_ptr_to_phys(queue_virt as *const u8).ok()?;

        // Allocate status page
        let status_layout = Layout::from_size_align(4096, 4096).ok()?;
        let status_ptr = crate::util::allocate_zeroed(status_layout);
        #[cfg(test)]
        log::info!(
            "[test][IOMMU] allocate_zeroed(status_layout) returned: {:?}",
            status_ptr.map(|p| p.as_ptr() as usize)
        );
        let status_virt = status_ptr?.as_ptr() as usize;
        let status_phys = virt_ptr_to_phys(status_virt as *const u8).ok()?;

        #[cfg(test)]
        log::info!(
            "[test][IOMMU] InvalidationQueue::new success base=0x{:x} status_addr=0x{:x} size={}",
            queue_phys, status_phys, size
        );

        Some(Self {
            queue_virt,
            queue_phys,
            size,
            tail: 0,
            cached_head: 0,
            status_virt,
            status_phys,
            stats: QiStats::default(),
        })
    }

    /// Get the queue base address for IQA register
    pub fn base_address(&self) -> u64 {
        self.queue_phys
    }

    #[cfg(test)]
    pub fn queue_virtual_address(&self) -> usize {
        self.queue_virt
    }

    #[cfg(test)]
    pub fn status_virtual_address(&self) -> usize {
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

    /// Submit a wait descriptor and return the status address
    pub fn submit_wait(&mut self) -> usize {
        // Use current tail as unique status data
        let status_data = (self.tail & 0xFFFFFFFF) as u32;
        let entry = InvalidationQueueEntry::wait(self.status_phys, status_data, false, true);
        self.submit(entry);
        self.status_virt
    }

    /// Build a wait descriptor without submitting it
    pub fn wait_entry(&self) -> InvalidationQueueEntry {
        let status_data = (self.tail & 0xFFFFFFFF) as u32;
        InvalidationQueueEntry::wait(self.status_phys, status_data, false, true)
    }

    /// Check if a wait has completed (status address updated)
    pub fn check_wait_complete(&self, expected: u32) -> bool {
        let status = unsafe { core::ptr::read_volatile(self.status_virt as *const u32) };
        status == expected
    }
}

/// Batched Invalidation for efficient QI usage
///
/// Collects multiple invalidation requests and submits them in a batch.
pub struct InvalidationBatch {
    /// Pending invalidation descriptors
    pending: Vec<InvalidationQueueEntry>,
    /// Maximum batch size before auto-flush
    max_batch: usize,
}

impl InvalidationBatch {
    /// Default batch size
    pub const DEFAULT_MAX: usize = 32;

    /// Create a new invalidation batch
    pub fn new(max_batch: usize) -> Self {
        Self {
            pending: Vec::with_capacity(max_batch),
            max_batch,
        }
    }

    /// Add an invalidation descriptor
    pub fn add(&mut self, entry: InvalidationQueueEntry) -> bool {
        self.pending.push(entry);
        self.pending.len() >= self.max_batch
    }

    /// Get pending descriptors and clear
    pub fn drain(&mut self) -> Vec<InvalidationQueueEntry> {
        core::mem::take(&mut self.pending)
    }

    /// Check if batch is empty
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Get pending count
    pub fn len(&self) -> usize {
        self.pending.len()
    }
}
