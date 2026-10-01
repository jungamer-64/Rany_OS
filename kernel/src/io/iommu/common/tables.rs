// ============================================================================
// kernel/src/io/iommu/common/tables.rs
// ============================================================================

use crate::io::iommu::types::{IommuError, PteFormat};
use core::marker::PhantomData;
use core::ptr::NonNull;

// Import architecture specific PTEs for helper functions
use crate::io::iommu::vendors::amd::tables::AmdPte;

// ============================================================================
// Zeroable Trait - Zero-initialization safety
// ============================================================================

/// Marker trait for types that can be safely zero-initialized.
///
/// # Safety
///
/// Implementing this trait guarantees that:
/// - All-zeros is a valid bit pattern for this type
/// - Creating a reference to a zeroed instance does not cause UB
///
/// Types like `NonZeroU64` or references MUST NOT implement this trait.
///
/// # Usage
///
/// ```ignore
/// #[repr(C)]
/// struct MyEntry { lo: u64, hi: u64 }
/// // SAFETY: All-zeros is valid (represents "not present")
/// unsafe impl Zeroable for MyEntry {}
/// ```
pub unsafe trait Zeroable: Copy {}

/// Page table entries per level (512 for 4KB pages)
pub const PT_ENTRIES: usize = 512;

/// Second level page table entry
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SlPte(pub u64);

impl SlPte {
    /// Present bit
    pub const PRESENT: u64 = 1 << 0;
    /// Read permission
    pub const READ: u64 = 1 << 0;
    /// Write permission
    pub const WRITE: u64 = 1 << 1;
    /// Access bit (A) - set by hardware when page is accessed
    pub const ACCESSED: u64 = 1 << 5;
    /// Dirty bit (D) - set by hardware when page is written
    pub const DIRTY: u64 = 1 << 6;
    /// Super-Page (PS) bit - marks entry as large page (2MB at PD level, 1GB at PDP level)
    pub const SUPER_PAGE: u64 = 1 << 7;
    /// Snoop behavior
    pub const SNOOP: u64 = 1 << 11;

    /// Physical address mask (bits 51:12)
    const PHYS_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    /// Create a new entry
    pub const fn new() -> Self {
        Self(0)
    }

    /// Create a present entry with address and permissions
    /// Intel VT-d spec: W bit is reserved (must be 0) when R=0,
    /// so if write is requested, read is automatically enabled.
    pub fn mapping(phys_addr: u64, read: bool, write: bool) -> Self {
        let mut flags = 0;
        // VT-d: R must be set for W to be valid
        if read || write {
            flags |= Self::READ;
        }
        if write {
            flags |= Self::WRITE;
        }
        // Mask to 52-bit physical address and ensure 4KB alignment
        Self((phys_addr & Self::PHYS_MASK) | flags)
    }

    /// Create a 2MB super-page entry (used at PD level)
    /// phys_addr must be 2MB-aligned
    pub fn super_page_2mb(phys_addr: u64, read: bool, write: bool) -> Self {
        const MASK_2MB: u64 = (2 * 1024 * 1024) - 1;
        let mut flags = Self::SUPER_PAGE;
        // VT-d: R must be set for W to be valid
        if read || write {
            flags |= Self::READ;
        }
        if write {
            flags |= Self::WRITE;
        }
        // Mask to 52-bit physical address and ensure 2MB alignment
        Self((phys_addr & Self::PHYS_MASK & !MASK_2MB) | flags)
    }

    /// Create a 1GB super-page entry (used at PDP level)
    /// phys_addr must be 1GB-aligned
    pub fn super_page_1gb(phys_addr: u64, read: bool, write: bool) -> Self {
        const MASK_1GB: u64 = (1024 * 1024 * 1024) - 1;
        let mut flags = Self::SUPER_PAGE;
        // VT-d: R must be set for W to be valid
        if read || write {
            flags |= Self::READ;
        }
        if write {
            flags |= Self::WRITE;
        }
        // Mask to 52-bit physical address and ensure 1GB alignment
        Self((phys_addr & Self::PHYS_MASK & !MASK_1GB) | flags)
    }

    /// Check if this is a super-page entry
    pub fn is_super_page(&self, format: PteFormat) -> bool {
        match format {
            PteFormat::Intel => (self.0 & Self::SUPER_PAGE) != 0,
            PteFormat::Amd => {
                // AMD: Next Level field (Bits 9-11) is 0 for pages (leaves) at PD/PDP levels
                ((self.0 >> 9) & 0x7) == 0
            }
        }
    }

    /// Check if present
    pub fn is_present(&self) -> bool {
        // Intel: Present if Read or Write bit is set.
        // AMD: Present if Bit 0 (PR) is set. Bit 1 is reserved (0).
        // So checking (bit 0 | bit 1) works for both.
        (self.0 & (Self::READ | Self::WRITE)) != 0
    }

    /// Get physical address
    pub fn phys_addr(&self) -> u64 {
        self.0 & Self::PHYS_MASK
    }

    /// Check read permission
    pub fn can_read(&self) -> bool {
        (self.0 & Self::READ) != 0
    }

    /// Check write permission
    pub fn can_write(&self) -> bool {
        (self.0 & Self::WRITE) != 0
    }

    /// Check if page has been accessed
    pub fn is_accessed(&self) -> bool {
        (self.0 & Self::ACCESSED) != 0
    }

    /// Check if page has been written (dirty)
    pub fn is_dirty(&self) -> bool {
        (self.0 & Self::DIRTY) != 0
    }

    /// Clear accessed bit (returns old value)
    pub fn clear_accessed(&mut self) -> bool {
        let was_set = self.is_accessed();
        self.0 &= !Self::ACCESSED;
        was_set
    }

    /// Clear dirty bit (returns old value)
    pub fn clear_dirty(&mut self) -> bool {
        let was_set = self.is_dirty();
        self.0 &= !Self::DIRTY;
        was_set
    }

    /// Clear both accessed and dirty bits
    pub fn clear_accessed_dirty(&mut self) -> (bool, bool) {
        let accessed = self.clear_accessed();
        let dirty = self.clear_dirty();
        (accessed, dirty)
    }
}

// SAFETY: SlPte with all zeros represents "not present" - a valid state
unsafe impl Zeroable for SlPte {}

/// A not-yet-committed table owner. Unattached rollback returns directly to
/// its pool; attached rollback clears the parent and retains RAM in quarantine.
/// The pending queue outlives the scope, and admission reserves capacity before
/// any parent publication. Mapping construction holds the domain paging lock.
pub(in crate::io::iommu) struct PageTableScope<'a> {
    allocation: Option<crate::io::iommu::common::dma::page_table_pool::PooledPt>,
    pool: alloc::sync::Arc<crate::io::iommu::common::dma::page_table_pool::PageTablePool>,
    pending: &'a crate::sync::PoisonLock<crate::io::iommu::common::dma::page_table_pool::TableRetirement>,
    parent_entry: Option<*mut SlPte>,
    parent_phys: Option<u64>,
}

impl<'a> PageTableScope<'a> {
    pub(in crate::io::iommu) fn new_with_pool(
        pool: alloc::sync::Arc<crate::io::iommu::common::dma::page_table_pool::PageTablePool>,
        node_hint: Option<usize>,
        pending: &'a crate::sync::PoisonLock<crate::io::iommu::common::dma::page_table_pool::TableRetirement>,
    ) -> Result<Self, IommuError> {
        // At most four scopes exist in a 5-level path; capture holds the paging
        // lock and cannot invalidate admission while these scopes remain live.
        pending.lock().map_err(|_| IommuError::Poisoned)?
            .reserve(4)?;
        let allocation = pool.acquire(node_hint)?;
        Ok(Self { allocation: Some(allocation), pool, pending, parent_entry: None, parent_phys: None })
    }
    pub(in crate::io::iommu) fn ptr(&self) -> *mut SlPte {
        self.allocation.as_ref().expect("uncommitted owner").ptr.as_ptr()
    }
    pub(in crate::io::iommu) fn phys(&self) -> u64 {
        self.allocation.as_ref().expect("uncommitted owner").phys
    }
    /// # Safety
    /// The parent entry is retained and exclusively mutated under its domain's
    /// paging lock through this scope's completion. This admission may publish
    /// to hardware; even a later rollback requires IOTLB retirement before reuse.
    pub(in crate::io::iommu) unsafe fn attach_to_parent(
        &mut self, parent_entry: *mut SlPte, parent_phys: u64, format: PteFormat, next_level: u8,
    ) {
        assert!(self.parent_entry.is_none(), "one parent publication per scope");
        let pte = match format {
            PteFormat::Intel => SlPte::mapping(self.phys(), true, true),
            PteFormat::Amd => SlPte(AmdPte::table_pointer(self.phys(), next_level).0),
        };
        // SAFETY: caller retains and exclusively mutates the aligned parent entry.
        unsafe { parent_entry.write(pte) };
        self.parent_entry = Some(parent_entry);
        self.parent_phys = Some(parent_phys);
    }
    /// Consume publication authority; the active registry retains the PMM owner.
    pub(in crate::io::iommu) fn commit(mut self) {
        if let Some(parent_phys) = self.parent_phys {
            crate::io::iommu::common::dma::page_table_pool::inc_ref(parent_phys);
        }
        crate::io::iommu::common::dma::page_table_pool::publish_table(
            self.allocation.take().expect("one table publication"));
    }
}

impl Drop for PageTableScope<'_> {
    fn drop(&mut self) {
        let Some(table) = self.allocation.take() else { return; };
        if let Some(parent) = self.parent_entry {
            // SAFETY: attach retains the parent and paging mutation authority
            // through rollback; clearing removes the sole published reference.
            unsafe { parent.write(SlPte::new()) };
            // SAFETY: this scope cleared its sole parent. RAM stays quarantined.
            let retired = unsafe {
                crate::io::iommu::common::dma::page_table_pool::QuarantinedPt::from_unlinked(table)
            };
            let mut pending = self.pending.lock().unwrap_or_else(|error| error.into_inner());
            pending.push(retired);
        } else {
            self.pool.release(table);
        }
    }
}

/// Helper: convert a virtual pointer to a physical address (u64).
/// - Non-test: use the kernel's higher_half translation helpers
/// - Test: assume identity (pointer value is physical for unit tests)
#[inline]
pub fn virt_ptr_to_phys(ptr: *const u8) -> Result<u64, IommuError> {
    #[cfg(not(test))]
    {
        let virt = ptr as u64;
        let hhdm_base = crate::mm::virt::mapping::physical_memory_offset();
        // Most IOMMU structures are allocated from HHDM-backed kernel memory.
        // Fast-path this region to avoid taking higher-half manager locks.
        const HHDM_FAST_WINDOW: u64 = 1u64 << 46; // 64 TiB window
        let hhdm_end = hhdm_base.saturating_add(HHDM_FAST_WINDOW);
        if virt >= hhdm_base && virt < hhdm_end {
            return Ok(virt - hhdm_base);
        }

        crate::mm::virt::higher_half::virt_to_phys(crate::mm::virt::higher_half::VirtAddr::new(
            virt,
        ))
        .ok_or(IommuError::HardwareError)
        .map(|p| p.as_u64())
    }

    #[cfg(test)]
    {
        Ok(ptr as u64)
    }
}

/// Helper: convert a physical address (u64) to a virtual address usize.
#[inline]
pub fn phys_to_virt_usize(phys: u64) -> usize {
    #[cfg(not(test))]
    {
        // Use the generic HHDM mapper here: this path is used very early during
        // IOMMU bring-up where HigherHalfManager may not be published yet.
        crate::mm::virt::mapping::phys_to_virt(x86_64::PhysAddr::new(phys)).as_u64() as usize
    }

    #[cfg(test)]
    {
        phys as usize
    }
}

// ============================================================================
// HardwareTable<T> - Type-safe IOMMU Hardware Table Abstraction
// ============================================================================

/// Type-safe wrapper for IOMMU hardware tables (Root Table, Context Tables)
///
/// # Guarantees
///
/// - **Physical Contiguity**: Always allocates exactly 1 page (4KB), ensuring
///   the returned memory is physically contiguous (VT-d requirement).
/// - **Zero Initialization**: Memory is zeroed before use (hardware safety).
/// - **NUMA Awareness**: Attempts NUMA-local allocation with automatic fallback.
/// - **RAII Deallocation**: Memory is freed on Drop.
///
/// # Safety
///
/// The caller must ensure that the table is not in use by hardware when it
/// is dropped. This typically means:
/// - Disabling IOMMU translation before dropping root/context tables
/// - Invalidating any TLB entries referencing this table
///
/// # Example
///
/// ```ignore
/// // Allocate a root table (256 RootEntry, each 16 bytes = 4KB)
/// let root_table = HardwareTable::<RootEntry>::new(256, Some(0))?;
///
/// // Get physical address for hardware register
/// let phys = root_table.phys_addr();
///
/// // Access entries safely
/// if let Some(entry) = root_table.get_mut(0) {
///     entry.set_context_table(ctx_phys);
/// }
/// ```
#[derive(Debug)]
enum HardwareTableBacking {
    Frames(crate::mm::phys::frame_allocator::PhysicalAllocation),
}

#[derive(Debug)]
pub struct HardwareTable<T: Sized + Copy> {
    /// Virtual address (NonNull for null safety)
    ptr: NonNull<T>,
    /// Physical address (required by VT-d hardware)
    phys: u64,
    /// Number of entries in the table
    count: usize,
    /// Allocation size in bytes (rounded to page size)
    alloc_bytes: usize,
    /// Number of 4KiB frames backing the table
    backing: Option<HardwareTableBacking>,
    /// PhantomData for T
    _marker: PhantomData<T>,
}

// SAFETY: HardwareTable is Send/Sync because:
// - The underlying memory is exclusively owned by this struct
// - Access is controlled via safe methods with bounds checking
// - Hardware access is serialized via external locks (IommuController::hardware)
unsafe impl<T: Sized + Copy + Send> Send for HardwareTable<T> {}
unsafe impl<T: Sized + Copy + Sync> Sync for HardwareTable<T> {}

impl<T: Sized + Zeroable> HardwareTable<T> {
    /// Create a new hardware table with the specified number of entries
    ///
    /// # Arguments
    /// * `count` - Number of entries (must fit within 4KB)
    /// * `numa_hint` - Optional NUMA node preference (falls back to any node)
    ///
    /// # Errors
    /// - `IommuError::InvalidAddress` - If `count * size_of::<T>()` exceeds 4KB
    /// - `IommuError::OutOfMemory` - If allocation fails
    ///
    /// # Physical Contiguity Guarantee
    ///
    /// This function guarantees physical contiguity by using the buddy frame
    /// allocator to allocate a contiguous region sized for the table. This is a
    /// VT-d hardware requirement - root tables, context tables, and page tables
    /// must all be physically contiguous.
    pub fn new(count: usize, numa_hint: Option<usize>) -> Result<Self, IommuError> {
        if count == 0 {
            return Err(IommuError::InvalidAddress);
        }

        let bytes = core::mem::size_of::<T>()
            .checked_mul(count)
            .ok_or(IommuError::InvalidAddress)?;

        let page_size = crate::mm::types::PAGE_SIZE_4K as usize;
        let alloc_bytes = bytes
            .checked_add(page_size - 1)
            .ok_or(IommuError::InvalidAddress)?
            / page_size
            * page_size;
        let frame_count = alloc_bytes / page_size;
        if frame_count == 0 {
            return Err(IommuError::InvalidAddress);
        }

        #[cfg(feature = "qemu-test-export")]
        {
            let _ = numa_hint;
            return Self::new_heap_backed(count, alloc_bytes, frame_count, page_size);
        }

        #[cfg(not(feature = "qemu-test-export"))]
        {
            return Self::new_frame_backed(count, alloc_bytes, frame_count, numa_hint);
        }
    }

    /// Frame-backed allocation using the buddy frame allocator.
    #[cfg(not(feature = "qemu-test-export"))]
    fn new_frame_backed(
        count: usize,
        alloc_bytes: usize,
        frame_count: usize,
        numa_hint: Option<usize>,
    ) -> Result<Self, IommuError> {
        let backing = Self::alloc_phys_frames(frame_count, numa_hint)?;
        let phys = backing.as_u64();

        let virt_addr = crate::mm::virt::mapping::phys_to_virt(x86_64::PhysAddr::new(phys));
        let raw_ptr = virt_addr.as_u64() as *mut u8;

        // SAFETY: We just allocated this region and own it exclusively
        unsafe {
            core::ptr::write_bytes(raw_ptr, 0, alloc_bytes);
        }

        let ptr = NonNull::new(raw_ptr as *mut T).ok_or(IommuError::HardwareError)?;

        // Security: Register the hardware table as protected from DMA
        crate::security::dma::register_protected_range(phys, alloc_bytes as u64);

        Ok(Self {
            ptr,
            phys,
            count,
            alloc_bytes,
            backing: Some(HardwareTableBacking::Frames(backing)),
            _marker: PhantomData,
        })
    }

    /// Allocate physical frames (single or contiguous).
    #[cfg(not(feature = "qemu-test-export"))]
    fn alloc_phys_frames(
        frame_count: usize,
        numa_hint: Option<usize>,
    ) -> Result<crate::mm::phys::frame_allocator::PhysicalAllocation, IommuError> {
        if let Some(node) = numa_hint {
            let node = u8::try_from(node).map_err(|_| IommuError::InvalidAddress)?;
            crate::mm::phys::frame_allocator::alloc_contiguous_frames_aligned_on_node(
                crate::mm::types::NumaNodeId::new(node),
                frame_count,
                crate::mm::types::PAGE_SIZE_4K,
            )
            .map_err(|_| IommuError::OutOfMemory)
        } else {
            crate::mm::phys::frame_allocator::alloc_contiguous_frames(frame_count)
                .map_err(|_| IommuError::OutOfMemory)
        }
    }

    /// Get the physical address (for VT-d hardware register programming)
    ///
    /// This is the value that should be written to RTADDR, context table
    /// pointers, etc.
    #[inline]
    pub fn phys_addr(&self) -> u64 {
        self.phys
    }

    /// Get the number of valid entries
    #[inline]
    pub fn count(&self) -> usize {
        self.count
    }

    /// Get a reference to an entry by index
    ///
    /// Returns `None` if index is out of bounds.
    #[inline]
    pub fn get(&self, index: usize) -> Option<&T> {
        if index < self.count {
            // SAFETY: Index is bounds-checked, ptr is valid for count elements
            Some(unsafe { &*self.ptr.as_ptr().add(index) })
        } else {
            None
        }
    }

    /// Get a mutable reference to an entry by index
    ///
    /// Returns `None` if index is out of bounds.
    #[inline]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index < self.count {
            // SAFETY: Index is bounds-checked, ptr is valid for count elements
            Some(unsafe { &mut *self.ptr.as_ptr().add(index) })
        } else {
            None
        }
    }
}

impl<T: Sized + Copy> Drop for HardwareTable<T> {
    fn drop(&mut self) {
        // Security: Unregister the entire range from DMA protection.
        // Using unregister_protected_range ensures consistency with the registration
        // call in New, correctly handling both bitmap and regions list for any size.
        crate::security::dma::unregister_protected_range(self.phys, self.alloc_bytes as u64);

        match self
            .backing
            .take()
            .expect("table retains its backing owner")
        {
            HardwareTableBacking::Heap(layout) => unsafe {
                alloc::alloc::dealloc(self.ptr.as_ptr().cast(), layout)
            },
            HardwareTableBacking::Frames(backing) => backing.release(),
        }
    }
}
