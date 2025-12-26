use super::types::IommuError;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ptr::NonNull;

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

/// Page table levels
pub const PT_LEVELS: usize = 4;

/// Page table entries per level (512 for 4KB pages)
pub const PT_ENTRIES: usize = 512;

/// Root table entry
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct RootEntry {
    /// Lower 64 bits (context table pointer)
    pub lo: u64,
    /// Upper 64 bits (reserved)
    pub hi: u64,
}

impl RootEntry {
    /// Check if entry is present
    pub fn is_present(&self) -> bool {
        (self.lo & 1) != 0
    }

    /// Set context table pointer
    pub fn set_context_table(&mut self, addr: u64) {
        self.lo = (addr & !0xFFF) | 1; // Present bit
    }

    /// Get context table address
    pub fn context_table_addr(&self) -> u64 {
        self.lo & !0xFFF
    }
}

// SAFETY: RootEntry with all zeros represents "not present" - a valid state
unsafe impl Zeroable for RootEntry {}

/// Context table entry
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct ContextEntry {
    /// Lower 64 bits
    pub lo: u64,
    /// Upper 64 bits
    pub hi: u64,
}

impl ContextEntry {
    /// Check if entry is present
    pub fn is_present(&self) -> bool {
        (self.lo & 1) != 0
    }

    /// Check if entry is fault disabled
    pub fn is_fault_disabled(&self) -> bool {
        (self.lo & 2) != 0
    }

    /// Set second level page table pointer (Translation Type = 00b)
    pub fn set_sl_pt(&mut self, addr: u64, domain_id: u16, agaw: u8) {
        self.lo = (addr & !0xFFF) | 1; // Present
        self.hi = ((domain_id as u64) << 8) | ((agaw as u64) << 0);
    }

    /// Set passthrough (Translation Type = 10b / 2)
    pub fn set_passthrough(&mut self, domain_id: u16) {
        // PT (bit 3:2) = 10b (2). Present (bit 0) = 1.
        self.lo = (2 << 2) | 1;
        self.hi = (domain_id as u64) << 8;
    }

    /// Get second level page table address
    pub fn sl_pt_addr(&self) -> u64 {
        self.lo & !0xFFF
    }

    /// Get domain ID
    pub fn domain_id(&self) -> u16 {
        ((self.hi >> 8) & 0xFFFF) as u16
    }
}

// SAFETY: ContextEntry with all zeros represents "not present" - a valid state
unsafe impl Zeroable for ContextEntry {}

/// Scalable Mode Context Entry (128 bytes)
///
/// Used in Scalable Mode Translation (SMTS) for PASID-based translation.
/// Each entry is 128 bytes and points to a PASID table.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug)]
pub struct ScalableContextEntry {
    /// 8 QWORDs (64 bytes each half)
    pub qwords: [u64; 16],
}

impl Default for ScalableContextEntry {
    fn default() -> Self {
        Self { qwords: [0; 16] }
    }
}

impl ScalableContextEntry {
    /// Present bit (QWORD 0, bit 0)
    pub const PRESENT: u64 = 1 << 0;
    /// PASID Table Pointer (QWORD 0, bits 12-63)
    pub const PTP_MASK: u64 = !0xFFF;
    /// PASID Table Size (QWORD 1, bits 0-3) - log2 of entries
    pub const PTS_SHIFT: u64 = 0;
    /// RID-PASID (Request ID to PASID mapping, QWORD 1)
    pub const RID_PASID_SHIFT: u64 = 4;
    /// Domain ID (QWORD 8, bits 8-23)
    pub const DID_SHIFT: u64 = 8;

    /// Create a new empty entry
    pub const fn new() -> Self {
        Self { qwords: [0; 16] }
    }

    /// Check if the entry is present
    pub fn is_present(&self) -> bool {
        (self.qwords[0] & Self::PRESENT) != 0
    }

    /// Set the PASID table pointer
    pub fn set_pasid_table(&mut self, pasid_table_addr: u64, size_log2: u8) {
        self.qwords[0] = (pasid_table_addr & Self::PTP_MASK) | Self::PRESENT;
        // Set PASID table size in QWORD 1
        self.qwords[1] = ((size_log2 as u64) & 0xF) << Self::PTS_SHIFT;
    }

    /// Set domain ID
    pub fn set_domain_id(&mut self, domain_id: u16) {
        self.qwords[8] = (self.qwords[8] & !0xFFFF00) | ((domain_id as u64) << Self::DID_SHIFT);
    }

    /// Get domain ID
    pub fn domain_id(&self) -> u16 {
        ((self.qwords[8] >> Self::DID_SHIFT) & 0xFFFF) as u16
    }

    /// Get PASID table pointer
    pub fn pasid_table_addr(&self) -> u64 {
        self.qwords[0] & Self::PTP_MASK
    }
}

/// PASID Table Entry (64 bytes)
///
/// Each entry in the PASID table defines the address translation
/// for a specific PASID.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug)]
pub struct PasidTableEntry {
    /// 8 QWORDs
    pub qwords: [u64; 8],
}

impl Default for PasidTableEntry {
    fn default() -> Self {
        Self { qwords: [0; 8] }
    }
}

impl PasidTableEntry {
    /// Present bit (QWORD 0, bit 0)
    pub const PRESENT: u64 = 1 << 0;
    /// Page Walk Disable (QWORD 0, bit 3)
    pub const PWD: u64 = 1 << 3;
    /// First Level Page Table Pointer (QWORD 0, bits 12-63)
    pub const FLPT_MASK: u64 = !0xFFF;
    /// Address Width (QWORD 1, bits 0-2)
    pub const AW_SHIFT: u64 = 0;
    /// Supervisor Request (QWORD 1, bit 5)
    pub const SRE: u64 = 1 << 5;
    /// Execute Enable (QWORD 1, bit 6)
    pub const EAFE: u64 = 1 << 6;

    /// Create a new empty entry
    pub const fn new() -> Self {
        Self { qwords: [0; 8] }
    }

    /// Check if present
    pub fn is_present(&self) -> bool {
        (self.qwords[0] & Self::PRESENT) != 0
    }

    /// Set first level page table pointer
    pub fn set_fl_pt(&mut self, addr: u64, address_width: u8) {
        self.qwords[0] = (addr & Self::FLPT_MASK) | Self::PRESENT;
        self.qwords[1] = ((address_width as u64) & 0x7) << Self::AW_SHIFT;
    }

    /// Set second level page table pointer (for nested translation)
    pub fn set_sl_pt(&mut self, addr: u64, address_width: u8) {
        // Set PWD = 0 (page walk enabled) and point to SL PT
        self.qwords[0] = (addr & Self::FLPT_MASK) | Self::PRESENT;
        self.qwords[1] = ((address_width as u64) & 0x7) << Self::AW_SHIFT;
    }

    /// Get first level page table address
    pub fn fl_pt_addr(&self) -> u64 {
        self.qwords[0] & Self::FLPT_MASK
    }
}

/// PASID Table
///
/// Manages PASID entries for Scalable Mode.
/// Each entry is 64 bytes (PasidTableEntry).
pub struct PasidTable {
    /// Base virtual address
    base: usize,
    /// Size (number of entries, power of 2)
    size: usize,
    /// Allocation bitmap
    allocated: Vec<u64>,
}

impl PasidTable {
    /// Default size (256 entries)
    pub const DEFAULT_SIZE: usize = 256;

    /// Create a new PASID table
    pub fn new(size: usize) -> Option<Self> {
        let size = size.next_power_of_two().min(1 << 20); // Max 2^20 PASIDs
        let total_bytes = size * core::mem::size_of::<PasidTableEntry>();

        // Allocate 4KB aligned memory
        let layout = alloc::alloc::Layout::from_size_align(total_bytes, 4096).ok()?;
        let base = crate::util::allocate_zeroed(layout)?.as_ptr() as usize;

        // Bitmap: 64 entries per u64
        let bitmap_size = (size + 63) / 64;
        let allocated = alloc::vec![0u64; bitmap_size];

        Some(Self {
            base,
            size,
            allocated,
        })
    }

    /// Get the physical base address
    pub fn base_address(&self) -> u64 {
        self.base as u64
    }

    /// Get size log2 (for context entry)
    pub fn size_log2(&self) -> u8 {
        self.size.trailing_zeros() as u8
    }

    /// Allocate a PASID
    pub fn allocate(&mut self) -> Option<u32> {
        for (word_idx, word) in self.allocated.iter_mut().enumerate() {
            if *word != u64::MAX {
                let bit = (!*word).trailing_zeros() as usize;
                let index = word_idx * 64 + bit;
                if index >= self.size {
                    return None;
                }
                *word |= 1 << bit;
                return Some(index as u32);
            }
        }
        None
    }

    /// Free a PASID
    pub fn free(&mut self, pasid: u32) {
        let word_idx = pasid as usize / 64;
        let bit = pasid as usize % 64;
        if word_idx < self.allocated.len() {
            self.allocated[word_idx] &= !(1 << bit);
        }
    }

    /// Get mutable reference to a PASID entry
    pub fn get_mut(&mut self, pasid: u32) -> Option<&mut PasidTableEntry> {
        if (pasid as usize) < self.size {
            let ptr = self.base as *mut PasidTableEntry;
            Some(unsafe { &mut *ptr.add(pasid as usize) })
        } else {
            None
        }
    }

    /// Get reference to a PASID entry
    pub fn get(&self, pasid: u32) -> Option<&PasidTableEntry> {
        if (pasid as usize) < self.size {
            let ptr = self.base as *const PasidTableEntry;
            Some(unsafe { &*ptr.add(pasid as usize) })
        } else {
            None
        }
    }
}

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
    /// Transient mapping hint
    pub const TRANSIENT: u64 = 1 << 62;

    /// Create a new entry
    pub const fn new() -> Self {
        Self(0)
    }

    /// Create a present entry with address and permissions
    pub fn mapping(phys_addr: u64, read: bool, write: bool) -> Self {
        let mut flags = Self::PRESENT;
        if read {
            flags |= Self::READ;
        }
        if write {
            flags |= Self::WRITE;
        }
        Self((phys_addr & !0xFFF) | flags)
    }

    /// Create a 2MB super-page entry (used at PD level)
    /// phys_addr must be 2MB-aligned
    pub fn super_page_2mb(phys_addr: u64, read: bool, write: bool) -> Self {
        const MASK_2MB: u64 = (2 * 1024 * 1024) - 1; // 0x1F_FFFF
        let mut flags = Self::PRESENT | Self::SUPER_PAGE;
        if read {
            flags |= Self::READ;
        }
        if write {
            flags |= Self::WRITE;
        }
        Self((phys_addr & !MASK_2MB) | flags)
    }

    /// Create a 1GB super-page entry (used at PDP level)
    /// phys_addr must be 1GB-aligned
    pub fn super_page_1gb(phys_addr: u64, read: bool, write: bool) -> Self {
        const MASK_1GB: u64 = (1024 * 1024 * 1024) - 1; // 0x3FFF_FFFF
        let mut flags = Self::PRESENT | Self::SUPER_PAGE;
        if read {
            flags |= Self::READ;
        }
        if write {
            flags |= Self::WRITE;
        }
        Self((phys_addr & !MASK_1GB) | flags)
    }

    /// Check if this is a super-page entry
    pub fn is_super_page(&self) -> bool {
        (self.0 & Self::SUPER_PAGE) != 0
    }

    /// Check if present
    pub fn is_present(&self) -> bool {
        (self.0 & Self::PRESENT) != 0
    }

    /// Get physical address
    pub fn phys_addr(&self) -> u64 {
        self.0 & !0xFFF
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

/// RAII guard for an allocated page-table page
///
/// Ensures that allocated page-tables are deallocated on panic or error unless explicitly committed.
///
/// # Phase 6: Pool Support
///
/// If created via `new_with_pool()`, the page table is acquired from the pool and
/// returned to the pool on Drop. Otherwise, direct allocation/deallocation is used.
///
/// # Lock Ordering
///
/// When acquiring pool pages, ensure domain lock is held BEFORE pool lock.
pub struct PageTableScope {
    /// Virtual pointer to the page table
    ptr: *mut SlPte,
    /// Physical address of the page table
    phys: u64,
    /// NUMA node where this table was allocated
    node: usize,
    /// Layout for direct deallocation (None if pool-managed)
    layout: Option<alloc::alloc::Layout>,
    /// Pool for release (Some if pool-managed)
    pool: Option<alloc::sync::Arc<super::page_table_pool::PageTablePool>>,
    /// Parent entry pointer that references this table. If set and the scope is not committed,
    /// Drop will clear the parent entry to avoid leaving stale pointers into freed memory.
    parent_entry: Option<*mut SlPte>,
    parent_phys: Option<u64>,
    committed: bool,
}

impl PageTableScope {
    /// Allocate a zeroed page table on the given NUMA node (direct allocation, no pool)
    ///
    /// Use `new_with_pool()` for pool-managed allocation.
    pub fn new(numa_hint: Option<usize>) -> Result<Self, IommuError> {
        let layout =
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .map_err(|_| IommuError::HardwareError)?;

        let node = numa_hint.unwrap_or(0);
        let ptr = crate::mm::numa::allocate_zeroed_on_node(layout, numa_hint)
            .ok_or(IommuError::HardwareError)?
            .as_ptr() as *mut SlPte;

        let phys = virt_ptr_to_phys(ptr as *const u8)?;

        Ok(Self {
            ptr,
            phys,
            node,
            layout: Some(layout),
            pool: None,
            parent_entry: None,
            parent_phys: None,
            committed: false,
        })
    }

    /// Allocate a zeroed page table from the pool (Phase 6)
    ///
    /// The page table is returned to the pool on Drop (unless committed to a
    /// structure that will manage lifetime separately).
    ///
    /// # Arguments
    /// * `pool` - The page table pool to acquire from
    /// * `node_hint` - Preferred NUMA node
    pub fn new_with_pool(
        pool: alloc::sync::Arc<super::page_table_pool::PageTablePool>,
        node_hint: Option<usize>,
    ) -> Result<Self, IommuError> {
        let pt = pool.acquire(node_hint)?;

        Ok(Self {
            ptr: pt.ptr.as_ptr(),
            phys: pt.phys,
            node: pt.node,
            layout: None, // Pool-managed, no layout needed
            pool: Some(pool),
            parent_entry: None,
            parent_phys: None,
            committed: false,
        })
    }

    /// Attach the newly allocated table to the provided parent entry.
    /// This writes the parent entry to point to the table and stores the parent information
    /// so that Drop can clear it if this scope is not committed.
    pub fn attach_to_parent(&mut self, parent_entry: *mut SlPte, parent_phys: u64) {
        unsafe {
            *parent_entry = SlPte::mapping(self.phys, true, true);
        }
        self.parent_entry = Some(parent_entry);
        self.parent_phys = Some(parent_phys);
    }

    /// Commit the allocation into the page table accounting structures.
    /// This will insert the entry into `page_table_counts` and increment the parent's usage count.
    pub fn commit(&mut self, page_table_counts: &mut alloc::collections::BTreeMap<u64, u16>) {
        // Ensure the table is present in accounting without overwriting any existing counts
        page_table_counts.entry(self.phys).or_insert(0);
        if let Some(parent_phys) = self.parent_phys {
            *page_table_counts.entry(parent_phys).or_default() += 1;
        }
        self.committed = true;
    }

    #[inline]
    pub fn ptr(&self) -> *mut SlPte {
        self.ptr
    }

    #[inline]
    pub fn phys(&self) -> u64 {
        self.phys
    }

    #[inline]
    pub fn node(&self) -> usize {
        self.node
    }
}

impl Drop for PageTableScope {
    fn drop(&mut self) {
        // If not committed, we must clear the parent entry (if any) and free the memory
        if !self.committed {
            if let Some(parent) = self.parent_entry {
                unsafe {
                    (*parent).0 = 0;
                }
            }

            // Release to pool or direct dealloc
            if let Some(ref pool) = self.pool {
                // Pool-managed: reconstruct PooledPt and release
                let pt = super::page_table_pool::PooledPt::new(
                    unsafe { core::ptr::NonNull::new_unchecked(self.ptr) },
                    self.phys,
                    self.node,
                );
                pool.release(pt);
            } else if let Some(layout) = self.layout {
                // Direct allocation: dealloc via NUMA helper
                unsafe {
                    crate::mm::numa::deallocate_on_node(
                        core::ptr::NonNull::new_unchecked(self.ptr as *mut u8),
                        layout,
                        Some(self.node),
                    );
                }
            }
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
        crate::mm::virt_to_phys(crate::mm::VirtAddr::new(ptr as u64))
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
        crate::mm::phys_to_virt(crate::mm::PhysAddr::new(phys)).as_u64() as usize
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
pub struct HardwareTable<T: Sized + Copy> {
    /// Virtual address (NonNull for null safety)
    ptr: NonNull<T>,
    /// Physical address (required by VT-d hardware)
    phys: u64,
    /// Number of entries in the table
    count: usize,
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
    /// Maximum allocation size: 4KB (1 page) for physical contiguity guarantee
    pub const MAX_SIZE: usize = 4096;

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
    /// allocator to allocate exactly one 4KB physical page frame. This is a
    /// VT-d hardware requirement - root tables, context tables, and page tables
    /// must all be physically contiguous.
    pub fn new(count: usize, numa_hint: Option<usize>) -> Result<Self, IommuError> {
        if count == 0 {
            return Err(IommuError::InvalidAddress);
        }

        let bytes = core::mem::size_of::<T>()
            .checked_mul(count)
            .ok_or(IommuError::InvalidAddress)?;

        // Enforce 4KB limit for physical contiguity
        if bytes > Self::MAX_SIZE {
            return Err(IommuError::InvalidAddress);
        }

        // Use buddy allocator to get a physically contiguous 4KB frame
        // This is the key change that guarantees physical contiguity!
        let frame = if let Some(node) = numa_hint {
            crate::mm::buddy_alloc_frame_on_node(node)
        } else {
            crate::mm::buddy_alloc_frame()
        }
        .ok_or(IommuError::OutOfMemory)?;

        // Get physical address from the frame
        let phys = frame.start_address().as_u64();

        // Convert to virtual address using linear mapping
        let virt_addr = crate::mm::mapping::phys_to_virt(x86_64::PhysAddr::new(phys));
        let raw_ptr = virt_addr.as_u64() as *mut u8;

        // Zero the memory (hardware safety requirement)
        // SAFETY: We just allocated this frame and own it exclusively
        unsafe {
            core::ptr::write_bytes(raw_ptr, 0, Self::MAX_SIZE);
        }

        let ptr = NonNull::new(raw_ptr as *mut T).ok_or(IommuError::HardwareError)?;

        Ok(Self {
            ptr,
            phys,
            count,
            _marker: PhantomData,
        })
    }

    /// Get the virtual pointer (for kernel access)
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.ptr.as_ptr()
    }

    /// Get a mutable virtual pointer (for kernel access)
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - Access is serialized via external locks (e.g., `IommuController::hardware`)
    /// - No other mutable references exist to this data
    /// - The returned pointer is not used after this table is dropped
    ///
    /// Prefer using `get_mut()` or `as_mut_slice()` for bounds-checked safe access.
    #[inline]
    pub unsafe fn as_mut_ptr_unchecked(&mut self) -> *mut T {
        self.ptr.as_ptr()
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

    /// Get a slice of all valid entries
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        // SAFETY: ptr is valid for `count` elements
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.count) }
    }

    /// Get a mutable slice of all valid entries
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: ptr is valid for `count` elements
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.count) }
    }

    /// Zero all entries in the table
    ///
    /// Useful for reinitializing a table without reallocating.
    pub fn clear(&mut self) {
        // SAFETY: ptr is valid for MAX_SIZE bytes (one full page)\n        unsafe {\n            core::ptr::write_bytes(self.ptr.as_ptr() as *mut u8, 0, Self::MAX_SIZE);\n        }
    }
}

impl<T: Sized + Copy> Drop for HardwareTable<T> {
    fn drop(&mut self) {
        // SAFETY: We own the frame and it was allocated via buddy_alloc_frame
        // The caller must ensure hardware is not using this table before drop
        use x86_64::structures::paging::{PhysFrame, Size4KiB};

        let frame = PhysFrame::<Size4KiB>::containing_address(x86_64::PhysAddr::new(self.phys));
        crate::mm::buddy_dealloc_frame(frame);
    }
}
