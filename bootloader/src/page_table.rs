use core::ops::{Index, IndexMut};
use uefi::boot::{self, AllocateType};
use uefi::mem::memory_map::MemoryType;

// Page Sizes
pub const PAGE_SIZE: u64 = 4096;
pub const PAGE_SIZE_2MB: u64 = 2 * 1024 * 1024;
pub const PAGE_SIZE_1GB: u64 = 1024 * 1024 * 1024;
const PAGE_TABLE_MIN_ADDR: u64 = PAGE_SIZE;
const PAGE_TABLE_MAX_ADDR: u64 = u32::MAX as u64;

// Page Table Flags
pub const PAGE_PRESENT: u64 = 1 << 0;
pub const PAGE_WRITABLE: u64 = 1 << 1;
pub const PAGE_HUGE: u64 = 1 << 7;
pub const PAGE_NO_EXECUTE: u64 = 1 << 63;
const FLAGS_MASK: u64 = 0x8000_0000_0000_0fff; // NX + lower 12 flag bits

/// CPU feature flags for page size support
#[derive(Debug, Clone, Copy)]
pub struct CpuPageFeatures {
    /// PSE (Page Size Extension) - 2MB pages supported
    pub pse: bool,
    /// Page1GB - 1GB pages supported (CPUID.80000001H:EDX[26])
    pub page_1gb: bool,
}

impl CpuPageFeatures {
    /// Detect CPU page size support via CPUID
    pub fn detect() -> Self {
        // CPUID.01H:EDX[3] = PSE (Page Size Extension, 2MB pages)
        let cpuid_01 = core::arch::x86_64::__cpuid(0x01);
        let pse = (cpuid_01.edx & (1 << 3)) != 0;

        // Check if extended CPUID is available
        let cpuid_ext = core::arch::x86_64::__cpuid(0x80000000);
        let page_1gb = if cpuid_ext.eax >= 0x80000001 {
            // CPUID.80000001H:EDX[26] = Page1GB
            let cpuid_ext_01 = core::arch::x86_64::__cpuid(0x80000001);
            (cpuid_ext_01.edx & (1 << 26)) != 0
        } else {
            false
        };

        Self { pse, page_1gb }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct PageTableEntry {
    entry: u64,
}
impl PageTableEntry {
    pub fn is_unused(&self) -> bool {
        self.entry == 0
    }

    pub fn addr(&self) -> u64 {
        self.entry & 0x000fffff_fffff000
    }

    pub fn set_addr(&mut self, addr: u64, flags: u64) {
        self.entry = (addr & 0x000f_ffff_ffff_f000) | (flags & FLAGS_MASK);
    }
}

#[repr(align(4096))]
#[repr(C)]
pub struct PageTable {
    pub entries: [PageTableEntry; 512],
}

impl Index<usize> for PageTable {
    type Output = PageTableEntry;

    fn index(&self, index: usize) -> &Self::Output {
        &self.entries[index]
    }
}

impl IndexMut<usize> for PageTable {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.entries[index]
    }
}

/// Simple mapper that allocates frames from UEFI
pub struct UefiMapper<'a> {
    pml4: &'a mut PageTable,
}

impl<'a> UefiMapper<'a> {
    pub fn new(pml4: &'a mut PageTable) -> Self {
        Self { pml4 }
    }

    /// Allocate zeroed frames with specific memory type
    pub fn alloc_zeroed_pages(num_pages: usize, mem_type: MemoryType) -> Option<u64> {
        boot::allocate_pages(AllocateType::AnyPages, mem_type, num_pages)
            .ok()
            .map(|ptr| {
                let addr = ptr.as_ptr() as u64;
                // Zero the memory
                unsafe {
                    core::ptr::write_bytes(addr as *mut u8, 0, (PAGE_SIZE as usize) * num_pages);
                }
                addr
            })
    }

    /// Allocate zeroed page-table pages suitable for the AP trampoline CR3 handoff.
    ///
    /// The trampoline mailbox stores the page-table root in a nonzero 32-bit
    /// slot, so every boot page-table page must live below 4 GiB and never at
    /// physical address zero.
    pub fn alloc_zeroed_page_table_pages(num_pages: usize) -> Option<u64> {
        if num_pages == 0 {
            return None;
        }

        let ptr = boot::allocate_pages(
            AllocateType::MaxAddress(PAGE_TABLE_MAX_ADDR),
            MemoryType::RUNTIME_SERVICES_DATA,
            num_pages,
        )
        .ok()?;
        let addr = ptr.as_ptr() as u64;
        let size = PAGE_SIZE.checked_mul(num_pages as u64)?;
        let end = addr.checked_add(size.checked_sub(1)?)?;

        if addr < PAGE_TABLE_MIN_ADDR || end > PAGE_TABLE_MAX_ADDR {
            unsafe {
                let _ = boot::free_pages(ptr, num_pages);
            }
            return None;
        }

        unsafe {
            core::ptr::write_bytes(addr as *mut u8, 0, (PAGE_SIZE as usize) * num_pages);
        }

        Some(addr)
    }

    /// Map a global page (kernel space)
    pub fn map_page(&mut self, virt: u64, phys: u64, flags: u64) -> Result<(), ()> {
        let p4_index = ((virt >> 39) & 0x1ff) as usize;
        let p3_index = ((virt >> 30) & 0x1ff) as usize;
        let p2_index = ((virt >> 21) & 0x1ff) as usize;
        let p1_index = ((virt >> 12) & 0x1ff) as usize;

        let p3 = self.get_or_create_table(p4_index)?;
        let p2 = self.get_or_create_table_from(p3, p3_index)?;
        let p1 = self.get_or_create_table_from(p2, p2_index)?;

        let entry = &mut p1.entries[p1_index];
        entry.set_addr(phys, flags | PAGE_PRESENT);
        Ok(())
    }

    /// Map a global 2MB huge page
    pub fn map_page_2mb(&mut self, virt: u64, phys: u64, flags: u64) -> Result<(), ()> {
        let p4_index = ((virt >> 39) & 0x1ff) as usize;
        let p3_index = ((virt >> 30) & 0x1ff) as usize;
        let p2_index = ((virt >> 21) & 0x1ff) as usize;

        let p3 = self.get_or_create_table(p4_index)?;
        let p2 = self.get_or_create_table_from(p3, p3_index)?;

        let entry = &mut p2.entries[p2_index];
        entry.set_addr(phys, flags | PAGE_PRESENT | PAGE_HUGE);
        Ok(())
    }

    /// Map a global 1GB huge page (requires CPU support)
    ///
    /// # Arguments
    /// * `virt` - Virtual address (must be 1GB aligned)
    /// * `phys` - Physical address (must be 1GB aligned)
    /// * `flags` - Page flags (PAGE_WRITABLE, PAGE_NO_EXECUTE, etc.)
    ///
    /// # Returns
    /// * `Ok(())` if mapping succeeded
    /// * `Err(())` if allocation failed
    pub fn map_page_1gb(&mut self, virt: u64, phys: u64, flags: u64) -> Result<(), ()> {
        debug_assert!(virt % PAGE_SIZE_1GB == 0, "1GB page virt not aligned");
        debug_assert!(phys % PAGE_SIZE_1GB == 0, "1GB page phys not aligned");

        let p4_index = ((virt >> 39) & 0x1ff) as usize;
        let p3_index = ((virt >> 30) & 0x1ff) as usize;

        let p3 = self.get_or_create_table(p4_index)?;

        // Set 1GB page directly in PDPT entry (PAGE_HUGE flag makes it a leaf)
        let entry = &mut p3.entries[p3_index];
        entry.set_addr(phys, flags | PAGE_PRESENT | PAGE_HUGE);
        Ok(())
    }

    fn get_or_create_table(&mut self, index: usize) -> Result<&'a mut PageTable, ()> {
        if self.pml4.entries[index].is_unused() {
            // Allocate page tables as RUNTIME_SERVICES_DATA so kernel preserves them
            let frame = Self::alloc_zeroed_page_table_pages(1).ok_or(())?;
            self.pml4.entries[index].set_addr(frame, PAGE_PRESENT | PAGE_WRITABLE);
        }
        let addr = self.pml4.entries[index].addr();
        Ok(unsafe { &mut *(addr as *mut PageTable) })
    }

    fn get_or_create_table_from(
        &self,
        table: &mut PageTable,
        index: usize,
    ) -> Result<&'a mut PageTable, ()> {
        if table.entries[index].is_unused() {
            // Allocate page tables as RUNTIME_SERVICES_DATA so kernel preserves them
            let frame = Self::alloc_zeroed_page_table_pages(1).ok_or(())?;
            table.entries[index].set_addr(frame, PAGE_PRESENT | PAGE_WRITABLE);
        }
        let addr = table.entries[index].addr();
        Ok(unsafe { &mut *(addr as *mut PageTable) })
    }
}
