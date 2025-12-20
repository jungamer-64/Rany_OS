use core::ops::{Index, IndexMut};
use uefi::table::boot::{AllocateType, BootServices, MemoryType};

// Page Size
pub const PAGE_SIZE: u64 = 4096;

// Page Table Flags
pub const PAGE_PRESENT: u64 = 1 << 0;
pub const PAGE_WRITABLE: u64 = 1 << 1;
pub const PAGE_USER: u64 = 1 << 2;
pub const PAGE_HUGE: u64 = 1 << 7;
pub const PAGE_NO_EXECUTE: u64 = 1 << 63;

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct PageTableEntry {
    entry: u64,
}

impl PageTableEntry {
    pub const fn new() -> Self {
        Self { entry: 0 }
    }

    pub fn is_unused(&self) -> bool {
        self.entry == 0
    }

    pub fn set_unused(&mut self) {
        self.entry = 0;
    }

    pub fn flags(&self) -> u64 {
        self.entry & 0xFFF
    }

    pub fn addr(&self) -> u64 {
        self.entry & 0x000fffff_fffff000
    }

    /// Get raw entry value (for debugging)
    pub fn raw(&self) -> u64 {
        self.entry
    }

    pub fn set_addr(&mut self, addr: u64, flags: u64) {
        self.entry = (addr & 0x000fffff_fffff000) | (flags & 0xFFF);
    }

    pub fn set_flags(&mut self, flags: u64) {
        self.entry = (self.entry & 0xFFFF_FFFF_FFFF_F000) | (flags & 0xFFF);
    }
}

#[repr(align(4096))]
#[repr(C)]
pub struct PageTable {
    pub entries: [PageTableEntry; 512],
}

impl PageTable {
    pub const fn new() -> Self {
        Self {
            entries: [PageTableEntry { entry: 0 }; 512],
        }
    }

    pub fn zero(&mut self) {
        for entry in self.entries.iter_mut() {
            entry.set_unused();
        }
    }
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
    boot_services: &'a BootServices,
    pml4: &'a mut PageTable,
}

impl<'a> UefiMapper<'a> {
    pub fn new(boot_services: &'a BootServices, pml4: &'a mut PageTable) -> Self {
        Self {
            boot_services,
            pml4,
        }
    }

    /// Allocate zeroed frames
    pub fn alloc_zeroed_pages(bs: &BootServices, num_pages: usize) -> Option<u64> {
        bs.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, num_pages)
            .ok()
            .map(|addr| {
                // Zero the memory
                unsafe {
                    core::ptr::write_bytes(addr as *mut u8, 0, (PAGE_SIZE as usize) * num_pages);
                }
                addr
            })
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

    fn get_or_create_table(&mut self, index: usize) -> Result<&'a mut PageTable, ()> {
        if self.pml4.entries[index].is_unused() {
            let frame = Self::alloc_zeroed_pages(self.boot_services, 1).ok_or(())?;
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
            let frame = Self::alloc_zeroed_pages(self.boot_services, 1).ok_or(())?;
            table.entries[index].set_addr(frame, PAGE_PRESENT | PAGE_WRITABLE);
        }
        let addr = table.entries[index].addr();
        Ok(unsafe { &mut *(addr as *mut PageTable) })
    }
}
