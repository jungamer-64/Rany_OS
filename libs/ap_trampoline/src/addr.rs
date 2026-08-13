// ============================================================================
// libs/ap_trampoline/src/addr.rs
// ============================================================================
use core::num::NonZeroUsize;

use crate::TRAMPOLINE_SIZE;

const LOW_MEM_LIMIT: u64 = 0x10_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrampolinePhysAddr(u32);

impl TrampolinePhysAddr {
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    pub fn new(addr: u64) -> Result<Self, &'static str> {
        let addr32 = u32::try_from(addr).map_err(|_| "AP trampoline address exceeds u32")?;
        if addr32 == 0 {
            return Err("AP trampoline must not reside at physical address zero");
        }
        if addr >= LOW_MEM_LIMIT {
            return Err("AP trampoline must reside below 1 MiB");
        }
        if !(addr32 as usize).is_multiple_of(TRAMPOLINE_SIZE) {
            return Err("AP trampoline must be 4 KiB aligned");
        }

        Ok(Self(addr32))
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }

    pub const fn as_u64(self) -> u64 {
        self.0 as u64
    }

    pub const fn sipi_vector(self) -> u8 {
        (self.0 / TRAMPOLINE_SIZE as u32) as u8
    }
}

impl TryFrom<u64> for TrampolinePhysAddr {
    type Error = &'static str;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<usize> for TrampolinePhysAddr {
    type Error = &'static str;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::new(value as u64)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrampolineVirtAddr(NonZeroUsize);

impl TrampolineVirtAddr {
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    pub fn new(addr: usize) -> Result<Self, &'static str> {
        let addr = NonZeroUsize::new(addr).ok_or("AP trampoline virtual address is null")?;
        if !addr.get().is_multiple_of(TRAMPOLINE_SIZE) {
            return Err("AP trampoline virtual address must be 4 KiB aligned");
        }

        Ok(Self(addr))
    }

    pub const fn as_usize(self) -> usize {
        self.0.get()
    }
}

impl TryFrom<usize> for TrampolineVirtAddr {
    type Error = &'static str;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageTable32Addr(u32);

impl PageTable32Addr {
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    pub fn new(addr: u64) -> Result<Self, &'static str> {
        let addr32 = u32::try_from(addr).map_err(|_| "AP page table base exceeds u32")?;
        if addr32 == 0 {
            return Err("AP page table base must not be zero");
        }
        if !(addr32 as usize).is_multiple_of(TRAMPOLINE_SIZE) {
            return Err("AP page table base must be 4 KiB aligned");
        }

        Ok(Self(addr32))
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }

    pub const fn as_u64(self) -> u64 {
        self.0 as u64
    }
}

impl TryFrom<u64> for PageTable32Addr {
    type Error = &'static str;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trampoline_phys_addr_rejects_out_of_range_values() {
        assert_eq!(
            TrampolinePhysAddr::new(u64::from(u32::MAX) + 1),
            Err("AP trampoline address exceeds u32")
        );
        assert_eq!(
            TrampolinePhysAddr::new(0),
            Err("AP trampoline must not reside at physical address zero")
        );
        assert_eq!(
            TrampolinePhysAddr::new(LOW_MEM_LIMIT),
            Err("AP trampoline must reside below 1 MiB")
        );
        assert_eq!(
            TrampolinePhysAddr::new(0x8100),
            Err("AP trampoline must be 4 KiB aligned")
        );
    }

    #[test]
    fn trampoline_virt_addr_rejects_invalid_values() {
        assert_eq!(
            TrampolineVirtAddr::new(0),
            Err("AP trampoline virtual address is null")
        );
        assert_eq!(
            TrampolineVirtAddr::new(0x8100),
            Err("AP trampoline virtual address must be 4 KiB aligned")
        );
        assert_eq!(TrampolineVirtAddr::new(0x1000).unwrap().as_usize(), 0x1000);
    }

    #[test]
    fn page_table_addr_rejects_invalid_values() {
        assert_eq!(
            PageTable32Addr::new(u64::from(u32::MAX) + 1),
            Err("AP page table base exceeds u32")
        );
        assert_eq!(
            PageTable32Addr::new(0),
            Err("AP page table base must not be zero")
        );
        assert_eq!(
            PageTable32Addr::new(0x2100),
            Err("AP page table base must be 4 KiB aligned")
        );
    }
}
