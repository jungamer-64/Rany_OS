//! Checked geometry for the loader-owned bootstrap RAM slab. These values
//! describe memory; they do not grant dereference, allocation, or release rights.
#![forbid(unsafe_code)]

use core::alloc::Layout;

const PAGE_BYTES: usize = 4096;
// Boot admission policy: enough space for IOMMU/firmware working sets, plus
// packet pools and domain-transfer objects. The kernel uses the handed-off
// geometry, not a second copy of this policy.
const KERNEL_BYTES: usize = 256 * 1024 * 1024;
const EXCHANGE_BYTES: usize = 16 * 1024 * 1024;

/// Wire observation of one firmware allocation, split into disjoint heaps.
/// Copying this descriptor does not transfer ownership of its RAM.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BootstrapHeapDescriptor {
    pub physical_start: u64,
    pub kernel_bytes: u64,
    pub exchange_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapMemoryError {
    Empty,
    Alignment,
    Extent,
    AddressOverflow,
    OutsideMapping,
}

/// Page-exact split and allocation layout, validated before firmware admission.
#[derive(Debug, Clone, Copy)]
pub struct BootstrapHeapLayout {
    allocation: Layout,
    kernel: Layout,
    exchange: Layout,
}

impl BootstrapHeapLayout {
    /// # Errors
    /// Rejects empty heaps, non-page sizes, and extents exceeding Rust's layout
    /// bound. Failure occurs before any memory ownership is acquired.
    pub fn new(kernel_bytes: usize, exchange_bytes: usize) -> Result<Self, BootstrapMemoryError> {
        if kernel_bytes == 0 || exchange_bytes == 0 {
            return Err(BootstrapMemoryError::Empty);
        }
        if !kernel_bytes.is_multiple_of(PAGE_BYTES) || !exchange_bytes.is_multiple_of(PAGE_BYTES) {
            return Err(BootstrapMemoryError::Alignment);
        }
        let bytes = kernel_bytes
            .checked_add(exchange_bytes)
            .ok_or(BootstrapMemoryError::Extent)?;
        let allocation =
            Layout::from_size_align(bytes, PAGE_BYTES).map_err(|_| BootstrapMemoryError::Extent)?;
        let kernel = Layout::from_size_align(kernel_bytes, PAGE_BYTES)
            .map_err(|_| BootstrapMemoryError::Extent)?;
        let exchange = Layout::from_size_align(exchange_bytes, PAGE_BYTES)
            .map_err(|_| BootstrapMemoryError::Extent)?;
        Ok(Self {
            allocation,
            kernel,
            exchange,
        })
    }

    /// Bootloader admission policy, evaluated through the same checked layout
    /// constructor as incoming ABI geometry.
    /// # Errors
    /// Invalid boot admission policy fails before firmware allocation, with the
    /// same extent/alignment classification as `Self::new`.
    pub fn for_kernel() -> Result<Self, BootstrapMemoryError> {
        Self::new(KERNEL_BYTES, EXCHANGE_BYTES)
    }

    pub const fn allocation(self) -> Layout {
        self.allocation
    }
    pub const fn pages(self) -> usize {
        self.allocation.size() / PAGE_BYTES
    }

    /// # Errors
    /// Rejects zero/misaligned base, physical or HHDM overflow, and a slab not
    /// fully covered by the installed mapping. This validates geometry only.
    pub fn at(
        self,
        physical_start: u64,
        hhdm_start: u64,
        mapped_physical_limit: u64,
    ) -> Result<BootstrapHeapGeometry, BootstrapMemoryError> {
        if physical_start == 0 {
            return Err(BootstrapMemoryError::Empty);
        }
        if !physical_start.is_multiple_of(PAGE_BYTES as u64)
            || !hhdm_start.is_multiple_of(PAGE_BYTES as u64)
        {
            return Err(BootstrapMemoryError::Alignment);
        }
        let physical_end = physical_start
            .checked_add(self.allocation.size() as u64)
            .ok_or(BootstrapMemoryError::AddressOverflow)?;
        if physical_end > mapped_physical_limit {
            return Err(BootstrapMemoryError::OutsideMapping);
        }
        let start = hhdm_start
            .checked_add(physical_start)
            .ok_or(BootstrapMemoryError::AddressOverflow)?;
        let end = start
            .checked_add(self.allocation.size() as u64)
            .ok_or(BootstrapMemoryError::AddressOverflow)?;
        let start = usize::try_from(start).map_err(|_| BootstrapMemoryError::Extent)?;
        let _end = usize::try_from(end).map_err(|_| BootstrapMemoryError::Extent)?;
        Ok(BootstrapHeapGeometry {
            physical_start,
            virtual_start: start,
            layout: self,
        })
    }
}

impl BootstrapHeapDescriptor {
    /// # Errors
    /// Validates incoming sizes and geometry without constructing a pointer or
    /// claiming that firmware actually allocated the described pages.
    pub fn geometry(
        self,
        hhdm_start: u64,
        mapped_physical_limit: u64,
    ) -> Result<BootstrapHeapGeometry, BootstrapMemoryError> {
        let kernel =
            usize::try_from(self.kernel_bytes).map_err(|_| BootstrapMemoryError::Extent)?;
        let exchange =
            usize::try_from(self.exchange_bytes).map_err(|_| BootstrapMemoryError::Extent)?;
        BootstrapHeapLayout::new(kernel, exchange)?.at(
            self.physical_start,
            hhdm_start,
            mapped_physical_limit,
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MappedHeapRange {
    start: usize,
    layout: Layout,
}

impl MappedHeapRange {
    pub const fn start(self) -> usize {
        self.start
    }
    pub const fn layout(self) -> Layout {
        self.layout
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BootstrapHeapGeometry {
    physical_start: u64,
    virtual_start: usize,
    layout: BootstrapHeapLayout,
}

impl BootstrapHeapGeometry {
    pub fn descriptor(self) -> BootstrapHeapDescriptor {
        BootstrapHeapDescriptor {
            physical_start: self.physical_start,
            kernel_bytes: self.layout.kernel.size() as u64,
            exchange_bytes: self.layout.exchange.size() as u64,
        }
    }
    pub const fn allocation_range(self) -> (u64, u64) {
        (self.physical_start, self.layout.allocation.size() as u64)
    }
    pub fn ranges(self) -> [MappedHeapRange; 2] {
        // Both sub-layouts are page multiples inside the validated parent.
        [
            MappedHeapRange {
                start: self.virtual_start,
                layout: self.layout.kernel,
            },
            MappedHeapRange {
                start: self.virtual_start + self.layout.kernel.size(),
                layout: self.layout.exchange,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slab_split_is_page_exact_and_nonoverlapping() -> Result<(), BootstrapMemoryError> {
        let geometry =
            BootstrapHeapLayout::new(0x2000, 0x3000)?.at(0x17000, 0x80000000, 0x20000)?;
        let [kernel, exchange] = geometry.ranges();
        assert_eq!(kernel.start() + kernel.layout().size(), exchange.start());
        assert_eq!(exchange.start() + exchange.layout().size(), 0x8001c000);
        assert_eq!(geometry.allocation_range(), (0x17000, 0x5000));
        assert_eq!(
            geometry
                .descriptor()
                .geometry(0x80000000, 0x20000)?
                .ranges()[1]
                .start(),
            exchange.start()
        );
        Ok(())
    }

    #[test]
    fn invalid_extent_alignment_and_mapping_are_rejected() {
        assert!(matches!(
            BootstrapHeapLayout::new(0, 4096),
            Err(BootstrapMemoryError::Empty)
        ));
        assert!(matches!(
            BootstrapHeapLayout::new(1, 4096),
            Err(BootstrapMemoryError::Alignment)
        ));
        assert!(matches!(
            BootstrapHeapLayout::new(usize::MAX & !4095, 4096),
            Err(BootstrapMemoryError::Extent)
        ));
        let layout = BootstrapHeapLayout::new(4096, 4096).unwrap();
        assert!(matches!(
            layout.at(0x1001, 0, u64::MAX),
            Err(BootstrapMemoryError::Alignment)
        ));
        assert!(matches!(
            layout.at(0x1000, u64::MAX & !4095, u64::MAX),
            Err(BootstrapMemoryError::AddressOverflow)
        ));
        assert!(matches!(
            layout.at(u64::MAX & !4095, 0, u64::MAX),
            Err(BootstrapMemoryError::AddressOverflow)
        ));
        assert!(matches!(
            layout.at(0x1000, 0, 0x2000),
            Err(BootstrapMemoryError::OutsideMapping)
        ));
    }
}
