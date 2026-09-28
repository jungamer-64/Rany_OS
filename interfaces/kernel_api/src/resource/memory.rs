//! Host-memory coordinate types, independent of any device address space.

#![forbid(unsafe_code)]

/// An observed host physical address, not allocation, DMA, or MMIO authority.
///
/// Construction does not prove the address is representable by this platform or
/// mapped by the CPU. Resource boundaries establish those independent facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PhysicalAddress(u64);

impl PhysicalAddress {
    /// Records a physical coordinate supplied by a platform/resource boundary.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Encodes the host physical coordinate, not a virtual or IOMMU address.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Offsets within the host physical domain; overflow is never saturation.
    #[must_use]
    pub const fn checked_offset_bytes(self, bytes: u64) -> Option<Self> {
        match self.0.checked_add(bytes) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_offset_preserves_zero_and_boundary_failure() {
        let first = PhysicalAddress::new(0);
        assert_eq!(first.checked_offset_bytes(0), Some(first));
        assert_eq!(
            first.checked_offset_bytes(u64::MAX),
            Some(PhysicalAddress::new(u64::MAX))
        );
        assert_eq!(PhysicalAddress::new(u64::MAX).checked_offset_bytes(1), None);
        assert_eq!(
            PhysicalAddress::new(u64::MAX - 3).checked_offset_bytes(4),
            None
        );
    }
}
