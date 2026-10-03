//! Device-scoped MMIO acquisition geometry.
//!
//! These values describe requests and validated PCI enumeration snapshots, not
//! access capabilities. A mapping boundary must separately authorize the caller,
//! reserve the resource against RAM allocation and PCI reconfiguration, establish
//! cache attributes, and retain the installed mapping before granting access.
//! Neither a PCI locator nor a resolved physical span permits dereferencing it.

#![forbid(unsafe_code)]

use core::marker::PhantomData;
use core::num::NonZeroUsize;

use crate::abi::driver::PackedPciLocation;
use crate::resource::memory::PhysicalAddress;
use crate::service::platform::{Bar, PciDeviceInfo};

/// Failure to describe or resolve a PCI register aperture; no mapping was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum MmioRequestError {
    /// The locator is null or has bits outside the supported segment/BDF domain.
    InvalidDevice,
    /// A BAR index is outside the function's configuration header.
    InvalidBar,
    /// Empty register authority is not an acquisition request.
    Empty,
    /// The requested span exceeds Rust's maximum object size.
    LengthTooLarge,
    /// The BAR-relative exclusive end cannot be represented.
    OffsetOverflow,
    /// The enumeration snapshot belongs to another function.
    DeviceMismatch,
    /// This configuration header has no supported BAR layout.
    UnsupportedHeader,
    /// The selected BAR is absent or has no assigned base/extent.
    UnassignedBar,
    /// The selected resource is port I/O, not memory.
    IoBar,
    /// The index denotes the upper word of a 64-bit BAR, not another resource.
    UpperBarWord,
    /// A 64-bit resource does not have room for both configuration words.
    IncompleteBarPair,
    /// The physical span wraps or escapes the BAR's address width.
    PhysicalOverflow,
    /// The requested bytes are not all contained in the assigned resource.
    OutOfBounds,
}

/// Acquisition failures distinguish intent validation, authorization, resource
/// admission, and installation. Failure grants no access to the aperture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmioAcquireError {
    Request(MmioRequestError),
    PermissionDenied,
    ResourceBusy,
    ResourceExhausted,
    PhysicalMemoryConflict,
    CachePolicy,
    MappingFailed,
    OutOfMemory,
    Unavailable,
}

impl MmioAcquireError {
    /// Stable status encoding used by the device-resource ABI.
    pub const fn into_abi(self) -> i32 {
        match self {
            Self::Request(error) => -256 - error as i32,
            Self::PermissionDenied => -1,
            Self::ResourceBusy => -2,
            Self::ResourceExhausted => -3,
            Self::PhysicalMemoryConflict => -4,
            Self::CachePolicy => -5,
            Self::MappingFailed => -6,
            Self::OutOfMemory => -7,
            Self::Unavailable => -8,
        }
    }

    /// Decodes a failing ABI status. An unknown status grants no authority.
    pub const fn from_abi(status: i32) -> Self {
        match status {
            -1 => Self::PermissionDenied,
            -2 => Self::ResourceBusy,
            -3 => Self::ResourceExhausted,
            -4 => Self::PhysicalMemoryConflict,
            -5 => Self::CachePolicy,
            -7 => Self::OutOfMemory,
            -8 => Self::Unavailable,
            -256 => Self::Request(MmioRequestError::InvalidDevice),
            -257 => Self::Request(MmioRequestError::InvalidBar),
            -258 => Self::Request(MmioRequestError::Empty),
            -259 => Self::Request(MmioRequestError::LengthTooLarge),
            -260 => Self::Request(MmioRequestError::OffsetOverflow),
            -261 => Self::Request(MmioRequestError::DeviceMismatch),
            -262 => Self::Request(MmioRequestError::UnsupportedHeader),
            -263 => Self::Request(MmioRequestError::UnassignedBar),
            -264 => Self::Request(MmioRequestError::IoBar),
            -265 => Self::Request(MmioRequestError::UpperBarWord),
            -266 => Self::Request(MmioRequestError::IncompleteBarPair),
            -267 => Self::Request(MmioRequestError::PhysicalOverflow),
            -268 => Self::Request(MmioRequestError::OutOfBounds),
            _ => Self::MappingFailed,
        }
    }
}

/// Non-empty, checked BAR-relative byte range. Offsets are not physical addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioByteRange {
    offset: usize,
    length: NonZeroUsize,
}

impl MmioByteRange {
    /// Checks a range without acquiring hardware or mapping authority.
    ///
    /// # Errors
    /// Rejects empty/oversized lengths and an overflowing exclusive end.
    pub fn new(offset: usize, length: usize) -> Result<Self, MmioRequestError> {
        let length = NonZeroUsize::new(length).ok_or(MmioRequestError::Empty)?;
        if length.get() > isize::MAX as usize {
            return Err(MmioRequestError::LengthTooLarge);
        }
        offset
            .checked_add(length.get())
            .ok_or(MmioRequestError::OffsetOverflow)?;
        Ok(Self { offset, length })
    }

    /// Byte offset from the beginning of the BAR.
    #[must_use]
    pub const fn offset(self) -> usize {
        self.offset
    }

    /// Requested byte count, not a page count or an absolute end address.
    #[must_use]
    pub const fn byte_count(self) -> usize {
        self.length.get()
    }

    /// Exclusive BAR-relative end; the constructor established no overflow.
    #[must_use]
    pub const fn end(self) -> usize {
        self.offset + self.length.get()
    }
}

/// A function/BAR-scoped request. Copying it duplicates intent, not authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciMmioRequest {
    device: PackedPciLocation,
    bar_index: u8,
    aperture: MmioAperture,
}

/// Whole BAR acquisition is for a device register-layout owner; a byte window
/// attenuates authority when one queue or protocol needs only part of the BAR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmioAperture {
    WholeBar,
    Bytes(MmioByteRange),
}

impl PciMmioRequest {
    /// Accepts a specific PCI function and BAR, never a caller-supplied address.
    ///
    /// # Errors
    /// Rejects null/noncanonical segment/BDF locators and indices beyond BAR5.
    /// BAR presence, header layout, extent, and caller authorization are separate
    /// checks; success here does not establish them.
    pub fn new(
        device: PackedPciLocation,
        bar_index: u8,
        range: MmioByteRange,
    ) -> Result<Self, MmioRequestError> {
        Self::with_aperture(device, bar_index, MmioAperture::Bytes(range))
    }

    /// Requests the function's complete BAR without supplying an address or
    /// guessing its size. The owner resolves and pins the resource at acquisition.
    ///
    /// # Errors
    /// Rejects a null/noncanonical function identity or a BAR slot beyond BAR5.
    pub fn whole_bar(device: PackedPciLocation, bar_index: u8) -> Result<Self, MmioRequestError> {
        Self::with_aperture(device, bar_index, MmioAperture::WholeBar)
    }

    fn with_aperture(
        device: PackedPciLocation,
        bar_index: u8,
        aperture: MmioAperture,
    ) -> Result<Self, MmioRequestError> {
        const LOCATOR_MASK: u64 = (0xffff << 32) | (0xff << 16) | (0x1f << 8) | 7;
        if device.is_null() || device.raw() & !LOCATOR_MASK != 0 {
            return Err(MmioRequestError::InvalidDevice);
        }
        if bar_index >= 6 {
            return Err(MmioRequestError::InvalidBar);
        }
        Ok(Self {
            device,
            bar_index,
            aperture,
        })
    }

    /// Requested function, including its segment identity.
    #[must_use]
    pub const fn device(self) -> PackedPciLocation {
        self.device
    }

    /// Configuration-space BAR slot, not a physical address.
    #[must_use]
    pub const fn bar_index(self) -> u8 {
        self.bar_index
    }

    /// Checked BAR-relative range.
    #[must_use]
    pub const fn aperture(self) -> MmioAperture {
        self.aperture
    }

    /// Resolves geometry against an immutable enumeration snapshot.
    ///
    /// The borrow keeps the checked snapshot from changing through Rust while
    /// this geometry exists. It does not pin hardware configuration: the resource
    /// owner must prevent BAR writes, reset, hot removal, and conflicting grants
    /// through mapping acquisition and until the last access capability retires.
    /// Prefetchability is a hardware property, not a choice of CPU cache policy.
    ///
    /// # Errors
    /// Rejects another function, unsupported headers, absent/I/O BARs, upper
    /// configuration words, incomplete 64-bit pairs, physical overflow, and
    /// requests extending past the complete resource. Failure has no side effect.
    pub fn resolve(
        self,
        snapshot: &PciDeviceInfo,
    ) -> Result<PciMmioGeometry<'_>, MmioRequestError> {
        if snapshot.packed_locator() != self.device {
            return Err(MmioRequestError::DeviceMismatch);
        }
        let slots = match snapshot.header_type_value() {
            0 => 6,
            1 => 2,
            _ => return Err(MmioRequestError::UnsupportedHeader),
        };
        let index = usize::from(self.bar_index);
        if index >= slots {
            return Err(MmioRequestError::InvalidBar);
        }

        // Walk BAR words rather than treating all six snapshot slots as
        // independent resources. A 64-bit low word consumes the next slot.
        let mut cursor = 0;
        // LOOP_PROOF: mode=condition; reason=Cursor advances by one or two BAR words and is bounded by the requested index below six.;
        while cursor < index {
            if matches!(snapshot.bars[cursor], Some(Bar::Memory64 { .. })) {
                if cursor + 1 == index {
                    return Err(MmioRequestError::UpperBarWord);
                }
                cursor += 2;
            } else {
                cursor += 1;
            }
        }

        let bar = snapshot.bars[index]
            .as_ref()
            .ok_or(MmioRequestError::UnassignedBar)?;
        let (base, size, address_limit) = match *bar {
            Bar::Memory32 { base, size, .. } => (base, size, Some(1u64 << 32)),
            Bar::Memory64 { base, size, .. } => {
                if index + 1 >= slots {
                    return Err(MmioRequestError::IncompleteBarPair);
                }
                (base, size, None)
            }
            Bar::Io { .. } => return Err(MmioRequestError::IoBar),
        };
        if base == 0 || size == 0 {
            return Err(MmioRequestError::UnassignedBar);
        }
        let resource_end = base
            .checked_add(size)
            .ok_or(MmioRequestError::PhysicalOverflow)?;
        if address_limit.is_some_and(|limit| resource_end > limit) {
            return Err(MmioRequestError::PhysicalOverflow);
        }
        let range = match self.aperture {
            MmioAperture::WholeBar => MmioByteRange::new(
                0,
                usize::try_from(size).map_err(|_| MmioRequestError::LengthTooLarge)?,
            )?,
            MmioAperture::Bytes(range) => range,
        };
        let end = u64::try_from(range.end()).map_err(|_| MmioRequestError::OffsetOverflow)?;
        if end > size {
            return Err(MmioRequestError::OutOfBounds);
        }
        let offset = u64::try_from(range.offset()).map_err(|_| MmioRequestError::OffsetOverflow)?;
        let physical_start = PhysicalAddress::new(base)
            .checked_offset_bytes(offset)
            .ok_or(MmioRequestError::PhysicalOverflow)?;
        Ok(PciMmioGeometry {
            request: self,
            snapshot: PhantomData,
            physical_start,
            range,
        })
    }
}

/// Checked geometry tied to its immutable source, deliberately not MMIO authority.
#[derive(Debug)]
pub struct PciMmioGeometry<'snapshot> {
    request: PciMmioRequest,
    // Preserve the immutable source borrow without exposing PciDeviceInfo's
    // ambient configuration-service methods through this narrow geometry value.
    snapshot: PhantomData<&'snapshot PciDeviceInfo>,
    physical_start: PhysicalAddress,
    range: MmioByteRange,
}

impl PciMmioGeometry<'_> {
    /// Request resolved by this snapshot; no address-to-request conversion exists.
    #[must_use]
    pub const fn request(&self) -> PciMmioRequest {
        self.request
    }

    /// Start in the host physical domain, never a device/IOMMU or virtual address.
    #[must_use]
    pub const fn physical_start(&self) -> PhysicalAddress {
        self.physical_start
    }

    /// Resolved BAR-relative byte range, including a resolved whole-BAR request.
    pub const fn range(&self) -> MmioByteRange {
        self.range
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::platform::{BdfAddress, ClassCode, DeviceId, VendorId};
    use alloc::vec::Vec;

    fn device(bars: [Option<Bar>; 6]) -> PciDeviceInfo {
        PciDeviceInfo {
            segment: 2,
            bdf: BdfAddress::new(3, 4, 5),
            vendor_id: VendorId(0x15b3),
            device_id: DeviceId(0x1017),
            revision_id: 0,
            class_code: ClassCode::new(2, 0, 0),
            header_type: 0,
            subsystem_vendor_id: 0,
            subsystem_id: 0,
            interrupt_line: 0,
            interrupt_pin: 0,
            bars,
            capabilities: Vec::new(),
            msi_cap_offset: None,
            msix_cap_offset: None,
            pcie_cap_offset: None,
            iommu_domain_id: None,
        }
    }

    fn memory32(base: u64, size: u64) -> Option<Bar> {
        Some(Bar::Memory32 {
            base,
            size,
            prefetchable: false,
        })
    }

    fn request(
        device: &PciDeviceInfo,
        bar: u8,
        offset: usize,
        length: usize,
    ) -> Result<PciMmioRequest, MmioRequestError> {
        PciMmioRequest::new(
            device.packed_locator(),
            bar,
            MmioByteRange::new(offset, length)?,
        )
    }

    #[test]
    fn range_errors_preserve_units_and_overflow() {
        assert_eq!(MmioByteRange::new(0, 0), Err(MmioRequestError::Empty));
        assert_eq!(
            MmioByteRange::new(0, usize::MAX),
            Err(MmioRequestError::LengthTooLarge)
        );
        assert_eq!(
            MmioByteRange::new(usize::MAX, 1),
            Err(MmioRequestError::OffsetOverflow)
        );
        assert_eq!(
            MmioByteRange::new(usize::MAX - 3, 4),
            Err(MmioRequestError::OffsetOverflow)
        );
    }

    #[test]
    fn locator_and_slot_validation_is_not_authorization() -> Result<(), MmioRequestError> {
        let range = MmioByteRange::new(0, 1)?;
        for raw in [0, 1 << 24, 1 << 48, 32 << 8, 8] {
            assert_eq!(
                PciMmioRequest::new(PackedPciLocation::from_raw(raw), 0, range),
                Err(MmioRequestError::InvalidDevice)
            );
        }
        let locator = PackedPciLocation::new(u16::MAX, u8::MAX, 31, 7);
        let valid = PciMmioRequest::new(locator, 5, range)?;
        assert_eq!(valid.device(), locator);
        assert_eq!(valid.bar_index(), 5);
        assert_eq!(
            PciMmioRequest::new(locator, 6, range),
            Err(MmioRequestError::InvalidBar)
        );
        Ok(())
    }

    #[test]
    fn exact_byte_window_does_not_round_up_access_authority() -> Result<(), MmioRequestError> {
        let info = device([memory32(0x8000_0000, 4096), None, None, None, None, None]);
        let req = request(&info, 0, 3, 4093)?;
        let geometry = req.resolve(&info)?;
        assert_eq!(geometry.physical_start(), PhysicalAddress::new(0x8000_0003));
        assert_eq!(geometry.range().byte_count(), 4093);
        assert_eq!(geometry.range().end(), 4096);
        assert_eq!(
            request(&info, 0, 4095, 2)?.resolve(&info).err(),
            Some(MmioRequestError::OutOfBounds)
        );
        Ok(())
    }

    #[test]
    fn identity_includes_segment_and_bdf() -> Result<(), MmioRequestError> {
        let info = device([memory32(0x8000_0000, 4096), None, None, None, None, None]);
        let req = request(&info, 0, 0, 1)?;
        let mut another = info.clone();
        another.segment += 1;
        assert_eq!(
            req.resolve(&another).err(),
            Some(MmioRequestError::DeviceMismatch)
        );
        another.segment = info.segment;
        another.bdf = BdfAddress::new(3, 4, 6);
        assert_eq!(
            req.resolve(&another).err(),
            Some(MmioRequestError::DeviceMismatch)
        );
        Ok(())
    }

    #[test]
    fn resource_class_and_absence_are_distinct() -> Result<(), MmioRequestError> {
        let mut info = device([None; 6]);
        let req = request(&info, 0, 0, 1)?;
        assert_eq!(
            req.resolve(&info).err(),
            Some(MmioRequestError::UnassignedBar)
        );
        info.bars[0] = Some(Bar::Io {
            base: 0x300,
            size: 16,
        });
        assert_eq!(req.resolve(&info).err(), Some(MmioRequestError::IoBar));
        for (base, size) in [(0, 4096), (0x8000_0000, 0)] {
            info.bars[0] = memory32(base, size);
            assert_eq!(
                req.resolve(&info).err(),
                Some(MmioRequestError::UnassignedBar)
            );
        }
        Ok(())
    }

    #[test]
    fn address_width_and_wrapping_are_checked() -> Result<(), MmioRequestError> {
        let mut info = device([memory32(0xffff_f000, 4096), None, None, None, None, None]);
        let req = request(&info, 0, 0, 4096)?;
        assert_eq!(
            req.resolve(&info)?.physical_start(),
            PhysicalAddress::new(0xffff_f000)
        );
        info.bars[0] = memory32(0xffff_f000, 8192);
        assert_eq!(
            req.resolve(&info).err(),
            Some(MmioRequestError::PhysicalOverflow)
        );
        info.bars[0] = Some(Bar::Memory64 {
            base: u64::MAX - 4095,
            size: 4096,
            prefetchable: true,
        });
        assert_eq!(
            req.resolve(&info).err(),
            Some(MmioRequestError::PhysicalOverflow)
        );
        info.bars[0] = Some(Bar::Memory64 {
            base: 0x1_0000_0000,
            size: 8192,
            prefetchable: true,
        });
        assert_eq!(
            req.resolve(&info)?.physical_start(),
            PhysicalAddress::new(0x1_0000_0000)
        );
        Ok(())
    }

    #[test]
    fn upper_configuration_words_are_never_independent_resources() -> Result<(), MmioRequestError> {
        let mut info = device([None; 6]);
        info.bars[0] = Some(Bar::Memory64 {
            base: 0x1_0000_0000,
            size: 4096,
            prefetchable: false,
        });
        // Even an inconsistent snapshot cannot turn the high word into authority.
        info.bars[1] = memory32(0x9000_0000, 4096);
        assert_eq!(
            request(&info, 1, 0, 1)?.resolve(&info).err(),
            Some(MmioRequestError::UpperBarWord)
        );
        info.bars[2] = memory32(0xa000_0000, 4096);
        assert_eq!(
            request(&info, 2, 0, 1)?.resolve(&info)?.physical_start(),
            PhysicalAddress::new(0xa000_0000)
        );
        info.bars[5] = info.bars[0];
        assert_eq!(
            request(&info, 5, 0, 1)?.resolve(&info).err(),
            Some(MmioRequestError::IncompleteBarPair)
        );
        Ok(())
    }

    #[test]
    fn header_geometry_and_multifunction_bit_are_checked() -> Result<(), MmioRequestError> {
        let mut info = device([memory32(0x8000_0000, 4096); 6]);
        info.header_type = 0x80;
        assert!(request(&info, 5, 0, 1)?.resolve(&info).is_ok());
        info.header_type = 0x81;
        assert!(request(&info, 1, 0, 1)?.resolve(&info).is_ok());
        assert_eq!(
            request(&info, 2, 0, 1)?.resolve(&info).err(),
            Some(MmioRequestError::InvalidBar)
        );
        info.bars[1] = Some(Bar::Memory64 {
            base: 0x1_0000_0000,
            size: 4096,
            prefetchable: false,
        });
        assert_eq!(
            request(&info, 1, 0, 1)?.resolve(&info).err(),
            Some(MmioRequestError::IncompleteBarPair)
        );
        info.header_type = 2;
        assert_eq!(
            request(&info, 0, 0, 1)?.resolve(&info).err(),
            Some(MmioRequestError::UnsupportedHeader)
        );
        Ok(())
    }
}
