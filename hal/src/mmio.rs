//! Architecture primitives for explicitly authorized device-memory access.
//!
//! Mappings retain their resource owner. Borrowed regions and registers cannot
//! survive that owner, and register derivation validates width, bounds, and
//! alignment before any volatile access.

use alloc::sync::Arc;
use core::fmt;
use core::marker::PhantomData;
use core::num::NonZeroUsize;

mod sealed {
    pub trait MmioValue {}
    pub trait Access {}
}

/// A primitive value whose complete bit domain is valid for MMIO access.
pub trait MmioValue: sealed::MmioValue + Copy {
    /// Required alignment of the hardware access.
    const ALIGN: usize;
    /// Width of the hardware access in bytes.
    const WIDTH: usize;
}

macro_rules! impl_mmio_value {
    ($value:ty) => {
        impl sealed::MmioValue for $value {}

        impl MmioValue for $value {
            const ALIGN: usize = core::mem::align_of::<Self>();
            const WIDTH: usize = core::mem::size_of::<Self>();
        }
    };
}

impl_mmio_value!(u8);
impl_mmio_value!(u16);
impl_mmio_value!(u32);
impl_mmio_value!(u64);

/// Register access is limited to reads.
#[derive(Debug)]
pub enum ReadOnly {}

/// Register access is limited to writes.
#[derive(Debug)]
pub enum WriteOnly {}

/// Register access permits both reads and writes.
#[derive(Debug)]
pub enum ReadWrite {}

impl sealed::Access for ReadOnly {}
impl sealed::Access for WriteOnly {}
impl sealed::Access for ReadWrite {}

/// Marker for register access modes that permit reads.
pub trait Readable: sealed::Access {}

/// Marker for register access modes that permit writes.
pub trait Writable: sealed::Access {}

impl Readable for ReadOnly {}
impl Readable for ReadWrite {}
impl Writable for WriteOnly {}
impl Writable for ReadWrite {}

/// Failure while establishing a mapped MMIO region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmioRegionError {
    /// Address zero cannot identify a live MMIO mapping.
    NullBase,
    /// A capability must contain at least one byte.
    Empty,
    /// The mapped span exceeds Rust's maximum object size.
    LengthTooLarge,
    /// The inclusive address range would wrap.
    AddressOverflow,
}

/// Failure while deriving a register from a mapped MMIO region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmioAccessError {
    /// `offset + width` overflowed.
    OffsetOverflow,
    /// The complete register is not contained in the mapping.
    OutOfBounds,
    /// The resulting register address is not aligned for its width.
    Misaligned,
}

/// Owns access to a mapped device register aperture.
///
/// The retained owner keeps the mapping live. Splitting attenuates the aperture
/// into disjoint subranges without creating another mapping or unmap authority.
pub struct MappedMmio {
    base: usize,
    length: NonZeroUsize,
    owner: Arc<dyn Send + Sync>,
}

impl fmt::Debug for MappedMmio {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MappedMmio")
            .field("base", &format_args!("{:#x}", self.base))
            .field("length", &self.length)
            .finish()
    }
}

impl MappedMmio {
    /// Establishes a capability for an externally managed MMIO mapping.
    ///
    /// Runtime-checkable range invariants are validated by this constructor.
    ///
    /// # Safety
    ///
    /// `owner` must retain the mapping of `base..base + length` until its last
    /// strong reference is dropped. It must not expose a safe unmap, remap, or
    /// revocation path while that reference exists. The aperture must be device
    /// memory, not ordinary Rust objects. All naturally aligned integer widths
    /// exposed by this capability must be permitted by the bus mapping. The
    /// device protocol must prevent register side effects from violating Rust
    /// memory safety; DMA publication remains a separate protocol obligation.
    /// Cache attributes and hardware ordering must match the platform contract.
    ///
    /// # Errors
    ///
    /// Returns an error for a null base, empty or oversized mapping, or an
    /// address range that would overflow.
    #[expect(
        unsafe_code,
        reason = "mapping lifetime and device validity are external authority"
    )]
    pub unsafe fn from_raw_parts(
        owner: Arc<dyn Send + Sync>,
        base: usize,
        length: usize,
    ) -> Result<Self, MmioRegionError> {
        let length = validate_mapping_span(base, length)?;
        Ok(Self {
            base,
            length,
            owner,
        })
    }

    /// Returns the size of the authorized mapping in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.length.get()
    }

    /// Returns whether the mapping contains no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Borrows the aperture; all derived registers retain this borrow.
    #[must_use]
    pub fn region(&self) -> MmioRegion<'_> {
        MmioRegion { mapping: self }
    }

    /// Consumes an aperture and retains only the requested subrange.
    ///
    /// # Errors
    /// Rejects empty, overflowing, or out-of-bounds ranges without I/O.
    pub fn into_subregion(self, offset: usize, length: usize) -> Result<Self, MmioAccessError> {
        let length = NonZeroUsize::new(length).ok_or(MmioAccessError::OutOfBounds)?;
        let end = offset
            .checked_add(length.get())
            .ok_or(MmioAccessError::OffsetOverflow)?;
        if end > self.length.get() {
            return Err(MmioAccessError::OutOfBounds);
        }
        Ok(Self {
            base: self.base + offset,
            length,
            owner: self.owner,
        })
    }

    /// Divides authority into two disjoint, independently owned apertures.
    ///
    /// # Errors
    /// Rejects a split that would leave either aperture empty.
    pub fn split_at(self, offset: usize) -> Result<(Self, Self), MmioAccessError> {
        if offset == 0 || offset >= self.length.get() {
            return Err(MmioAccessError::OutOfBounds);
        }
        let left_length = NonZeroUsize::new(offset).ok_or(MmioAccessError::OutOfBounds)?;
        let right_length =
            NonZeroUsize::new(self.length.get() - offset).ok_or(MmioAccessError::OutOfBounds)?;
        let left = Self {
            base: self.base,
            length: left_length,
            owner: Arc::clone(&self.owner),
        };
        let right = Self {
            base: self.base + offset,
            length: right_length,
            owner: self.owner,
        };
        Ok((left, right))
    }
}

/// A register aperture borrowed from its live mapping owner.
#[derive(Debug)]
pub struct MmioRegion<'mapping> {
    mapping: &'mapping MappedMmio,
}

impl<'mapping> MmioRegion<'mapping> {
    /// Derives a read-only register at `offset`.
    ///
    /// # Errors
    ///
    /// Returns an error when the register would overflow, exceed the mapping,
    /// or violate the primitive's alignment.
    pub fn read_only<T: MmioValue>(
        &self,
        offset: usize,
    ) -> Result<MmioRegister<'mapping, T, ReadOnly>, MmioAccessError> {
        self.register(offset)
    }

    /// Derives a write-only register at `offset`.
    ///
    /// # Errors
    ///
    /// Returns an error when the register would overflow, exceed the mapping,
    /// or violate the primitive's alignment.
    pub fn write_only<T: MmioValue>(
        &self,
        offset: usize,
    ) -> Result<MmioRegister<'mapping, T, WriteOnly>, MmioAccessError> {
        self.register(offset)
    }

    /// Derives a read-write register at `offset`.
    ///
    /// # Errors
    ///
    /// Returns an error when the register would overflow, exceed the mapping,
    /// or violate the primitive's alignment.
    pub fn read_write<T: MmioValue>(
        &self,
        offset: usize,
    ) -> Result<MmioRegister<'mapping, T, ReadWrite>, MmioAccessError> {
        self.register(offset)
    }

    fn register<T: MmioValue, Access: sealed::Access>(
        &self,
        offset: usize,
    ) -> Result<MmioRegister<'mapping, T, Access>, MmioAccessError> {
        let address = checked_register_address::<T>(self.mapping.base, self.mapping.len(), offset)?;
        Ok(MmioRegister {
            address,
            mapping: self.mapping,
            value: PhantomData,
            access: PhantomData,
        })
    }
}

/// Pure geometry check; it deliberately does not claim mapping validity.
fn validate_mapping_span(base: usize, length: usize) -> Result<NonZeroUsize, MmioRegionError> {
    if base == 0 {
        return Err(MmioRegionError::NullBase);
    }
    let length = NonZeroUsize::new(length).ok_or(MmioRegionError::Empty)?;
    if length.get() > isize::MAX as usize {
        return Err(MmioRegionError::LengthTooLarge);
    }
    base.checked_add(length.get() - 1)
        .ok_or(MmioRegionError::AddressOverflow)?;
    Ok(length)
}

fn checked_register_address<T: MmioValue>(
    base: usize,
    length: usize,
    offset: usize,
) -> Result<usize, MmioAccessError> {
    let end = offset
        .checked_add(T::WIDTH)
        .ok_or(MmioAccessError::OffsetOverflow)?;
    if end > length {
        return Err(MmioAccessError::OutOfBounds);
    }
    let address = base
        .checked_add(offset)
        .ok_or(MmioAccessError::OffsetOverflow)?;
    if !address.is_multiple_of(T::ALIGN) {
        return Err(MmioAccessError::Misaligned);
    }
    Ok(address)
}

/// A width- and access-checked register borrowed from an MMIO mapping.
pub struct MmioRegister<'region, T: MmioValue, Access: sealed::Access> {
    address: usize,
    mapping: &'region MappedMmio,
    value: PhantomData<T>,
    access: PhantomData<Access>,
}

macro_rules! register_access {
    ($value:ty) => {
        impl<Access: Readable> MmioRegister<'_, $value, Access> {
            /// Performs one volatile register read; this is not a memory barrier.
            #[must_use]
            #[expect(
                unsafe_code,
                reason = "volatile access is confined to a checked live mapping"
            )]
            pub fn read(&self) -> $value {
                let _owner = self.mapping;
                let pointer = core::ptr::without_provenance::<$value>(self.address);
                // SAFETY: derivation checked bounds/alignment; the borrowed
                // mapping retains the owner and integer bit patterns are valid.
                unsafe { core::ptr::read_volatile(pointer) }
            }
        }
        impl<Access: Writable> MmioRegister<'_, $value, Access> {
            /// Performs one volatile register write; this is not a memory barrier.
            #[expect(
                unsafe_code,
                reason = "volatile access is confined to a checked live mapping"
            )]
            pub fn write(&mut self, value: $value) {
                let _owner = self.mapping;
                let pointer = core::ptr::without_provenance_mut::<$value>(self.address);
                // SAFETY: derivation checked bounds/alignment; the borrowed
                // mapping retains the register aperture for this access.
                unsafe { core::ptr::write_volatile(pointer, value) }
            }
        }
    };
}

register_access!(u8);
register_access!(u16);
register_access!(u32);
register_access!(u64);

/// Orders preceding stores, including write-combining stores, before later
/// stores. This does not order subsequent loads or prove device completion.
#[inline]
#[expect(
    unsafe_code,
    reason = "x86-64 store ordering requires a hardware instruction even in soft-float builds"
)]
pub fn sfence() {
    // SAFETY: SFENCE is available on every supported x86-64 CPU and touches no
    // pointer or SIMD register state. Omitting `nomem` also orders the compiler.
    unsafe {
        core::arch::asm!("sfence", options(nostack, preserves_flags));
    }
}

static SIMD_LEVEL: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// SIMD support level
pub mod simd_level {
    pub const NONE: u8 = 0;
    pub const SSE2: u8 = 0; // Baseline for x86_64
    pub const AVX: u8 = 1;
    pub const SSSE3: u8 = 2;
    pub const AVX2: u8 = 3; // For future use
}

/// Set the supported SIMD level for optimized MMIO operations.
///
/// # Safety
/// Caller must ensure the CPU supports the specified level.
/// - level >= 1 requires AVX support
#[expect(
    unsafe_code,
    reason = "CPU and enabled extended-state support must be established by boot code"
)]
pub unsafe fn set_simd_level(level: u8) {
    SIMD_LEVEL.store(level, core::sync::atomic::Ordering::Relaxed);
}

/// Get the current SIMD support level.
#[inline]
#[must_use]
pub fn get_simd_level() -> u8 {
    SIMD_LEVEL.load(core::sync::atomic::Ordering::Relaxed)
}

/// Check if debug printing is allowed during benchmarks.
/// Use this instead of direct env var checks to allow use in `no_std` context.
/// Returns true if `std` feature is enabled AND `RANY_DEBUG_DRAW` == "1".
#[inline]
#[must_use]
pub fn bench_debug_print_allowed() -> bool {
    #[cfg(feature = "std")]
    {
        std::env::var("RANY_DEBUG_DRAW").ok().as_deref() == Some("1")
    }
    #[cfg(not(feature = "std"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_geometry_rejects_empty_overflow_and_oversize() {
        assert_eq!(validate_mapping_span(0, 8), Err(MmioRegionError::NullBase));
        assert_eq!(validate_mapping_span(8, 0), Err(MmioRegionError::Empty));
        assert_eq!(
            validate_mapping_span(8, usize::MAX),
            Err(MmioRegionError::LengthTooLarge)
        );
        assert_eq!(
            validate_mapping_span(usize::MAX, 2),
            Err(MmioRegionError::AddressOverflow)
        );
        assert_eq!(
            validate_mapping_span(usize::MAX, 1).map(NonZeroUsize::get),
            Ok(1)
        );
    }

    #[test]
    fn registers_require_their_full_width_inside_the_aperture() {
        assert_eq!(checked_register_address::<u8>(0x1000, 8, 7), Ok(0x1007));
        assert_eq!(checked_register_address::<u16>(0x1000, 8, 6), Ok(0x1006));
        assert_eq!(checked_register_address::<u32>(0x1000, 8, 4), Ok(0x1004));
        assert_eq!(checked_register_address::<u64>(0x1000, 8, 0), Ok(0x1000));
        assert_eq!(
            checked_register_address::<u64>(0x1000, 8, 1),
            Err(MmioAccessError::OutOfBounds)
        );
        assert_eq!(
            checked_register_address::<u8>(0x1000, 8, 8),
            Err(MmioAccessError::OutOfBounds)
        );
    }

    #[test]
    fn register_alignment_is_relative_to_the_final_address() {
        assert_eq!(
            checked_register_address::<u32>(0x1001, 8, 0),
            Err(MmioAccessError::Misaligned)
        );
        assert_eq!(checked_register_address::<u32>(0x1001, 8, 3), Ok(0x1004));
        assert_eq!(
            checked_register_address::<u64>(0x1000, 16, 4),
            Err(MmioAccessError::Misaligned)
        );
    }

    #[test]
    fn register_derivation_checks_offset_and_address_overflow() {
        assert_eq!(
            checked_register_address::<u32>(0x1000, 8, usize::MAX),
            Err(MmioAccessError::OffsetOverflow)
        );
        assert_eq!(
            checked_register_address::<u8>(usize::MAX, 2, 1),
            Err(MmioAccessError::OffsetOverflow)
        );
    }
}
