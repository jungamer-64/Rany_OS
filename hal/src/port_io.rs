//! Architecture primitives for explicitly authorized x86 port I/O.
//!
//! A port is borrowed from its allocated range; constructing a range is the
//! platform resource boundary and never an implicit effect of a register read.

use core::marker::PhantomData;
use core::num::NonZeroU16;
use x86_64::instructions::port::Port as XPort;

mod sealed {
    pub trait PortValue {}
}

/// Primitive value supported by x86 port-I/O instructions.
pub trait PortValue: sealed::PortValue + Copy {}

impl sealed::PortValue for u8 {}
impl sealed::PortValue for u16 {}
impl sealed::PortValue for u32 {}
impl PortValue for u8 {}
impl PortValue for u16 {}
impl PortValue for u32 {}

/// Failure while establishing or attenuating port-I/O authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoPortError {
    /// A range must contain at least one port number.
    Empty,
    /// The inclusive port-number range would overflow `u16`.
    RangeOverflow,
    /// The requested offset is not within the authorized range.
    OutOfRange,
}

/// Capability for a contiguous range of x86 I/O ports.
pub struct IoPortRange {
    base: u16,
    length: NonZeroU16,
}

impl IoPortRange {
    /// Establishes authority for an externally allocated port range.
    ///
    /// # Safety
    ///
    /// The caller must own the complete port range for the lifetime of this
    /// value and must prevent conflicting access or reassignment. The selected
    /// device protocol must define the permitted access widths and ordering.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty range or an inclusive range that exceeds
    /// the x86 port-number domain.
    #[expect(
        unsafe_code,
        reason = "external port allocation authority enters only here"
    )]
    pub const unsafe fn from_raw_parts(base: u16, length: u16) -> Result<Self, IoPortError> {
        let Some(length) = NonZeroU16::new(length) else {
            return Err(IoPortError::Empty);
        };
        if base.checked_add(length.get() - 1).is_none() {
            return Err(IoPortError::RangeOverflow);
        }
        Ok(Self { base, length })
    }

    /// Number of port numbers covered by this allocation.
    #[must_use]
    pub const fn len(&self) -> u16 {
        self.length.get()
    }

    /// Allocated ranges are non-empty by construction.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Establishes authority for exactly one externally allocated port.
    ///
    /// # Safety
    ///
    /// The caller must own `port` and prevent conflicting access or
    /// reassignment while this value exists.
    #[must_use]
    #[expect(
        unsafe_code,
        reason = "external single-port allocation requires caller authority"
    )]
    pub const unsafe fn single(port: u16) -> Self {
        Self {
            base: port,
            length: NonZeroU16::MIN,
        }
    }

    /// Attenuates this range to one typed port at `offset`.
    ///
    /// # Errors
    ///
    /// Returns an error when the complete access lies outside the range.
    pub fn port<T: PortValue>(&self, offset: u16) -> Result<IoPort<'_, T>, IoPortError> {
        let port = checked_port_address::<T>(self.base, self.length.get(), offset)?;
        Ok(IoPort {
            port,
            authority: PhantomData,
            value: PhantomData,
        })
    }

    /// Attenuates a single-port range to its typed port.
    ///
    /// # Errors
    ///
    /// Returns an error when this range is narrower than the requested access.
    pub fn first<T: PortValue>(&self) -> Result<IoPort<'_, T>, IoPortError> {
        self.port(0)
    }
}

/// A typed port borrowed from an authorized port range.
pub struct IoPort<'range, T: PortValue> {
    port: u16,
    authority: PhantomData<&'range IoPortRange>,
    value: PhantomData<T>,
}

fn checked_port_address<T: PortValue>(
    base: u16,
    length: u16,
    offset: u16,
) -> Result<u16, IoPortError> {
    let end = usize::from(offset) + core::mem::size_of::<T>();
    if end > usize::from(length) {
        return Err(IoPortError::OutOfRange);
    }
    base.checked_add(offset).ok_or(IoPortError::RangeOverflow)
}

macro_rules! port_access {
    ($value:ty) => {
        impl IoPort<'_, $value> {
            /// Reads one value using the port's explicit width.
            #[expect(
                unsafe_code,
                reason = "the checked capability authorizes the x86 input instruction"
            )]
            pub fn read(&mut self) -> $value {
                // SAFETY: the borrowed allocation authorizes the whole access;
                // this concrete integer width is supported by x86 port I/O.
                unsafe { XPort::<$value>::new(self.port).read() }
            }

            /// Writes one value using the port's explicit width.
            #[expect(
                unsafe_code,
                reason = "the checked capability authorizes the x86 output instruction"
            )]
            pub fn write(&mut self, value: $value) {
                // SAFETY: the borrowed allocation authorizes the whole access;
                // this concrete integer width is supported by x86 port I/O.
                unsafe { XPort::<$value>::new(self.port).write(value) }
            }
        }
    };
}

port_access!(u8);
port_access!(u16);
port_access!(u32);

impl IoPort<'_, u16> {
    /// Reads `buffer.len()` words with `rep insw`.
    #[expect(
        unsafe_code,
        reason = "the capability and mutable slice bound the port-to-memory transfer"
    )]
    pub fn read_words(&mut self, buffer: &mut [u16]) {
        // SAFETY: the slice is live, aligned, and exclusively writable. The
        // range capability establishes authority for this port.
        unsafe {
            core::arch::asm!(
                "cld",
                "rep insw",
                in("dx") self.port,
                inout("rdi") buffer.as_mut_ptr() => _,
                inout("rcx") buffer.len() => _,
                options(nostack)
            );
        }
    }

    /// Writes `buffer.len()` words with `rep outsw`.
    #[expect(
        unsafe_code,
        reason = "the capability and slice bound the memory-to-port transfer"
    )]
    pub fn write_words(&mut self, buffer: &[u16]) {
        // SAFETY: the slice is live and readable. The range capability
        // establishes authority for this port.
        unsafe {
            core::arch::asm!(
                "cld",
                "rep outsw",
                in("dx") self.port,
                inout("rsi") buffer.as_ptr() => _,
                inout("rcx") buffer.len() => _,
                options(nostack)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_width_must_fit_the_allocated_port_numbers() {
        assert_eq!(checked_port_address::<u8>(0xcf8, 8, 7), Ok(0xcff));
        assert_eq!(checked_port_address::<u16>(0xcf8, 8, 6), Ok(0xcfe));
        assert_eq!(checked_port_address::<u32>(0xcf8, 8, 4), Ok(0xcfc));
        assert_eq!(
            checked_port_address::<u32>(0xcf8, 8, 5),
            Err(IoPortError::OutOfRange)
        );
        assert_eq!(
            checked_port_address::<u16>(0x61, 1, 0),
            Err(IoPortError::OutOfRange)
        );
        assert_eq!(
            checked_port_address::<u8>(0xffff, 2, 1),
            Err(IoPortError::RangeOverflow)
        );
    }
}
