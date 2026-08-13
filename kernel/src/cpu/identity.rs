use alloc::sync::Arc;
use core::fmt;

pub const MAX_POSSIBLE_CPUS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuIdOutOfRange {
    pub value: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CpuId(u16);

impl CpuId {
    pub const BOOTSTRAP: Self = Self(0);

    pub const fn new(value: u16) -> Result<Self, CpuIdOutOfRange> {
        if value < MAX_POSSIBLE_CPUS as u16 {
            Ok(Self(value))
        } else {
            Err(CpuIdOutOfRange {
                value: value as usize,
            })
        }
    }

    pub const fn as_u16(self) -> u16 {
        self.0
    }

    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }

    pub(crate) const fn from_valid_index(value: usize) -> Self {
        debug_assert!(value < MAX_POSSIBLE_CPUS);
        Self(value as u16)
    }
}

impl fmt::Debug for CpuId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "CpuId({})", self.0)
    }
}

impl fmt::Display for CpuId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl TryFrom<usize> for CpuId {
    type Error = CpuIdOutOfRange;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value < MAX_POSSIBLE_CPUS {
            Ok(Self(value as u16))
        } else {
            Err(CpuIdOutOfRange { value })
        }
    }
}

impl From<CpuId> for usize {
    fn from(value: CpuId) -> Self {
        value.as_usize()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApicId(u32);

impl ApicId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Debug for ApicId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ApicId({:#x})", self.0)
    }
}

impl fmt::Display for ApicId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuRole {
    Bootstrap,
    Application,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FirmwareCpuUid {
    Integer(u64),
    String(Arc<str>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_id_accepts_255_and_rejects_256() {
        assert_eq!(CpuId::try_from(255usize).map(CpuId::as_u16), Ok(255));
        assert_eq!(
            CpuId::try_from(256usize),
            Err(CpuIdOutOfRange { value: 256 })
        );
    }

    #[test]
    fn apic_id_keeps_x2apic_destination_bits() {
        let id = ApicId::new(0xfedc_ba98);
        assert_eq!(id.as_u32(), 0xfedc_ba98);
    }
}
