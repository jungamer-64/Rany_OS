//! Authorized, read-only observations of a PCI function's conventional header.
//! A result grants no MMIO, configuration-write or device-lifetime authority.
#![forbid(unsafe_code)]

use crate::abi::driver::PackedPciLocation;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PciConfigReadError {
    InvalidDevice,
    PermissionDenied,
    DeviceAbsent,
    ResourceBusy,
    ResourceExhausted,
    Unavailable,
    InvalidResponse,
}

impl PciConfigReadError {
    pub const fn into_abi(self) -> i32 {
        match self {
            Self::InvalidDevice => -1,
            Self::PermissionDenied => -3,
            Self::DeviceAbsent => -4,
            Self::ResourceBusy => -5,
            Self::ResourceExhausted => -6,
            Self::Unavailable => -7,
            Self::InvalidResponse => -8,
        }
    }

    pub const fn from_abi(status: i32) -> Self {
        match status {
            -1 => Self::InvalidDevice,
            -3 => Self::PermissionDenied,
            -4 => Self::DeviceAbsent,
            -5 => Self::ResourceBusy,
            -6 => Self::ResourceExhausted,
            -7 => Self::Unavailable,
            _ => Self::InvalidResponse,
        }
    }
}

/// Device identity and an observed conventional configuration header.
/// These bytes are metadata, not register or PCI reconfiguration authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PciConfigSnapshot {
    device: PackedPciLocation,
    bytes: [u8; 256],
}

impl PciConfigSnapshot {
    /// Associate conventional header observations with their checked function.
    /// The provider owns authorization and read lifetime; capability parsers
    /// must validate the byte structure before using its geometry.
    ///
    /// # Errors
    /// Rejects a null or noncanonical segment/BDF identity.
    pub fn from_bytes(
        device: PackedPciLocation,
        bytes: [u8; 256],
    ) -> Result<Self, PciConfigReadError> {
        if device.is_null() || !device.is_canonical() {
            return Err(PciConfigReadError::InvalidDevice);
        }
        Ok(Self { device, bytes })
    }
    pub const fn device(&self) -> PackedPciLocation {
        self.device
    }
    pub const fn bytes(&self) -> &[u8; 256] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_retains_function_and_complete_header_observation() {
        let device = PackedPciLocation::new(u16::MAX, u8::MAX, 31, 7);
        let mut bytes = [0; 256];
        bytes[255] = 19;
        let snapshot = PciConfigSnapshot::from_bytes(device, bytes).expect("valid function");
        assert_eq!(snapshot.device(), device);
        assert_eq!(snapshot.bytes()[255], 19);
        for raw in [0, 1 << 24, 1 << 48, 32 << 8, 8] {
            assert_eq!(
                PciConfigSnapshot::from_bytes(PackedPciLocation::from_raw(raw), bytes),
                Err(PciConfigReadError::InvalidDevice)
            );
        }
    }
    #[test]
    fn read_failure_encoding_preserves_caller_decisions() {
        for cause in [
            PciConfigReadError::InvalidDevice,
            PciConfigReadError::PermissionDenied,
            PciConfigReadError::DeviceAbsent,
            PciConfigReadError::ResourceBusy,
            PciConfigReadError::ResourceExhausted,
            PciConfigReadError::Unavailable,
            PciConfigReadError::InvalidResponse,
        ] {
            assert_eq!(PciConfigReadError::from_abi(cause.into_abi()), cause);
        }
        assert_eq!(
            PciConfigReadError::from_abi(19),
            PciConfigReadError::InvalidResponse
        );
    }
}
