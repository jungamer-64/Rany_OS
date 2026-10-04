//! PCI capability observations become bounded register requests before mapping.
#![forbid(unsafe_code)]

use alloc::sync::Arc;
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::mmio::{MmioAcquireError, MmioByteRange, MmioRequestError, PciMmioRequest};
use kernel_api::pci_config::{PciConfigReadError, PciConfigSnapshot};

use super::{PciTransportApertures, TransportError, VirtioPciTransport};
use crate::defs::{VirtioDeviceType, VirtioPciCapType};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PciCapabilityError {
    WrongDevice,
    HeaderType,
    ListAbsent,
    InvalidPointer,
    CyclicList,
    Truncated,
    InvalidBar,
    InvalidRange(MmioRequestError),
    InvalidNotificationMultiplier,
    Missing(VirtioPciCapType),
}

/// Every failure precedes DMA/register publication. Acquired apertures retire
/// automatically; no controller or accepted command owner exists at this point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PciTransportDiscoveryError {
    Configuration(PciConfigReadError),
    Capabilities(PciCapabilityError),
    Mapping(MmioAcquireError),
    Registers(TransportError),
    Allocation,
}

#[derive(Clone, Copy, Debug)]
struct Capability {
    bar: u8,
    range: MmioByteRange,
}

#[derive(Debug)]
struct Capabilities {
    common: Capability,
    notification: Capability,
    interrupt_status: Capability,
    device_configuration: Option<Capability>,
    notification_multiplier: u32,
}

impl VirtioPciTransport {
    /// Discover modern capabilities of one authorized PCI function and acquire
    /// their exact BAR-relative byte windows. Configuration observations grant
    /// no register access; each successful mapping separately pins its resource.
    ///
    /// # Errors
    /// Preserves configuration, malformed capability, resource admission,
    /// mapping and register-geometry failures. No queue DMA is published.
    pub fn acquire(
        device: PackedPciLocation,
        device_type: VirtioDeviceType,
    ) -> Result<Self, PciTransportDiscoveryError> {
        let services = kernel_api::service::kernel::instance();
        let snapshot = services
            .read_pci_config(device)
            .map_err(PciTransportDiscoveryError::Configuration)?;
        let capabilities =
            parse(&snapshot, device_type).map_err(PciTransportDiscoveryError::Capabilities)?;
        let map = |capability: Capability| {
            let request =
                PciMmioRequest::new(device, capability.bar, capability.range).map_err(|cause| {
                    PciTransportDiscoveryError::Mapping(MmioAcquireError::Request(cause))
                })?;
            let mapping = services
                .acquire_pci_mmio(request)
                .map_err(PciTransportDiscoveryError::Mapping)?;
            Arc::try_new(mapping).map_err(|_| PciTransportDiscoveryError::Allocation)
        };
        let apertures = PciTransportApertures {
            common: map(capabilities.common)?,
            notification: map(capabilities.notification)?,
            interrupt_status: map(capabilities.interrupt_status)?,
            device_configuration: capabilities.device_configuration.map(map).transpose()?,
            notification_multiplier: capabilities.notification_multiplier,
        };
        Self::new(device, device_type, apertures)
            .map_err(|failure| PciTransportDiscoveryError::Registers(failure.cause))
    }
}

fn read_u32(bytes: &[u8; 256], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn parse(
    snapshot: &PciConfigSnapshot,
    expected: VirtioDeviceType,
) -> Result<Capabilities, PciCapabilityError> {
    let bytes = snapshot.bytes();
    let vendor = u16::from_le_bytes([bytes[0], bytes[1]]);
    let pci_id = u16::from_le_bytes([bytes[2], bytes[3]]);
    let actual = match pci_id {
        0x1040..=0x107f => VirtioDeviceType::from(u32::from(pci_id - 0x1040)),
        0x1000..=0x103f => {
            VirtioDeviceType::from(u32::from(u16::from_le_bytes([bytes[0x2e], bytes[0x2f]])))
        }
        _ => VirtioDeviceType::Unknown,
    };
    if vendor != 0x1af4 || actual == VirtioDeviceType::Unknown || actual != expected {
        return Err(PciCapabilityError::WrongDevice);
    }
    if bytes[0x0e] & 0x7f != 0 {
        return Err(PciCapabilityError::HeaderType);
    }
    if bytes[6] & 0x10 == 0 {
        return Err(PciCapabilityError::ListAbsent);
    }
    let mut visited = [false; 64];
    let mut pointer = bytes[0x34];
    let mut common = None;
    let mut notification = None;
    let mut interrupt_status = None;
    let mut device_configuration = None;
    let mut multiplier = 0;
    // LOOP_PROOF: mode=condition; reason=Each nonzero pointer must identify a previously unvisited aligned dword in the finite 256-byte conventional header, repetition fails and a null link terminates.;
    while pointer != 0 {
        let offset = usize::from(pointer);
        if offset < 0x40 || !offset.is_multiple_of(4) {
            return Err(PciCapabilityError::InvalidPointer);
        }
        if visited[offset / 4] {
            return Err(PciCapabilityError::CyclicList);
        }
        visited[offset / 4] = true;
        pointer = bytes[offset + 1];
        if bytes[offset] != 9 {
            continue;
        }
        let length = usize::from(bytes[offset + 2]);
        if length < 4 || offset + length > bytes.len() {
            return Err(PciCapabilityError::Truncated);
        }
        let kind = match bytes[offset + 3] {
            1 => VirtioPciCapType::CommonCfg,
            2 => VirtioPciCapType::NotifyCfg,
            3 => VirtioPciCapType::IsrCfg,
            4 => VirtioPciCapType::DeviceCfg,
            _ => continue,
        };
        if length < 16 || (kind == VirtioPciCapType::NotifyCfg && length < 20) {
            return Err(PciCapabilityError::Truncated);
        }
        let bar = bytes[offset + 4];
        if bar >= 6 {
            return Err(PciCapabilityError::InvalidBar);
        }
        // An I/O capability may precede the device's memory alternative.
        // MMIO admission separately rejects upper BAR words and absent extents.
        if read_u32(bytes, 0x10 + usize::from(bar) * 4) & 1 != 0 {
            continue;
        }
        let range = MmioByteRange::new(
            read_u32(bytes, offset + 8) as usize,
            read_u32(bytes, offset + 12) as usize,
        )
        .map_err(PciCapabilityError::InvalidRange)?;
        let capability = Capability { bar, range };
        match kind {
            VirtioPciCapType::CommonCfg => {
                if common.is_none() {
                    common = Some(capability);
                }
            }
            VirtioPciCapType::NotifyCfg => {
                if notification.is_none() {
                    multiplier = read_u32(bytes, offset + 16);
                    super::pci::notification_offset(0, multiplier)
                        .map_err(|_| PciCapabilityError::InvalidNotificationMultiplier)?;
                    notification = Some(capability);
                }
            }
            VirtioPciCapType::IsrCfg => {
                if interrupt_status.is_none() {
                    interrupt_status = Some(capability);
                }
            }
            VirtioPciCapType::DeviceCfg => {
                if device_configuration.is_none() {
                    device_configuration = Some(capability);
                }
            }
            VirtioPciCapType::PciCfg => {
                unreachable!("only register capability types enter this match")
            }
        }
    }
    Ok(Capabilities {
        common: common.ok_or(PciCapabilityError::Missing(VirtioPciCapType::CommonCfg))?,
        notification: notification
            .ok_or(PciCapabilityError::Missing(VirtioPciCapType::NotifyCfg))?,
        interrupt_status: interrupt_status
            .ok_or(PciCapabilityError::Missing(VirtioPciCapType::IsrCfg))?,
        device_configuration,
        notification_multiplier: multiplier,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot(bytes: [u8; 256]) -> PciConfigSnapshot {
        PciConfigSnapshot::from_bytes(PackedPciLocation::new(0, 0, 1, 0), bytes)
            .expect("fixture device")
    }
    fn header() -> [u8; 256] {
        let mut bytes = [0; 256];
        bytes[..4].copy_from_slice(&[0xf4, 0x1a, 0x42, 0x10]);
        bytes[6] = 0x10;
        bytes[0x34] = 0x40;
        bytes[0x20..0x24].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        for (offset, next, kind, bar_offset, extent) in [
            (0x40, 0x54, 1, 0x1000u32, 56u32),
            (0x54, 0x68, 2, 0x2000, 256),
            (0x68, 0, 3, 0x3000, 1),
        ] {
            bytes[offset..offset + 5].copy_from_slice(&[
                9,
                next,
                if kind == 2 { 20 } else { 16 },
                kind,
                4,
            ]);
            bytes[offset + 8..offset + 12].copy_from_slice(&bar_offset.to_le_bytes());
            bytes[offset + 12..offset + 16].copy_from_slice(&extent.to_le_bytes());
        }
        bytes[0x64..0x68].copy_from_slice(&4u32.to_le_bytes());
        bytes
    }
    #[test]
    fn discovery_keeps_capability_windows_and_optional_config_distinct() {
        let parsed =
            parse(&snapshot(header()), VirtioDeviceType::Block).expect("modern block capabilities");
        assert_eq!(parsed.common.bar, 4);
        assert_eq!(parsed.common.range.offset(), 0x1000);
        assert_eq!(parsed.common.range.byte_count(), 56);
        assert_eq!(parsed.notification.range.offset(), 0x2000);
        assert_eq!(parsed.notification_multiplier, 4);
        assert_eq!(parsed.interrupt_status.range.byte_count(), 1);
        assert!(parsed.device_configuration.is_none());
    }
    #[test]
    fn transitional_type_is_read_from_subsystem_identity() {
        let mut bytes = header();
        bytes[2..4].copy_from_slice(&0x1001u16.to_le_bytes());
        bytes[0x2e..0x30].copy_from_slice(&2u16.to_le_bytes());
        assert!(parse(&snapshot(bytes), VirtioDeviceType::Block).is_ok());
        assert!(matches!(
            parse(&snapshot(bytes), VirtioDeviceType::Network),
            Err(PciCapabilityError::WrongDevice)
        ));
    }
    #[test]
    fn malformed_links_and_truncated_fields_fail_before_mapping() {
        for pointer in [1, 0x3c, 0x41, 0xff] {
            let mut bytes = header();
            bytes[0x34] = pointer;
            assert!(matches!(
                parse(&snapshot(bytes), VirtioDeviceType::Block),
                Err(PciCapabilityError::InvalidPointer)
            ));
        }
        let mut bytes = header();
        bytes[0x69] = 0x40;
        assert!(matches!(
            parse(&snapshot(bytes), VirtioDeviceType::Block),
            Err(PciCapabilityError::CyclicList)
        ));
        let mut bytes = header();
        bytes[0x56] = 16;
        assert!(matches!(
            parse(&snapshot(bytes), VirtioDeviceType::Block),
            Err(PciCapabilityError::Truncated)
        ));
        let mut bytes = header();
        bytes[0x34] = 0xfc;
        bytes[0xfc..].copy_from_slice(&[9, 0, 20, 2]);
        assert!(matches!(
            parse(&snapshot(bytes), VirtioDeviceType::Block),
            Err(PciCapabilityError::Truncated)
        ));
    }
    #[test]
    fn discovery_rejects_missing_ranges_and_invalid_notification_geometry() {
        let mut bytes = header();
        bytes[0x44] = 6;
        assert!(matches!(
            parse(&snapshot(bytes), VirtioDeviceType::Block),
            Err(PciCapabilityError::InvalidBar)
        ));
        let mut bytes = header();
        bytes[0x4c..0x50].fill(0);
        assert!(matches!(
            parse(&snapshot(bytes), VirtioDeviceType::Block),
            Err(PciCapabilityError::InvalidRange(MmioRequestError::Empty))
        ));
        let mut bytes = header();
        bytes[0x64..0x68].copy_from_slice(&3u32.to_le_bytes());
        assert!(matches!(
            parse(&snapshot(bytes), VirtioDeviceType::Block),
            Err(PciCapabilityError::InvalidNotificationMultiplier)
        ));
        let mut bytes = header();
        bytes[0x41] = 0;
        assert!(matches!(
            parse(&snapshot(bytes), VirtioDeviceType::Block),
            Err(PciCapabilityError::Missing(VirtioPciCapType::NotifyCfg))
        ));
    }
}
