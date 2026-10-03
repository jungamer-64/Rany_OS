//! Function-resource pins prevent destructive BAR sizing while access exists.
#![forbid(unsafe_code)]

use crate::{BdfAddress, ConfigSpaceAccessor, PciBusScanner, PciDeviceInfo};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU16, Ordering};
use exorust_sync::Mutex;

const MAX_PINS: usize = 256;
static PINS: Mutex<[Option<PinEntry>; MAX_PINS]> = Mutex::new([const { None }; MAX_PINS]);
// Derived lifetime index: one increment per FunctionResources construction and
// one decrement at destruction. It permits raw configuration accessors to reject
// forbidden writes without recursively acquiring the enumeration lock.
static LIVE: [AtomicU16; 65536] = [const { AtomicU16::new(0) }; 65536];

/// A retained immutable BAR assignment for segment zero's configuration owner.
/// Drivers do not receive this pin; the kernel includes it in a mapping owner.
pub struct FunctionResources {
    info: Arc<PciDeviceInfo>,
}

// One immutable snapshot is shared by the owner and its derived index. Keeping
// metadata through the final destructor never restores access authority.
struct PinEntry {
    info: Arc<PciDeviceInfo>,
    owner: Weak<FunctionResources>,
}

impl FunctionResources {
    pub fn info(&self) -> &PciDeviceInfo {
        &self.info
    }

    /// Resolves this pinned bridge's downstream bus range. The pin excludes
    /// bus-number repurposing while the caller uses the resulting observation.
    ///
    /// # Errors
    /// Reports a non-bridge function or a bus range inconsistent with this
    /// function's primary bus, including an unconfigured or cyclic assignment.
    pub fn bridge_buses(&self) -> Result<BridgeBuses, BridgeBusError> {
        if !self.info.is_pci_bridge() {
            return Err(BridgeBusError::NotBridge);
        }
        let raw = crate::legacy::get_legacy_accessor().read32(self.info.bdf, 0x18);
        decode_bridge_buses(self.info.bdf.bus(), raw)
    }

    /// Programs message zero of this retained function's MSI capability.
    /// The function pin keeps its immutable assignment valid through the write;
    /// the platform interrupt owner must already own the supplied vector.
    ///
    /// # Errors
    /// Returns an error when the function has no MSI capability. No configuration
    /// write occurs in that case. Additional messages require a vector range.
    pub fn configure_msi(
        &self,
        config: &crate::msi::MsiConfig,
    ) -> Result<(), MsiConfigurationError> {
        let accessor = crate::legacy::get_legacy_accessor();
        let capability = crate::msi::MsiCapability::probe(accessor, self.info())
            .ok_or(MsiConfigurationError::CapabilityAbsent)?;
        capability.enable(accessor, config);
        crate::msi::disable_intx(accessor, self.info());
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsiConfigurationError {
    CapabilityAbsent,
}

impl Drop for FunctionResources {
    fn drop(&mut self) {
        let old = LIVE[usize::from(self.info.bdf.to_u16())].fetch_sub(1, Ordering::Release);
        assert_eq!(old, 1, "PCI function pin lifetime index corrupted");
    }
}

/// Resource admission is distinct from hardware absence and from allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FunctionResourceError {
    Absent,
    Busy,
    Exhausted,
}

/// Pins BAR assignments before granting register access. Enumeration reuses
/// their extents while retained, so it never writes sizing masks into a live BAR.
///
/// # Errors
/// Reports an absent function, a retiring pin, or exhausted registration slots.
pub fn retain(bdf: BdfAddress) -> Result<Arc<FunctionResources>, FunctionResourceError> {
    let mut pins = PINS.lock();
    for pin in pins
        .iter()
        .flatten()
        .filter_map(|entry| entry.owner.upgrade())
    {
        if pin.info.bdf == bdf {
            return Ok(pin);
        }
    }
    if is_retained(bdf) {
        return Err(FunctionResourceError::Busy);
    }
    let slot = pins
        .iter_mut()
        .find(|pin| {
            pin.as_ref()
                .is_none_or(|entry| entry.owner.strong_count() == 0 && !is_retained(entry.info.bdf))
        })
        .ok_or(FunctionResourceError::Exhausted)?;
    let scanner = PciBusScanner::new(crate::legacy::get_legacy_accessor());
    let info = scanner
        .read_unretained_device(bdf)
        .ok_or(FunctionResourceError::Absent)?;
    LIVE[usize::from(bdf.to_u16())].fetch_add(1, Ordering::Release);
    let info = Arc::new(info);
    let owner = Arc::new(FunctionResources {
        info: Arc::clone(&info),
    });
    *slot = Some(PinEntry {
        info,
        owner: Arc::downgrade(&owner),
    });
    Ok(owner)
}

/// Serializes sizing with pin publication. The callback cannot retain its borrow.
pub(crate) fn with_configuration<R>(
    bdf: BdfAddress,
    use_config: impl FnOnce(Option<&PciDeviceInfo>) -> R,
) -> R {
    let pins = PINS.lock();
    let pin = pins
        .iter()
        .flatten()
        .find(|entry| entry.info.bdf == bdf && is_retained(bdf));
    use_config(pin.map(|entry| entry.info.as_ref()))
}

/// Used by resource removal and decode changes to report a live access blocker.
pub fn is_retained(bdf: BdfAddress) -> bool {
    LIVE[usize::from(bdf.to_u16())].load(Ordering::Acquire) != 0
}

pub(crate) fn assert_configuration_write(bdf: BdfAddress, offset: u16, width: u16) {
    // BAR words and bridge windows cannot be repurposed while a register owner
    // exists. Raw accessor misuse is a kernel programming error; normal resource
    // operations check is_retained and return Busy before writing.
    let end = offset.saturating_add(width);
    assert!(
        !(offset < 0x34 && end > 0x10 && is_retained(bdf)),
        "PCI address assignment write while register resources are retained"
    );
}

/// A validated downstream range observed through a retained function pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeBuses {
    secondary: u8,
    subordinate: u8,
}
impl BridgeBuses {
    pub const fn secondary(self) -> u8 {
        self.secondary
    }
    pub const fn subordinate(self) -> u8 {
        self.subordinate
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeBusError {
    NotBridge,
    InvalidRange,
}

fn decode_bridge_buses(bus: u8, raw: u32) -> Result<BridgeBuses, BridgeBusError> {
    let primary = raw as u8;
    let secondary = (raw >> 8) as u8;
    let subordinate = (raw >> 16) as u8;
    if primary != bus || secondary == 0 || secondary == bus || secondary > subordinate {
        return Err(BridgeBusError::InvalidRange);
    }
    Ok(BridgeBuses {
        secondary,
        subordinate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_bus_range_checks_primary_and_complete_downstream_extent() {
        let buses = decode_bridge_buses(2, 0x00ff_0302).unwrap();
        assert_eq!(buses.secondary(), 3);
        assert_eq!(buses.subordinate(), 255);
        assert!(decode_bridge_buses(1, 0x00ff_0302).is_err());
        assert!(decode_bridge_buses(2, 0x0002_0202).is_err());
        assert!(decode_bridge_buses(2, 0x0002_0302).is_err());
        assert!(decode_bridge_buses(2, 0x00ff_0002).is_err());
    }
}
