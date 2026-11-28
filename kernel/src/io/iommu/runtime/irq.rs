// ============================================================================
// kernel/src/io/iommu/runtime/irq.rs
// ============================================================================

//! Interrupt Remapping API
//!
//! Provides functions to map interrupts via the IOMMU (Interrupt Remapping/IR).

use super::registry::get_iommu_driver;
use crate::cpu::ApicId;
use crate::io::iommu::types::{DeviceId, IommuError};

// ============================================================================
// MSI/MSI-X Constants (x86 Format)
// ============================================================================

/// Base address for MSI messages (x86 architecture).
/// All MSI messages are directed to the LAPIC address range.
const MSI_BASE_ADDRESS: u64 = 0xFEE0_0000;

/// Shift for the lower 15 bits of the interrupt handle in MSI address.
/// Bits [19:5] contain handle[14:0].
const MSI_HANDLE_LOW_SHIFT: u8 = 5;

/// Mask for the lower 15 bits of the interrupt handle.
const MSI_HANDLE_LOW_MASK: u64 = 0x7FFF;

/// Position of interrupt handle bit 15 in the remappable MSI address.
const MSI_HANDLE_HIGH: u64 = 1 << 2;

/// Marks an MSI request as using the interrupt-remappable message format.
const MSI_INTERRUPT_FORMAT: u64 = 1 << 4;

/// Map an interrupt for a device using Interrupt Remapping
///
/// Returns the IRTE handle (index) to be used for generating the MSI message.
pub fn map_interrupt(
    segment: u16,
    bus: u8,
    device: u8,
    function: u8,
    vector: u8,
    destination: ApicId,
    logical: bool,
) -> Result<u16, IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    driver.map_interrupt(segment, bus, device, function, vector, destination, logical)
}

pub(crate) fn retire_interrupt(device: DeviceId, index: u16, vector: u8) -> Result<(), IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    driver.retire_interrupt(device, index, vector)
}

/// Generate the active backend's MSI address and data for an admitted IRTE.
pub fn get_remap_msi_message(handle: u16) -> (u64, u32) {
    if let Some(driver) = get_iommu_driver() {
        return driver.get_remap_msi_message(handle);
    }

    encode_remappable_msi_message(handle)
}

pub(crate) fn encode_remappable_msi_message(handle: u16) -> (u64, u32) {
    let handle = u64::from(handle);
    let handle_high = if handle & (1 << 15) != 0 {
        MSI_HANDLE_HIGH
    } else {
        0
    };
    (
        MSI_BASE_ADDRESS
            | MSI_INTERRUPT_FORMAT
            | handle_high
            | ((handle & MSI_HANDLE_LOW_MASK) << MSI_HANDLE_LOW_SHIFT),
        0,
    )
}

#[cfg(test)]
mod tests {
    use super::encode_remappable_msi_message;

    #[test]
    fn remappable_msi_message_sets_interrupt_format_and_index() {
        assert_eq!(encode_remappable_msi_message(0), (0xFEE0_0010, 0));
        assert_eq!(encode_remappable_msi_message(255), (0xFEE0_1FF0, 0));
        assert_eq!(encode_remappable_msi_message(0x8000), (0xFEE0_0014, 0));
        assert_eq!(encode_remappable_msi_message(0xffff), (0xFEEF_FFF4, 0));
    }
}
