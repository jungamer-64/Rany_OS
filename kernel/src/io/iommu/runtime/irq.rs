// ============================================================================
// kernel/src/io/iommu/runtime/irq.rs
// ============================================================================

//! Interrupt Remapping API
//!
//! Provides functions to map interrupts via the IOMMU (Interrupt Remapping/IR).

use super::registry::get_iommu_driver;
use crate::cpu::ApicId;
use crate::io::iommu::types::IommuError;

// ============================================================================
// MSI/MSI-X Constants (x86 Format)
// ============================================================================

/// Base address for MSI messages (x86 architecture).
/// All MSI messages are directed to the LAPIC address range.
const MSI_BASE_ADDRESS: u64 = 0xFEE0_0000;

/// Shift for the lower 15 bits of the interrupt handle in MSI address.
/// Bits [19:5] contain handle[14:0].
const MSI_HANDLE_LOW_SHIFT: u8 = 5;

/// Shift for the high bit of the interrupt handle in MSI address.
/// Bit [3] contains handle[15] (SHV bit in VT-d terminology).
const MSI_HANDLE_HIGH_SHIFT: u8 = 3;

/// Mask for the lower 15 bits of the interrupt handle.
const MSI_HANDLE_LOW_MASK: u64 = 0x7FFF;

/// Mask for the high bit (bit 15) of the interrupt handle.
const MSI_HANDLE_HIGH_MASK: u64 = 1;

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

/// Generate MSI Address and Data for a Remapped Interrupt
///
/// # Arguments
/// * `handle` - IRTE handle returned by `map_interrupt`
///
/// # Returns
/// (Address, Data) tuple for MSI/MSI-X configuration
///
/// # Address Format (x86, Intel VT-d/AMD-Vi compatible)
/// ```text
/// Bits [31:20]: 0xFEE (LAPIC base)
/// Bits [19:5]:  handle[14:0] - lower 15 bits of interrupt handle
/// Bit  [4]:     Reserved (0)
/// Bit  [3]:     handle[15] - high bit of handle (SHV in VT-d)
/// Bits [2:0]:   Reserved (0)
/// ```
pub fn get_remap_msi_message(handle: u16) -> (u64, u32) {
    if let Some(driver) = get_iommu_driver() {
        return driver.get_remap_msi_message(handle);
    }

    // Fallback to Intel VT-d MSI/MSI-X format if no driver is registered.
    let handle = handle as u64;
    let index_low = handle & MSI_HANDLE_LOW_MASK;
    let index_high = (handle >> 15) & MSI_HANDLE_HIGH_MASK;
    let address = MSI_BASE_ADDRESS
        | (index_low << MSI_HANDLE_LOW_SHIFT)
        | (index_high << MSI_HANDLE_HIGH_SHIFT);
    let data = 0;
    (address, data)
}
