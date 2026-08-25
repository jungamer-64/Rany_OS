/// Program MSI for a PCI device
///
/// # Safety
/// This modifies PCI configuration space
pub unsafe fn program_msi(
    bus: u8,
    device: u8,
    function: u8,
    msi_offset: u8,
    message_address: u64,
    message_data: u32,
) -> Result<(), crate::io::interrupt_manager::InterruptError> {
    // Read MSI control register
    let control = crate::drivers::pci::legacy::pci_read16(bus, device, function, msi_offset + 2);

    // Check if 64-bit capable
    let is_64bit = (control & 0x80) != 0;
    if !is_64bit && message_address > u64::from(u32::MAX) {
        return Err(crate::io::interrupt_manager::InterruptError::HardwareError);
    }

    if is_64bit {
        // 64-bit MSI
        // Write lower address
        crate::drivers::pci::legacy::pci_write(
            bus,
            device,
            function,
            msi_offset + 4,
            message_address as u32,
        );
        crate::drivers::pci::legacy::pci_write(
            bus,
            device,
            function,
            msi_offset + 8,
            (message_address >> 32) as u32,
        );
        // Write message data
        let data_reg =
            crate::drivers::pci::legacy::pci_read(bus, device, function, msi_offset + 12);
        crate::drivers::pci::legacy::pci_write(
            bus,
            device,
            function,
            msi_offset + 12,
            (data_reg & 0xFFFF0000) | (message_data & 0xffff),
        );
    } else {
        // 32-bit MSI
        // Write address
        crate::drivers::pci::legacy::pci_write(
            bus,
            device,
            function,
            msi_offset + 4,
            message_address as u32,
        );
        // Write message data
        let data_reg = crate::drivers::pci::legacy::pci_read(bus, device, function, msi_offset + 8);
        crate::drivers::pci::legacy::pci_write(
            bus,
            device,
            function,
            msi_offset + 8,
            (data_reg & 0xFFFF0000) | (message_data & 0xffff),
        );
    }

    // Enable MSI
    let new_control = control | 0x01;
    let control_reg = crate::drivers::pci::legacy::pci_read(bus, device, function, msi_offset);
    crate::drivers::pci::legacy::pci_write(
        bus,
        device,
        function,
        msi_offset,
        (control_reg & 0xFFFF) | ((new_control as u32) << 16),
    );
    Ok(())
}
