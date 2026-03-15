use super::*;

/// Initialize the global VirtIO input device from an existing VirtioTransport (MMIO or PCI) at a specific index.
pub unsafe fn init_virtio_input_with_transport_at_index(
    index: u8,
    transport: Box<dyn VirtioTransport>,
    iommu_device_id: IommuDeviceId,
) -> Result<(), InputError> {
    let mut dev = VirtioInputDevice::new_with_device(transport, iommu_device_id);
    dev.init()?;

    let name = dev.device_name();
    let device_arc = Arc::new(dev);

    if let Some(name_bytes) = name {
        if let Ok(name_str) = core::str::from_utf8(&name_bytes) {
            log::info!(
                "VirtIO-input index={} initialized: \"{}\"\n",
                index,
                name_str
            );
        } else {
            log::info!(
                "VirtIO-input index={} initialized: (non-UTF8 name, {} bytes)\n",
                index,
                name_bytes.len()
            );
        }
    } else {
        log::info!("VirtIO-input index={} initialized\n", index);
    }

    install_virtio_input_device(index, device_arc);
    Ok(())
}

/// Handle VirtIO input device interrupt for a specific index.
pub fn handle_virtio_input_interrupt_for_index(index: u8) {
    if let Some(device) = get_virtio_input_device_at_index(index) {
        // Ack interrupt with shared reference
        let status = device.transport.get_interrupt_status();
        device.transport.ack_interrupt(status);
        device.handle_interrupt();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, not(feature = "qemu-test-export")))]
#[path = "tests.rs"]
mod tests;
