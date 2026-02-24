use super::*;


/// Initialize the global VirtIO input device from an existing VirtioTransport (MMIO or PCI).
///
/// # Safety
/// Caller must ensure the transport is properly initialized and points to a valid device.
pub unsafe fn init_virtio_input_with_transport(
    transport: Box<dyn VirtioTransport>,
    iommu_device_id: Option<IommuDeviceId>,
) -> Result<(), InputError> {
    let mut dev = VirtioInputDevice::new_with_device(transport, iommu_device_id);
    unsafe { dev.init()? };

    let name = dev.device_name();
    let device_arc = Arc::new(dev);

    if let Some(name_bytes) = name {
        if let Ok(name_str) = core::str::from_utf8(&name_bytes) {
            log::info!("VirtIO-input initialized: \"{}\"\n", name_str);
        } else {
            log::info!("VirtIO-input initialized: (non-UTF8 name, {} bytes)\n", name_bytes.len());
        }
    } else {
        log::info!("VirtIO-input initialized\n");
    }

    *VIRTIO_INPUT_DEVICE.lock() = Some(Arc::clone(&device_arc));
    Ok(())
}


/// Handle VirtIO input device interrupt (called from interrupt handler).
pub fn handle_virtio_input_interrupt() {
    if let Some(device) = VIRTIO_INPUT_DEVICE.lock().as_ref() {
        // Ack interrupt with shared reference
        let status = device.transport.get_interrupt_status();
        device.transport.ack_interrupt(status);
        device.handle_interrupt();
    }
}

/// Get a clone of the global VirtIO input device Arc if initialized.
pub fn get_virtio_input_device() -> Option<Arc<VirtioInputDevice>> {
    VIRTIO_INPUT_DEVICE.lock().as_ref().cloned()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
