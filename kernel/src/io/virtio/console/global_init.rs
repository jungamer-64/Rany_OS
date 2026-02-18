use super::*;


// ============================================================================
// Global Device Instance
// ============================================================================

/// Global VirtIO console device instance (stored in an Arc for shared access)
pub(crate) static VIRTIO_CONSOLE_DEVICE: Mutex<Option<Arc<VirtioConsoleDevice>>> = Mutex::new(None);

/// Initialize the global VirtIO console device.
///
/// # Safety
/// Caller must ensure MMIO address is valid and device exists.
pub unsafe fn init_virtio_console(mmio_base: u64) -> Result<(), ConsoleError> {
    let transport = unsafe {
        VirtioMmioTransport::new(mmio_base as usize).map_err(|_| ConsoleError::NotReady)?
    };
    let mut dev = VirtioConsoleDevice::new(Box::new(transport));
    unsafe { dev.init()? };

    let device_arc = Arc::new(dev);

    log::info!(
        "VirtIO-console initialized: {}x{} (cols x rows)\n",
        device_arc.config().cols,
        device_arc.config().rows
    );

    *VIRTIO_CONSOLE_DEVICE.lock() = Some(Arc::clone(&device_arc));
    Ok(())
}

/// Initialize the global VirtIO console device with an IOMMU device ID.
///
/// # Safety
/// Caller must ensure MMIO address is valid and device exists.
pub unsafe fn init_virtio_console_for_device(
    mmio_base: u64,
    device: IommuDeviceId,
) -> Result<(), ConsoleError> {
    let transport = unsafe {
        VirtioMmioTransport::new(mmio_base as usize).map_err(|_| ConsoleError::NotReady)?
    };
    let mut dev = VirtioConsoleDevice::new_with_device(Box::new(transport), Some(device));
    unsafe { dev.init()? };

    let device_arc = Arc::new(dev);

    log::info!(
        "VirtIO-console initialized: {}x{} (cols x rows)\n",
        device_arc.config().cols,
        device_arc.config().rows
    );

    *VIRTIO_CONSOLE_DEVICE.lock() = Some(Arc::clone(&device_arc));
    Ok(())
}

/// Initialize the global VirtIO console device from an existing VirtioTransport (MMIO or PCI).
///
/// # Safety
/// Caller must ensure the transport is properly initialized and points to a valid device.
pub unsafe fn init_virtio_console_with_transport(
    transport: Box<dyn VirtioTransport>,
    iommu_device_id: Option<IommuDeviceId>,
) -> Result<(), ConsoleError> {
    let mut dev = VirtioConsoleDevice::new_with_device(transport, iommu_device_id);
    unsafe { dev.init()? };

    let device_arc = Arc::new(dev);

    log::info!(
        "VirtIO-console initialized: {}x{} (cols x rows)\n",
        device_arc.config().cols,
        device_arc.config().rows
    );

    *VIRTIO_CONSOLE_DEVICE.lock() = Some(Arc::clone(&device_arc));
    Ok(())
}

/// Handle VirtIO console device interrupt.
pub fn handle_virtio_console_interrupt() {
    if let Some(device) = VIRTIO_CONSOLE_DEVICE.lock().as_ref() {
        // Ack interrupt with shared reference
        let status = device.transport.get_interrupt_status();
        device.transport.ack_interrupt(status);
        device.handle_interrupt();
    }
}

/// Get a clone of the global VirtIO console device Arc if initialized.
pub fn get_virtio_console_device() -> Option<Arc<VirtioConsoleDevice>> {
    VIRTIO_CONSOLE_DEVICE.lock().as_ref().cloned()
}

/// Align `val` up to the nearest multiple of `align`.
pub(crate) fn align_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
