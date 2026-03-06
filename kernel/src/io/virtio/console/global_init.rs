use super::*;

// ============================================================================
// Global Device Instance
// ============================================================================

/// Primary (legacy) VirtIO console device slot kept for compatibility (`index=0`).
pub(crate) static VIRTIO_CONSOLE_DEVICE: crate::sync::PoisonLock<Option<Arc<VirtioConsoleDevice>>> =
    crate::sync::PoisonLock::new(None);

/// Additional VirtIO console devices (`index != 0`).
pub(crate) static VIRTIO_CONSOLE_DEVICES: spin::RwLock<
    alloc::collections::BTreeMap<u8, Arc<VirtioConsoleDevice>>,
> = spin::RwLock::new(alloc::collections::BTreeMap::new());

fn install_virtio_console_device(index: u8, device_arc: Arc<VirtioConsoleDevice>) {
    if index == 0 {
        *VIRTIO_CONSOLE_DEVICE
            .lock()
            .expect("VIRTIO_CONSOLE_DEVICE lock poisoned") = Some(device_arc);
    } else {
        VIRTIO_CONSOLE_DEVICES.write().insert(index, device_arc);
    }
}

/// Get a shared reference to the VirtIO console device by index.
pub fn get_virtio_console_device_at_index(index: u8) -> Option<Arc<VirtioConsoleDevice>> {
    if index == 0 {
        VIRTIO_CONSOLE_DEVICE
            .lock()
            .expect("VIRTIO_CONSOLE_DEVICE lock poisoned")
            .clone()
    } else {
        VIRTIO_CONSOLE_DEVICES.read().get(&index).cloned()
    }
}

/// Initialize the global VirtIO console device at a specific index.
pub unsafe fn init_virtio_console_at_index(index: u8, mmio_base: u64) -> Result<(), ConsoleError> {
    let transport = unsafe {
        VirtioMmioTransport::new(mmio_base as usize).map_err(|_| ConsoleError::NotReady)?
    };
    let mut dev = VirtioConsoleDevice::new(Box::new(transport));
    dev.init()?;

    let device_arc = Arc::new(dev);

    log::info!(
        "VirtIO-console index={} initialized: {}x{} (cols x rows)\n",
        index,
        device_arc.config().cols,
        device_arc.config().rows
    );

    install_virtio_console_device(index, device_arc);
    Ok(())
}

/// Initialize the global VirtIO console device (legacy `index=0`).
pub unsafe fn init_virtio_console(mmio_base: u64) -> Result<(), ConsoleError> {
    init_virtio_console_at_index(0, mmio_base)
}

/// Initialize the global VirtIO console device with an IOMMU device ID at a specific index.
pub unsafe fn init_virtio_console_for_device_at_index(
    index: u8,
    mmio_base: u64,
    device: IommuDeviceId,
) -> Result<(), ConsoleError> {
    let transport = unsafe {
        VirtioMmioTransport::new(mmio_base as usize).map_err(|_| ConsoleError::NotReady)?
    };
    let mut dev = VirtioConsoleDevice::new_with_device(Box::new(transport), Some(device));
    dev.init()?;

    let device_arc = Arc::new(dev);

    log::info!(
        "VirtIO-console index={} initialized: {}x{} (cols x rows)\n",
        index,
        device_arc.config().cols,
        device_arc.config().rows
    );

    install_virtio_console_device(index, device_arc);
    Ok(())
}

/// Initialize the global VirtIO console device with an IOMMU device ID (legacy `index=0`).
pub unsafe fn init_virtio_console_for_device(
    mmio_base: u64,
    device: IommuDeviceId,
) -> Result<(), ConsoleError> {
    init_virtio_console_for_device_at_index(0, mmio_base, device)
}

/// Initialize the global VirtIO console device from an existing VirtioTransport (MMIO or PCI) at a specific index.
pub unsafe fn init_virtio_console_with_transport_at_index(
    index: u8,
    transport: Box<dyn VirtioTransport>,
    iommu_device_id: Option<IommuDeviceId>,
) -> Result<(), ConsoleError> {
    let mut dev = VirtioConsoleDevice::new_with_device(transport, iommu_device_id);
    dev.init()?;

    let device_arc = Arc::new(dev);

    log::info!(
        "VirtIO-console index={} initialized: {}x{} (cols x rows)\n",
        index,
        device_arc.config().cols,
        device_arc.config().rows
    );

    install_virtio_console_device(index, device_arc);
    Ok(())
}

/// Initialize the global VirtIO console device from an existing VirtioTransport (MMIO or PCI).
pub unsafe fn init_virtio_console_with_transport(
    transport: Box<dyn VirtioTransport>,
    iommu_device_id: Option<IommuDeviceId>,
) -> Result<(), ConsoleError> {
    init_virtio_console_with_transport_at_index(0, transport, iommu_device_id)
}

/// Handle VirtIO console device interrupt for a specific index.
pub fn handle_virtio_console_interrupt_for_index(index: u8) {
    if let Some(device) = get_virtio_console_device_at_index(index) {
        // Ack interrupt with shared reference
        let status = device.transport.get_interrupt_status();
        device.transport.ack_interrupt(status);
        device.handle_interrupt();
    }
}

/// Handle VirtIO console device interrupt for index 0 (legacy compatibility).
pub fn handle_virtio_console_interrupt() {
    handle_virtio_console_interrupt_for_index(0);
}

/// Get a clone of the global VirtIO console device Arc if initialized (legacy `index=0`).
pub fn get_virtio_console_device() -> Option<Arc<VirtioConsoleDevice>> {
    get_virtio_console_device_at_index(0)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, not(feature = "qemu-test-export")))]
#[path = "tests.rs"]
mod tests;
