use super::*;
use exorust_sync::{PoisonLock, PoisonRwLock};
use kernel_api::abi::driver::PackedPciLocation;

// ============================================================================
// Global Device Instance
// ============================================================================

/// Primary VirtIO console device slot (`index=0`).
pub(crate) static VIRTIO_CONSOLE_DEVICE: PoisonLock<Option<Arc<VirtioConsoleDevice>>> =
    PoisonLock::new(None);

/// Additional VirtIO console devices (`index != 0`).
pub(crate) static VIRTIO_CONSOLE_DEVICES: PoisonRwLock<
    alloc::collections::BTreeMap<u8, Arc<VirtioConsoleDevice>>,
> = PoisonRwLock::new(alloc::collections::BTreeMap::new());

fn install_virtio_console_device(index: u8, device_arc: Arc<VirtioConsoleDevice>) {
    if index == 0 {
        *VIRTIO_CONSOLE_DEVICE
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(device_arc);
    } else {
        VIRTIO_CONSOLE_DEVICES
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(index, device_arc);
    }
}

#[cfg(test)]
fn test_device_for_index(index: u8) -> PackedPciLocation {
    PackedPciLocation::new(0, 0, index, 0)
}

/// Get a shared reference to the VirtIO console device by index.
pub fn get_virtio_console_device_at_index(index: u8) -> Option<Arc<VirtioConsoleDevice>> {
    if index == 0 {
        VIRTIO_CONSOLE_DEVICE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    } else {
        VIRTIO_CONSOLE_DEVICES
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&index)
            .cloned()
    }
}

#[cfg(test)]
/// Initialize the global VirtIO console device at a specific index.
pub unsafe fn init_virtio_console_at_index(index: u8, mmio_base: u64) -> Result<(), ConsoleError> {
    let transport = unsafe {
        VirtioMmioTransport::new(mmio_base as usize).map_err(|_| ConsoleError::NotReady)?
    };
    let mut dev = VirtioConsoleDevice::new(Box::new(transport), test_device_for_index(index));
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

/// Initialize the global VirtIO console device with an IOMMU device ID at a specific index.
/// # Errors
///
/// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
pub unsafe fn init_virtio_console_for_device_at_index(
    index: u8,
    mmio_base: u64,
    device: PackedPciLocation,
) -> Result<(), ConsoleError> {
    let transport = unsafe {
        VirtioMmioTransport::new(mmio_base as usize).map_err(|_| ConsoleError::NotReady)?
    };
    let mut dev = VirtioConsoleDevice::new_with_device(Box::new(transport), device);
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

/// Initialize the global VirtIO console device from an existing VirtioTransport (MMIO or PCI) at a specific index.
/// # Errors
///
/// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
pub unsafe fn init_virtio_console_with_transport_at_index(
    index: u8,
    transport: Box<dyn VirtioTransport>,
    pci_locator: PackedPciLocation,
) -> Result<(), ConsoleError> {
    let mut dev = VirtioConsoleDevice::new_with_device(transport, pci_locator);
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

/// Handle VirtIO console device interrupt for a specific index.
pub fn handle_virtio_console_interrupt_for_index(index: u8) {
    if let Some(device) = get_virtio_console_device_at_index(index) {
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
