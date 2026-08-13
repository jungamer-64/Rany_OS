use super::*;

fn install_virtio_blk_device(index: u8, device_arc: Arc<VirtioBlkDevice>) {
    device_arc.set_device_index(index);
    if index == 0 {
        *VIRTIO_BLK_DEVICE.lock().unwrap_or_else(|e| e.into_inner()) = Some(device_arc);
    } else {
        VIRTIO_BLK_DEVICES
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(index, device_arc);
    }
}

#[cfg(test)]
fn test_device_for_index(index: u8) -> PackedPciLocation {
    PackedPciLocation::new(0, 0, index, 0)
}

/// Primary VirtIO block device slot (`index=0`).
pub(crate) static VIRTIO_BLK_DEVICE: PoisonLock<Option<Arc<VirtioBlkDevice>>> =
    PoisonLock::new(None);

/// Additional VirtIO block devices (`index != 0`).
pub(crate) static VIRTIO_BLK_DEVICES: PoisonRwLock<
    alloc::collections::BTreeMap<u8, Arc<VirtioBlkDevice>>,
> = PoisonRwLock::new(alloc::collections::BTreeMap::new());

pub fn get_virtio_blk_device_at_index(index: u8) -> Option<Arc<VirtioBlkDevice>> {
    if index == 0 {
        VIRTIO_BLK_DEVICE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    } else {
        VIRTIO_BLK_DEVICES
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&index)
            .cloned()
    }
}

#[cfg(test)]
pub unsafe fn init_virtio_blk_at_index(index: u8, mmio_base: u64) -> Result<(), BlockError> {
    let transport =
        unsafe { VirtioMmioTransport::new(mmio_base as usize).map_err(|_| BlockError::NotReady)? };
    let mut dev = VirtioBlkDevice::new(Box::new(transport), test_device_for_index(index));
    dev.init()?;

    let device_arc = Arc::new(dev);
    install_virtio_blk_device(index, device_arc);
    Ok(())
}

/// # Errors
///
/// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
pub unsafe fn init_virtio_blk_for_device_at_index(
    index: u8,
    mmio_base: u64,
    device: PackedPciLocation,
) -> Result<(), BlockError> {
    let transport =
        unsafe { VirtioMmioTransport::new(mmio_base as usize).map_err(|_| BlockError::NotReady)? };
    let mut dev = VirtioBlkDevice::new_with_device(Box::new(transport), device);
    dev.init()?;

    let device_arc = Arc::new(dev);
    install_virtio_blk_device(index, device_arc);
    Ok(())
}

/// # Errors
///
/// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
pub unsafe fn init_virtio_blk_with_transport_at_index(
    index: u8,
    transport: Box<dyn VirtioTransport>,
    pci_locator: PackedPciLocation,
) -> Result<(), BlockError> {
    let mut dev = VirtioBlkDevice::new_with_device(transport, pci_locator);
    dev.init()?;

    let device_arc = Arc::new(dev);
    install_virtio_blk_device(index, device_arc);
    Ok(())
}

pub fn handle_virtio_blk_interrupt_for_index(index: u8) {
    if let Some(device) = get_virtio_blk_device_at_index(index) {
        let status = device.transport.get_interrupt_status();
        if status == 0 {
            return;
        }
        device.transport.ack_interrupt(status);
        device.handle_interrupt();
    }
}
