use super::*;

/// Handle VirtIO block device interrupt for a specific index.
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

/// Synchronous read from global device
///
/// Note: For a proper async implementation, you would need to use
/// Arc<VirtioBlkDevice> to allow the future to outlive the lock.
pub fn blk_read_sync(_sector: u64, buf: &mut [u8]) -> Result<usize, BlockError> {
    let device_guard = VIRTIO_BLK_DEVICE.lock().unwrap_or_else(|e| e.into_inner());
    let _device = device_guard.as_ref().ok_or(BlockError::NotReady)?;

    // Placeholder: In production, this would submit the request and poll for completion
    // For now, just verify parameters
    if buf.is_empty() {
        return Err(BlockError::InvalidParam);
    }

    // Would need to implement polling-based read here
    Err(BlockError::NotReady)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, not(feature = "qemu-test-export")))]
mod unit_tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    pub(super) fn test_virtio_blk_req_type() {
        assert_eq!(VIRTIO_BLK_T_IN, 0);
        assert_eq!(VIRTIO_BLK_T_OUT, 1);
        assert_eq!(VIRTIO_BLK_T_FLUSH, 4);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    pub(super) fn test_block_device_config_default() {
        let config = BlockDeviceInfo::default();
        assert_eq!(config.total_blocks, 0);
        assert_eq!(config.block_size, 512);
        assert!(!config.read_only);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    pub(super) fn test_bounce_map_unmap_via_dmahandle() {
        // Verify that bounce allocation + DmaHandle mapping/unmap works
        let len = 4096usize;
        let device = crate::io::iommu::types::DeviceId::new(0, 0, 0x22, 0);
        crate::io::iommu::testkit::fixtures::ensure_test_intel_iommu_device(device);
        let mut rref = allocate_iommu_bounce_bytes(len).expect("alloc bounce bytes failed");
        for i in 0..len {
            rref[i] = 0xABu8;
        }

        let handle =
            crate::io::iommu::api::map_rref_slice_for_device(rref, &device, DmaDirection::ToDevice)
                .expect("map_rref_slice_for_device failed");
        let _iova = handle.iova();
        // Unmap and recover RRef
        let rref = handle.unmap().expect("unmap failed");
        assert_eq!(rref[0], 0xABu8);
    }
}
