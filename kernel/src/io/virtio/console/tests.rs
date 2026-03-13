use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::*;
use crate::io::virtio::{TransportType, VIRTQUEUE_MAX_SIZE, VirtioDeviceType, VirtioTransport};

#[derive(Debug)]
struct NoopTransport;

fn test_device() -> crate::io::iommu::types::DeviceId {
    let device = crate::io::iommu::types::DeviceId::new(0, 0, 0x20, 0);
    crate::io::iommu::testkit::fixtures::ensure_test_intel_iommu_device(device);
    device
}

impl VirtioTransport for NoopTransport {
    fn device_type(&self) -> VirtioDeviceType {
        VirtioDeviceType::Console
    }

    fn get_status(&self) -> u8 {
        0
    }

    fn set_status(&self, _status: u8) {}

    fn get_device_features_low(&self) -> u32 {
        0
    }

    fn get_device_features_high(&self) -> u32 {
        0
    }

    fn set_driver_features_low(&self, _features: u32) {}

    fn set_driver_features_high(&self, _features: u32) {}

    fn get_num_queues(&self) -> u16 {
        2
    }

    fn select_queue(&self, _queue_index: u16) {}

    fn get_queue_max_size(&self) -> u16 {
        VIRTQUEUE_MAX_SIZE
    }

    fn set_queue_size(&self, _size: u16) {}

    fn is_queue_ready(&self) -> bool {
        false
    }

    fn enable_queue(&self) {}

    fn disable_queue(&self) {}

    fn set_queue_desc_addr(&self, _addr: u64) {}

    fn set_queue_avail_addr(&self, _addr: u64) {}

    fn set_queue_used_addr(&self, _addr: u64) {}

    fn notify_queue(&self, _queue_index: u16) {}

    fn get_notify_addr(&self, _queue_index: u16) -> Option<u64> {
        None
    }

    fn get_interrupt_status(&self) -> u32 {
        0
    }

    fn ack_interrupt(&self, _status: u32) {}

    fn read_config_u8(&self, _offset: usize) -> u8 {
        0
    }

    fn read_config_u16(&self, _offset: usize) -> u16 {
        0
    }

    fn read_config_u32(&self, _offset: usize) -> u32 {
        0
    }

    fn write_config_u8(&self, _offset: usize, _value: u8) {}

    fn write_config_u16(&self, _offset: usize, _value: u16) {}

    fn write_config_u32(&self, _offset: usize, _value: u32) {}

    fn transport_type(&self) -> TransportType {
        TransportType::Mmio
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_console_device_creation() {
    let dev = VirtioConsoleDevice::new(Box::new(NoopTransport), test_device());
    assert!(!dev.is_ready());
    assert_eq!(dev.config().cols, 80);
    assert_eq!(dev.config().rows, 24);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_console_write_not_ready() {
    let dev = VirtioConsoleDevice::new(Box::new(NoopTransport), test_device());
    let result = dev.write_bytes(b"hello");
    assert_eq!(result, Err(ConsoleError::NotReady));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_console_write_empty_data() {
    // Create a device that is "ready" with a manually constructed TX queue
    let queue_size: u16 = 8;
    let mut descs = alloc::vec![VringDesc::default(); queue_size as usize];
    let desc_ptr = descs.as_mut_ptr();

    let mut avail = alloc::vec![0u16; 2 + queue_size as usize];
    let avail_ptr = avail.as_mut_ptr() as *mut VringAvail;

    let used_bytes = core::mem::size_of::<VringUsed>()
        + (queue_size as usize) * core::mem::size_of::<VringUsedElem>();
    let mut used_mem = alloc::vec![0u8; used_bytes];
    let used_ptr = used_mem.as_mut_ptr() as *mut VringUsed;

    let vq = unsafe { VirtQueue::new(queue_size, desc_ptr, avail_ptr, used_ptr, None, 1, 0) };

    let mut dev = VirtioConsoleDevice::new(Box::new(NoopTransport), test_device());
    dev.tx_queue = Some(Arc::new(crate::sync::PoisonLock::new(vq)));
    dev.ready.store(true, Ordering::Release);

    // Writing empty data should succeed immediately
    let result = dev.write_bytes(b"");
    assert_eq!(result, Ok(()));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_console_read_no_data() {
    let dev = VirtioConsoleDevice::new(Box::new(NoopTransport), test_device());
    // No RX queue set up, should return None
    assert!(dev.read_bytes().is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_console_config_default() {
    let config = VirtioConsoleConfig::default();
    assert_eq!(config.cols, 80);
    assert_eq!(config.rows, 24);
    assert_eq!(config.max_nr_ports, 1);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_console_error_variants() {
    assert_ne!(ConsoleError::NotReady, ConsoleError::IoError);
    assert_ne!(ConsoleError::QueueFull, ConsoleError::Unsupported);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_virtqueue_alloc_free_desc() {
    let queue_size: u16 = 8;
    let mut descs = alloc::vec![VringDesc::default(); queue_size as usize];
    let desc_ptr = descs.as_mut_ptr();

    let mut avail = alloc::vec![0u16; 2 + queue_size as usize];
    let avail_ptr = avail.as_mut_ptr() as *mut VringAvail;

    let used_bytes = core::mem::size_of::<VringUsed>()
        + (queue_size as usize) * core::mem::size_of::<VringUsedElem>();
    let mut used_mem = alloc::vec![0u8; used_bytes];
    let used_ptr = used_mem.as_mut_ptr() as *mut VringUsed;

    let vq = unsafe { VirtQueue::new(queue_size, desc_ptr, avail_ptr, used_ptr, None, 0, 0) };

    // Allocate all descriptors
    let mut allocated = Vec::new();
    for _ in 0..queue_size {
        let idx = vq.alloc_desc().expect("should allocate");
        allocated.push(idx);
    }

    // Next allocation should fail
    assert!(vq.alloc_desc().is_none());

    // Free one and reallocate
    vq.free_desc(allocated[0]);
    let idx = vq.alloc_desc().expect("should allocate after free");
    assert_eq!(idx, allocated[0]);
}
