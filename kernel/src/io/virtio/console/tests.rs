use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::*;
use crate::io::virtio::{TransportType, VirtioDeviceType, VirtioTransport};

struct NoopTransport;

impl VirtioTransport for NoopTransport {
    fn device_type(&self) -> VirtioDeviceType {
        VirtioDeviceType::Console
    }

    fn get_status(&self) -> u8 {
        0
    }

    fn set_status(&mut self, _status: u8) {}

    fn get_device_features_low(&self) -> u32 {
        0
    }

    fn get_device_features_high(&self) -> u32 {
        0
    }

    fn set_driver_features_low(&mut self, _features: u32) {}

    fn set_driver_features_high(&mut self, _features: u32) {}

    fn get_num_queues(&self) -> u16 {
        2
    }

    fn select_queue(&mut self, _queue_index: u16) {}

    fn get_queue_max_size(&self) -> u16 {
        VIRTQUEUE_MAX_SIZE
    }

    fn set_queue_size(&mut self, _size: u16) {}

    fn is_queue_ready(&self) -> bool {
        false
    }

    fn enable_queue(&mut self) {}

    fn disable_queue(&mut self) {}

    fn set_queue_desc_addr(&mut self, _addr: u64) {}

    fn set_queue_avail_addr(&mut self, _addr: u64) {}

    fn set_queue_used_addr(&mut self, _addr: u64) {}

    fn notify_queue(&mut self, _queue_index: u16) {}

    fn get_notify_addr(&mut self, _queue_index: u16) -> Option<u64> {
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

    fn write_config_u8(&mut self, _offset: usize, _value: u8) {}

    fn write_config_u16(&mut self, _offset: usize, _value: u16) {}

    fn write_config_u32(&mut self, _offset: usize, _value: u32) {}

    fn transport_type(&self) -> TransportType {
        TransportType::Mmio
    }
}

#[test_case]
fn test_console_device_creation() {
    let dev = VirtioConsoleDevice::new(Box::new(NoopTransport));
    assert!(!dev.is_ready());
    assert_eq!(dev.config().cols, 80);
    assert_eq!(dev.config().rows, 24);
}

#[test_case]
fn test_console_write_not_ready() {
    let dev = VirtioConsoleDevice::new(Box::new(NoopTransport));
    let result = dev.write_bytes(b"hello");
    assert_eq!(result, Err(ConsoleError::NotReady));
}

#[test_case]
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

    let mut dev = VirtioConsoleDevice::new(Box::new(NoopTransport));
    dev.tx_queue = Some(Arc::new(crate::sync::PoisonLock::new(vq)));
    dev.ready.store(true, Ordering::Release);

    // Writing empty data should succeed immediately
    let result = dev.write_bytes(b"");
    assert_eq!(result, Ok(()));
}

#[test_case]
fn test_console_read_no_data() {
    let dev = VirtioConsoleDevice::new(Box::new(NoopTransport));
    // No RX queue set up, should return None
    assert!(dev.read_bytes().is_none());
}

#[test_case]
fn test_console_config_default() {
    let config = VirtioConsoleConfig::default();
    assert_eq!(config.cols, 80);
    assert_eq!(config.rows, 24);
    assert_eq!(config.max_nr_ports, 1);
}

#[test_case]
fn test_console_error_variants() {
    assert_ne!(ConsoleError::NotReady, ConsoleError::IoError);
    assert_ne!(ConsoleError::QueueFull, ConsoleError::Unsupported);
}

#[test_case]
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
