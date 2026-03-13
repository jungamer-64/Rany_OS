use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::*;
use crate::io::virtio::{TransportType, VIRTQUEUE_MAX_SIZE, VirtioDeviceType, VirtioTransport};

fn align_up(value: usize, align: usize) -> usize {
    if align == 0 {
        value
    } else {
        (value + align - 1) & !(align - 1)
    }
}

#[derive(Debug)]
struct NoopTransport;

fn test_device() -> crate::io::iommu::types::DeviceId {
    let device = crate::io::iommu::types::DeviceId::new(0, 0, 0x10, 0);
    crate::io::iommu::testkit::fixtures::ensure_test_intel_iommu_device(device);
    device
}

impl VirtioTransport for NoopTransport {
    fn device_type(&self) -> VirtioDeviceType {
        VirtioDeviceType::Input
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
fn test_virtio_input_event_size() {
    assert_eq!(core::mem::size_of::<VirtioInputEvent>(), 8);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_virtio_input_event_default() {
    let event = VirtioInputEvent::default();
    assert_eq!(event.type_, 0);
    assert_eq!(event.code, 0);
    assert_eq!(event.value, 0);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_virtio_input_device_new() {
    let dev = VirtioInputDevice::new(Box::new(NoopTransport), test_device());
    assert!(!dev.is_ready());
    assert!(dev.event_queue.is_none());
    assert!(dev.status_queue.is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_virtio_input_device_new_with_device() {
    use crate::io::iommu::types::DeviceId;
    let device_id = DeviceId::new(0, 0, 0, 0);
    crate::io::iommu::testkit::fixtures::ensure_test_intel_iommu_device(device_id);
    let dev = VirtioInputDevice::new_with_device(Box::new(NoopTransport), device_id);
    assert!(!dev.is_ready());
    assert_eq!(dev.iommu_device_id, device_id);
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

    // Queue should be empty now
    assert!(vq.alloc_desc().is_none());

    // Free one and reallocate
    vq.free_desc(allocated[3]);
    let realloc = vq.alloc_desc().expect("should reallocate");
    assert_eq!(realloc, allocated[3]);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_config_select_constants() {
    assert_eq!(config_select::VIRTIO_INPUT_CFG_UNSET, 0x00);
    assert_eq!(config_select::VIRTIO_INPUT_CFG_ID_NAME, 0x01);
    assert_eq!(config_select::VIRTIO_INPUT_CFG_ID_SERIAL, 0x02);
    assert_eq!(config_select::VIRTIO_INPUT_CFG_ID_DEVIDS, 0x03);
    assert_eq!(config_select::VIRTIO_INPUT_CFG_PROP_BITS, 0x10);
    assert_eq!(config_select::VIRTIO_INPUT_CFG_EV_BITS, 0x11);
    assert_eq!(config_select::VIRTIO_INPUT_CFG_ABS_INFO, 0x12);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_query_config_returns_none_for_zero_size() {
    let dev = VirtioInputDevice::new(Box::new(NoopTransport), test_device());
    // NoopTransport returns 0 for all reads, so size=0 => None
    let result = dev.query_config(config_select::VIRTIO_INPUT_CFG_ID_NAME, 0);
    assert!(result.is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_device_name_returns_none_for_noop() {
    let dev = VirtioInputDevice::new(Box::new(NoopTransport), test_device());
    assert!(dev.device_name().is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_set_event_handler() {
    let dev = VirtioInputDevice::new(Box::new(NoopTransport), test_device());

    fn my_handler(_event: VirtioInputEvent) {}

    dev.set_event_handler(my_handler);
    let handler = dev.event_handler.lock().unwrap_or_else(|e| e.into_inner());
    assert!(handler.is_some());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_align_up() {
    assert_eq!(align_up(0, 4), 0);
    assert_eq!(align_up(1, 4), 4);
    assert_eq!(align_up(4, 4), 4);
    assert_eq!(align_up(5, 4), 8);
    assert_eq!(align_up(4096, 4096), 4096);
    assert_eq!(align_up(4097, 4096), 8192);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_input_error_display() {
    use alloc::format;
    assert_eq!(format!("{}", InputError::NotReady), "Device not ready");
    assert_eq!(format!("{}", InputError::IoError), "I/O error");
    assert_eq!(format!("{}", InputError::QueueFull), "Queue full");
}
