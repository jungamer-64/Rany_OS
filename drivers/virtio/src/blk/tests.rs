use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use exorust_sync::PoisonLock;
use kernel_api::abi::driver::PackedPciLocation;

use super::*;
use crate::{TransportType, VIRTQUEUE_MAX_SIZE, VirtioDeviceType, VirtioTransport};

#[derive(Debug)]
struct NoopTransport;

fn test_device() -> PackedPciLocation {
    PackedPciLocation::new(0, 0, 0x11, 0)
}

impl VirtioTransport for NoopTransport {
    fn device_type(&self) -> VirtioDeviceType {
        VirtioDeviceType::Block
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
        1
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

fn make_test_queue(queue_index: u16, queue_size: u16) -> (VirtQueue, *mut VringDesc) {
    let mut descs = alloc::vec![VringDesc::default(); queue_size as usize];
    let desc_ptr = descs.as_mut_ptr();
    let desc_ptr_raw = desc_ptr;

    let mut avail = alloc::vec![0u16; 2 + queue_size as usize];
    let avail_ptr = avail.as_mut_ptr() as *mut VringAvail;

    let used_bytes = core::mem::size_of::<VringUsed>()
        + (queue_size as usize) * core::mem::size_of::<VringUsedElem>();
    let mut used_mem = alloc::vec![0u8; used_bytes];
    let used_ptr = used_mem.as_mut_ptr() as *mut VringUsed;

    let queue = unsafe {
        VirtQueue::new(
            queue_index,
            queue_size,
            desc_ptr,
            avail_ptr,
            used_ptr,
            None,
            0,
        )
    }
    .expect("virtqueue");

    core::mem::forget(descs);
    core::mem::forget(avail);
    core::mem::forget(used_mem);

    (queue, desc_ptr_raw)
}

fn make_ready_device() -> (VirtioBlkDevice, *mut VringDesc) {
    let queue_size = 8u16;
    let (queue, desc_ptr) = make_test_queue(0, queue_size);
    let mut dev = VirtioBlkDevice::new(Box::new(NoopTransport), test_device());
    dev.queues.push(Arc::new(PoisonLock::new(queue)));
    dev.pending_wakers.push(PoisonLock::new({
        let mut wakers = Vec::with_capacity(queue_size as usize);
        wakers.resize_with(queue_size as usize, || None);
        wakers
    }));
    dev.inflight_dma.push(PoisonLock::new({
        let mut dmas = Vec::with_capacity(queue_size as usize);
        dmas.resize_with(queue_size as usize, || None);
        dmas
    }));
    dev.ready.store(true, Ordering::Release);
    dev.core.capacity = 1024;
    (dev, desc_ptr)
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_submit_read_uses_dma_addr() {
    let (dev, desc_ptr) = make_ready_device();
    let dma_addr = 0x1234_5000u64;

    let head = dev
        .submit_read(0, dma_addr, 512, 0)
        .expect("submit_read failed");

    let header_desc = unsafe { *desc_ptr.add(head as usize) };
    let data_idx = header_desc.next as usize;
    let data_desc = unsafe { *desc_ptr.add(data_idx) };

    assert_eq!(data_desc.addr, dma_addr);
    assert_eq!(data_desc.len, 512);
    assert_ne!(data_desc.flags & vring_flags::VRING_DESC_F_WRITE, 0);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_submit_write_uses_dma_addr() {
    let (dev, desc_ptr) = make_ready_device();
    let dma_addr = 0x5678_9000u64;

    let head = dev
        .submit_write(0, dma_addr, 512, 0)
        .expect("submit_write failed");

    let header_desc = unsafe { *desc_ptr.add(head as usize) };
    let data_idx = header_desc.next as usize;
    let data_desc = unsafe { *desc_ptr.add(data_idx) };

    assert_eq!(data_desc.addr, dma_addr);
    assert_eq!(data_desc.len, 512);
    assert_eq!(data_desc.flags & vring_flags::VRING_DESC_F_WRITE, 0);
}
