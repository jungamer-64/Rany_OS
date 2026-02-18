use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::*;
use crate::io::virtio::{TransportType, VirtioDeviceType, VirtioTransport};
use crate::fs::page_cluster_buffer::PageClusterBuffer;
use crate::mm::types::PAGE_SIZE_4K;
use crate::mm::phys::frame_allocator::{alloc_contiguous_frames, dealloc_contiguous_frames};
use x86_64::PhysAddr;

struct NoopTransport;

impl VirtioTransport for NoopTransport {
    fn device_type(&self) -> VirtioDeviceType {
        VirtioDeviceType::Block
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
        1
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
fn test_submit_read_uses_dma_addr() {
    // Setup small virtqueue memory regions
    let queue_size: u16 = 8;
    let mut descs = vec![VringDesc::default(); queue_size as usize];
    let desc_ptr = descs.as_mut_ptr();

    let mut avail = vec![0u16; 2 + queue_size as usize];
    let avail_ptr = avail.as_mut_ptr() as *mut VringAvail;

    let used_bytes = core::mem::size_of::<VringUsed>()
        + (queue_size as usize) * core::mem::size_of::<VringUsedElem>();
    let mut used_mem = vec![0u8; used_bytes];
    let used_ptr = used_mem.as_mut_ptr() as *mut VringUsed;

    let vq = unsafe {
        VirtQueue::new(queue_size, desc_ptr, avail_ptr, used_ptr, None, 0, None, false)
    };

    let mut dev = VirtioBlkDevice::new(Box::new(NoopTransport));
    dev.queues.push(Arc::new(spin::Mutex::new(vq)));
    dev.ready.store(true, Ordering::Release);
    dev.config.capacity = 1024;

    // Initialize wakers vector
    let mut w = dev.pending_wakers.lock();
    w.resize(VIRTQUEUE_MAX_SIZE as usize * dev.queues.len(), None);
    drop(w);

    // Skip test if contiguous frames unavailable
    let frames_needed = 1usize;
    if let Some(start_phys) = alloc_contiguous_frames(frames_needed) {
        let real_size = PAGE_SIZE_4K as usize;
        let buf = PageClusterBuffer::new_from_phys(start_phys.as_u64(), real_size)
            .expect("new_from_phys failed");
        let dma = buf.dma_info().expect("dma_info missing");

        let head = dev
            .submit_read(0, dma.phys_addr, 512u32, 0)
            .expect("submit_read failed");

        // Inspect descriptor chain: header -> data -> status
        let header_desc = unsafe { *desc_ptr.add(head as usize) };
        let data_idx = header_desc.next as usize;
        let data_desc = unsafe { *desc_ptr.add(data_idx) };

        assert_eq!(data_desc.addr, dma.phys_addr);
        assert_eq!(data_desc.len, 512u32);
        assert!((data_desc.flags & vring_flags::VRING_DESC_F_WRITE) != 0);

        // Clean up allocated frames
        dealloc_contiguous_frames(PhysAddr::new(start_phys.as_u64()), frames_needed);
    } else {
        eprintln!("Skipping test: contiguous frames not available");
    }
}

#[test_case]
fn test_submit_write_uses_dma_addr() {
    // Setup small virtqueue memory regions
    let queue_size: u16 = 8;
    let mut descs = vec![VringDesc::default(); queue_size as usize];
    let desc_ptr = descs.as_mut_ptr();

    let mut avail = vec![0u16; 2 + queue_size as usize];
    let avail_ptr = avail.as_mut_ptr() as *mut VringAvail;

    let used_bytes = core::mem::size_of::<VringUsed>()
        + (queue_size as usize) * core::mem::size_of::<VringUsedElem>();
    let mut used_mem = vec![0u8; used_bytes];
    let used_ptr = used_mem.as_mut_ptr() as *mut VringUsed;

    let vq = unsafe {
        VirtQueue::new(queue_size, desc_ptr, avail_ptr, used_ptr, None, 0, None, false)
    };

    let mut dev = VirtioBlkDevice::new(Box::new(NoopTransport));
    dev.queues.push(Arc::new(spin::Mutex::new(vq)));
    dev.ready.store(true, Ordering::Release);
    dev.config.capacity = 1024;

    // Initialize wakers vector
    let mut w = dev.pending_wakers.lock();
    w.resize(VIRTQUEUE_MAX_SIZE as usize * dev.queues.len(), None);
    drop(w);

    // Skip test if contiguous frames unavailable
    let frames_needed = 1usize;
    if let Some(start_phys) = alloc_contiguous_frames(frames_needed) {
        let real_size = PAGE_SIZE_4K as usize;
        let buf = PageClusterBuffer::new_from_phys(start_phys.as_u64(), real_size)
            .expect("new_from_phys failed");
        let dma = buf.dma_info().expect("dma_info missing");

        let head = dev
            .submit_write(0, dma.phys_addr, 512u32, 0)
            .expect("submit_write failed");

        // Inspect descriptor chain: header -> data -> status
        let header_desc = unsafe { *desc_ptr.add(head as usize) };
        let data_idx = header_desc.next as usize;
        let data_desc = unsafe { *desc_ptr.add(data_idx) };

        assert_eq!(data_desc.addr, dma.phys_addr);
        assert_eq!(data_desc.len, 512u32);
        // For write, device reads from buffer (no VRING_DESC_F_WRITE flag)
        assert_eq!(data_desc.flags & vring_flags::VRING_DESC_F_WRITE, 0);

        // Clean up allocated frames
        dealloc_contiguous_frames(PhysAddr::new(start_phys.as_u64()), frames_needed);
    } else {
        eprintln!("Skipping test: contiguous frames not available");
    }
}
