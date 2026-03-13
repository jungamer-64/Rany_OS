use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::*;
use crate::fs::page_cluster_buffer::PageClusterBuffer;
use crate::io::dma::{DeviceDmaContext, DmaDirection as DeviceDmaDirection};
use crate::io::iommu::testkit::fixtures::ensure_test_intel_iommu_device;
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use crate::io::virtio::{TransportType, VIRTQUEUE_MAX_SIZE, VirtioDeviceType, VirtioTransport};
use crate::mm::phys::frame_allocator::{alloc_contiguous_frames, dealloc_contiguous_frames};
use crate::mm::types::PAGE_SIZE_4K;
use x86_64::PhysAddr;

#[derive(Debug)]
struct NoopTransport;

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

#[test_case]
fn test_submit_read_uses_dma_addr() {
    let iommu_device_id = IommuDeviceId::new(0, 0, 0x20, 0);
    ensure_test_intel_iommu_device(iommu_device_id);

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

    let vq = unsafe { VirtQueue::new(queue_size, desc_ptr, avail_ptr, used_ptr, None, 0, 0) };

    let mut dev = VirtioBlkDevice::new(Box::new(NoopTransport), iommu_device_id);
    dev.queues
        .push(Arc::new(crate::sync::IrqPoisonLock::new(vq)));
    dev.pending_wakers.push(crate::sync::IrqPoisonLock::new({
        let mut wakers = Vec::with_capacity(queue_size as usize);
        wakers.resize_with(queue_size as usize, || None);
        wakers
    }));
    dev.inflight_dma.push(crate::sync::IrqPoisonLock::new({
        let mut dmas = Vec::with_capacity(queue_size as usize);
        dmas.resize_with(queue_size as usize, || None);
        dmas
    }));
    dev.ready.store(true, Ordering::Release);
    dev.core.capacity = 1024;

    // Skip test if contiguous frames unavailable
    let frames_needed = 1usize;
    if let Some(start_phys) = alloc_contiguous_frames(frames_needed) {
        let real_size = PAGE_SIZE_4K as usize;
        let buf = PageClusterBuffer::new_from_phys(start_phys.as_u64(), real_size)
            .expect("new_from_phys failed");
        let dma = buf.dma_info().expect("dma_info missing");
        let mapping = DeviceDmaContext::for_attached_device(iommu_device_id)
            .map_physical_range(
                PhysAddr::new(dma.phys_addr),
                real_size,
                DeviceDmaDirection::Bidirectional,
            )
            .expect("map_physical_range failed");

        let head = dev
            .submit_read(0, mapping.device_addr(), 512u32, 0)
            .expect("submit_read failed");

        // Inspect descriptor chain: header -> data -> status
        let header_desc = unsafe { *desc_ptr.add(head as usize) };
        let data_idx = header_desc.next as usize;
        let data_desc = unsafe { *desc_ptr.add(data_idx) };

        assert_eq!(data_desc.addr, mapping.device_addr());
        assert_eq!(data_desc.len, 512u32);
        assert!((data_desc.flags & vring_flags::VRING_DESC_F_WRITE) != 0);

        drop(mapping);
        // Clean up allocated frames
        dealloc_contiguous_frames(PhysAddr::new(start_phys.as_u64()), frames_needed);
    } else {
        eprintln!("Skipping test: contiguous frames not available");
    }
}

#[test_case]
fn test_submit_write_uses_dma_addr() {
    let iommu_device_id = IommuDeviceId::new(0, 0, 0x21, 0);
    ensure_test_intel_iommu_device(iommu_device_id);

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

    let vq = unsafe { VirtQueue::new(queue_size, desc_ptr, avail_ptr, used_ptr, None, 0, 0) };

    let mut dev = VirtioBlkDevice::new(Box::new(NoopTransport), iommu_device_id);
    dev.queues
        .push(Arc::new(crate::sync::IrqPoisonLock::new(vq)));
    dev.pending_wakers.push(crate::sync::IrqPoisonLock::new({
        let mut wakers = Vec::with_capacity(queue_size as usize);
        wakers.resize_with(queue_size as usize, || None);
        wakers
    }));
    dev.inflight_dma.push(crate::sync::IrqPoisonLock::new({
        let mut dmas = Vec::with_capacity(queue_size as usize);
        dmas.resize_with(queue_size as usize, || None);
        dmas
    }));
    dev.ready.store(true, Ordering::Release);
    dev.core.capacity = 1024;

    // Skip test if contiguous frames unavailable
    let frames_needed = 1usize;
    if let Some(start_phys) = alloc_contiguous_frames(frames_needed) {
        let real_size = PAGE_SIZE_4K as usize;
        let buf = PageClusterBuffer::new_from_phys(start_phys.as_u64(), real_size)
            .expect("new_from_phys failed");
        let dma = buf.dma_info().expect("dma_info missing");
        let mapping = DeviceDmaContext::for_attached_device(iommu_device_id)
            .map_physical_range(
                PhysAddr::new(dma.phys_addr),
                real_size,
                DeviceDmaDirection::Bidirectional,
            )
            .expect("map_physical_range failed");

        let head = dev
            .submit_write(0, mapping.device_addr(), 512u32, 0)
            .expect("submit_write failed");

        // Inspect descriptor chain: header -> data -> status
        let header_desc = unsafe { *desc_ptr.add(head as usize) };
        let data_idx = header_desc.next as usize;
        let data_desc = unsafe { *desc_ptr.add(data_idx) };

        assert_eq!(data_desc.addr, mapping.device_addr());
        assert_eq!(data_desc.len, 512u32);
        // For write, device reads from buffer (no VRING_DESC_F_WRITE flag)
        assert_eq!(data_desc.flags & vring_flags::VRING_DESC_F_WRITE, 0);

        drop(mapping);
        // Clean up allocated frames
        dealloc_contiguous_frames(PhysAddr::new(start_phys.as_u64()), frames_needed);
    } else {
        eprintln!("Skipping test: contiguous frames not available");
    }
}
