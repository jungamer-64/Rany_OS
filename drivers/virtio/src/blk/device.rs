// ============================================================================
// drivers/virtio/src/blk/device.rs - Shared VirtIO Block Device Logic
// ============================================================================

use crate::transport::VirtioTransport;
use crate::core::virtqueue::VirtQueue;
use crate::transport::TransportError;
use crate::blk::*;

/// Shared VirtIO Block Device logic.
#[derive(Debug, Default)]
pub struct VirtioBlkDevice {
    pub capacity: u64,
    pub size_max: u32,
    pub seg_max: u32,
    pub block_size: u32,
    pub features: u64,
    pub num_queues: u16,
}

impl VirtioBlkDevice {
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize the block device.
    pub fn init(&mut self, transport: &dyn VirtioTransport) -> Result<(), TransportError> {
        // 1. Reset
        transport.reset();

        // 2. Acknowledge
        transport.add_status(crate::defs::status::VIRTIO_STATUS_ACKNOWLEDGE);

        // 3. Driver
        transport.add_status(crate::defs::status::VIRTIO_STATUS_DRIVER);

        // 4. Negotiate features
        self.negotiate_features(transport);

        // 5. Features OK
        transport.add_status(crate::defs::status::VIRTIO_STATUS_FEATURES_OK);
        if (transport.get_status() & crate::defs::status::VIRTIO_STATUS_FEATURES_OK) == 0 {
            transport.add_status(crate::defs::status::VIRTIO_STATUS_FAILED);
            return Err(TransportError::DeviceError);
        }

        // 6. Read config
        self.read_config(transport);

        Ok(())
    }

    pub fn negotiate_features(&mut self, transport: &dyn VirtioTransport) -> u64 {
        let device_features = transport.get_device_features();
        let accepted_features = device_features & (
            crate::core::VIRTIO_F_VERSION_1 |
            crate::defs::VIRTIO_F_INDIRECT_DESC |
            VIRTIO_BLK_F_SIZE_MAX |
            VIRTIO_BLK_F_SEG_MAX |
            VIRTIO_BLK_F_GEOMETRY |
            VIRTIO_BLK_F_RO |
            VIRTIO_BLK_F_BLK_SIZE |
            VIRTIO_BLK_F_TOPOLOGY |
            VIRTIO_BLK_F_MQ
        );

        transport.set_driver_features(accepted_features);
        self.features = accepted_features;
        accepted_features
    }

    pub fn read_config(&mut self, transport: &dyn VirtioTransport) {
        self.capacity = transport.read_config_u64(0);
        self.size_max = transport.read_config_u32(8);
        self.seg_max = transport.read_config_u32(12);
        self.block_size = transport.read_config_u32(20);
        if self.block_size == 0 {
            self.block_size = 512;
        }
        if self.features & VIRTIO_BLK_F_MQ != 0 {
            self.num_queues = transport.read_config_u16(34);
        } else {
            self.num_queues = 1;
        }
    }

    pub fn build_request(
        &self,
        vq: &VirtQueue,
        _type: u32,
        _sector: u64,
        data_phys: u64,
        data_len: u32,
        header_phys: u64,
        status_phys: u64,
    ) -> Result<u16, BlockError> {
        let head = vq.alloc_desc().ok_or(BlockError::QueueFull)?;
        let data_idx = vq.alloc_desc().ok_or(BlockError::QueueFull)?;
        let status_idx = vq.alloc_desc().ok_or(BlockError::QueueFull)?;

        let d0 = vq.get_desc_mut(head);
        d0.addr = header_phys;
        d0.len = core::mem::size_of::<VirtioBlkReqHeader>() as u32;
        d0.flags = crate::defs::vring_flags::VRING_DESC_F_NEXT;
        d0.next = data_idx;

        let d1 = vq.get_desc_mut(data_idx);
        d1.addr = data_phys;
        d1.len = data_len;
        d1.flags = crate::defs::vring_flags::VRING_DESC_F_NEXT;
        if _type == VIRTIO_BLK_T_IN {
            d1.flags |= crate::defs::vring_flags::VRING_DESC_F_WRITE;
        }
        d1.next = status_idx;

        let d2 = vq.get_desc_mut(status_idx);
        d2.addr = status_phys;
        d2.len = 1;
        d2.flags = crate::defs::vring_flags::VRING_DESC_F_WRITE;
        d2.next = 0;

        unsafe { vq.submit_avail(head); }
        Ok(head)
    }

    pub fn build_request_indirect(
        &self,
        vq: &VirtQueue,
        _type: u32,
        _sector: u64,
        data_phys: u64,
        data_len: u32,
        header_phys: u64,
        status_phys: u64,
        indirect_table: *mut crate::defs::VringDesc,
        indirect_phys: u64,
    ) -> Result<u16, BlockError> {
        unsafe {
            let d0 = &mut *indirect_table;
            d0.addr = header_phys;
            d0.len = core::mem::size_of::<VirtioBlkReqHeader>() as u32;
            d0.flags = crate::defs::vring_flags::VRING_DESC_F_NEXT;
            d0.next = 1;

            let d1 = &mut *indirect_table.add(1);
            d1.addr = data_phys;
            d1.len = data_len;
            d1.flags = crate::defs::vring_flags::VRING_DESC_F_NEXT;
            if _type == VIRTIO_BLK_T_IN {
                d1.flags |= crate::defs::vring_flags::VRING_DESC_F_WRITE;
            }
            d1.next = 2;

            let d2 = &mut *indirect_table.add(2);
            d2.addr = status_phys;
            d2.len = 1;
            d2.flags = crate::defs::vring_flags::VRING_DESC_F_WRITE;
            d2.next = 0;
        }

        let head = vq.alloc_desc().ok_or(BlockError::QueueFull)?;
        let d = vq.get_desc_mut(head);
        d.addr = indirect_phys;
        d.len = (3 * core::mem::size_of::<crate::defs::VringDesc>()) as u32;
        d.flags = crate::defs::vring_flags::VRING_DESC_F_INDIRECT;
        d.next = 0;

        unsafe { vq.submit_avail(head); }
        Ok(head)
    }
}
