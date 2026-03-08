// ============================================================================
// drivers/virtio/src/net/device.rs - Shared VirtIO Network Device Logic
// ============================================================================

use crate::transport::VirtioTransport;
use crate::transport::TransportError;
use crate::net::*;
use crate::net::features::*;

/// Shared VirtIO Network Device logic.
#[derive(Debug, Default)]
pub struct VirtioNetDevice {
    pub config: VirtioNetConfig,
    pub stats: VirtioNetStats,
}

impl VirtioNetDevice {
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize the network device.
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
            VIRTIO_NET_F_MAC |
            VIRTIO_NET_F_STATUS |
            VIRTIO_NET_F_CSUM |
            VIRTIO_NET_F_MTU |
            VIRTIO_NET_F_MQ
        );

        transport.set_driver_features(accepted_features);
        accepted_features
    }

    pub fn read_config(&mut self, transport: &dyn VirtioTransport) {
        let mut mac = [0u8; 6];
        for i in 0..6 {
            mac[i] = transport.read_config_u8(i);
        }
        self.config.mac = mac;
        self.config.max_queues = transport.read_config_u16(8);
        self.config.mtu = transport.read_config_u16(10);
    }

    /// Get the number of queue pairs to use.
    pub fn get_pair_count(&self) -> usize {
        core::cmp::max(self.config.max_queues as usize, 1)
    }

    /// Calculate queue size based on device maximum.
    pub fn calculate_queue_size(&self, max_size: u16) -> u16 {
        max_size.min(256)
    }

    /// Prepare a queue for initialization.
    /// Returns the negotiated queue size and memory layout.
    pub fn prepare_queue(
        &self,
        transport: &dyn VirtioTransport,
        queue_index: u16,
    ) -> Result<(u16, QueueMemoryLayout), TransportError> {
        transport.select_queue(queue_index);
        let max_size = transport.get_queue_max_size();
        if max_size == 0 {
            return Err(TransportError::DeviceError);
        }

        let queue_size = self.calculate_queue_size(max_size);
        transport.set_queue_size(queue_size);

        let layout = QueueMemoryLayout::calculate(queue_index, queue_size);
        Ok((queue_size, layout))
    }

    /// Commit queue addresses to the transport.
    pub fn commit_queue(
        &self,
        transport: &dyn VirtioTransport,
        _queue_index: u16,
        desc_addr: u64,
        avail_addr: u64,
        used_addr: u64,
    ) {
        transport.set_queue_desc_addr(desc_addr);
        transport.set_queue_avail_addr(avail_addr);
        transport.set_queue_used_addr(used_addr);
        transport.enable_queue();
    }
}
