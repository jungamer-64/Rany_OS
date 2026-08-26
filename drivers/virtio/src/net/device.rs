// ============================================================================
// drivers/virtio/src/net/device.rs - Shared VirtIO Network Device Logic
// ============================================================================

use crate::net::features::*;
use crate::net::*;
use crate::transport::TransportError;
use crate::transport::VirtioTransport;

const MAX_VIRTIO_RX_REFILLS_PER_PASS: usize = 128;

#[derive(Debug, Default)]
pub struct VirtioNetDevice {
    pub config: VirtioNetConfig,
    pub stats: VirtioNetStats,
    accepted_features: u64,
    /// TX inflight trackers (per queue)
    pub tx_trackers: alloc::vec::Vec<InflightTracker<TxInflight>>,
    /// RX inflight trackers (per queue)
    pub rx_trackers: alloc::vec::Vec<InflightTracker<RxInflight>>,
}

impl VirtioNetDevice {
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize the network device.
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    pub fn init(&mut self, transport: &dyn VirtioTransport) -> Result<(), TransportError> {
        // 1. Reset
        transport.reset();

        // 2. Acknowledge
        transport.add_status(crate::defs::status::VIRTIO_STATUS_ACKNOWLEDGE);

        // 3. Driver
        transport.add_status(crate::defs::status::VIRTIO_STATUS_DRIVER);

        // 4. Negotiate features
        self.accepted_features = self.negotiate_features(transport);

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
        let accepted_features = device_features
            & (crate::core::VIRTIO_F_VERSION_1
                | VIRTIO_F_ACCESS_PLATFORM
                | VIRTIO_NET_F_MAC
                | VIRTIO_NET_F_STATUS
                | VIRTIO_NET_F_CSUM
                | VIRTIO_NET_F_MTU
                | VIRTIO_NET_F_MQ);

        transport.set_driver_features(accepted_features);
        accepted_features
    }

    pub fn read_config(&mut self, transport: &dyn VirtioTransport) {
        if self.accepted_features & VIRTIO_NET_F_MAC != 0 {
            let mut mac = [0u8; 6];
            for (i, octet) in mac.iter_mut().enumerate() {
                *octet = transport.read_config_u8(i);
            }
            self.config.mac = mac;
        }

        let advertised_pairs = if self.accepted_features & VIRTIO_NET_F_MQ != 0 {
            transport.read_config_u16(8)
        } else {
            1
        };
        self.config.max_queues = Self::active_queue_pairs(
            self.accepted_features,
            advertised_pairs,
            transport.get_num_queues(),
        );

        if self.accepted_features & VIRTIO_NET_F_MTU != 0 {
            self.config.mtu = transport.read_config_u16(10);
        }
    }

    pub fn link_up(&self, transport: &dyn VirtioTransport) -> bool {
        if self.accepted_features & VIRTIO_NET_F_STATUS == 0 {
            return true;
        }
        transport.read_config_u16(6) & VIRTIO_NET_S_LINK_UP != 0
    }

    /// Get the number of queue pairs to use.
    pub fn get_pair_count(&self) -> usize {
        self.config.max_queues as usize
    }

    fn active_queue_pairs(features: u64, advertised_pairs: u16, device_queues: u16) -> u16 {
        let requested_pairs = if features & VIRTIO_NET_F_MQ != 0 {
            advertised_pairs.max(1)
        } else {
            1
        };
        let available_pairs = (device_queues / 2).max(1);
        requested_pairs.min(available_pairs)
    }

    /// Calculate queue size based on device maximum.
    pub fn calculate_queue_size(&self, max_size: u16) -> u16 {
        max_size.min(256)
    }

    /// Prepare a queue for initialization.
    /// Returns the negotiated queue size and memory layout.
    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
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

    /// Process completions on a TX queue.
    pub fn process_tx_completions<F>(
        &self,
        _runtime: &dyn NetRuntime,
        queue_index: u16,
        vq: &NetVirtQueue,
        mut handler: F,
    ) -> usize
    where
        F: FnMut(u16, TxInflight, u32),
    {
        let tracker = match self.tx_trackers.get(queue_index as usize) {
            Some(t) => t,
            None => return 0,
        };

        let mut count = 0;
        let mut processed = 0usize;
        // LOOP_PROOF: mode=condition; reason=TX completion loop is capped per pass and exits on empty queue or MAX_VIRTIO_COMPLETIONS_PER_PASS.;
        while processed < MAX_VIRTIO_COMPLETIONS_PER_PASS {
            let Some((desc_idx, len)) = vq.poll_complete() else {
                break;
            };
            processed += 1;
            if let Some(inflight) = tracker.take(desc_idx) {
                handler(desc_idx, inflight, len);
                vq.free_desc_chain(desc_idx);
                count += 1;
            }
        }
        count
    }

    /// Process completions on an RX queue.
    pub fn process_rx_completions<F>(
        &self,
        queue_index: u16,
        vq: &NetVirtQueue,
        mut handler: F,
    ) -> usize
    where
        F: FnMut(u16, RxInflight, u32),
    {
        let tracker = match self.rx_trackers.get(queue_index as usize) {
            Some(t) => t,
            None => return 0,
        };

        let mut count = 0;
        let mut processed = 0usize;
        // LOOP_PROOF: mode=condition; reason=RX completion loop is capped per pass and exits on empty queue or MAX_VIRTIO_COMPLETIONS_PER_PASS.;
        while processed < MAX_VIRTIO_COMPLETIONS_PER_PASS {
            let Some((desc_idx, len)) = vq.poll_complete() else {
                break;
            };
            processed += 1;
            if let Some(inflight) = tracker.take(desc_idx) {
                handler(desc_idx, inflight, len);
                vq.free_desc_chain(desc_idx);
                count += 1;
            }
        }
        count
    }

    /// Refill an RX queue with buffers from the runtime.
    pub fn refill_rx_queue(
        &self,
        runtime: &dyn NetRuntime,
        queue_index: u16,
        vq: &NetVirtQueue,
    ) -> usize {
        let mut count = 0;

        // LOOP_PROOF: mode=condition; reason=Refill loop is capped per pass and exits on descriptor exhaustion, allocation failure, or MAX_VIRTIO_RX_REFILLS_PER_PASS.;
        while count < MAX_VIRTIO_RX_REFILLS_PER_PASS && vq.available_descriptors() > 0 {
            match self.try_post_rx_packet(runtime, queue_index, vq) {
                Ok(true) => count += 1,
                Ok(false) => break, // Out of packets or queue full
                Err(_) => break,
            }
        }
        count
    }

    /// Try to allocate and post a single RX packet to a queue.
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the device cannot accept the operation.
    pub fn try_post_rx_packet(
        &self,
        runtime: &dyn NetRuntime,
        queue_index: u16,
        vq: &NetVirtQueue,
    ) -> Result<bool, VirtioNetError> {
        let tracker = match self.rx_trackers.get(queue_index as usize) {
            Some(t) => t,
            None => return Ok(false),
        };

        if vq.available_descriptors() == 0 {
            return Ok(false);
        }

        let buffer = match runtime.lease_rx_buffer() {
            Some(buffer) => buffer,
            None => return Ok(false),
        };

        let region = buffer.writable_region();
        let len = region.writable_len();
        let device_addr = region.device_addr();

        match unsafe { vq.add_rx_buffer(device_addr, len) } {
            Ok(desc_idx) => {
                tracker
                    .put(desc_idx, RxInflight { buffer })
                    .map_err(|_| VirtioNetError::DeviceError)?;
                Ok(true)
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::VirtioNetDevice;
    use crate::net::features::VIRTIO_NET_F_MQ;

    #[test]
    fn queue_pairs_ignore_mq_configuration_without_the_negotiated_feature() {
        assert_eq!(VirtioNetDevice::active_queue_pairs(0, 8, 17), 1);
    }

    #[test]
    fn queue_pairs_do_not_exceed_the_transport_queue_set() {
        assert_eq!(
            VirtioNetDevice::active_queue_pairs(VIRTIO_NET_F_MQ, 2, 3),
            1
        );
        assert_eq!(
            VirtioNetDevice::active_queue_pairs(VIRTIO_NET_F_MQ, 8, 9),
            4
        );
    }
}
