// ============================================================================
// drivers/virtio/src/net/device.rs - Shared VirtIO Network Device Logic
// ============================================================================

use crate::net::features::*;
use crate::net::*;
use crate::transport::TransportError;
use crate::transport::VirtioTransport;

const MAX_VIRTIO_COMPLETIONS_PER_PASS: usize = 256;
const MAX_VIRTIO_RX_REFILLS_PER_PASS: usize = 128;

#[derive(Debug, Default)]
pub struct VirtioNetDevice {
    pub config: VirtioNetConfig,
    pub stats: VirtioNetStats,
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
        let accepted_features = device_features
            & (crate::core::VIRTIO_F_VERSION_1
                | VIRTIO_NET_F_MAC
                | VIRTIO_NET_F_STATUS
                | VIRTIO_NET_F_CSUM
                | VIRTIO_NET_F_MTU
                | VIRTIO_NET_F_MQ);

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

    /// Process completions on a TX queue.
    pub fn process_tx_completions<F>(
        &self,
        runtime: &dyn NetRuntime,
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
                // If IOMMU was used, unmap it before returning the packet
                if let Some(iova) = inflight.iommu_iova {
                    runtime.unmap_dma(iova, inflight.iommu_map_len);
                }

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
        runtime: &dyn NetRuntime,
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
                // If IOMMU was used, unmap it
                if let Some(iova) = inflight.iommu_iova {
                    runtime.unmap_dma(iova, inflight.iommu_map_len);
                }

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

        let packet = match runtime.alloc_packet() {
            Some(p) => p,
            None => return Ok(false),
        };

        let len = packet.capacity();
        let (device_addr, iova) = runtime.map_packet(&packet, NetDmaDirection::FromDevice)?;

        match unsafe { vq.add_rx_buffer(device_addr, len) } {
            Ok(desc_idx) => {
                tracker.put(
                    desc_idx,
                    RxInflight {
                        packet,
                        iommu_iova: iova,
                        iommu_map_len: len as u64,
                    },
                );
                Ok(true)
            }
            Err(e) => {
                if let Some(iova) = iova {
                    runtime.unmap_dma(iova, len as u64);
                }
                Err(e)
            }
        }
    }
}
