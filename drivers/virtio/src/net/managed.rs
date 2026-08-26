use super::device::VirtioNetDevice as CoreNetDevice;
use super::{
    InflightTracker, NetDmaPurpose, NetRuntime, NetVirtQueue as CoreNetVirtQueue, TxInflight,
    VirtioNetError, VirtioNetHeader,
};
use crate::defs::{VringAvailHeader, VringDesc, VringUsedHeader, status};
use crate::dma::VirtioDmaBuffer;
use crate::transport::VirtioTransport;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::num::NonZeroU16;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use exorust_sync::{IrqPoisonLock, PoisonLock};
use kernel_api::netdev::{
    NET_RX_FLAG_IP_CSUM_VERIFIED, NET_RX_FLAG_L4_CSUM_VERIFIED, NetDeviceInfo, NetPortStats,
    TxLeaseId,
};
use kernel_api::resource::net::PacketByteCount;

const DEFAULT_MTU: u32 = 1500;

pub struct ManagedNetVirtQueue {
    inner: IrqPoisonLock<CoreNetVirtQueue>,
    dma_buffer: Option<VirtioDmaBuffer>,
}

unsafe impl Send for ManagedNetVirtQueue {}
unsafe impl Sync for ManagedNetVirtQueue {}

impl ManagedNetVirtQueue {
    #[allow(clippy::too_many_arguments)]
    /// # Panics
    ///
    /// Panics if `size` is not a supported power of two or any required vring
    /// pointer is null.
    pub unsafe fn new(
        index: u16,
        size: u16,
        desc_table: *mut VringDesc,
        avail_ring: *mut VringAvailHeader,
        used_ring: *mut VringUsedHeader,
        dma_buffer: Option<VirtioDmaBuffer>,
        tx_headers: Option<*mut VirtioNetHeader>,
        tx_header_dma_base: Option<u64>,
        features: u64,
    ) -> Self {
        let vq_inner = unsafe {
            crate::core::VirtQueue::new(index, size, desc_table, avail_ring, used_ring, features)
        }
        .expect("[VIRTIO-NET] failed to init core virtqueue");

        let net_vq_core =
            unsafe { CoreNetVirtQueue::new(vq_inner, tx_header_dma_base, tx_headers) };

        Self {
            inner: IrqPoisonLock::new(net_vq_core),
            dma_buffer,
        }
    }

    pub(crate) fn with_core<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&CoreNetVirtQueue) -> R,
    {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        f(&guard)
    }

    pub fn queue_index(&self) -> u16 {
        self.with_core(|inner| inner.vq.queue_index())
    }

    pub fn max_tx_segments(&self) -> u16 {
        self.with_core(|inner| inner.vq.queue_size().saturating_sub(1))
    }

    pub fn notify(&self, transport: &dyn VirtioTransport) {
        self.with_core(|inner| inner.notify(transport));
    }

    pub fn set_interrupts_enabled(&self, enabled: bool) {
        self.with_core(|inner| inner.set_interrupts_enabled(enabled));
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
    pub fn add_tx_buffer_zero_copy_with_header(
        &self,
        phys_addr: u64,
        data_len: usize,
        header: VirtioNetHeader,
    ) -> Result<u16, VirtioNetError> {
        self.with_core(|inner| unsafe { inner.add_tx_buffer(&header, phys_addr, data_len) })
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
    pub fn add_tx_buffer_zero_copy(
        &self,
        phys_addr: u64,
        data_len: usize,
    ) -> Result<u16, VirtioNetError> {
        self.add_tx_buffer_zero_copy_with_header(phys_addr, data_len, VirtioNetHeader::new_tx())
    }

    /// # Errors
    ///
    /// Returns an error if the iterator is empty, does not match
    /// `segment_count`, exceeds the negotiated queue capacity, or descriptors
    /// cannot be acquired.
    pub fn add_tx_segments<I>(
        &self,
        segment_count: usize,
        segments: I,
        header: VirtioNetHeader,
    ) -> Result<u16, VirtioNetError>
    where
        I: Iterator<Item = (u64, PacketByteCount)>,
    {
        self.with_core(|inner| unsafe {
            inner.add_tx_buffer_segments(&header, segment_count, segments)
        })
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
    pub fn add_rx_buffer_zero_copy(
        &self,
        phys_addr: u64,
        buffer_len: usize,
    ) -> Result<u16, VirtioNetError> {
        self.with_core(|inner| unsafe { inner.add_rx_buffer(phys_addr, buffer_len) })
    }

    pub fn poll_used_one(&self) -> Option<(u16, u32)> {
        self.with_core(CoreNetVirtQueue::poll_complete)
    }

    pub fn free_desc_chain(&self, head: u16) {
        self.with_core(|inner| inner.free_desc_chain(head));
    }

    pub fn has_pending(&self) -> bool {
        self.with_core(|inner| inner.vq.has_pending())
    }

    pub fn available_descriptors(&self) -> u16 {
        self.with_core(|inner| inner.available_descriptors())
    }

    pub fn queue_dma(&self) -> Option<&VirtioDmaBuffer> {
        self.dma_buffer.as_ref()
    }
}

pub struct VirtioNetDevice {
    transport: Arc<dyn VirtioTransport>,
    runtime: Arc<dyn NetRuntime>,
    core: CoreNetDevice,
    net_if_id: PoisonLock<Option<u16>>,
    rx_queues: Vec<ManagedNetVirtQueue>,
    tx_queues: Vec<ManagedNetVirtQueue>,
    queue_msix_table: Option<u16>,
    initialized: AtomicBool,
    link_up: AtomicBool,
    rx_packets: AtomicU32,
    rx_bytes: AtomicU32,
    tx_packets: AtomicU32,
    tx_bytes: AtomicU32,
}

unsafe impl Send for VirtioNetDevice {}
unsafe impl Sync for VirtioNetDevice {}

impl VirtioNetDevice {
    pub fn new(
        transport: Box<dyn VirtioTransport>,
        runtime: Arc<dyn NetRuntime>,
        queue_msix_table: Option<u16>,
    ) -> Self {
        Self {
            transport: Arc::from(transport),
            runtime,
            core: CoreNetDevice::new(),
            net_if_id: PoisonLock::new(None),
            rx_queues: Vec::new(),
            tx_queues: Vec::new(),
            queue_msix_table,
            initialized: AtomicBool::new(false),
            link_up: AtomicBool::new(false),
            rx_packets: AtomicU32::new(0),
            rx_bytes: AtomicU32::new(0),
            tx_packets: AtomicU32::new(0),
            tx_bytes: AtomicU32::new(0),
        }
    }

    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    pub fn init(&mut self) -> Result<(), VirtioNetError> {
        if let Err(err) = self.core.init(self.transport.as_ref()) {
            self.runtime.log(
                log::Level::Error,
                format_args!("virtio-net feature negotiation failed: {err:?}"),
            );
            return Err(err.into());
        }
        if let Err(err) = self.setup_queues() {
            self.runtime.log(
                log::Level::Error,
                format_args!("virtio-net queue setup failed: {err:?}"),
            );
            return Err(err);
        }
        self.set_interrupts_enabled_all(true);
        self.transport.add_status(status::VIRTIO_STATUS_DRIVER_OK);

        self.link_up.store(
            self.core.link_up(self.transport.as_ref()),
            Ordering::Release,
        );

        for rx_queue in &self.rx_queues {
            rx_queue.notify(self.transport.as_ref());
        }

        self.initialized.store(true, Ordering::Release);
        Ok(())
    }

    pub fn ack_interrupt(&self) {
        let status = self.transport.get_interrupt_status();
        self.transport.ack_interrupt(status);
    }

    pub fn handle_interrupt(&self) {
        self.runtime.schedule_interrupt();
    }

    pub fn process_interrupt_deferred(&self) {
        self.refresh_link_state();
        self.process_rx_completions();
        self.process_tx_completions();
    }

    pub fn refill_rx_queues(&self) {
        for (pair_idx, rx_queue) in self.rx_queues.iter().enumerate() {
            let count = rx_queue.with_core(|inner| {
                self.core
                    .refill_rx_queue(self.runtime.as_ref(), pair_idx as u16, inner)
            });
            if count > 0 {
                rx_queue.notify(self.transport.as_ref());
            }
        }
    }

    pub fn first_rx_queue(&self) -> Option<&ManagedNetVirtQueue> {
        self.rx_queues.first()
    }

    pub fn first_tx_queue(&self) -> Option<&ManagedNetVirtQueue> {
        self.tx_queues.first()
    }

    pub fn mac_address(&self) -> [u8; 6] {
        self.core.config.mac
    }

    pub fn transport(&self) -> &dyn VirtioTransport {
        self.transport.as_ref()
    }

    pub fn queue_pairs(&self) -> u16 {
        self.core.get_pair_count() as u16
    }

    pub fn max_tx_segments(&self) -> NonZeroU16 {
        self.tx_queues
            .iter()
            .map(ManagedNetVirtQueue::max_tx_segments)
            .min()
            .and_then(NonZeroU16::new)
            .unwrap_or(NonZeroU16::MIN)
    }

    pub fn mtu(&self) -> u32 {
        let mtu = self.core.config.mtu as u32;
        if mtu == 0 { DEFAULT_MTU } else { mtu }
    }

    pub fn set_net_if_id(&self, if_id: u16) {
        *self.net_if_id.lock().unwrap_or_else(|e| e.into_inner()) = Some(if_id);
    }

    pub fn net_if_id(&self) -> Option<u16> {
        *self.net_if_id.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Submit a validated DMA segment stream without allocating an adapter
    /// descriptor vector.
    ///
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the device cannot accept
    /// the operation.
    pub fn enqueue_send_segments<I>(
        &self,
        lease_id: TxLeaseId,
        segment_count: usize,
        segments: I,
    ) -> Result<(), VirtioNetError>
    where
        I: Iterator<Item = (u64, PacketByteCount)>,
    {
        let Some(tx_queue) = self.tx_queues.first() else {
            return Err(VirtioNetError::NotInitialized);
        };

        match tx_queue.add_tx_segments(segment_count, segments, VirtioNetHeader::new_tx()) {
            Ok(desc_idx) => {
                if let Some(tracker) = self.core.tx_trackers.get(0) {
                    tracker
                        .put(desc_idx, TxInflight { lease_id })
                        .map_err(|_| VirtioNetError::DeviceError)?;
                }
                tx_queue.notify(self.transport.as_ref());
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    pub fn set_interrupts_enabled_all(&self, enabled: bool) {
        for queue in &self.rx_queues {
            queue.set_interrupts_enabled(enabled);
        }
        for queue in &self.tx_queues {
            queue.set_interrupts_enabled(enabled);
        }
    }

    /// Revokes device access before releasing any RX or TX in-flight state.
    pub fn quiesce(&self) {
        self.initialized.store(false, Ordering::Release);
        self.link_up.store(false, Ordering::Release);
        self.set_interrupts_enabled_all(false);
        self.transport.reset();
        core::sync::atomic::fence(Ordering::SeqCst);
        for tracker in &self.core.rx_trackers {
            tracker.clear();
        }
        for tracker in &self.core.tx_trackers {
            tracker.clear();
        }
    }

    pub fn is_ready(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    pub fn link_up(&self) -> bool {
        self.link_up.load(Ordering::Acquire)
    }

    pub fn publish_link_state(&self) {
        self.runtime.update_link(self.link_up());
    }

    fn refresh_link_state(&self) {
        let current = self.core.link_up(self.transport.as_ref());
        let previous = self.link_up.swap(current, Ordering::AcqRel);
        if previous != current {
            self.publish_link_state();
        }
    }

    pub fn net_port_stats(&self) -> NetPortStats {
        NetPortStats {
            tx_packets: self.tx_packets.load(Ordering::Relaxed) as u64,
            rx_packets: self.rx_packets.load(Ordering::Relaxed) as u64,
            tx_errors: 0,
            rx_errors: 0,
            initialized: self.is_ready(),
        }
    }

    pub fn info_snapshot(&self, port_id: kernel_api::netdev::NetPortId) -> NetDeviceInfo {
        let mac = self.mac_address();
        NetDeviceInfo {
            port_id,
            if_id: self.net_if_id(),
            driver_name: "virtio-net",
            queue_pairs: self.queue_pairs(),
            max_tx_segments: self.max_tx_segments(),
            mtu: self.mtu(),
            mac: kernel_api::netdev::MacAddress::from_octets(
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            ),
            flags: kernel_api::netdev::NETDEV_FLAG_ADMIN_UP
                | kernel_api::netdev::NETDEV_FLAG_HEALTHY
                | if self.link_up() {
                    kernel_api::netdev::NETDEV_FLAG_LINK_UP
                } else {
                    0
                },
        }
    }

    fn setup_queues(&mut self) -> Result<(), VirtioNetError> {
        for pair_idx in 0..self.core.get_pair_count() {
            let rx_index = (pair_idx * 2) as u16;
            let rx_queue = self.setup_single_queue(rx_index)?;
            self.rx_queues.push(rx_queue);

            let tx_index = rx_index + 1;
            let tx_queue = self.setup_single_queue(tx_index)?;
            self.tx_queues.push(tx_queue);
        }
        Ok(())
    }

    fn setup_single_queue(
        &mut self,
        queue_index: u16,
    ) -> Result<ManagedNetVirtQueue, VirtioNetError> {
        let (queue_size, layout) = match self
            .core
            .prepare_queue(self.transport.as_ref(), queue_index)
        {
            Ok(prepared) => prepared,
            Err(err) => {
                self.runtime.log(
                    log::Level::Error,
                    format_args!(
                        "virtio-net queue {queue_index} unavailable (device queues={}): {err:?}",
                        self.transport.get_num_queues()
                    ),
                );
                return Err(err.into());
            }
        };
        let buffer = self
            .runtime
            .alloc_dma(layout.total_size, NetDmaPurpose::QueueMemory)?;
        let dma_base = buffer.device_address();
        let ptr = buffer.as_ptr();

        let desc_table = ptr as *mut VringDesc;
        let avail_ring = unsafe { ptr.add(layout.desc_size) } as *mut VringAvailHeader;
        let used_ring = unsafe { ptr.add(layout.used_offset) } as *mut VringUsedHeader;

        let (tx_headers, tx_header_dma_base) = if (queue_index % 2) == 1 {
            let header_ptr = unsafe { ptr.add(layout.header_offset) as *mut VirtioNetHeader };
            let header_dma_base = dma_base + layout.header_offset as u64;
            (Some(header_ptr), Some(header_dma_base))
        } else {
            (None, None)
        };

        if (queue_index % 2) == 0 {
            self.core.rx_trackers.push(InflightTracker::new(queue_size));
        } else {
            self.core.tx_trackers.push(InflightTracker::new(queue_size));
        }

        if let Some(table_index) = self.queue_msix_table {
            self.transport
                .configure_msix(queue_index, table_index)
                .map_err(|_| VirtioNetError::DeviceError)?;
        }

        self.core.commit_queue(
            self.transport.as_ref(),
            queue_index,
            dma_base,
            dma_base + layout.desc_size as u64,
            dma_base + layout.used_offset as u64,
        );

        let queue = unsafe {
            ManagedNetVirtQueue::new(
                queue_index,
                queue_size,
                desc_table,
                avail_ring,
                used_ring,
                Some(buffer),
                tx_headers,
                tx_header_dma_base,
                self.transport.get_device_features(),
            )
        };

        if (queue_index % 2) == 0 {
            let pair_idx = queue_index / 2;
            queue.with_core(|inner| {
                let _ = self
                    .core
                    .refill_rx_queue(self.runtime.as_ref(), pair_idx, inner);
            });
        }

        Ok(queue)
    }

    fn process_rx_completions(&self) {
        for (pair_idx, rx_queue) in self.rx_queues.iter().enumerate() {
            let queue_index = rx_queue.queue_index();

            let mut processed = 0usize;
            // LOOP_PROOF: mode=condition; reason=RX completion work is bounded by the maximum queue size per deferred pass.;
            while processed < super::MAX_VIRTIO_COMPLETIONS_PER_PASS {
                let Some((desc_idx, len)) = rx_queue.poll_used_one() else {
                    break;
                };
                processed += 1;
                let Some(tracker) = self.core.rx_trackers.get(pair_idx) else {
                    rx_queue.free_desc_chain(desc_idx);
                    continue;
                };

                let Some(inflight) = tracker.take(desc_idx) else {
                    rx_queue.free_desc_chain(desc_idx);
                    continue;
                };

                self.rx_packets.fetch_add(1, Ordering::Relaxed);
                self.rx_bytes.fetch_add(len, Ordering::Relaxed);

                let header_len = VirtioNetHeader::SIZE;
                let region = inflight.buffer.writable_region();
                let packet_len = len as usize;
                if packet_len > region.writable_len() || packet_len < header_len {
                    rx_queue.free_desc_chain(desc_idx);
                    continue;
                }
                // SAFETY: the used-ring completion transfers device write
                // authority back to the driver, and the checked completion
                // length proves the fixed header is initialized.
                let header = unsafe {
                    core::ptr::read_unaligned(region.cpu_ptr().cast::<VirtioNetHeader>())
                };
                let flags = if (header.flags & VirtioNetHeader::F_DATA_VALID) != 0 {
                    NET_RX_FLAG_IP_CSUM_VERIFIED | NET_RX_FLAG_L4_CSUM_VERIFIED
                } else {
                    0
                };
                let payload_len = packet_len.saturating_sub(header_len);
                self.runtime.receive_packet(
                    queue_index,
                    inflight.buffer,
                    header_len,
                    payload_len,
                    flags,
                );
                rx_queue.free_desc_chain(desc_idx);
                rx_queue.with_core(|inner| {
                    let _ =
                        self.core
                            .try_post_rx_packet(self.runtime.as_ref(), pair_idx as u16, inner);
                });
            }
        }
    }

    fn process_tx_completions(&self) {
        for (pair_idx, tx_queue) in self.tx_queues.iter().enumerate() {
            let queue_index = tx_queue.queue_index();

            let mut processed = 0usize;
            // LOOP_PROOF: mode=condition; reason=TX completion work is bounded by the maximum queue size per deferred pass.;
            while processed < super::MAX_VIRTIO_COMPLETIONS_PER_PASS {
                let Some((desc_idx, len)) = tx_queue.poll_used_one() else {
                    break;
                };
                processed += 1;
                let Some(tracker) = self.core.tx_trackers.get(pair_idx) else {
                    tx_queue.free_desc_chain(desc_idx);
                    continue;
                };

                let Some(inflight) = tracker.take(desc_idx) else {
                    tx_queue.free_desc_chain(desc_idx);
                    continue;
                };

                self.tx_packets.fetch_add(1, Ordering::Relaxed);
                self.tx_bytes.fetch_add(len, Ordering::Relaxed);
                self.runtime
                    .transmit_complete(queue_index, inflight.lease_id);

                tx_queue.free_desc_chain(desc_idx);
            }
        }
    }
}
