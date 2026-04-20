use super::device::VirtioNetDevice as CoreNetDevice;
use super::{
    InflightTracker, NetDmaPurpose, NetRuntime, NetVirtQueue as CoreNetVirtQueue, TxInflight,
    VirtioNetError, VirtioNetHeader,
};
use crate::defs::{VringAvailHeader, VringDesc, VringUsedHeader, status};
use crate::dma::VirtioDmaBuffer;
use crate::transport::VirtioTransport;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use core::task::Waker;
use exorust_sync::{IrqPoisonLock, PoisonLock};
use kernel_api::netdev::{NetDeviceInfo, NetPortStats, NetTxMeta, TxSubmission};

const DEFAULT_MTU: u32 = 1500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetCompletionKind {
    Rx,
    Tx,
}

pub type NetCompletionHandler = fn(u8, NetCompletionKind, u16, u32) -> bool;

pub struct ManagedNetVirtQueue {
    inner: IrqPoisonLock<CoreNetVirtQueue>,
    pending_wakers: PoisonLock<Vec<Waker>>,
    dma_buffer: Option<VirtioDmaBuffer>,
    completion_map: PoisonLock<BTreeMap<u16, u32>>,
}

unsafe impl Send for ManagedNetVirtQueue {}
unsafe impl Sync for ManagedNetVirtQueue {}

impl ManagedNetVirtQueue {
    #[allow(clippy::too_many_arguments)]
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
            pending_wakers: PoisonLock::new(Vec::new()),
            dma_buffer,
            completion_map: PoisonLock::new(BTreeMap::new()),
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

    pub fn notify(&self, transport: &dyn VirtioTransport) {
        self.with_core(|inner| inner.notify(transport));
    }

    pub fn set_interrupts_enabled(&self, enabled: bool) {
        self.with_core(|inner| inner.set_interrupts_enabled(enabled));
    }

    pub fn add_tx_buffer_zero_copy_with_header(
        &self,
        phys_addr: u64,
        data_len: usize,
        header: VirtioNetHeader,
    ) -> Result<u16, VirtioNetError> {
        self.with_core(|inner| unsafe { inner.add_tx_buffer(&header, phys_addr, data_len) })
    }

    pub fn add_tx_buffer_zero_copy(
        &self,
        phys_addr: u64,
        data_len: usize,
    ) -> Result<u16, VirtioNetError> {
        self.add_tx_buffer_zero_copy_with_header(phys_addr, data_len, VirtioNetHeader::new_tx())
    }

    pub fn add_tx_submission(
        &self,
        submission: TxSubmission<'_>,
        header: VirtioNetHeader,
    ) -> Result<u16, VirtioNetError> {
        self.with_core(|inner| unsafe { inner.add_tx_buffer_chain(&header, submission.segments()) })
    }

    pub fn add_rx_buffer_zero_copy(
        &self,
        phys_addr: u64,
        buffer_len: usize,
    ) -> Result<u16, VirtioNetError> {
        self.with_core(|inner| unsafe { inner.add_rx_buffer(phys_addr, buffer_len) })
    }

    pub fn process_used_with<F>(&self, mut on_complete: F) -> usize
    where
        F: FnMut(u16, u32),
    {
        let mut count = 0;
        {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            while let Some((desc_idx, len)) = inner.poll_complete() {
                self.completion_map
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(desc_idx, len);
                on_complete(desc_idx, len);
                count += 1;
            }
        }

        if count > 0 {
            self.wake_all();
        }

        count
    }

    pub fn process_used(&self) -> Vec<(u16, u32)> {
        let mut completed = Vec::new();
        let _ = self.process_used_with(|desc_idx, len| completed.push((desc_idx, len)));
        completed
    }

    pub fn register_waker(&self, waker: Waker) {
        let mut pending = self
            .pending_wakers
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if pending.iter().any(|existing| existing.will_wake(&waker)) {
            return;
        }
        pending.push(waker);
    }

    pub fn take_completion(&self, desc_idx: u16) -> Option<u32> {
        if let Some(len) = self
            .completion_map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&desc_idx)
        {
            return Some(len);
        }

        let _ = self.process_used();
        self.completion_map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&desc_idx)
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

    fn wake_all(&self) {
        let waiters = {
            let mut pending = self
                .pending_wakers
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            core::mem::take(&mut *pending)
        };

        for waker in waiters {
            waker.wake();
        }
    }
}

pub struct VirtioNetDevice {
    transport: Arc<dyn VirtioTransport>,
    runtime: Arc<dyn NetRuntime>,
    core: CoreNetDevice,
    virtio_index: u8,
    net_if_id: PoisonLock<Option<u16>>,
    rx_queues: Vec<ManagedNetVirtQueue>,
    tx_queues: Vec<ManagedNetVirtQueue>,
    completion_handler: PoisonLock<Option<NetCompletionHandler>>,
    initialized: AtomicBool,
    rx_packets: AtomicU32,
    rx_bytes: AtomicU32,
    tx_packets: AtomicU32,
    tx_bytes: AtomicU32,
}

unsafe impl Send for VirtioNetDevice {}
unsafe impl Sync for VirtioNetDevice {}

impl VirtioNetDevice {
    pub fn new(
        index: u8,
        transport: Box<dyn VirtioTransport>,
        runtime: Arc<dyn NetRuntime>,
    ) -> Self {
        Self {
            transport: Arc::from(transport),
            runtime,
            core: CoreNetDevice::new(),
            virtio_index: index,
            net_if_id: PoisonLock::new(None),
            rx_queues: Vec::new(),
            tx_queues: Vec::new(),
            completion_handler: PoisonLock::new(None),
            initialized: AtomicBool::new(false),
            rx_packets: AtomicU32::new(0),
            rx_bytes: AtomicU32::new(0),
            tx_packets: AtomicU32::new(0),
            tx_bytes: AtomicU32::new(0),
        }
    }

    pub fn init(&mut self) -> Result<(), VirtioNetError> {
        self.core.init(self.transport.as_ref())?;
        self.setup_queues()?;
        self.transport.add_status(status::VIRTIO_STATUS_DRIVER_OK);

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
        if let Some(runtime) = crate::net::virtio_net_runtime(self.virtio_index) {
            let _ = runtime.schedule_event(kernel_api::netdev::NetDriverEvent::Interrupt);
        }
    }

    pub fn process_interrupt_deferred(&self) {
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

    pub fn set_completion_handler(&self, handler: Option<NetCompletionHandler>) {
        *self
            .completion_handler
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = handler;
    }

    pub fn enqueue_send_submission(
        &self,
        submission: TxSubmission<'_>,
        _meta: NetTxMeta,
    ) -> Result<(), VirtioNetError> {
        let Some(tx_queue) = self.tx_queues.first() else {
            return Err(VirtioNetError::NotInitialized);
        };

        match tx_queue.add_tx_submission(submission, VirtioNetHeader::new_tx()) {
            Ok(desc_idx) => {
                if let Some(tracker) = self.core.tx_trackers.get(0) {
                    tracker.put(
                        desc_idx,
                        TxInflight {
                            lease_id: submission.lease_id(),
                        },
                    );
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

    pub fn is_ready(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
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
            mtu: self.mtu(),
            mac: kernel_api::netdev::MacAddress::from_octets(
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            ),
            flags: kernel_api::netdev::NETDEV_FLAG_HEALTHY
                | kernel_api::netdev::NETDEV_FLAG_LINK_UP,
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
        let (queue_size, layout) = self
            .core
            .prepare_queue(self.transport.as_ref(), queue_index)?;
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

            for (desc_idx, len) in rx_queue.process_used() {
                if self.handle_scheduler_completion(NetCompletionKind::Rx, desc_idx, len) {
                    rx_queue.free_desc_chain(desc_idx);
                    continue;
                }

                let Some(tracker) = self.core.rx_trackers.get(pair_idx) else {
                    rx_queue.free_desc_chain(desc_idx);
                    continue;
                };

                let Some(mut inflight) = tracker.take(desc_idx) else {
                    rx_queue.free_desc_chain(desc_idx);
                    continue;
                };

                if let Some(mapping) = inflight.dma_mapping.take() {
                    self.runtime.release_dma_mapping(mapping);
                }

                self.rx_packets.fetch_add(1, Ordering::Relaxed);
                self.rx_bytes.fetch_add(len, Ordering::Relaxed);

                let header_len = VirtioNetHeader::SIZE;
                let packet_len = core::cmp::min(len as usize, inflight.packet.capacity());
                inflight.packet.set_len(packet_len);
                if inflight.packet.data().len() >= header_len {
                    let header = unsafe {
                        core::ptr::read_unaligned(
                            inflight.packet.data().as_ptr() as *const VirtioNetHeader
                        )
                    };
                    if (header.flags & VirtioNetHeader::F_DATA_VALID) != 0 {
                        let meta = inflight.packet.meta_mut();
                        meta.set_l4_csum_verified();
                        meta.set_ip_csum_verified();
                    }
                }
                let payload_len = packet_len.saturating_sub(header_len);

                if let Some(runtime) = crate::net::virtio_net_runtime(self.virtio_index) {
                    let _ = runtime.submit_rx(
                        inflight.packet,
                        kernel_api::netdev::NetRxMeta {
                            queue_index,
                            header_len: header_len as u16,
                            payload_len: payload_len as u16,
                            flags: 0,
                        },
                    );
                } else {
                    self.runtime.receive_packet(
                        queue_index,
                        inflight.packet,
                        header_len,
                        payload_len,
                    );
                }

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

            for (desc_idx, len) in tx_queue.process_used() {
                if self.handle_scheduler_completion(NetCompletionKind::Tx, desc_idx, len) {
                    tx_queue.free_desc_chain(desc_idx);
                    continue;
                }

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

    fn handle_scheduler_completion(
        &self,
        kind: NetCompletionKind,
        desc_idx: u16,
        len: u32,
    ) -> bool {
        self.completion_handler
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map(|handler| handler(self.virtio_index, kind, desc_idx, len))
            .unwrap_or(false)
    }
}
