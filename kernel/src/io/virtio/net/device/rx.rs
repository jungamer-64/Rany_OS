use super::*;
use crate::net::obs::{
    counters,
    trace::{self, NetEventKind, NetLayer},
};

const MAX_RX_COMPLETIONS_PER_PASS: usize = 256;

impl VirtioNetDevice {
    /// パケットを受信（非同期）
    pub fn recv_async<'a>(&'a self, buffer: &'a mut [u8]) -> RecvFuture<'a> {
        RecvFuture {
            device: self,
            buffer,
            submitted: false,
            desc_idx: 0,
            dma_len: 0,
            dma_iova: None,
            pool_bounce_buffer: None,
        }
    }

    /// ゼロコピーパケット受信（設計書 6.2準拠）
    ///
    /// Mempoolから割り当てられたバッファに直接受信し、
    /// PacketRefとして返却する。
    pub fn recv_zero_copy(
        &self,
        pool: &'static crate::net::datapath::mempool::Mempool,
    ) -> ZeroCopyRecvFuture<'_> {
        ZeroCopyRecvFuture {
            device: self,
            pool,
            packet: None,
            submitted: false,
            desc_idx: 0,
            dma_len: 0,
            dma_iova: None,
            pool_bounce_buffer: None,
        }
    }

    /// RXキュー完了を処理し、パケットをスタックに渡す
    pub(super) fn process_rx_completions(&self) {
        for (q_idx_pair, rx_queue) in self.rx_queues.iter().enumerate() {
            let inner = rx_queue.inner.lock().unwrap_or_else(|e| e.into_inner());

            let mut processed = 0usize;
            // LOOP_PROOF: mode=condition; reason=RX completion loop is capped per pass and exits on empty queue or MAX_RX_COMPLETIONS_PER_PASS.;
            while processed < MAX_RX_COMPLETIONS_PER_PASS {
                let Some((desc_idx, len)) = inner.poll_complete() else {
                    break;
                };
                self.rx_packets.fetch_add(1, Ordering::Relaxed);
                self.rx_bytes.fetch_add(len, Ordering::Relaxed);
                trace::push_event(NetLayer::Driver, NetEventKind::Rx, "virtio rx completion");
                processed += 1;

                // IoScheduler path: completion belongs to a pending IoRequest.
                if let Some(handler) = get_poll_handler(self.virtio_index) {
                    if let Some((io_id, requested_bytes)) = handler.take_pending_rx(desc_idx) {
                        // Reclaim descriptor
                        inner.free_desc_chain(desc_idx);

                        // Fix: Also remove from tracker to avoid leaking PacketRef
                        let tracker = &self.core.rx_trackers[q_idx_pair];
                        let _inflight = tracker.take(desc_idx);
                        
                        let payload_len = (len as usize).saturating_sub(VirtioNetHeader::SIZE);
                        let payload_cap = requested_bytes.saturating_sub(VirtioNetHeader::SIZE);
                        let completed = core::cmp::min(payload_len, payload_cap);
                        
                        let device_id = crate::io::io_scheduler::DeviceId::VirtioNet {
                            index: self.virtio_index,
                        };
                        let bridge = crate::io::io_scheduler::hybrid_coordinator().interrupt_bridge();
                        bridge.handle_interrupt(device_id, &[(io_id, crate::io::io_scheduler::IoResult::Success(completed))]);
                        continue;
                    }
                }

                // Core tracker path
                let tracker = &self.core.rx_trackers[q_idx_pair];
                if let Some(inflight) = tracker.take(desc_idx) {
                    inner.free_desc_chain(desc_idx);
                    self.complete_rx_packetref(rx_queue, desc_idx, len, inflight);
                    continue;
                }

                // Fallback for legacy or unknown
                log::warn!("[VIRTIO-NET] Received completion for unknown desc {}", desc_idx);
                inner.free_desc_chain(desc_idx);
                counters::global().record_drop();
            }
        }
    }

    /// PacketRef ZeroCopy RX完了: IOMMUアンマップ + ブリッジ転送 + 再ポスト
    pub(super) fn complete_rx_packetref(
        &self,
        rx_queue: &NetVirtQueue,
        _desc_idx: u16,
        len: u32,
        mut inflight: virtio_driver::net::RxInflight,
    ) {
        // Unmap IOMMU mapping if it was active
        if let (Some(iova), Some(device_id)) = (inflight.iommu_iova, &self.iommu_device_id) {
            let _ =
                crate::io::iommu::api::unmap_for_device(device_id, iova, inflight.iommu_map_len);
        }

        let header_size = core::mem::size_of::<VirtioNetHeader>();
        let payload_len = (len as usize).saturating_sub(header_size);

        // Security: Set temporary length to read VirtIO header and verify checksum offload.
        inflight.packet.set_len(len as usize);
        let data = inflight.packet.data();
        if data.len() >= header_size {
            // SAFETY: VirtioNetHeader is a packed POD struct.
            let header = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const VirtioNetHeader) };
            if (header.flags & VirtioNetHeader::F_DATA_VALID) != 0 {
                let meta = inflight.packet.meta_mut();
                meta.set_l4_csum_verified();
                meta.set_ip_csum_verified();
            }
        }

        trace::push_event(
            NetLayer::Driver,
            NetEventKind::Rx,
            "virtio zero-copy rx packetref",
        );

        // Pass PacketRef to bridge for zero-copy processing (prefer interface-aware path).
        if let Some(if_id) = self
            .net_if_id()
            .or_else(|| crate::net::runtime::bridge::lookup_if_by_virtio_index(self.virtio_index))
        {
            crate::net::runtime::bridge::process_received_packet_zero_copy_for_interface(
                if_id,
                inflight.packet,
                header_size,
                payload_len,
            );
        } else {
            crate::net::runtime::bridge::process_received_packet_zero_copy(
                inflight.packet,
                header_size,
                payload_len,
            );
        }

        // Re-post a new packet if needed
        if let Ok(inner) = rx_queue.inner.lock() {
            let q_idx = self.rx_queues.iter().position(|q| core::ptr::eq(q, rx_queue)).unwrap_or(0);
            self.core.try_post_rx_packet(self, (q_idx * 2) as u16, &inner).ok();
        }
    }
}
