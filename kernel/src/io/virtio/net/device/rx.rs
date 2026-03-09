use super::*;
use crate::net::obs::trace::{self, NetEventKind, NetLayer};

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
            let q_idx = (q_idx_pair * 2) as u16;

            let _ = self.core.process_rx_completions(
                self,
                q_idx,
                &rx_queue.inner.lock().unwrap_or_else(|e| e.into_inner()),
                |desc_idx, mut inflight, len| {
                    self.rx_packets.fetch_add(1, Ordering::Relaxed);
                    self.rx_bytes.fetch_add(len, Ordering::Relaxed);
                    trace::push_event(NetLayer::Driver, NetEventKind::Rx, "virtio rx completion");

                    // Cleanup DMA for ALL paths if mapped
                    if let (Some(iova), Some(device_id)) =
                        (inflight.iommu_iova, &self.iommu_device_id)
                    {
                        let _ = crate::io::iommu::api::unmap_for_device(
                            device_id,
                            iova,
                            inflight.iommu_map_len,
                        );
                        inflight.iommu_iova = None; // Avoid double unmap
                    }

                    // IoScheduler path: completion belongs to a pending IoRequest.
                    if let Some(handler) = get_poll_handler(self.virtio_index) {
                        if let Some((io_id, requested_bytes)) = handler.take_pending_rx(desc_idx) {
                            let payload_len = (len as usize).saturating_sub(VirtioNetHeader::SIZE);
                            let payload_cap = requested_bytes.saturating_sub(VirtioNetHeader::SIZE);
                            let completed = core::cmp::min(payload_len, payload_cap);

                            let device_id = crate::io::io_scheduler::DeviceId::VirtioNet {
                                index: self.virtio_index,
                            };
                            let bridge =
                                crate::io::io_scheduler::hybrid_coordinator().interrupt_bridge();
                            bridge.handle_interrupt(
                                device_id,
                                &[(io_id, crate::io::io_scheduler::IoResult::Success(completed))],
                            );
                            return;
                        }
                    }

                    // Standard path: Use NetRuntime callback (implemented in mod.rs)
                    let header_size = core::mem::size_of::<VirtioNetHeader>();
                    let payload_len = (len as usize).saturating_sub(header_size);

                    // Security: Set temporary length to read VirtIO header
                    inflight.packet.set_len(len as usize);
                    let data = inflight.packet.data();
                    if data.len() >= header_size {
                        let header = unsafe {
                            core::ptr::read_unaligned(data.as_ptr() as *const VirtioNetHeader)
                        };
                        if (header.flags & VirtioNetHeader::F_DATA_VALID) != 0 {
                            let meta = inflight.packet.meta_mut();
                            meta.set_l4_csum_verified();
                            meta.set_ip_csum_verified();
                        }
                    }

                    self.receive_packet(q_idx, inflight.packet, header_size, payload_len);

                    // Re-post a new packet to the queue
                    if let Ok(inner) = rx_queue.inner.lock() {
                        self.core.try_post_rx_packet(self, q_idx, &inner).ok();
                    }
                },
            );
        }
    }
}
