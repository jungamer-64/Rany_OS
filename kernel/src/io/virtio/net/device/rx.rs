use super::*;
use crate::net::obs::{
    counters,
    trace::{self, NetEventKind, NetLayer},
};

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
        for (q_idx, rx_queue) in self.rx_queues.iter().enumerate() {
            // Diagnostic: check raw used ring state
            let completions = rx_queue.process_used();
            for (desc_idx, len) in completions {
                self.rx_packets.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                trace::push_event(NetLayer::Driver, NetEventKind::Rx, "virtio rx completion");

                // IoScheduler path: completion belongs to a pending IoRequest.
                if let Some(handler) = get_poll_handler(self.virtio_index) {
                    if let Some((io_id, requested_bytes)) = handler.take_pending_rx(desc_idx) {
                        let result = if let Some(completion_len) = rx_queue.take_completion(desc_idx) {
                            let payload_len =
                                (completion_len as usize).saturating_sub(VirtioNetHeader::SIZE);
                            let payload_cap = requested_bytes.saturating_sub(VirtioNetHeader::SIZE);
                            let completed = core::cmp::min(payload_len, payload_cap);
                            crate::io::io_scheduler::IoResult::Success(completed)
                        } else {
                            log::warn!(
                                "[VIRTIO-NET] RX scheduler completion disappeared desc={}",
                                desc_idx
                            );
                            counters::global().record_error();
                            trace::push_event(
                                NetLayer::Driver,
                                NetEventKind::Error,
                                "virtio rx scheduler completion missing",
                            );
                            crate::io::io_scheduler::IoResult::Error(
                                crate::io::io_scheduler::IoError::DeviceError,
                            )
                        };
                        let device_id = crate::io::io_scheduler::DeviceId::VirtioNet {
                            index: self.virtio_index,
                        };
                        let bridge = crate::io::io_scheduler::hybrid_coordinator().interrupt_bridge();
                        bridge.handle_interrupt(device_id, &[(io_id, result)]);
                        continue;
                    }
                }

                if self.handle_legacy_rx_completion(rx_queue, q_idx, desc_idx, len) {
                    continue;
                }

                self.release_unknown_rx_completion(rx_queue, desc_idx);
            }
        }
    }

    /// PacketRef ZeroCopy RX完了: IOMMUアンマップ + ブリッジ転送 + 再ポスト
    pub(super) fn complete_rx_packetref(&self, rx_queue: &NetVirtQueue, desc_idx: u16, len: u32, inflight: RxPacketInflight) {
        // Unmap IOMMU mapping if it was active
        if let (Some(iova), Some(device_id)) = (inflight.iommu_iova, &self.iommu_device_id) {
            let _ = crate::io::iommu::api::unmap_for_device(device_id, iova, inflight.iommu_map_len);
        }

        let header_size = core::mem::size_of::<VirtioNetHeader>();
        let payload_len = (len as usize).saturating_sub(header_size);
        trace::push_event(NetLayer::Driver, NetEventKind::Rx, "virtio zero-copy rx packetref");

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

        // Re-post a new PacketRef buffer to the queue so we keep a steady supply
        match self.try_post_rx_packet(rx_queue) {
            Ok(true) => {}
            Ok(false) => {
                log::warn!("[VIRTIO-NET] OOM allocating replacement PacketRef");
                counters::global().record_drop();
                trace::push_event(
                    NetLayer::Driver,
                    NetEventKind::QueuePressure,
                    "virtio rx packetref repost oom",
                );
            }
            Err(_) => {
                counters::global().record_error();
                trace::push_event(
                    NetLayer::Driver,
                    NetEventKind::Error,
                    "virtio rx packetref repost failed",
                );
            }
        }
    }

    /// VBuf RX完了: IOMMUアンマップ + 受信完了 + ブリッジ転送 + 再ポスト
    pub(super) fn complete_rx_vbuf(
        &self,
        rx_queue: &NetVirtQueue,
        desc_idx: u16,
        len: u32,
        mut inflight: RxVbufInflight,
    ) {
        // Unmap IOMMU mapping if it was active
        if let (Some(iova), Some(device_id)) = (inflight.iommu_iova, &self.iommu_device_id) {
            let _ = crate::io::iommu::api::unmap_for_device(device_id, iova, inflight.iommu_map_len);
        }

        if let Err(e) = inflight.vbuf.complete_receive() {
            log::warn!("[VIRTIO-NET] failed to complete rx buffer {}: {}", desc_idx, e);
            counters::global().record_error();
            trace::push_event(
                NetLayer::Driver,
                NetEventKind::Error,
                "virtio rx complete_receive failed",
            );
            return;
        }

        let header_size = core::mem::size_of::<VirtioNetHeader>();
        let payload_len = (len as usize).saturating_sub(header_size);
        let data = match inflight.vbuf.received_data() {
            Some(d) => d,
            None => {
                log::warn!("[VIRTIO-NET] Received completion for unknown desc {}", desc_idx);
                counters::global().record_error();
                trace::push_event(
                    NetLayer::Driver,
                    NetEventKind::Error,
                    "virtio rx completion missing payload",
                );
                return;
            }
        };

        let actual_len = core::cmp::min(payload_len, data.len());
        let payload_slice = &data[..actual_len];

        if actual_len >= 12 {
            log::info!(
                "[VIRTIO-NET][RX-COMP] desc={} len={} payload_len={} src={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                desc_idx, len, actual_len,
                payload_slice[6], payload_slice[7], payload_slice[8],
                payload_slice[9], payload_slice[10], payload_slice[11]
            );
        } else {
            log::info!("[VIRTIO-NET][RX-COMP] desc={} len={} payload_len={}", desc_idx, len, actual_len);
        }

        // Convert the completed RX DMA buffer into PacketRef (zero-copy handoff).
        if let Some(cpu_buf) = inflight.vbuf.take_cpu_buffer() {
            let packet = crate::net::datapath::mempool::PacketRef::from_dma_slice(cpu_buf);
            if let Some(if_id) = self
                .net_if_id()
                .or_else(|| crate::net::runtime::bridge::lookup_if_by_virtio_index(self.virtio_index))
            {
                crate::net::runtime::bridge::process_received_packet_zero_copy_for_interface(
                    if_id,
                    packet,
                    header_size,
                    actual_len,
                );
            } else {
                crate::net::runtime::bridge::process_received_packet_zero_copy(
                    packet,
                    header_size,
                    actual_len,
                );
            }
        } else {
            log::warn!("[VIRTIO-NET] RX completion missing CPU buffer desc={}", desc_idx);
            counters::global().record_error();
            trace::push_event(
                NetLayer::Driver,
                NetEventKind::Error,
                "virtio rx completion missing cpu buffer",
            );
        }

        // Keep RX queue depth stable even when PacketRef mempool is unavailable.
        match self.try_post_rx_packet(rx_queue) {
            Ok(true) => {}
            Ok(false) => match self.try_post_rx_vbuf(rx_queue) {
                Ok(true) => {}
                Ok(false) => {
                    log::warn!("[VIRTIO-NET] failed to repost RX buffer after desc={}", desc_idx);
                    counters::global().record_drop();
                    trace::push_event(
                        NetLayer::Driver,
                        NetEventKind::QueuePressure,
                        "virtio rx repost failed",
                    );
                }
                Err(_) => {
                    log::warn!("[VIRTIO-NET] RX repost aborted after desc={}", desc_idx);
                    counters::global().record_error();
                    trace::push_event(
                        NetLayer::Driver,
                        NetEventKind::Error,
                        "virtio rx repost aborted",
                    );
                }
            },
            Err(_) => match self.try_post_rx_vbuf(rx_queue) {
                Ok(true) => {}
                Ok(false) => {
                    log::warn!("[VIRTIO-NET] failed to repost RX buffer after desc={}", desc_idx);
                    counters::global().record_drop();
                    trace::push_event(
                        NetLayer::Driver,
                        NetEventKind::QueuePressure,
                        "virtio rx repost failed",
                    );
                }
                Err(_) => {
                    log::warn!("[VIRTIO-NET] RX repost aborted after desc={}", desc_idx);
                    counters::global().record_error();
                    trace::push_event(
                        NetLayer::Driver,
                        NetEventKind::Error,
                        "virtio rx repost aborted",
                    );
                }
            },
        }
    }

    /// Legacy RX completion handler shared by IRQ path and PollHandler path.
    ///
    /// Returns true when the descriptor belonged to the legacy data path and was handled.
    pub(super) fn handle_legacy_rx_completion(
        &self,
        rx_queue: &NetVirtQueue,
        q_idx: usize,
        desc_idx: u16,
        len: u32,
    ) -> bool {
        let packetref_inflight = if let Some(lock) = self.rx_packetrefs.get(q_idx) {
            if let Ok(mut guard) = lock.lock() {
                guard.get_mut(desc_idx as usize).and_then(|slot| slot.take())
            } else {
                None
            }
        } else {
            None
        };

        if let Some(inflight) = packetref_inflight {
            let completion_len = match rx_queue.take_completion(desc_idx) {
                Some(completion_len) => completion_len,
                None => {
                    log::warn!(
                        "[VIRTIO-NET] RX legacy completion missing pending slot desc={}",
                        desc_idx
                    );
                    counters::global().record_error();
                    trace::push_event(
                        NetLayer::Driver,
                        NetEventKind::Error,
                        "virtio rx packetref completion missing",
                    );
                    len
                }
            };
            self.complete_rx_packetref(rx_queue, desc_idx, completion_len, inflight);
            return true;
        }

        let vbuf_inflight = if let Some(lock) = self.rx_buffers.get(q_idx) {
            if let Ok(mut guard) = lock.lock() {
                guard.get_mut(desc_idx as usize).and_then(|slot| slot.take())
            } else {
                None
            }
        } else {
            None
        };

        if let Some(inflight) = vbuf_inflight {
            let completion_len = match rx_queue.take_completion(desc_idx) {
                Some(completion_len) => completion_len,
                None => {
                    log::warn!(
                        "[VIRTIO-NET] RX legacy completion missing pending slot desc={}",
                        desc_idx
                    );
                    counters::global().record_error();
                    trace::push_event(
                        NetLayer::Driver,
                        NetEventKind::Error,
                        "virtio rx vbuf completion missing",
                    );
                    len
                }
            };
            self.complete_rx_vbuf(rx_queue, desc_idx, completion_len, inflight);
            return true;
        }

        false
    }

    /// Release unknown RX completion to avoid descriptor leaks.
    pub(super) fn release_unknown_rx_completion(&self, rx_queue: &NetVirtQueue, desc_idx: u16) {
        if rx_queue.take_completion(desc_idx).is_none() {
            log::warn!(
                "[VIRTIO-NET] RX completion missing pending slot for unknown desc {}",
                desc_idx
            );
        }
        log::warn!("[VIRTIO-NET] Received completion for unknown desc {}", desc_idx);
        counters::global().record_drop();
        trace::push_event(
            NetLayer::Driver,
            NetEventKind::Drop,
            "virtio rx completion unknown desc",
        );
    }
}
