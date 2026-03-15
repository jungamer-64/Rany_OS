use super::*;
use crate::net::obs::trace::{self, NetEventKind, NetLayer};

// IOMMU helpers require an x86_64 PhysAddr type
const MAX_TX_COMPLETIONS_PER_PASS: usize = 256;

impl VirtioNetDevice {
    /// パケットを送信（非同期）
    pub fn send_async(&self, data: &[u8]) -> SendFuture<'_> {
        SendFuture {
            device: self,
            data: data.as_ptr(),
            len: data.len(),
            submitted: false,
            desc_idx: 0,
            dma_mapping: None,
            pool_bounce_buffer: None,
        }
    }

    /// ゼロコピーパケット送信（設計書 6.2準拠） - Future返却版
    pub fn send_zero_copy(&self, packet: PacketRef) -> ZeroCopySendFuture<'_> {
        ZeroCopySendFuture {
            device: self,
            packet: Some(packet),
            submitted: false,
            desc_idx: 0,
            dma_mapping: None,
            pool_bounce_buffer: None,
        }
    }

    /// ゼロコピーパケット送信（同期キュー投入版）
    pub fn enqueue_send_zero_copy(
        &self,
        packet: PacketRef,
        meta: kernel_api::service::netdev::NetTxMeta,
    ) -> Result<(), VirtioNetError> {
        if let Some(tx_queue) = self.tx_queues.first() {
            let q_idx = 0;
            let data_len = packet.len();
            let cap = packet.capacity();
            let dma_mapping = map_net_dma_for_range(
                self.iommu_device_id,
                packet.phys_addr().as_u64(),
                cap,
                virtio_driver::net::NetDmaDirection::ToDevice,
            )?;
            let device_addr = dma_mapping.device_address();
            let inflight_mapping = dma_mapping.requires_unmap().then_some(dma_mapping);

            match tx_queue.add_tx_buffer_zero_copy(device_addr, data_len) {
                Ok(desc_idx) => {
                    let tracker = &self.core.tx_trackers[q_idx];
                    tracker.put(
                        desc_idx,
                        virtio_driver::net::TxInflight {
                            packet,
                            bounce_buffer: None,
                            dma_mapping: inflight_mapping,
                            completion_id: meta.completion_id,
                        },
                    );
                    tx_queue.notify(self.transport.as_ref());
                    Ok(())
                }
                Err(e) => {
                    if dma_mapping.requires_unmap() {
                        release_net_dma_mapping(self.iommu_device_id, dma_mapping);
                    }
                    Err(e)
                }
            }
        } else {
            Err(VirtioNetError::NotInitialized)
        }
    }

    /// TX完了を処理する
    pub(super) fn process_tx_completions(&self) {
        for (q_idx_pair, tx_queue) in self.tx_queues.iter().enumerate() {
            let q_idx = (q_idx_pair * 2 + 1) as u16;

            let _ = self.core.process_tx_completions(
                self,
                q_idx,
                &tx_queue.inner.lock().unwrap_or_else(|e| e.into_inner()),
                |desc_idx, inflight, _len| {
                    self.tx_packets.fetch_add(1, Ordering::Relaxed);
                    trace::push_event(NetLayer::Driver, NetEventKind::Tx, "virtio tx completion");

                    // IoScheduler path: completion belongs to a pending IoRequest.
                    if let Some(handler) = get_poll_handler(self.virtio_index) {
                        if let Some((io_id, _requested_bytes)) = handler.take_pending_tx(desc_idx) {
                            let device_id = crate::io::io_scheduler::DeviceId::VirtioNet {
                                index: self.virtio_index,
                            };
                            let bridge =
                                crate::io::io_scheduler::hybrid_coordinator().interrupt_bridge();
                            bridge.handle_interrupt(
                                device_id,
                                &[(io_id, crate::io::io_scheduler::IoResult::Success(0))],
                            );
                            return;
                        }
                    }

                    // Standard path: Use NetRuntime callback (implemented in mod.rs)
                    if let Some(completion_id) = inflight.completion_id {
                        let _ =
                            crate::net::runtime::device::complete_tx_request(completion_id, Ok(()));
                    }
                    self.transmit_complete(q_idx, inflight.packet);
                },
            );

            // Notify network stack that TX resources became available
            crate::net::l4::endpoint::event::enqueue_event_ignore(
                crate::net::l4::endpoint::event::NetworkEvent::TxAvailable,
            );
        }
    }
}
