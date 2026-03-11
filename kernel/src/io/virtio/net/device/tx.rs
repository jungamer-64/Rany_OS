use super::*;
use crate::net::obs::{
    counters,
    trace::{self, NetEventKind, NetLayer},
};
use kernel_api::dma::{CpuOwned, DmaSlice};

// IOMMU helpers require an x86_64 PhysAddr type
use x86_64::PhysAddr;

const MAX_TX_COMPLETIONS_PER_PASS: usize = 256;

impl VirtioNetDevice {
    /// 同期パケット送信（非推奨：send_async または send_zero_copy を使用してください）
    ///
    /// DMAバッファを同期的に割り当て、`notify()` 後に `process_tx_completions()` を
    /// インラインで呼び出す。割り込みコンテキストから呼ばれるとデッドロックのリスクがある。
    /// 初期化時のブートストラップ送信（エグゼキュータ起動前）では引き続き使用可能。
    #[deprecated(note = "use send_async() or send_zero_copy() instead")]
    pub fn submit_tx(&self, data: &[u8]) -> Result<(), VirtioNetError> {
        let data_len = data.len();
        if data_len >= 14 {
            log::info!(
                "[NET-TX] submit_tx len={} dst={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                data_len,
                data[0],
                data[1],
                data[2],
                data[3],
                data[4],
                data[5]
            );
        } else {
            log::info!("[NET-TX] submit_tx len={}", data_len);
        }
        let mut buffer = match self.iommu_device_id {
            Some(device_id) => crate::io::dma::CoherentDmaBuffer::new_for_device(
                data_len,
                crate::io::dma::DmaMemoryAttributes::MMIO,
                &device_id,
            ),
            None => crate::io::dma::CoherentDmaBuffer::new(
                data_len,
                crate::io::dma::DmaMemoryAttributes::MMIO,
            ),
        }
        .ok_or_else(|| {
            counters::global().record_error();
            trace::push_event(
                NetLayer::Driver,
                NetEventKind::Error,
                "virtio tx dma buffer alloc failed",
            );
            VirtioNetError::DeviceError
        })?;

        if is_iommu_enabled() && self.iommu_device_id.is_some() && !buffer.is_iommu_mapped() {
            log::error!(
                "[NET-TX] IOMMU enabled but TX buffer is not mapped for device DMA; refusing phys fallback"
            );
            counters::global().record_error();
            trace::push_event(
                NetLayer::Driver,
                NetEventKind::Error,
                "virtio tx iommu mapping missing",
            );
            return Err(VirtioNetError::DeviceError);
        }

        // Copy payload into the DMA buffer
        let dst = unsafe { buffer.as_mut_slice() };
        if dst.len() < data_len {
            counters::global().record_error();
            trace::push_event(
                NetLayer::Driver,
                NetEventKind::Error,
                "virtio tx buffer too small",
            );
            return Err(VirtioNetError::BufferTooSmall);
        }
        dst[..data_len].copy_from_slice(data);

        if let Some(tx_queue) = self.tx_queues.first() {
            let q_idx = 0; // First TX queue index in per-queue vectors
            let device_addr = buffer.device_addr();
            let iova = if buffer.is_iommu_mapped() {
                Some(device_addr)
            } else {
                None
            };
            let iommu_len = buffer.size() as u64;

            match tx_queue.add_tx_buffer_zero_copy(device_addr, data_len) {
                Ok(desc_idx) => {
                    let tracker = &self.core.tx_trackers[q_idx];
                    let (phys, iova2, virt, len, rel) = buffer.into_raw_parts();
                    let rel_unsafe: Option<unsafe fn(*mut u8, usize, u64)> = rel.map(|f| f as _);
                    let bounce = unsafe {
                        DmaSlice::<CpuOwned>::from_raw_parts(phys, iova2, virt, len, rel_unsafe)
                    };
                    let packet = match crate::net::datapath::mempool::alloc_packet() {
                        Some(p) => p,
                        None => return Err(VirtioNetError::DeviceError),
                    };
                    tracker.put(
                        desc_idx,
                        virtio_driver::net::TxInflight {
                            packet,
                            bounce_buffer: Some(bounce),
                            iommu_iova: iova,
                            iommu_map_len: iommu_len,
                            completion_id: None,
                        },
                    );

                    tx_queue.notify(self.transport.as_ref());

                    self.process_tx_completions();
                    trace::push_event(NetLayer::Driver, NetEventKind::Tx, "virtio tx queued");
                    Ok(())
                }
                Err(e) => {
                    log::warn!("[NET-TX] failed to add tx buffer: {:?}", e);
                    match e {
                        VirtioNetError::QueueFull => {
                            counters::global().record_drop();
                            trace::push_event(
                                NetLayer::Driver,
                                NetEventKind::QueuePressure,
                                "virtio tx queue full",
                            );
                        }
                        _ => {
                            counters::global().record_error();
                            trace::push_event(
                                NetLayer::Driver,
                                NetEventKind::Error,
                                "virtio tx enqueue failed",
                            );
                        }
                    }
                    Err(e)
                }
            }
        } else {
            log::warn!("[NET-TX] device not initialized");
            counters::global().record_error();
            trace::push_event(
                NetLayer::Driver,
                NetEventKind::Error,
                "virtio tx not initialized",
            );
            Err(VirtioNetError::NotInitialized)
        }
    }

    /// パケットを送信（非同期）
    pub fn send_async(&self, data: &[u8]) -> SendFuture<'_> {
        SendFuture {
            device: self,
            data: data.as_ptr(),
            len: data.len(),
            submitted: false,
            desc_idx: 0,
            dma_len: 0,
            dma_iova: None,
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
            dma_len: 0,
            dma_iova: None,
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
            let cap = packet.capacity() as u64;
            let phys_addr = packet.phys_addr();
            // convert to kernel/x86_64 PhysAddr for the IOMMU API
            let phys = PhysAddr::new(phys_addr.as_u64());

            let (device_addr, iova) = if is_iommu_enabled() {
                let device_id = self.iommu_device_id.ok_or(VirtioNetError::DeviceError)?;
                // Use a larger size (capacity) for mapping to be safe, although we only send len.
                // VT-d mapping must be 4K-aligned, and PacketBuffer is 4K.
                let size = cap;
                unsafe {
                    let iova = crate::io::iommu::api::map_for_device_with_perms(
                        &device_id, phys, size, true,
                        false, // TX: read-only from device perspective
                    )
                    .map_err(|_| VirtioNetError::DeviceError)?;
                    (iova, Some(iova))
                }
            } else {
                (phys_addr.as_u64(), None)
            };

            match tx_queue.add_tx_buffer_zero_copy(device_addr, data_len) {
                Ok(desc_idx) => {
                    let tracker = &self.core.tx_trackers[q_idx];
                    tracker.put(
                        desc_idx,
                        virtio_driver::net::TxInflight {
                            packet,
                            bounce_buffer: None,
                            iommu_iova: iova,
                            iommu_map_len: cap,
                            completion_id: meta.completion_id,
                        },
                    );
                    tx_queue.notify(self.transport.as_ref());
                    Ok(())
                }
                Err(e) => {
                    if let Some(iova_to_unmap) = iova {
                        let device_id = self.iommu_device_id.unwrap();
                        let _ = crate::io::iommu::api::unmap_for_device(
                            &device_id,
                            iova_to_unmap,
                            packet.capacity() as u64,
                        );
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
                |desc_idx, mut inflight, _len| {
                    self.tx_packets.fetch_add(1, Ordering::Relaxed);
                    trace::push_event(NetLayer::Driver, NetEventKind::Tx, "virtio tx completion");

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
            crate::net::l4::endpoint::event::send_event_ignore(
                crate::net::l4::endpoint::event::NetworkEvent::TxAvailable,
            );
        }
    }
}
