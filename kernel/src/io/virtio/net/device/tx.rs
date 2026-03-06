use super::*;
use crate::net::obs::{
    counters,
    trace::{self, NetEventKind, NetLayer},
};

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
            match tx_queue.add_tx_buffer_zero_copy(device_addr, data_len) {
                Ok(desc_idx) => {
                    if let Some(lock) = self.tx_inflight.get(q_idx) {
                        if let Ok(mut guard) = lock.lock() {
                            if let Some(slot) = guard.get_mut(desc_idx as usize) {
                                *slot = Some(buffer);
                            }
                        }
                    }

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

    /// ゼロコピーパケット送信（設計書 6.2準拠）
    ///
    /// PacketRefを直接使用し、コピーなしでDMAバッファに渡す。
    /// 送信完了まで所有権を保持し、完了後に自動解放される。
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

    /// Enqueue a zero-copy PacketRef for transmission without waiting for completion.
    /// Ownership of `packet` is moved into the device's inflight map; completion will
    /// perform unmap/cleanup and return the buffer to the pool.
    pub fn enqueue_send_zero_copy(
        &self,
        packet: crate::net::datapath::mempool::PacketRef,
    ) -> Result<(), VirtioNetError> {
        let tx_queue = match self.first_tx_queue() {
            Some(q) => q,
            None => {
                counters::global().record_error();
                trace::push_event(
                    NetLayer::Driver,
                    NetEventKind::Error,
                    "virtio zero-copy tx not initialized",
                );
                return Err(VirtioNetError::NotInitialized);
            }
        };

        let data = packet.data();
        let phys_addr = packet.phys_addr();
        let payload_len = data.len();
        let phys_addr_val = phys_addr.as_u64();

        let (dma_addr, mapped_iova, mapped_len, bounce_buffer) =
            self.prepare_zero_copy_dma(phys_addr_val, data, payload_len)?;

        if let Err(err) = check_device_dma_mask(self.iommu_device_id, dma_addr, payload_len) {
            self.cleanup_dma_on_error(bounce_buffer, mapped_iova, mapped_len);
            counters::global().record_error();
            trace::push_event(
                NetLayer::Driver,
                NetEventKind::Error,
                "virtio tx dma mask violation",
            );
            return Err(err);
        }

        match tx_queue.add_tx_buffer_zero_copy(dma_addr, data.len()) {
            Ok(desc_idx) => {
                let entry = TxPacketInflight {
                    packet,
                    bounce_handle: None,
                    dma_iova: mapped_iova,
                    dma_len: mapped_len,
                    pool_bounce_buffer: bounce_buffer,
                };

                let q_idx = 0; // Simplified for first TX queue
                if let Some(lock) = self.tx_packetrefs.get(q_idx) {
                    if let Ok(mut guard) = lock.lock() {
                        if let Some(slot) = guard.get_mut(desc_idx as usize) {
                            *slot = Some(entry);
                        }
                    }
                }

                tx_queue.notify(self.transport.as_ref());
                trace::push_event(
                    NetLayer::Driver,
                    NetEventKind::Tx,
                    "virtio zero-copy tx queued",
                );
                Ok(())
            }
            Err(e) => {
                self.cleanup_dma_on_error(bounce_buffer, mapped_iova, mapped_len);
                match e {
                    VirtioNetError::QueueFull => {
                        counters::global().record_drop();
                        trace::push_event(
                            NetLayer::Driver,
                            NetEventKind::QueuePressure,
                            "virtio zero-copy tx queue full",
                        );
                    }
                    _ => {
                        counters::global().record_error();
                        trace::push_event(
                            NetLayer::Driver,
                            NetEventKind::Error,
                            "virtio zero-copy tx enqueue failed",
                        );
                    }
                }
                Err(e)
            }
        }
    }

    /// Prepare DMA mapping for zero-copy send (IOMMU bounce buffer pool usage)
    pub(super) fn prepare_zero_copy_dma(
        &self,
        phys_addr_val: u64,
        data: &[u8],
        data_len: usize,
    ) -> Result<
        (
            u64,
            Option<u64>,
            usize,
            Option<crate::io::dma::CoherentDmaBuffer>,
        ),
        VirtioNetError,
    > {
        if !is_iommu_enabled() {
            if is_iommu_required() {
                return Err(VirtioNetError::DeviceError);
            }
            return Ok((phys_addr_val, None, 0, None));
        }

        let page_mask = (crate::mm::types::PAGE_SIZE_4K as u64) - 1;
        let page_base = phys_addr_val & !page_mask;
        let page_offset = (phys_addr_val - page_base) as usize;
        let map_len = crate::mm::types::PAGE_SIZE_4K;

        // Ensure the data fits within the aligned page.
        // PacketBuffer is designed to be 4K-aligned and contiguous.
        if page_offset + data_len <= map_len {
            if let Some(device_id) = self.iommu_device_id.as_ref() {
                match unsafe {
                    map_for_device_with_perms(
                        device_id,
                        x86_64::PhysAddr::new(page_base),
                        map_len as u64,
                        true,
                        false,
                    )
                } {
                    Ok(iova) => {
                        let dma_addr = iova + page_offset as u64;
                        return Ok((dma_addr, Some(iova), map_len, None));
                    }
                    Err(e) => {
                        log::warn!("[VIRTIO-NET] IOMMU map failed for zero-copy: {:?}", e);
                        // Fallback to bounce buffer
                    }
                }
            }
        }

        // Fallback to bounce buffer if direct mapping is not possible or failed
        if page_offset + data_len > map_len {
            self.prepare_bounce_no_page_align(data, data_len)
        } else {
            self.prepare_bounce_page_align(data, data_len, page_offset, map_len)
        }
    }

    pub(super) fn prepare_bounce_no_page_align(
        &self,
        data: &[u8],
        data_len: usize,
    ) -> Result<
        (
            u64,
            Option<u64>,
            usize,
            Option<crate::io::dma::CoherentDmaBuffer>,
        ),
        VirtioNetError,
    > {
        let mut buffer = self.get_tx_bounce_buffer(data_len)?;
        if data_len > 0 {
            let slice = unsafe { buffer.as_mut_slice() };
            slice[..data_len].fill(0);
            let copy_len = core::cmp::min(data.len(), data_len);
            slice[..copy_len].copy_from_slice(&data[..copy_len]);
        }
        buffer.prepare_for_device();
        let dma_addr = buffer.device_addr();
        Ok((dma_addr, None, 0, Some(buffer)))
    }

    pub(super) fn prepare_bounce_page_align(
        &self,
        data: &[u8],
        data_len: usize,
        page_offset: usize,
        map_len: usize,
    ) -> Result<
        (
            u64,
            Option<u64>,
            usize,
            Option<crate::io::dma::CoherentDmaBuffer>,
        ),
        VirtioNetError,
    > {
        let mut buffer = self.get_tx_bounce_buffer(map_len)?;
        if data_len > 0 {
            let slice = unsafe { buffer.as_mut_slice() };
            slice[page_offset..page_offset + data_len].fill(0);
            let copy_len = core::cmp::min(data.len(), data_len);
            slice[page_offset..page_offset + copy_len].copy_from_slice(&data[..copy_len]);
        }
        buffer.prepare_for_device();
        let dma_addr = buffer.device_addr() + page_offset as u64;
        Ok((dma_addr, None, map_len, Some(buffer)))
    }

    pub(super) fn cleanup_dma_on_error(
        &self,
        bounce_buffer: Option<crate::io::dma::CoherentDmaBuffer>,
        mapped_iova: Option<u64>,
        mapped_len: usize,
    ) {
        if let Some(buf) = bounce_buffer {
            self.return_tx_bounce_buffer(buf);
        }
        if let Some(iova) = mapped_iova {
            let _ = unmap_iommu_addr(self.iommu_device_id, iova, mapped_len);
        }
    }

    /// TXキュー完了を処理し、インフライトバッファを解放
    pub(super) fn process_tx_completions(&self) {
        for (q_idx, tx_queue) in self.tx_queues.iter().enumerate() {
            let completions = tx_queue.process_used();
            if completions.is_empty() {
                continue;
            }

            for (desc_idx, len) in completions {
                self.tx_packets.fetch_add(1, Ordering::Relaxed);
                self.tx_bytes.fetch_add(len, Ordering::Relaxed);
                trace::push_event(NetLayer::Driver, NetEventKind::Tx, "virtio tx completion");

                log::info!("[VIRTIO-NET][TX-COMP] desc={} len={}", desc_idx, len);

                // IoScheduler path: completion belongs to a pending IoRequest.
                if let Some(handler) = get_poll_handler(self.virtio_index) {
                    if let Some((io_id, requested_bytes)) = handler.take_pending_tx(desc_idx) {
                        let result = if tx_queue.take_completion(desc_idx).is_some() {
                            crate::io::io_scheduler::IoResult::Success(requested_bytes)
                        } else {
                            log::warn!(
                                "[VIRTIO-NET] TX scheduler completion disappeared desc={}",
                                desc_idx
                            );
                            counters::global().record_error();
                            trace::push_event(
                                NetLayer::Driver,
                                NetEventKind::Error,
                                "virtio tx scheduler completion missing",
                            );
                            crate::io::io_scheduler::IoResult::Error(
                                crate::io::io_scheduler::IoError::DeviceError,
                            )
                        };
                        let device_id = crate::io::io_scheduler::DeviceId::VirtioNet {
                            index: self.virtio_index,
                        };
                        let bridge =
                            crate::io::io_scheduler::hybrid_coordinator().interrupt_bridge();
                        bridge.handle_interrupt(device_id, &[(io_id, result)]);
                        continue;
                    }
                }

                if self.handle_legacy_tx_completion(tx_queue, q_idx, desc_idx, len) {
                    continue;
                }

                self.release_unknown_tx_completion(tx_queue, desc_idx);
            }

            // Notify network stack that TX resources became available
            crate::net::l4::endpoint::event::send_event_ignore(
                crate::net::l4::endpoint::event::NetworkEvent::TxAvailable,
            );
        }
    }

    /// Legacy TX completion handler shared by IRQ path and PollHandler path.
    ///
    /// Returns true when the descriptor belonged to the legacy data path and was handled.
    pub(super) fn handle_legacy_tx_completion(
        &self,
        tx_queue: &NetVirtQueue,
        q_idx: usize,
        desc_idx: u16,
        _len: u32,
    ) -> bool {
        let buf = if let Some(lock) = self.tx_inflight.get(q_idx) {
            if let Ok(mut guard) = lock.lock() {
                guard
                    .get_mut(desc_idx as usize)
                    .and_then(|slot| slot.take())
            } else {
                None
            }
        } else {
            None
        };

        if let Some(_buf) = buf {
            if tx_queue.take_completion(desc_idx).is_none() {
                log::warn!(
                    "[VIRTIO-NET] TX legacy completion missing pending slot desc={}",
                    desc_idx
                );
                counters::global().record_error();
                trace::push_event(
                    NetLayer::Driver,
                    NetEventKind::Error,
                    "virtio tx legacy completion missing",
                );
            }
            return true;
        }

        let entry = if let Some(lock) = self.tx_packetrefs.get(q_idx) {
            if let Ok(mut guard) = lock.lock() {
                guard
                    .get_mut(desc_idx as usize)
                    .and_then(|slot| slot.take())
            } else {
                None
            }
        } else {
            None
        };

        if let Some(entry) = entry {
            if tx_queue.take_completion(desc_idx).is_none() {
                log::warn!(
                    "[VIRTIO-NET] TX legacy completion missing pending slot desc={}",
                    desc_idx
                );
                counters::global().record_error();
                trace::push_event(
                    NetLayer::Driver,
                    NetEventKind::Error,
                    "virtio tx zero-copy completion missing",
                );
            }
            if let Some(buf) = entry.pool_bounce_buffer {
                self.return_tx_bounce_buffer(buf);
            }
            if let Some(handle) = entry.bounce_handle {
                let _ = handle.unmap();
            }
            if let Some(iova) = entry.dma_iova {
                let _ = unmap_iommu_addr(self.iommu_device_id, iova, entry.dma_len);
            }
            return true;
        }

        false
    }

    /// Release unknown TX completion to avoid descriptor leaks.
    pub(super) fn release_unknown_tx_completion(&self, tx_queue: &NetVirtQueue, desc_idx: u16) {
        if tx_queue.take_completion(desc_idx).is_none() {
            log::warn!(
                "[VIRTIO-NET] TX completion missing pending slot for unknown desc {}",
                desc_idx
            );
        }
        log::warn!("[VIRTIO-NET] TX completion for unknown desc {}", desc_idx);
        counters::global().record_error();
        trace::push_event(
            NetLayer::Driver,
            NetEventKind::Error,
            "virtio tx completion unknown desc",
        );
    }
}
