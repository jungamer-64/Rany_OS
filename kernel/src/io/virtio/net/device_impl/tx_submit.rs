use super::*;

impl VirtioNetDevice {

    pub fn submit_tx(&self, data: &[u8]) -> Result<(), VirtioNetError> {
        let data_len = data.len();
        crate::io::log::early_print(&alloc::format!("[EARLY][NET-TX] submit_tx called len={}\n", data_len));
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
        let mut buffer = crate::io::dma::CoherentDmaBuffer::new(
            data_len,
            crate::io::dma::DmaMemoryAttributes::MMIO,
        )
        .ok_or(VirtioNetError::DeviceError)?;

        // Copy payload into the DMA buffer
        let dst = unsafe { buffer.as_mut_slice() };
        if dst.len() < data_len {
            return Err(VirtioNetError::BufferTooSmall);
        }
        dst[..data_len].copy_from_slice(data);

        if let Some(tx_queue) = self.first_tx_queue() {
            let phys = buffer.phys_addr().as_u64();
            crate::io::log::early_print(&alloc::format!("[EARLY][NET-TX] about to call add_tx_buffer_zero_copy phys=0x{:x} len={}\n", phys, data_len));
            match tx_queue.add_tx_buffer_zero_copy(phys, data_len) {
                Ok(desc_idx) => {
                    crate::io::log::early_print(&alloc::format!("[EARLY][NET-TX] add_tx_buffer_zero_copy returned desc={}\n", desc_idx));
                    self.tx_inflight.lock().insert(desc_idx, buffer);
                    crate::io::log::early_print(&alloc::format!("[EARLY][NET-TX] queued desc={} phys=0x{:x} len={}\n", desc_idx, phys, data_len));
                    log::info!("[NET-TX] queued desc={} phys=0x{:x} len={}", desc_idx, phys, data_len);
                    // Diagnostic: read device status/features before notifying
                    let dev_status = self.transport.get_status();
                    crate::io::log::early_print(&alloc::format!("[EARLY][NET-TX] transport.get_status()=0x{:x}\n", dev_status));
                    let dev_features = self.transport.get_device_features();
                    crate::io::log::early_print(&alloc::format!("[EARLY][NET-TX] transport.get_device_features()=0x{:x}\n", dev_features));

                    tx_queue.notify();
                    crate::io::log::early_print(&alloc::format!("[EARLY][NET-TX] notify called for queue={}\n", tx_queue.index));

                    // Diagnostic: check device interrupt status and process used ring immediately
                    let intr_status = self.transport.get_interrupt_status();
                    crate::io::log::early_print(&alloc::format!("[EARLY][NET-TX] transport.get_interrupt_status()=0x{:x}\n", intr_status));

                    self.process_post_notify_completions();

                    log::info!("[NET-TX] notify called for queue={}", tx_queue.index);
                    Ok(())
                }
                Err(e) => {
                    log::warn!("[NET-TX] failed to add tx buffer: {:?}", e);
                    Err(e)
                }
            }
        } else {
            log::warn!("[NET-TX] device not initialized");
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
            bounce_handle: None,
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
            bounce_handle: None,
        }
    }

    /// Enqueue a zero-copy PacketRef for transmission without waiting for completion.
    /// Ownership of `packet` is moved into the device's inflight map; completion will
    /// perform unmap/cleanup and return the buffer to the pool.
    pub fn enqueue_send_zero_copy(&self, packet: crate::net::PacketRef) -> Result<(), VirtioNetError> {
        let tx_queue = match self.first_tx_queue() {
            Some(q) => q,
            None => return Err(VirtioNetError::NotInitialized),
        };

        let data = packet.data();
        let phys_addr = packet.phys_addr();
        let data_len = core::mem::size_of::<VirtioNetHeader>() + data.len();
        let phys_addr_val = phys_addr.as_u64();

        let (dma_addr, mapped_iova, mapped_len, bounce_handle) =
            self.prepare_zero_copy_dma(phys_addr_val, data, data_len)?;

        if let Err(err) = check_device_dma_mask(self.iommu_device_id, dma_addr, data_len) {
            Self::cleanup_dma_on_error(bounce_handle, mapped_iova, mapped_len, self.iommu_device_id);
            return Err(err);
        }

        match tx_queue.add_tx_buffer_zero_copy(dma_addr, data.len()) {
            Ok(desc_idx) => {
                let entry = TxPacketInflight {
                    packet,
                    bounce_handle,
                    dma_iova: mapped_iova,
                    dma_len: mapped_len,
                };
                self.tx_packetrefs.lock().insert(desc_idx, entry);
                tx_queue.notify();
                Ok(())
            }
            Err(e) => {
                Self::cleanup_dma_on_error(bounce_handle, mapped_iova, mapped_len, self.iommu_device_id);
                Err(e)
            }
        }
    }

    /// Prepare DMA mapping for zero-copy send (IOMMU bounce buffer allocation)
    pub(super) fn prepare_zero_copy_dma(
        &self,
        phys_addr_val: u64,
        data: &[u8],
        data_len: usize,
    ) -> Result<(u64, Option<u64>, usize, Option<crate::io::iommu::api::DmaHandle<[u8]>>), VirtioNetError> {
        let page_mask = (crate::mm::types::PAGE_SIZE_4K as u64) - 1;
        let page_base = phys_addr_val & !page_mask;
        let page_offset = (phys_addr_val - page_base) as usize;
        let map_len = crate::mm::types::PAGE_SIZE_4K;
        let can_map_page = page_offset + data_len <= map_len;

        if !is_iommu_enabled() {
            if is_iommu_required() {
                return Err(VirtioNetError::DeviceError);
            }
            return Ok((phys_addr_val, None, 0, None));
        }

        if !can_map_page {
            self.prepare_bounce_no_page_align(data, data_len)
        } else {
            self.prepare_bounce_page_align(data, data_len, page_offset, map_len)
        }
    }

    pub(super) fn prepare_bounce_no_page_align(
        &self,
        data: &[u8],
        data_len: usize,
    ) -> Result<(u64, Option<u64>, usize, Option<crate::io::iommu::api::DmaHandle<[u8]>>), VirtioNetError> {
        let mut rref = allocate_iommu_bounce_bytes(data_len).map_err(|err| match err {
            IommuBounceAllocError::InvalidLen => VirtioNetError::BufferTooSmall,
            IommuBounceAllocError::AllocFailed => VirtioNetError::DeviceError,
        })?;
        if data_len > 0 {
            rref[..data_len].fill(0);
            let copy_len = core::cmp::min(data.len(), data_len);
            rref[..copy_len].copy_from_slice(&data[..copy_len]);
        }
        let handle = match self.iommu_device_id {
            Some(device) => map_rref_slice_for_device(rref, &device, DmaDirection::ToDevice),
            None => DmaHandle::map_rref_slice(rref, 0, DmaDirection::ToDevice),
        }
        .map_err(|_| VirtioNetError::DeviceError)?;
        let dma_addr = handle.iova();
        Ok((dma_addr, None, 0, Some(handle)))
    }

    pub(super) fn prepare_bounce_page_align(
        &self,
        data: &[u8],
        data_len: usize,
        page_offset: usize,
        map_len: usize,
    ) -> Result<(u64, Option<u64>, usize, Option<crate::io::iommu::api::DmaHandle<[u8]>>), VirtioNetError> {
        let mut rref = allocate_iommu_bounce_bytes(map_len).map_err(|err| match err {
            IommuBounceAllocError::InvalidLen => VirtioNetError::BufferTooSmall,
            IommuBounceAllocError::AllocFailed => VirtioNetError::DeviceError,
        })?;
        if data_len > 0 {
            rref[page_offset..page_offset + data_len].fill(0);
            let copy_len = core::cmp::min(data.len(), data_len);
            rref[page_offset..page_offset + copy_len].copy_from_slice(&data[..copy_len]);
        }
        let handle = match self.iommu_device_id {
            Some(device) => map_rref_slice_for_device(rref, &device, DmaDirection::ToDevice),
            None => DmaHandle::map_rref_slice(rref, 0, DmaDirection::ToDevice),
        }
        .map_err(|_| VirtioNetError::DeviceError)?;
        let dma_addr = handle.iova() + page_offset as u64;
        Ok((dma_addr, None, map_len, Some(handle)))
    }

    pub(super) fn cleanup_dma_on_error(
        bounce_handle: Option<crate::io::iommu::api::DmaHandle<[u8]>>,
        mapped_iova: Option<u64>,
        mapped_len: usize,
        iommu_device_id: Option<IommuDeviceId>,
    ) {
        if let Some(handle) = bounce_handle {
            let _ = handle.unmap();
        }
        if let Some(iova) = mapped_iova {
            let _ = unmap_iommu_addr(iommu_device_id, iova, mapped_len);
        }
    }
    /// パケットを受信（非同期）
    pub fn recv_async<'a>(&'a self, buffer: &'a mut [u8]) -> RecvFuture<'a> {
        RecvFuture {
            device: self,
            buffer,
            submitted: false,
            desc_idx: 0,
            dma_len: 0,
            dma_iova: None,
            bounce_handle: None,
        }
    }

    /// ゼロコピーパケット受信（設計書 6.2準拠）
    ///
    /// Mempoolから割り当てられたバッファに直接受信し、
    /// PacketRefとして返却する。
    pub fn recv_zero_copy(
        &self,
        pool: &'static crate::net::mempool::Mempool,
    ) -> ZeroCopyRecvFuture<'_> {
        ZeroCopyRecvFuture {
            device: self,
            pool,
            packet: None,
            submitted: false,
            desc_idx: 0,
            dma_len: 0,
            dma_iova: None,
            bounce_handle: None,
        }
    }

    /// MACアドレスを取得
    pub fn mac_address(&self) -> [u8; 6] {
        self.config.mac
    }

    /// 割り込みハンドラ
    pub fn handle_interrupt(&self) {
        self.process_rx_completions();
        self.process_tx_completions();

        // Interrupt-Wakerブリッジに通知（設計書 4.2）
        // RX/TXで待機中のFutureを起床
        crate::task::interrupt_waker::wake_from_interrupt(
            crate::task::interrupt_waker::InterruptSource::VirtioNet(self.virtio_index),
        );
    }

    /// Legacy RX completion handler shared by IRQ path and PollHandler path.
    ///
    /// Returns true when the descriptor belonged to the legacy data path and was handled.
    pub(super) fn handle_legacy_rx_completion(
        &self,
        rx_queue: &NetVirtQueue,
        desc_idx: u16,
        len: u32,
    ) -> bool {
        if let Some(inflight) = self.rx_packetrefs.lock().remove(&desc_idx) {
            let completion_len = match rx_queue.take_completion(desc_idx) {
                Some(completion_len) => completion_len,
                None => {
                    log::warn!(
                        "[VIRTIO-NET] RX legacy completion missing pending slot desc={}",
                        desc_idx
                    );
                    len
                }
            };
            self.complete_rx_packetref(rx_queue, desc_idx, completion_len, inflight);
            return true;
        }

        if let Some(inflight) = self.rx_buffers.lock().remove(&desc_idx) {
            let completion_len = match rx_queue.take_completion(desc_idx) {
                Some(completion_len) => completion_len,
                None => {
                    log::warn!(
                        "[VIRTIO-NET] RX legacy completion missing pending slot desc={}",
                        desc_idx
                    );
                    len
                }
            };
            self.complete_rx_vbuf(desc_idx, completion_len, inflight);
            return true;
        }

        false
    }

    /// Legacy TX completion handler shared by IRQ path and PollHandler path.
    ///
    /// Returns true when the descriptor belonged to the legacy data path and was handled.
    pub(super) fn handle_legacy_tx_completion(
        &self,
        tx_queue: &NetVirtQueue,
        desc_idx: u16,
        len: u32,
    ) -> bool {
        if let Some(_buf) = self.tx_inflight.lock().remove(&desc_idx) {
            if tx_queue.take_completion(desc_idx).is_none() {
                log::warn!(
                    "[VIRTIO-NET] TX legacy completion missing pending slot desc={}",
                    desc_idx
                );
            }
            crate::io::log::early_print(&alloc::format!(
                "[EARLY][VIRTIO-NET] TX-COMP freed buffer for desc={} len={}\n",
                desc_idx, len
            ));
            log::info!("[VIRTIO-NET][TX-COMP] freed buffer for desc={}", desc_idx);
            return true;
        }

        if let Some(entry) = self.tx_packetrefs.lock().remove(&desc_idx) {
            if tx_queue.take_completion(desc_idx).is_none() {
                log::warn!(
                    "[VIRTIO-NET] TX legacy completion missing pending slot desc={}",
                    desc_idx
                );
            }
            cleanup_dma_resources(
                self.iommu_device_id,
                entry.bounce_handle,
                entry.dma_iova,
                entry.dma_len,
            );
            crate::io::log::early_print(&alloc::format!(
                "[EARLY][VIRTIO-NET] TX-COMP freed PacketRef for desc={} len={}\n",
                desc_idx, len
            ));
            log::info!("[VIRTIO-NET][TX-COMP] freed PacketRef for desc={}", desc_idx);
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
    }

    /// RXキュー完了を処理し、パケットをスタックに渡す
    pub(super) fn process_rx_completions(&self) {
        for rx_queue in &self.rx_queues {
            let completions = rx_queue.process_used();
            for (desc_idx, len) in completions {
                self.rx_packets.fetch_add(1, Ordering::Relaxed);

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

                if self.handle_legacy_rx_completion(rx_queue, desc_idx, len) {
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
            let _ = unmap_for_device(device_id, iova, inflight.iommu_map_len);
        }

        let header_size = core::mem::size_of::<VirtioNetHeader>();
        let payload_len = (len as usize).saturating_sub(header_size);
        crate::io::log::early_print(&alloc::format!("[EARLY][VIRTIO-NET][RX-COMP] desc={} len={} payload_len={} (packetref)\n", desc_idx, len, payload_len));

        // Pass PacketRef to bridge for zero-copy processing (prefer interface-aware path).
        if let Some(if_id) = self
            .net_if_id()
            .or_else(|| crate::net::driver_bridge::lookup_if_by_virtio_index(self.virtio_index))
        {
            crate::net::driver_bridge::process_received_packet_zero_copy_for_interface(
                if_id,
                inflight.packet,
                header_size,
                payload_len,
            );
        } else {
            crate::net::driver_bridge::process_received_packet_zero_copy(
                inflight.packet,
                header_size,
                payload_len,
            );
        }

        // Re-post a new PacketRef buffer to the queue so we keep a steady supply
        match self.try_post_rx_packet(rx_queue) {
            Ok(true) => {}
            Ok(false) => log::warn!("[VIRTIO-NET] OOM allocating replacement PacketRef"),
            Err(_) => {}
        }
    }

    /// VBuf RX完了: IOMMUアンマップ + 受信完了 + ブリッジ転送
    pub(super) fn complete_rx_vbuf(&self, desc_idx: u16, len: u32, mut inflight: RxVbufInflight) {
        // Unmap IOMMU mapping if it was active
        if let (Some(iova), Some(device_id)) = (inflight.iommu_iova, &self.iommu_device_id) {
            let _ = unmap_for_device(device_id, iova, inflight.iommu_map_len);
        }

        if let Err(e) = inflight.vbuf.complete_receive() {
            log::warn!("[VIRTIO-NET] failed to complete rx buffer {}: {}", desc_idx, e);
            return;
        }

        let header_size = core::mem::size_of::<VirtioNetHeader>();
        let payload_len = (len as usize).saturating_sub(header_size);
        let data = match inflight.vbuf.received_data() {
            Some(d) => d,
            None => {
                log::warn!("[VIRTIO-NET] Received completion for unknown desc {}", desc_idx);
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

        crate::io::log::early_print(&alloc::format!("[EARLY][VIRTIO-NET] handing payload desc={} payload_len={} to bridge\n", desc_idx, actual_len));
        // Allocate a PacketRef and delegate to the zero-copy bridge API
        if let Some(mut packet) = crate::net::mempool::alloc_packet() {
            let len_to_copy = core::cmp::min(actual_len, packet.capacity());
            packet.data_mut()[..len_to_copy].copy_from_slice(&payload_slice[..len_to_copy]);
            if let Some(if_id) = self
                .net_if_id()
                .or_else(|| crate::net::driver_bridge::lookup_if_by_virtio_index(self.virtio_index))
            {
                crate::net::driver_bridge::process_received_packet_zero_copy_for_interface(
                    if_id,
                    packet,
                    0,
                    len_to_copy,
                );
            } else {
                crate::net::driver_bridge::process_received_packet_zero_copy(packet, 0, len_to_copy);
            }
        } else {
            #[cfg(debug_assertions)]
            {
                log::warn!("[VIRTIO-NET] OOM allocating packet for rx copy");
            }
        }
    }

    /// TXキュー完了を処理し、インフライトバッファを解放
    pub(super) fn process_tx_completions(&self) {
        for tx_queue in &self.tx_queues {
            let completions = tx_queue.process_used();
            if completions.is_empty() {
                continue;
            }

            for (desc_idx, len) in completions {
                self.tx_packets.fetch_add(1, Ordering::Relaxed);
                self.tx_bytes.fetch_add(len, Ordering::Relaxed);

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

                if self.handle_legacy_tx_completion(tx_queue, desc_idx, len) {
                    continue;
                }

                self.release_unknown_tx_completion(tx_queue, desc_idx);
            }

            // Notify network stack that TX resources became available
            crate::net::endpoint::event::send_event_ignore(
                crate::net::endpoint::event::NetworkEvent::TxAvailable,
            );
        }
    }

    /// 統計を取得
    pub fn stats(&self) -> VirtioNetStats {
        VirtioNetStats {
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::virtio::{TransportType, VirtioDeviceType, VirtioTransport};
    use crate::net::mempool;
    use crate::net::driver_bridge;

    struct NoopTransport;

    impl VirtioTransport for NoopTransport {
        fn device_type(&self) -> VirtioDeviceType {
            VirtioDeviceType::Network
        }
        fn get_status(&self) -> u8 { 0 }
        fn set_status(&mut self, _status: u8) {}
        fn get_device_features_low(&self) -> u32 { 0 }
        fn get_device_features_high(&self) -> u32 { 0 }
        fn set_driver_features_low(&mut self, _features: u32) {}
        fn set_driver_features_high(&mut self, _features: u32) {}
        fn get_num_queues(&self) -> u16 { 2 }
        fn select_queue(&mut self, _queue_index: u16) {}
        fn get_queue_max_size(&self) -> u16 { 16 }
        fn set_queue_size(&mut self, _size: u16) {}
        fn is_queue_ready(&self) -> bool { false }
        fn enable_queue(&mut self) {}
        fn disable_queue(&mut self) {}
        fn set_queue_desc_addr(&mut self, _addr: u64) {}
        fn set_queue_avail_addr(&mut self, _addr: u64) {}
        fn set_queue_used_addr(&mut self, _addr: u64) {}
        fn notify_queue(&mut self, _queue_index: u16) {}
        fn get_notify_addr(&mut self, _queue_index: u16) -> Option<u64> { None }
        fn get_interrupt_status(&self) -> u32 { 0 }
        fn ack_interrupt(&self, _status: u32) {}
        fn read_config_u8(&self, _offset: usize) -> u8 { 0 }
        fn read_config_u16(&self, _offset: usize) -> u16 { 0 }
        fn read_config_u32(&self, _offset: usize) -> u32 { 0 }
        fn write_config_u8(&mut self, _offset: usize, _value: u8) {}
        fn write_config_u16(&mut self, _offset: usize, _value: u16) {}
        fn write_config_u32(&mut self, _offset: usize, _value: u32) {}
        fn transport_type(&self) -> TransportType { TransportType::Mmio }
    }

    fn run_irq_path_completes_scheduler_pending_tx_and_rx(index: u8) {
        crate::io::io_scheduler::init_io_scheduler();
        clear_poll_handler_registry_for_tests();
        clear_virtio_net_devices_for_tests();

        assert!(crate::io::virtio::init_virtio_net_with_transport_at_index(
            index,
            Box::new(NoopTransport),
            None
        )
        .is_ok());

        register_virtio_net_with_io_scheduler(index);
        let handler = get_poll_handler(index).expect("registered poll handler");

        let bridge = crate::io::io_scheduler::hybrid_coordinator().interrupt_bridge();
        let device_id = crate::io::io_scheduler::DeviceId::VirtioNet { index };

        // TX completion with scheduler pending
        let tx_io_id = IoRequestId(3001);
        let tx_desc = crate::io::virtio::with_virtio_net_at_index(index, |device| {
            let tx_queue = device.first_tx_queue().expect("tx queue");
            let desc = tx_queue
                .add_tx_buffer_zero_copy(0x8000, 64)
                .expect("tx submit");
            unsafe {
                let used = &mut *tx_queue.used_ring.as_ptr();
                let slot = (used.idx % tx_queue.size) as usize;
                used.ring[slot] = VringUsedElem {
                    id: desc as u32,
                    len: 64,
                };
                used.idx = used.idx.wrapping_add(1);
            }
            desc
        })
        .expect("device");
        handler.add_pending_tx(tx_io_id, tx_desc, 64);
        bridge.register_pending(device_id, tx_io_id);

        crate::io::virtio::with_virtio_net_at_index(index, |device| {
            device.process_tx_completions();
        })
        .expect("device");

        // RX completion with scheduler pending
        let rx_io_id = IoRequestId(3002);
        let rx_buf_len = VirtioNetHeader::SIZE + 96;
        let rx_desc = crate::io::virtio::with_virtio_net_at_index(index, |device| {
            let rx_queue = device.first_rx_queue().expect("rx queue");
            let desc = rx_queue
                .add_rx_buffer_zero_copy(0x9000, rx_buf_len)
                .expect("rx submit");
            unsafe {
                let used = &mut *rx_queue.used_ring.as_ptr();
                let slot = (used.idx % rx_queue.size) as usize;
                used.ring[slot] = VringUsedElem {
                    id: desc as u32,
                    len: (VirtioNetHeader::SIZE + 40) as u32,
                };
                used.idx = used.idx.wrapping_add(1);
            }
            desc
        })
        .expect("device");
        handler.add_pending_rx(rx_io_id, rx_desc, rx_buf_len);
        bridge.register_pending(device_id, rx_io_id);

        crate::io::virtio::with_virtio_net_at_index(index, |device| {
            device.process_rx_completions();
        })
        .expect("device");

        let processed = crate::io::io_scheduler::process_deferred_completions_local();
        assert!(processed >= 2, "expected both TX and RX deferred completions");
        assert_eq!(bridge.pending_count(device_id), 0);

        clear_virtio_net_devices_for_tests();
        clear_poll_handler_registry_for_tests();
    }

    #[test_case]
    fn test_complete_rx_packetref_handoff_and_repost() {
        // Ensure mempool is available for PacketRef posting
        let _ = mempool::init_net_mempool(4);

        // Create and initialize device
        let mut dev = VirtioNetDevice::new(Box::new(NoopTransport));
        assert!(dev.init().is_ok());

        let rxq = dev.rx_queue.as_ref().expect("rx_queue present after init");

        // Post a PacketRef into the RX queue
        assert!(dev.try_post_rx_packet(rxq).unwrap());

        // Grab the desc index of the posted PacketRef
        let desc_idx = {
            let map = dev.rx_packetrefs.lock();
            *map.keys().next().expect("expected a posted PacketRef")
        };

        // Populate the PacketRef payload to simulate device write
        let payload = b"driver-test";
        let header_size = core::mem::size_of::<crate::io::virtio::net::VirtioNetHeader>();
        {
            let mut map = dev.rx_packetrefs.lock();
            let inflight = map.get_mut(&desc_idx).expect("inflight present");
            let buf = inflight.packet.data_mut();
            // Write virtio header (zeros) + ethernet/payload starting at header_size
            for i in 0..header_size { buf[i] = 0; }
            let start = header_size;
            buf[start..start + payload.len()].copy_from_slice(payload);
        }

        // Ensure bridge counter is zero before completion
        let before = driver_bridge::get_bridge_stats().rx_packets;

        // Simulate device placing a used ring entry for the posted desc
        unsafe {
            let used = &mut *rxq.used_ring.as_ptr();
            let slot = (used.idx % rxq.size) as usize;
            used.ring[slot] = VringUsedElem { id: desc_idx as u32, len: (header_size + payload.len()) as u32 };
            used.idx = used.idx.wrapping_add(1);
        }

        // Process RX completions (this should call complete_rx_packetref)
        dev.process_rx_completions();

        // Bridge should have observed one RX (process_received_packet_zero_copy increments RX_PACKETS)
        let after = driver_bridge::get_bridge_stats().rx_packets;
        assert!(after >= before + 1, "bridge did not observe RX packet");

        // The original desc entry must have been consumed (removed)
        let map = dev.rx_packetrefs.lock();
        assert!(!map.contains_key(&desc_idx), "old desc should be removed after completion");
        // A replacement PacketRef should have been reposted (map should not be empty)
        assert!(!map.is_empty(), "replacement PacketRef should be posted");
    }

    #[test_case]
    fn test_irq_path_completes_scheduler_pending_tx_and_rx() {
        run_irq_path_completes_scheduler_pending_tx_and_rx(0);
    }

    #[test_case]
    fn test_irq_path_completes_scheduler_pending_tx_and_rx_nonzero_index() {
        run_irq_path_completes_scheduler_pending_tx_and_rx(1);
    }
}
