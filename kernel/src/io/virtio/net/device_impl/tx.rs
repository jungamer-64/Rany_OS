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
        .ok_or(VirtioNetError::DeviceError)?;

        if is_iommu_enabled() && self.iommu_device_id.is_some() && !buffer.is_iommu_mapped() {
            log::error!(
                "[NET-TX] IOMMU enabled but TX buffer is not mapped for device DMA; refusing phys fallback"
            );
            return Err(VirtioNetError::DeviceError);
        }

        // Copy payload into the DMA buffer
        let dst = unsafe { buffer.as_mut_slice() };
        if dst.len() < data_len {
            return Err(VirtioNetError::BufferTooSmall);
        }
        dst[..data_len].copy_from_slice(data);

        if let Some(tx_queue) = self.first_tx_queue() {
            let phys = buffer.phys_addr().as_u64();
            let device_addr = buffer.device_addr();
            crate::io::log::early_print(&alloc::format!(
                "[EARLY][NET-TX] about to call add_tx_buffer_zero_copy phys=0x{:x} device_addr=0x{:x} len={}\n",
                phys,
                device_addr,
                data_len
            ));
            match tx_queue.add_tx_buffer_zero_copy(device_addr, data_len) {
                Ok(desc_idx) => {
                    crate::io::log::early_print(&alloc::format!("[EARLY][NET-TX] add_tx_buffer_zero_copy returned desc={}\n", desc_idx));
                    let mut guard = self.tx_inflight.lock().unwrap_or_else(|e| e.into_inner());
                    guard.insert(desc_idx, buffer);
                    crate::io::log::early_print(&alloc::format!(
                        "[EARLY][NET-TX] queued desc={} phys=0x{:x} device_addr=0x{:x} len={}\n",
                        desc_idx,
                        phys,
                        device_addr,
                        data_len
                    ));
                    log::info!(
                        "[NET-TX] queued desc={} phys=0x{:x} device_addr=0x{:x} len={}",
                        desc_idx,
                        phys,
                        device_addr,
                        data_len
                    );
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
    pub fn enqueue_send_zero_copy(&self, packet: crate::net::PacketRef) -> Result<(), VirtioNetError> {
        let tx_queue = match self.first_tx_queue() {
            Some(q) => q,
            None => return Err(VirtioNetError::NotInitialized),
        };

        let data = packet.data();
        let phys_addr = packet.phys_addr();
        let payload_len = data.len();
        let phys_addr_val = phys_addr.as_u64();

        let (dma_addr, mapped_iova, mapped_len, bounce_buffer) =
            self.prepare_zero_copy_dma(phys_addr_val, data, payload_len)?;

        if let Err(err) = check_device_dma_mask(self.iommu_device_id, dma_addr, payload_len) {
            self.cleanup_dma_on_error(bounce_buffer, mapped_iova, mapped_len);
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
                let mut guard = self.tx_packetrefs.lock().unwrap_or_else(|e| e.into_inner());
                guard.insert(desc_idx, entry);
                tx_queue.notify();
                Ok(())
            }
            Err(e) => {
                self.cleanup_dma_on_error(bounce_buffer, mapped_iova, mapped_len);
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
    ) -> Result<(u64, Option<u64>, usize, Option<crate::io::dma::CoherentDmaBuffer>), VirtioNetError> {
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
    ) -> Result<(u64, Option<u64>, usize, Option<crate::io::dma::CoherentDmaBuffer>), VirtioNetError> {
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
    ) -> Result<(u64, Option<u64>, usize, Option<crate::io::dma::CoherentDmaBuffer>), VirtioNetError> {
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

    /// Legacy TX completion handler shared by IRQ path and PollHandler path.
    ///
    /// Returns true when the descriptor belonged to the legacy data path and was handled.
    pub(super) fn handle_legacy_tx_completion(
        &self,
        tx_queue: &NetVirtQueue,
        desc_idx: u16,
        len: u32,
    ) -> bool {
        let buf = {
            let mut guard = self.tx_inflight.lock().unwrap_or_else(|e| e.into_inner());
            guard.remove(&desc_idx)
        };
        if let Some(_buf) = buf {
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

        let entry = {
            let mut guard = self.tx_packetrefs.lock().unwrap_or_else(|e| e.into_inner());
            guard.remove(&desc_idx)
        };
        if let Some(entry) = entry {
            if tx_queue.take_completion(desc_idx).is_none() {
                log::warn!(
                    "[VIRTIO-NET] TX legacy completion missing pending slot desc={}",
                    desc_idx
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
            crate::io::log::early_print(&alloc::format!(
                "[EARLY][VIRTIO-NET] TX-COMP freed PacketRef for desc={} len={}\n",
                desc_idx, len
            ));
            log::info!("[VIRTIO-NET][TX-COMP] freed PacketRef for desc={}", desc_idx);
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
    }
}
