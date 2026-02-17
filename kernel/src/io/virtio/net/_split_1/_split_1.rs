use super::*;


// ============================================================================
// DMA Preparation Helpers (shared by poll implementations)
// ============================================================================

/// Result of DMA buffer preparation for virtio-net I/O.
mod _split_1;
pub(crate) struct DmaPrepareResult {
    dma_addr: u64,
    mapped_iova: Option<u64>,
    mapped_len: usize,
    bounce_handle: Option<crate::io::iommu::api::DmaHandle<[u8]>>,
}

/// Fill a bounce buffer region for TX.
///
/// When `data.len() < total_len`, the region is zero-filled first (header padding).
pub(crate) fn fill_bounce_tx(buf: &mut [u8], offset: usize, data: &[u8], total_len: usize) {
    if total_len == 0 {
        return;
    }
    if data.len() < total_len {
        buf[offset..offset + total_len].fill(0);
    }
    let copy_len = core::cmp::min(data.len(), total_len);
    if copy_len > 0 {
        buf[offset..offset + copy_len].copy_from_slice(&data[..copy_len]);
    }
}

/// IOMMUバウンスバッファのTXマッピングを準備する
pub(crate) fn prepare_iommu_bounce_tx(
    device_id: Option<IommuDeviceId>,
    result: &mut DmaPrepareResult,
    page_offset: usize,
    can_map_page: bool,
    data: &[u8],
    total_len: usize,
) -> Result<(), VirtioNetError> {
    let (alloc_len, offset) = if can_map_page {
        (crate::mm::PAGE_SIZE_4K, page_offset)
    } else {
        (total_len, 0)
    };
    let mut rref = allocate_iommu_bounce_bytes(alloc_len).map_err(|err| match err {
        IommuBounceAllocError::InvalidLen => VirtioNetError::BufferTooSmall,
        IommuBounceAllocError::AllocFailed => VirtioNetError::DeviceError,
    })?;
    fill_bounce_tx(&mut rref, offset, data, total_len);
    let handle = match device_id {
        Some(device) => map_rref_slice_for_device(rref, &device, DmaDirection::ToDevice),
        None => DmaHandle::map_rref_slice(rref, 0, DmaDirection::ToDevice),
    }
    .map_err(|_| VirtioNetError::DeviceError)?;
    result.dma_addr = handle.iova() + if can_map_page { page_offset as u64 } else { 0 };
    result.bounce_handle = Some(handle);
    if can_map_page {
        result.mapped_len = crate::mm::PAGE_SIZE_4K;
    }
    Ok(())
}

/// Prepare a DMA mapping for a TX operation.
///
/// Handles IOMMU bounce buffer allocation + data copy + device mapping.
pub(crate) fn prepare_dma_mapping_tx(
    device_id: Option<IommuDeviceId>,
    phys_addr_val: u64,
    data: &[u8],
    total_len: usize,
) -> Result<DmaPrepareResult, VirtioNetError> {
    let page_mask = (crate::mm::PAGE_SIZE_4K as u64) - 1;
    let page_offset = (phys_addr_val & page_mask) as usize;
    let map_len = crate::mm::PAGE_SIZE_4K;
    let can_map_page = page_offset + total_len <= map_len;

    let mut result = DmaPrepareResult {
        dma_addr: phys_addr_val,
        mapped_iova: None,
        mapped_len: 0,
        bounce_handle: None,
    };

    if is_iommu_enabled() {
        prepare_iommu_bounce_tx(device_id, &mut result, page_offset, can_map_page, data, total_len)?;
    } else if is_iommu_required() {
        return Err(VirtioNetError::DeviceError);
    }

    Ok(result)
}

/// IOMMUバウンスバッファのRXマッピングを準備する
pub(crate) fn prepare_iommu_bounce_rx(
    device_id: Option<IommuDeviceId>,
    result: &mut DmaPrepareResult,
    page_offset: usize,
    can_map_page: bool,
    data_len: usize,
) -> Result<(), VirtioNetError> {
    let alloc_len = if can_map_page { crate::mm::PAGE_SIZE_4K } else { data_len };
    let rref = allocate_iommu_bounce_bytes(alloc_len).map_err(|err| match err {
        IommuBounceAllocError::InvalidLen => VirtioNetError::BufferTooSmall,
        IommuBounceAllocError::AllocFailed => VirtioNetError::DeviceError,
    })?;
    let handle = match device_id {
        Some(device) => map_rref_slice_for_device(rref, &device, DmaDirection::FromDevice),
        None => DmaHandle::map_rref_slice(rref, 0, DmaDirection::FromDevice),
    }
    .map_err(|_| VirtioNetError::DeviceError)?;
    result.dma_addr = handle.iova() + if can_map_page { page_offset as u64 } else { 0 };
    result.bounce_handle = Some(handle);
    if can_map_page {
        result.mapped_len = crate::mm::PAGE_SIZE_4K;
    }
    Ok(())
}

/// Prepare a DMA mapping for an RX operation (no data copy needed).
pub(crate) fn prepare_dma_mapping_rx(
    device_id: Option<IommuDeviceId>,
    phys_addr_val: u64,
    data_len: usize,
) -> Result<DmaPrepareResult, VirtioNetError> {
    let page_mask = (crate::mm::PAGE_SIZE_4K as u64) - 1;
    let page_offset = (phys_addr_val & page_mask) as usize;
    let map_len = crate::mm::PAGE_SIZE_4K;
    let can_map_page = page_offset + data_len <= map_len;

    let mut result = DmaPrepareResult {
        dma_addr: phys_addr_val,
        mapped_iova: None,
        mapped_len: 0,
        bounce_handle: None,
    };

    if is_iommu_enabled() {
        prepare_iommu_bounce_rx(device_id, &mut result, page_offset, can_map_page, data_len)?;
    } else if is_iommu_required() {
        return Err(VirtioNetError::DeviceError);
    }

    Ok(result)
}

/// Clean up DMA resources (bounce handle and IOMMU mapping) on error.
pub(crate) fn cleanup_dma_resources(
    device_id: Option<IommuDeviceId>,
    bounce_handle: Option<crate::io::iommu::api::DmaHandle<[u8]>>,
    mapped_iova: Option<u64>,
    mapped_len: usize,
) {
    if let Some(handle) = bounce_handle {
        if let Err(e) = handle.unmap() {
            log::warn!("[VIRTIO-NET] failed to unmap bounce buffer: {:?}", e);
        }
    }
    if let Some(iova) = mapped_iova {
        unmap_iommu_addr(device_id, iova, mapped_len);
    }
}

/// Unmap bounce handle and IOVA on TX/RX completion, returning error on failure.
pub(crate) fn unmap_dma_on_completion(
    device_id: Option<IommuDeviceId>,
    bounce_handle: &mut Option<crate::io::iommu::api::DmaHandle<[u8]>>,
    dma_iova: &mut Option<u64>,
    dma_len: usize,
) -> Result<Option<crate::ipc::RRef<[u8]>>, VirtioNetError> {
    let rref = if let Some(handle) = bounce_handle.take() {
        match handle.unmap() {
            Ok(rref) => Some(rref),
            Err(err) => {
                log::warn!("[VIRTIO-NET] failed to unmap bounce buffer: {:?}", err);
                return Err(VirtioNetError::DeviceError);
            }
        }
    } else {
        None
    };
    if let Some(iova) = dma_iova.take() {
        unmap_iommu_addr(device_id, iova, dma_len);
    }
    Ok(rref)
}

// ============================================================================
// Async Futures
// ============================================================================

/// 送信用Future
pub struct SendFuture<'a> {
    device: &'a VirtioNetDevice,
    data: *const u8,
    len: usize,
    submitted: bool,
    desc_idx: u16,
    dma_len: usize,
    dma_iova: Option<u64>,
    bounce_handle: Option<crate::io::iommu::api::DmaHandle<[u8]>>,
}

impl<'a> SendFuture<'a> {
    /// 送信バッファのサブミットを試みる
    fn try_submit(&mut self, cx: &mut Context<'_>) -> Result<(), VirtioNetError> {
        let tx_queue = self.device.tx_queue.as_ref()
            .ok_or(VirtioNetError::NotInitialized)?;

        let data_len = self.len;
        let data_ptr = self.data;
        let phys_addr_val = crate::mm::mapping::virt_to_phys(VirtAddr::new(data_ptr as u64)).as_u64();
        let data_slice = unsafe { crate::util::raw_ptr_as_slice(data_ptr, data_len) };

        let mut prep = prepare_dma_mapping_tx(
            self.device.iommu_device_id, phys_addr_val, data_slice, data_len,
        )?;

        if let Err(err) = check_device_dma_mask(self.device.iommu_device_id, prep.dma_addr, data_len) {
            cleanup_dma_resources(self.device.iommu_device_id, prep.bounce_handle.take(), prep.mapped_iova.take(), prep.mapped_len);
            return Err(err);
        }

        match tx_queue.add_tx_buffer_zero_copy(prep.dma_addr, data_len) {
            Ok(desc_idx) => {
                self.submitted = true;
                self.desc_idx = desc_idx;
                self.dma_iova = prep.mapped_iova;
                self.dma_len = prep.mapped_len;
                self.bounce_handle = prep.bounce_handle;
                tx_queue.register_waker(cx.waker().clone());
                tx_queue.notify();
                Ok(())
            }
            Err(e) => {
                cleanup_dma_resources(self.device.iommu_device_id, prep.bounce_handle, prep.mapped_iova, prep.mapped_len);
                Err(e)
            }
        }
    }
}

impl<'a> Future for SendFuture<'a> {
    type Output = Result<usize, VirtioNetError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        if !this.submitted {
            if let Err(e) = this.try_submit(cx) {
                return Poll::Ready(Err(e));
            }
        }

        // Check for TX completion
        let tx_queue = match this.device.tx_queue.as_ref() {
            Some(q) => q,
            None => return Poll::Ready(Err(VirtioNetError::NotInitialized)),
        };
        if tx_queue.take_completion(this.desc_idx).is_some() {
            unmap_dma_on_completion(this.device.iommu_device_id, &mut this.bounce_handle, &mut this.dma_iova, this.dma_len)?;
            Poll::Ready(Ok(this.len))
        } else {
            tx_queue.register_waker(cx.waker().clone());
            Poll::Pending
        }
    }
}

/// 受信用Future
pub struct RecvFuture<'a> {
    device: &'a VirtioNetDevice,
    buffer: &'a mut [u8],
    submitted: bool,
    desc_idx: u16,
    dma_len: usize,
    dma_iova: Option<u64>,
    bounce_handle: Option<crate::io::iommu::api::DmaHandle<[u8]>>,
}

impl<'a> RecvFuture<'a> {
    /// RXバッファのサブミットフェーズ
    fn try_submit_rx(&mut self, cx: &mut Context<'_>) -> Result<(), VirtioNetError> {
        if self.buffer.len() < VirtioNetHeader::SIZE {
            return Err(VirtioNetError::BufferTooSmall);
        }

        let rx_queue = self.device.rx_queue.as_ref()
            .ok_or(VirtioNetError::NotInitialized)?;

        let buffer_len = self.buffer.len();
        let phys_addr_val = crate::mm::mapping::virt_to_phys(VirtAddr::new(self.buffer.as_ptr() as u64)).as_u64();

        let mut prep = prepare_dma_mapping_rx(
            self.device.iommu_device_id, phys_addr_val, buffer_len,
        )?;

        if prep.bounce_handle.is_none() {
            if let Err(err) = check_device_dma_mask(self.device.iommu_device_id, prep.dma_addr, buffer_len) {
                cleanup_dma_resources(self.device.iommu_device_id, None, prep.mapped_iova.take(), prep.mapped_len);
                return Err(err);
            }
        }

        match rx_queue.add_rx_buffer_zero_copy(prep.dma_addr, buffer_len) {
            Ok(desc_idx) => {
                self.submitted = true;
                self.desc_idx = desc_idx;
                self.dma_iova = prep.mapped_iova;
                self.dma_len = prep.mapped_len;
                self.bounce_handle = prep.bounce_handle;
                rx_queue.register_waker(cx.waker().clone());
                Ok(())
            }
            Err(e) => {
                cleanup_dma_resources(self.device.iommu_device_id, prep.bounce_handle, prep.mapped_iova, prep.mapped_len);
                Err(e)
            }
        }
    }

    /// RX完了チェックとペイロード抽出
    fn check_rx_completion(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize, VirtioNetError>> {
        let rx_queue = match self.device.rx_queue.as_ref() {
            Some(q) => q,
            None => return Poll::Ready(Err(VirtioNetError::NotInitialized)),
        };

        let Some(len) = rx_queue.take_completion(self.desc_idx) else {
            rx_queue.register_waker(cx.waker().clone());
            return Poll::Pending;
        };

        let total_len = len as usize;
        let payload_len = total_len.saturating_sub(VirtioNetHeader::SIZE);
        let payload_cap = self.buffer.len().saturating_sub(VirtioNetHeader::SIZE);
        let payload_len = core::cmp::min(payload_len, payload_cap);

        let rref = unmap_dma_on_completion(
            self.device.iommu_device_id, &mut self.bounce_handle, &mut self.dma_iova, self.dma_len,
        )?;

        if let Some(rref) = rref {
            if payload_len > 0 {
                self.buffer[..payload_len].copy_from_slice(
                    &rref[VirtioNetHeader::SIZE..(VirtioNetHeader::SIZE + payload_len)],
                );
            }
        } else if payload_len > 0 {
            let buf_ptr = self.buffer.as_mut_ptr();
            unsafe {
                core::ptr::copy(buf_ptr.add(VirtioNetHeader::SIZE), buf_ptr, payload_len);
            }
        }

        Poll::Ready(Ok(payload_len))
    }
}

impl<'a> Future for RecvFuture<'a> {
    type Output = Result<usize, VirtioNetError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        if !this.submitted {
            match this.try_submit_rx(cx) {
                Ok(()) => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        this.check_rx_completion(cx)
    }
}

// ============================================================================
// ゼロコピー送受信 Futures（設計書 6.2）
// ============================================================================

/// ゼロコピー送信用Future
///
/// PacketRefの所有権を取得し、DMA転送が完了するまで保持する。
/// 完了後、PacketRefは自動的にMempoolに返却される。
pub struct ZeroCopySendFuture<'a> {
    device: &'a VirtioNetDevice,
    packet: Option<PacketRef>,
    submitted: bool,
    desc_idx: u16,
    dma_len: usize,
    dma_iova: Option<u64>,
    bounce_handle: Option<crate::io::iommu::api::DmaHandle<[u8]>>,
}

impl<'a> Future for ZeroCopySendFuture<'a> {
    type Output = Result<usize, VirtioNetError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        if !this.submitted {
            if let Err(e) = this.submit_zero_copy_tx(cx) {
                return Poll::Ready(Err(e));
            }
        }

        // 完了を確認
        let tx_queue = match this.device.tx_queue.as_ref() {
            Some(q) => q,
            None => return Poll::Ready(Err(VirtioNetError::NotInitialized)),
        };
        if tx_queue.take_completion(this.desc_idx).is_some() {
            unmap_dma_on_completion(this.device.iommu_device_id, &mut this.bounce_handle, &mut this.dma_iova, this.dma_len)?;
            let packet = this.packet.take();
            let len = packet.map(|p: crate::net::mempool::PacketRef| p.data().len()).unwrap_or(0);
            Poll::Ready(Ok(len))
        } else {
            tx_queue.register_waker(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl<'a> ZeroCopySendFuture<'a> {
    fn submit_zero_copy_tx(&mut self, cx: &mut Context<'_>) -> Result<(), VirtioNetError> {
        let tx_queue = self.device.tx_queue.as_ref()
            .ok_or(VirtioNetError::NotInitialized)?;
        let packet = self.packet.as_ref()
            .ok_or(VirtioNetError::BufferTooSmall)?;

        let data = packet.data();
        let phys_addr_val = packet.phys_addr().as_u64();
        let data_len = VirtioNetHeader::SIZE + data.len();

        let mut prep = prepare_dma_mapping_tx(
            self.device.iommu_device_id, phys_addr_val, data, data_len,
        )?;

        if let Err(err) = check_device_dma_mask(self.device.iommu_device_id, prep.dma_addr, data_len) {
            cleanup_dma_resources(self.device.iommu_device_id, prep.bounce_handle.take(), prep.mapped_iova.take(), prep.mapped_len);
            return Err(err);
        }

        match tx_queue.add_tx_buffer_zero_copy(prep.dma_addr, data.len()) {
            Ok(desc_idx) => {
                self.submitted = true;
                self.desc_idx = desc_idx;
                self.dma_iova = prep.mapped_iova;
                self.dma_len = prep.mapped_len;
                self.bounce_handle = prep.bounce_handle;
                tx_queue.register_waker(cx.waker().clone());
                Ok(())
            }
            Err(e) => {
                cleanup_dma_resources(self.device.iommu_device_id, prep.bounce_handle, prep.mapped_iova, prep.mapped_len);
                Err(e)
            }
        }
    }
}

/// ゼロコピー受信用Future
///
/// Mempoolから直接バッファを割り当て、DMAバッファとして使用。
/// 受信完了後、PacketRefとしてデータを返却する。
pub struct ZeroCopyRecvFuture<'a> {
    device: &'a VirtioNetDevice,
    pool: &'static crate::net::mempool::Mempool,
    packet: Option<PacketRef>,
    submitted: bool,
    desc_idx: u16,
    dma_len: usize,
    dma_iova: Option<u64>,
    bounce_handle: Option<crate::io::iommu::api::DmaHandle<[u8]>>,
}

impl<'a> ZeroCopyRecvFuture<'a> {
    /// Submit an RX buffer: allocate from mempool, prepare DMA mapping, and enqueue.
    fn submit_rx_buffer(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), VirtioNetError>> {
        let packet = self.pool.alloc().ok_or(VirtioNetError::BufferTooSmall)?;
        let phys_addr_val = packet.phys_addr().as_u64();
        let buffer_len = packet.capacity();

        let mut prep = match prepare_dma_mapping_rx(
            self.device.iommu_device_id, phys_addr_val, buffer_len,
        ) {
            Ok(p) => p,
            Err(e) => return Poll::Ready(Err(e)),
        };

        if let Err(err) = check_device_dma_mask(self.device.iommu_device_id, prep.dma_addr, buffer_len) {
            cleanup_dma_resources(self.device.iommu_device_id, prep.bounce_handle.take(), prep.mapped_iova.take(), prep.mapped_len);
            return Poll::Ready(Err(err));
        }

        let rx_queue = match self.device.rx_queue.as_ref() {
            Some(q) => q,
            None => return Poll::Ready(Err(VirtioNetError::NotInitialized)),
        };
        match rx_queue.add_rx_buffer_zero_copy(prep.dma_addr, buffer_len) {
            Ok(desc_idx) => {
                self.packet = Some(packet);
                self.submitted = true;
                self.desc_idx = desc_idx;
                self.dma_iova = prep.mapped_iova;
                self.dma_len = prep.mapped_len;
                self.bounce_handle = prep.bounce_handle;
                rx_queue.register_waker(cx.waker().clone());
                Poll::Pending
            }
            Err(e) => {
                cleanup_dma_resources(self.device.iommu_device_id, prep.bounce_handle, prep.mapped_iova, prep.mapped_len);
                Poll::Ready(Err(e))
            }
        }
    }

    /// Finalize a completed RX packet: unmap DMA and copy bounce if needed.
    fn finalize_packet(&mut self, len: u32) -> Result<PacketRef, VirtioNetError> {
        let rref = unmap_dma_on_completion(
            self.device.iommu_device_id, &mut self.bounce_handle, &mut self.dma_iova, self.dma_len,
        )?;

        let mut packet = self.packet.take().ok_or(VirtioNetError::BufferTooSmall)?;
        let copy_len = core::cmp::min(len as usize, packet.capacity() as usize);
        if let Some(rref) = rref {
            packet.set_len(copy_len);
            packet.data_mut()[..copy_len].copy_from_slice(&rref[..copy_len]);
        } else {
            packet.set_len(copy_len);
        }
        packet.advance(VirtioNetHeader::SIZE);
        Ok(packet)
    }
}

impl<'a> Future for ZeroCopyRecvFuture<'a> {
    type Output = Result<PacketRef, VirtioNetError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        if !this.submitted {
            match this.submit_rx_buffer(cx) {
                Poll::Pending => {} // submitted successfully, fall through to check completion
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => unreachable!(),
            }
        }

        let rx_queue = match this.device.rx_queue.as_ref() {
            Some(q) => q,
            None => return Poll::Ready(Err(VirtioNetError::NotInitialized)),
        };
        if let Some(len) = rx_queue.take_completion(this.desc_idx) {
            Poll::Ready(this.finalize_packet(len))
        } else {
            rx_queue.register_waker(cx.waker().clone());
            Poll::Pending
        }
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// VirtIO ネットワークエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtioNetError {
    /// デバイスが初期化されていない
    NotInitialized,
    /// キューが満杯
    QueueFull,
    /// バッファが不足
    BufferTooSmall,
    /// デバイスエラー
    DeviceError,
    /// タイムアウト
    Timeout,
}

impl core::fmt::Display for VirtioNetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VirtioNetError::NotInitialized => write!(f, "Device not initialized"),
            VirtioNetError::QueueFull => write!(f, "Queue is full"),
            VirtioNetError::BufferTooSmall => write!(f, "Buffer too small"),
            VirtioNetError::DeviceError => write!(f, "Device error"),
            VirtioNetError::Timeout => write!(f, "Operation timed out"),
        }
    }
}
