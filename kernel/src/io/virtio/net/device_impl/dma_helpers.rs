use super::*;


// ============================================================================
// DMA Preparation Helpers (shared by poll implementations)
// ============================================================================

/// Result of DMA buffer preparation for virtio-net I/O.
mod stats;
pub use stats::*;
mod poll_handler;
pub use poll_handler::*;
mod registry;
pub use registry::*;
mod dma_buffer;
pub use dma_buffer::*;
pub(crate) struct DmaPrepareResult {
    dma_addr: u64,
    mapped_iova: Option<u64>,
    mapped_len: usize,
    pool_bounce_buffer: Option<crate::io::dma::CoherentDmaBuffer>,
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
    device: &VirtioNetDevice,
    result: &mut DmaPrepareResult,
    page_offset: usize,
    can_map_page: bool,
    data: &[u8],
    total_len: usize,
) -> Result<(), VirtioNetError> {
    let alloc_len = if can_map_page { crate::mm::types::PAGE_SIZE_4K } else { total_len };
    let mut buffer = device.get_tx_bounce_buffer(alloc_len)?;
    let slice = unsafe { buffer.as_mut_slice() };
    if can_map_page {
        fill_bounce_tx(slice, page_offset, data, total_len);
    } else {
        fill_bounce_tx(slice, 0, data, total_len);
    }
    buffer.prepare_for_device();
    
    result.dma_addr = buffer.device_addr() + if can_map_page { page_offset as u64 } else { 0 };
    result.pool_bounce_buffer = Some(buffer);
    if can_map_page {
        result.mapped_len = crate::mm::types::PAGE_SIZE_4K;
    }
    Ok(())
}

/// Prepare a DMA mapping for a TX operation.
///
/// Handles IOMMU bounce buffer allocation + data copy + device mapping.
pub(crate) fn prepare_dma_mapping_tx(
    device: &VirtioNetDevice,
    phys_addr_val: u64,
    data: &[u8],
    total_len: usize,
) -> Result<DmaPrepareResult, VirtioNetError> {
    let page_mask = (crate::mm::types::PAGE_SIZE_4K as u64) - 1;
    let page_offset = (phys_addr_val & page_mask) as usize;
    let map_len = crate::mm::types::PAGE_SIZE_4K;
    let can_map_page = page_offset + total_len <= map_len;

    let mut result = DmaPrepareResult {
        dma_addr: phys_addr_val,
        mapped_iova: None,
        mapped_len: 0,
        pool_bounce_buffer: None,
    };

    if is_iommu_enabled() {
        prepare_iommu_bounce_tx(device, &mut result, page_offset, can_map_page, data, total_len)?;
    } else if is_iommu_required() {
        return Err(VirtioNetError::DeviceError);
    }

    Ok(result)
}

/// IOMMUバウンスバッファのRXマッピングを準備する
pub(crate) fn prepare_iommu_bounce_rx(
    device: &VirtioNetDevice,
    result: &mut DmaPrepareResult,
    page_offset: usize,
    can_map_page: bool,
    data_len: usize,
) -> Result<(), VirtioNetError> {
    let alloc_len = if can_map_page { crate::mm::types::PAGE_SIZE_4K } else { data_len };
    let buffer = device.get_rx_bounce_buffer(alloc_len)?;
    
    result.dma_addr = buffer.device_addr() + if can_map_page { page_offset as u64 } else { 0 };
    result.pool_bounce_buffer = Some(buffer);
    if can_map_page {
        result.mapped_len = crate::mm::types::PAGE_SIZE_4K;
    }
    Ok(())
}

/// Prepare a DMA mapping for an RX operation (no data copy needed).
pub(crate) fn prepare_dma_mapping_rx(
    device: &VirtioNetDevice,
    phys_addr_val: u64,
    data_len: usize,
) -> Result<DmaPrepareResult, VirtioNetError> {
    let page_mask = (crate::mm::types::PAGE_SIZE_4K as u64) - 1;
    let page_offset = (phys_addr_val & page_mask) as usize;
    let map_len = crate::mm::types::PAGE_SIZE_4K;
    let can_map_page = page_offset + data_len <= map_len;

    let mut result = DmaPrepareResult {
        dma_addr: phys_addr_val,
        mapped_iova: None,
        mapped_len: 0,
        pool_bounce_buffer: None,
    };

    if is_iommu_enabled() {
        prepare_iommu_bounce_rx(device, &mut result, page_offset, can_map_page, data_len)?;
    } else if is_iommu_required() {
        return Err(VirtioNetError::DeviceError);
    }

    Ok(result)
}

/// Clean up DMA resources (bounce handle and IOMMU mapping) on error.
pub(crate) fn cleanup_dma_resources(
    device: &VirtioNetDevice,
    bounce_buffer: Option<crate::io::dma::CoherentDmaBuffer>,
    mapped_iova: Option<u64>,
    mapped_len: usize,
    is_rx: bool,
) {
    if let Some(buf) = bounce_buffer {
        if is_rx {
            device.return_rx_bounce_buffer(buf);
        } else {
            device.return_tx_bounce_buffer(buf);
        }
    }
    if let Some(iova) = mapped_iova {
        let _ = unmap_iommu_addr(device.iommu_device_id, iova, mapped_len);
    }
}

/// Unmap bounce handle and IOVA on TX/RX completion, returning error on failure.
pub(crate) fn unmap_dma_on_completion(
    device: &VirtioNetDevice,
    bounce_buffer: &mut Option<crate::io::dma::CoherentDmaBuffer>,
    dma_iova: &mut Option<u64>,
    dma_len: usize,
    is_rx: bool,
) {
    if let Some(buf) = bounce_buffer.take() {
        if is_rx {
            device.return_rx_bounce_buffer(buf);
        } else {
            device.return_tx_bounce_buffer(buf);
        }
    }
    if let Some(iova) = dma_iova.take() {
        let _ = unmap_iommu_addr(device.iommu_device_id, iova, dma_len);
    }
}

// ============================================================================
// Async Futures
// ============================================================================

/// 送信用Future
pub struct SendFuture<'a> {
    pub(crate) device: &'a VirtioNetDevice,
    pub(crate) data: *const u8,
    pub(crate) len: usize,
    pub(crate) submitted: bool,
    pub(crate) desc_idx: u16,
    pub(crate) dma_len: usize,
    pub(crate) dma_iova: Option<u64>,
    pub(crate) pool_bounce_buffer: Option<crate::io::dma::CoherentDmaBuffer>,
}

impl<'a> SendFuture<'a> {
    /// 送信バッファのサブミットを試みる
    pub(super) fn try_submit(&mut self, cx: &mut Context<'_>) -> Result<(), VirtioNetError> {
        let tx_queue = self.device.first_tx_queue()
            .ok_or(VirtioNetError::NotInitialized)?;

        let data_len = self.len;
        let data_ptr = self.data;
        let phys_addr_val = crate::mm::virt::mapping::virt_to_phys(VirtAddr::new(data_ptr as u64)).as_u64();
        let data_slice = unsafe { crate::util::raw_ptr_as_slice(data_ptr, data_len) };

        let mut prep = prepare_dma_mapping_tx(
            self.device, phys_addr_val, data_slice, data_len,
        )?;

        if let Err(err) = check_device_dma_mask(self.device.iommu_device_id, prep.dma_addr, data_len) {
            cleanup_dma_resources(self.device, prep.pool_bounce_buffer.take(), prep.mapped_iova.take(), prep.mapped_len, false);
            return Err(err);
        }

        match tx_queue.add_tx_buffer_zero_copy(prep.dma_addr, data_len) {
            Ok(desc_idx) => {
                self.submitted = true;
                self.desc_idx = desc_idx;
                self.dma_iova = prep.mapped_iova;
                self.dma_len = prep.mapped_len;
                self.pool_bounce_buffer = prep.pool_bounce_buffer;
                tx_queue.register_waker(cx.waker().clone());
                tx_queue.notify();
                Ok(())
            }
            Err(e) => {
                cleanup_dma_resources(self.device, prep.pool_bounce_buffer, prep.mapped_iova, prep.mapped_len, false);
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
        let tx_queue = match this.device.first_tx_queue() {
            Some(q) => q,
            None => return Poll::Ready(Err(VirtioNetError::NotInitialized)),
        };
        if tx_queue.take_completion(this.desc_idx).is_some() {
            unmap_dma_on_completion(this.device, &mut this.pool_bounce_buffer, &mut this.dma_iova, this.dma_len, false);
            Poll::Ready(Ok(this.len))
        } else {
            tx_queue.register_waker(cx.waker().clone());
            Poll::Pending
        }
    }
}

/// 受信用Future
pub struct RecvFuture<'a> {
    pub(crate) device: &'a VirtioNetDevice,
    pub(crate) buffer: &'a mut [u8],
    pub(crate) submitted: bool,
    pub(crate) desc_idx: u16,
    pub(crate) dma_len: usize,
    pub(crate) dma_iova: Option<u64>,
    pub(crate) pool_bounce_buffer: Option<crate::io::dma::CoherentDmaBuffer>,
}

impl<'a> RecvFuture<'a> {
    /// RXバッファのサブミットフェーズ
    pub(super) fn try_submit_rx(&mut self, cx: &mut Context<'_>) -> Result<(), VirtioNetError> {
        if self.buffer.len() < VirtioNetHeader::SIZE {
            return Err(VirtioNetError::BufferTooSmall);
        }

        let rx_queue = self.device.first_rx_queue()
            .ok_or(VirtioNetError::NotInitialized)?;

        let buffer_len = self.buffer.len();
        let phys_addr_val = crate::mm::virt::mapping::virt_to_phys(VirtAddr::new(self.buffer.as_ptr() as u64)).as_u64();

        let mut prep = prepare_dma_mapping_rx(
            self.device, phys_addr_val, buffer_len,
        )?;

        if prep.pool_bounce_buffer.is_none() {
            if let Err(err) = check_device_dma_mask(self.device.iommu_device_id, prep.dma_addr, buffer_len) {
                cleanup_dma_resources(self.device, None, prep.mapped_iova.take(), prep.mapped_len, true);
                return Err(err);
            }
        }

        match rx_queue.add_rx_buffer_zero_copy(prep.dma_addr, buffer_len) {
            Ok(desc_idx) => {
                self.submitted = true;
                self.desc_idx = desc_idx;
                self.dma_iova = prep.mapped_iova;
                self.dma_len = prep.mapped_len;
                self.pool_bounce_buffer = prep.pool_bounce_buffer;
                rx_queue.register_waker(cx.waker().clone());
                Ok(())
            }
            Err(e) => {
                cleanup_dma_resources(self.device, prep.pool_bounce_buffer, prep.mapped_iova, prep.mapped_len, true);
                Err(e)
            }
        }
    }

    /// RX完了チェックとペイロード抽出
    pub(super) fn check_rx_completion(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize, VirtioNetError>> {
        let rx_queue = match self.device.first_rx_queue() {
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

        if let Some(ref buf) = self.pool_bounce_buffer {
            buf.finish_from_device();
            if payload_len > 0 {
                let slice = unsafe { buf.as_slice() };
                self.buffer[..payload_len].copy_from_slice(
                    &slice[VirtioNetHeader::SIZE..(VirtioNetHeader::SIZE + payload_len)],
                );
            }
        } else if payload_len > 0 {
            let buf_ptr = self.buffer.as_mut_ptr();
            unsafe {
                core::ptr::copy(buf_ptr.add(VirtioNetHeader::SIZE), buf_ptr, payload_len);
            }
        }
        
        unmap_dma_on_completion(
            self.device, &mut self.pool_bounce_buffer, &mut self.dma_iova, self.dma_len, true
        );

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
    pub(crate) device: &'a VirtioNetDevice,
    pub(crate) packet: Option<PacketRef>,
    pub(crate) submitted: bool,
    pub(crate) desc_idx: u16,
    pub(crate) dma_len: usize,
    pub(crate) dma_iova: Option<u64>,
    pub(crate) pool_bounce_buffer: Option<crate::io::dma::CoherentDmaBuffer>,
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
        let tx_queue = match this.device.first_tx_queue() {
            Some(q) => q,
            None => return Poll::Ready(Err(VirtioNetError::NotInitialized)),
        };
        if tx_queue.take_completion(this.desc_idx).is_some() {
            unmap_dma_on_completion(this.device, &mut this.pool_bounce_buffer, &mut this.dma_iova, this.dma_len, false);
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
    pub(super) fn submit_zero_copy_tx(&mut self, cx: &mut Context<'_>) -> Result<(), VirtioNetError> {
        let tx_queue = self.device.first_tx_queue()
            .ok_or(VirtioNetError::NotInitialized)?;
        let packet = self.packet.as_ref()
            .ok_or(VirtioNetError::BufferTooSmall)?;

        let data = packet.data();
        let phys_addr_val = packet.phys_addr().as_u64();
        let data_len = VirtioNetHeader::SIZE + data.len();

        let mut prep = prepare_dma_mapping_tx(
            self.device, phys_addr_val, data, data_len,
        )?;

        if let Err(err) = check_device_dma_mask(self.device.iommu_device_id, prep.dma_addr, data_len) {
            cleanup_dma_resources(self.device, prep.pool_bounce_buffer.take(), prep.mapped_iova.take(), prep.mapped_len, false);
            return Err(err);
        }

        match tx_queue.add_tx_buffer_zero_copy(prep.dma_addr, data.len()) {
            Ok(desc_idx) => {
                self.submitted = true;
                self.desc_idx = desc_idx;
                self.dma_iova = prep.mapped_iova;
                self.dma_len = prep.mapped_len;
                self.pool_bounce_buffer = prep.pool_bounce_buffer;
                tx_queue.register_waker(cx.waker().clone());
                Ok(())
            }
            Err(e) => {
                cleanup_dma_resources(self.device, prep.pool_bounce_buffer, prep.mapped_iova, prep.mapped_len, false);
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
    pub(crate) device: &'a VirtioNetDevice,
    pub(crate) pool: &'static crate::net::mempool::Mempool,
    pub(crate) packet: Option<PacketRef>,
    pub(crate) submitted: bool,
    pub(crate) desc_idx: u16,
    pub(crate) dma_len: usize,
    pub(crate) dma_iova: Option<u64>,
    pub(crate) pool_bounce_buffer: Option<crate::io::dma::CoherentDmaBuffer>,
}

impl<'a> ZeroCopyRecvFuture<'a> {
    /// Submit an RX buffer: allocate from mempool, prepare DMA mapping, and enqueue.
    pub(super) fn submit_rx_buffer(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), VirtioNetError>> {
        let packet = self.pool.alloc().ok_or(VirtioNetError::BufferTooSmall)?;
        let phys_addr_val = packet.phys_addr().as_u64();
        let buffer_len = packet.capacity();

        let mut prep = match prepare_dma_mapping_rx(
            self.device, phys_addr_val, buffer_len,
        ) {
            Ok(p) => p,
            Err(e) => return Poll::Ready(Err(e)),
        };

        if let Err(err) = check_device_dma_mask(self.device.iommu_device_id, prep.dma_addr, buffer_len) {
            cleanup_dma_resources(self.device, prep.pool_bounce_buffer.take(), prep.mapped_iova.take(), prep.mapped_len, true);
            return Poll::Ready(Err(err));
        }

        let rx_queue = match self.device.first_rx_queue() {
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
                self.pool_bounce_buffer = prep.pool_bounce_buffer;
                rx_queue.register_waker(cx.waker().clone());
                Poll::Pending
            }
            Err(e) => {
                cleanup_dma_resources(self.device, prep.pool_bounce_buffer, prep.mapped_iova, prep.mapped_len, true);
                Poll::Ready(Err(e))
            }
        }
    }

    /// Finalize a completed RX packet: unmap DMA and copy bounce if needed.
    pub(super) fn finalize_packet(&mut self, len: u32) -> Result<PacketRef, VirtioNetError> {
        let mut packet = self.packet.take().ok_or(VirtioNetError::BufferTooSmall)?;
        let copy_len = core::cmp::min(len as usize, packet.capacity() as usize);
        
        if let Some(ref buf) = self.pool_bounce_buffer {
            buf.finish_from_device();
            let slice = unsafe { buf.as_slice() };
            packet.set_len(copy_len);
            packet.data_mut()[..copy_len].copy_from_slice(&slice[..copy_len]);
        } else {
            packet.set_len(copy_len);
        }
        
        unmap_dma_on_completion(
            self.device, &mut self.pool_bounce_buffer, &mut self.dma_iova, self.dma_len, true
        );

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

        let rx_queue = match this.device.first_rx_queue() {
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
