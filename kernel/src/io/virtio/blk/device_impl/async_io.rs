use super::*;
use crate::sync::PoisonRwLock;

// ============================================================================
// Async Futures
// ============================================================================

mod interrupt_sync;
pub use interrupt_sync::*;
#[cfg(all(test, not(feature = "qemu-test-export")))]
#[path = "../tests.rs"]
mod tests;

const MAX_BLK_COMPLETIONS_PER_POLL: usize = 128;

/// デスクリプタ完了をポーリングする
pub(crate) fn poll_for_completion(
    device: &VirtioBlkDevice,
    queue_idx: usize,
    desc_id: u16,
) -> Option<(u16, u32)> {
    let queue = &device.queues[queue_idx];
    let mut queue_guard = queue.lock().unwrap_or_else(|e| e.into_inner());
    let mut target = None;
    let mut processed = 0usize;
    // LOOP_PROOF: mode=condition; reason=Completion drain is capped per poll and exits on empty queue or MAX_BLK_COMPLETIONS_PER_POLL.;
    while processed < MAX_BLK_COMPLETIONS_PER_POLL {
        let Some((completed_id, len)) = queue_guard.poll_complete() else {
            break;
        };
        processed += 1;
        device.process_completion_entry(&*queue_guard, queue_idx, completed_id, len);
        if completed_id == desc_id {
            target = Some((completed_id, len));
        }
    }
    target
}

/// DMAバッファのサイズを検証してバイト数を返す
pub(crate) fn validate_dma_buf_size(buf_len: usize) -> Result<u32, BlockError> {
    if buf_len % 512 != 0 {
        return Err(BlockError::InvalidParam);
    }
    if buf_len > (u32::MAX as usize) {
        return Err(BlockError::InvalidParam);
    }
    Ok(buf_len as u32)
}

pub(crate) fn register_desc_waker(
    device: &VirtioBlkDevice,
    queue_idx: usize,
    desc_id: u16,
    waker: &core::task::Waker,
) {
    if let Some(queue_wakers) = device.pending_wakers.get(queue_idx) {
        let mut wakers = queue_wakers.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(slot) = wakers.get_mut(desc_id as usize) {
            *slot = Some(waker.clone());
        }
    }
}

/// Future for async DMA read operation (uses device-visible DMA address).
pub struct DmaReadFuture<'a> {
    pub(crate) device: &'a VirtioBlkDevice,
    pub(crate) sector: u64,
    pub(crate) dma_addr: u64,
    pub(crate) buf: &'a mut [u8],
    pub(crate) submitted: bool,
    pub(crate) desc_id: Option<u16>,
    pub(crate) queue_idx: usize,
}

impl<'a> Future for DmaReadFuture<'a> {
    type Output = Result<usize, BlockError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.submitted {
            let len = validate_dma_buf_size(self.buf.len())?;

            match self
                .device
                .submit_read(self.sector, self.dma_addr, len, self.queue_idx)
            {
                Ok(desc_id) => {
                    self.desc_id = Some(desc_id);
                    self.submitted = true;
                    register_desc_waker(self.device, self.queue_idx, desc_id, cx.waker());
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        if let Some(desc_id) = self.desc_id {
            if poll_for_completion(self.device, self.queue_idx, desc_id).is_some() {
                return Poll::Ready(Ok(self.buf.len()));
            }
        }

        if let Some(desc_id) = self.desc_id {
            register_desc_waker(self.device, self.queue_idx, desc_id, cx.waker());
        }

        Poll::Pending
    }
}

/// Future for async DMA write operation (uses device-visible DMA address).
pub struct DmaWriteFuture<'a> {
    pub(crate) device: &'a VirtioBlkDevice,
    pub(crate) sector: u64,
    pub(crate) dma_addr: u64,
    pub(crate) buf: &'a [u8],
    pub(crate) submitted: bool,
    pub(crate) desc_id: Option<u16>,
    pub(crate) queue_idx: usize,
}

impl<'a> Future for DmaWriteFuture<'a> {
    type Output = Result<usize, BlockError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.submitted {
            let len = validate_dma_buf_size(self.buf.len())?;

            match self
                .device
                .submit_write(self.sector, self.dma_addr, len, self.queue_idx)
            {
                Ok(desc_id) => {
                    self.desc_id = Some(desc_id);
                    self.submitted = true;
                    register_desc_waker(self.device, self.queue_idx, desc_id, cx.waker());
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        if let Some(desc_id) = self.desc_id {
            if poll_for_completion(self.device, self.queue_idx, desc_id).is_some() {
                return Poll::Ready(Ok(self.buf.len()));
            }
        }

        if let Some(desc_id) = self.desc_id {
            register_desc_waker(self.device, self.queue_idx, desc_id, cx.waker());
        }

        Poll::Pending
    }
}

/// Future for async flush operation
pub struct FlushFuture<'a> {
    pub(crate) device: &'a VirtioBlkDevice,
    pub(crate) submitted: bool,
    pub(crate) desc_id: Option<u16>,
    pub(crate) queue_idx: usize,
}

impl<'a> Future for FlushFuture<'a> {
    type Output = Result<(), BlockError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.submitted {
            // Check if flush is supported
            if self.device.core.features & features::VIRTIO_BLK_F_FLUSH == 0 {
                return Poll::Ready(Err(BlockError::Unsupported));
            }

            // Submit flush request using submit_flush
            match self.device.submit_flush(self.queue_idx) {
                Ok(desc_id) => {
                    self.desc_id = Some(desc_id);
                    self.submitted = true;
                    register_desc_waker(self.device, self.queue_idx, desc_id, cx.waker());
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        // Poll for completion
        if let Some(desc_id) = self.desc_id {
            if poll_for_completion(self.device, self.queue_idx, desc_id).is_some() {
                return Poll::Ready(Ok(()));
            }
            register_desc_waker(self.device, self.queue_idx, desc_id, cx.waker());
        }

        Poll::Pending
    }
}

// ============================================================================
// Block Device Trait
// ============================================================================

/// Generic block device trait for async I/O
pub trait AsyncBlockDevice: Send + Sync {
    /// Read sectors into buffer
    fn read<'a>(
        &'a self,
        sector: u64,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize, BlockError>> + Send + 'a>>;

    /// Write buffer to sectors
    fn write<'a>(
        &'a self,
        sector: u64,
        buf: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize, BlockError>> + Send + 'a>>;

    /// Flush pending writes
    fn flush<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<(), BlockError>> + Send + 'a>>;

    /// Get device capacity in sectors
    fn capacity(&self) -> u64;

    /// Get sector size
    fn sector_size(&self) -> u32;
}

// ============================================================================
// VFS Zero-Copy Adapter (transitional: OwnedBytes + borrowed read)
// ============================================================================

pub(crate) const SECTOR_SIZE: u32 = 512;

pub(crate) fn map_vfs_block_error(err: BlockError) -> VfsBlockError {
    match err {
        BlockError::NotReady => VfsBlockError::NotReady,
        BlockError::IoError | BlockError::Unsupported => VfsBlockError::IoError,
        BlockError::QueueFull => VfsBlockError::QueueFull,
        BlockError::InvalidParam => VfsBlockError::InvalidBufferSize,
    }
}

pub(crate) fn effective_block_size_from_core(_core: &CoreBlkDevice) -> u32 {
    // For now assume 512 if not in CoreBlkDevice
    SECTOR_SIZE
}

pub(crate) fn block_to_sector(block: u64, block_size: u32) -> Result<u64, VfsBlockError> {
    if block_size == 0 || (block_size % SECTOR_SIZE) != 0 {
        return Err(VfsBlockError::InvalidBufferSize);
    }
    let sectors_per_block = (block_size / SECTOR_SIZE) as u64;
    block
        .checked_mul(sectors_per_block)
        .ok_or(VfsBlockError::InvalidBufferSize)
}

/// Validate block I/O parameters common to read/write.
pub(crate) fn validate_block_io_params_from_core(
    core: &CoreBlkDevice,
    block: u64,
    len: usize,
) -> VfsBlockResult<Option<u64>> {
    let block_size = effective_block_size_from_core(core) as usize;
    if block_size == 0 {
        return Err(VfsBlockError::InvalidBufferSize);
    }
    if len == 0 {
        return Ok(None);
    }
    if (len % block_size) != 0 {
        return Err(VfsBlockError::InvalidBufferSize);
    }
    let blocks = len / block_size;
    if blocks > (u32::MAX as usize) {
        return Err(VfsBlockError::InvalidBufferSize);
    }
    let sector = block_to_sector(block, block_size as u32)?;
    Ok(Some(sector))
}

/// Allocate an IOMMU bounce buffer, mapping the error type for VFS.
pub(crate) fn alloc_bounce_buffer(len: usize) -> VfsBlockResult<crate::ipc::RRef<[u8]>> {
    allocate_iommu_bounce_bytes(len).map_err(|err| match err {
        IommuBounceAllocError::InvalidLen => VfsBlockError::InvalidBufferSize,
        IommuBounceAllocError::AllocFailed => VfsBlockError::IoError,
    })
}

impl ZeroCopyBlockDevice for VirtioBlkDevice {
    type Buffer = OwnedBytes;

    fn info(&self) -> VfsBlockDeviceInfo {
        let block_size = effective_block_size_from_core(&self.core);
        let sectors_per_block = (block_size / SECTOR_SIZE) as u64;
        let total_blocks = if sectors_per_block == 0 {
            0
        } else {
            self.core.capacity / sectors_per_block
        };

        VfsBlockDeviceInfo {
            name: "virtio-blk",
            total_blocks,
            block_size,
            read_only: false,
            max_sectors: self.core.seg_max,
            num_queues: 1,
        }
    }

    fn flush(&self) -> VfsBlockResult<()> {
        match crate::task::block_on(self.flush_async()) {
            Ok(()) => Ok(()),
            Err(BlockError::Unsupported) => Ok(()),
            Err(err) => Err(map_vfs_block_error(err)),
        }
    }

    fn alloc_buffer(&self, size: usize) -> VfsBlockResult<Self::Buffer> {
        Ok(OwnedBytes::from_vec(vec![0u8; size]))
    }

    fn read_async(&self, block: u64, count: u32) -> ZcFuture<'_, VfsBlockResult<Self::Buffer>> {
        let block_size = effective_block_size_from_core(&self.core) as usize;
        if block_size == 0 {
            return Box::pin(async { Err(VfsBlockError::InvalidBufferSize) });
        }
        let size = match block_size.checked_mul(count as usize) {
            Some(size) => size,
            None => return Box::pin(async { Err(VfsBlockError::InvalidBufferSize) }),
        };
        let sector = match block_to_sector(block, block_size as u32) {
            Ok(sector) => sector,
            Err(err) => return Box::pin(async move { Err(err) }),
        };

        Box::pin(async move {
            let mut buf = OwnedBytes::from_vec(vec![0u8; size]);
            if size == 0 {
                return Ok(buf);
            }
            VirtioBlkDevice::read_async(self, sector, buf.as_mut())
                .await
                .map_err(map_vfs_block_error)?;
            Ok(buf)
        })
    }

    fn write_async(
        &self,
        block: u64,
        buffer: Self::Buffer,
    ) -> ZcFuture<'_, VfsBlockResult<Self::Buffer>> {
        let block_size = effective_block_size_from_core(&self.core) as usize;
        if block_size == 0 {
            return Box::pin(async { Err(VfsBlockError::InvalidBufferSize) });
        }
        let len = buffer.as_ref().len();
        if len == 0 {
            return Box::pin(async move { Ok(buffer) });
        }
        if (len % block_size) != 0 {
            return Box::pin(async move { Err(VfsBlockError::InvalidBufferSize) });
        }
        let sector = match block_to_sector(block, block_size as u32) {
            Ok(sector) => sector,
            Err(err) => return Box::pin(async move { Err(err) }),
        };

        Box::pin(async move {
            VirtioBlkDevice::write_async(self, sector, buffer.as_ref())
                .await
                .map_err(map_vfs_block_error)?;
            Ok(buffer)
        })
    }

    fn read_into_buf<'a>(
        &'a self,
        block: u64,
        dst: &'a mut dyn IoBufferMut,
    ) -> ZcFuture<'a, VfsBlockResult<()>> {
        let dma = dst.dma_info();
        let buf = dst.as_mut_slice();
        let len = buf.len();

        let sector = match validate_block_io_params_from_core(&self.core, block, len) {
            Ok(Some(sector)) => sector,
            Ok(None) => return Box::pin(async { Ok(()) }),
            Err(err) => return Box::pin(async move { Err(err) }),
        };

        if let Some(dma) = dma {
            return self.dma_read_dispatch(sector, dma, buf, len);
        }

        Box::pin(async move {
            VirtioBlkDevice::read_async(self, sector, buf)
                .await
                .map_err(map_vfs_block_error)?;
            Ok(())
        })
    }

    fn write_from_buf<'a>(
        &'a self,
        block: u64,
        src: &'a dyn IoBuffer,
    ) -> ZcFuture<'a, VfsBlockResult<()>> {
        let dma = src.dma_info();
        let data = src.as_slice();
        let len = data.len();

        let sector = match validate_block_io_params_from_core(&self.core, block, len) {
            Ok(Some(sector)) => sector,
            Ok(None) => return Box::pin(async { Ok(()) }),
            Err(err) => return Box::pin(async move { Err(err) }),
        };

        if let Some(dma) = dma {
            return self.dma_write_dispatch(sector, dma, data, len);
        }

        Box::pin(async move {
            VirtioBlkDevice::write_async(self, sector, data)
                .await
                .map_err(map_vfs_block_error)?;
            Ok(())
        })
    }
}

// ============================================================================
// Global Device Instance
// ============================================================================

/// Primary (legacy) VirtIO block device slot kept for compatibility (`index=0`).
pub(crate) static VIRTIO_BLK_DEVICE: crate::sync::PoisonLock<Option<Arc<VirtioBlkDevice>>> =
    crate::sync::PoisonLock::new(None);

/// Additional VirtIO block devices (`index != 0`).
pub(crate) static VIRTIO_BLK_DEVICES: PoisonRwLock<
    alloc::collections::BTreeMap<u8, Arc<VirtioBlkDevice>>,
> = PoisonRwLock::new(alloc::collections::BTreeMap::new());

fn install_virtio_blk_device(index: u8, device_arc: Arc<VirtioBlkDevice>) {
    if index == 0 {
        *VIRTIO_BLK_DEVICE.lock().unwrap_or_else(|e| e.into_inner()) = Some(device_arc);
    } else {
        VIRTIO_BLK_DEVICES
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(index, device_arc);
    }
}

/// Get a shared reference to the VirtIO block device by index.
pub fn get_virtio_blk_device_at_index(index: u8) -> Option<Arc<VirtioBlkDevice>> {
    if index == 0 {
        let device_guard = VIRTIO_BLK_DEVICE.lock().unwrap_or_else(|e| e.into_inner());
        device_guard.clone()
    } else {
        VIRTIO_BLK_DEVICES
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&index)
            .cloned()
    }
}

/// Initialize the global VirtIO block device at a specific index.
#[cfg(test)]
pub unsafe fn init_virtio_blk_at_index(index: u8, mmio_base: u64) -> Result<(), BlockError> {
    let transport =
        unsafe { VirtioMmioTransport::new(mmio_base as usize).map_err(|_| BlockError::NotReady)? };
    let device = IommuDeviceId::new(0, 0, index, 0);
    crate::io::iommu::testkit::fixtures::ensure_test_intel_iommu_device(device);
    let mut dev = VirtioBlkDevice::new(Box::new(transport), device);
    dev.init()?;

    let device_arc = Arc::new(dev);

    log::info!(
        "VirtIO-blk index={} initialized: {} sectors, {} bytes/sector\n",
        index,
        device_arc.config().capacity,
        device_arc.config().block_size
    );

    install_virtio_blk_device(index, device_arc);
    Ok(())
}

/// Initialize the global VirtIO block device (legacy `index=0`).
#[cfg(test)]
pub unsafe fn init_virtio_blk(mmio_base: u64) -> Result<(), BlockError> {
    init_virtio_blk_at_index(0, mmio_base)
}

/// Initialize the global VirtIO block device with an IOMMU device ID at a specific index.
pub unsafe fn init_virtio_blk_for_device_at_index(
    index: u8,
    mmio_base: u64,
    device: IommuDeviceId,
) -> Result<(), BlockError> {
    let transport =
        unsafe { VirtioMmioTransport::new(mmio_base as usize).map_err(|_| BlockError::NotReady)? };
    let mut dev = VirtioBlkDevice::new_with_device(Box::new(transport), device);
    dev.init()?;

    let device_arc = Arc::new(dev);

    log::info!(
        "VirtIO-blk index={} initialized: {} sectors, {} bytes/sector\n",
        index,
        device_arc.config().capacity,
        device_arc.config().block_size
    );

    install_virtio_blk_device(index, device_arc);
    Ok(())
}

/// Initialize the global VirtIO block device with an IOMMU device ID (legacy `index=0`).
pub unsafe fn init_virtio_blk_for_device(
    mmio_base: u64,
    device: IommuDeviceId,
) -> Result<(), BlockError> {
    init_virtio_blk_for_device_at_index(0, mmio_base, device)
}

/// Initialize the global VirtIO block device from an existing VirtioTransport at a specific index.
pub unsafe fn init_virtio_blk_with_transport_at_index(
    index: u8,
    transport: Box<dyn VirtioTransport>,
    iommu_device_id: IommuDeviceId,
) -> Result<(), BlockError> {
    let mut dev = VirtioBlkDevice::new_with_device(transport, iommu_device_id);
    dev.init()?;

    let device_arc = Arc::new(dev);

    log::info!(
        "VirtIO-blk index={} initialized: {} sectors, {} bytes/sector\n",
        index,
        device_arc.config().capacity,
        device_arc.config().block_size
    );

    install_virtio_blk_device(index, device_arc);
    Ok(())
}

/// Initialize the global VirtIO block device from an existing VirtioTransport (MMIO or PCI).
pub unsafe fn init_virtio_blk_with_transport(
    transport: Box<dyn VirtioTransport>,
    iommu_device_id: IommuDeviceId,
) -> Result<(), BlockError> {
    init_virtio_blk_with_transport_at_index(0, transport, iommu_device_id)
}

/// Get a clone of the global VirtioBlk device Arc if initialized
pub fn get_virtio_blk_device() -> Option<Arc<VirtioBlkDevice>> {
    get_virtio_blk_device_at_index(0)
}
