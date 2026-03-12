use super::*;

impl VirtioBlkDevice {
    /// Dispatch DMA read based on IOMMU state.
    pub(super) fn dma_read_dispatch<'a>(
        &'a self,
        sector: u64,
        dma: DmaInfo,
        buf: &'a mut [u8],
        len: usize,
    ) -> ZcFuture<'a, VfsBlockResult<()>> {
        if dma.len != len {
            return Box::pin(async { Err(VfsBlockError::InvalidBufferSize) });
        }
        debug_assert!(
            is_iommu_enabled(),
            "virtio-blk DMA dispatch expects translated IOMMU to remain active"
        );
        if iommu_needs_bounce(dma.phys_addr, len) {
            return self.dma_read_bounce_async(sector, buf, len);
        }
        self.dma_read_bounce_eager(sector, buf, len)
    }

    /// DMA write via fully-async IOMMU bounce path.
    pub(super) fn dma_write_bounce_async<'a>(
        &'a self,
        sector: u64,
        data: &'a [u8],
        len: usize,
    ) -> ZcFuture<'a, VfsBlockResult<()>> {
        Box::pin(async move {
            let mut rref = alloc_bounce_buffer(len)?;
            rref[..len].copy_from_slice(data);
            let handle = self.map_bounce_for_device(rref, DmaDirection::ToDevice)?;
            let dma_addr = handle.iova();
            let result = DmaWriteFuture {
                device: self,
                sector,
                dma_addr,
                buf: data,
                submitted: false,
                desc_id: None,
                queue_idx: 0,
            }
            .await;
            handle.unmap().map_err(|_| VfsBlockError::IoError)?;
            result.map_err(map_vfs_block_error)?;
            Ok(())
        })
    }

    /// DMA write via eager-alloc IOMMU bounce path.
    pub(super) fn dma_write_bounce_eager<'a>(
        &'a self,
        sector: u64,
        data: &'a [u8],
        len: usize,
    ) -> ZcFuture<'a, VfsBlockResult<()>> {
        let mut rref = match alloc_bounce_buffer(len) {
            Ok(r) => r,
            Err(e) => return Box::pin(async move { Err(e) }),
        };
        rref[..len].copy_from_slice(data);
        crate::io::dma::flush_cache_range(rref.as_ptr(), rref.len());
        let handle = match self.map_bounce_for_device(rref, DmaDirection::ToDevice) {
            Ok(handle) => handle,
            Err(err) => return Box::pin(async move { Err(err) }),
        };
        let dma_addr = handle.iova();
        Box::pin(async move {
            let result = DmaWriteFuture {
                device: self,
                sector,
                dma_addr,
                buf: data,
                submitted: false,
                desc_id: None,
                queue_idx: 0,
            }
            .await;
            handle.unmap().map_err(|_| VfsBlockError::IoError)?;
            result.map_err(map_vfs_block_error)?;
            Ok(())
        })
    }

    /// Dispatch DMA write based on IOMMU state.
    pub(super) fn dma_write_dispatch<'a>(
        &'a self,
        sector: u64,
        dma: DmaInfo,
        data: &'a [u8],
        len: usize,
    ) -> ZcFuture<'a, VfsBlockResult<()>> {
        if dma.len != len {
            return Box::pin(async { Err(VfsBlockError::InvalidBufferSize) });
        }
        debug_assert!(
            is_iommu_enabled(),
            "virtio-blk DMA dispatch expects translated IOMMU to remain active"
        );
        if iommu_needs_bounce(dma.phys_addr, len) {
            return self.dma_write_bounce_async(sector, data, len);
        }
        self.dma_write_bounce_eager(sector, data, len)
    }
}
