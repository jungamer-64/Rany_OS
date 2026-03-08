use super::*;
use crate::io::iommu::api::is_global_dma_mapping_allowed;
use crate::io::iommu::types::DmaAddr;
use crate::io::virtio::virtqueue::vring_flags;

mod async_io;
pub use async_io::*;
mod dma_dispatch;

/// VirtIO Block Device Configuration space offsets
pub mod config_offsets {
    pub const CAPACITY: usize = 0;
    pub const BLK_SIZE: usize = 20;
    pub const NUM_QUEUES: usize = 34;
}

impl VirtioBlkDevice {
    /// Create a new VirtIO block device (uninitialized)
    ///
    /// The transport must already be validated (magic/version checks).
    pub fn new(transport: Box<dyn VirtioTransport>) -> Self {
        Self::new_with_device(transport, None)
    }

    /// Create a new VirtIO block device with an IOMMU device ID.
    pub fn new_with_device(
        transport: Box<dyn VirtioTransport>,
        iommu_device_id: Option<IommuDeviceId>,
    ) -> Self {
        Self {
            core: CoreBlkDevice::new(),
            queues: Vec::new(),
            pending_wakers: Vec::new(),
            ready: AtomicBool::new(false),
            iommu_device_id,
            transport,
            inflight_dma: Vec::new(),
        }
    }

    /// Initialize the device
    pub fn init(&mut self) -> Result<(), BlockError> {
        // Step 1: Perform common VirtIO initialization using shared core
        self.core.init(self.transport.as_ref()).map_err(|_| BlockError::NotReady)?;

        // Step 2: Setup queues
        let num_queues = if self.core.features & features::VIRTIO_BLK_F_MQ != 0 {
            self.core.num_queues
        } else {
            1
        };

        for i in 0..num_queues {
            self.setup_queue(i)?;
        }

        // Step 3: Driver OK
        self.transport.add_status(crate::io::virtio::status::VIRTIO_STATUS_DRIVER_OK);

        self.ready.store(true, Ordering::Release);
        Ok(())
    }

    // read_status, write_status, read_device_features, write_driver_features REMOVED
    // as we use self.transport methods directly.


    /// Setup a virtqueue
    pub(super) fn setup_queue(&mut self, queue_idx: u16) -> Result<(), BlockError> {
        // Select queue and read size
        self.transport.select_queue(queue_idx);
        let max_size = self.transport.get_queue_max_size();

        if max_size == 0 {
            return Err(BlockError::NotReady);
        }

        let queue_size = max_size.min(VIRTQUEUE_MAX_SIZE);
        let _ = self.transport.get_notify_addr(queue_idx);

        // Standardized layout calculation
        let (desc_size, _avail_size, used_offset, total_size) =
            VirtQueue::calculate_layout(queue_size);

        // Use CoherentDmaBuffer for shared queue memory (IOMMU-aware)
        // We use Bidirectional as default, allowing device to read/write rings
        let buffer = crate::io::virtio::dma::alloc_virtio_dma_buffer(
            total_size,
            crate::io::dma::DmaMemoryAttributes::MMIO,
            self.iommu_device_id.as_ref(),
        )
        .ok_or(BlockError::NotReady)?;

        let dev_base = buffer.device_addr();
        let ptr = unsafe { buffer.as_slice().as_ptr() } as *mut u8;

        let desc_table = ptr as *mut VringDesc;
        let avail_ring = unsafe { ptr.add(desc_size) as *mut VringAvail };
        let used_ring = unsafe { ptr.add(used_offset) as *mut VringUsed };

        // Write queue configuration
        self.transport.set_queue_size(queue_size);
        self.transport.set_queue_desc_addr(dev_base);
        self.transport
            .set_queue_avail_addr(dev_base + desc_size as u64);
        self.transport
            .set_queue_used_addr(dev_base + used_offset as u64);

        // Activate queue
        self.transport.enable_queue();

        // Create VirtQueue instance (safe because buffer ensures memory validity)
        let virtqueue = unsafe {
            VirtQueue::new(
                queue_size,
                desc_table,
                avail_ring,
                used_ring,
                Some(buffer),
                queue_idx,
                self.core.features,
            )
        };

        let mut wakers = Vec::with_capacity(queue_size as usize);
        wakers.resize_with(queue_size as usize, || None);
        let mut dmas = Vec::with_capacity(queue_size as usize);
        dmas.resize_with(queue_size as usize, || None);

        self.queues.push(Arc::new(IrqPoisonLock::new(virtqueue)));
        self.pending_wakers.push(IrqPoisonLock::new(wakers));
        self.inflight_dma.push(IrqPoisonLock::new(dmas));

        Ok(())
    }

    /// Get device configuration
    pub fn config(&self) -> &CoreBlkDevice {
        &self.core
    }

    /// Check if device is ready
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// キュー数を取得（io_scheduler 統合用）
    pub(crate) fn queue_count(&self) -> usize {
        self.queues.len()
    }

    /// 指定インデックスのキューを取得（io_scheduler 統合用）
    pub(crate) fn queue(&self, idx: usize) -> Option<&Arc<IrqPoisonLock<VirtQueue>>> {
        self.queues.get(idx)
    }

    /// Read sectors asynchronously
    pub fn read_async<'a>(&'a self, sector: u64, buf: &'a mut [u8]) -> ReadFuture<'a> {
        ReadFuture {
            device: self,
            sector,
            buf,
            submitted: false,
            desc_id: None,
            queue_idx: 0,
        }
    }

    /// Write sectors asynchronously
    pub fn write_async<'a>(&'a self, sector: u64, buf: &'a [u8]) -> WriteFuture<'a> {
        WriteFuture {
            device: self,
            sector,
            buf,
            submitted: false,
            desc_id: None,
            queue_idx: 0,
        }
    }

    /// Flush device cache
    pub fn flush_async(&self) -> FlushFuture<'_> {
        FlushFuture {
            device: self,
            submitted: false,
            desc_id: None,
            queue_idx: 0,
        }
    }

    /// Handle interrupt
    pub fn handle_interrupt(&self) {
        // Process completions on all queues
        for (q_idx, queue) in self.queues.iter().enumerate() {
            if let Ok(mut queue_guard) = queue.lock() {
                while let Some((desc_id, completed_len)) = queue_guard.poll_complete() {
                    self.process_completion_entry(&queue_guard, q_idx, desc_id, completed_len);
                }
            }
        }

        // Interrupt-Wakerブリッジに通知（設計書 4.2）
        crate::task::interrupt_waker::wake_from_interrupt(
            crate::task::interrupt_waker::InterruptSource::VirtioBlk(0),
        );
    }

    pub(super) fn process_completion_entry(
        &self,
        queue_guard: &VirtQueue,
        q_idx: usize,
        desc_id: u16,
        completed_len: u32,
    ) {
        // io_scheduler 管理下のリクエストかチェック
        let io_sched_req = crate::io::virtio::blk_scheduler::get_poll_handler(0).and_then(
            |handler: alloc::sync::Arc<crate::io::virtio::blk_scheduler::VirtioBlkPollHandler>| {
                handler.take_pending(q_idx, desc_id)
            },
        );

        // DMA バッファからステータスを確認
        let status_ok = if let Some(inflight_q) = self.inflight_dma.get(q_idx) {
            if let Ok(mut inflight) = inflight_q.lock() {
                if let Some(req_dma) = inflight
                    .get_mut(desc_id as usize)
                    .and_then(|slot| slot.take())
                {
                    let status = req_dma.status();
                    if status != VIRTIO_BLK_S_OK {
                        log::warn!(
                            "[VIRTIO-BLK] request {} completed with status {}",
                            desc_id,
                            status
                        );
                    }
                    status == VIRTIO_BLK_S_OK
                } else {
                    true
                }
            } else {
                true
            }
        } else {
            true
        };

        // Free descriptor
        queue_guard.free_desc(desc_id);

        if let Some((io_id, _bytes)) = io_sched_req {
            // io_scheduler パス: ISR-safe な遅延完了キューに積む
            let result = if status_ok {
                crate::io::io_scheduler::IoResult::Success(completed_len as usize)
            } else {
                crate::io::io_scheduler::IoResult::Error(
                    crate::io::io_scheduler::IoError::DeviceError,
                )
            };
            let device_id = crate::io::io_scheduler::DeviceId::VirtioBlk { index: 0 };
            let bridge = crate::io::io_scheduler::hybrid_coordinator().interrupt_bridge();
            bridge.handle_interrupt(device_id, &[(io_id, result)]);
        } else {
            // レガシーパス: 既存の Waker を起動
            if let Some(queue_wakers_lock) = self.pending_wakers.get(q_idx) {
                if let Ok(mut wakers) = queue_wakers_lock.lock() {
                    if let Some(waker) = wakers
                        .get_mut(desc_id as usize)
                        .and_then(|slot| slot.take())
                    {
                        waker.wake();
                    }
                }
            }
        }
    }

    /// Submit a read request (internal)

    pub(crate) fn submit_read(
        &self,
        sector: u64,
        buf_addr: u64,
        len: u32,
        queue_idx: usize,
    ) -> Result<u16, BlockError> {
        if !self.is_ready() {
            return Err(BlockError::NotReady);
        }

        if sector >= self.core.capacity {
            return Err(BlockError::InvalidParam);
        }

        // SECURITY CHECK: If IOMMU is enabled and global mappings are disallowed,
        // we cannot trust a raw `buf_addr` unless we know it's an IOVA.
        if is_iommu_enabled() && self.iommu_device_id.is_some() && !is_global_dma_mapping_allowed()
        {
            log::error!(
                "[VIRTIO-BLK][SECURITY] attempt to use raw DMA address {:#x} without global mapping allowed. Use IoBuffer/DmaInfo instead.",
                buf_addr
            );
            return Err(BlockError::Unsupported);
        }

        let header = VirtioBlkReqHeader {
            type_: VIRTIO_BLK_T_IN,
            reserved: 0,
            sector,
        };
        let use_indirect = (self.core.features & crate::io::virtio::VIRTIO_F_INDIRECT_DESC) != 0;
        let mut req_dma =
            BlkRequestDma::new_with_device(&header, self.iommu_device_id.as_ref(), use_indirect)
                .ok_or(BlockError::NotReady)?;

        let queue = self.queues.get(queue_idx).ok_or(BlockError::NotReady)?;
        let queue_guard = queue.lock().map_err(|_| BlockError::NotReady)?;

        let desc_id = if use_indirect {
            let indirect_table = req_dma.indirect_table_mut().ok_or(BlockError::NotReady)?;
            let indirect_phys = req_dma
                .indirect_table_phys
                .map(DmaAddr::new)
                .ok_or(BlockError::NotReady)?;

            unsafe {
                self.core.build_request_indirect(
                    &*queue_guard.inner(),
                    VIRTIO_BLK_T_IN,
                    sector,
                    buf_addr,
                    len,
                    req_dma.header_phys,
                    req_dma.status_phys,
                    indirect_table as *mut virtio_driver::defs::VringDesc,
                    indirect_phys.as_u64(),
                ).map_err(|_| BlockError::NotReady)?
            }
        } else {
            unsafe {
                self.core.build_request(
                    &*queue_guard.inner(),
                    VIRTIO_BLK_T_IN,
                    sector,
                    buf_addr,
                    len,
                    req_dma.header_phys,
                    req_dma.status_phys,
                ).map_err(|_| BlockError::NotReady)?
            }
        };

        // Retain DMA buffer until completion
        if let Some(inflight_q) = self.inflight_dma.get(queue_idx) {
            if let Ok(mut inflight) = inflight_q.lock() {
                if let Some(slot) = inflight.get_mut(desc_id as usize) {
                    *slot = Some(req_dma);
                }
            }
        }

        queue_guard.notify(self.transport.as_ref());
        log::info!(
            "[VIRTIO-BLK][DBG] submit_read notified q={} desc0={}",
            queue_idx,
            desc_id
        );

        Ok(desc_id)
    }

    /// Prepare a write request: validate state and create DMA header
    pub(super) fn prepare_write_request(&self, sector: u64) -> Result<BlkRequestDma, BlockError> {
        if !self.is_ready() {
            return Err(BlockError::NotReady);
        }
        if (self.core.features & features::VIRTIO_BLK_F_RO) != 0 {
            return Err(BlockError::Unsupported);
        }
        if sector >= self.core.capacity {
            return Err(BlockError::InvalidParam);
        }
        let header = VirtioBlkReqHeader {
            type_: VIRTIO_BLK_T_OUT,
            reserved: 0,
            sector,
        };
        let use_indirect = (self.core.features & crate::io::virtio::VIRTIO_F_INDIRECT_DESC) != 0;
        BlkRequestDma::new_with_device(&header, self.iommu_device_id.as_ref(), use_indirect)
            .ok_or(BlockError::NotReady)
    }

    /// Submit a write request (internal)
    pub(crate) fn submit_write(
        &self,
        sector: u64,
        buf_addr: u64,
        len: u32,
        queue_idx: usize,
    ) -> Result<u16, BlockError> {
        // SECURITY CHECK: Matches submit_read
        if is_iommu_enabled() && self.iommu_device_id.is_some() && !is_global_dma_mapping_allowed()
        {
            log::error!(
                "[VIRTIO-BLK][SECURITY] attempt to use raw DMA address {:#x} without global mapping allowed. Use IoBuffer/DmaInfo instead.",
                buf_addr
            );
            return Err(BlockError::Unsupported);
        }

        let mut req_dma = self.prepare_write_request(sector)?;
        let use_indirect = (self.core.features & crate::io::virtio::VIRTIO_F_INDIRECT_DESC) != 0;

        let queue = self.queues.get(queue_idx).ok_or(BlockError::NotReady)?;
        let queue_guard = queue.lock().map_err(|_| BlockError::NotReady)?;

        let desc_id = if use_indirect {
            let indirect_table = req_dma.indirect_table_mut().ok_or(BlockError::NotReady)?;
            let indirect_phys = req_dma
                .indirect_table_phys
                .map(DmaAddr::new)
                .ok_or(BlockError::NotReady)?;

            unsafe {
                self.core.build_request_indirect(
                    &*queue_guard.inner(),
                    VIRTIO_BLK_T_OUT,
                    sector,
                    buf_addr,
                    len,
                    req_dma.header_phys,
                    req_dma.status_phys,
                    indirect_table as *mut virtio_driver::defs::VringDesc,
                    indirect_phys.as_u64(),
                ).map_err(|_| BlockError::NotReady)?
            }
        } else {
            unsafe {
                self.core.build_request(
                    &*queue_guard.inner(),
                    VIRTIO_BLK_T_OUT,
                    sector,
                    buf_addr,
                    len,
                    req_dma.header_phys,
                    req_dma.status_phys,
                ).map_err(|_| BlockError::NotReady)?
            }
        };

        // Retain DMA buffer until completion
        if let Some(inflight_q) = self.inflight_dma.get(queue_idx) {
            if let Ok(mut inflight) = inflight_q.lock() {
                if let Some(slot) = inflight.get_mut(desc_id as usize) {
                    *slot = Some(req_dma);
                }
            }
        }

        queue_guard.notify(&*self.transport);

        Ok(desc_id)
    }

    /// Submit a flush request (internal)
    pub(crate) fn submit_flush(&self, queue_idx: usize) -> Result<u16, BlockError> {
        if !self.is_ready() {
            return Err(BlockError::NotReady);
        }

        // Check if flush is supported
        if self.core.features & features::VIRTIO_BLK_F_FLUSH == 0 {
            return Err(BlockError::Unsupported);
        }

        // Allocate DMA-safe header + status byte
        let header = VirtioBlkReqHeader {
            type_: VIRTIO_BLK_T_FLUSH,
            reserved: 0,
            sector: 0, // sector is ignored for flush
        };
        let use_indirect = (self.core.features & crate::io::virtio::VIRTIO_F_INDIRECT_DESC) != 0;
        let mut req_dma =
            BlkRequestDma::new_with_device(&header, self.iommu_device_id.as_ref(), use_indirect)
                .ok_or(BlockError::NotReady)?;

        let queue = self.queues.get(queue_idx).ok_or(BlockError::NotReady)?;
        let mut queue_guard = queue.lock().map_err(|_| BlockError::NotReady)?;

        let desc_id = if use_indirect {
            let indirect_table = req_dma.indirect_table_mut().ok_or(BlockError::NotReady)?;
            let indirect_phys = req_dma
                .indirect_table_phys
                .map(DmaAddr::new)
                .ok_or(BlockError::NotReady)?;

            unsafe {
                // Indirect Descriptor 0: Header
                (*indirect_table.add(0)) = VringDesc {
                    addr: req_dma.header_phys,
                    len: core::mem::size_of::<VirtioBlkReqHeader>() as u32,
                    flags: VringDesc::F_NEXT,
                    next: 1,
                };
                // Indirect Descriptor 1: Status
                (*indirect_table.add(1)) = VringDesc {
                    addr: req_dma.status_phys,
                    len: 1,
                    flags: VringDesc::F_WRITE,
                    next: 0,
                };

                queue_guard
                    .submit_indirect(indirect_phys, 2)
                    .ok_or(BlockError::QueueFull)?
            }
        } else {
            // Flush only requires 2 descriptors: header and status (no data)
            let desc0 = queue_guard.alloc_desc().ok_or(BlockError::QueueFull)?;
            let desc1 = queue_guard.alloc_desc().ok_or_else(|| {
                queue_guard.free_desc(desc0);
                BlockError::QueueFull
            })?;

            unsafe {
                let desc_table = queue_guard.desc_table_ptr();

                // Descriptor 0: Header (device reads from DMA memory)
                (*desc_table.add(desc0 as usize)) = VringDesc {
                    addr: req_dma.header_phys,
                    len: core::mem::size_of::<VirtioBlkReqHeader>() as u32,
                    flags: vring_flags::VRING_DESC_F_NEXT,
                    next: desc1,
                };

                // Descriptor 1: Status byte (device writes to DMA memory)
                (*desc_table.add(desc1 as usize)) = VringDesc {
                    addr: req_dma.status_phys,
                    len: 1,
                    flags: vring_flags::VRING_DESC_F_WRITE,
                    next: 0,
                };

                queue_guard.submit(desc0)
            }
        };

        // Retain DMA buffer until completion
        if let Some(inflight_q) = self.inflight_dma.get(queue_idx) {
            if let Ok(mut inflight) = inflight_q.lock() {
                if let Some(slot) = inflight.get_mut(desc_id as usize) {
                    *slot = Some(req_dma);
                }
            }
        }

        queue_guard.notify(&*self.transport);

        Ok(desc_id)
    }

    // ========================================================================
    // DMA bounce ヘルパー
    // ========================================================================

    /// Map an RRef bounce buffer for a DMA operation via IOMMU.
    pub(super) fn map_bounce_for_device(
        &self,
        rref: crate::ipc::RRef<[u8]>,
        direction: DmaDirection,
    ) -> VfsBlockResult<DmaHandle<[u8]>> {
        let handle = if let Some(device) = self.iommu_device_id {
            map_rref_slice_for_device(rref, &device, direction)
        } else {
            DmaHandle::map_rref_slice(rref, 0, direction)
        }
        .map_err(|_| VfsBlockError::IoError)?;
        Ok(handle)
    }

    /// DMA read via fully-async IOMMU bounce path.
    pub(super) fn dma_read_bounce_async<'a>(
        &'a self,
        sector: u64,
        buf: &'a mut [u8],
        len: usize,
    ) -> ZcFuture<'a, VfsBlockResult<()>> {
        Box::pin(async move {
            let rref = alloc_bounce_buffer(len)?;
            let handle = self.map_bounce_for_device(rref, DmaDirection::FromDevice)?;
            let dma_addr = handle.iova();
            let result = DmaReadFuture {
                device: self,
                sector,
                dma_addr,
                buf,
                submitted: false,
                desc_id: None,
                queue_idx: 0,
            }
            .await;
            let rref = handle.unmap().map_err(|_| VfsBlockError::IoError)?;
            result.map_err(map_vfs_block_error)?;
            buf.copy_from_slice(&rref[..len]);
            Ok(())
        })
    }

    /// DMA read via eager-alloc IOMMU bounce path.
    pub(super) fn dma_read_bounce_eager<'a>(
        &'a self,
        sector: u64,
        buf: &'a mut [u8],
        len: usize,
    ) -> ZcFuture<'a, VfsBlockResult<()>> {
        let rref = match alloc_bounce_buffer(len) {
            Ok(r) => r,
            Err(e) => return Box::pin(async move { Err(e) }),
        };
        let handle = match self.map_bounce_for_device(rref, DmaDirection::FromDevice) {
            Ok(handle) => handle,
            Err(err) => return Box::pin(async move { Err(err) }),
        };
        let dma_addr = handle.iova();
        Box::pin(async move {
            let result = DmaReadFuture {
                device: self,
                sector,
                dma_addr,
                buf,
                submitted: false,
                desc_id: None,
                queue_idx: 0,
            }
            .await;
            let rref = handle.unmap().map_err(|_| VfsBlockError::IoError)?;
            result.map_err(map_vfs_block_error)?;
            buf.copy_from_slice(&rref[..len]);
            Ok(())
        })
    }
}
