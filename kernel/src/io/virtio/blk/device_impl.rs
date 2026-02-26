use super::*;
use crate::util::align_up_usize as align_up;


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
            config: BlockDeviceConfig::default(),
            queues: Vec::new(),
            pending_wakers: Mutex::new(BTreeMap::new()),
            ready: AtomicBool::new(false),
            iommu_device_id,
            transport,
            features: 0,
            inflight_dma: Mutex::new(BTreeMap::new()),
        }
    }

    /// Initialize the device
    ///
    /// # Safety
    /// Caller must ensure MMIO address is valid
    pub unsafe fn init(&mut self) -> Result<(), BlockError> {
        // Step 1: Reset device
        self.transport.set_status(0);

        // Step 2: Acknowledge device
        self.transport
            .set_status(VirtioDeviceStatus::Acknowledge as u8);

        // Step 3: Driver loaded
        self.transport
            .set_status(VirtioDeviceStatus::Acknowledge as u8 | VirtioDeviceStatus::Driver as u8);

        // Step 4: Negotiate features
        let device_features = self.transport.get_device_features();
        let driver_features = device_features
            & (features::VIRTIO_BLK_F_SIZE_MAX
                | features::VIRTIO_BLK_F_SEG_MAX
                | features::VIRTIO_BLK_F_BLK_SIZE
                | features::VIRTIO_BLK_F_FLUSH
                | features::VIRTIO_BLK_F_MQ);
        self.transport.set_driver_features(driver_features);
        self.features = driver_features;

        // Step 5: Features OK
        // Step 5: Features OK
        self.transport.set_status(
            VirtioDeviceStatus::Acknowledge as u8
                | VirtioDeviceStatus::Driver as u8
                | VirtioDeviceStatus::FeaturesOk as u8,
        );

        // Verify features accepted
        let status = self.transport.get_status();
        if (status & VirtioDeviceStatus::FeaturesOk as u8) == 0 {
            self.transport.set_status(VirtioDeviceStatus::Failed as u8);
            return Err(BlockError::NotReady);
        }

        // Step 6: Read configuration
        self.read_config()?;

        // Step 7: Setup queues
        let num_queues = if self.features & features::VIRTIO_BLK_F_MQ != 0 {
            self.config.num_queues
        } else {
            1
        };

        for i in 0..num_queues {
            self.setup_queue(i)?;
        }

        // pending_wakers is now a BTreeMap, so no resizing is needed.

        // Step 8: Driver OK
        self.transport.set_status(
            VirtioDeviceStatus::Acknowledge as u8
                | VirtioDeviceStatus::Driver as u8
                | VirtioDeviceStatus::FeaturesOk as u8
                | VirtioDeviceStatus::DriverOk as u8,
        );

        self.ready.store(true, Ordering::Release);
        Ok(())
    }

    // read_status, write_status, read_device_features, write_driver_features REMOVED
    // as we use self.transport methods directly.

    /// Read device configuration
    pub(super) fn read_config(&mut self) -> Result<(), BlockError> {
        // Read capacity (8 bytes at offset 0)
        self.config.capacity = self.transport.read_config_u64(config_offsets::CAPACITY);

        // Read block size if feature supported
        // Read block size if feature supported
        if self.features & features::VIRTIO_BLK_F_BLK_SIZE != 0 {
            // Block size (u32) at offset 0x14 - wait, offset depends on struct layout.
            // But transport.read_config_u32(offset) works relative to config space.
            // Offset 0 is capacity (u64, size 8).
            // size_max (u32) at 8
            // seg_max (u32) at 12
            // geometry (cylinders, heads, sectors) at 16 (u16*3) -> 6 bytes
            // blk_size (u32) is after geometry? Spec says:
            // struct virtio_blk_config {
            //     u64 capacity; (0)
            //     u32 size_max; (8)
            //     u32 seg_max; (12)
            //     struct virtio_blk_geometry geometry; (16)
            //     u32 blk_size; (20? 16+4+2+4=26? No, geometry is u16 cylinders, u8 heads, u8 sectors = 4 bytes total? 16+4=20)
            //     ...
            // }
            // block_size (u32) at 20.
            self.config.block_size = self.transport.read_config_u32(config_offsets::BLK_SIZE);
        }

        // Read num_queues if multiqueue supported
        // Read num_queues if multiqueue supported
        if self.features & features::VIRTIO_BLK_F_MQ != 0 {
            // Number of queues (u16). Offset?
            // topology (alignment etc) is after blk_size.
            // writeback?
            // Spec says num_queues is later?
            // Existing code used 0x22 (34).
            // Number of queues (u16) at 34.
            self.config.num_queues = self.transport.read_config_u16(config_offsets::NUM_QUEUES);
        }

        // Check read-only
        if self.features & features::VIRTIO_BLK_F_RO != 0 {
            self.config.read_only = true;
        }

        Ok(())
    }

    /// Setup a virtqueue
    pub(super) fn setup_queue(&mut self, queue_idx: u16) -> Result<(), BlockError> {
        // Select queue and read size
        self.transport.select_queue(queue_idx);
        let max_size = self.transport.get_queue_max_size();

        if max_size == 0 {
            return Err(BlockError::NotReady);
        }

        let queue_size = max_size.min(VIRTQUEUE_MAX_SIZE);
        let _notify_addr = self.transport.get_notify_addr(queue_idx);
        let _notify_is_32bit = matches!(self.transport.transport_type(), TransportType::Mmio);

        // Allocate queue memory (proper DMA allocation)
        let desc_size = core::mem::size_of::<VringDesc>() * queue_size as usize;
        let avail_size = 6 + 2 * queue_size as usize; // flags + idx + ring + used_event
        let used_size = 6 + 8 * queue_size as usize; // flags + idx + ring + avail_event

        // Align used ring per VirtIO requirements
        let used_align = 4usize; // VirtIO spec: used ring must be aligned to 4 bytes
        let used_offset = align_up(desc_size + avail_size, used_align);
        let total_size = used_offset + used_size;

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

        // Create VirtQueue instance with transport-provided notify address
        let virtqueue = unsafe {
            VirtQueue::new(
                queue_size,
                desc_table,
                avail_ring,
                used_ring,
                Some(buffer),
                queue_idx, // Index
            )
        };

        self.queues.push(Arc::new(Mutex::new(virtqueue)));

        Ok(())
    }

    /// Get device configuration
    pub fn config(&self) -> &BlockDeviceConfig {
        &self.config
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
    pub(crate) fn queue(&self, idx: usize) -> Option<&Arc<Mutex<VirtQueue>>> {
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
            let mut queue_guard = queue.lock();
            while let Some((desc_id, _len)) = queue_guard.poll_completions() {
                self.process_completion_entry(&queue_guard, q_idx, desc_id, _len);
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
        let status_ok = if let Some(req_dma) = self.inflight_dma.lock().remove(&desc_id) {
            let status = req_dma.status();
            if status != VirtioBlkStatus::Ok as u8 {
                log::warn!(
                    "[VIRTIO-BLK] request {} completed with status {}",
                    desc_id,
                    status
                );
            }
            status == VirtioBlkStatus::Ok as u8
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
                crate::io::io_scheduler::IoResult::Error(crate::io::io_scheduler::IoError::DeviceError)
            };
            let device_id = crate::io::io_scheduler::DeviceId::VirtioBlk { index: 0 };
            let bridge = crate::io::io_scheduler::hybrid_coordinator().interrupt_bridge();
            bridge.handle_interrupt(device_id, &[(io_id, result)]);
        } else {
            // レガシーパス: 既存の Waker を起動
            let waker_idx = q_idx * VIRTQUEUE_MAX_SIZE as usize + desc_id as usize;
            let mut wakers = self.pending_wakers.lock();
            if let Some(waker) = wakers.remove(&waker_idx) {
                waker.wake();
            }
        }
    }

    /// Submit a read request (internal)
    pub(super) fn alloc_three_descriptors(queue: &VirtQueue) -> Result<(u16, u16, u16), BlockError> {
        let desc0 = queue.alloc_desc().ok_or(BlockError::QueueFull)?;
        let desc1 = queue.alloc_desc().ok_or_else(|| {
            queue.free_desc(desc0);
            BlockError::QueueFull
        })?;
        let desc2 = queue.alloc_desc().ok_or_else(|| {
            queue.free_desc(desc0);
            queue.free_desc(desc1);
            BlockError::QueueFull
        })?;
        Ok((desc0, desc1, desc2))
    }

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

        if sector >= self.config.capacity {
            return Err(BlockError::InvalidSector);
        }

        let header = VirtioBlkReqHeader {
            req_type: VirtioBlkReqType::In as u32,
            reserved: 0,
            sector,
        };
        let req_dma = BlkRequestDma::new_with_device(&header, self.iommu_device_id.as_ref())
            .ok_or(BlockError::NotReady)?;

        let queue = self.queues.get(queue_idx).ok_or(BlockError::NotReady)?;
        let mut queue_guard = queue.lock();

        let (desc0, desc1, desc2) = Self::alloc_three_descriptors(&queue_guard)?;

        unsafe {
            let desc_table = queue_guard.desc_table;

            // Descriptor 0: Header (device reads from DMA memory)
            (*desc_table.add(desc0 as usize)) = VringDesc {
                addr: req_dma.header_phys,
                len: core::mem::size_of::<VirtioBlkReqHeader>() as u32,
                flags: vring_flags::VRING_DESC_F_NEXT,
                next: desc1,
            };

            // Descriptor 1: Data buffer (device writes)
            (*desc_table.add(desc1 as usize)) = VringDesc {
                addr: buf_addr,
                len,
                flags: vring_flags::VRING_DESC_F_NEXT | vring_flags::VRING_DESC_F_WRITE,
                next: desc2,
            };

            // Descriptor 2: Status byte (device writes to DMA memory)
            (*desc_table.add(desc2 as usize)) = VringDesc {
                addr: req_dma.status_phys,
                len: 1,
                flags: vring_flags::VRING_DESC_F_WRITE,
                next: 0,
            };

            // Submit to available ring
            log::info!(
                "[VIRTIO-BLK][DBG] submit_read q={} sector={} len={} descs=[{},{},{}] data_addr=0x{:016x} hdr=0x{:016x} status=0x{:016x}",
                queue_idx,
                sector,
                len,
                desc0,
                desc1,
                desc2,
                buf_addr,
                req_dma.header_phys,
                req_dma.status_phys
            );
            queue_guard.submit(desc0);
        }

        // Retain DMA buffer until completion
        self.inflight_dma.lock().insert(desc0, req_dma);

        queue_guard.notify(&*self.transport);
        log::info!(
            "[VIRTIO-BLK][DBG] submit_read notified q={} desc0={}",
            queue_idx,
            desc0
        );

        Ok(desc0)
    }

    /// Prepare a write request: validate state and create DMA header
    pub(super) fn prepare_write_request(&self, sector: u64) -> Result<BlkRequestDma, BlockError> {
        if !self.is_ready() {
            return Err(BlockError::NotReady);
        }
        if self.config.read_only {
            return Err(BlockError::ReadOnly);
        }
        if sector >= self.config.capacity {
            return Err(BlockError::InvalidSector);
        }
        let header = VirtioBlkReqHeader {
            req_type: VirtioBlkReqType::Out as u32,
            reserved: 0,
            sector,
        };
        BlkRequestDma::new_with_device(&header, self.iommu_device_id.as_ref())
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
        let req_dma = self.prepare_write_request(sector)?;

        let queue = self.queues.get(queue_idx).ok_or(BlockError::NotReady)?;
        let mut queue_guard = queue.lock();

        // Allocate 3 descriptors
        let desc0 = queue_guard.alloc_desc().ok_or(BlockError::QueueFull)?;
        let desc1 = queue_guard.alloc_desc().ok_or_else(|| {
            queue_guard.free_desc(desc0);
            BlockError::QueueFull
        })?;
        let desc2 = queue_guard.alloc_desc().ok_or_else(|| {
            queue_guard.free_desc(desc0);
            queue_guard.free_desc(desc1);
            BlockError::QueueFull
        })?;

        unsafe {
            let desc_table = queue_guard.desc_table;

            // Descriptor 0: Header (device reads from DMA memory)
            (*desc_table.add(desc0 as usize)) = VringDesc {
                addr: req_dma.header_phys,
                len: core::mem::size_of::<VirtioBlkReqHeader>() as u32,
                flags: vring_flags::VRING_DESC_F_NEXT,
                next: desc1,
            };

            // Descriptor 1: Data buffer (device reads)
            (*desc_table.add(desc1 as usize)) = VringDesc {
                addr: buf_addr,
                len,
                flags: vring_flags::VRING_DESC_F_NEXT,
                next: desc2,
            };

            // Descriptor 2: Status byte (device writes to DMA memory)
            (*desc_table.add(desc2 as usize)) = VringDesc {
                addr: req_dma.status_phys,
                len: 1,
                flags: vring_flags::VRING_DESC_F_WRITE,
                next: 0,
            };

            queue_guard.submit(desc0);
        }

        // Retain DMA buffer until completion
        self.inflight_dma.lock().insert(desc0, req_dma);

        queue_guard.notify(&*self.transport);

        Ok(desc0)
    }

    /// Submit a flush request (internal)
    pub(crate) fn submit_flush(&self, queue_idx: usize) -> Result<u16, BlockError> {
        if !self.is_ready() {
            return Err(BlockError::NotReady);
        }

        // Check if flush is supported
        if self.features & features::VIRTIO_BLK_F_FLUSH == 0 {
            return Err(BlockError::Unsupported);
        }

        // Allocate DMA-safe header + status byte
        let header = VirtioBlkReqHeader {
            req_type: VirtioBlkReqType::Flush as u32,
            reserved: 0,
            sector: 0, // sector is ignored for flush
        };
        let req_dma = BlkRequestDma::new_with_device(&header, self.iommu_device_id.as_ref())
            .ok_or(BlockError::NotReady)?;

        let queue = self.queues.get(queue_idx).ok_or(BlockError::NotReady)?;
        let mut queue_guard = queue.lock();

        // Flush only requires 2 descriptors: header and status (no data)
        let desc0 = queue_guard.alloc_desc().ok_or(BlockError::QueueFull)?;
        let desc1 = queue_guard.alloc_desc().ok_or_else(|| {
            queue_guard.free_desc(desc0);
            BlockError::QueueFull
        })?;

        unsafe {
            let desc_table = queue_guard.desc_table;

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

            queue_guard.submit(desc0);
        }

        // Retain DMA buffer until completion
        self.inflight_dma.lock().insert(desc0, req_dma);

        queue_guard.notify(&*self.transport);

        Ok(desc0)
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
