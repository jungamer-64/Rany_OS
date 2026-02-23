use super::*;


mod sg_io_future;
pub use self::sg_io_future::*;
impl<'a> Future for AsyncFlushFuture<'a> {
    type Output = FsResult<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.started {
            self.started = true;

            if self.file.direct_io {
                let future = crate::io::io_scheduler::hybrid_coordinator().submit_io_command(
                    self.file.io_device(),
                    IoCommand::Flush,
                    IoPriority::High,
                );
                self.io_future = Some(future);
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            return match flush_page_cache(self.file.id) {
                Ok(()) => Poll::Ready(Ok(())),
                Err(e) => Poll::Ready(Err(e)),
            };
        }

        if let Some(future) = self.io_future.as_mut() {
            return match Pin::new(future).poll(cx) {
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
                Poll::Ready(Err(_)) => Poll::Ready(Err(FsError::IoError)),
                Poll::Pending => Poll::Pending,
            };
        }

        Poll::Ready(Ok(()))
    }
}

/// 非同期同期Future
pub struct AsyncSyncFuture<'a> {
    file: &'a AsyncFile,
    started: bool,
    flush: Option<AsyncFlushFuture<'a>>,
}

impl<'a> AsyncSyncFuture<'a> {
    pub(crate) fn new(file: &'a AsyncFile) -> Self {
        Self {
            file,
            started: false,
            flush: None,
        }
    }
}

impl<'a> Future for AsyncSyncFuture<'a> {
    type Output = FsResult<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.started {
            self.started = true;

            // データとメタデータの同期
            // ダイレクトI/Oの場合は既に同期済み
            if self.file.direct_io {
                self.flush = Some(AsyncFlushFuture::new(self.file));
            } else {
                self.flush = Some(AsyncFlushFuture::new(self.file));
            }
        }

        if let Some(flush) = self.flush.as_mut() {
            return Pin::new(flush).poll(cx);
        }

        Poll::Ready(Ok(()))
    }
}

// ============================================================================
// ダイレクトブロックアクセス API
// 設計書 6.3: ファイルシステムをバイパスした直接アクセス
// ============================================================================

/// ダイレクトブロックデバイスハンドル
/// データベースなどのアプリケーション向けに、
/// ファイルシステムを通さずNVMeを直接操作
#[derive(Clone, Copy)]
pub struct DirectBlockHandle {
    /// デバイスID（NVMe namespace ID）
    device_id: u64,
    /// 開始ブロック
    start_block: u64,
    /// ブロック数
    block_count: u64,
    /// ブロックサイズ
    block_size: u32,
}

impl DirectBlockHandle {
    /// 新しいダイレクトブロックハンドルを作成
    pub fn new(device_id: u64, start_block: u64, block_count: u64, block_size: u32) -> Self {
        Self {
            device_id,
            start_block,
            block_count,
            block_size,
        }
    }

    #[cfg(any(test, feature = "qemu-test-export"))]
    pub(crate) fn qemu_test_block_count(&self) -> u64 {
        self.block_count
    }

    #[cfg(any(test, feature = "qemu-test-export"))]
    pub(crate) fn qemu_test_block_size(&self) -> u32 {
        self.block_size
    }

    pub(super) fn io_device(&self) -> IoDeviceId {
        IoDeviceId::Nvme {
            controller: 0,
            namespace: nsid_from_device(self.device_id),
        }
    }

    /// Validate read_blocks parameters and return block count
    pub(super) fn validate_read_block_params(&self, block_offset: u64, buf_len: usize) -> FsResult<usize> {
        if block_offset >= self.block_count {
            return Err(FsError::InvalidArgument);
        }
        if buf_len % self.block_size as usize != 0 {
            return Err(FsError::InvalidArgument);
        }
        let blocks_to_read = buf_len / self.block_size as usize;
        let blocks_available = (self.block_count - block_offset) as usize;
        let blocks = blocks_to_read.min(blocks_available);
        if blocks > u16::MAX as usize {
            return Err(FsError::InvalidArgument);
        }
        Ok(blocks)
    }

    /// Complete a DMA read by copying data from the slot to the user buffer
    pub(super) fn complete_dma_read(slot: &Arc<Mutex<Option<(TypedDmaSlice<CpuOwned>, usize)>>>, dma_len: usize, buf: &mut [u8]) -> FsResult<usize> {
        let mut guard = slot.lock();
        let (data, bytes_received) = guard.take().ok_or(FsError::IoError)?;
        let bytes_received: usize = bytes_received;
        let copy_len = bytes_received.min(dma_len).min(buf.len());
        if copy_len > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (data as TypedDmaSlice<CpuOwned>).as_slice().as_ptr(),
                    buf.as_mut_ptr(),
                    copy_len,
                );
            }
        }
        Ok(copy_len)
    }

    /// ブロック読み取り
    pub async fn read_blocks(&self, block_offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        let blocks = self.validate_read_block_params(block_offset, buf.len())?;
        if blocks == 0 {
            return Ok(0);
        }

        let dma_len = blocks * self.block_size as usize;
        // Prepare unified DMA buffer
        let (ctx, prp1, _prp2) = prepare_dma_read(dma_len)?;
        let lba = self.start_block + block_offset;
        let canceled = Arc::new(AtomicBool::new(false));
        let mut cancel_guard = NvmeCancelGuard::new(canceled.clone());
        let slot = Arc::new(Mutex::new(None::<(TypedDmaSlice<CpuOwned>, usize)>));
        let slot_clone = slot.clone();
        let alloc_len = align_up(dma_len, NVME_PAGE_SIZE);
        let future = {
            let buf = DmaBufHandle { iova: prp1, len: alloc_len };
            crate::io::io_scheduler::hybrid_coordinator().submit_io_command(
                self.io_device(),
                IoCommand::BlockRead { lba, blocks: blocks as u16, bytes: dma_len, buf },
                IoPriority::Normal,
            )
        };
        let request_id = future.request_id();

        let mut ctx: NvmeDmaContext = ctx;
        ctx.mark_inflight();
        let hook: CompletionHook = Box::new(move |result| {
            let data = ctx.complete();
            if canceled.load(Ordering::Acquire) {
                return;
            }
            if let IoResult::Success(bytes) = result {
                *slot_clone.lock() = Some((data, bytes));
            }
        });
        crate::io::io_scheduler::io_scheduler().register_completion_hook(request_id, hook);

        let result = future.await;
        cancel_guard.disarm();
        match result {
            Ok(_reported) => Self::complete_dma_read(&slot, dma_len, buf),
            Err(_) => Err(FsError::IoError),
        }
    }

    /// DMAバッファへのブロック読み取り
    pub async fn read_blocks_dma(
        &self,
        block_offset: u64,
        buffer: DmaBuffer,
    ) -> FsResult<DmaBuffer> {
        if block_offset >= self.block_count {
            return Err(FsError::InvalidArgument);
        }

        if buffer.size() == 0 {
            return Ok(buffer);
        }

        if buffer.size() % self.block_size as usize != 0 {
            return Err(FsError::InvalidArgument);
        }

        let blocks = buffer.size() / self.block_size as usize;
        if blocks == 0 {
            return Ok(buffer);
        }
        if blocks > u16::MAX as usize {
            return Err(FsError::InvalidArgument);
        }
        if blocks as u64 > self.block_count - block_offset {
            return Err(FsError::InvalidArgument);
        }

        let (ctx, prp1, _prp2) = prepare_dma_from_kapi_buffer(&buffer)?;
        let lba = self.start_block + block_offset;
        let bytes = blocks * self.block_size as usize;
        let alloc_len = align_up(bytes, NVME_PAGE_SIZE);
        let future = {
            let buf = DmaBufHandle { iova: prp1, len: alloc_len };
            crate::io::io_scheduler::hybrid_coordinator().submit_io_command(
                self.io_device(),
                IoCommand::BlockRead { lba, blocks: blocks as u16, bytes, buf },
                IoPriority::Normal,
            )
        };
        let request_id = future.request_id();
        let mut ctx: NvmeExternalDmaContext = ctx;
        ctx.mark_inflight();
        let hook: CompletionHook = Box::new(move |_result| {
            ctx.complete();
        });
        crate::io::io_scheduler::io_scheduler().register_completion_hook(request_id, hook);

        let result = future.await;
        match result {
            Ok(_) => Ok(buffer),
            Err(_) => Err(FsError::IoError),
        }
    }

    /// Scatter-Gather DMAバッファへのブロック読み取り
    pub async fn read_blocks_sg_dma(
        &self,
        block_offset: u64,
        mut list: TypedSgList<CpuOwned>,
    ) -> FsResult<TypedSgList<CpuOwned>> {
        if block_offset >= self.block_count {
            return Err(FsError::InvalidArgument);
        }
        if list.is_empty() {
            return Ok(list);
        }

        let total_bytes = sg_total_bytes(&list)?;
        if total_bytes == 0 {
            return Ok(list);
        }
        validate_sg_block_params(total_bytes, self.block_size, block_offset, self.block_count)?;

        let mut bounce = vec![0u8; total_bytes];
        let read_len = self.read_blocks(block_offset, &mut bounce).await?;
        sg_copy_from_vec(&mut list, &bounce[..read_len])?;
        Ok(list)
    }

    /// ブロック書き込み
    pub async fn write_blocks(&self, block_offset: u64, buf: &[u8]) -> FsResult<usize> {
        if block_offset >= self.block_count {
            return Err(FsError::InvalidArgument);
        }

        if buf.len() % self.block_size as usize != 0 {
            return Err(FsError::InvalidArgument);
        }

        let blocks_to_write = buf.len() / self.block_size as usize;
        let blocks_available = (self.block_count - block_offset) as usize;
        let blocks = blocks_to_write.min(blocks_available);

        if blocks == 0 {
            return Ok(0);
        }

        if blocks > u16::MAX as usize {
            return Err(FsError::InvalidArgument);
        }

        let dma_len = blocks * self.block_size as usize;

        let (ctx, prp1, _prp2) = prepare_dma_write(buf, dma_len)?;
        let lba = self.start_block + block_offset;
        let alloc_len = align_up(dma_len, NVME_PAGE_SIZE);
        let future = {
            let buf = DmaBufHandle { iova: prp1, len: alloc_len };
            crate::io::io_scheduler::hybrid_coordinator().submit_io_command(
                self.io_device(),
                IoCommand::BlockWrite { lba, blocks: blocks as u16, bytes: dma_len, buf },
                IoPriority::Normal,
            )
        };
        let request_id = future.request_id();
        let mut ctx: NvmeDmaContext = ctx;
        ctx.mark_inflight();
        let hook: CompletionHook = Box::new(move |_result| {
            let _ = ctx.complete();
        });
        crate::io::io_scheduler::io_scheduler().register_completion_hook(request_id, hook);

        let result = future.await;
        match result {
            Ok(bytes) => Ok(bytes),
            Err(_) => Err(FsError::IoError),
        }
    }

    /// Scatter-Gather DMAバッファからのブロック書き込み
    pub async fn write_blocks_sg_dma(
        &self,
        block_offset: u64,
        list: TypedSgList<CpuOwned>,
    ) -> FsResult<TypedSgList<CpuOwned>> {
        if block_offset >= self.block_count {
            return Err(FsError::InvalidArgument);
        }
        if list.is_empty() {
            return Ok(list);
        }

        let total_bytes = sg_total_bytes(&list)?;
        if total_bytes == 0 {
            return Ok(list);
        }
        validate_sg_block_params(total_bytes, self.block_size, block_offset, self.block_count)?;

        let bounce = sg_copy_to_vec(&list)?;
        let _ = self.write_blocks(block_offset, &bounce).await?;
        Ok(list)
    }

    /// Scatter-Gatherリクエストを非同期スケジューラに送信
    pub fn submit_sg_request(&self, request: Arc<SgIoRequest>) -> SgIoFuture {
        async_io_scheduler().submit_sg_request(*self, request)
    }

    /// SG I/Oリクエストのパラメータを検証する
    pub(super) fn validate_sg_request(&self, request: &SgIoRequest) -> Result<(usize, u64), FsError> {
        if request.entries.is_empty() {
            return Ok((0, 0));
        }
        if request.offset % (self.block_size as u64) != 0 {
            return Err(FsError::InvalidArgument);
        }
        let total_bytes = request.total_bytes();
        if total_bytes == 0 {
            return Ok((0, 0));
        }
        if total_bytes % self.block_size as usize != 0 {
            return Err(FsError::InvalidArgument);
        }
        Ok((total_bytes, request.offset / (self.block_size as u64)))
    }

    pub(super) async fn execute_sg_request(&self, request: &SgIoRequest) -> FsResult<usize> {
        let (total_bytes, block_offset) = self.validate_sg_request(request)?;
        if total_bytes == 0 {
            return Ok(0);
        }

        let list = sg_request_to_dma_list(request)?;

        if request.is_read {
            let list = self.read_blocks_sg_dma(block_offset, list).await?;
            sg_request_copy_back(request, &list, total_bytes)?;
        } else {
            let _ = self.write_blocks_sg_dma(block_offset, list).await?;
        }

        Ok(total_bytes)
    }

    /// Validate write_blocks_dma parameters and return block count
    pub(super) fn validate_write_block_params(&self, block_offset: u64, buf_size: usize) -> FsResult<usize> {
        if block_offset >= self.block_count {
            return Err(FsError::InvalidArgument);
        }
        if buf_size % self.block_size as usize != 0 {
            return Err(FsError::InvalidArgument);
        }
        let blocks = buf_size / self.block_size as usize;
        if blocks > u16::MAX as usize {
            return Err(FsError::InvalidArgument);
        }
        if blocks as u64 > self.block_count - block_offset {
            return Err(FsError::InvalidArgument);
        }
        Ok(blocks)
    }

    /// DMAバッファからのブロック書き込み
    pub async fn write_blocks_dma(
        &self,
        block_offset: u64,
        buffer: DmaBuffer,
    ) -> FsResult<DmaBuffer> {
        if buffer.size() == 0 {
            return Ok(buffer);
        }

        let blocks = self.validate_write_block_params(block_offset, buffer.size())?;
        if blocks == 0 {
            return Ok(buffer);
        }

        let (ctx, prp1, _prp2) = prepare_dma_from_kapi_buffer(&buffer)?;
        let lba = self.start_block + block_offset;
        let bytes = blocks * self.block_size as usize;
        let alloc_len = align_up(bytes, NVME_PAGE_SIZE);
        let page_mask = (NVME_PAGE_SIZE as u64) - 1;
        let use_command = {
            let start_page = prp1 & !page_mask;
            let end_addr = prp1.saturating_add(bytes as u64).saturating_sub(1);
            let end_page = end_addr & !page_mask;
            (bytes as u64) <= (NVME_PAGE_SIZE as u64) && start_page == end_page
        };
        let future = if use_command {
            let buf = DmaBufHandle { iova: prp1, len: alloc_len };
            crate::io::io_scheduler::hybrid_coordinator().submit_io_command(
                self.io_device(),
                IoCommand::BlockWrite { lba, blocks: blocks as u16, bytes, buf },
                IoPriority::Normal,
            )
        } else {
            crate::io::io_scheduler::hybrid_coordinator().submit_io_command(
                self.io_device(),
                IoCommand::BlockWrite { lba, blocks: blocks as u16, bytes: bytes, buf: DmaBufHandle { iova: prp1, len: bytes } },
                IoPriority::Normal,
            )
        };
        let request_id = future.request_id();
        let mut ctx: NvmeExternalDmaContext = ctx;
        ctx.mark_inflight();
        let hook: CompletionHook = Box::new(move |_result| {
            ctx.complete();
        });
        crate::io::io_scheduler::io_scheduler().register_completion_hook(request_id, hook);

        let result = future.await;
        match result {
            Ok(_) => Ok(buffer),
            Err(_) => Err(FsError::IoError),
        }
    }

    /// フラッシュ
    pub async fn flush(&self) -> FsResult<()> {
        let result = crate::io::io_scheduler::hybrid_coordinator()
            .submit_io_command(
                self.io_device(),
                IoCommand::Flush,
                IoPriority::High,
            )
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(_) => Err(FsError::IoError),
        }
    }

    /// TRIM（Discard）
    pub async fn discard(&self, block_offset: u64, block_count: u64) -> FsResult<()> {
        if block_offset >= self.block_count {
            return Err(FsError::InvalidArgument);
        }

        let count = block_count.min(self.block_count - block_offset);
        if count == 0 {
            return Ok(());
        }
        if count > u32::MAX as u64 {
            return Err(FsError::InvalidArgument);
        }

        let mut dsm = TypedDmaSlice::<CpuOwned>::new(NVME_PAGE_SIZE)
            .ok_or(FsError::NoSpace)?;
        let range = LocalDsmRange::new(
            self.start_block + block_offset,
            count as u32,
        );

        // Use kernel_api abstractions - device param is now ignored
        let (_prp1_unused, prp_map) = map_nvme_iommu(dsm.phys_addr().as_u64(), dsm.len())?;
        // Initialize descriptor with ranges
        let dsm_bytes = dsm.as_mut_slice();
        unsafe {
            let ptr = dsm_bytes.as_mut_ptr() as *mut LocalDsmRange;
            ptr.write(range);
        }
        let dsm_len = dsm.len();

        let (dev, guard) = dsm.start_dma();
        let prp1 = dev.phys_addr().as_u64();

        // Submit IO request
        let future = crate::io::io_scheduler::hybrid_coordinator().submit_io_command(
            self.io_device(),
            IoCommand::Ioctl {
                code: 0x09, // Dataset Management
                buf: DmaBufHandle { iova: prp1, len: dsm_len }
            },
            IoPriority::High
        );
        let request_id = future.request_id();
        let hook: CompletionHook = Box::new(move |_result| {
            let _ = (guard as SliceDmaGuard).complete(dev);
            if let Some(map) = prp_map {
                map.unmap();
            }
        });
        crate::io::io_scheduler::io_scheduler().register_completion_hook(request_id, hook);

        let result = future.await;
        match result {
            Ok(_) => Ok(()),
            Err(_) => Err(FsError::IoError),
        }
    }
}

// ============================================================================
// Scatter-Gather I/O
// ============================================================================

/// Scatter-Gatherエントリ
#[derive(Debug, Clone)]
pub struct SgEntry {
    /// バッファアドレス
    pub addr: usize,
    /// 長さ
    pub len: usize,
}

/// Scatter-Gather I/O リクエスト
pub struct SgIoRequest {
    /// リクエストID
    pub id: u64,
    /// 読み取り/書き込み
    pub is_read: bool,
    /// オフセット
    pub offset: u64,
    /// SGエントリリスト
    pub entries: Vec<SgEntry>,
    /// 完了フラグ
    completed: AtomicBool,
    /// 結果
    result: Mutex<Option<FsResult<usize>>>,
    /// Waker
    waker: Mutex<Option<Waker>>,
}

impl SgIoRequest {
    /// 新しいSG I/Oリクエストを作成
    pub fn new(id: u64, is_read: bool, offset: u64, entries: Vec<SgEntry>) -> Self {
        Self {
            id,
            is_read,
            offset,
            entries,
            completed: AtomicBool::new(false),
            result: Mutex::new(None),
            waker: Mutex::new(None),
        }
    }

    /// 総バイト数を計算
    pub fn total_bytes(&self) -> usize {
        self.entries.iter().map(|e| e.len).sum()
    }

    /// 完了をマーク
    pub fn complete(&self, result: FsResult<usize>) {
        *self.result.lock() = Some(result);
        self.completed.store(true, Ordering::Release);

        if let Some(waker) = self.waker.lock().take() {
            waker.wake();
        }
    }

    /// 完了したか
    pub fn is_completed(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }

    /// Futureを取得
    pub fn into_future(self: Arc<Self>) -> SgIoFuture {
        SgIoFuture::new(self)
    }
}
