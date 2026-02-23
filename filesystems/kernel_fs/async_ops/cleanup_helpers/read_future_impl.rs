use super::*;


mod flush_future_impl;
pub use self::flush_future_impl::*;
impl<'a> AsyncReadFuture<'a> {
    pub(super) fn new(file: &'a AsyncFile, buf: &'a mut [u8]) -> Self {
        Self {
            file,
            buf,
            started: false,
            io_future: None,
            dma_user_len: 0,
            cancel_guard: None,
            dma_result: None,
            dma_offset_in_block: None,
            dma_dma_len: None,
        }
    }

    /// Issue a direct-I/O NVMe read command and return Pending.
    pub(super) fn start_direct_io(
        &mut self,
        cx: &mut Context<'_>,
        position: u64,
        to_read: usize,
    ) -> Poll<FsResult<usize>> {
        let block_size = self.file.block_size;
        let offset_in_block = (position % block_size) as usize;
        let total_len = offset_in_block + to_read;
        let blocks_u64 = (total_len as u64 + block_size - 1) / block_size;
        if blocks_u64 > u16::MAX as u64 {
            return Poll::Ready(Err(FsError::InvalidArgument));
        }
        let blocks = blocks_u64 as u16;
        let dma_len = (blocks as usize) * (block_size as usize);
        let lba = self.file.start_block + (position / block_size);
        let (ctx, prp1, _prp2) = match prepare_dma_read(dma_len) {
            Ok(v) => v,
            Err(e) => return Poll::Ready(Err(e)),
        };

        let canceled = Arc::new(AtomicBool::new(false));
        self.cancel_guard = Some(NvmeCancelGuard::new(canceled.clone()));
        let slot = Arc::new(Mutex::new(None::<(TypedDmaSlice<CpuOwned>, usize)>));
        let slot_clone = slot.clone();
        self.dma_result = Some(slot);
        self.dma_offset_in_block = Some(offset_in_block);
        self.dma_dma_len = Some(dma_len);

        let alloc_len = align_up(dma_len, NVME_PAGE_SIZE);
        let future = {
            let buf = DmaBufHandle { iova: prp1, len: alloc_len };
            crate::io::io_scheduler::hybrid_coordinator().submit_io_command(
                self.file.io_device(),
                IoCommand::BlockRead { lba, blocks, bytes: dma_len, buf },
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
        crate::io::io_scheduler::io_scheduler()
            .register_completion_hook(request_id, hook);

        self.io_future = Some(future);
        self.dma_user_len = to_read;
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    /// Extract completed DMA data into the user buffer.
    pub(super) fn complete_dma_read(&mut self) -> Poll<FsResult<usize>> {
        if let Some(mut guard) = self.cancel_guard.take() {
            guard.disarm();
        }
        let slot = match self.dma_result.take() {
            Some(s) => s,
            None => return Poll::Ready(Err(FsError::IoError)),
        };
        let (data, bytes_received) = slot.lock().take().ok_or(FsError::IoError)?;
        let dma_len = self.dma_dma_len.take().ok_or(FsError::IoError)?;
        let offset_in_block = self.dma_offset_in_block.take().ok_or(FsError::IoError)?;
        let available = bytes_received.min(dma_len).min(data.len());
        let start = offset_in_block.min(available);
        let remaining = available.saturating_sub(start);
        let copy_len = remaining.min(self.dma_user_len);
        if copy_len > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data.as_slice().as_ptr().add(start),
                    self.buf.as_mut_ptr(),
                    copy_len,
                );
            }
        }
        self.file
            .position
            .fetch_add(copy_len as u64, Ordering::Relaxed);
        Poll::Ready(Ok(copy_len))
    }
}

impl<'a> AsyncReadFuture<'a> {
    pub(super) fn try_start_read(&mut self, cx: &mut Context<'_>) -> Option<Poll<FsResult<usize>>> {
        let position = self.file.position.load(Ordering::Relaxed);
        let len = self.buf.len();
        let size = self.file.attr.lock().size;
        if position >= size {
            return Some(Poll::Ready(Ok(0)));
        }
        let available = (size - position) as usize;
        let to_read = len.min(available);
        if to_read == 0 {
            return Some(Poll::Ready(Ok(0)));
        }
        if self.file.direct_io {
            return Some(self.start_direct_io(cx, position, to_read));
        }
        let file_id = self.file.id;
        match read_via_page_cache(file_id, position, &mut self.buf[..to_read], size) {
            Ok(read_len) => {
                self.file
                    .position
                    .fetch_add(read_len as u64, Ordering::Relaxed);
                Some(Poll::Ready(Ok(read_len)))
            }
            Err(e) => Some(Poll::Ready(Err(e))),
        }
    }
}

impl<'a> Future for AsyncReadFuture<'a> {
    type Output = FsResult<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.file.readable {
            return Poll::Ready(Err(FsError::PermissionDenied));
        }

        if !self.started {
            self.started = true;
            if let Some(result) = self.try_start_read(cx) {
                return result;
            }
        }

        if let Some(future) = self.io_future.as_mut() {
            match Pin::new(future).poll(cx) {
                Poll::Ready(Ok(_)) => return self.complete_dma_read(),
                Poll::Ready(Err(_)) => {
                    if let Some(mut guard) = self.cancel_guard.take() {
                        guard.disarm();
                    }
                    return Poll::Ready(Err(FsError::IoError));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(0))
    }
}

/// 非同期書き込みFuture
pub struct AsyncWriteFuture<'a> {
    file: &'a AsyncFile,
    buf: &'a [u8],
    started: bool,
    io_future: Option<crate::io::io_scheduler::IoFuture>,
    dma_user_len: usize,
    unaligned: Option<UnalignedWriteState>,
}

pub(crate) struct UnalignedReadSlot {
    data: Mutex<Option<TypedDmaSlice<CpuOwned>>>,
}

impl UnalignedReadSlot {
    pub(super) fn new() -> Self {
        Self {
            data: Mutex::new(None),
        }
    }
}

pub(crate) enum UnalignedWriteState {
    Reading {
        io_future: crate::io::io_scheduler::IoFuture,
        data_slot: Arc<UnalignedReadSlot>,
        lba: u64,
        blocks: u16,
        offset: usize,
        len: usize,
        start_pos: u64,
    },
    Writing {
        io_future: crate::io::io_scheduler::IoFuture,
        len: usize,
        start_pos: u64,
    },
}

impl<'a> AsyncWriteFuture<'a> {
    pub(super) fn new(file: &'a AsyncFile, buf: &'a [u8]) -> Self {
        Self {
            file,
            buf,
            started: false,
            io_future: None,
            dma_user_len: 0,
            unaligned: None,
        }
    }

    /// ファイル位置とサイズを更新する共通ヘルパー
    pub(super) fn commit_write(&self, written: usize, base_position: u64) {
        self.file
            .position
            .fetch_add(written as u64, Ordering::Relaxed);
        let mut attr = self.file.attr.lock();
        let new_end = base_position + written as u64;
        if new_end > attr.size {
            attr.size = new_end;
        }
    }

    /// 初回ポーリング時の書き込み開始処理
    pub(super) fn poll_start(&mut self, cx: &mut Context<'_>) -> Poll<FsResult<usize>> {
        self.started = true;

        let position = self.file.position.load(Ordering::Relaxed);
        let len = self.buf.len();

        if len == 0 {
            return Poll::Ready(Ok(0));
        }

        // ダイレクトI/Oの場合
        if self.file.direct_io {
            let block_size = self.file.block_size;
            let offset_in_block = (position % block_size) as usize;
            if offset_in_block != 0 || (len as u64) % block_size != 0 {
                return self.start_unaligned_rmw(position, len, cx);
            }
            return self.start_aligned_direct_write(position, len, cx);
        }

        let file_size = self.file.attr.lock().size;
        match write_via_page_cache(self.file.id, position, self.buf, file_size) {
            Ok(written) => {
                self.commit_write(written, position);
                Poll::Ready(Ok(written))
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    /// 非アラインDMA: Read-Modify-Write開始
    pub(super) fn start_unaligned_rmw(
        &mut self,
        position: u64,
        len: usize,
        cx: &mut Context<'_>,
    ) -> Poll<FsResult<usize>> {
        let block_size = self.file.block_size;
        let offset_in_block = (position % block_size) as usize;
        let end_pos = position + len as u64;
        let aligned_start = position / block_size;
        let aligned_end =
            (end_pos + block_size - 1) / block_size;
        let blocks_u64 = aligned_end.saturating_sub(aligned_start);

        if blocks_u64 > u16::MAX as u64 {
            return Poll::Ready(Err(FsError::InvalidArgument));
        }

        let blocks = blocks_u64 as u16;
        let dma_len = (blocks as usize) * (block_size as usize);
        let lba = self.file.start_block + aligned_start;

        let (ctx, prp1, _prp2) = match prepare_dma_read(dma_len) {
            Ok(v) => v,
            Err(e) => return Poll::Ready(Err(e)),
        };

        let data_slot = Arc::new(UnalignedReadSlot::new());
        let slot = data_slot.clone();
        let future = crate::io::io_scheduler::hybrid_coordinator().submit_io_command(
            self.file.io_device(),
            IoCommand::BlockRead { lba, blocks, bytes: dma_len, buf: DmaBufHandle { iova: prp1, len: dma_len } },
            IoPriority::Normal,
        );
        let request_id = future.request_id();
        let mut ctx: NvmeDmaContext = ctx;
        ctx.mark_inflight();
        let hook: CompletionHook = Box::new(move |result| {
            let data = ctx.complete();
            if let IoResult::Success(_) = result {
                *slot.data.lock() = Some(data);
            }
        });
        crate::io::io_scheduler::io_scheduler().register_completion_hook(request_id, hook);

        self.unaligned = Some(UnalignedWriteState::Reading {
            io_future: future,
            data_slot,
            lba,
            blocks,
            offset: offset_in_block,
            len,
            start_pos: position,
        });
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    /// アラインDMAライト開始
    pub(super) fn start_aligned_direct_write(
        &mut self,
        position: u64,
        len: usize,
        cx: &mut Context<'_>,
    ) -> Poll<FsResult<usize>> {
        let block_size = self.file.block_size;
        let blocks_u64 = len as u64 / block_size;
        if blocks_u64 > u16::MAX as u64 {
            return Poll::Ready(Err(FsError::InvalidArgument));
        }
        let blocks = blocks_u64 as u16;
        let dma_len = (blocks as usize) * (block_size as usize);
        let lba = self.file.start_block + (position / block_size);

        let (ctx, prp1, _prp2) = match prepare_dma_write(self.buf, dma_len) {
            Ok(v) => v,
            Err(e) => return Poll::Ready(Err(e)),
        };

        let alloc_len = align_up(dma_len, NVME_PAGE_SIZE);
        let future = {
            let buf = DmaBufHandle { iova: prp1, len: alloc_len };
            crate::io::io_scheduler::hybrid_coordinator().submit_io_command(
                self.file.io_device(),
                IoCommand::BlockWrite { lba, blocks, bytes: dma_len, buf },
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

        self.io_future = Some(future);
        self.dma_user_len = len;
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    /// アラインDMAライトの完了ポーリング
    pub(super) fn poll_aligned_completion(&mut self, cx: &mut Context<'_>) -> Poll<FsResult<usize>> {
        let future = self.io_future.as_mut().unwrap();
        match Pin::new(future).poll(cx) {
            Poll::Ready(Ok(_)) => {
                let len = self.dma_user_len;
                let position = self.file.position.load(Ordering::Relaxed);
                self.commit_write(len, position);
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(FsError::IoError)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// 非アラインDMAステートのポーリング
    pub(super) fn poll_unaligned_state(&mut self, cx: &mut Context<'_>) -> Poll<FsResult<usize>> {
        let state = self.unaligned.take().unwrap();
        match state {
            UnalignedWriteState::Reading {
                io_future,
                data_slot,
                lba,
                blocks,
                offset,
                len,
                start_pos,
            } => self.poll_unaligned_reading(
                io_future, data_slot, lba, blocks, offset, len, start_pos, cx,
            ),
            UnalignedWriteState::Writing {
                io_future,
                len,
                start_pos,
            } => self.poll_unaligned_writing(io_future, len, start_pos, cx),
        }
    }

    /// 非アラインDMA Reading状態のポーリング
    pub(super) fn poll_unaligned_reading(
        &mut self,
        mut io_future: crate::io::io_scheduler::IoFuture,
        data_slot: Arc<UnalignedReadSlot>,
        lba: u64,
        blocks: u16,
        offset: usize,
        len: usize,
        start_pos: u64,
        cx: &mut Context<'_>,
    ) -> Poll<FsResult<usize>> {
        match Pin::new(&mut io_future).poll(cx) {
            Poll::Ready(Ok(_)) => {
                let mut data = match data_slot.data.lock().take() {
                    Some(data) => data,
                    None => return Poll::Ready(Err(FsError::IoError)),
                };
                let end = offset + len;
                if end > data.len() {
                    return Poll::Ready(Err(FsError::InvalidArgument));
                }
                data.as_mut_slice()[offset..end].copy_from_slice(self.buf);

                let dma_len = data.len();
                let (write_ctx, prp1, _prp2) = match prepare_dma_from_cpu_buffer(data) {
                    Ok(v) => v,
                    Err(e) => return Poll::Ready(Err(e)),
                };
                let alloc_len = align_up(dma_len, NVME_PAGE_SIZE);
                let future = {
                    let buf = DmaBufHandle { iova: prp1, len: alloc_len };
                    crate::io::io_scheduler::hybrid_coordinator().submit_io_command(
                        self.file.io_device(),
                        IoCommand::BlockWrite { lba, blocks, bytes: dma_len, buf },
                        IoPriority::Normal,
                    )
                };
                let request_id = future.request_id();
                let mut write_ctx: NvmeDmaContext = write_ctx;
                write_ctx.mark_inflight();
                let hook: CompletionHook = Box::new(move |_result| {
                    let _ = write_ctx.complete();
                });
                crate::io::io_scheduler::io_scheduler()
                    .register_completion_hook(request_id, hook);

                self.unaligned = Some(UnalignedWriteState::Writing {
                    io_future: future,
                    len,
                    start_pos,
                });
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(FsError::IoError)),
            Poll::Pending => {
                self.unaligned = Some(UnalignedWriteState::Reading {
                    io_future,
                    data_slot,
                    lba,
                    blocks,
                    offset,
                    len,
                    start_pos,
                });
                Poll::Pending
            }
        }
    }

    /// 非アラインDMA Writing状態のポーリング
    pub(super) fn poll_unaligned_writing(
        &mut self,
        mut io_future: crate::io::io_scheduler::IoFuture,
        len: usize,
        start_pos: u64,
        cx: &mut Context<'_>,
    ) -> Poll<FsResult<usize>> {
        match Pin::new(&mut io_future).poll(cx) {
            Poll::Ready(Ok(_)) => {
                self.commit_write(len, start_pos);
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(FsError::IoError)),
            Poll::Pending => {
                self.unaligned = Some(UnalignedWriteState::Writing {
                    io_future,
                    len,
                    start_pos,
                });
                Poll::Pending
            }
        }
    }
}

impl<'a> Future for AsyncWriteFuture<'a> {
    type Output = FsResult<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.file.writable {
            return Poll::Ready(Err(FsError::PermissionDenied));
        }

        if !self.started {
            return self.poll_start(cx);
        }

        if self.io_future.is_some() {
            return self.poll_aligned_completion(cx);
        }

        if self.unaligned.is_some() {
            return self.poll_unaligned_state(cx);
        }

        Poll::Ready(Ok(0))
    }
}

/// 非同期フラッシュFuture
pub struct AsyncFlushFuture<'a> {
    file: &'a AsyncFile,
    started: bool,
    io_future: Option<crate::io::io_scheduler::IoFuture>,
}

impl<'a> AsyncFlushFuture<'a> {
    pub(super) fn new(file: &'a AsyncFile) -> Self {
        Self {
            file,
            started: false,
            io_future: None,
        }
    }
}
