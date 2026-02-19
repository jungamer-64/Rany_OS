// ============================================================================
// libs/vfs/src/block.rs - Block Device Abstraction
// ============================================================================
//!
//! ブロックデバイス抽象化レイヤー
//!
//! ## 設計
//! - 統一ブロックデバイスインターフェース
//! - `VirtIO`-blk、`NVMe`、RAMディスク対応
//! - 非同期I/Oサポート
//!

// Allow common patterns in block device code
#![allow(clippy::missing_const_for_fn)] // Many functions use sync primitives
#![allow(clippy::missing_errors_doc)] // Block device trait methods
#![allow(clippy::cast_possible_truncation)] // 64-bit kernel, u64->usize is safe
#![allow(clippy::collapsible_if)] // Kept for readability in state machines
#![allow(clippy::useless_asref)] // Option::as_ref().map pattern
#![allow(clippy::redundant_closure_for_method_calls)] // Clone pattern
#![allow(clippy::must_use_candidate)] // Internal implementation
#![allow(clippy::option_if_let_else)] // Kept for readability

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;

// ============================================================================
// Common Constants
// ============================================================================

/// Standard sector size (512 bytes)
///
/// Most block devices use 512-byte sectors. Some advanced devices (NVMe with
/// 4K sectors, Advanced Format HDDs) may use different sizes, but 512 is the
/// de-facto standard for compatibility.
pub const SECTOR_SIZE: usize = 512;

// ============================================================================
// Block Device Error
// ============================================================================

/// Block device error types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockError {
    /// Device not ready
    NotReady,
    /// Invalid block address
    InvalidBlock,
    /// I/O error
    IoError,
    /// Device is read-only
    ReadOnly,
    /// Invalid buffer size
    InvalidBufferSize,
    /// Queue full
    QueueFull,
    /// Timeout
    Timeout,
}

/// Result type for block operations
pub type BlockResult<T> = Result<T, BlockError>;

// ============================================================================
// Zero-Copy Buffer + Block Device (Ownership-Moving I/O)
// ============================================================================

/// Owned buffer for zero-copy I/O (default Vec-backed compatibility type).
///
/// This is a transitional buffer type; real zero-copy drivers should use
/// DMA-capable buffers and implement `ZeroCopyBufferMut` directly.
pub struct OwnedBytes {
    data: Vec<u8>,
}

impl OwnedBytes {
    /// Create a new owned buffer from Vec.
    pub fn from_vec(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Consume the buffer and return the inner Vec.
    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }

    /// Return buffer length in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl AsRef<[u8]> for OwnedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for OwnedBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl From<Vec<u8>> for OwnedBytes {
    fn from(data: Vec<u8>) -> Self {
        Self::from_vec(data)
    }
}

/// Zero-copy buffer interface (ownership moves across layers).
pub trait ZeroCopyBuffer: Send + 'static {
    /// Read-only view of the buffer.
    fn as_slice(&self) -> &[u8];

    /// Buffer length in bytes.
    fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Whether the buffer is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Optional DMA info for DMA-capable buffers. Default: None.
    fn dma_info(&self) -> Option<DmaInfo> {
        None
    }
}

/// Mutable zero-copy buffer interface (for write paths).
pub trait ZeroCopyBufferMut: ZeroCopyBuffer {
    /// Mutable view of the buffer.
    fn as_mut_slice(&mut self) -> &mut [u8];
}

impl ZeroCopyBuffer for OwnedBytes {
    fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl ZeroCopyBufferMut for OwnedBytes {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

// ============================================================================
// Borrowed I/O Buffer Abstraction
// ============================================================================

#[derive(Clone, Copy, Debug)]
pub struct DmaInfo {
    /// NOTE: phys_addr is CPU physical; map to IOVA before DMA.
    pub phys_addr: u64,
    pub len: usize,
}

/// Borrowed I/O buffer.
///
/// Invariant: as_slice().len() == dma_info().len (if Some)
pub trait IoBuffer: Send {
    fn as_slice(&self) -> &[u8];

    #[inline]
    fn dma_info(&self) -> Option<DmaInfo> {
        None
    }
}

/// Mutable borrowed I/O buffer.
///
/// Invariant: as_mut_slice().len() == as_slice().len()
pub trait IoBufferMut: IoBuffer {
    fn as_mut_slice(&mut self) -> &mut [u8];
}

impl IoBuffer for &[u8] {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        self
    }
}

impl IoBuffer for &mut [u8] {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        self
    }
}

impl IoBufferMut for &mut [u8] {
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self
    }
}

impl IoBuffer for Vec<u8> {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        self.as_slice()
    }
}

impl IoBufferMut for Vec<u8> {
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

// NOTE: We forward dma info from ZeroCopyBuffer when available. This allows
// DMA-capable owned buffers to advertise physical addresses while keeping the
// default behavior (None) for arbitrary owned buffers.
impl<T: ZeroCopyBuffer> IoBuffer for T {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        self.as_slice()
    }

    #[inline]
    fn dma_info(&self) -> Option<DmaInfo> {
        ZeroCopyBuffer::dma_info(self)
    }
}

impl<T: ZeroCopyBufferMut> IoBufferMut for T {
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

/// Boxed future type for object-safe zero-copy device APIs.
pub type ZcFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Zero-copy block device interface (async, ownership-moving).
///
/// This trait is object-safe to allow `Arc<dyn ZeroCopyBlockDevice<Buffer = B>>`.
pub trait ZeroCopyBlockDevice: Send + Sync {
    /// Owned buffer type for transfers.
    type Buffer: ZeroCopyBufferMut;

    /// Get device information.
    fn info(&self) -> BlockDeviceInfo;

    /// Flush pending writes.
    fn flush(&self) -> BlockResult<()>;

    /// Allocate a buffer for I/O.
    fn alloc_buffer(&self, size: usize) -> BlockResult<Self::Buffer>;

    /// Read blocks into a newly owned buffer.
    fn read_async(&self, block: u64, count: u32) -> ZcFuture<'_, BlockResult<Self::Buffer>>;

    /// Write blocks from an owned buffer, returning ownership for reuse.
    fn write_async(
        &self,
        block: u64,
        buffer: Self::Buffer,
    ) -> ZcFuture<'_, BlockResult<Self::Buffer>>;

    /// Read blocks into a borrowed buffer (default: owned fallback).
    ///
    /// Requirements:
    /// - len % block_size == 0
    /// - blocks = len / block_size
    fn read_into_buf<'a>(
        &'a self,
        block: u64,
        dst: &'a mut dyn IoBufferMut,
    ) -> ZcFuture<'a, BlockResult<()>> {
        Box::pin(async move {
            let bs_u32 = self.info().block_size;
            if bs_u32 == 0 {
                return Err(BlockError::InvalidBufferSize);
            }
            let bs = bs_u32 as usize;
            let len = dst.as_mut_slice().len();
            if len == 0 {
                return Ok(());
            }
            if !len.is_multiple_of(bs) {
                return Err(BlockError::InvalidBufferSize);
            }
            let blocks = len / bs;
            if blocks > (u32::MAX as usize) {
                return Err(BlockError::InvalidBufferSize);
            }

            let buf = self.read_async(block, blocks as u32).await?;
            let src = ZeroCopyBuffer::as_slice(&buf);
            if src.len() < len {
                return Err(BlockError::IoError);
            }
            dst.as_mut_slice().copy_from_slice(&src[..len]);
            Ok(())
        })
    }

    /// Write blocks from a borrowed buffer (default: owned fallback).
    ///
    /// Requirements:
    /// - len % block_size == 0
    /// - blocks = len / block_size
    fn write_from_buf<'a>(
        &'a self,
        block: u64,
        src: &'a dyn IoBuffer,
    ) -> ZcFuture<'a, BlockResult<()>> {
        let bs_u32 = self.info().block_size;
        if bs_u32 == 0 {
            return Box::pin(async { Err(BlockError::InvalidBufferSize) });
        }
        let bs = bs_u32 as usize;
        let len = src.as_slice().len();
        if len == 0 {
            return Box::pin(async { Ok(()) });
        }
        if !len.is_multiple_of(bs) {
            return Box::pin(async { Err(BlockError::InvalidBufferSize) });
        }
        let blocks = len / bs;
        if blocks > (u32::MAX as usize) {
            return Box::pin(async { Err(BlockError::InvalidBufferSize) });
        }

        let mut buf = match self.alloc_buffer(len) {
            Ok(buf) => buf,
            Err(err) => return Box::pin(async move { Err(err) }),
        };
        if ZeroCopyBufferMut::as_mut_slice(&mut buf).len() < len {
            return Box::pin(async { Err(BlockError::InvalidBufferSize) });
        }
        ZeroCopyBufferMut::as_mut_slice(&mut buf)[..len].copy_from_slice(src.as_slice());

        Box::pin(async move {
            let _ = self.write_async(block, buf).await?;
            Ok(())
        })
    }

    /// Convenience wrapper for slice-based reads.
    fn read_into<'a>(&'a self, block: u64, dst: &'a mut [u8]) -> ZcFuture<'a, BlockResult<()>> {
        Box::pin(async move {
            let bs_u32 = self.info().block_size;
            if bs_u32 == 0 {
                return Err(BlockError::InvalidBufferSize);
            }
            let bs = bs_u32 as usize;
            let len = dst.len();
            if len == 0 {
                return Ok(());
            }
            if !len.is_multiple_of(bs) {
                return Err(BlockError::InvalidBufferSize);
            }
            let blocks = len / bs;
            if blocks > (u32::MAX as usize) {
                return Err(BlockError::InvalidBufferSize);
            }

            let buf = self.read_async(block, blocks as u32).await?;
            let src = ZeroCopyBuffer::as_slice(&buf);
            if src.len() < len {
                return Err(BlockError::IoError);
            }
            dst.copy_from_slice(&src[..len]);
            Ok(())
        })
    }

    /// Convenience wrapper for slice-based writes.
    fn write_from(&self, block: u64, src: &[u8]) -> ZcFuture<'_, BlockResult<()>> {
        let bs_u32 = self.info().block_size;
        if bs_u32 == 0 {
            return Box::pin(async { Err(BlockError::InvalidBufferSize) });
        }
        let bs = bs_u32 as usize;
        let len = src.len();
        if len == 0 {
            return Box::pin(async { Ok(()) });
        }
        if !len.is_multiple_of(bs) {
            return Box::pin(async { Err(BlockError::InvalidBufferSize) });
        }
        let blocks = len / bs;
        if blocks > (u32::MAX as usize) {
            return Box::pin(async { Err(BlockError::InvalidBufferSize) });
        }

        let mut buf = match self.alloc_buffer(len) {
            Ok(buf) => buf,
            Err(err) => return Box::pin(async move { Err(err) }),
        };
        if ZeroCopyBufferMut::as_mut_slice(&mut buf).len() < len {
            return Box::pin(async { Err(BlockError::InvalidBufferSize) });
        }
        ZeroCopyBufferMut::as_mut_slice(&mut buf)[..len].copy_from_slice(src);

        Box::pin(async move {
            let _ = self.write_async(block, buf).await?;
            Ok(())
        })
    }
}

/// Compatibility adapter: wrap a legacy `BlockDevice` and expose zero-copy API.
///
/// Note: This adapter still copies internally; real zero-copy drivers should
/// implement `ZeroCopyBlockDevice` directly with DMA-capable buffers.
pub struct BlockDeviceZeroCopyAdapter {
    device: Arc<dyn BlockDevice>,
}

impl BlockDeviceZeroCopyAdapter {
    /// Wrap a legacy block device.
    pub fn new(device: Arc<dyn BlockDevice>) -> Self {
        Self { device }
    }

    /// Access the wrapped device.
    pub fn device(&self) -> &Arc<dyn BlockDevice> {
        &self.device
    }
}

impl ZeroCopyBlockDevice for BlockDeviceZeroCopyAdapter {
    type Buffer = OwnedBytes;

    fn info(&self) -> BlockDeviceInfo {
        self.device.info()
    }

    fn flush(&self) -> BlockResult<()> {
        self.device.flush()
    }

    fn alloc_buffer(&self, size: usize) -> BlockResult<Self::Buffer> {
        Ok(OwnedBytes::from_vec(vec![0u8; size]))
    }

    fn read_async(&self, block: u64, count: u32) -> ZcFuture<'_, BlockResult<Self::Buffer>> {
        let device = Arc::clone(&self.device);
        Box::pin(async move {
            let data = BlockReadFuture::new(device, block, count).await?;
            Ok(OwnedBytes::from_vec(data))
        })
    }

    fn write_async(
        &self,
        block: u64,
        buffer: Self::Buffer,
    ) -> ZcFuture<'_, BlockResult<Self::Buffer>> {
        let device = Arc::clone(&self.device);
        Box::pin(async move {
            // Transitional path: copy into a Vec for legacy BlockDevice.
            let data = ZeroCopyBuffer::as_slice(&buffer).to_vec();
            let _ = BlockWriteFuture::new(device, block, data).await?;
            Ok(buffer)
        })
    }
}

// ============================================================================
// Block Request
// ============================================================================

/// Request type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestType {
    /// Read from device
    Read,
    /// Write to device
    Write,
    /// Flush pending writes
    Flush,
    /// Discard blocks
    Discard,
}

/// Request state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestState {
    /// Request is pending submission
    Pending,
    /// Request has been submitted
    Submitted,
    /// Request completed successfully
    Completed,
    /// Request failed
    Failed(BlockError),
}

/// A block I/O request
pub struct BlockRequest {
    /// Request ID
    pub id: u64,
    /// Request type
    pub req_type: RequestType,
    /// Starting block address
    pub block: u64,
    /// Number of blocks
    pub count: u32,
    /// Data buffer (for read/write)
    pub buffer: Mutex<Option<Vec<u8>>>,
    /// Request state
    state: Mutex<RequestState>,
    /// Waker for async completion
    waker: Mutex<Option<Waker>>,
}

impl BlockRequest {
    /// Create a new read request
    pub fn read(id: u64, block: u64, count: u32) -> Self {
        let buffer_size = count as usize * 512; // Assuming 512-byte blocks
        Self {
            id,
            req_type: RequestType::Read,
            block,
            count,
            buffer: Mutex::new(Some(alloc::vec![0u8; buffer_size])),
            state: Mutex::new(RequestState::Pending),
            waker: Mutex::new(None),
        }
    }

    /// Create a new write request
    pub fn write(id: u64, block: u64, data: Vec<u8>) -> Self {
        let count = (data.len() / 512) as u32;
        Self {
            id,
            req_type: RequestType::Write,
            block,
            count,
            buffer: Mutex::new(Some(data)),
            state: Mutex::new(RequestState::Pending),
            waker: Mutex::new(None),
        }
    }

    /// Create a flush request
    pub fn flush(id: u64) -> Self {
        Self {
            id,
            req_type: RequestType::Flush,
            block: 0,
            count: 0,
            buffer: Mutex::new(None),
            state: Mutex::new(RequestState::Pending),
            waker: Mutex::new(None),
        }
    }

    /// Get request state
    pub fn state(&self) -> RequestState {
        *self.state.lock()
    }

    /// Set request state
    pub fn set_state(&self, state: RequestState) {
        *self.state.lock() = state;

        // Wake pending future
        if let Some(waker) = self.waker.lock().take() {
            waker.wake();
        }
    }

    /// Check if request is complete
    pub fn is_complete(&self) -> bool {
        matches!(
            self.state(),
            RequestState::Completed | RequestState::Failed(_)
        )
    }

    /// Register waker for async completion
    pub fn register_waker(&self, waker: Waker) {
        *self.waker.lock() = Some(waker);
    }

    /// Take the data buffer
    pub fn take_buffer(&mut self) -> Option<Vec<u8>> {
        self.buffer.lock().take()
    }
}

// ============================================================================
// Block Device Trait
// ============================================================================

/// Block device information
#[derive(Clone, Debug)]
pub struct BlockDeviceInfo {
    /// Device name
    pub name: &'static str,
    /// Total number of blocks
    pub total_blocks: u64,
    /// Block size in bytes
    pub block_size: u32,
    /// Is device read-only
    pub read_only: bool,
    /// Maximum sectors per request
    pub max_sectors: u32,
    /// Number of queues
    pub num_queues: u16,
}

impl Default for BlockDeviceInfo {
    fn default() -> Self {
        Self {
            name: "unknown",
            total_blocks: 0,
            block_size: 512,
            read_only: false,
            max_sectors: 256,
            num_queues: 1,
        }
    }
}

/// Block device trait
pub trait BlockDevice: Send + Sync {
    /// Get device information
    fn info(&self) -> BlockDeviceInfo;

    /// Submit a request
    fn submit(&self, request: Arc<BlockRequest>) -> BlockResult<()>;

    /// Poll for completions
    fn poll_completions(&self) -> usize;

    /// Synchronous read
    ///
    /// # パフォーマンス注意
    /// `Arc::clone()` は同期read毎に参照カウンタの atomic increment を発生させる。
    /// ホットパスでは `submit()` が Arc<BlockRequest> を直接受け取り、
    /// クローンを回避するAPIの追加を検討すること。
    fn read_sync(&self, block: u64, buf: &mut [u8]) -> BlockResult<usize> {
        let info = self.info();
        let count = buf.len() / info.block_size as usize;

        let request = Arc::new(BlockRequest::read(0, block, count as u32));
        // Note: Arc::clone() は atomic increment (約3-5 CPU cycles on x86-64)
        // submit() が &Arc<T> を受け取れれば回避可能
        self.submit(Arc::clone(&request))?;

        // Poll until complete
        loop {
            self.poll_completions();
            match request.state() {
                RequestState::Completed => {
                    // Copy data from the request's internal buffer into caller buf
                    let guard = request.buffer.lock();
                    if let Some(inner) = guard.as_ref() {
                        let to_copy = inner.len().min(buf.len());
                        buf[..to_copy].copy_from_slice(&inner[..to_copy]);
                        return Ok(to_copy);
                    }
                    return Ok(0);
                }
                RequestState::Failed(e) => return Err(e),
                _ => core::hint::spin_loop(),
            }
        }
    }

    /// Synchronous write
    fn write_sync(&self, block: u64, buf: &[u8]) -> BlockResult<usize> {
        let request = Arc::new(BlockRequest::write(0, block, buf.to_vec()));
        self.submit(Arc::clone(&request))?;

        loop {
            self.poll_completions();
            match request.state() {
                RequestState::Completed => return Ok(buf.len()),
                RequestState::Failed(e) => return Err(e),
                _ => core::hint::spin_loop(),
            }
        }
    }

    /// Flush pending writes
    fn flush(&self) -> BlockResult<()> {
        let request = Arc::new(BlockRequest::flush(0));
        self.submit(Arc::clone(&request))?;

        loop {
            self.poll_completions();
            match request.state() {
                RequestState::Completed => return Ok(()),
                RequestState::Failed(e) => return Err(e),
                _ => core::hint::spin_loop(),
            }
        }
    }
}

// ============================================================================
// RAM Disk Implementation
// ============================================================================

/// Simple RAM disk for testing
pub struct RamDisk {
    /// Device info
    info: BlockDeviceInfo,
    /// Storage
    data: Mutex<Vec<u8>>,
    /// Pending requests
    pending: Mutex<VecDeque<Arc<BlockRequest>>>,
    /// Request ID counter
    next_id: AtomicU64,
}

impl RamDisk {
    /// Create a new RAM disk
    pub fn new(size_blocks: u64, block_size: u32) -> Self {
        let total_size = size_blocks as usize * block_size as usize;

        Self {
            info: BlockDeviceInfo {
                name: "ramdisk",
                total_blocks: size_blocks,
                block_size,
                read_only: false,
                max_sectors: 256,
                num_queues: 1,
            },
            data: Mutex::new(alloc::vec![0u8; total_size]),
            pending: Mutex::new(VecDeque::new()),
            next_id: AtomicU64::new(0),
        }
    }

    /// Create a 1MB RAM disk
    pub fn new_1mb() -> Self {
        Self::new(2048, 512) // 2048 * 512 = 1MB
    }

    /// Process a single request
    fn process_request(&self, request: &BlockRequest) {
        let block_size = self.info.block_size as usize;
        let offset = request.block as usize * block_size;
        let size = request.count as usize * block_size;

        match request.req_type {
            RequestType::Read => {
                let data = self.data.lock();
                if offset + size <= data.len() {
                    // Copy data into the request buffer
                    let mut buf_guard = request.buffer.lock();
                    if let Some(buf) = buf_guard.as_mut() {
                        let to_copy = buf.len().min(size);
                        buf[..to_copy].copy_from_slice(&data[offset..offset + to_copy]);
                    }
                    request.set_state(RequestState::Completed);
                } else {
                    request.set_state(RequestState::Failed(BlockError::InvalidBlock));
                }
            }
            RequestType::Write => {
                let mut data = self.data.lock();
                if offset + size <= data.len() {
                    // Read data from the request buffer and write into the ramdisk
                    let buf_guard = request.buffer.lock();
                    if let Some(buf) = buf_guard.as_ref() {
                        let to_copy = buf.len().min(size);
                        data[offset..offset + to_copy].copy_from_slice(&buf[..to_copy]);
                    }
                    request.set_state(RequestState::Completed);
                } else {
                    request.set_state(RequestState::Failed(BlockError::InvalidBlock));
                }
            }
            RequestType::Flush => {
                request.set_state(RequestState::Completed);
            }
            RequestType::Discard => {
                let mut data = self.data.lock();
                if offset + size <= data.len() {
                    data[offset..offset + size].fill(0);
                    request.set_state(RequestState::Completed);
                } else {
                    request.set_state(RequestState::Failed(BlockError::InvalidBlock));
                }
            }
        }
    }

    /// Get next request ID
    pub fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }
}

impl BlockDevice for RamDisk {
    fn info(&self) -> BlockDeviceInfo {
        self.info.clone()
    }

    fn submit(&self, request: Arc<BlockRequest>) -> BlockResult<()> {
        request.set_state(RequestState::Submitted);
        self.pending.lock().push_back(request);
        Ok(())
    }

    fn poll_completions(&self) -> usize {
        let mut pending = self.pending.lock();
        let mut completed = 0;

        // Process all pending requests
        while let Some(request) = pending.pop_front() {
            self.process_request(&request);
            completed += 1;
        }

        completed
    }
}

// ============================================================================
// Async Block I/O
// ============================================================================

/// Future for async block read
pub struct BlockReadFuture {
    device: Arc<dyn BlockDevice>,
    request: Arc<BlockRequest>,
}

impl BlockReadFuture {
    /// Create a new read future
    pub fn new(device: Arc<dyn BlockDevice>, block: u64, count: u32) -> Self {
        let request = Arc::new(BlockRequest::read(0, block, count));
        Self { device, request }
    }
}

impl Future for BlockReadFuture {
    type Output = BlockResult<Vec<u8>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Submit if pending
        if matches!(self.request.state(), RequestState::Pending) {
            if let Err(e) = self.device.submit(self.request.clone()) {
                return Poll::Ready(Err(e));
            }
        }

        // Poll completions
        self.device.poll_completions();

        // Check state
        match self.request.state() {
            RequestState::Completed => {
                // Return data (clone the inner buffer)
                let buffer = self
                    .request
                    .buffer
                    .lock()
                    .as_ref()
                    .map(|b| b.clone())
                    .unwrap_or_default();
                Poll::Ready(Ok(buffer))
            }
            RequestState::Failed(e) => Poll::Ready(Err(e)),
            _ => {
                self.request.register_waker(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

/// Future for async block write
pub struct BlockWriteFuture {
    device: Arc<dyn BlockDevice>,
    request: Arc<BlockRequest>,
}

impl BlockWriteFuture {
    /// Create a new write future
    pub fn new(device: Arc<dyn BlockDevice>, block: u64, data: Vec<u8>) -> Self {
        let request = Arc::new(BlockRequest::write(0, block, data));
        Self { device, request }
    }
}

impl Future for BlockWriteFuture {
    type Output = BlockResult<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if matches!(self.request.state(), RequestState::Pending) {
            if let Err(e) = self.device.submit(self.request.clone()) {
                return Poll::Ready(Err(e));
            }
        }

        self.device.poll_completions();

        match self.request.state() {
            RequestState::Completed => {
                let size = self.request.count as usize * 512;
                Poll::Ready(Ok(size))
            }
            RequestState::Failed(e) => Poll::Ready(Err(e)),
            _ => {
                self.request.register_waker(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

// ============================================================================
// Block Device Manager
// ============================================================================

/// Block device registry entry
struct DeviceEntry {
    /// Device name
    name: &'static str,
    /// Device instance
    device: Arc<dyn BlockDevice>,
}

/// Block device manager
pub struct BlockDeviceManager {
    devices: Mutex<Vec<DeviceEntry>>,
}

impl BlockDeviceManager {
    /// Create a new device manager
    pub const fn new() -> Self {
        Self {
            devices: Mutex::new(Vec::new()),
        }
    }
}

impl Default for BlockDeviceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockDeviceManager {
    /// Register a block device
    pub fn register(&self, name: &'static str, device: Arc<dyn BlockDevice>) {
        self.devices.lock().push(DeviceEntry { name, device });
    }

    /// Get a device by name
    pub fn get(&self, name: &str) -> Option<Arc<dyn BlockDevice>> {
        self.devices
            .lock()
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.device.clone())
    }

    /// List all devices
    pub fn list(&self) -> Vec<&'static str> {
        self.devices.lock().iter().map(|e| e.name).collect()
    }

    /// Remove a device
    pub fn unregister(&self, name: &str) -> Option<Arc<dyn BlockDevice>> {
        let mut devices = self.devices.lock();
        if let Some(pos) = devices.iter().position(|e| e.name == name) {
            Some(devices.remove(pos).device)
        } else {
            None
        }
    }
}

/// Global block device manager
static BLOCK_MANAGER: BlockDeviceManager = BlockDeviceManager::new();

/// Get the block device manager
pub fn block_manager() -> &'static BlockDeviceManager {
    &BLOCK_MANAGER
}

#[cfg(feature = "qemu-test-export")]
#[allow(clippy::must_use_candidate)]
pub mod qemu_tests {
    use super::{
        BlockDevice, BlockDeviceInfo, BlockError, BlockResult, OwnedBytes, RamDisk, ZcFuture,
        ZeroCopyBlockDevice,
    };
    use alloc::boxed::Box;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::future::Future;
    use core::pin::Pin;
    use core::ptr;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use spin::Mutex;

    fn noop_raw_waker() -> RawWaker {
        unsafe fn clone(_: *const ()) -> RawWaker {
            noop_raw_waker()
        }
        unsafe fn wake(_: *const ()) {}
        unsafe fn wake_by_ref(_: *const ()) {}
        unsafe fn drop(_: *const ()) {}
        RawWaker::new(
            ptr::null(),
            &RawWakerVTable::new(clone, wake, wake_by_ref, drop),
        )
    }

    fn run_future<F: Future>(fut: F) -> F::Output {
        let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(fut);
        loop {
            match Pin::new(&mut fut).poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => core::hint::spin_loop(),
            }
        }
    }

    struct MemDev {
        info: BlockDeviceInfo,
        data: Mutex<Vec<u8>>,
        read_calls: AtomicUsize,
        write_calls: AtomicUsize,
        alloc_calls: AtomicUsize,
    }

    impl MemDev {
        fn new(block_size: u32, blocks: usize) -> Self {
            Self {
                info: BlockDeviceInfo {
                    block_size,
                    total_blocks: blocks as u64,
                    ..BlockDeviceInfo::default()
                },
                data: Mutex::new(vec![0u8; block_size as usize * blocks]),
                read_calls: AtomicUsize::new(0),
                write_calls: AtomicUsize::new(0),
                alloc_calls: AtomicUsize::new(0),
            }
        }
    }

    impl ZeroCopyBlockDevice for MemDev {
        type Buffer = OwnedBytes;

        fn info(&self) -> BlockDeviceInfo {
            self.info.clone()
        }

        fn flush(&self) -> BlockResult<()> {
            Ok(())
        }

        fn alloc_buffer(&self, size: usize) -> BlockResult<Self::Buffer> {
            self.alloc_calls.fetch_add(1, Ordering::SeqCst);
            Ok(OwnedBytes::from_vec(vec![0u8; size]))
        }

        fn read_async(&self, block: u64, count: u32) -> ZcFuture<'_, BlockResult<Self::Buffer>> {
            self.read_calls.fetch_add(1, Ordering::SeqCst);

            let bs = self.info.block_size as usize;
            let start = block as usize * bs;
            let len = count as usize * bs;
            let data = {
                let data = self.data.lock();
                if start + len > data.len() {
                    None
                } else {
                    Some(data[start..start + len].to_vec())
                }
            };

            Box::pin(async move {
                match data {
                    Some(bytes) => Ok(OwnedBytes::from_vec(bytes)),
                    None => Err(BlockError::InvalidBlock),
                }
            })
        }

        fn write_async(
            &self,
            block: u64,
            buffer: Self::Buffer,
        ) -> ZcFuture<'_, BlockResult<Self::Buffer>> {
            self.write_calls.fetch_add(1, Ordering::SeqCst);

            let bs = self.info.block_size as usize;
            let start = block as usize * bs;
            let data = &self.data;

            Box::pin(async move {
                let bytes: &[u8] = AsRef::<[u8]>::as_ref(&buffer);
                let len = bytes.len();
                let mut data = data.lock();
                if start + len > data.len() {
                    return Err(BlockError::InvalidBlock);
                }
                data[start..start + len].copy_from_slice(bytes);
                Ok(buffer)
            })
        }
    }

    pub fn ramdisk_read_write_sync_smoke() -> bool {
        let disk = RamDisk::new(16, 512);
        let data = [0xABu8; 512];
        if disk.write_sync(1, &data).ok() != Some(512) {
            return false;
        }

        let mut buf = [0u8; 512];
        disk.read_sync(1, &mut buf).ok() == Some(512) && buf == data
    }

    pub fn ramdisk_read_write_multiple_blocks_smoke() -> bool {
        let disk = RamDisk::new(4, 512);
        let data = [0x12u8; 1024];
        if disk.write_sync(1, &data).ok() != Some(1024) {
            return false;
        }

        let mut buf = [0u8; 1024];
        disk.read_sync(1, &mut buf).ok() == Some(1024) && buf == data
    }

    pub fn read_into_buf_invalid_size_smoke() -> bool {
        let dev = MemDev::new(4, 2);
        let mut dst = OwnedBytes::from_vec(vec![0u8; 6]);

        let err = run_future(dev.read_into_buf(0, &mut dst)).err();
        err == Some(BlockError::InvalidBufferSize) && dev.read_calls.load(Ordering::SeqCst) == 0
    }

    pub fn read_into_buf_default_fallback_smoke() -> bool {
        let dev = MemDev::new(4, 4);
        let expected = [1u8, 2, 3, 4, 5, 6, 7, 8];
        {
            let mut data = dev.data.lock();
            data[..expected.len()].copy_from_slice(&expected);
        }

        let mut dst = OwnedBytes::from_vec(vec![0u8; 8]);
        if run_future(dev.read_into_buf(0, &mut dst)).is_err() {
            return false;
        }

        AsRef::<[u8]>::as_ref(&dst) == expected.as_slice()
            && dev.read_calls.load(Ordering::SeqCst) == 1
    }

    pub fn write_from_buf_default_fallback_smoke() -> bool {
        let dev = MemDev::new(4, 4);
        let src = OwnedBytes::from_vec(vec![9u8, 8, 7, 6, 5, 4, 3, 2]);

        if run_future(dev.write_from_buf(0, &src)).is_err() {
            return false;
        }

        let data = dev.data.lock();
        dev.alloc_calls.load(Ordering::SeqCst) == 1
            && dev.write_calls.load(Ordering::SeqCst) == 1
            && &data[..src.len()] == AsRef::<[u8]>::as_ref(&src)
    }
}

// ============================================================================
// Simple Block Device Adapter
// ============================================================================
//
// シンプルなブロックデバイス（USB MSC、IDE等）からVFS BlockDeviceへの変換

/// シンプルなブロックデバイストレイト
///
/// USB Mass Storage Class、IDE、SATA等のシンプルなブロックデバイス向け。
/// このトレイトを実装することで、`SimpleBlockDeviceAdapter`を通じて
/// VFSの`BlockDevice`として使用可能になる。
pub trait SimpleBlockDevice: Send + Sync {
    /// ブロックサイズを取得
    fn block_size(&self) -> u32;

    /// 総ブロック数を取得
    fn total_blocks(&self) -> u64;

    /// デバイス名を取得
    fn name(&self) -> &'static str {
        "simple_block"
    }

    /// 読み取り専用かどうか
    fn is_read_only(&self) -> bool {
        false
    }

    /// ブロックを読み取り
    ///
    /// # Arguments
    /// * `start_lba` - 開始論理ブロックアドレス
    /// * `count` - 読み取るブロック数
    /// * `buffer` - データを格納するバッファ（サイズは `count * block_size` 以上必要）
    fn read_blocks(&self, start_lba: u64, count: u32, buffer: &mut [u8]) -> BlockResult<()>;

    /// ブロックを書き込み
    ///
    /// # Arguments
    /// * `start_lba` - 開始論理ブロックアドレス
    /// * `count` - 書き込むブロック数
    /// * `buffer` - 書き込むデータ（サイズは `count * block_size` 以上必要）
    fn write_blocks(&self, start_lba: u64, count: u32, buffer: &[u8]) -> BlockResult<()>;

    /// キャッシュをフラッシュ
    fn flush(&self) -> BlockResult<()> {
        Ok(()) // デフォルトは何もしない
    }
}

/// シンプルなブロックデバイスをVFS BlockDeviceに変換するアダプター
pub struct SimpleBlockDeviceAdapter<T: SimpleBlockDevice> {
    /// 内部デバイス
    inner: T,
    /// ペンディングリクエスト
    pending: Mutex<VecDeque<Arc<BlockRequest>>>,
    /// リクエストIDカウンター
    #[allow(dead_code)]
    next_id: AtomicU64,
}

impl<T: SimpleBlockDevice> SimpleBlockDeviceAdapter<T> {
    /// 新しいアダプターを作成
    pub fn new(device: T) -> Self {
        Self {
            inner: device,
            pending: Mutex::new(VecDeque::new()),
            next_id: AtomicU64::new(0),
        }
    }

    /// 内部デバイスへの参照を取得
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// リクエストを処理
    fn process_request(&self, request: &BlockRequest) {
        let block_size = self.inner.block_size() as usize;
        let offset = request.block;
        let count = request.count;

        match request.req_type {
            RequestType::Read => {
                let size = count as usize * block_size;
                let mut buf = alloc::vec![0u8; size];

                match self.inner.read_blocks(offset, count, &mut buf) {
                    Ok(()) => {
                        *request.buffer.lock() = Some(buf);
                        request.set_state(RequestState::Completed);
                    }
                    Err(e) => request.set_state(RequestState::Failed(e)),
                }
            }
            RequestType::Write => {
                let guard = request.buffer.lock();
                if let Some(ref data) = *guard {
                    match self.inner.write_blocks(offset, count, data) {
                        Ok(()) => request.set_state(RequestState::Completed),
                        Err(e) => request.set_state(RequestState::Failed(e)),
                    }
                } else {
                    request.set_state(RequestState::Failed(BlockError::InvalidBufferSize));
                }
            }
            RequestType::Flush => match self.inner.flush() {
                Ok(()) => request.set_state(RequestState::Completed),
                Err(e) => request.set_state(RequestState::Failed(e)),
            },
            RequestType::Discard => {
                // SimpleBlockDevice has no discard primitive; treat as best-effort no-op.
                request.set_state(RequestState::Completed);
            }
        }
    }
}

impl<T: SimpleBlockDevice> BlockDevice for SimpleBlockDeviceAdapter<T> {
    fn info(&self) -> BlockDeviceInfo {
        BlockDeviceInfo {
            name: self.inner.name(),
            total_blocks: self.inner.total_blocks(),
            block_size: self.inner.block_size(),
            read_only: self.inner.is_read_only(),
            max_sectors: 256,
            num_queues: 1,
        }
    }

    fn submit(&self, request: Arc<BlockRequest>) -> BlockResult<()> {
        self.pending.lock().push_back(request);
        Ok(())
    }

    fn poll_completions(&self) -> usize {
        let mut completed = 0;
        let mut pending = self.pending.lock();

        while let Some(request) = pending.pop_front() {
            self.process_request(&request);
            completed += 1;
        }

        completed
    }
}
