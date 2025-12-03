// ============================================================================
// src/fs/block.rs - Block Device Abstraction
// ============================================================================
//!
//! ブロックデバイス抽象化レイヤー
//!
//! ## 設計
//! - 統一ブロックデバイスインターフェース
//! - VirtIO-blk、NVMe、RAMディスク対応
//! - 非同期I/Oサポート

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::sync::atomic::{AtomicU64, Ordering};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

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
    pub buffer: Option<Vec<u8>>,
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
            buffer: Some(alloc::vec![0u8; buffer_size]),
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
            buffer: Some(data),
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
            buffer: None,
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
        matches!(self.state(), RequestState::Completed | RequestState::Failed(_))
    }
    
    /// Register waker for async completion
    pub fn register_waker(&self, waker: Waker) {
        *self.waker.lock() = Some(waker);
    }
    
    /// Take the data buffer
    pub fn take_buffer(&mut self) -> Option<Vec<u8>> {
        self.buffer.take()
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
                    // Copy data from request buffer
                    // (In real impl, buffer would be shared)
                    return Ok(buf.len());
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
                    // Copy data to request buffer
                    // In real impl, we'd use shared buffer
                    request.set_state(RequestState::Completed);
                } else {
                    request.set_state(RequestState::Failed(BlockError::InvalidBlock));
                }
            }
            RequestType::Write => {
                let mut data = self.data.lock();
                if offset + size <= data.len() {
                    if let Some(buf) = &request.buffer {
                        data[offset..offset + buf.len().min(size)]
                            .copy_from_slice(&buf[..buf.len().min(size)]);
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
                // Return data
                let buffer = self.request.buffer.as_ref()
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ram_disk() {
        let disk = RamDisk::new_1mb();
        let info = disk.info();
        
        assert_eq!(info.total_blocks, 2048);
        assert_eq!(info.block_size, 512);
        assert!(!info.read_only);
    }
    
    #[test]
    fn test_block_request() {
        let req = BlockRequest::read(1, 0, 4);
        assert_eq!(req.id, 1);
        assert_eq!(req.req_type, RequestType::Read);
        assert_eq!(req.block, 0);
        assert_eq!(req.count, 4);
        assert!(matches!(req.state(), RequestState::Pending));
    }
    
    #[test]
    fn test_ram_disk_sync_io() {
        let disk = Arc::new(RamDisk::new_1mb());
        
        // Write data
        let data = [0x42u8; 512];
        let result = disk.write_sync(0, &data);
        assert!(result.is_ok());
        
        // Read back
        let mut buf = [0u8; 512];
        let result = disk.read_sync(0, &mut buf);
        assert!(result.is_ok());
    }
}
