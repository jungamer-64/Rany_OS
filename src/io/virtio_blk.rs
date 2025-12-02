// ============================================================================
// src/io/virtio_blk.rs - VirtIO Block Device Driver
// ============================================================================
//!
//! VirtIO-blkドライバ実装
//! 
//! ## 設計原則 (仕様書 7.1準拠)
//! - VirtQueueを用いた非同期ブロックI/O
//! - per-CPUキューによるコンテンション削減
//! - 割り込み/ポーリングハイブリッドモード
//!
//! ## VirtIO Block Device Specification
//! - Feature bits, request format, configuration space
//! - 複数キューサポート (VIRTIO_BLK_F_MQ)

#![allow(dead_code)]

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

// ============================================================================
// VirtIO Common Definitions
// ============================================================================

/// VirtIO device status bits
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioDeviceStatus {
    /// Driver has noticed the device
    Acknowledge = 1,
    /// Driver knows how to drive the device
    Driver = 2,
    /// Driver is set up and ready to drive the device
    DriverOk = 4,
    /// Driver has finished configuring features
    FeaturesOk = 8,
    /// Device has experienced an error from which it can't recover
    DeviceNeedsReset = 64,
    /// Driver has given up on the device
    Failed = 128,
}

/// VirtIO feature bits for block devices
pub mod features {
    /// Maximum size of any single segment is in `size_max`
    pub const VIRTIO_BLK_F_SIZE_MAX: u64 = 1 << 1;
    /// Maximum number of segments in a request is in `seg_max`
    pub const VIRTIO_BLK_F_SEG_MAX: u64 = 1 << 2;
    /// Disk-style geometry specified in `geometry`
    pub const VIRTIO_BLK_F_GEOMETRY: u64 = 1 << 4;
    /// Device is read-only
    pub const VIRTIO_BLK_F_RO: u64 = 1 << 5;
    /// Block size of disk is in `blk_size`
    pub const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;
    /// Device supports request flushing
    pub const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;
    /// Device supports topology information
    pub const VIRTIO_BLK_F_TOPOLOGY: u64 = 1 << 10;
    /// Device supports multiqueue
    pub const VIRTIO_BLK_F_MQ: u64 = 1 << 12;
    /// Device supports discard command
    pub const VIRTIO_BLK_F_DISCARD: u64 = 1 << 13;
    /// Device supports write zeroes command
    pub const VIRTIO_BLK_F_WRITE_ZEROES: u64 = 1 << 14;
}

/// VirtIO block request types
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioBlkReqType {
    /// Read from device
    In = 0,
    /// Write to device
    Out = 1,
    /// Flush data to device
    Flush = 4,
    /// Get device ID
    GetId = 8,
    /// Discard sectors
    Discard = 11,
    /// Write zeroes
    WriteZeroes = 13,
}

/// VirtIO block status codes
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioBlkStatus {
    /// Success
    Ok = 0,
    /// I/O error
    IoErr = 1,
    /// Unsupported request
    Unsupported = 2,
}

// ============================================================================
// VirtQueue Implementation
// ============================================================================

/// Virtqueue descriptor flags
pub mod vring_flags {
    pub const VRING_DESC_F_NEXT: u16 = 1;
    pub const VRING_DESC_F_WRITE: u16 = 2;
    pub const VRING_DESC_F_INDIRECT: u16 = 4;
}

/// Virtqueue descriptor
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VringDesc {
    /// Guest physical address
    pub addr: u64,
    /// Length in bytes
    pub len: u32,
    /// Flags
    pub flags: u16,
    /// Next descriptor index
    pub next: u16,
}

/// Virtqueue available ring
#[repr(C)]
pub struct VringAvail {
    pub flags: u16,
    pub idx: u16,
    // ring: [u16; queue_size] follows
}

/// Used element
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VringUsedElem {
    pub id: u32,
    pub len: u32,
}

/// Virtqueue used ring
#[repr(C)]
pub struct VringUsed {
    pub flags: u16,
    pub idx: u16,
    // ring: [VringUsedElem; queue_size] follows
}

/// Maximum queue size
pub const VIRTQUEUE_MAX_SIZE: u16 = 256;

/// VirtQueue管理構造体
pub struct VirtQueue {
    /// Queue size (must be power of 2)
    queue_size: u16,
    /// Descriptor table base address
    desc_table: *mut VringDesc,
    /// Available ring base address  
    avail_ring: *mut VringAvail,
    /// Used ring base address
    used_ring: *mut VringUsed,
    /// Free descriptor bitmap
    free_bitmap: AtomicU64,
    /// Last seen used index
    last_used_idx: AtomicU32,
    /// Notification address (MMIO)
    notify_addr: *mut u16,
}

unsafe impl Send for VirtQueue {}
unsafe impl Sync for VirtQueue {}

impl VirtQueue {
    /// Initialize a VirtQueue with pre-allocated memory regions
    /// 
    /// # Safety
    /// Caller must ensure:
    /// - Memory regions are valid and properly aligned
    /// - Queue size is power of 2 and <= VIRTQUEUE_MAX_SIZE
    pub unsafe fn new(
        queue_size: u16,
        desc_table: *mut VringDesc,
        avail_ring: *mut VringAvail,
        used_ring: *mut VringUsed,
        notify_addr: *mut u16,
    ) -> Self {
        // Initialize descriptor table
        for i in 0..queue_size {
            (*desc_table.add(i as usize)) = VringDesc::default();
        }
        
        // Initialize available ring
        (*avail_ring).flags = 0;
        (*avail_ring).idx = 0;
        
        // Initialize used ring
        (*used_ring).flags = 0;
        (*used_ring).idx = 0;
        
        Self {
            queue_size,
            desc_table,
            avail_ring,
            used_ring,
            free_bitmap: AtomicU64::new((1u64 << queue_size.min(64)) - 1),
            last_used_idx: AtomicU32::new(0),
            notify_addr,
        }
    }
    
    /// Allocate a descriptor from the free list
    pub fn alloc_desc(&self) -> Option<u16> {
        loop {
            let bitmap = self.free_bitmap.load(Ordering::Acquire);
            if bitmap == 0 {
                return None;
            }
            
            let idx = bitmap.trailing_zeros() as u16;
            let new_bitmap = bitmap & !(1u64 << idx);
            
            if self.free_bitmap.compare_exchange(
                bitmap,
                new_bitmap,
                Ordering::AcqRel,
                Ordering::Acquire,
            ).is_ok() {
                return Some(idx);
            }
        }
    }
    
    /// Free a descriptor back to the free list
    pub fn free_desc(&self, idx: u16) {
        loop {
            let bitmap = self.free_bitmap.load(Ordering::Acquire);
            let new_bitmap = bitmap | (1u64 << idx);
            
            if self.free_bitmap.compare_exchange(
                bitmap,
                new_bitmap,
                Ordering::AcqRel,
                Ordering::Acquire,
            ).is_ok() {
                return;
            }
        }
    }
    
    /// Add a buffer chain to the available ring
    /// 
    /// # Safety
    /// Caller must ensure descriptors are properly set up
    pub unsafe fn submit(&self, head: u16) {
        // Memory barrier before making buffer visible to device
        core::sync::atomic::fence(Ordering::Release);
        
        let avail_idx = (*self.avail_ring).idx;
        let ring_ptr = (self.avail_ring as *mut u16).add(2); // Skip flags and idx
        *ring_ptr.add((avail_idx % self.queue_size) as usize) = head;
        
        // Memory barrier before updating index
        core::sync::atomic::fence(Ordering::Release);
        
        (*self.avail_ring).idx = avail_idx.wrapping_add(1);
        
        // Notify device
        core::ptr::write_volatile(self.notify_addr, 0);
    }
    
    /// Poll for completed requests
    pub fn poll_completions(&self) -> Option<(u16, u32)> {
        let last_used = self.last_used_idx.load(Ordering::Acquire);
        
        // Memory barrier before reading used ring
        core::sync::atomic::fence(Ordering::Acquire);
        
        let used_idx = unsafe { (*self.used_ring).idx } as u32;
        
        if last_used == used_idx {
            return None;
        }
        
        let ring_ptr = unsafe {
            (self.used_ring as *const u8).add(4) as *const VringUsedElem
        };
        let elem = unsafe {
            *ring_ptr.add((last_used % self.queue_size as u32) as usize)
        };
        
        self.last_used_idx.store(last_used.wrapping_add(1), Ordering::Release);
        
        Some((elem.id as u16, elem.len))
    }
}

// ============================================================================
// Block Request Format
// ============================================================================

/// VirtIO block request header
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VirtioBlkReqHeader {
    /// Request type (IN, OUT, FLUSH, etc.)
    pub req_type: u32,
    /// Reserved (for future use)
    pub reserved: u32,
    /// Sector number (512-byte sectors)
    pub sector: u64,
}

/// A block I/O request
pub struct BlockRequest {
    /// Request ID (descriptor index)
    pub id: u16,
    /// Request header
    pub header: VirtioBlkReqHeader,
    /// Data buffer
    pub data: Vec<u8>,
    /// Status byte (filled by device)
    pub status: u8,
}

// ============================================================================
// VirtIO Block Device
// ============================================================================

/// Block device configuration
#[derive(Clone, Debug)]
pub struct BlockDeviceConfig {
    /// Device capacity in 512-byte sectors
    pub capacity: u64,
    /// Block size (usually 512)
    pub block_size: u32,
    /// Maximum segment size
    pub seg_max: u32,
    /// Number of queues
    pub num_queues: u16,
    /// Read-only flag
    pub read_only: bool,
}

impl Default for BlockDeviceConfig {
    fn default() -> Self {
        Self {
            capacity: 0,
            block_size: 512,
            seg_max: 126,
            num_queues: 1,
            read_only: false,
        }
    }
}

/// VirtIO block device driver
pub struct VirtioBlkDevice {
    /// Device configuration
    config: BlockDeviceConfig,
    /// Request queues (one per CPU for multiqueue)
    queues: Vec<Arc<Mutex<VirtQueue>>>,
    /// Pending request wakers
    pending_wakers: Mutex<Vec<Option<Waker>>>,
    /// Device ready flag
    ready: AtomicBool,
    /// MMIO base address
    mmio_base: u64,
    /// Features negotiated
    features: u64,
}

unsafe impl Send for VirtioBlkDevice {}
unsafe impl Sync for VirtioBlkDevice {}

/// Block device error types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockError {
    /// Device not ready
    NotReady,
    /// Device is read-only
    ReadOnly,
    /// Invalid sector address
    InvalidSector,
    /// I/O error from device
    IoError,
    /// Queue full
    QueueFull,
    /// Unsupported operation
    Unsupported,
    /// Invalid buffer size
    InvalidBufferSize,
}

impl VirtioBlkDevice {
    /// Create a new VirtIO block device (uninitialized)
    pub fn new(mmio_base: u64) -> Self {
        Self {
            config: BlockDeviceConfig::default(),
            queues: Vec::new(),
            pending_wakers: Mutex::new(Vec::new()),
            ready: AtomicBool::new(false),
            mmio_base,
            features: 0,
        }
    }
    
    /// Initialize the device
    /// 
    /// # Safety
    /// Caller must ensure MMIO address is valid
    pub unsafe fn init(&mut self) -> Result<(), BlockError> {
        // Step 1: Reset device
        self.write_status(0);
        
        // Step 2: Acknowledge device
        self.write_status(VirtioDeviceStatus::Acknowledge as u8);
        
        // Step 3: Driver loaded
        self.write_status(
            VirtioDeviceStatus::Acknowledge as u8 | 
            VirtioDeviceStatus::Driver as u8
        );
        
        // Step 4: Negotiate features
        let device_features = self.read_device_features();
        let driver_features = device_features & (
            features::VIRTIO_BLK_F_SIZE_MAX |
            features::VIRTIO_BLK_F_SEG_MAX |
            features::VIRTIO_BLK_F_BLK_SIZE |
            features::VIRTIO_BLK_F_FLUSH |
            features::VIRTIO_BLK_F_MQ
        );
        self.write_driver_features(driver_features);
        self.features = driver_features;
        
        // Step 5: Features OK
        self.write_status(
            VirtioDeviceStatus::Acknowledge as u8 |
            VirtioDeviceStatus::Driver as u8 |
            VirtioDeviceStatus::FeaturesOk as u8
        );
        
        // Verify features accepted
        let status = self.read_status();
        if (status & VirtioDeviceStatus::FeaturesOk as u8) == 0 {
            self.write_status(VirtioDeviceStatus::Failed as u8);
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
        
        // Initialize pending wakers
        let mut wakers = self.pending_wakers.lock();
        wakers.resize(VIRTQUEUE_MAX_SIZE as usize * num_queues as usize, None);
        drop(wakers);
        
        // Step 8: Driver OK
        self.write_status(
            VirtioDeviceStatus::Acknowledge as u8 |
            VirtioDeviceStatus::Driver as u8 |
            VirtioDeviceStatus::FeaturesOk as u8 |
            VirtioDeviceStatus::DriverOk as u8
        );
        
        self.ready.store(true, Ordering::Release);
        Ok(())
    }
    
    /// Read device status register
    unsafe fn read_status(&self) -> u8 {
        // MMIO offset 0x70 for status
        let ptr = (self.mmio_base + 0x70) as *const u8;
        core::ptr::read_volatile(ptr)
    }
    
    /// Write device status register
    unsafe fn write_status(&self, status: u8) {
        let ptr = (self.mmio_base + 0x70) as *mut u8;
        core::ptr::write_volatile(ptr, status);
    }
    
    /// Read device features
    unsafe fn read_device_features(&self) -> u64 {
        // MMIO offset 0x10 for device features
        let ptr = (self.mmio_base + 0x10) as *const u32;
        let low = core::ptr::read_volatile(ptr) as u64;
        let high = core::ptr::read_volatile(ptr.add(1)) as u64;
        low | (high << 32)
    }
    
    /// Write driver features
    unsafe fn write_driver_features(&self, features: u64) {
        // MMIO offset 0x20 for driver features
        let ptr = (self.mmio_base + 0x20) as *mut u32;
        core::ptr::write_volatile(ptr, features as u32);
        core::ptr::write_volatile(ptr.add(1), (features >> 32) as u32);
    }
    
    /// Read device configuration
    unsafe fn read_config(&mut self) -> Result<(), BlockError> {
        // Configuration space starts at MMIO offset 0x100
        let config_base = self.mmio_base + 0x100;
        
        // Read capacity (8 bytes at offset 0)
        let capacity_ptr = config_base as *const u64;
        self.config.capacity = core::ptr::read_volatile(capacity_ptr);
        
        // Read block size if feature supported
        if self.features & features::VIRTIO_BLK_F_BLK_SIZE != 0 {
            let blk_size_ptr = (config_base + 0x14) as *const u32;
            self.config.block_size = core::ptr::read_volatile(blk_size_ptr);
        }
        
        // Read num_queues if multiqueue supported
        if self.features & features::VIRTIO_BLK_F_MQ != 0 {
            let mq_ptr = (config_base + 0x22) as *const u16;
            self.config.num_queues = core::ptr::read_volatile(mq_ptr);
        }
        
        // Check read-only
        if self.features & features::VIRTIO_BLK_F_RO != 0 {
            self.config.read_only = true;
        }
        
        Ok(())
    }
    
    /// Setup a virtqueue
    unsafe fn setup_queue(&mut self, queue_idx: u16) -> Result<(), BlockError> {
        // Select queue
        let queue_sel_ptr = (self.mmio_base + 0x30) as *mut u32;
        core::ptr::write_volatile(queue_sel_ptr, queue_idx as u32);
        
        // Read max queue size
        let queue_num_max_ptr = (self.mmio_base + 0x34) as *const u32;
        let max_size = core::ptr::read_volatile(queue_num_max_ptr) as u16;
        
        if max_size == 0 {
            return Err(BlockError::NotReady);
        }
        
        let queue_size = max_size.min(VIRTQUEUE_MAX_SIZE);
        
        // Allocate queue memory (simplified - should use proper allocator)
        // In real implementation, this would allocate physically contiguous memory
        let desc_size = core::mem::size_of::<VringDesc>() * queue_size as usize;
        let avail_size = 6 + 2 * queue_size as usize; // flags + idx + ring + used_event
        let used_size = 6 + 8 * queue_size as usize;  // flags + idx + ring + avail_event
        
        let total_size = desc_size + avail_size + used_size;
        let layout = alloc::alloc::Layout::from_size_align(total_size, 4096)
            .map_err(|_| BlockError::NotReady)?;
        let ptr = alloc::alloc::alloc_zeroed(layout);
        
        if ptr.is_null() {
            return Err(BlockError::NotReady);
        }
        
        let desc_table = ptr as *mut VringDesc;
        let avail_ring = ptr.add(desc_size) as *mut VringAvail;
        let used_ring = ptr.add(desc_size + avail_size) as *mut VringUsed;
        
        // Write queue configuration
        let queue_num_ptr = (self.mmio_base + 0x38) as *mut u32;
        core::ptr::write_volatile(queue_num_ptr, queue_size as u32);
        
        // Write descriptor table address (split into low/high)
        let desc_addr = desc_table as u64;
        let desc_low_ptr = (self.mmio_base + 0x80) as *mut u32;
        let desc_high_ptr = (self.mmio_base + 0x84) as *mut u32;
        core::ptr::write_volatile(desc_low_ptr, desc_addr as u32);
        core::ptr::write_volatile(desc_high_ptr, (desc_addr >> 32) as u32);
        
        // Write available ring address
        let avail_addr = avail_ring as u64;
        let avail_low_ptr = (self.mmio_base + 0x90) as *mut u32;
        let avail_high_ptr = (self.mmio_base + 0x94) as *mut u32;
        core::ptr::write_volatile(avail_low_ptr, avail_addr as u32);
        core::ptr::write_volatile(avail_high_ptr, (avail_addr >> 32) as u32);
        
        // Write used ring address
        let used_addr = used_ring as u64;
        let used_low_ptr = (self.mmio_base + 0xa0) as *mut u32;
        let used_high_ptr = (self.mmio_base + 0xa4) as *mut u32;
        core::ptr::write_volatile(used_low_ptr, used_addr as u32);
        core::ptr::write_volatile(used_high_ptr, (used_addr >> 32) as u32);
        
        // Enable queue
        let queue_ready_ptr = (self.mmio_base + 0x44) as *mut u32;
        core::ptr::write_volatile(queue_ready_ptr, 1);
        
        // Create notify address for this queue
        let notify_addr = (self.mmio_base + 0x50) as *mut u16;
        
        let virtqueue = VirtQueue::new(
            queue_size,
            desc_table,
            avail_ring,
            used_ring,
            notify_addr,
        );
        
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
        }
    }
    
    /// Handle interrupt
    pub fn handle_interrupt(&self) {
        // Process completions on all queues
        for (q_idx, queue) in self.queues.iter().enumerate() {
            let queue_guard = queue.lock();
            while let Some((desc_id, _len)) = queue_guard.poll_completions() {
                // Free descriptor
                queue_guard.free_desc(desc_id);
                
                // Wake pending future
                let waker_idx = q_idx * VIRTQUEUE_MAX_SIZE as usize + desc_id as usize;
                let mut wakers = self.pending_wakers.lock();
                if let Some(waker) = wakers.get_mut(waker_idx).and_then(|w| w.take()) {
                    waker.wake();
                }
            }
        }
        
        // Interrupt-Wakerブリッジに通知（設計書 4.2）
        crate::task::interrupt_waker::wake_from_interrupt(
            crate::task::interrupt_waker::InterruptSource::VirtioBlk(0)
        );
    }
    
    /// Submit a read request (internal)
    fn submit_read(&self, sector: u64, buf_addr: u64, len: u32, queue_idx: usize) -> Result<u16, BlockError> {
        if !self.is_ready() {
            return Err(BlockError::NotReady);
        }
        
        if sector >= self.config.capacity {
            return Err(BlockError::InvalidSector);
        }
        
        let queue = self.queues.get(queue_idx).ok_or(BlockError::NotReady)?;
        let queue_guard = queue.lock();
        
        // Allocate 3 descriptors: header, data, status
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
        
        // Setup header (device reads)
        let header = VirtioBlkReqHeader {
            req_type: VirtioBlkReqType::In as u32,
            reserved: 0,
            sector,
        };
        
        // In real implementation, header and status would be in separate allocations
        // For now, we use buf_addr directly with proper offset calculations
        
        unsafe {
            let desc_table = queue_guard.desc_table;
            
            // Descriptor 0: Header (device reads)
            (*desc_table.add(desc0 as usize)) = VringDesc {
                addr: &header as *const _ as u64,
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
            
            // Descriptor 2: Status (device writes)
            (*desc_table.add(desc2 as usize)) = VringDesc {
                addr: 0, // Status byte location
                len: 1,
                flags: vring_flags::VRING_DESC_F_WRITE,
                next: 0,
            };
            
            // Submit to available ring
            queue_guard.submit(desc0);
        }
        
        Ok(desc0)
    }
    
    /// Submit a write request (internal)
    fn submit_write(&self, sector: u64, buf_addr: u64, len: u32, queue_idx: usize) -> Result<u16, BlockError> {
        if !self.is_ready() {
            return Err(BlockError::NotReady);
        }
        
        if self.config.read_only {
            return Err(BlockError::ReadOnly);
        }
        
        if sector >= self.config.capacity {
            return Err(BlockError::InvalidSector);
        }
        
        let queue = self.queues.get(queue_idx).ok_or(BlockError::NotReady)?;
        let queue_guard = queue.lock();
        
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
        
        let header = VirtioBlkReqHeader {
            req_type: VirtioBlkReqType::Out as u32,
            reserved: 0,
            sector,
        };
        
        unsafe {
            let desc_table = queue_guard.desc_table;
            
            // Descriptor 0: Header
            (*desc_table.add(desc0 as usize)) = VringDesc {
                addr: &header as *const _ as u64,
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
            
            // Descriptor 2: Status
            (*desc_table.add(desc2 as usize)) = VringDesc {
                addr: 0,
                len: 1,
                flags: vring_flags::VRING_DESC_F_WRITE,
                next: 0,
            };
            
            queue_guard.submit(desc0);
        }
        
        Ok(desc0)
    }
}

// ============================================================================
// Async Futures
// ============================================================================

/// Future for async read operation
pub struct ReadFuture<'a> {
    device: &'a VirtioBlkDevice,
    sector: u64,
    buf: &'a mut [u8],
    submitted: bool,
    desc_id: Option<u16>,
    queue_idx: usize,
}

impl<'a> Future for ReadFuture<'a> {
    type Output = Result<usize, BlockError>;
    
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.submitted {
            // Validate buffer size
            if self.buf.len() % 512 != 0 {
                return Poll::Ready(Err(BlockError::InvalidBufferSize));
            }
            
            // Submit request
            let buf_addr = self.buf.as_ptr() as u64;
            let len = self.buf.len() as u32;
            
            match self.device.submit_read(self.sector, buf_addr, len, self.queue_idx) {
                Ok(desc_id) => {
                    self.desc_id = Some(desc_id);
                    self.submitted = true;
                    
                    // Register waker
                    let waker_idx = self.queue_idx * VIRTQUEUE_MAX_SIZE as usize + desc_id as usize;
                    let mut wakers = self.device.pending_wakers.lock();
                    if let Some(slot) = wakers.get_mut(waker_idx) {
                        *slot = Some(cx.waker().clone());
                    }
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        
        // Check for completion
        if let Some(desc_id) = self.desc_id {
            let queue = &self.device.queues[self.queue_idx];
            let queue_guard = queue.lock();
            
            // Poll for our specific completion
            if let Some((completed_id, _len)) = queue_guard.poll_completions() {
                if completed_id == desc_id {
                    return Poll::Ready(Ok(self.buf.len()));
                }
            }
        }
        
        // Re-register waker
        if let Some(desc_id) = self.desc_id {
            let waker_idx = self.queue_idx * VIRTQUEUE_MAX_SIZE as usize + desc_id as usize;
            let mut wakers = self.device.pending_wakers.lock();
            if let Some(slot) = wakers.get_mut(waker_idx) {
                *slot = Some(cx.waker().clone());
            }
        }
        
        Poll::Pending
    }
}

/// Future for async write operation
pub struct WriteFuture<'a> {
    device: &'a VirtioBlkDevice,
    sector: u64,
    buf: &'a [u8],
    submitted: bool,
    desc_id: Option<u16>,
    queue_idx: usize,
}

impl<'a> Future for WriteFuture<'a> {
    type Output = Result<usize, BlockError>;
    
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.submitted {
            if self.buf.len() % 512 != 0 {
                return Poll::Ready(Err(BlockError::InvalidBufferSize));
            }
            
            let buf_addr = self.buf.as_ptr() as u64;
            let len = self.buf.len() as u32;
            
            match self.device.submit_write(self.sector, buf_addr, len, self.queue_idx) {
                Ok(desc_id) => {
                    self.desc_id = Some(desc_id);
                    self.submitted = true;
                    
                    let waker_idx = self.queue_idx * VIRTQUEUE_MAX_SIZE as usize + desc_id as usize;
                    let mut wakers = self.device.pending_wakers.lock();
                    if let Some(slot) = wakers.get_mut(waker_idx) {
                        *slot = Some(cx.waker().clone());
                    }
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        
        if let Some(desc_id) = self.desc_id {
            let queue = &self.device.queues[self.queue_idx];
            let queue_guard = queue.lock();
            
            if let Some((completed_id, _len)) = queue_guard.poll_completions() {
                if completed_id == desc_id {
                    return Poll::Ready(Ok(self.buf.len()));
                }
            }
        }
        
        if let Some(desc_id) = self.desc_id {
            let waker_idx = self.queue_idx * VIRTQUEUE_MAX_SIZE as usize + desc_id as usize;
            let mut wakers = self.device.pending_wakers.lock();
            if let Some(slot) = wakers.get_mut(waker_idx) {
                *slot = Some(cx.waker().clone());
            }
        }
        
        Poll::Pending
    }
}

/// Future for async flush operation
pub struct FlushFuture<'a> {
    device: &'a VirtioBlkDevice,
    submitted: bool,
    desc_id: Option<u16>,
}

impl<'a> Future for FlushFuture<'a> {
    type Output = Result<(), BlockError>;
    
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.submitted {
            if self.device.features & features::VIRTIO_BLK_F_FLUSH == 0 {
                return Poll::Ready(Err(BlockError::Unsupported));
            }
            
            // Submit flush request (simplified)
            self.submitted = true;
            // TODO: Actual flush submission
        }
        
        // For now, flush completes immediately
        Poll::Ready(Ok(()))
    }
}

// ============================================================================
// Block Device Trait
// ============================================================================

/// Generic block device trait for async I/O
pub trait AsyncBlockDevice: Send + Sync {
    /// Read sectors into buffer
    fn read<'a>(&'a self, sector: u64, buf: &'a mut [u8]) -> Pin<Box<dyn Future<Output = Result<usize, BlockError>> + Send + 'a>>;
    
    /// Write buffer to sectors
    fn write<'a>(&'a self, sector: u64, buf: &'a [u8]) -> Pin<Box<dyn Future<Output = Result<usize, BlockError>> + Send + 'a>>;
    
    /// Flush pending writes
    fn flush<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<(), BlockError>> + Send + 'a>>;
    
    /// Get device capacity in sectors
    fn capacity(&self) -> u64;
    
    /// Get sector size
    fn sector_size(&self) -> u32;
}

// ============================================================================
// Global Device Instance
// ============================================================================

/// Global VirtIO block device instance
static VIRTIO_BLK_DEVICE: Mutex<Option<VirtioBlkDevice>> = Mutex::new(None);

/// Initialize the global VirtIO block device
/// 
/// # Safety
/// Caller must ensure MMIO address is valid and device exists
pub unsafe fn init_virtio_blk(mmio_base: u64) -> Result<(), BlockError> {
    let mut device = VirtioBlkDevice::new(mmio_base);
    device.init()?;
    
    crate::log!("VirtIO-blk initialized: {} sectors, {} bytes/sector\n",
        device.config().capacity,
        device.config().block_size
    );
    
    *VIRTIO_BLK_DEVICE.lock() = Some(device);
    Ok(())
}

/// Handle VirtIO block device interrupt
pub fn handle_virtio_blk_interrupt() {
    if let Some(device) = VIRTIO_BLK_DEVICE.lock().as_ref() {
        device.handle_interrupt();
    }
}

/// Synchronous read from global device
/// 
/// Note: For a proper async implementation, you would need to use
/// Arc<VirtioBlkDevice> to allow the future to outlive the lock.
pub fn blk_read_sync(sector: u64, buf: &mut [u8]) -> Result<usize, BlockError> {
    let device_guard = VIRTIO_BLK_DEVICE.lock();
    let _device = device_guard.as_ref().ok_or(BlockError::NotReady)?;
    
    // Placeholder: In production, this would submit the request and poll for completion
    // For now, just verify parameters
    if buf.is_empty() {
        return Err(BlockError::InvalidBufferSize);
    }
    
    // Would need to implement polling-based read here
    Err(BlockError::NotReady)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_virtio_blk_req_type() {
        assert_eq!(VirtioBlkReqType::In as u32, 0);
        assert_eq!(VirtioBlkReqType::Out as u32, 1);
        assert_eq!(VirtioBlkReqType::Flush as u32, 4);
    }
    
    #[test]
    fn test_block_device_config_default() {
        let config = BlockDeviceConfig::default();
        assert_eq!(config.capacity, 0);
        assert_eq!(config.block_size, 512);
        assert!(!config.read_only);
    }
}
