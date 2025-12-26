// ============================================================================
// src/io/virtio/blk.rs - VirtIO Block Device Driver
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

use crate::io::iommu::{is_iommu_enabled, map_for_dma, unmap_dma};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;
use vfs::block::{
    BlockDeviceInfo as VfsBlockDeviceInfo, BlockError as VfsBlockError,
    BlockResult as VfsBlockResult, IoBuffer, IoBufferMut, OwnedBytes, ZcFuture,
    ZeroCopyBlockDevice,
};
use x86_64::PhysAddr;

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
    #[deprecated(
        note = "notify_addr is deprecated; prefer using transport-level notify configuration or `notify` methods; this field will be removed in a future release."
    )]
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
            unsafe {
                (*desc_table.add(i as usize)) = VringDesc::default();
            }
        }

        // Initialize available ring
        unsafe {
            (*avail_ring).flags = 0;
            (*avail_ring).idx = 0;
        }

        // Initialize used ring
        unsafe {
            (*used_ring).flags = 0;
            (*used_ring).idx = 0;
        }

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

            if self
                .free_bitmap
                .compare_exchange(bitmap, new_bitmap, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(idx);
            }
        }
    }

    /// Free a descriptor back to the free list
    pub fn free_desc(&self, idx: u16) {
        loop {
            let bitmap = self.free_bitmap.load(Ordering::Acquire);
            let new_bitmap = bitmap | (1u64 << idx);

            if self
                .free_bitmap
                .compare_exchange(bitmap, new_bitmap, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
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

        let avail_idx = unsafe { (*self.avail_ring).idx };
        let ring_ptr = unsafe { (self.avail_ring as *mut u16).add(2) }; // Skip flags and idx
        unsafe {
            *ring_ptr.add((avail_idx % self.queue_size) as usize) = head;
        }

        // Memory barrier before updating index
        core::sync::atomic::fence(Ordering::Release);

        unsafe {
            (*self.avail_ring).idx = avail_idx.wrapping_add(1);
        }

        // Notify device via MMIO write to notification register
        crate::io::mmio_write_u16(self.notify_addr as usize, 0);
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

        let ring_ptr = unsafe { (self.used_ring as *const u8).add(4) as *const VringUsedElem };
        let elem = unsafe { *ring_ptr.add((last_used % self.queue_size as u32) as usize) };

        self.last_used_idx
            .store(last_used.wrapping_add(1), Ordering::Release);

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
        unsafe {
            self.write_status(0);
        }

        // Step 2: Acknowledge device
        unsafe {
            self.write_status(VirtioDeviceStatus::Acknowledge as u8);
        }

        // Step 3: Driver loaded
        unsafe {
            self.write_status(
                VirtioDeviceStatus::Acknowledge as u8 | VirtioDeviceStatus::Driver as u8,
            );
        }

        // Step 4: Negotiate features
        let device_features = unsafe { self.read_device_features() };
        let driver_features = device_features
            & (features::VIRTIO_BLK_F_SIZE_MAX
                | features::VIRTIO_BLK_F_SEG_MAX
                | features::VIRTIO_BLK_F_BLK_SIZE
                | features::VIRTIO_BLK_F_FLUSH
                | features::VIRTIO_BLK_F_MQ);
        unsafe {
            self.write_driver_features(driver_features);
        }
        self.features = driver_features;

        // Step 5: Features OK
        unsafe {
            self.write_status(
                VirtioDeviceStatus::Acknowledge as u8
                    | VirtioDeviceStatus::Driver as u8
                    | VirtioDeviceStatus::FeaturesOk as u8,
            );
        }

        // Verify features accepted
        let status = unsafe { self.read_status() };
        if (status & VirtioDeviceStatus::FeaturesOk as u8) == 0 {
            unsafe {
                self.write_status(VirtioDeviceStatus::Failed as u8);
            }
            return Err(BlockError::NotReady);
        }

        // Step 6: Read configuration
        unsafe { self.read_config()? };

        // Step 7: Setup queues
        let num_queues = if self.features & features::VIRTIO_BLK_F_MQ != 0 {
            self.config.num_queues
        } else {
            1
        };

        for i in 0..num_queues {
            unsafe {
                self.setup_queue(i)?;
            }
        }

        // Initialize pending wakers
        let mut wakers = self.pending_wakers.lock();
        wakers.resize(VIRTQUEUE_MAX_SIZE as usize * num_queues as usize, None);
        drop(wakers);

        // Step 8: Driver OK
        unsafe {
            self.write_status(
                VirtioDeviceStatus::Acknowledge as u8
                    | VirtioDeviceStatus::Driver as u8
                    | VirtioDeviceStatus::FeaturesOk as u8
                    | VirtioDeviceStatus::DriverOk as u8,
            );
        }

        self.ready.store(true, Ordering::Release);
        Ok(())
    }

    /// Read device status register
    unsafe fn read_status(&self) -> u8 {
        // MMIO offset 0x70 for status
        let ptr = (self.mmio_base + 0x70) as *const u8;
        crate::io::mmio_read_u8((self.mmio_base + 0x70) as usize)
    }

    /// Write device status register
    unsafe fn write_status(&self, status: u8) {
        let ptr = (self.mmio_base + 0x70) as *mut u8;
        crate::io::mmio_write_u8((self.mmio_base + 0x70) as usize, status);
    }

    /// Read device features
    unsafe fn read_device_features(&self) -> u64 {
        // MMIO offset 0x10 for device features
        let low = crate::io::mmio_read_u32((self.mmio_base + 0x10) as usize) as u64;
        let high = crate::io::mmio_read_u32((self.mmio_base + 0x10 + 4) as usize) as u64;
        low | (high << 32)
    }

    /// Write driver features
    unsafe fn write_driver_features(&self, features: u64) {
        // MMIO offset 0x20 for driver features
        crate::io::mmio_write_u32((self.mmio_base + 0x20) as usize, features as u32);
        crate::io::mmio_write_u32(
            (self.mmio_base + 0x20 + 4) as usize,
            (features >> 32) as u32,
        );
    }

    /// Read device configuration
    unsafe fn read_config(&mut self) -> Result<(), BlockError> {
        // Configuration space starts at MMIO offset 0x100
        let config_base = self.mmio_base + 0x100;

        // Read capacity (8 bytes at offset 0)
        self.config.capacity = crate::io::mmio_read_u64(config_base as usize);

        // Read block size if feature supported
        if self.features & features::VIRTIO_BLK_F_BLK_SIZE != 0 {
            // Block size (u32) at offset 0x14
            self.config.block_size = crate::io::mmio::mmio_read_u32((config_base + 0x14) as usize);
        }

        // Read num_queues if multiqueue supported
        if self.features & features::VIRTIO_BLK_F_MQ != 0 {
            // Number of queues (u16) at offset 0x22
            self.config.num_queues = crate::io::mmio::mmio_read_u16((config_base + 0x22) as usize);
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
        // Select queue
        crate::io::mmio::mmio_write_u32((self.mmio_base + 0x30) as usize, queue_idx as u32);

        // Read max queue size
        // Read max queue size
        let max_size = crate::io::mmio::mmio_read_u32((self.mmio_base + 0x34) as usize) as u16;

        if max_size == 0 {
            return Err(BlockError::NotReady);
        }

        let queue_size = max_size.min(VIRTQUEUE_MAX_SIZE);

        // Allocate queue memory (simplified - should use proper allocator)
        // In real implementation, this would allocate physically contiguous memory
        let desc_size = core::mem::size_of::<VringDesc>() * queue_size as usize;
        let avail_size = 6 + 2 * queue_size as usize; // flags + idx + ring + used_event
        let used_size = 6 + 8 * queue_size as usize; // flags + idx + ring + avail_event

        let total_size = desc_size + avail_size + used_size;
        let layout = alloc::alloc::Layout::from_size_align(total_size, 4096)
            .map_err(|_| BlockError::NotReady)?;
        let ptr_nn = crate::util::allocate_zeroed(layout).ok_or(BlockError::NotReady)?;
        let ptr = ptr_nn.as_ptr();

        let desc_table = ptr as *mut VringDesc;
        let avail_ring = unsafe { ptr.add(desc_size) as *mut VringAvail };
        let used_ring = unsafe { ptr.add(desc_size + avail_size) as *mut VringUsed };

        // Write queue configuration
        // Write queue size
        crate::io::mmio::mmio_write_u32((self.mmio_base + 0x38) as usize, queue_size as u32);

        // Write descriptor table address (split into low/high)
        let desc_addr = desc_table as u64;
        let desc_low_addr = (self.mmio_base + 0x80) as usize;
        let desc_high_addr = (self.mmio_base + 0x84) as usize;
        crate::io::mmio::mmio_write_u32(desc_low_addr, desc_addr as u32);
        crate::io::mmio::mmio_write_u32(desc_high_addr, (desc_addr >> 32) as u32);

        // Write available ring address
        let avail_addr = avail_ring as u64;
        let avail_low_addr = (self.mmio_base + 0x90) as usize;
        let avail_high_addr = (self.mmio_base + 0x94) as usize;
        crate::io::mmio::mmio_write_u32(avail_low_addr, avail_addr as u32);
        crate::io::mmio::mmio_write_u32(avail_high_addr, (avail_addr >> 32) as u32);

        // Write used ring address
        let used_addr = used_ring as u64;
        let used_low_addr = (self.mmio_base + 0xa0) as usize;
        let used_high_addr = (self.mmio_base + 0xa4) as usize;
        crate::io::mmio::mmio_write_u32(used_low_addr, used_addr as u32);
        crate::io::mmio::mmio_write_u32(used_high_addr, (used_addr >> 32) as u32);

        // Enable queue
        crate::io::mmio::mmio_write_u32((self.mmio_base + 0x44) as usize, 1);

        // Create notify address for this queue
        let notify_addr = (self.mmio_base + 0x50) as *mut u16;

        let virtqueue =
            unsafe { VirtQueue::new(queue_size, desc_table, avail_ring, used_ring, notify_addr) };

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
            queue_idx: 0,
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
            crate::task::interrupt_waker::InterruptSource::VirtioBlk(0),
        );
    }

    /// Submit a read request (internal)
    fn submit_read(
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
            unsafe {
                queue_guard.submit(desc0);
            }
        }

        Ok(desc0)
    }

    /// Submit a write request (internal)
    fn submit_write(
        &self,
        sector: u64,
        buf_addr: u64,
        len: u32,
        queue_idx: usize,
    ) -> Result<u16, BlockError> {
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

    /// Submit a flush request (internal)
    fn submit_flush(&self, queue_idx: usize) -> Result<u16, BlockError> {
        if !self.is_ready() {
            return Err(BlockError::NotReady);
        }

        // Check if flush is supported
        if self.features & features::VIRTIO_BLK_F_FLUSH == 0 {
            return Err(BlockError::Unsupported);
        }

        let queue = self.queues.get(queue_idx).ok_or(BlockError::NotReady)?;
        let queue_guard = queue.lock();

        // Flush only requires 2 descriptors: header and status (no data)
        let desc0 = queue_guard.alloc_desc().ok_or(BlockError::QueueFull)?;
        let desc1 = queue_guard.alloc_desc().ok_or_else(|| {
            queue_guard.free_desc(desc0);
            BlockError::QueueFull
        })?;

        let header = VirtioBlkReqHeader {
            req_type: VirtioBlkReqType::Flush as u32,
            reserved: 0,
            sector: 0, // sector is ignored for flush
        };

        unsafe {
            let desc_table = queue_guard.desc_table;

            // Descriptor 0: Header (device reads)
            (*desc_table.add(desc0 as usize)) = VringDesc {
                addr: &header as *const _ as u64,
                len: core::mem::size_of::<VirtioBlkReqHeader>() as u32,
                flags: vring_flags::VRING_DESC_F_NEXT,
                next: desc1,
            };

            // Descriptor 1: Status (device writes)
            (*desc_table.add(desc1 as usize)) = VringDesc {
                addr: 0, // Status byte location
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

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::sync::atomic::Ordering;
    use alloc::vec::Vec;

    use super::*;
    use crate::mm::{alloc_contiguous_frames, dealloc_contiguous_frames, PAGE_SIZE_4K};
    use crate::fs::page_cluster_buffer::PageClusterBuffer;
    use x86_64::PhysAddr;

    #[test]
    fn test_submit_read_uses_dma_addr() {
        // Setup small virtqueue memory regions
        let queue_size: u16 = 8;
        let mut descs = vec![VringDesc::default(); queue_size as usize];
        let desc_ptr = descs.as_mut_ptr();

        let mut avail = vec![0u16; 2 + queue_size as usize];
        let avail_ptr = avail.as_mut_ptr() as *mut VringAvail;

        let used_bytes = core::mem::size_of::<VringUsed>() + (queue_size as usize) * core::mem::size_of::<VringUsedElem>();
        let mut used_mem = vec![0u8; used_bytes];
        let used_ptr = used_mem.as_mut_ptr() as *mut VringUsed;

        let mut notify = Box::new(0u16);
        let notify_ptr: *mut u16 = &mut *notify;

        let vq = unsafe { VirtQueue::new(queue_size, desc_ptr, avail_ptr, used_ptr, notify_ptr) };

        let mut dev = VirtioBlkDevice::new(0);
        dev.queues.push(Arc::new(spin::Mutex::new(vq)));
        dev.ready.store(true, Ordering::Release);
        dev.config.capacity = 1024;

        // Initialize wakers vector
        let mut w = dev.pending_wakers.lock();
        w.resize(VIRTQUEUE_MAX_SIZE as usize * dev.queues.len(), None);
        drop(w);

        // Skip test if contiguous frames unavailable
        let frames_needed = 1usize;
        if let Some(start_phys) = alloc_contiguous_frames(frames_needed) {
            let real_size = PAGE_SIZE_4K as usize;
            let buf = PageClusterBuffer::new_from_phys(start_phys.as_u64(), real_size).expect("new_from_phys failed");
            let dma = buf.dma_info().expect("dma_info missing");

            let head = dev.submit_read(0, dma.phys_addr, 512u32, 0).expect("submit_read failed");

            // Inspect descriptor chain: header -> data -> status
            let header_desc = unsafe { *desc_ptr.add(head as usize) };
            let data_idx = header_desc.next as usize;
            let data_desc = unsafe { *desc_ptr.add(data_idx) };

            assert_eq!(data_desc.addr, dma.phys_addr);
            assert_eq!(data_desc.len, 512u32);
            assert!((data_desc.flags & vring_flags::VRING_DESC_F_WRITE) != 0);

            // Clean up allocated frames
            dealloc_contiguous_frames(PhysAddr::new(start_phys.as_u64()), frames_needed);
        } else {
            eprintln!("Skipping test: contiguous frames not available");
        }
    }

    #[test]
    fn test_submit_write_uses_dma_addr() {
        // Setup small virtqueue memory regions
        let queue_size: u16 = 8;
        let mut descs = vec![VringDesc::default(); queue_size as usize];
        let desc_ptr = descs.as_mut_ptr();

        let mut avail = vec![0u16; 2 + queue_size as usize];
        let avail_ptr = avail.as_mut_ptr() as *mut VringAvail;

        let used_bytes = core::mem::size_of::<VringUsed>() + (queue_size as usize) * core::mem::size_of::<VringUsedElem>();
        let mut used_mem = vec![0u8; used_bytes];
        let used_ptr = used_mem.as_mut_ptr() as *mut VringUsed;

        let mut notify = Box::new(0u16);
        let notify_ptr: *mut u16 = &mut *notify;

        let vq = unsafe { VirtQueue::new(queue_size, desc_ptr, avail_ptr, used_ptr, notify_ptr) };

        let mut dev = VirtioBlkDevice::new(0);
        dev.queues.push(Arc::new(spin::Mutex::new(vq)));
        dev.ready.store(true, Ordering::Release);
        dev.config.capacity = 1024;

        // Initialize wakers vector
        let mut w = dev.pending_wakers.lock();
        w.resize(VIRTQUEUE_MAX_SIZE as usize * dev.queues.len(), None);
        drop(w);

        // Skip test if contiguous frames unavailable
        let frames_needed = 1usize;
        if let Some(start_phys) = alloc_contiguous_frames(frames_needed) {
            let real_size = PAGE_SIZE_4K as usize;
            let buf = PageClusterBuffer::new_from_phys(start_phys.as_u64(), real_size).expect("new_from_phys failed");
            let dma = buf.dma_info().expect("dma_info missing");

            let head = dev.submit_write(0, dma.phys_addr, 512u32, 0).expect("submit_write failed");

            // Inspect descriptor chain: header -> data -> status
            let header_desc = unsafe { *desc_ptr.add(head as usize) };
            let data_idx = header_desc.next as usize;
            let data_desc = unsafe { *desc_ptr.add(data_idx) };

            assert_eq!(data_desc.addr, dma.phys_addr);
            assert_eq!(data_desc.len, 512u32);
            // For write, device reads from buffer (no VRING_DESC_F_WRITE flag)
            assert_eq!(data_desc.flags & vring_flags::VRING_DESC_F_WRITE, 0);

            // Clean up allocated frames
            dealloc_contiguous_frames(PhysAddr::new(start_phys.as_u64()), frames_needed);
        } else {
            eprintln!("Skipping test: contiguous frames not available");
        }
    }
}

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

            match self
                .device
                .submit_read(self.sector, buf_addr, len, self.queue_idx)
            {
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

            match self
                .device
                .submit_write(self.sector, buf_addr, len, self.queue_idx)
            {
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

/// Future for async DMA read operation (uses physical address).
pub struct DmaReadFuture<'a> {
    device: &'a VirtioBlkDevice,
    sector: u64,
    dma_addr: u64,
    buf: &'a mut [u8],
    submitted: bool,
    desc_id: Option<u16>,
    queue_idx: usize,
}

impl<'a> Future for DmaReadFuture<'a> {
    type Output = Result<usize, BlockError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.submitted {
            if self.buf.len() % 512 != 0 {
                return Poll::Ready(Err(BlockError::InvalidBufferSize));
            }
            if self.buf.len() > (u32::MAX as usize) {
                return Poll::Ready(Err(BlockError::InvalidBufferSize));
            }

            let len = self.buf.len() as u32;
            match self
                .device
                .submit_read(self.sector, self.dma_addr, len, self.queue_idx)
            {
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

/// Future for async DMA write operation (uses physical address).
pub struct DmaWriteFuture<'a> {
    device: &'a VirtioBlkDevice,
    sector: u64,
    dma_addr: u64,
    buf: &'a [u8],
    submitted: bool,
    desc_id: Option<u16>,
    queue_idx: usize,
}

impl<'a> Future for DmaWriteFuture<'a> {
    type Output = Result<usize, BlockError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.submitted {
            if self.buf.len() % 512 != 0 {
                return Poll::Ready(Err(BlockError::InvalidBufferSize));
            }
            if self.buf.len() > (u32::MAX as usize) {
                return Poll::Ready(Err(BlockError::InvalidBufferSize));
            }

            let len = self.buf.len() as u32;
            match self
                .device
                .submit_write(self.sector, self.dma_addr, len, self.queue_idx)
            {
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
    queue_idx: usize,
}

impl<'a> Future for FlushFuture<'a> {
    type Output = Result<(), BlockError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.submitted {
            // Check if flush is supported
            if self.device.features & features::VIRTIO_BLK_F_FLUSH == 0 {
                return Poll::Ready(Err(BlockError::Unsupported));
            }

            // Submit flush request using submit_flush
            match self.device.submit_flush(self.queue_idx) {
                Ok(desc_id) => {
                    self.desc_id = Some(desc_id);
                    self.submitted = true;

                    // Register waker for completion notification
                    let waker_idx = self.queue_idx * VIRTQUEUE_MAX_SIZE as usize + desc_id as usize;
                    let mut wakers = self.device.pending_wakers.lock();
                    if let Some(slot) = wakers.get_mut(waker_idx) {
                        *slot = Some(cx.waker().clone());
                    }
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        // Poll for completion
        if let Some(desc_id) = self.desc_id {
            let queue = &self.device.queues[self.queue_idx];
            let queue_guard = queue.lock();

            if let Some((completed_id, _len)) = queue_guard.poll_completions() {
                if completed_id == desc_id {
                    // Flush completed successfully
                    return Poll::Ready(Ok(()));
                }
            }
        }

        // Re-register waker for next poll
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

const SECTOR_SIZE: u32 = 512;

fn map_vfs_block_error(err: BlockError) -> VfsBlockError {
    match err {
        BlockError::NotReady => VfsBlockError::NotReady,
        BlockError::ReadOnly => VfsBlockError::ReadOnly,
        BlockError::InvalidSector => VfsBlockError::InvalidBlock,
        BlockError::IoError | BlockError::Unsupported => VfsBlockError::IoError,
        BlockError::QueueFull => VfsBlockError::QueueFull,
        BlockError::InvalidBufferSize => VfsBlockError::InvalidBufferSize,
    }
}

fn effective_block_size(config: &BlockDeviceConfig) -> u32 {
    let bs = config.block_size;
    if bs == 0 || (bs % SECTOR_SIZE) != 0 {
        SECTOR_SIZE
    } else {
        bs
    }
}

fn block_to_sector(block: u64, block_size: u32) -> Result<u64, VfsBlockError> {
    if block_size == 0 || (block_size % SECTOR_SIZE) != 0 {
        return Err(VfsBlockError::InvalidBufferSize);
    }
    let sectors_per_block = (block_size / SECTOR_SIZE) as u64;
    block
        .checked_mul(sectors_per_block)
        .ok_or(VfsBlockError::InvalidBufferSize)
}

fn map_dma_addr(phys_addr: u64, len: usize) -> Result<Option<u64>, VfsBlockError> {
    if !is_iommu_enabled() {
        return Ok(None);
    }
    // SAFETY: caller guarantees phys_addr is owned and valid for DMA for len bytes.
    unsafe { map_for_dma(PhysAddr::new(phys_addr), len as u64) }
        .map(Some)
        .map_err(|_| VfsBlockError::IoError)
}

impl ZeroCopyBlockDevice for VirtioBlkDevice {
    type Buffer = OwnedBytes;

    fn info(&self) -> VfsBlockDeviceInfo {
        let block_size = effective_block_size(&self.config);
        let sectors_per_block = (block_size / SECTOR_SIZE) as u64;
        let total_blocks = if sectors_per_block == 0 {
            0
        } else {
            self.config.capacity / sectors_per_block
        };

        VfsBlockDeviceInfo {
            name: "virtio-blk",
            total_blocks,
            block_size,
            read_only: self.config.read_only,
            max_sectors: self.config.seg_max,
            num_queues: self.config.num_queues,
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
        let block_size = effective_block_size(&self.config) as usize;
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
        let block_size = effective_block_size(&self.config) as usize;
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
        let block_size = effective_block_size(&self.config) as usize;
        if block_size == 0 {
            return Box::pin(async { Err(VfsBlockError::InvalidBufferSize) });
        }
        let dma = dst.dma_info();
        let buf = dst.as_mut_slice();
        let len = buf.len();
        if len == 0 {
            return Box::pin(async { Ok(()) });
        }
        if (len % block_size) != 0 {
            return Box::pin(async { Err(VfsBlockError::InvalidBufferSize) });
        }
        let blocks = len / block_size;
        if blocks > (u32::MAX as usize) {
            return Box::pin(async { Err(VfsBlockError::InvalidBufferSize) });
        }
        let sector = match block_to_sector(block, block_size as u32) {
            Ok(sector) => sector,
            Err(err) => return Box::pin(async move { Err(err) }),
        };

        if let Some(dma) = dma {
            if dma.len != len {
                return Box::pin(async { Err(VfsBlockError::InvalidBufferSize) });
            }
            let iova = match map_dma_addr(dma.phys_addr, len) {
                Ok(iova) => iova,
                Err(err) => return Box::pin(async move { Err(err) }),
            };
            let dma_addr = iova.unwrap_or(dma.phys_addr);
            return Box::pin(async move {
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
                if let Some(iova) = iova {
                    let _ = unmap_dma(iova, len as u64);
                }
                result.map_err(map_vfs_block_error)?;
                Ok(())
            });
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
        let block_size = effective_block_size(&self.config) as usize;
        if block_size == 0 {
            return Box::pin(async { Err(VfsBlockError::InvalidBufferSize) });
        }
        let dma = src.dma_info();
        let data = src.as_slice();
        let len = data.len();
        if len == 0 {
            return Box::pin(async { Ok(()) });
        }
        if (len % block_size) != 0 {
            return Box::pin(async { Err(VfsBlockError::InvalidBufferSize) });
        }
        let blocks = len / block_size;
        if blocks > (u32::MAX as usize) {
            return Box::pin(async { Err(VfsBlockError::InvalidBufferSize) });
        }
        let sector = match block_to_sector(block, block_size as u32) {
            Ok(sector) => sector,
            Err(err) => return Box::pin(async move { Err(err) }),
        };

        if let Some(dma) = dma {
            if dma.len != len {
                return Box::pin(async { Err(VfsBlockError::InvalidBufferSize) });
            }
            let iova = match map_dma_addr(dma.phys_addr, len) {
                Ok(iova) => iova,
                Err(err) => return Box::pin(async move { Err(err) }),
            };
            let dma_addr = iova.unwrap_or(dma.phys_addr);
            return Box::pin(async move {
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
                if let Some(iova) = iova {
                    let _ = unmap_dma(iova, len as u64);
                }
                result.map_err(map_vfs_block_error)?;
                Ok(())
            });
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

/// Global VirtIO block device instance
static VIRTIO_BLK_DEVICE: Mutex<Option<VirtioBlkDevice>> = Mutex::new(None);

/// Initialize the global VirtIO block device
///
/// # Safety
/// Caller must ensure MMIO address is valid and device exists
pub unsafe fn init_virtio_blk(mmio_base: u64) -> Result<(), BlockError> {
    let mut device = VirtioBlkDevice::new(mmio_base);
    unsafe { device.init()? };

    log::info!(
        "VirtIO-blk initialized: {} sectors, {} bytes/sector\n",
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
pub fn blk_read_sync(_sector: u64, buf: &mut [u8]) -> Result<usize, BlockError> {
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
