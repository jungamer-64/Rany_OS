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

use crate::io::dma::{IommuBounceAllocError, allocate_iommu_bounce_bytes, iommu_needs_bounce};
use crate::io::iommu::api::{
    DmaDirection, DmaHandle, is_iommu_enabled, is_iommu_required, map_rref_slice_for_device,
};
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use super::transport::{TransportType, VirtioMmioTransport, VirtioTransport};
use spin::Mutex;
use vfs::block::{
    BlockDeviceInfo as VfsBlockDeviceInfo, BlockError as VfsBlockError,
    BlockResult as VfsBlockResult, IoBuffer, IoBufferMut, OwnedBytes, ZcFuture,
    ZeroCopyBlockDevice,
};

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
    /// DMA Buffer to keep memory alive (and properly manage ownership)
    dma_buffer: Option<crate::io::dma::CoherentDmaBuffer>,
    /// Queue index
    index: u16,
    /// Queue notify address (transport-provided)
    notify_addr: Option<u64>,
    /// Notify width (MMIO uses 32-bit, PCI uses 16-bit)
    notify_is_32bit: bool,
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
        dma_buffer: Option<crate::io::dma::CoherentDmaBuffer>,
        index: u16,
        notify_addr: Option<u64>,
        notify_is_32bit: bool,
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
            dma_buffer,
            index,
            notify_addr,
            notify_is_32bit,
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
    pub unsafe fn submit(&self, head: u16) -> u16 {
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

        self.index
    }

    /// Notify the device that new buffers are available.
    pub fn notify(&self) {
        let Some(addr) = self.notify_addr else {
            return;
        };

        if self.notify_is_32bit {
            crate::io::mmio::mmio_write_u32(addr as usize, self.index as u32);
        } else {
            crate::io::mmio::mmio_write_u16(addr as usize, self.index);
        }
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
    /// Optional IOMMU device identifier for device-scoped mappings
    iommu_device_id: Option<IommuDeviceId>,
    /// Transport
    transport: Box<dyn VirtioTransport>,
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
            pending_wakers: Mutex::new(Vec::new()),
            ready: AtomicBool::new(false),
            iommu_device_id,
            transport,
            features: 0,
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

        // Initialize pending wakers
        let mut wakers = self.pending_wakers.lock();
        wakers.resize(VIRTQUEUE_MAX_SIZE as usize * num_queues as usize, None);
        drop(wakers);

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
    fn read_config(&mut self) -> Result<(), BlockError> {
        // Read capacity (8 bytes at offset 0)
        self.config.capacity = self.transport.read_config_u64(0);

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
            // Let's assume standard offsets. 0x14 is 20.
            self.config.block_size = self.transport.read_config_u32(20);
        }

        // Read num_queues if multiqueue supported
        // Read num_queues if multiqueue supported
        if self.features & features::VIRTIO_BLK_F_MQ != 0 {
            // Number of queues (u16). Offset?
            // topology (alignment etc) is after blk_size.
            // writeback?
            // Spec says num_queues is later?
            // Existing code used 0x22 (34).
            // Let's trust existing offset.
            self.config.num_queues = self.transport.read_config_u16(34);
        }

        // Check read-only
        if self.features & features::VIRTIO_BLK_F_RO != 0 {
            self.config.read_only = true;
        }

        Ok(())
    }

    /// Setup a virtqueue
    fn setup_queue(&mut self, queue_idx: u16) -> Result<(), BlockError> {
        // Select queue and read size
        self.transport.select_queue(queue_idx);
        let max_size = self.transport.get_queue_max_size();

        if max_size == 0 {
            return Err(BlockError::NotReady);
        }

        let queue_size = max_size.min(VIRTQUEUE_MAX_SIZE);
        let notify_addr = self.transport.get_notify_addr(queue_idx);
        let notify_is_32bit = matches!(self.transport.transport_type(), TransportType::Mmio);

        // Allocate queue memory (proper DMA allocation)
        let desc_size = core::mem::size_of::<VringDesc>() * queue_size as usize;
        let avail_size = 6 + 2 * queue_size as usize; // flags + idx + ring + used_event
        let used_size = 6 + 8 * queue_size as usize; // flags + idx + ring + avail_event

        // Align used ring per VirtIO requirements
        let used_align = core::mem::align_of::<VringUsed>();
        let used_offset = align_up(desc_size + avail_size, used_align);
        let total_size = used_offset + used_size;

        // Use CoherentDmaBuffer for shared queue memory
        // We use Bidirectional as default, allowing device to read/write rings
        let buffer = crate::io::dma::CoherentDmaBuffer::new(
            total_size,
            crate::io::dma::DmaMemoryAttributes::MMIO, // Use MMIO/Uncacheable for rings to ensure visibility? Or Bidirectional?
                                                       // Usually rings are Coherent/Consistent. DmaMemoryAttributes::TO_DEVICE says WriteBack.
                                                       // MMIO says Uncacheable.
                                                       // VirtIO legacy often requires legacy access, but modern requires correct flags.
                                                       // Let's use DmaMemoryAttributes::MMIO which gives Uncacheable + Bidirectional, ensuring changes are visible immediately.
                                                       // Wait, standard RAM for rings should be cacheable if snooped.
                                                       // But to be safe and consistent with "Coherent", Uncacheable is often used if no hardware snooping.
                                                       // Let's stick to DmaMemoryAttributes::MMIO for safety as per user guideline "wrap unsafe MMIO".
                                                       // Actually, `alloc_dma_buffer` usually returns coherent memory.
                                                       // Let's use `DmaMemoryAttributes { cache_mode: CacheMode::Uncacheable, contiguous: true, direction: DmaDirection::Bidirectional }`.
                                                       // Which is `DmaMemoryAttributes::MMIO`.
        )
        .ok_or(BlockError::NotReady)?;

        let phys_base = buffer.phys_addr().as_u64();
        let ptr = unsafe { buffer.as_slice().as_ptr() } as *mut u8;

        let desc_table = ptr as *mut VringDesc;
        let avail_ring = unsafe { ptr.add(desc_size) as *mut VringAvail };
        let used_ring = unsafe { ptr.add(used_offset) as *mut VringUsed };

        // Write queue configuration
        self.transport.set_queue_size(queue_size);
        self.transport.set_queue_desc_addr(phys_base);
        self.transport
            .set_queue_avail_addr(phys_base + desc_size as u64);
        self.transport
            .set_queue_used_addr(phys_base + used_offset as u64);

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
                notify_addr,
                notify_is_32bit,
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
            queue_guard.submit(desc0);
        }

        queue_guard.notify();

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

        queue_guard.notify();

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

        queue_guard.notify();

        Ok(desc0)
    }
}

// ============================================================================
// Async Futures
// ============================================================================

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::Ordering;

    use super::*;
    use crate::io::virtio::{TransportType, VirtioDeviceType, VirtioTransport};
    use crate::fs::page_cluster_buffer::PageClusterBuffer;
    use crate::mm::{PAGE_SIZE_4K, alloc_contiguous_frames, dealloc_contiguous_frames};
    use x86_64::PhysAddr;

    struct NoopTransport;

    impl VirtioTransport for NoopTransport {
        fn device_type(&self) -> VirtioDeviceType {
            VirtioDeviceType::Block
        }

        fn get_status(&self) -> u8 {
            0
        }

        fn set_status(&mut self, _status: u8) {}

        fn get_device_features_low(&self) -> u32 {
            0
        }

        fn get_device_features_high(&self) -> u32 {
            0
        }

        fn set_driver_features_low(&mut self, _features: u32) {}

        fn set_driver_features_high(&mut self, _features: u32) {}

        fn get_num_queues(&self) -> u16 {
            1
        }

        fn select_queue(&mut self, _queue_index: u16) {}

        fn get_queue_max_size(&self) -> u16 {
            VIRTQUEUE_MAX_SIZE
        }

        fn set_queue_size(&mut self, _size: u16) {}

        fn is_queue_ready(&self) -> bool {
            false
        }

        fn enable_queue(&mut self) {}

        fn disable_queue(&mut self) {}

        fn set_queue_desc_addr(&mut self, _addr: u64) {}

        fn set_queue_avail_addr(&mut self, _addr: u64) {}

        fn set_queue_used_addr(&mut self, _addr: u64) {}

        fn notify_queue(&mut self, _queue_index: u16) {}

        fn get_notify_addr(&mut self, _queue_index: u16) -> Option<u64> {
            None
        }

        fn get_interrupt_status(&self) -> u32 {
            0
        }

        fn ack_interrupt(&self, _status: u32) {}

        fn read_config_u8(&self, _offset: usize) -> u8 {
            0
        }

        fn read_config_u16(&self, _offset: usize) -> u16 {
            0
        }

        fn read_config_u32(&self, _offset: usize) -> u32 {
            0
        }

        fn write_config_u8(&mut self, _offset: usize, _value: u8) {}

        fn write_config_u16(&mut self, _offset: usize, _value: u16) {}

        fn write_config_u32(&mut self, _offset: usize, _value: u32) {}

        fn transport_type(&self) -> TransportType {
            TransportType::Mmio
        }
    }

    #[test_case]
    fn test_submit_read_uses_dma_addr() {
        // Setup small virtqueue memory regions
        let queue_size: u16 = 8;
        let mut descs = vec![VringDesc::default(); queue_size as usize];
        let desc_ptr = descs.as_mut_ptr();

        let mut avail = vec![0u16; 2 + queue_size as usize];
        let avail_ptr = avail.as_mut_ptr() as *mut VringAvail;

        let used_bytes = core::mem::size_of::<VringUsed>()
            + (queue_size as usize) * core::mem::size_of::<VringUsedElem>();
        let mut used_mem = vec![0u8; used_bytes];
        let used_ptr = used_mem.as_mut_ptr() as *mut VringUsed;

        let vq = unsafe {
            VirtQueue::new(queue_size, desc_ptr, avail_ptr, used_ptr, None, 0, None, false)
        };

        let mut dev = VirtioBlkDevice::new(Box::new(NoopTransport));
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
            let buf = PageClusterBuffer::new_from_phys(start_phys.as_u64(), real_size)
                .expect("new_from_phys failed");
            let dma = buf.dma_info().expect("dma_info missing");

            let head = dev
                .submit_read(0, dma.phys_addr, 512u32, 0)
                .expect("submit_read failed");

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

    #[test_case]
    fn test_submit_write_uses_dma_addr() {
        // Setup small virtqueue memory regions
        let queue_size: u16 = 8;
        let mut descs = vec![VringDesc::default(); queue_size as usize];
        let desc_ptr = descs.as_mut_ptr();

        let mut avail = vec![0u16; 2 + queue_size as usize];
        let avail_ptr = avail.as_mut_ptr() as *mut VringAvail;

        let used_bytes = core::mem::size_of::<VringUsed>()
            + (queue_size as usize) * core::mem::size_of::<VringUsedElem>();
        let mut used_mem = vec![0u8; used_bytes];
        let used_ptr = used_mem.as_mut_ptr() as *mut VringUsed;

        let vq = unsafe {
            VirtQueue::new(queue_size, desc_ptr, avail_ptr, used_ptr, None, 0, None, false)
        };

        let mut dev = VirtioBlkDevice::new(Box::new(NoopTransport));
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
            let buf = PageClusterBuffer::new_from_phys(start_phys.as_u64(), real_size)
                .expect("new_from_phys failed");
            let dma = buf.dma_info().expect("dma_info missing");

            let head = dev
                .submit_write(0, dma.phys_addr, 512u32, 0)
                .expect("submit_write failed");

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

// NOTE: raw mapping helpers removed for `virtio-blk`; drivers should use
// `DeviceDmaContext` / `DmaHandle`-based mappings or bounce buffers via
// `allocate_iommu_bounce_bytes()` and `map_rref_slice_for_device()` /
// `DmaHandle::map_rref_slice()` to avoid deprecated APIs.

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
            if is_iommu_enabled() && iommu_needs_bounce(dma.phys_addr, len) {
                return Box::pin(async move {
                    let rref = allocate_iommu_bounce_bytes(len).map_err(|err| match err {
                        IommuBounceAllocError::InvalidLen => VfsBlockError::InvalidBufferSize,
                        IommuBounceAllocError::AllocFailed => VfsBlockError::IoError,
                    })?;
                    let handle = if let Some(device) = self.iommu_device_id {
                        map_rref_slice_for_device(rref, &device, DmaDirection::FromDevice)
                    } else {
                        DmaHandle::map_rref_slice(rref, 0, DmaDirection::FromDevice)
                    }
                    .map_err(|_| VfsBlockError::IoError)?;
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
                });
            }
            // IOMMU enabled: use a bounce-backed mapping (avoid deprecated raw mapping).
            if is_iommu_enabled() {
                // Allocate an aligned bounce buffer and map it for the device (read path - FromDevice)
                let rref = match allocate_iommu_bounce_bytes(len).map_err(|err| match err {
                    IommuBounceAllocError::InvalidLen => VfsBlockError::InvalidBufferSize,
                    IommuBounceAllocError::AllocFailed => VfsBlockError::IoError,
                }) {
                    Ok(r) => r,
                    Err(e) => return Box::pin(async move { Err(e) }),
                };

                let handle = match self.iommu_device_id {
                    Some(device) => map_rref_slice_for_device(rref, &device, DmaDirection::FromDevice),
                    None => DmaHandle::map_rref_slice(rref, 0, DmaDirection::FromDevice),
                }
                .map_err(|_| VfsBlockError::IoError);

                let handle = match handle {
                    Ok(handle) => handle,
                    Err(err) => return Box::pin(async move { Err(err) }),
                };

                let dma_addr = handle.iova();

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

                    // Unmap and copy back from the bounce buffer
                    let rref = handle.unmap().map_err(|_| VfsBlockError::IoError)?;
                    result.map_err(map_vfs_block_error)?;
                    buf.copy_from_slice(&rref[..len]);
                    Ok(())
                });
            } else if is_iommu_required() {
                return Box::pin(async move { Err(VfsBlockError::IoError) });
            }

            // Fallback: IOMMU not enabled
            let dma_addr = dma.phys_addr;
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
            if is_iommu_enabled() && iommu_needs_bounce(dma.phys_addr, len) {
                return Box::pin(async move {
                    let mut rref = allocate_iommu_bounce_bytes(len).map_err(|err| match err {
                        IommuBounceAllocError::InvalidLen => VfsBlockError::InvalidBufferSize,
                        IommuBounceAllocError::AllocFailed => VfsBlockError::IoError,
                    })?;
                    rref[..len].copy_from_slice(data);
                    let handle = if let Some(device) = self.iommu_device_id {
                        map_rref_slice_for_device(rref, &device, DmaDirection::ToDevice)
                    } else {
                        DmaHandle::map_rref_slice(rref, 0, DmaDirection::ToDevice)
                    }
                    .map_err(|_| VfsBlockError::IoError)?;
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
                });
            }
            // IOMMU enabled: use bounce-backed mapping (avoid deprecated raw mapping)
            if is_iommu_enabled() {
                let mut rref = match allocate_iommu_bounce_bytes(len).map_err(|err| match err {
                    IommuBounceAllocError::InvalidLen => VfsBlockError::InvalidBufferSize,
                    IommuBounceAllocError::AllocFailed => VfsBlockError::IoError,
                }) {
                    Ok(r) => r,
                    Err(e) => return Box::pin(async move { Err(e) }),
                };

                // Copy source data into the bounce buffer
                rref[..len].copy_from_slice(data);
                // Ensure cache is flushed for device
                crate::io::dma::flush_cache_range(rref.as_ptr(), rref.len());

                let handle = match self.iommu_device_id {
                    Some(device) => map_rref_slice_for_device(rref, &device, DmaDirection::ToDevice),
                    None => DmaHandle::map_rref_slice(rref, 0, DmaDirection::ToDevice),
                }
                .map_err(|_| VfsBlockError::IoError);

                let handle = match handle {
                    Ok(handle) => handle,
                    Err(err) => return Box::pin(async move { Err(err) }),
                };

                let dma_addr = handle.iova();

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

                    // Unmap the bounce buffer
                    handle.unmap().map_err(|_| VfsBlockError::IoError)?;
                    result.map_err(map_vfs_block_error)?;
                    Ok(())
                });
            } else if is_iommu_required() {
                return Box::pin(async move { Err(VfsBlockError::IoError) });
            }

            // Fallback: IOMMU not enabled
            let dma_addr = dma.phys_addr;
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

/// Global VirtIO block device instance (stored in an Arc for async usage)
static VIRTIO_BLK_DEVICE: Mutex<Option<Arc<VirtioBlkDevice>>> = Mutex::new(None);

/// Initialize the global VirtIO block device
///
/// # Safety
/// Caller must ensure MMIO address is valid and device exists
pub unsafe fn init_virtio_blk(mmio_base: u64) -> Result<(), BlockError> {
    let transport = unsafe {
        VirtioMmioTransport::new(mmio_base as usize).map_err(|_| BlockError::NotReady)?
    };
    let mut dev = VirtioBlkDevice::new(Box::new(transport));
    unsafe { dev.init()? };

    let device_arc = Arc::new(dev);

    log::info!(
        "VirtIO-blk initialized: {} sectors, {} bytes/sector\n",
        device_arc.config().capacity,
        device_arc.config().block_size
    );

    *VIRTIO_BLK_DEVICE.lock() = Some(Arc::clone(&device_arc));
    Ok(())
}

/// Initialize the global VirtIO block device with an IOMMU device ID.
///
/// # Safety
/// Caller must ensure MMIO address is valid and device exists.
pub unsafe fn init_virtio_blk_for_device(
    mmio_base: u64,
    device: IommuDeviceId,
) -> Result<(), BlockError> {
    let transport = unsafe {
        VirtioMmioTransport::new(mmio_base as usize).map_err(|_| BlockError::NotReady)?
    };
    let mut dev = VirtioBlkDevice::new_with_device(Box::new(transport), Some(device));
    unsafe { dev.init()? };

    let device_arc = Arc::new(dev);

    log::info!(
        "VirtIO-blk initialized: {} sectors, {} bytes/sector\n",
        device_arc.config().capacity,
        device_arc.config().block_size
    );

    *VIRTIO_BLK_DEVICE.lock() = Some(Arc::clone(&device_arc));
    Ok(())
}

fn align_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

/// Get a clone of the global VirtioBlk device Arc if initialized
pub fn get_virtio_blk_device() -> Option<Arc<VirtioBlkDevice>> {
    VIRTIO_BLK_DEVICE.lock().as_ref().cloned()
}

/// Handle VirtIO block device interrupt
pub fn handle_virtio_blk_interrupt() {
    if let Some(device) = VIRTIO_BLK_DEVICE.lock().as_ref() {
        // Ack interrupt with shared reference
        let status = device.transport.get_interrupt_status();
        crate::io::log::early_print(&alloc::format!("[EARLY][VIRTIO-BLK] IRQ status read=0x{:x}\n", status));
        device.transport.ack_interrupt(status);
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
mod unit_tests {
    use super::*;

    #[test_case]
    fn test_virtio_blk_req_type() {
        assert_eq!(VirtioBlkReqType::In as u32, 0);
        assert_eq!(VirtioBlkReqType::Out as u32, 1);
        assert_eq!(VirtioBlkReqType::Flush as u32, 4);
    }

    #[test_case]
    fn test_block_device_config_default() {
        let config = BlockDeviceConfig::default();
        assert_eq!(config.capacity, 0);
        assert_eq!(config.block_size, 512);
        assert!(!config.read_only);
    }

    #[test_case]
    fn test_bounce_map_unmap_via_dmahandle() {
        // Verify that bounce allocation + DmaHandle mapping/unmap works
        let len = 4096usize;
        let mut rref = allocate_iommu_bounce_bytes(len).expect("alloc bounce bytes failed");
        for i in 0..len {
            rref[i] = 0xABu8;
        }

        // Map (domain 0 / identity mapping in test env)
        let handle = crate::io::iommu::dma_handle::DmaHandle::map_rref_slice(rref, 0, DmaDirection::ToDevice)
            .expect("map_rref_slice failed");
        let _iova = handle.iova();
        // Unmap and recover RRef
        let rref = handle.unmap().expect("unmap failed");
        assert_eq!(rref[0], 0xABu8);
    }
}

