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

use crate::io::dma::{
    CoherentDmaBuffer, DmaMemoryAttributes, IommuBounceAllocError, allocate_iommu_bounce_bytes,
    iommu_needs_bounce,
};
use crate::io::iommu::api::{
    DmaDirection, DmaHandle, is_iommu_enabled, is_iommu_required, map_rref_slice_for_device,
};
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use super::transport::{TransportType, VirtioMmioTransport, VirtioTransport};
use spin::Mutex;
mod device_impl;
pub use device_impl::*;
use vfs::block::{
    BlockDeviceInfo as VfsBlockDeviceInfo, BlockError as VfsBlockError,
    BlockResult as VfsBlockResult, DmaInfo, IoBuffer, IoBufferMut, OwnedBytes, ZcFuture,
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
    #[deprecated(since = "0.3.0", note = "Prefer transport-level notify methods and interrupt-driven notifications; avoid per-queue MMIO `notify_addr` when possible.")]
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
    #[allow(deprecated)]
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
    #[allow(deprecated)]
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
// DMA-safe request storage
// ============================================================================

/// DMA-safe storage for a VirtIO block request header and status byte.
///
/// Both header and status must remain valid and DMA-accessible until the device
/// completes the request. This struct allocates a CoherentDmaBuffer to hold
/// `[VirtioBlkReqHeader | u8 status]` in physically contiguous, uncacheable memory.
pub(crate) struct BlkRequestDma {
    /// Coherent DMA buffer holding header + status byte
    buffer: CoherentDmaBuffer,
    /// Physical address of the header (start of buffer)
    header_phys: u64,
    /// Physical address of the status byte
    status_phys: u64,
}

impl BlkRequestDma {
    /// Allocate DMA memory and copy the header into it.
    fn new(header: &VirtioBlkReqHeader) -> Option<Self> {
        Self::new_with_device(header, None)
    }

    /// Allocate IOMMU-aware DMA memory and copy the header into it.
    fn new_with_device(
        header: &VirtioBlkReqHeader,
        device_id: Option<&IommuDeviceId>,
    ) -> Option<Self> {
        let header_size = core::mem::size_of::<VirtioBlkReqHeader>();
        let total = header_size + 1; // header + 1 status byte
        let mut buffer = match device_id {
            Some(dev_id) => CoherentDmaBuffer::new_for_device(total, DmaMemoryAttributes::MMIO, dev_id)?,
            None => CoherentDmaBuffer::new(total, DmaMemoryAttributes::MMIO)?,
        };
        let base_dev = buffer.device_addr();

        unsafe {
            let slice = buffer.as_mut_slice();
            let src = header as *const VirtioBlkReqHeader as *const u8;
            core::ptr::copy_nonoverlapping(src, slice.as_mut_ptr(), header_size);
            // Sentinel status: 0xFF means "not yet completed"
            slice[header_size] = 0xFF;
        }

        Some(Self {
            buffer,
            header_phys: base_dev,
            status_phys: base_dev + header_size as u64,
        })
    }

    /// Read the status byte written by the device after completion.
    pub(crate) fn status(&self) -> u8 {
        unsafe { self.buffer.as_slice()[core::mem::size_of::<VirtioBlkReqHeader>()] }
    }
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
    /// DMA buffers for inflight requests (header + status), keyed by head descriptor index
    pub(crate) inflight_dma: Mutex<BTreeMap<u16, BlkRequestDma>>,
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
