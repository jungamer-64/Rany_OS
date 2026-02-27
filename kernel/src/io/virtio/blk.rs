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
    DmaDirection, DmaHandle, map_rref_slice_for_device,
    is_iommu_enabled, is_iommu_required,
};
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use crate::io::virtio::virtqueue::*;
use core::task::{Context, Poll, Waker};
use crate::io::virtio::transport::{VirtioMmioTransport, VirtioTransport};
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
#[derive(Debug)]
pub(crate) struct BlkRequestDma {
    /// Coherent DMA buffer holding header + status byte (+ indirect table)
    buffer: CoherentDmaBuffer,
    /// Physical address of the header (start of buffer)
    pub(crate) header_phys: u64,
    /// Physical address of the status byte
    pub(crate) status_phys: u64,
    /// Physical address of the indirect table
    pub(crate) indirect_table_phys: Option<u64>,
}

impl BlkRequestDma {
    /// Allocate DMA memory and copy the header into it.
    fn new(header: &VirtioBlkReqHeader) -> Option<Self> {
        Self::new_with_device(header, None, false)
    }

    /// Allocate IOMMU-aware DMA memory and copy the header into it.
    pub(crate) fn new_with_device(
        header: &VirtioBlkReqHeader,
        device_id: Option<&IommuDeviceId>,
        use_indirect: bool,
    ) -> Option<Self> {
        let header_size = core::mem::size_of::<VirtioBlkReqHeader>();
        let status_offset = header_size;
        let indirect_align = core::mem::align_of::<VringDesc>();
        let indirect_offset = crate::util::align_up_usize(status_offset + 1, indirect_align);
        let indirect_size = if use_indirect {
            core::mem::size_of::<VringDesc>() * 3
        } else {
            0
        };
        let total = if use_indirect {
            indirect_offset + indirect_size
        } else {
            status_offset + 1
        };
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
            slice[status_offset] = 0xFF;
        }

        Some(Self {
            buffer,
            header_phys: base_dev,
            status_phys: base_dev + status_offset as u64,
            indirect_table_phys: if use_indirect {
                Some(base_dev + indirect_offset as u64)
            } else {
                None
            },
        })
    }

    /// Read the status byte written by the device after completion.
    pub(crate) fn status(&self) -> u8 {
        unsafe { self.buffer.as_slice()[core::mem::size_of::<VirtioBlkReqHeader>()] }
    }
    /// Get a mutable pointer to the indirect table in the buffer.
    pub(crate) fn indirect_table_mut(&mut self) -> Option<*mut VringDesc> {
        let header_size = core::mem::size_of::<VirtioBlkReqHeader>();
        let indirect_offset =
            crate::util::align_up_usize(header_size + 1, core::mem::align_of::<VringDesc>());
        self.indirect_table_phys.map(|_| unsafe {
            self.buffer
                .as_mut_slice()
                .as_mut_ptr()
                .add(indirect_offset) as *mut VringDesc
        })
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

use crate::sync::IrqPoisonLock;

/// VirtIO block device driver
#[derive(Debug)]
pub struct VirtioBlkDevice {
    /// Device configuration
    config: BlockDeviceConfig,
    /// Request queues (one per CPU for multiqueue)
    queues: Vec<Arc<IrqPoisonLock<VirtQueue>>>,
    /// Pending request wakers (one per queue)
    pending_wakers: Vec<IrqPoisonLock<Vec<Option<Waker>>>>,
    /// Device ready flag
    ready: AtomicBool,
    /// Optional IOMMU device identifier for device-scoped mappings
    iommu_device_id: Option<IommuDeviceId>,
    /// Transport
    transport: Box<dyn crate::io::virtio::transport::VirtioTransport>,
    /// Features negotiated
    features: u64,
    /// DMA buffers for inflight requests (header + status), per queue, indexed by descriptor index
    pub(crate) inflight_dma: Vec<IrqPoisonLock<Vec<Option<BlkRequestDma>>>>,
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
