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
use crate::io::virtio::transport::{VirtioMmioTransport, VirtioTransport};
use crate::io::virtio::virtqueue::*;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};
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

pub use virtio_driver::blk::{
    BlockError, VIRTIO_BLK_S_IOERR, VIRTIO_BLK_S_OK, VIRTIO_BLK_S_UNSUPP, VIRTIO_BLK_T_FLUSH,
    VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT, VirtioBlkConfig, VirtioBlkReqHeader, features,
};

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
            Some(dev_id) => {
                CoherentDmaBuffer::new_for_device(total, DmaMemoryAttributes::MMIO, dev_id)?
            }
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
            self.buffer.as_mut_slice().as_mut_ptr().add(indirect_offset) as *mut VringDesc
        })
    }
}

// ============================================================================
// VirtIO Block Device
// ============================================================================

use crate::sync::IrqPoisonLock;

use virtio_driver::blk::device::VirtioBlkDevice as CoreBlkDevice;

/// VirtIO block device driver
#[derive(Debug)]
pub struct VirtioBlkDevice {
    /// Core logic from shared driver crate
    pub(crate) core: CoreBlkDevice,
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
    /// DMA buffers for inflight requests (header + status), per queue, indexed by descriptor index
    pub(crate) inflight_dma: Vec<IrqPoisonLock<Vec<Option<BlkRequestDma>>>>,
}

unsafe impl Send for VirtioBlkDevice {}
unsafe impl Sync for VirtioBlkDevice {}
