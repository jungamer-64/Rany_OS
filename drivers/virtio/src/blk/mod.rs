// ============================================================================
// drivers/virtio/src/blk/mod.rs - VirtIO Block Device Driver
// ============================================================================

#![allow(dead_code)]

use crate::dma::{VirtioDmaBuffer, alloc_dma_buffer};
use crate::transport::{VirtioMmioTransport, VirtioTransport};
use crate::virtqueue::*;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use core::task::{Context, Poll, Waker};
use exorust_sync::{PoisonLock, PoisonRwLock};
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::block_io::{
    BlockDeviceInfo, BlockError as IoBlockError, BlockResult, IoBuffer, IoBufferMut, OwnedBytes,
    SECTOR_SIZE, ZcFuture, ZeroCopyBlockDevice,
};
use kernel_api::dma::{CpuOwned, DmaSlice};

pub mod device;
mod global_init;
pub use global_init::*;
pub mod driver;
#[cfg(test)]
mod tests;

use self::device::VirtioBlkDevice as CoreBlkDevice;

/// VirtIO feature bits for block devices
pub mod features {
    pub const VIRTIO_BLK_F_SIZE_MAX: u64 = 1 << 1;
    pub const VIRTIO_BLK_F_SEG_MAX: u64 = 1 << 2;
    pub const VIRTIO_BLK_F_GEOMETRY: u64 = 1 << 4;
    pub const VIRTIO_BLK_F_RO: u64 = 1 << 5;
    pub const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;
    pub const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;
    pub const VIRTIO_BLK_F_TOPOLOGY: u64 = 1 << 10;
    pub const VIRTIO_BLK_F_CONFIG_WCE: u64 = 1 << 11;
    pub const VIRTIO_BLK_F_MQ: u64 = 1 << 12;
    pub const VIRTIO_BLK_F_DISCARD: u64 = 1 << 13;
    pub const VIRTIO_BLK_F_WRITE_ZEROES: u64 = 1 << 14;
}

pub use features::*;

pub const VIRTIO_BLK_T_IN: u32 = 0;
pub const VIRTIO_BLK_T_OUT: u32 = 1;
pub const VIRTIO_BLK_T_FLUSH: u32 = 4;
pub const VIRTIO_BLK_T_DISCARD: u32 = 11;
pub const VIRTIO_BLK_T_WRITE_ZEROES: u32 = 13;

pub const VIRTIO_BLK_S_OK: u8 = 0;
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioBlkReqHeader {
    pub type_: u32,
    pub reserved: u32,
    pub sector: u64,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioBlkConfig {
    pub capacity: u64,
    pub size_max: u32,
    pub seg_max: u32,
    pub cylinders: u16,
    pub heads: u8,
    pub sectors: u8,
    pub blk_size: u32,
    pub physical_block_exp: u8,
    pub alignment_offset: u8,
    pub min_io_size: u16,
    pub opt_io_size: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockError {
    NotReady,
    IoError,
    QueueFull,
    Unsupported,
    InvalidParam,
}

impl core::fmt::Display for BlockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BlockError::NotReady => write!(f, "Device not ready"),
            BlockError::IoError => write!(f, "I/O error"),
            BlockError::QueueFull => write!(f, "Queue full"),
            BlockError::Unsupported => write!(f, "Unsupported operation"),
            BlockError::InvalidParam => write!(f, "Invalid parameter"),
        }
    }
}

/// Runtime hooks required by a portable VirtIO block implementation.
pub trait BlkRuntime: Send + Sync {
    fn alloc_dma(&self, size: usize) -> Result<DmaSlice<CpuOwned>, BlockError>;
    fn schedule_wake(&self, queue_index: u16);
    fn log(&self, level: log::Level, msg: core::fmt::Arguments);
}

/// IRQ-side completion hook installed by the kernel scheduler integration.
pub type BlockCompletionHandler = fn(u8, usize, u16, u32, bool);

const MAX_BLK_COMPLETIONS_PER_POLL: usize = 128;

fn align_up(value: usize, align: usize) -> usize {
    if align == 0 {
        value
    } else {
        (value + align - 1) & !(align - 1)
    }
}

#[cfg(test)]
fn release_test_dma_buffer(ptr: *mut u8, size: usize, _host_addr: u64) {
    let raw = core::ptr::slice_from_raw_parts_mut(ptr, size);
    unsafe {
        drop(Box::<[u8]>::from_raw(raw));
    }
}

fn alloc_blk_dma_buffer(size: usize, pci_locator: PackedPciLocation) -> Option<VirtioDmaBuffer> {
    if kernel_api::service::kernel::is_installed() {
        if let Some(buffer) = alloc_dma_buffer(size, pci_locator) {
            return Some(buffer);
        }
    }

    #[cfg(not(test))]
    if let Some(buffer) = alloc_dma_buffer(size, pci_locator) {
        return Some(buffer);
    }

    #[cfg(test)]
    {
        use kernel_api::dma::InternalDmaReclaimer;

        let mut backing = vec![0u8; size].into_boxed_slice();
        let ptr = backing.as_mut_ptr();
        let len = backing.len();
        let raw = Box::into_raw(backing) as *mut u8;
        let addr = ptr as usize as u64;
        return Some(unsafe {
            DmaSlice::from_internal_parts_unchecked(
                addr,
                addr,
                raw,
                len,
                InternalDmaReclaimer::KernelBuffer {
                    releaser: Some(release_test_dma_buffer),
                },
            )
        });
    }

    #[cfg(not(test))]
    {
        None
    }
}

#[derive(Debug)]
pub(crate) struct BlkRequestDma {
    buffer: VirtioDmaBuffer,
    pub(crate) header_phys: u64,
    pub(crate) status_phys: u64,
    pub(crate) indirect_table_phys: Option<u64>,
}

impl BlkRequestDma {
    pub(crate) fn new_with_device(
        header: &VirtioBlkReqHeader,
        pci_locator: PackedPciLocation,
        use_indirect: bool,
    ) -> Option<Self> {
        let header_size = core::mem::size_of::<VirtioBlkReqHeader>();
        let status_offset = header_size;
        let indirect_align = core::mem::align_of::<VringDesc>();
        let indirect_offset = align_up(status_offset + 1, indirect_align);
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

        let mut buffer = alloc_blk_dma_buffer(total, pci_locator)?;
        let base_dev = buffer.device_address();

        unsafe {
            let dst = buffer.as_slice_mut().as_mut_ptr();
            let src = header as *const VirtioBlkReqHeader as *const u8;
            core::ptr::copy_nonoverlapping(src, dst, header_size);
            buffer.as_slice_mut()[status_offset] = 0xFF;
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

    pub(crate) fn status(&self) -> u8 {
        self.buffer.as_slice()[core::mem::size_of::<VirtioBlkReqHeader>()]
    }

    pub(crate) fn indirect_table_mut(&mut self) -> Option<*mut VringDesc> {
        let header_size = core::mem::size_of::<VirtioBlkReqHeader>();
        let indirect_offset = align_up(header_size + 1, core::mem::align_of::<VringDesc>());
        self.indirect_table_phys.map(|_| unsafe {
            self.buffer.as_slice_mut().as_mut_ptr().add(indirect_offset) as *mut VringDesc
        })
    }
}

/// Generic block device trait for async I/O.
pub trait AsyncBlockDevice: Send + Sync {
    fn read<'a>(
        &'a self,
        sector: u64,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize, BlockError>> + Send + 'a>>;

    fn write<'a>(
        &'a self,
        sector: u64,
        buf: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize, BlockError>> + Send + 'a>>;

    fn flush<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<(), BlockError>> + Send + 'a>>;

    fn capacity(&self) -> u64;

    fn sector_size(&self) -> u32;
}

pub struct VirtioBlkDevice {
    pub(crate) core: CoreBlkDevice,
    queues: Vec<Arc<PoisonLock<VirtQueue>>>,
    pending_wakers: Vec<PoisonLock<Vec<Option<Waker>>>>,
    ready: AtomicBool,
    pci_locator: PackedPciLocation,
    transport: Box<dyn VirtioTransport>,
    inflight_dma: Vec<PoisonLock<Vec<Option<BlkRequestDma>>>>,
    completion_handler: PoisonLock<Option<BlockCompletionHandler>>,
    device_index: AtomicU8,
}

unsafe impl Send for VirtioBlkDevice {}
unsafe impl Sync for VirtioBlkDevice {}

impl VirtioBlkDevice {
    pub fn new(transport: Box<dyn VirtioTransport>, pci_locator: PackedPciLocation) -> Self {
        Self::new_with_device(transport, pci_locator)
    }

    pub fn new_with_device(
        transport: Box<dyn VirtioTransport>,
        pci_locator: PackedPciLocation,
    ) -> Self {
        Self {
            core: CoreBlkDevice::new(),
            queues: Vec::new(),
            pending_wakers: Vec::new(),
            ready: AtomicBool::new(false),
            pci_locator,
            transport,
            inflight_dma: Vec::new(),
            completion_handler: PoisonLock::new(None),
            device_index: AtomicU8::new(0),
        }
    }

    pub(crate) fn set_device_index(&self, index: u8) {
        self.device_index.store(index, Ordering::Release);
    }

    pub fn set_completion_handler(&self, handler: Option<BlockCompletionHandler>) {
        *self
            .completion_handler
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = handler;
    }

    pub fn init(&mut self) -> Result<(), BlockError> {
        self.core
            .init(self.transport.as_ref())
            .map_err(|_| BlockError::NotReady)?;

        let num_queues = if self.core.features & features::VIRTIO_BLK_F_MQ != 0 {
            self.core.num_queues
        } else {
            1
        };

        for queue_idx in 0..num_queues {
            self.setup_queue(queue_idx)?;
        }

        self.transport
            .add_status(crate::defs::status::VIRTIO_STATUS_DRIVER_OK);
        self.ready.store(true, Ordering::Release);
        Ok(())
    }

    fn setup_queue(&mut self, queue_idx: u16) -> Result<(), BlockError> {
        self.transport.select_queue(queue_idx);
        let max_size = self.transport.get_queue_max_size();
        if max_size == 0 {
            return Err(BlockError::NotReady);
        }

        let queue_size = max_size.min(VIRTQUEUE_MAX_SIZE);
        let (desc_size, _avail_size, used_offset, total_size) =
            VirtQueue::calculate_layout(queue_size);
        let buffer =
            alloc_blk_dma_buffer(total_size, self.pci_locator).ok_or(BlockError::NotReady)?;

        let dev_base = buffer.device_address();
        let ptr = buffer.as_ptr();
        let desc_table = ptr as *mut VringDesc;
        let avail_ring = unsafe { ptr.add(desc_size) as *mut VringAvail };
        let used_ring = unsafe { ptr.add(used_offset) as *mut VringUsed };

        self.transport.set_queue_size(queue_size);
        self.transport.set_queue_desc_addr(dev_base);
        self.transport
            .set_queue_avail_addr(dev_base + desc_size as u64);
        self.transport
            .set_queue_used_addr(dev_base + used_offset as u64);
        self.transport.enable_queue();

        let virtqueue = unsafe {
            VirtQueue::new(
                queue_idx,
                queue_size,
                desc_table,
                avail_ring,
                used_ring,
                Some(buffer),
                self.core.features,
            )
        }
        .map_err(|_| BlockError::NotReady)?;

        let mut wakers = Vec::with_capacity(queue_size as usize);
        wakers.resize_with(queue_size as usize, || None);
        let mut dmas = Vec::with_capacity(queue_size as usize);
        dmas.resize_with(queue_size as usize, || None);

        self.queues.push(Arc::new(PoisonLock::new(virtqueue)));
        self.pending_wakers.push(PoisonLock::new(wakers));
        self.inflight_dma.push(PoisonLock::new(dmas));
        Ok(())
    }

    pub fn config(&self) -> &CoreBlkDevice {
        &self.core
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    pub fn queue_count(&self) -> usize {
        self.queues.len()
    }

    pub fn submit_read(
        &self,
        sector: u64,
        dma_addr: u64,
        len: u32,
        queue_idx: usize,
    ) -> Result<u16, BlockError> {
        if !self.is_ready() {
            return Err(BlockError::NotReady);
        }
        if sector >= self.core.capacity {
            return Err(BlockError::InvalidParam);
        }

        let header = VirtioBlkReqHeader {
            type_: VIRTIO_BLK_T_IN,
            reserved: 0,
            sector,
        };
        let use_indirect = (self.core.features & crate::VIRTIO_F_INDIRECT_DESC) != 0;
        let mut req_dma = BlkRequestDma::new_with_device(&header, self.pci_locator, use_indirect)
            .ok_or(BlockError::NotReady)?;

        let queue = self.queues.get(queue_idx).ok_or(BlockError::NotReady)?;
        let queue_guard = queue.lock().unwrap_or_else(|e| e.into_inner());

        let desc_id = if use_indirect {
            let indirect_table = req_dma.indirect_table_mut().ok_or(BlockError::NotReady)?;
            let indirect_phys = req_dma.indirect_table_phys.ok_or(BlockError::NotReady)?;

            self.core.build_request_indirect(
                queue_guard.inner(),
                VIRTIO_BLK_T_IN,
                sector,
                dma_addr,
                len,
                req_dma.header_phys,
                req_dma.status_phys,
                indirect_table,
                indirect_phys,
            )
        } else {
            self.core.build_request(
                queue_guard.inner(),
                VIRTIO_BLK_T_IN,
                sector,
                dma_addr,
                len,
                req_dma.header_phys,
                req_dma.status_phys,
            )
        }?;

        self.install_inflight_dma(queue_idx, desc_id, req_dma);
        queue_guard.notify(self.transport.as_ref());
        Ok(desc_id)
    }

    fn prepare_write_request(&self, sector: u64) -> Result<BlkRequestDma, BlockError> {
        if !self.is_ready() {
            return Err(BlockError::NotReady);
        }
        if (self.core.features & features::VIRTIO_BLK_F_RO) != 0 {
            return Err(BlockError::Unsupported);
        }
        if sector >= self.core.capacity {
            return Err(BlockError::InvalidParam);
        }

        let header = VirtioBlkReqHeader {
            type_: VIRTIO_BLK_T_OUT,
            reserved: 0,
            sector,
        };
        let use_indirect = (self.core.features & crate::VIRTIO_F_INDIRECT_DESC) != 0;
        BlkRequestDma::new_with_device(&header, self.pci_locator, use_indirect)
            .ok_or(BlockError::NotReady)
    }

    pub fn submit_write(
        &self,
        sector: u64,
        dma_addr: u64,
        len: u32,
        queue_idx: usize,
    ) -> Result<u16, BlockError> {
        let mut req_dma = self.prepare_write_request(sector)?;
        let use_indirect = (self.core.features & crate::VIRTIO_F_INDIRECT_DESC) != 0;
        let queue = self.queues.get(queue_idx).ok_or(BlockError::NotReady)?;
        let queue_guard = queue.lock().unwrap_or_else(|e| e.into_inner());

        let desc_id = if use_indirect {
            let indirect_table = req_dma.indirect_table_mut().ok_or(BlockError::NotReady)?;
            let indirect_phys = req_dma.indirect_table_phys.ok_or(BlockError::NotReady)?;
            self.core.build_request_indirect(
                queue_guard.inner(),
                VIRTIO_BLK_T_OUT,
                sector,
                dma_addr,
                len,
                req_dma.header_phys,
                req_dma.status_phys,
                indirect_table,
                indirect_phys,
            )
        } else {
            self.core.build_request(
                queue_guard.inner(),
                VIRTIO_BLK_T_OUT,
                sector,
                dma_addr,
                len,
                req_dma.header_phys,
                req_dma.status_phys,
            )
        }?;

        self.install_inflight_dma(queue_idx, desc_id, req_dma);
        queue_guard.notify(self.transport.as_ref());
        Ok(desc_id)
    }

    pub fn submit_flush(&self, queue_idx: usize) -> Result<u16, BlockError> {
        if !self.is_ready() {
            return Err(BlockError::NotReady);
        }
        if self.core.features & features::VIRTIO_BLK_F_FLUSH == 0 {
            return Err(BlockError::Unsupported);
        }

        let header = VirtioBlkReqHeader {
            type_: VIRTIO_BLK_T_FLUSH,
            reserved: 0,
            sector: 0,
        };
        let use_indirect = (self.core.features & crate::VIRTIO_F_INDIRECT_DESC) != 0;
        let mut req_dma = BlkRequestDma::new_with_device(&header, self.pci_locator, use_indirect)
            .ok_or(BlockError::NotReady)?;

        let queue = self.queues.get(queue_idx).ok_or(BlockError::NotReady)?;
        let queue_guard = queue.lock().unwrap_or_else(|e| e.into_inner());

        let desc_id = if use_indirect {
            let indirect_table = req_dma.indirect_table_mut().ok_or(BlockError::NotReady)?;
            let indirect_phys = req_dma.indirect_table_phys.ok_or(BlockError::NotReady)?;
            unsafe {
                (*indirect_table.add(0)) = VringDesc {
                    addr: req_dma.header_phys,
                    len: core::mem::size_of::<VirtioBlkReqHeader>() as u32,
                    flags: VringDesc::F_NEXT,
                    next: 1,
                };
                (*indirect_table.add(1)) = VringDesc {
                    addr: req_dma.status_phys,
                    len: 1,
                    flags: VringDesc::F_WRITE,
                    next: 0,
                };
                queue_guard
                    .submit_indirect(indirect_phys, 2)
                    .ok_or(BlockError::QueueFull)?
            }
        } else {
            let desc0 = queue_guard.alloc_desc().ok_or(BlockError::QueueFull)?;
            let desc1 = queue_guard.alloc_desc().ok_or_else(|| {
                queue_guard.free_desc(desc0);
                BlockError::QueueFull
            })?;

            unsafe {
                let desc_table = queue_guard.desc_table_ptr();
                (*desc_table.add(desc0 as usize)) = VringDesc {
                    addr: req_dma.header_phys,
                    len: core::mem::size_of::<VirtioBlkReqHeader>() as u32,
                    flags: vring_flags::VRING_DESC_F_NEXT,
                    next: desc1,
                };
                (*desc_table.add(desc1 as usize)) = VringDesc {
                    addr: req_dma.status_phys,
                    len: 1,
                    flags: vring_flags::VRING_DESC_F_WRITE,
                    next: 0,
                };
                queue_guard.submit(desc0)
            }
        };

        self.install_inflight_dma(queue_idx, desc_id, req_dma);
        queue_guard.notify(self.transport.as_ref());
        Ok(desc_id)
    }

    fn install_inflight_dma(&self, queue_idx: usize, desc_id: u16, req_dma: BlkRequestDma) {
        if let Some(inflight_q) = self.inflight_dma.get(queue_idx) {
            let mut inflight = inflight_q.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(slot) = inflight.get_mut(desc_id as usize) {
                *slot = Some(req_dma);
            }
        }
    }

    fn take_request_status(&self, queue_idx: usize, desc_id: u16) -> bool {
        self.inflight_dma
            .get(queue_idx)
            .and_then(|queue_dma| {
                let mut dmas = queue_dma.lock().unwrap_or_else(|e| e.into_inner());
                dmas.get_mut(desc_id as usize).and_then(|slot| slot.take())
            })
            .map(|dma| dma.status() == VIRTIO_BLK_S_OK)
            .unwrap_or(true)
    }

    fn wake_pending_desc(&self, queue_idx: usize, desc_id: u16) {
        if let Some(queue_wakers) = self.pending_wakers.get(queue_idx) {
            let mut wakers = queue_wakers.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(waker) = wakers
                .get_mut(desc_id as usize)
                .and_then(|slot| slot.take())
            {
                waker.wake();
            }
        }
    }

    fn process_completion_entry(
        &self,
        queue_guard: &VirtQueue,
        queue_idx: usize,
        desc_id: u16,
        completed_len: u32,
        notify_registered_handler: bool,
    ) -> bool {
        let status_ok = self.take_request_status(queue_idx, desc_id);
        queue_guard.free_desc(desc_id);

        if notify_registered_handler {
            if let Some(handler) = *self
                .completion_handler
                .lock()
                .unwrap_or_else(|e| e.into_inner())
            {
                handler(
                    self.device_index.load(Ordering::Acquire),
                    queue_idx,
                    desc_id,
                    completed_len,
                    status_ok,
                );
            }
        }

        self.wake_pending_desc(queue_idx, desc_id);
        status_ok
    }

    pub fn handle_interrupt(&self) {
        for (queue_idx, queue) in self.queues.iter().enumerate() {
            let queue_guard = queue.lock().unwrap_or_else(|e| e.into_inner());
            while let Some((desc_id, completed_len)) = queue_guard.poll_complete() {
                let _ = self.process_completion_entry(
                    &queue_guard,
                    queue_idx,
                    desc_id,
                    completed_len,
                    true,
                );
            }
        }
    }

    pub fn drain_completions_with<F>(&self, mut on_completion: F) -> usize
    where
        F: FnMut(usize, u16, u32, bool),
    {
        let mut processed = 0usize;
        for (queue_idx, queue) in self.queues.iter().enumerate() {
            let queue_guard = queue.lock().unwrap_or_else(|e| e.into_inner());
            while let Some((desc_id, completed_len)) = queue_guard.poll_complete() {
                let status_ok = self.process_completion_entry(
                    &queue_guard,
                    queue_idx,
                    desc_id,
                    completed_len,
                    false,
                );
                on_completion(queue_idx, desc_id, completed_len, status_ok);
                processed += 1;
            }
        }
        processed
    }

    pub fn read_async<'a>(
        &'a self,
        sector: u64,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize, BlockError>> + Send + 'a>> {
        Box::pin(DmaReadFuture {
            device: self,
            sector,
            buf,
            dma: None,
            submitted: false,
            desc_id: None,
            queue_idx: 0,
        })
    }

    pub fn write_async<'a>(
        &'a self,
        sector: u64,
        buf: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize, BlockError>> + Send + 'a>> {
        Box::pin(DmaWriteFuture {
            device: self,
            sector,
            buf,
            dma: None,
            submitted: false,
            desc_id: None,
            queue_idx: 0,
        })
    }

    pub fn flush_async(&self) -> FlushFuture<'_> {
        FlushFuture {
            device: self,
            submitted: false,
            desc_id: None,
            queue_idx: 0,
        }
    }
}

fn validate_dma_buf_size(buf_len: usize) -> Result<u32, BlockError> {
    if !buf_len.is_multiple_of(SECTOR_SIZE) {
        return Err(BlockError::InvalidParam);
    }
    if buf_len > u32::MAX as usize {
        return Err(BlockError::InvalidParam);
    }
    Ok(buf_len as u32)
}

fn poll_for_completion(
    device: &VirtioBlkDevice,
    queue_idx: usize,
    desc_id: u16,
) -> Option<(u16, u32)> {
    let queue = device.queues.get(queue_idx)?;
    let queue_guard = queue.lock().unwrap_or_else(|e| e.into_inner());
    let mut target = None;
    let mut processed = 0usize;

    while processed < MAX_BLK_COMPLETIONS_PER_POLL {
        let Some((completed_id, len)) = queue_guard.poll_complete() else {
            break;
        };
        processed += 1;
        let _ = device.process_completion_entry(&queue_guard, queue_idx, completed_id, len, true);
        if completed_id == desc_id {
            target = Some((completed_id, len));
        }
    }

    target
}

fn register_desc_waker(device: &VirtioBlkDevice, queue_idx: usize, desc_id: u16, waker: &Waker) {
    if let Some(queue_wakers) = device.pending_wakers.get(queue_idx) {
        let mut wakers = queue_wakers.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(slot) = wakers.get_mut(desc_id as usize) {
            *slot = Some(waker.clone());
        }
    }
}

pub struct DmaReadFuture<'a> {
    device: &'a VirtioBlkDevice,
    sector: u64,
    buf: &'a mut [u8],
    dma: Option<VirtioDmaBuffer>,
    submitted: bool,
    desc_id: Option<u16>,
    queue_idx: usize,
}

impl<'a> Future for DmaReadFuture<'a> {
    type Output = Result<usize, BlockError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.submitted {
            let len = validate_dma_buf_size(self.buf.len())?;
            let dma = alloc_blk_dma_buffer(self.buf.len(), self.device.pci_locator)
                .ok_or(BlockError::NotReady)?;
            let desc_id =
                self.device
                    .submit_read(self.sector, dma.device_address(), len, self.queue_idx)?;
            register_desc_waker(self.device, self.queue_idx, desc_id, cx.waker());
            self.dma = Some(dma);
            self.desc_id = Some(desc_id);
            self.submitted = true;
        }

        if let Some(desc_id) = self.desc_id {
            if poll_for_completion(self.device, self.queue_idx, desc_id).is_some() {
                if let Some(dma) = self.dma.take() {
                    let len = self.buf.len();
                    self.buf.copy_from_slice(&dma.as_slice()[..len]);
                }
                return Poll::Ready(Ok(self.buf.len()));
            }
            register_desc_waker(self.device, self.queue_idx, desc_id, cx.waker());
        }

        Poll::Pending
    }
}

pub struct DmaWriteFuture<'a> {
    device: &'a VirtioBlkDevice,
    sector: u64,
    buf: &'a [u8],
    dma: Option<VirtioDmaBuffer>,
    submitted: bool,
    desc_id: Option<u16>,
    queue_idx: usize,
}

impl<'a> Future for DmaWriteFuture<'a> {
    type Output = Result<usize, BlockError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.submitted {
            let len = validate_dma_buf_size(self.buf.len())?;
            let mut dma = alloc_blk_dma_buffer(self.buf.len(), self.device.pci_locator)
                .ok_or(BlockError::NotReady)?;
            dma.as_slice_mut()[..self.buf.len()].copy_from_slice(self.buf);
            let desc_id =
                self.device
                    .submit_write(self.sector, dma.device_address(), len, self.queue_idx)?;
            register_desc_waker(self.device, self.queue_idx, desc_id, cx.waker());
            self.dma = Some(dma);
            self.desc_id = Some(desc_id);
            self.submitted = true;
        }

        if let Some(desc_id) = self.desc_id {
            if poll_for_completion(self.device, self.queue_idx, desc_id).is_some() {
                let _ = self.dma.take();
                return Poll::Ready(Ok(self.buf.len()));
            }
            register_desc_waker(self.device, self.queue_idx, desc_id, cx.waker());
        }

        Poll::Pending
    }
}

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
            if self.device.core.features & features::VIRTIO_BLK_F_FLUSH == 0 {
                return Poll::Ready(Err(BlockError::Unsupported));
            }

            let desc_id = self.device.submit_flush(self.queue_idx)?;
            register_desc_waker(self.device, self.queue_idx, desc_id, cx.waker());
            self.desc_id = Some(desc_id);
            self.submitted = true;
        }

        if let Some(desc_id) = self.desc_id {
            if poll_for_completion(self.device, self.queue_idx, desc_id).is_some() {
                return Poll::Ready(Ok(()));
            }
            register_desc_waker(self.device, self.queue_idx, desc_id, cx.waker());
        }

        Poll::Pending
    }
}

fn map_block_error(err: BlockError) -> IoBlockError {
    match err {
        BlockError::NotReady => IoBlockError::NotReady,
        BlockError::IoError | BlockError::Unsupported => IoBlockError::IoError,
        BlockError::QueueFull => IoBlockError::QueueFull,
        BlockError::InvalidParam => IoBlockError::InvalidBufferSize,
    }
}

fn effective_block_size_from_core(core: &CoreBlkDevice) -> u32 {
    if core.block_size == 0 {
        SECTOR_SIZE as u32
    } else {
        core.block_size
    }
}

fn block_to_sector(block: u64, block_size: u32) -> Result<u64, IoBlockError> {
    if block_size == 0 || !block_size.is_multiple_of(SECTOR_SIZE as u32) {
        return Err(IoBlockError::InvalidBufferSize);
    }
    let sectors_per_block = (block_size / SECTOR_SIZE as u32) as u64;
    block
        .checked_mul(sectors_per_block)
        .ok_or(IoBlockError::InvalidBufferSize)
}

fn validate_block_io_params_from_core(
    core: &CoreBlkDevice,
    block: u64,
    len: usize,
) -> BlockResult<Option<u64>> {
    let block_size = effective_block_size_from_core(core) as usize;
    if block_size == 0 {
        return Err(IoBlockError::InvalidBufferSize);
    }
    if len == 0 {
        return Ok(None);
    }
    if !len.is_multiple_of(block_size) {
        return Err(IoBlockError::InvalidBufferSize);
    }
    let blocks = len / block_size;
    if blocks > u32::MAX as usize {
        return Err(IoBlockError::InvalidBufferSize);
    }
    let sector = block_to_sector(block, block_size as u32)?;
    Ok(Some(sector))
}

impl AsyncBlockDevice for VirtioBlkDevice {
    fn read<'a>(
        &'a self,
        sector: u64,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize, BlockError>> + Send + 'a>> {
        VirtioBlkDevice::read_async(self, sector, buf)
    }

    fn write<'a>(
        &'a self,
        sector: u64,
        buf: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize, BlockError>> + Send + 'a>> {
        VirtioBlkDevice::write_async(self, sector, buf)
    }

    fn flush<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<(), BlockError>> + Send + 'a>> {
        Box::pin(self.flush_async())
    }

    fn capacity(&self) -> u64 {
        self.core.capacity
    }

    fn sector_size(&self) -> u32 {
        effective_block_size_from_core(&self.core)
    }
}

impl ZeroCopyBlockDevice for VirtioBlkDevice {
    type Buffer = OwnedBytes;

    fn info(&self) -> BlockDeviceInfo {
        let block_size = effective_block_size_from_core(&self.core);
        let sectors_per_block = (block_size / SECTOR_SIZE as u32) as u64;
        let total_blocks = if sectors_per_block == 0 {
            0
        } else {
            self.core.capacity / sectors_per_block
        };

        BlockDeviceInfo {
            name: "virtio-blk",
            total_blocks,
            block_size,
            read_only: (self.core.features & features::VIRTIO_BLK_F_RO) != 0,
            max_sectors: self.core.seg_max,
            num_queues: self.core.num_queues.max(1),
        }
    }

    fn flush(&self) -> BlockResult<()> {
        if self.core.features & features::VIRTIO_BLK_F_FLUSH == 0 {
            return Ok(());
        }

        let desc_id = self.submit_flush(0).map_err(map_block_error)?;
        loop {
            if poll_for_completion(self, 0, desc_id).is_some() {
                return Ok(());
            }
            core::hint::spin_loop();
        }
    }

    fn alloc_buffer(&self, size: usize) -> BlockResult<Self::Buffer> {
        Ok(OwnedBytes::from_vec(vec![0u8; size]))
    }

    fn read_async(&self, block: u64, count: u32) -> ZcFuture<'_, BlockResult<Self::Buffer>> {
        let block_size = effective_block_size_from_core(&self.core) as usize;
        if block_size == 0 {
            return Box::pin(async { Err(IoBlockError::InvalidBufferSize) });
        }

        let size = match block_size.checked_mul(count as usize) {
            Some(size) => size,
            None => return Box::pin(async { Err(IoBlockError::InvalidBufferSize) }),
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
                .map_err(map_block_error)?;
            Ok(buf)
        })
    }

    fn write_async(
        &self,
        block: u64,
        buffer: Self::Buffer,
    ) -> ZcFuture<'_, BlockResult<Self::Buffer>> {
        let block_size = effective_block_size_from_core(&self.core) as usize;
        if block_size == 0 {
            return Box::pin(async { Err(IoBlockError::InvalidBufferSize) });
        }

        let len = buffer.as_ref().len();
        if len == 0 {
            return Box::pin(async move { Ok(buffer) });
        }
        if !len.is_multiple_of(block_size) {
            return Box::pin(async move { Err(IoBlockError::InvalidBufferSize) });
        }

        let sector = match block_to_sector(block, block_size as u32) {
            Ok(sector) => sector,
            Err(err) => return Box::pin(async move { Err(err) }),
        };

        Box::pin(async move {
            VirtioBlkDevice::write_async(self, sector, buffer.as_ref())
                .await
                .map_err(map_block_error)?;
            Ok(buffer)
        })
    }

    fn read_into_buf<'a>(
        &'a self,
        block: u64,
        dst: &'a mut dyn IoBufferMut,
    ) -> ZcFuture<'a, BlockResult<()>> {
        let buf = dst.as_mut_slice();
        let len = buf.len();
        let sector = match validate_block_io_params_from_core(&self.core, block, len) {
            Ok(Some(sector)) => sector,
            Ok(None) => return Box::pin(async { Ok(()) }),
            Err(err) => return Box::pin(async move { Err(err) }),
        };

        Box::pin(async move {
            VirtioBlkDevice::read_async(self, sector, buf)
                .await
                .map_err(map_block_error)?;
            Ok(())
        })
    }

    fn write_from_buf<'a>(
        &'a self,
        block: u64,
        src: &'a dyn IoBuffer,
    ) -> ZcFuture<'a, BlockResult<()>> {
        let data = src.as_slice();
        let len = data.len();
        let sector = match validate_block_io_params_from_core(&self.core, block, len) {
            Ok(Some(sector)) => sector,
            Ok(None) => return Box::pin(async { Ok(()) }),
            Err(err) => return Box::pin(async move { Err(err) }),
        };

        Box::pin(async move {
            VirtioBlkDevice::write_async(self, sector, data)
                .await
                .map_err(map_block_error)?;
            Ok(())
        })
    }
}
