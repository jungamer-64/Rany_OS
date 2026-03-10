// ============================================================================
// src/io/virtio/balloon.rs - VirtIO Balloon Device Driver
// ============================================================================
//!
//! VirtIO-balloonドライバ実装
//!
//! ## 設計原則 (仕様書 5.5準拠)
//! - VirtQueueを用いたページ返却/回収
//! - inflateq (queue 0): ドライバがPFN配列をホストに送信しページを返却
//! - deflateq (queue 1): ドライバがPFN配列を送信しページを回収
//! - 設定空間: num_pages (u32, offset 0) / actual (u32, offset 4)
//!
//! ## VirtIO Balloon Device Specification
//! - Feature bits, PFN array format, configuration space
//! - 4K page granularity (PFN = physical address >> 12)

#![allow(dead_code)]

use crate::io::dma::{CoherentDmaBuffer, DmaMemoryAttributes};
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use crate::io::virtio::transport::{VirtioMmioTransport, VirtioTransport};
use crate::io::virtio::virtqueue::*;
use crate::sync::{PoisonLock, PoisonRwLock};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

// ============================================================================
// VirtIO Balloon Feature Bits
// ============================================================================

pub use virtio_driver::balloon::{
    BalloonError, device::VirtioBalloonDevice as CoreBalloonDevice, features,
};

// ============================================================================
// VirtIO Common Definitions (local to balloon)
// ============================================================================

// ============================================================================
// VirtIO Balloon Device
// ============================================================================

/// Balloon device configuration space offsets
mod config_offsets {
    /// num_pages: target number of balloon pages (u32, offset 0)
    pub const NUM_PAGES: usize = 0;
    /// actual: current number of balloon pages reported by driver (u32, offset 4)
    pub const ACTUAL: usize = 4;
}

/// VirtIO balloon device driver
#[derive(Debug)]
pub struct VirtioBalloonDevice {
    /// Transport layer (MMIO or PCI)
    transport: Box<dyn VirtioTransport>,
    /// Inflate virtqueue (queue 0)
    inflate_queue: Option<Arc<PoisonLock<VirtQueue>>>,
    /// Deflate virtqueue (queue 1)
    deflate_queue: Option<Arc<PoisonLock<VirtQueue>>>,
    /// DMA buffers for inflight requests
    inflight_buffers: PoisonLock<BTreeMap<u16, CoherentDmaBuffer>>,
    /// Device ready flag
    ready: AtomicBool,
    /// Optional IOMMU device identifier
    iommu_device_id: Option<IommuDeviceId>,
    /// Shared core device logic
    core: CoreBalloonDevice,
    /// Guest page size in bytes
    guest_page_size: u32,
}

unsafe impl Send for VirtioBalloonDevice {}
unsafe impl Sync for VirtioBalloonDevice {}

impl VirtioBalloonDevice {
    /// Create a new VirtIO balloon device (uninitialized)
    pub fn new(transport: Box<dyn VirtioTransport>) -> Self {
        Self::new_with_device(transport, None)
    }

    /// Create a new VirtIO balloon device with an IOMMU device ID.
    pub fn new_with_device(
        transport: Box<dyn VirtioTransport>,
        iommu_device_id: Option<IommuDeviceId>,
    ) -> Self {
        Self {
            transport,
            inflate_queue: None,
            deflate_queue: None,
            inflight_buffers: PoisonLock::new(BTreeMap::new()),
            ready: AtomicBool::new(false),
            iommu_device_id,
            core: CoreBalloonDevice::default(),
            guest_page_size: 4096,
        }
    }

    /// Set the guest page size for PFN calculations.
    pub fn set_guest_page_size(&mut self, page_size: u32) {
        self.guest_page_size = page_size;
    }

    /// Initialize the device
    pub fn init(&mut self) -> Result<(), BalloonError> {
        self.core
            .init(self.transport.as_ref())
            .map_err(|_| BalloonError::NotReady)?;

        // Queue 0: inflateq
        self.setup_queue(0)?;
        // Queue 1: deflateq
        self.setup_queue(1)?;

        self.transport
            .add_status(crate::io::virtio::status::VIRTIO_STATUS_DRIVER_OK);
        self.ready.store(true, Ordering::Release);
        Ok(())
    }

    /// Setup a virtqueue
    fn setup_queue(&mut self, queue_idx: u16) -> Result<(), BalloonError> {
        self.transport.select_queue(queue_idx);
        let max_size = self.transport.get_queue_max_size();

        if max_size == 0 {
            return Err(BalloonError::NotReady);
        }

        let queue_size = max_size.min(VIRTQUEUE_MAX_SIZE);
        let (desc_size, _avail_size, used_offset, total_size) =
            VirtQueue::calculate_layout(queue_size);

        let buffer = crate::io::virtio::dma::alloc_virtio_dma_buffer(
            total_size,
            crate::io::dma::DmaMemoryAttributes::MMIO,
            self.iommu_device_id.as_ref(),
        )
        .ok_or(BalloonError::NotReady)?;

        let dev_base = buffer.device_addr();
        let ptr = unsafe { buffer.as_slice().as_ptr() } as *mut u8;

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
                queue_size,
                desc_table,
                avail_ring,
                used_ring,
                Some(buffer),
                queue_idx,
                self.core.features,
            )
        };

        match queue_idx {
            0 => self.inflate_queue = Some(Arc::new(PoisonLock::new(virtqueue))),
            1 => self.deflate_queue = Some(Arc::new(PoisonLock::new(virtqueue))),
            _ => {}
        }

        Ok(())
    }

    /// Calculate PFN for a physical address based on guest_page_size.
    fn phys_to_pfn(&self, phys_addr: u64) -> u32 {
        (phys_addr / self.guest_page_size as u64) as u32
    }

    /// Submit a PFN array to the specified queue.
    fn submit_pfns(
        &self,
        queue: &Arc<PoisonLock<VirtQueue>>,
        pfns: &[u32],
    ) -> Result<(), BalloonError> {
        if !self.is_ready() {
            return Err(BalloonError::NotReady);
        }

        if pfns.is_empty() {
            return Ok(());
        }

        let byte_len = pfns.len() * core::mem::size_of::<u32>();

        let mut dma_buf = crate::io::virtio::dma::alloc_virtio_dma_buffer(
            byte_len,
            DmaMemoryAttributes::MMIO,
            self.iommu_device_id.as_ref(),
        )
        .ok_or(BalloonError::AllocFailed)?;

        unsafe {
            let dst = dma_buf.as_mut_slice();
            let src = pfns.as_ptr() as *const u8;
            core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), byte_len);
        }

        let phys_addr = dma_buf.device_addr();

        let mut queue_guard = queue.lock().unwrap_or_else(|e| e.into_inner());

        let desc_idx = queue_guard.alloc_desc().ok_or(BalloonError::QueueFull)?;

        unsafe {
            let desc_table = queue_guard.desc_table_ptr();

            (*desc_table.add(desc_idx as usize)) = VringDesc {
                addr: phys_addr,
                len: byte_len as u32,
                flags: 0,
                next: 0,
            };

            queue_guard.submit(desc_idx);
        }

        self.inflight_buffers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(desc_idx, dma_buf);

        queue_guard.notify(&*self.transport);

        Ok(())
    }

    pub fn inflate_pages(&self, pfns: &[u32]) -> Result<(), BalloonError> {
        let queue = self.inflate_queue.as_ref().ok_or(BalloonError::NotReady)?;
        self.submit_pfns(queue, pfns)
    }

    pub fn deflate_pages(&self, pfns: &[u32]) -> Result<(), BalloonError> {
        let queue = self.deflate_queue.as_ref().ok_or(BalloonError::NotReady)?;
        self.submit_pfns(queue, pfns)
    }

    pub fn read_target(&self) -> u32 {
        self.core.read_target(self.transport.as_ref())
    }

    pub fn write_actual(&self, pages: u32) {
        self.core.write_actual(self.transport.as_ref(), pages);
    }

    pub fn handle_interrupt(&self) {
        let interrupt_status = self.transport.get_interrupt_status();

        let queue_interrupt = (interrupt_status & 0x01) != 0;
        let config_change = (interrupt_status & 0x02) != 0;

        if config_change {
            let target = self.read_target();
            log::info!(
                "[VIRTIO-BALLOON] config change: target num_pages={}",
                target
            );
        }

        if queue_interrupt {
            if let Some(ref queue) = self.inflate_queue {
                let mut queue_guard = queue.lock().unwrap_or_else(|e| e.into_inner());
                // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
                while let Some((desc_id, _len)) = queue_guard.poll_complete() {
                    self.inflight_buffers
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&desc_id);
                    queue_guard.free_desc(desc_id);
                }
            }

            if let Some(ref queue) = self.deflate_queue {
                let mut queue_guard = queue.lock().unwrap_or_else(|e| e.into_inner());
                // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
                while let Some((desc_id, _len)) = queue_guard.poll_complete() {
                    self.inflight_buffers
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&desc_id);
                    queue_guard.free_desc(desc_id);
                }
            }
        }
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    pub fn features(&self) -> u64 {
        self.core.features
    }
}

// ============================================================================
// Global Device Instance
// ============================================================================

/// Primary (legacy) VirtIO balloon device slot kept for compatibility (`index=0`).
pub(crate) static VIRTIO_BALLOON_DEVICE: PoisonLock<Option<Arc<VirtioBalloonDevice>>> =
    PoisonLock::new(None);

/// Additional VirtIO balloon devices (`index != 0`).
pub(crate) static VIRTIO_BALLOON_DEVICES: PoisonRwLock<
    alloc::collections::BTreeMap<u8, Arc<VirtioBalloonDevice>>,
> = PoisonRwLock::new(alloc::collections::BTreeMap::new());

fn install_virtio_balloon_device(index: u8, device_arc: Arc<VirtioBalloonDevice>) {
    if index == 0 {
        *VIRTIO_BALLOON_DEVICE
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(device_arc);
    } else {
        VIRTIO_BALLOON_DEVICES
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(index, device_arc);
    }
}

pub fn get_virtio_balloon_device_at_index(index: u8) -> Option<Arc<VirtioBalloonDevice>> {
    if index == 0 {
        VIRTIO_BALLOON_DEVICE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    } else {
        VIRTIO_BALLOON_DEVICES
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&index)
            .cloned()
    }
}

pub unsafe fn init_virtio_balloon_at_index(index: u8, mmio_base: u64) -> Result<(), BalloonError> {
    let transport = unsafe {
        VirtioMmioTransport::new(mmio_base as usize).map_err(|_| BalloonError::NotReady)?
    };
    let mut dev = VirtioBalloonDevice::new(Box::new(transport));
    dev.init()?;

    let device_arc = Arc::new(dev);

    log::info!(
        "VirtIO-balloon index={} initialized: target={} pages\n",
        index,
        device_arc.read_target()
    );

    install_virtio_balloon_device(index, device_arc);
    Ok(())
}

pub unsafe fn init_virtio_balloon(mmio_base: u64) -> Result<(), BalloonError> {
    init_virtio_balloon_at_index(0, mmio_base)
}

pub unsafe fn init_virtio_balloon_for_device_at_index(
    index: u8,
    mmio_base: u64,
    device: IommuDeviceId,
) -> Result<(), BalloonError> {
    let transport = unsafe {
        VirtioMmioTransport::new(mmio_base as usize).map_err(|_| BalloonError::NotReady)?
    };
    let mut dev = VirtioBalloonDevice::new_with_device(Box::new(transport), Some(device));
    dev.init()?;

    let device_arc = Arc::new(dev);

    log::info!(
        "VirtIO-balloon index={} initialized: target={} pages\n",
        index,
        device_arc.read_target()
    );

    install_virtio_balloon_device(index, device_arc);
    Ok(())
}

pub unsafe fn init_virtio_balloon_for_device(
    mmio_base: u64,
    device: IommuDeviceId,
) -> Result<(), BalloonError> {
    init_virtio_balloon_for_device_at_index(0, mmio_base, device)
}

pub unsafe fn init_virtio_balloon_with_transport_at_index(
    index: u8,
    transport: Box<dyn VirtioTransport>,
    iommu_device_id: Option<IommuDeviceId>,
) -> Result<(), BalloonError> {
    let mut dev = VirtioBalloonDevice::new_with_device(transport, iommu_device_id);
    dev.init()?;

    let device_arc = Arc::new(dev);

    log::info!(
        "VirtIO-balloon index={} initialized: target={} pages\n",
        index,
        device_arc.read_target()
    );

    install_virtio_balloon_device(index, device_arc);
    Ok(())
}

pub unsafe fn init_virtio_balloon_with_transport(
    transport: Box<dyn VirtioTransport>,
    iommu_device_id: Option<IommuDeviceId>,
) -> Result<(), BalloonError> {
    init_virtio_balloon_with_transport_at_index(0, transport, iommu_device_id)
}

pub fn handle_virtio_balloon_interrupt_for_index(index: u8) {
    if let Some(device) = get_virtio_balloon_device_at_index(index) {
        let status = device.transport.get_interrupt_status();
        device.transport.ack_interrupt(status);
        device.handle_interrupt();
    }
}

pub fn handle_virtio_balloon_interrupt() {
    handle_virtio_balloon_interrupt_for_index(0);
}

pub fn get_virtio_balloon_device() -> Option<Arc<VirtioBalloonDevice>> {
    get_virtio_balloon_device_at_index(0)
}

#[cfg(all(test, not(feature = "qemu-test-export")))]
mod tests;
