// ============================================================================
// drivers/virtio/src/balloon/mod.rs - VirtIO Balloon Device Driver
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
use crate::dma::{VirtioDmaBuffer, alloc_dma_buffer};
use crate::transport::{VirtioMmioTransport, VirtioTransport};
use crate::virtqueue::*;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use exorust_sync::{PoisonLock, PoisonRwLock};
use kernel_api::abi::driver::PackedPciLocation;
pub mod driver;

// ============================================================================
// VirtIO Balloon Feature Bits
// ============================================================================

pub mod features {
    /// Host must be told before pages are reclaimed
    pub const VIRTIO_BALLOON_F_MUST_TELL_HOST: u64 = 1 << 0;
    /// A virtqueue for reporting guest memory statistics is present
    pub const VIRTIO_BALLOON_F_STATS_VQ: u64 = 1 << 1;
    /// Deflate balloon on guest OOM
    pub const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u64 = 1 << 2;
    /// Free page hint reporting is supported
    pub const VIRTIO_BALLOON_F_FREE_PAGE_HINT: u64 = 1 << 3;
    /// Page reporting is supported
    pub const VIRTIO_BALLOON_F_PAGE_REPORTING: u64 = 1 << 5;
}

pub mod device;
pub use self::device::VirtioBalloonDevice as CoreBalloonDevice;

// ============================================================================
// VirtIO Common Definitions (local to balloon)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BalloonError {
    NotReady,
    IoError,
    QueueFull,
    AllocFailed,
}

// ============================================================================
// VirtIO Balloon Device
// ============================================================================

/// VirtIO balloon device driver
pub struct VirtioBalloonDevice {
    /// Transport layer (MMIO or PCI)
    transport: Box<dyn VirtioTransport>,
    /// Inflate virtqueue (queue 0)
    inflate_queue: Option<Arc<PoisonLock<VirtQueue>>>,
    /// Deflate virtqueue (queue 1)
    deflate_queue: Option<Arc<PoisonLock<VirtQueue>>>,
    /// DMA buffers for inflight requests
    inflight_buffers: PoisonLock<BTreeMap<u16, VirtioDmaBuffer>>,
    /// Device ready flag
    ready: AtomicBool,
    /// PCI locator used for device-scoped DMA mappings
    pci_locator: PackedPciLocation,
    /// Shared core device logic
    core: CoreBalloonDevice,
    /// Guest page size in bytes
    guest_page_size: u32,
}

unsafe impl Send for VirtioBalloonDevice {}
unsafe impl Sync for VirtioBalloonDevice {}

impl VirtioBalloonDevice {
    /// Create a new VirtIO balloon device (uninitialized)
    pub fn new(transport: Box<dyn VirtioTransport>, pci_locator: PackedPciLocation) -> Self {
        Self::new_with_device(transport, pci_locator)
    }

    /// Create a new VirtIO balloon device with a PCI locator.
    pub fn new_with_device(
        transport: Box<dyn VirtioTransport>,
        pci_locator: PackedPciLocation,
    ) -> Self {
        Self {
            transport,
            inflate_queue: None,
            deflate_queue: None,
            inflight_buffers: PoisonLock::new(BTreeMap::new()),
            ready: AtomicBool::new(false),
            pci_locator,
            core: CoreBalloonDevice::default(),
            guest_page_size: 4096,
        }
    }

    /// Set the guest page size for PFN calculations.
    pub fn set_guest_page_size(&mut self, page_size: u32) {
        self.guest_page_size = page_size;
    }

    /// Initialize the device
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    pub fn init(&mut self) -> Result<(), BalloonError> {
        self.core
            .init(self.transport.as_ref())
            .map_err(|_| BalloonError::NotReady)?;

        // Queue 0: inflateq
        self.setup_queue(0)?;
        // Queue 1: deflateq
        self.setup_queue(1)?;

        self.transport
            .add_status(crate::defs::status::VIRTIO_STATUS_DRIVER_OK);
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

        let buffer =
            alloc_dma_buffer(total_size, self.pci_locator).ok_or(BalloonError::NotReady)?;

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
        .map_err(|_| BalloonError::NotReady)?;

        match queue_idx {
            0 => self.inflate_queue = Some(Arc::new(PoisonLock::new(virtqueue))),
            1 => self.deflate_queue = Some(Arc::new(PoisonLock::new(virtqueue))),
            _ => {}
        }

        Ok(())
    }

    /// Calculate PFN for a physical address based on guest_page_size.
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

        let mut dma_buf =
            alloc_dma_buffer(byte_len, self.pci_locator).ok_or(BalloonError::AllocFailed)?;

        unsafe {
            let dst = dma_buf.as_slice_mut();
            let src = pfns.as_ptr() as *const u8;
            core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), byte_len);
        }

        let phys_addr = dma_buf.device_address();

        let queue_guard = queue.lock().unwrap_or_else(|e| e.into_inner());

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

    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
    pub fn inflate_pages(&self, pfns: &[u32]) -> Result<(), BalloonError> {
        let queue = self.inflate_queue.as_ref().ok_or(BalloonError::NotReady)?;
        self.submit_pfns(queue, pfns)
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
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
                let queue_guard = queue.lock().unwrap_or_else(|e| e.into_inner());
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
                let queue_guard = queue.lock().unwrap_or_else(|e| e.into_inner());
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

/// Primary VirtIO balloon device slot (`index=0`).
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

#[cfg(test)]
fn test_device_for_index(index: u8) -> PackedPciLocation {
    PackedPciLocation::new(0, 0, index, 0)
}

#[cfg(test)]
pub unsafe fn init_virtio_balloon_at_index(index: u8, mmio_base: u64) -> Result<(), BalloonError> {
    let transport = unsafe {
        VirtioMmioTransport::new(mmio_base as usize).map_err(|_| BalloonError::NotReady)?
    };
    let mut dev = VirtioBalloonDevice::new(Box::new(transport), test_device_for_index(index));
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

/// # Errors
///
/// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
pub unsafe fn init_virtio_balloon_for_device_at_index(
    index: u8,
    mmio_base: u64,
    device: PackedPciLocation,
) -> Result<(), BalloonError> {
    let transport = unsafe {
        VirtioMmioTransport::new(mmio_base as usize).map_err(|_| BalloonError::NotReady)?
    };
    let mut dev = VirtioBalloonDevice::new_with_device(Box::new(transport), device);
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

/// # Errors
///
/// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
pub unsafe fn init_virtio_balloon_with_transport_at_index(
    index: u8,
    transport: Box<dyn VirtioTransport>,
    pci_locator: PackedPciLocation,
) -> Result<(), BalloonError> {
    let mut dev = VirtioBalloonDevice::new_with_device(transport, pci_locator);
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

pub fn handle_virtio_balloon_interrupt_for_index(index: u8) {
    if let Some(device) = get_virtio_balloon_device_at_index(index) {
        let status = device.transport.get_interrupt_status();
        device.transport.ack_interrupt(status);
        device.handle_interrupt();
    }
}

#[cfg(all(test, not(feature = "qemu-test-export")))]
mod tests;
