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
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use crate::io::virtio::virtqueue::*;
use super::transport::{TransportType, VirtioMmioTransport, VirtioTransport};
use spin::Mutex;

// ============================================================================
// VirtIO Balloon Feature Bits
// ============================================================================

/// VirtIO feature bits for balloon devices
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

// ============================================================================
// VirtIO Common Definitions (local to balloon)
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

// ============================================================================
// Balloon Error Types
// ============================================================================

/// Balloon device error types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BalloonError {
    /// Device not ready
    NotReady,
    /// I/O error from device
    IoError,
    /// Queue full
    QueueFull,
    /// DMA allocation failed
    AllocFailed,
}

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
pub struct VirtioBalloonDevice {
    /// Transport layer (MMIO or PCI)
    transport: Box<dyn VirtioTransport>,
    /// Inflate virtqueue (queue 0) - driver sends PFN arrays to host to return pages
    inflate_queue: Option<Arc<Mutex<VirtQueue>>>,
    /// Deflate virtqueue (queue 1) - driver sends PFN arrays to host to reclaim pages
    deflate_queue: Option<Arc<Mutex<VirtQueue>>>,
    /// DMA buffers for inflight requests, keyed by head descriptor index
    inflight_buffers: Mutex<BTreeMap<u16, CoherentDmaBuffer>>,
    /// Device ready flag
    ready: AtomicBool,
    /// Optional IOMMU device identifier for device-scoped mappings
    iommu_device_id: Option<IommuDeviceId>,
    /// Features negotiated
    features: u64,
}

unsafe impl Send for VirtioBalloonDevice {}
unsafe impl Sync for VirtioBalloonDevice {}

impl VirtioBalloonDevice {
    /// Create a new VirtIO balloon device (uninitialized)
    ///
    /// The transport must already be validated (magic/version checks).
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
            inflight_buffers: Mutex::new(BTreeMap::new()),
            ready: AtomicBool::new(false),
            iommu_device_id,
            features: 0,
        }
    }

    /// Initialize the device
    ///
    /// # Safety
    /// Caller must ensure MMIO address is valid
    pub unsafe fn init(&mut self) -> Result<(), BalloonError> {
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
            & (features::VIRTIO_BALLOON_F_MUST_TELL_HOST
                | features::VIRTIO_BALLOON_F_DEFLATE_ON_OOM);
        self.transport.set_driver_features(driver_features);
        self.features = driver_features;

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
            return Err(BalloonError::NotReady);
        }

        // Step 6: Setup queues
        // Queue 0: inflateq
        self.setup_queue(0)?;
        // Queue 1: deflateq
        self.setup_queue(1)?;

        // Step 7: Driver OK
        self.transport.set_status(
            VirtioDeviceStatus::Acknowledge as u8
                | VirtioDeviceStatus::Driver as u8
                | VirtioDeviceStatus::FeaturesOk as u8
                | VirtioDeviceStatus::DriverOk as u8,
        );

        self.ready.store(true, Ordering::Release);
        Ok(())
    }

    /// Setup a virtqueue
    fn setup_queue(&mut self, queue_idx: u16) -> Result<(), BalloonError> {
        // Select queue and read size
        self.transport.select_queue(queue_idx);
        let max_size = self.transport.get_queue_max_size();

        if max_size == 0 {
            return Err(BalloonError::NotReady);
        }

        let queue_size = max_size.min(VIRTQUEUE_MAX_SIZE);
        let notify_addr = self.transport.get_notify_addr(queue_idx);
        let notify_is_32bit = matches!(self.transport.transport_type(), TransportType::Mmio);

        // Allocate queue memory (proper DMA allocation)
        let desc_size = core::mem::size_of::<VringDesc>() * queue_size as usize;
        let avail_size = 6 + 2 * queue_size as usize; // flags + idx + ring + used_event
        let used_size = 6 + 8 * queue_size as usize; // flags + idx + ring + avail_event

        // Align used ring per VirtIO requirements
        let used_align = 4usize; // VirtIO spec: used ring must be aligned to 4 bytes
        let used_offset = align_up(desc_size + avail_size, used_align);
        let total_size = used_offset + used_size;

        // Use CoherentDmaBuffer for shared queue memory (IOMMU-aware)
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

        // Write queue configuration
        self.transport.set_queue_size(queue_size);
        self.transport.set_queue_desc_addr(dev_base);
        self.transport
            .set_queue_avail_addr(dev_base + desc_size as u64);
        self.transport
            .set_queue_used_addr(dev_base + used_offset as u64);

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
                queue_idx,
                notify_addr,
                notify_is_32bit,
            )
        };

        match queue_idx {
            0 => self.inflate_queue = Some(Arc::new(Mutex::new(virtqueue))),
            1 => self.deflate_queue = Some(Arc::new(Mutex::new(virtqueue))),
            _ => {} // Ignore unknown queue indices (e.g. statsq not yet supported)
        }

        Ok(())
    }

    /// Submit a PFN array to the specified queue.
    ///
    /// Allocates a CoherentDmaBuffer, copies the PFN array into it,
    /// submits a single readable descriptor to the queue, and notifies the device.
    fn submit_pfns(
        &self,
        queue: &Arc<Mutex<VirtQueue>>,
        pfns: &[u32],
    ) -> Result<(), BalloonError> {
        if !self.is_ready() {
            return Err(BalloonError::NotReady);
        }

        if pfns.is_empty() {
            return Ok(());
        }

        let byte_len = pfns.len() * core::mem::size_of::<u32>();

        // Allocate a DMA-safe buffer for the PFN array (IOMMU-aware)
        let mut dma_buf = crate::io::virtio::dma::alloc_virtio_dma_buffer(
            byte_len,
            DmaMemoryAttributes::MMIO,
            self.iommu_device_id.as_ref(),
        )
        .ok_or(BalloonError::AllocFailed)?;

        // Copy PFN data into the DMA buffer
        unsafe {
            let dst = dma_buf.as_mut_slice();
            let src = pfns.as_ptr() as *const u8;
            core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), byte_len);
        }

        let phys_addr = dma_buf.device_addr();

        let queue_guard = queue.lock();

        // Allocate a single descriptor for the PFN array (device-readable)
        let desc_idx = queue_guard.alloc_desc().ok_or(BalloonError::QueueFull)?;

        unsafe {
            let desc_table = queue_guard.desc_table;

            // Single readable descriptor: device reads PFN array from driver
            (*desc_table.add(desc_idx as usize)) = VringDesc {
                addr: phys_addr,
                len: byte_len as u32,
                flags: 0, // No WRITE flag = device-readable
                next: 0,
            };

            // Submit to available ring
            queue_guard.submit(desc_idx);
        }

        // Retain DMA buffer until completion
        self.inflight_buffers.lock().insert(desc_idx, dma_buf);

        // Notify device
        queue_guard.notify();

        Ok(())
    }

    /// Inflate the balloon by sending PFN arrays to the host.
    ///
    /// The driver sends page frame numbers to the inflateq, telling the host
    /// to reclaim those pages from the guest (4K page granularity).
    pub fn inflate_pages(&self, pfns: &[u32]) -> Result<(), BalloonError> {
        let queue = self
            .inflate_queue
            .as_ref()
            .ok_or(BalloonError::NotReady)?;
        self.submit_pfns(queue, pfns)
    }

    /// Deflate the balloon by sending PFN arrays to the host.
    ///
    /// The driver sends page frame numbers to the deflateq, telling the host
    /// to return those pages to the guest (4K page granularity).
    pub fn deflate_pages(&self, pfns: &[u32]) -> Result<(), BalloonError> {
        let queue = self
            .deflate_queue
            .as_ref()
            .ok_or(BalloonError::NotReady)?;
        self.submit_pfns(queue, pfns)
    }

    /// Read the target number of balloon pages from config space.
    ///
    /// The host writes `num_pages` to indicate the desired balloon size.
    /// The driver should inflate/deflate to match this target.
    pub fn read_target(&self) -> u32 {
        self.transport.read_config_u32(config_offsets::NUM_PAGES)
    }

    /// Write the actual number of balloon pages to config space.
    ///
    /// The driver updates `actual` to report how many pages it currently holds.
    pub fn write_actual(&self, pages: u32) {
        // Note: write_config_u32 requires &mut self on the transport trait, but our transport
        // is behind Box<dyn VirtioTransport> which is not &mut. The balloon device needs
        // to use the transport in a way that is safe for shared access. Since the transport
        // is only accessed from within VirtioBalloonDevice which is behind Arc<>,
        // and config writes are atomic MMIO operations, we use a pointer cast here.
        //
        // This is the same pattern used by other VirtIO drivers in this codebase where
        // interrupt handlers need to call transport methods with &self.
        let transport_ptr = &*self.transport as *const dyn VirtioTransport as *mut dyn VirtioTransport;
        unsafe {
            (*transport_ptr).write_config_u32(config_offsets::ACTUAL, pages);
        }
    }

    /// Handle interrupt from the balloon device.
    ///
    /// Checks for configuration change (interrupt status bit 1) and
    /// processes queue completions on both inflate and deflate queues,
    /// freeing inflight DMA buffers for completed requests.
    pub fn handle_interrupt(&self) {
        let interrupt_status = self.transport.get_interrupt_status();

        // Bit 0: used buffer notification (queue completion)
        let queue_interrupt = (interrupt_status & 0x01) != 0;
        // Bit 1: configuration change notification
        let config_change = (interrupt_status & 0x02) != 0;

        if config_change {
            let target = self.read_target();
            log::info!(
                "[VIRTIO-BALLOON] config change: target num_pages={}",
                target
            );
        }

        if queue_interrupt {
            // Process inflate queue completions
            if let Some(ref queue) = self.inflate_queue {
                let queue_guard = queue.lock();
                while let Some((desc_id, _len)) = queue_guard.poll_completions() {
                    // Free the inflight DMA buffer
                    self.inflight_buffers.lock().remove(&desc_id);
                    // Free descriptor
                    queue_guard.free_desc(desc_id);
                }
            }

            // Process deflate queue completions
            if let Some(ref queue) = self.deflate_queue {
                let queue_guard = queue.lock();
                while let Some((desc_id, _len)) = queue_guard.poll_completions() {
                    // Free the inflight DMA buffer
                    self.inflight_buffers.lock().remove(&desc_id);
                    // Free descriptor
                    queue_guard.free_desc(desc_id);
                }
            }
        }
    }

    /// Check if device is ready
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// Get negotiated features
    pub fn features(&self) -> u64 {
        self.features
    }
}

// ============================================================================
// Global Device Instance
// ============================================================================

/// Primary (legacy) VirtIO balloon device slot kept for compatibility (`index=0`).
pub(crate) static VIRTIO_BALLOON_DEVICE: crate::sync::PoisonLock<Option<Arc<VirtioBalloonDevice>>> = crate::sync::PoisonLock::new(None);

/// Additional VirtIO balloon devices (`index != 0`).
pub(crate) static VIRTIO_BALLOON_DEVICES: spin::RwLock<alloc::collections::BTreeMap<u8, Arc<VirtioBalloonDevice>>> =
    spin::RwLock::new(alloc::collections::BTreeMap::new());

fn install_virtio_balloon_device(index: u8, device_arc: Arc<VirtioBalloonDevice>) {
    if index == 0 {
        *VIRTIO_BALLOON_DEVICE.lock().unwrap_or_else(|e| e.into_inner()) = Some(device_arc);
    } else {
        VIRTIO_BALLOON_DEVICES.write().insert(index, device_arc);
    }
}

/// Get a shared reference to the VirtIO balloon device by index.
pub fn get_virtio_balloon_device_at_index(index: u8) -> Option<Arc<VirtioBalloonDevice>> {
    if index == 0 {
        VIRTIO_BALLOON_DEVICE.lock().unwrap_or_else(|e| e.into_inner()).clone()
    } else {
        VIRTIO_BALLOON_DEVICES.read().get(&index).cloned()
    }
}

/// Initialize the global VirtIO balloon device at a specific index.
pub unsafe fn init_virtio_balloon_at_index(index: u8, mmio_base: u64) -> Result<(), BalloonError> {
    let transport = unsafe {
        VirtioMmioTransport::new(mmio_base as usize).map_err(|_| BalloonError::NotReady)?
    };
    let mut dev = VirtioBalloonDevice::new(Box::new(transport));
    unsafe { dev.init()? };

    let device_arc = Arc::new(dev);

    log::info!(
        "VirtIO-balloon index={} initialized: target={} pages\n",
        index,
        device_arc.read_target()
    );

    install_virtio_balloon_device(index, device_arc);
    Ok(())
}

/// Initialize the global VirtIO balloon device (legacy `index=0`)
///
/// # Safety
/// Caller must ensure MMIO address is valid and device exists
pub unsafe fn init_virtio_balloon(mmio_base: u64) -> Result<(), BalloonError> {
    init_virtio_balloon_at_index(0, mmio_base)
}

/// Initialize the global VirtIO balloon device with an IOMMU device ID at a specific index.
pub unsafe fn init_virtio_balloon_for_device_at_index(
    index: u8,
    mmio_base: u64,
    device: IommuDeviceId,
) -> Result<(), BalloonError> {
    let transport = unsafe {
        VirtioMmioTransport::new(mmio_base as usize).map_err(|_| BalloonError::NotReady)?
    };
    let mut dev = VirtioBalloonDevice::new_with_device(Box::new(transport), Some(device));
    unsafe { dev.init()? };

    let device_arc = Arc::new(dev);

    log::info!(
        "VirtIO-balloon index={} initialized: target={} pages\n",
        index,
        device_arc.read_target()
    );

    install_virtio_balloon_device(index, device_arc);
    Ok(())
}

/// Initialize the global VirtIO balloon device with an IOMMU device ID (legacy `index=0`).
///
/// # Safety
/// Caller must ensure MMIO address is valid and device exists.
pub unsafe fn init_virtio_balloon_for_device(
    mmio_base: u64,
    device: IommuDeviceId,
) -> Result<(), BalloonError> {
    init_virtio_balloon_for_device_at_index(0, mmio_base, device)
}

/// Initialize the global VirtIO balloon device from an existing VirtioTransport at a specific index.
pub unsafe fn init_virtio_balloon_with_transport_at_index(
    index: u8,
    transport: Box<dyn VirtioTransport>,
    iommu_device_id: Option<IommuDeviceId>,
) -> Result<(), BalloonError> {
    let mut dev = VirtioBalloonDevice::new_with_device(transport, iommu_device_id);
    unsafe { dev.init()? };

    let device_arc = Arc::new(dev);

    log::info!(
        "VirtIO-balloon index={} initialized: target={} pages\n",
        index,
        device_arc.read_target()
    );

    install_virtio_balloon_device(index, device_arc);
    Ok(())
}

/// Initialize the global VirtIO balloon device from an existing VirtioTransport (MMIO or PCI).
///
/// # Safety
/// Caller must ensure the transport is properly initialized and points to a valid device.
pub unsafe fn init_virtio_balloon_with_transport(
    transport: Box<dyn VirtioTransport>,
    iommu_device_id: Option<IommuDeviceId>,
) -> Result<(), BalloonError> {
    init_virtio_balloon_with_transport_at_index(0, transport, iommu_device_id)
}

/// Handle VirtIO balloon device interrupt for a specific index.
pub fn handle_virtio_balloon_interrupt_for_index(index: u8) {
    if let Some(device) = get_virtio_balloon_device_at_index(index) {
        let status = device.transport.get_interrupt_status();
        device.transport.ack_interrupt(status);
        device.handle_interrupt();
    }
}

/// Handle VirtIO balloon device interrupt.
pub fn handle_virtio_balloon_interrupt() {
    handle_virtio_balloon_interrupt_for_index(0);
}

/// Get a clone of the global VirtioBalloon device Arc if initialized (legacy `index=0`).
pub fn get_virtio_balloon_device() -> Option<Arc<VirtioBalloonDevice>> {
    get_virtio_balloon_device_at_index(0)
}

use crate::util::align_up_usize as align_up;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests;
