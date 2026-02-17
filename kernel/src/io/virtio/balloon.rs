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
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
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
// VirtQueue Implementation (local to balloon)
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

    /// IOMMU対応のDMAバッファを割り当てるヘルパー。
    fn alloc_coherent(
        &self,
        size: usize,
        attrs: DmaMemoryAttributes,
    ) -> Option<CoherentDmaBuffer> {
        match &self.iommu_device_id {
            Some(dev_id) => CoherentDmaBuffer::new_for_device(size, attrs, dev_id),
            None => CoherentDmaBuffer::new(size, attrs),
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
        let used_align = core::mem::align_of::<VringUsed>();
        let used_offset = align_up(desc_size + avail_size, used_align);
        let total_size = used_offset + used_size;

        // Use CoherentDmaBuffer for shared queue memory (IOMMU-aware)
        let buffer = self.alloc_coherent(
            total_size,
            crate::io::dma::DmaMemoryAttributes::MMIO,
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
        let mut dma_buf = self.alloc_coherent(byte_len, DmaMemoryAttributes::MMIO)
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

/// Global VirtIO balloon device instance (stored in an Arc for shared access)
static VIRTIO_BALLOON_DEVICE: Mutex<Option<Arc<VirtioBalloonDevice>>> = Mutex::new(None);

/// Initialize the global VirtIO balloon device
///
/// # Safety
/// Caller must ensure MMIO address is valid and device exists
pub unsafe fn init_virtio_balloon(mmio_base: u64) -> Result<(), BalloonError> {
    let transport = unsafe {
        VirtioMmioTransport::new(mmio_base as usize).map_err(|_| BalloonError::NotReady)?
    };
    let mut dev = VirtioBalloonDevice::new(Box::new(transport));
    unsafe { dev.init()? };

    let device_arc = Arc::new(dev);

    log::info!(
        "VirtIO-balloon initialized: target={} pages\n",
        device_arc.read_target()
    );

    *VIRTIO_BALLOON_DEVICE.lock() = Some(Arc::clone(&device_arc));
    Ok(())
}

/// Initialize the global VirtIO balloon device with an IOMMU device ID.
///
/// # Safety
/// Caller must ensure MMIO address is valid and device exists.
pub unsafe fn init_virtio_balloon_for_device(
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
        "VirtIO-balloon initialized: target={} pages\n",
        device_arc.read_target()
    );

    *VIRTIO_BALLOON_DEVICE.lock() = Some(Arc::clone(&device_arc));
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
    let mut dev = VirtioBalloonDevice::new_with_device(transport, iommu_device_id);
    unsafe { dev.init()? };

    let device_arc = Arc::new(dev);

    log::info!(
        "VirtIO-balloon initialized: target={} pages\n",
        device_arc.read_target()
    );

    *VIRTIO_BALLOON_DEVICE.lock() = Some(Arc::clone(&device_arc));
    Ok(())
}

/// Handle VirtIO balloon device interrupt
pub fn handle_virtio_balloon_interrupt() {
    if let Some(device) = VIRTIO_BALLOON_DEVICE.lock().as_ref() {
        let status = device.transport.get_interrupt_status();
        device.transport.ack_interrupt(status);
        device.handle_interrupt();
    }
}

/// Get a clone of the global VirtioBalloon device Arc if initialized
pub fn get_virtio_balloon_device() -> Option<Arc<VirtioBalloonDevice>> {
    VIRTIO_BALLOON_DEVICE.lock().as_ref().cloned()
}

fn align_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec;
    use core::sync::atomic::Ordering;

    use super::*;
    use crate::io::virtio::{TransportType, VirtioDeviceType, VirtioTransport};

    /// Noop transport for unit-testing balloon without real hardware
    struct NoopTransport {
        /// Simulated config space (at least 8 bytes for num_pages + actual)
        config: [u8; 16],
    }

    impl NoopTransport {
        fn new() -> Self {
            Self { config: [0u8; 16] }
        }

        /// Create a transport with a pre-set target num_pages value
        fn with_target(num_pages: u32) -> Self {
            let mut config = [0u8; 16];
            config[0..4].copy_from_slice(&num_pages.to_le_bytes());
            Self { config }
        }
    }

    impl VirtioTransport for NoopTransport {
        fn device_type(&self) -> VirtioDeviceType {
            VirtioDeviceType::Balloon
        }

        fn get_status(&self) -> u8 {
            // Return FeaturesOk to allow init to succeed
            VirtioDeviceStatus::Acknowledge as u8
                | VirtioDeviceStatus::Driver as u8
                | VirtioDeviceStatus::FeaturesOk as u8
        }

        fn set_status(&mut self, _status: u8) {}

        fn get_device_features_low(&self) -> u32 {
            (features::VIRTIO_BALLOON_F_MUST_TELL_HOST
                | features::VIRTIO_BALLOON_F_DEFLATE_ON_OOM) as u32
        }

        fn get_device_features_high(&self) -> u32 {
            0
        }

        fn set_driver_features_low(&mut self, _features: u32) {}

        fn set_driver_features_high(&mut self, _features: u32) {}

        fn get_num_queues(&self) -> u16 {
            2
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

        fn read_config_u8(&self, offset: usize) -> u8 {
            if offset < self.config.len() {
                self.config[offset]
            } else {
                0
            }
        }

        fn read_config_u16(&self, offset: usize) -> u16 {
            if offset + 1 < self.config.len() {
                u16::from_le_bytes([self.config[offset], self.config[offset + 1]])
            } else {
                0
            }
        }

        fn read_config_u32(&self, offset: usize) -> u32 {
            if offset + 3 < self.config.len() {
                u32::from_le_bytes([
                    self.config[offset],
                    self.config[offset + 1],
                    self.config[offset + 2],
                    self.config[offset + 3],
                ])
            } else {
                0
            }
        }

        fn write_config_u8(&mut self, offset: usize, value: u8) {
            if offset < self.config.len() {
                self.config[offset] = value;
            }
        }

        fn write_config_u16(&mut self, offset: usize, value: u16) {
            if offset + 1 < self.config.len() {
                let bytes = value.to_le_bytes();
                self.config[offset] = bytes[0];
                self.config[offset + 1] = bytes[1];
            }
        }

        fn write_config_u32(&mut self, offset: usize, value: u32) {
            if offset + 3 < self.config.len() {
                let bytes = value.to_le_bytes();
                self.config[offset] = bytes[0];
                self.config[offset + 1] = bytes[1];
                self.config[offset + 2] = bytes[2];
                self.config[offset + 3] = bytes[3];
            }
        }

        fn transport_type(&self) -> TransportType {
            TransportType::Mmio
        }
    }

    /// Helper: create a VirtioBalloonDevice with manually wired queues
    /// (bypasses hardware init, directly injects VirtQueues)
    fn make_test_device(transport: NoopTransport) -> (VirtioBalloonDevice, TestQueues) {
        let queue_size: u16 = 8;

        // Inflate queue memory
        let mut inflate_descs = vec![VringDesc::default(); queue_size as usize];
        let inflate_desc_ptr = inflate_descs.as_mut_ptr();
        let mut inflate_avail = vec![0u16; 2 + queue_size as usize];
        let inflate_avail_ptr = inflate_avail.as_mut_ptr() as *mut VringAvail;
        let inflate_used_bytes = core::mem::size_of::<VringUsed>()
            + (queue_size as usize) * core::mem::size_of::<VringUsedElem>();
        let mut inflate_used_mem = vec![0u8; inflate_used_bytes];
        let inflate_used_ptr = inflate_used_mem.as_mut_ptr() as *mut VringUsed;

        let inflate_vq = unsafe {
            VirtQueue::new(
                queue_size,
                inflate_desc_ptr,
                inflate_avail_ptr,
                inflate_used_ptr,
                None,
                0,
                None,
                false,
            )
        };

        // Deflate queue memory
        let mut deflate_descs = vec![VringDesc::default(); queue_size as usize];
        let deflate_desc_ptr = deflate_descs.as_mut_ptr();
        let mut deflate_avail = vec![0u16; 2 + queue_size as usize];
        let deflate_avail_ptr = deflate_avail.as_mut_ptr() as *mut VringAvail;
        let deflate_used_bytes = core::mem::size_of::<VringUsed>()
            + (queue_size as usize) * core::mem::size_of::<VringUsedElem>();
        let mut deflate_used_mem = vec![0u8; deflate_used_bytes];
        let deflate_used_ptr = deflate_used_mem.as_mut_ptr() as *mut VringUsed;

        let deflate_vq = unsafe {
            VirtQueue::new(
                queue_size,
                deflate_desc_ptr,
                deflate_avail_ptr,
                deflate_used_ptr,
                None,
                1,
                None,
                false,
            )
        };

        let mut dev = VirtioBalloonDevice::new(Box::new(transport));
        dev.inflate_queue = Some(Arc::new(Mutex::new(inflate_vq)));
        dev.deflate_queue = Some(Arc::new(Mutex::new(deflate_vq)));
        dev.ready.store(true, Ordering::Release);

        let queues = TestQueues {
            inflate_descs,
            inflate_avail,
            inflate_used_mem,
            inflate_desc_ptr,
            deflate_descs,
            deflate_avail,
            deflate_used_mem,
            deflate_desc_ptr,
        };

        (dev, queues)
    }

    /// Holds Vec ownership so queue memory stays alive for the test
    #[allow(dead_code)]
    struct TestQueues {
        inflate_descs: Vec<VringDesc>,
        inflate_avail: Vec<u16>,
        inflate_used_mem: Vec<u8>,
        inflate_desc_ptr: *mut VringDesc,
        deflate_descs: Vec<VringDesc>,
        deflate_avail: Vec<u16>,
        deflate_used_mem: Vec<u8>,
        deflate_desc_ptr: *mut VringDesc,
    }

    #[test_case]
    fn test_balloon_device_creation() {
        let transport = NoopTransport::new();
        let dev = VirtioBalloonDevice::new(Box::new(transport));
        assert!(!dev.is_ready());
        assert_eq!(dev.features(), 0);
    }

    #[test_case]
    fn test_balloon_read_target() {
        let transport = NoopTransport::with_target(1024);
        let dev = VirtioBalloonDevice::new(Box::new(transport));
        assert_eq!(dev.read_target(), 1024);
    }

    #[test_case]
    fn test_balloon_write_actual() {
        let transport = NoopTransport::new();
        let dev = VirtioBalloonDevice::new(Box::new(transport));
        dev.write_actual(512);
        // Read back from config space offset 4
        let actual = dev.transport.read_config_u32(config_offsets::ACTUAL);
        assert_eq!(actual, 512);
    }

    #[test_case]
    fn test_balloon_inflate_not_ready() {
        let transport = NoopTransport::new();
        let dev = VirtioBalloonDevice::new(Box::new(transport));
        // Device is not ready, inflate should fail with NotReady
        let pfns = [0x1000u32, 0x2000, 0x3000];
        assert_eq!(dev.inflate_pages(&pfns), Err(BalloonError::NotReady));
    }

    #[test_case]
    fn test_balloon_inflate_empty_pfns() {
        let transport = NoopTransport::new();
        let (dev, _queues) = make_test_device(transport);
        // Empty PFN array should succeed without submitting
        assert_eq!(dev.inflate_pages(&[]), Ok(()));
    }

    #[test_case]
    fn test_balloon_inflate_submits_descriptor() {
        let transport = NoopTransport::new();
        let (dev, queues) = make_test_device(transport);

        let pfns = [0x100u32, 0x200, 0x300];
        let result = dev.inflate_pages(&pfns);
        assert_eq!(result, Ok(()));

        // Verify descriptor was written
        let desc = unsafe { *queues.inflate_desc_ptr.add(0) };
        assert_eq!(desc.len, (3 * core::mem::size_of::<u32>()) as u32);
        // Should be readable (no WRITE flag)
        assert_eq!(desc.flags & vring_flags::VRING_DESC_F_WRITE, 0);

        // Verify inflight buffer is tracked
        assert!(dev.inflight_buffers.lock().contains_key(&0));
    }

    #[test_case]
    fn test_balloon_deflate_submits_descriptor() {
        let transport = NoopTransport::new();
        let (dev, queues) = make_test_device(transport);

        let pfns = [0x400u32, 0x500];
        let result = dev.deflate_pages(&pfns);
        assert_eq!(result, Ok(()));

        // Verify descriptor was written on deflate queue
        let desc = unsafe { *queues.deflate_desc_ptr.add(0) };
        assert_eq!(desc.len, (2 * core::mem::size_of::<u32>()) as u32);
        assert_eq!(desc.flags & vring_flags::VRING_DESC_F_WRITE, 0);
    }

    #[test_case]
    fn test_balloon_feature_bits() {
        assert_eq!(features::VIRTIO_BALLOON_F_MUST_TELL_HOST, 1 << 0);
        assert_eq!(features::VIRTIO_BALLOON_F_STATS_VQ, 1 << 1);
        assert_eq!(features::VIRTIO_BALLOON_F_DEFLATE_ON_OOM, 1 << 2);
        assert_eq!(features::VIRTIO_BALLOON_F_FREE_PAGE_HINT, 1 << 3);
        assert_eq!(features::VIRTIO_BALLOON_F_PAGE_REPORTING, 1 << 5);
    }

    #[test_case]
    fn test_balloon_error_variants() {
        assert_ne!(BalloonError::NotReady, BalloonError::IoError);
        assert_ne!(BalloonError::QueueFull, BalloonError::AllocFailed);
    }

    #[test_case]
    fn test_balloon_handle_interrupt_no_panic() {
        let transport = NoopTransport::new();
        let (dev, _queues) = make_test_device(transport);
        // Should not panic even with no completions
        dev.handle_interrupt();
    }

    #[test_case]
    fn test_balloon_align_up() {
        assert_eq!(align_up(0, 4), 0);
        assert_eq!(align_up(1, 4), 4);
        assert_eq!(align_up(4, 4), 4);
        assert_eq!(align_up(5, 4), 8);
        assert_eq!(align_up(4096, 4096), 4096);
        assert_eq!(align_up(4097, 4096), 8192);
    }
}
