// ============================================================================
// src/io/virtio/console.rs - VirtIO Console Device Driver
// ============================================================================
//!
//! VirtIO-consoleドライバ実装
//!
//! ## 設計原則 (仕様書 5.3準拠)
//! - VirtQueueを用いた非同期コンソールI/O
//! - RX (receiveq, queue 0): デバイスからゲストへのコンソールデータ
//! - TX (transmitq, queue 1): ゲストからデバイスへのコンソールデータ
//!
//! ## VirtIO Console Device Specification
//! - Feature bits, configuration space, queue layout
//! - Emergency write support (VIRTIO_CONSOLE_F_EMERG_WRITE)

#![allow(dead_code)]

use crate::io::dma::{CoherentDmaBuffer, DmaMemoryAttributes};
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use core::task::Waker;
use super::transport::{TransportType, VirtioMmioTransport, VirtioTransport};
use spin::Mutex;

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

/// VirtIO feature bits for console devices
pub mod features {
    /// Console size (cols, rows) is available in config space
    pub const VIRTIO_CONSOLE_F_SIZE: u64 = 1 << 0;
    /// Device supports multiple ports
    pub const VIRTIO_CONSOLE_F_MULTIPORT: u64 = 1 << 1;
    /// Device supports emergency write
    pub const VIRTIO_CONSOLE_F_EMERG_WRITE: u64 = 1 << 2;
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

/// Number of pre-posted RX buffers
const RX_BUFFER_COUNT: usize = 16;

/// Size of each RX buffer in bytes
const RX_BUFFER_SIZE: usize = 4096;

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
// Console Configuration
// ============================================================================

/// VirtIO console device configuration (from device config space)
#[derive(Clone, Debug)]
pub struct VirtioConsoleConfig {
    /// Console width in columns (valid if VIRTIO_CONSOLE_F_SIZE is negotiated)
    pub cols: u16,
    /// Console height in rows (valid if VIRTIO_CONSOLE_F_SIZE is negotiated)
    pub rows: u16,
    /// Maximum number of ports (valid if VIRTIO_CONSOLE_F_MULTIPORT is negotiated)
    pub max_nr_ports: u32,
}

impl Default for VirtioConsoleConfig {
    fn default() -> Self {
        Self {
            cols: 80,
            rows: 24,
            max_nr_ports: 1,
        }
    }
}

// ============================================================================
// Console Error Types
// ============================================================================

/// Console device error types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsoleError {
    /// Device not ready
    NotReady,
    /// I/O error from device
    IoError,
    /// Queue full
    QueueFull,
    /// Unsupported operation
    Unsupported,
}

// ============================================================================
// VirtIO Console Device
// ============================================================================

/// VirtIO console device driver
pub struct VirtioConsoleDevice {
    /// Transport layer (MMIO or PCI)
    transport: Box<dyn VirtioTransport>,
    /// Device configuration
    config: VirtioConsoleConfig,
    /// Receive queue (queue 0)
    rx_queue: Option<Arc<Mutex<VirtQueue>>>,
    /// Transmit queue (queue 1)
    tx_queue: Option<Arc<Mutex<VirtQueue>>>,
    /// Pre-posted RX DMA buffers keyed by descriptor index
    rx_buffers: Mutex<BTreeMap<u16, CoherentDmaBuffer>>,
    /// TX DMA buffers awaiting completion keyed by descriptor index
    tx_inflight: Mutex<BTreeMap<u16, CoherentDmaBuffer>>,
    /// Pending wakers for async notification
    pending_wakers: Mutex<Vec<Option<Waker>>>,
    /// Device ready flag
    ready: AtomicBool,
    /// Optional IOMMU device identifier for device-scoped mappings
    iommu_device_id: Option<IommuDeviceId>,
    /// Features negotiated
    features: u64,
}

unsafe impl Send for VirtioConsoleDevice {}
unsafe impl Sync for VirtioConsoleDevice {}

impl VirtioConsoleDevice {
    /// Create a new VirtIO console device (uninitialized)
    ///
    /// The transport must already be validated (magic/version checks).
    pub fn new(transport: Box<dyn VirtioTransport>) -> Self {
        Self::new_with_device(transport, None)
    }

    /// Create a new VirtIO console device with an IOMMU device ID.
    pub fn new_with_device(
        transport: Box<dyn VirtioTransport>,
        iommu_device_id: Option<IommuDeviceId>,
    ) -> Self {
        Self {
            transport,
            config: VirtioConsoleConfig::default(),
            rx_queue: None,
            tx_queue: None,
            rx_buffers: Mutex::new(BTreeMap::new()),
            tx_inflight: Mutex::new(BTreeMap::new()),
            pending_wakers: Mutex::new(Vec::new()),
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

    /// Initialize the device following the VirtIO initialization sequence.
    ///
    /// # Safety
    /// Caller must ensure MMIO address is valid and device exists.
    pub unsafe fn init(&mut self) -> Result<(), ConsoleError> {
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
            & (features::VIRTIO_CONSOLE_F_SIZE
                | features::VIRTIO_CONSOLE_F_MULTIPORT
                | features::VIRTIO_CONSOLE_F_EMERG_WRITE);
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
            return Err(ConsoleError::NotReady);
        }

        // Step 6: Read configuration
        self.read_config()?;

        // Step 7: Setup queues (RX = queue 0, TX = queue 1)
        self.setup_queue(0)?;
        self.setup_queue(1)?;

        // Initialize pending wakers
        let mut wakers = self.pending_wakers.lock();
        wakers.resize(VIRTQUEUE_MAX_SIZE as usize * 2, None);
        drop(wakers);

        // Step 8: Driver OK
        self.transport.set_status(
            VirtioDeviceStatus::Acknowledge as u8
                | VirtioDeviceStatus::Driver as u8
                | VirtioDeviceStatus::FeaturesOk as u8
                | VirtioDeviceStatus::DriverOk as u8,
        );

        self.ready.store(true, Ordering::Release);

        // Pre-post RX buffers so the device can immediately send data
        self.post_rx_buffers()?;

        Ok(())
    }

    /// Read device configuration from config space.
    fn read_config(&mut self) -> Result<(), ConsoleError> {
        // Read cols (u16 at offset 0) and rows (u16 at offset 2)
        // if VIRTIO_CONSOLE_F_SIZE is negotiated
        if self.features & features::VIRTIO_CONSOLE_F_SIZE != 0 {
            self.config.cols = self.transport.read_config_u16(0);
            self.config.rows = self.transport.read_config_u16(2);
        }

        // Read max_nr_ports (u32 at offset 4)
        // if VIRTIO_CONSOLE_F_MULTIPORT is negotiated
        if self.features & features::VIRTIO_CONSOLE_F_MULTIPORT != 0 {
            self.config.max_nr_ports = self.transport.read_config_u32(4);
        }

        Ok(())
    }

    /// Setup a virtqueue (same pattern as blk.rs)
    fn setup_queue(&mut self, queue_idx: u16) -> Result<(), ConsoleError> {
        // Select queue and read size
        self.transport.select_queue(queue_idx);
        let max_size = self.transport.get_queue_max_size();

        if max_size == 0 {
            return Err(ConsoleError::NotReady);
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
        .ok_or(ConsoleError::NotReady)?;

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

        let queue_arc = Arc::new(Mutex::new(virtqueue));

        if queue_idx == 0 {
            self.rx_queue = Some(queue_arc);
        } else {
            self.tx_queue = Some(queue_arc);
        }

        Ok(())
    }

    /// Pre-post RX buffers to the receive queue so the device can immediately
    /// write console data into them. Posts RX_BUFFER_COUNT buffers of
    /// RX_BUFFER_SIZE bytes each.
    fn post_rx_buffers(&self) -> Result<(), ConsoleError> {
        let rx_queue = self.rx_queue.as_ref().ok_or(ConsoleError::NotReady)?;
        let queue_guard = rx_queue.lock();

        for _ in 0..RX_BUFFER_COUNT {
            let buffer = self.alloc_coherent(RX_BUFFER_SIZE, DmaMemoryAttributes::MMIO)
                .ok_or(ConsoleError::NotReady)?;
            let phys_addr = buffer.device_addr();

            // Allocate a descriptor for this RX buffer
            let desc_idx = queue_guard.alloc_desc().ok_or(ConsoleError::QueueFull)?;

            // Configure descriptor: device writes into this buffer
            unsafe {
                (*queue_guard.desc_table.add(desc_idx as usize)) = VringDesc {
                    addr: phys_addr,
                    len: RX_BUFFER_SIZE as u32,
                    flags: vring_flags::VRING_DESC_F_WRITE,
                    next: 0,
                };

                // Submit to available ring
                queue_guard.submit(desc_idx);
            }

            // Track the DMA buffer
            self.rx_buffers.lock().insert(desc_idx, buffer);
        }

        // Notify device that RX buffers are available
        queue_guard.notify();

        Ok(())
    }

    /// Write bytes to the console via the TX queue.
    ///
    /// Allocates a CoherentDmaBuffer, copies the data, submits to the TX queue,
    /// and notifies the device.
    pub fn write_bytes(&self, data: &[u8]) -> Result<(), ConsoleError> {
        if !self.is_ready() {
            return Err(ConsoleError::NotReady);
        }

        if data.is_empty() {
            return Ok(());
        }

        let tx_queue = self.tx_queue.as_ref().ok_or(ConsoleError::NotReady)?;
        let queue_guard = tx_queue.lock();

        // Allocate a DMA buffer and copy the data (IOMMU-aware)
        let mut buffer = self.alloc_coherent(data.len(), DmaMemoryAttributes::MMIO)
            .ok_or(ConsoleError::NotReady)?;
        let phys_addr = buffer.device_addr();

        unsafe {
            let dst = buffer.as_mut_slice();
            dst[..data.len()].copy_from_slice(data);
        }

        // Allocate a descriptor
        let desc_idx = queue_guard.alloc_desc().ok_or(ConsoleError::QueueFull)?;

        // Configure descriptor: device reads from this buffer
        unsafe {
            (*queue_guard.desc_table.add(desc_idx as usize)) = VringDesc {
                addr: phys_addr,
                len: data.len() as u32,
                flags: 0, // Device reads (no WRITE flag)
                next: 0,
            };

            // Submit to available ring
            queue_guard.submit(desc_idx);
        }

        // Track the inflight TX buffer
        self.tx_inflight.lock().insert(desc_idx, buffer);

        // Notify device
        queue_guard.notify();

        Ok(())
    }

    /// Read bytes from the console by polling the RX queue for completed buffers.
    ///
    /// Returns `Some(data)` if data is available, `None` otherwise.
    /// After reading, reposts a fresh RX buffer to the queue.
    pub fn read_bytes(&self) -> Option<Vec<u8>> {
        let rx_queue = self.rx_queue.as_ref()?;
        let queue_guard = rx_queue.lock();

        // Poll for a completed RX buffer
        let (desc_id, len) = queue_guard.poll_completions()?;

        // Extract the DMA buffer
        let buffer = self.rx_buffers.lock().remove(&desc_id)?;

        // Copy received data out
        let received_len = len as usize;
        let data = unsafe {
            let slice = buffer.as_slice();
            let copy_len = core::cmp::min(received_len, slice.len());
            slice[..copy_len].to_vec()
        };

        // Free the descriptor
        queue_guard.free_desc(desc_id);

        // Drop the old buffer (it is consumed)
        drop(buffer);

        // Repost a fresh RX buffer (IOMMU-aware)
        if let Ok(new_buffer) =
            self.alloc_coherent(RX_BUFFER_SIZE, DmaMemoryAttributes::MMIO).ok_or(())
        {
            let phys_addr = new_buffer.device_addr();
            if let Some(new_desc) = queue_guard.alloc_desc() {
                unsafe {
                    (*queue_guard.desc_table.add(new_desc as usize)) = VringDesc {
                        addr: phys_addr,
                        len: RX_BUFFER_SIZE as u32,
                        flags: vring_flags::VRING_DESC_F_WRITE,
                        next: 0,
                    };
                    queue_guard.submit(new_desc);
                }
                self.rx_buffers.lock().insert(new_desc, new_buffer);
                queue_guard.notify();
            }
        }

        Some(data)
    }

    /// Handle interrupt from the VirtIO console device.
    ///
    /// Processes TX completions (freeing inflight buffers) and RX completions
    /// (extracting data and reposting buffers), then wakes any pending futures.
    pub fn handle_interrupt(&self) {
        // Process TX queue completions
        self.process_tx_completions();

        // Process RX queue completions
        self.process_rx_wakeups();
    }

    fn process_tx_completions(&self) {
        if let Some(ref tx_queue) = self.tx_queue {
            let queue_guard = tx_queue.lock();
            while let Some((desc_id, _len)) = queue_guard.poll_completions() {
                // Free the inflight DMA buffer
                if let Some(_buf) = self.tx_inflight.lock().remove(&desc_id) {
                    // Buffer dropped here, freeing the DMA allocation
                }

                // Free descriptor
                queue_guard.free_desc(desc_id);

                // Wake pending future
                let waker_idx = VIRTQUEUE_MAX_SIZE as usize + desc_id as usize;
                let mut wakers = self.pending_wakers.lock();
                if let Some(waker) = wakers.get_mut(waker_idx).and_then(|w| w.take()) {
                    waker.wake();
                }
            }
        }
    }

    fn process_rx_wakeups(&self) {
        // Note: RX completions are typically consumed via read_bytes(), but
        // we also wake any async waiters here so they can poll.
        if let Some(ref rx_queue) = self.rx_queue {
            let queue_guard = rx_queue.lock();
            // Peek: check if there are pending completions without consuming them,
            // since read_bytes() will consume them. We just wake the waiters.
            let last_used = queue_guard.last_used_idx.load(Ordering::Acquire);
            let used_idx = unsafe { (*queue_guard.used_ring).idx } as u32;
            if last_used != used_idx {
                // There are unprocessed RX completions - wake waiters
                let mut wakers = self.pending_wakers.lock();
                for slot in wakers.iter_mut().take(VIRTQUEUE_MAX_SIZE as usize) {
                    if let Some(waker) = slot.take() {
                        waker.wake();
                    }
                }
            }
        }
    }

    /// Get device configuration.
    pub fn config(&self) -> &VirtioConsoleConfig {
        &self.config
    }

    /// Check if device is ready.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// Perform an emergency write of a single byte if the EMERG_WRITE feature
    /// is supported. This writes directly to the `emerg_wr` config register
    /// at offset 8 and does not require queue initialization.
    pub fn emergency_write(&self, c: u8) {
        if self.features & features::VIRTIO_CONSOLE_F_EMERG_WRITE != 0 {
            // emerg_wr is a u32 at config space offset 8.
            // Write the character in the low byte.
            // Use pointer cast since transport.write_config_u32 requires &mut self
            // but config writes are atomic MMIO operations safe for shared access.
            let transport_ptr = &*self.transport as *const dyn VirtioTransport as *mut dyn VirtioTransport;
            unsafe {
                (*transport_ptr).write_config_u32(8, c as u32);
            }
        }
    }
}

// ============================================================================
// Global Device Instance
// ============================================================================

/// Global VirtIO console device instance (stored in an Arc for shared access)
static VIRTIO_CONSOLE_DEVICE: Mutex<Option<Arc<VirtioConsoleDevice>>> = Mutex::new(None);

/// Initialize the global VirtIO console device.
///
/// # Safety
/// Caller must ensure MMIO address is valid and device exists.
pub unsafe fn init_virtio_console(mmio_base: u64) -> Result<(), ConsoleError> {
    let transport = unsafe {
        VirtioMmioTransport::new(mmio_base as usize).map_err(|_| ConsoleError::NotReady)?
    };
    let mut dev = VirtioConsoleDevice::new(Box::new(transport));
    unsafe { dev.init()? };

    let device_arc = Arc::new(dev);

    log::info!(
        "VirtIO-console initialized: {}x{} (cols x rows)\n",
        device_arc.config().cols,
        device_arc.config().rows
    );

    *VIRTIO_CONSOLE_DEVICE.lock() = Some(Arc::clone(&device_arc));
    Ok(())
}

/// Initialize the global VirtIO console device with an IOMMU device ID.
///
/// # Safety
/// Caller must ensure MMIO address is valid and device exists.
pub unsafe fn init_virtio_console_for_device(
    mmio_base: u64,
    device: IommuDeviceId,
) -> Result<(), ConsoleError> {
    let transport = unsafe {
        VirtioMmioTransport::new(mmio_base as usize).map_err(|_| ConsoleError::NotReady)?
    };
    let mut dev = VirtioConsoleDevice::new_with_device(Box::new(transport), Some(device));
    unsafe { dev.init()? };

    let device_arc = Arc::new(dev);

    log::info!(
        "VirtIO-console initialized: {}x{} (cols x rows)\n",
        device_arc.config().cols,
        device_arc.config().rows
    );

    *VIRTIO_CONSOLE_DEVICE.lock() = Some(Arc::clone(&device_arc));
    Ok(())
}

/// Initialize the global VirtIO console device from an existing VirtioTransport (MMIO or PCI).
///
/// # Safety
/// Caller must ensure the transport is properly initialized and points to a valid device.
pub unsafe fn init_virtio_console_with_transport(
    transport: Box<dyn VirtioTransport>,
    iommu_device_id: Option<IommuDeviceId>,
) -> Result<(), ConsoleError> {
    let mut dev = VirtioConsoleDevice::new_with_device(transport, iommu_device_id);
    unsafe { dev.init()? };

    let device_arc = Arc::new(dev);

    log::info!(
        "VirtIO-console initialized: {}x{} (cols x rows)\n",
        device_arc.config().cols,
        device_arc.config().rows
    );

    *VIRTIO_CONSOLE_DEVICE.lock() = Some(Arc::clone(&device_arc));
    Ok(())
}

/// Handle VirtIO console device interrupt.
pub fn handle_virtio_console_interrupt() {
    if let Some(device) = VIRTIO_CONSOLE_DEVICE.lock().as_ref() {
        // Ack interrupt with shared reference
        let status = device.transport.get_interrupt_status();
        device.transport.ack_interrupt(status);
        device.handle_interrupt();
    }
}

/// Get a clone of the global VirtIO console device Arc if initialized.
pub fn get_virtio_console_device() -> Option<Arc<VirtioConsoleDevice>> {
    VIRTIO_CONSOLE_DEVICE.lock().as_ref().cloned()
}

/// Align `val` up to the nearest multiple of `align`.
fn align_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests;
