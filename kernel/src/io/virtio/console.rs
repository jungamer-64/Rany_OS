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
use crate::io::virtio::transport::{TransportType, VirtioMmioTransport, VirtioTransport};
use crate::io::virtio::virtqueue::*;
use crate::sync::PoisonLock;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::Waker;

// ============================================================================
// VirtIO Common Definitions
// ============================================================================

use crate::io::virtio::VirtioDeviceStatus;

mod global_init;
pub use global_init::*;

pub use virtio_driver::console::{ConsoleError, VirtioConsoleConfig, features, device::VirtioConsoleDevice as CoreConsoleDevice};

// ============================================================================
// VirtIO Console Device
// ============================================================================

/// Number of pre-posted RX buffers
const RX_BUFFER_COUNT: usize = 16;

/// Size of each RX buffer in bytes
const RX_BUFFER_SIZE: usize = 4096;

/// VirtIO console device driver
#[derive(Debug)]
pub struct VirtioConsoleDevice {
    /// Transport layer (MMIO or PCI)
    transport: Box<dyn VirtioTransport>,
    /// Receive queue (queue 0)
    rx_queue: Option<Arc<PoisonLock<VirtQueue>>>,
    /// Transmit queue (queue 1)
    tx_queue: Option<Arc<PoisonLock<VirtQueue>>>,
    /// Pre-posted RX DMA buffers keyed by descriptor index
    rx_buffers: PoisonLock<BTreeMap<u16, CoherentDmaBuffer>>,
    /// TX DMA buffers awaiting completion keyed by descriptor index
    tx_inflight: PoisonLock<BTreeMap<u16, CoherentDmaBuffer>>,
    /// Pending wakers for async notification
    pending_wakers: PoisonLock<BTreeMap<usize, Waker>>,
    /// Shared core device logic
    core: CoreConsoleDevice,
    /// Device ready flag
    ready: AtomicBool,
    /// Optional IOMMU device identifier for device-scoped mappings
    iommu_device_id: Option<IommuDeviceId>,
}

unsafe impl Send for VirtioConsoleDevice {}
unsafe impl Sync for VirtioConsoleDevice {}

/// VirtIO Console Configuration space offsets
pub mod config_offsets {
    pub const COLS: usize = 0;
    pub const ROWS: usize = 2;
    pub const MAX_NR_PORTS: usize = 4;
    pub const EMERG_WR: usize = 8;
}

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
            core: CoreConsoleDevice::default(),
            rx_queue: None,
            tx_queue: None,
            rx_buffers: PoisonLock::new(BTreeMap::new()),
            tx_inflight: PoisonLock::new(BTreeMap::new()),
            pending_wakers: PoisonLock::new(BTreeMap::new()),
            ready: AtomicBool::new(false),
            iommu_device_id,
        }
    }

    /// Initialize the device following the VirtIO initialization sequence.
    pub fn init(&mut self) -> Result<(), ConsoleError> {
        // Step 1-6: Perform common VirtIO initialization using shared core
        self.core.init(self.transport.as_ref()).map_err(|_| ConsoleError::NotReady)?;

        // Step 7: Setup queues (RX = queue 0, TX = queue 1)
        self.setup_queue(0)?;
        self.setup_queue(1)?;

        // Step 8: Driver OK
        self.transport.add_status(crate::io::virtio::status::VIRTIO_STATUS_DRIVER_OK);

        self.ready.store(true, Ordering::Release);

        // Pre-post RX buffers so the device can immediately send data
        self.post_rx_buffers()?;

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
        let _notify_addr = self.transport.get_notify_addr(queue_idx);
        let _notify_is_32bit = matches!(self.transport.transport_type(), TransportType::Mmio);

        // Standardized layout calculation
        let (desc_size, _avail_size, used_offset, total_size) =
            VirtQueue::calculate_layout(queue_size);

        // Use CoherentDmaBuffer for shared queue memory (IOMMU-aware)
        let buffer = crate::io::virtio::dma::alloc_virtio_dma_buffer(
            total_size,
            crate::io::dma::DmaMemoryAttributes::MMIO,
            self.iommu_device_id.as_ref(),
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

        let queue_arc = Arc::new(PoisonLock::new(virtqueue));

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
        let mut queue_guard = rx_queue.lock().expect("rx_queue lock poisoned");

        for _ in 0..RX_BUFFER_COUNT {
            let buffer = crate::io::virtio::dma::alloc_virtio_dma_buffer(
                RX_BUFFER_SIZE,
                DmaMemoryAttributes::MMIO,
                self.iommu_device_id.as_ref(),
            )
            .ok_or(ConsoleError::NotReady)?;
            let phys_addr = buffer.device_addr();

            // Allocate a descriptor for this RX buffer
            let desc_idx = queue_guard.alloc_desc().ok_or(ConsoleError::QueueFull)?;

            // Configure descriptor: device writes into this buffer
            unsafe {
                let desc_table = queue_guard.desc_table_ptr();
                (*desc_table.add(desc_idx as usize)) = VringDesc {
                    addr: phys_addr,
                    len: RX_BUFFER_SIZE as u32,
                    flags: vring_flags::VRING_DESC_F_WRITE,
                    next: 0,
                };

                // Submit to available ring
                queue_guard.submit(desc_idx);
            }

            // Track the DMA buffer
            self.rx_buffers
                .lock()
                .expect("rx_buffers lock poisoned")
                .insert(desc_idx, buffer);
        }

        // Notify device that RX buffers are available
        queue_guard.notify(&*self.transport);

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
        let mut queue_guard = tx_queue.lock().expect("tx_queue lock poisoned");

        // Allocate a DMA buffer and copy the data (IOMMU-aware)
        let mut buffer = crate::io::virtio::dma::alloc_virtio_dma_buffer(
            data.len(),
            DmaMemoryAttributes::MMIO,
            self.iommu_device_id.as_ref(),
        )
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
            let desc_table = queue_guard.desc_table_ptr();
            (*desc_table.add(desc_idx as usize)) = VringDesc {
                addr: phys_addr,
                len: data.len() as u32,
                flags: 0, // Device reads (no WRITE flag)
                next: 0,
            };

            // Submit to available ring
            queue_guard.submit(desc_idx);
        }

        // Track the inflight TX buffer
        self.tx_inflight
            .lock()
            .expect("tx_inflight lock poisoned")
            .insert(desc_idx, buffer);

        // Notify device
        queue_guard.notify(&*self.transport);

        Ok(())
    }

    /// Read bytes from the console by polling the RX queue for completed buffers.
    ///
    /// Returns `Some(data)` if data is available, `None` otherwise.
    /// After reading, reposts a fresh RX buffer to the queue.
    pub fn read_bytes(&self) -> Option<Vec<u8>> {
        let rx_queue = self.rx_queue.as_ref()?;
        let mut queue_guard = rx_queue.lock().expect("rx_queue lock poisoned");

        // Poll for a completed RX buffer
        let (desc_id, len) = queue_guard.poll_complete()?;

        // Extract the DMA buffer
        let buffer = self
            .rx_buffers
            .lock()
            .expect("rx_buffers lock poisoned")
            .remove(&desc_id)?;

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
        let new_buffer_opt = crate::io::virtio::dma::alloc_virtio_dma_buffer(
            RX_BUFFER_SIZE,
            DmaMemoryAttributes::MMIO,
            self.iommu_device_id.as_ref(),
        );

        if let Some(new_buffer) = new_buffer_opt {
            let phys_addr = new_buffer.device_addr();
            if let Some(new_desc) = queue_guard.alloc_desc() {
                unsafe {
                    let desc_table = queue_guard.desc_table_ptr();
                    (*desc_table.add(new_desc as usize)) = VringDesc {
                        addr: phys_addr,
                        len: RX_BUFFER_SIZE as u32,
                        flags: vring_flags::VRING_DESC_F_WRITE,
                        next: 0,
                    };
                    queue_guard.submit(new_desc);
                }
                self.rx_buffers
                    .lock()
                    .expect("rx_buffers lock poisoned")
                    .insert(new_desc, new_buffer);
                queue_guard.notify(&*self.transport);
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
            let mut queue_guard = tx_queue.lock().expect("tx_queue lock poisoned");
            while let Some((desc_id, _len)) = queue_guard.poll_complete() {
                // Free the inflight DMA buffer
                if let Some(_buf) = self
                    .tx_inflight
                    .lock()
                    .expect("tx_inflight lock poisoned")
                    .remove(&desc_id)
                {
                    // Buffer dropped here, freeing the DMA allocation
                }

                // Free descriptor
                queue_guard.free_desc(desc_id);

                // Wake pending future
                let waker_idx = VIRTQUEUE_MAX_SIZE as usize + desc_id as usize;
                let mut wakers = self
                    .pending_wakers
                    .lock()
                    .expect("pending_wakers lock poisoned");
                if let Some(waker) = wakers.remove(&waker_idx) {
                    waker.wake();
                }
            }
        }
    }

    fn process_rx_wakeups(&self) {
        // Note: RX completions are typically consumed via read_bytes(), but
        // we also wake any async waiters here so they can poll.
        if let Some(ref rx_queue) = self.rx_queue {
            let queue_guard = rx_queue.lock().expect("rx_queue lock poisoned");
            // Peek: check if there are pending completions without consuming them,
            // since read_bytes() will consume them. We just wake the waiters.
            if queue_guard.has_pending() {
                // There are unprocessed RX completions - wake waiters
                let mut wakers = self
                    .pending_wakers
                    .lock()
                    .expect("pending_wakers lock poisoned");
                wakers.retain(|&idx, waker| {
                    if idx < VIRTQUEUE_MAX_SIZE as usize {
                        waker.wake_by_ref();
                        false
                    } else {
                        true
                    }
                });
            }
        }
    }

    /// Get device configuration.
    pub fn config(&self) -> &VirtioConsoleConfig {
        &self.core.config
    }

    /// Check if device is ready.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// Perform an emergency write of a single byte if the EMERG_WRITE feature
    /// is supported. This writes directly to the `emerg_wr` config register
    /// at offset 8 and does not require queue initialization.
    pub fn emergency_write(&self, c: u8) {
        self.core.emergency_write(self.transport.as_ref(), c);
    }
}
