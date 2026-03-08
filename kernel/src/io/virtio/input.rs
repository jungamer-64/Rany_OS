// ============================================================================
// src/io/virtio/input.rs - VirtIO Input Device Driver
// ============================================================================
//!
//! VirtIO-Inputドライバ実装
//!
//! ## 設計原則 (仕様書 Section 5.8 準拠)
//! - VirtQueueを用いたイベントベース入力処理
//! - eventq (Queue 0): デバイスがゲストへ入力イベントを送信
//! - statusq (Queue 1): ゲストがデバイスへLED/FF状態を送信
//! - Config selectメカニズムによるデバイス情報取得
//!
//! ## VirtIO Input Device Specification
//! - Queue 0: eventq - device writes VirtioInputEvent to guest
//! - Queue 1: statusq - guest writes status updates to device
//! - Config space: select/subsel mechanism for querying device info

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

// ============================================================================
// VirtIO Input Config Select Constants
// ============================================================================

/// Config select values for querying input device configuration.
///
/// The driver writes a `select` and `subsel` value, then reads `size` and
/// `data` from the config space to obtain device information.
mod global_init;
pub use global_init::*;

pub use virtio_driver::input::{InputError, VirtioInputEvent, config_select, device::VirtioInputDevice as CoreInputDevice};

// ============================================================================
// VirtIO Common Definitions (local copies, same as blk.rs)
// ============================================================================

use crate::io::virtio::VirtioDeviceStatus;

// ============================================================================

// ============================================================================
// VirtIO Input Device
// ============================================================================

/// Number of event buffers to pre-allocate and post
const EVENT_BUFFER_COUNT: usize = 128;

/// VirtIO input device driver
///
/// Manages two virtqueues:
/// - eventq (index 0): device writes input events to pre-posted guest buffers
/// - statusq (index 1): guest writes LED/force-feedback status to device
#[derive(Debug)]
pub struct VirtioInputDevice {
    /// Transport layer (MMIO or PCI)
    transport: Box<dyn VirtioTransport>,
    /// Event queue (index 0)
    event_queue: Option<Arc<PoisonLock<VirtQueue>>>,
    /// Status queue (index 1)
    status_queue: Option<Arc<PoisonLock<VirtQueue>>>,
    /// DMA buffers for inflight event reads, keyed by descriptor index
    event_buffers: PoisonLock<BTreeMap<u16, CoherentDmaBuffer>>,
    /// Shared core device logic
    core: CoreInputDevice,
    /// Device ready flag
    ready: AtomicBool,
    /// Optional IOMMU device identifier for device-scoped mappings
    iommu_device_id: Option<IommuDeviceId>,
    /// User-provided event handler callback
    event_handler: PoisonLock<Option<fn(VirtioInputEvent)>>,
    /// Number of events dropped due to buffer allocation failures
    dropped_events: core::sync::atomic::AtomicU64,
}

unsafe impl Send for VirtioInputDevice {}
unsafe impl Sync for VirtioInputDevice {}

/// VirtIO Input Device Configuration space offsets
pub mod config_offsets {
    pub const SELECT: usize = 0;
    pub const SUBSEL: usize = 1;
    pub const SIZE: usize = 2;
    pub const DATA: usize = 8;
}

impl VirtioInputDevice {
    /// Create a new VirtIO input device (uninitialized).
    ///
    /// The transport must already be validated (magic/version checks).
    pub fn new(transport: Box<dyn VirtioTransport>) -> Self {
        Self::new_with_device(transport, None)
    }

    /// Create a new VirtIO input device with an IOMMU device ID.
    pub fn new_with_device(
        transport: Box<dyn VirtioTransport>,
        iommu_device_id: Option<IommuDeviceId>,
    ) -> Self {
        Self {
            transport,
            event_queue: None,
            status_queue: None,
            event_buffers: PoisonLock::new(BTreeMap::new()),
            core: CoreInputDevice::default(),
            ready: AtomicBool::new(false),
            iommu_device_id,
            event_handler: PoisonLock::new(None),
            dropped_events: core::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Initialize the device following the standard VirtIO initialization sequence.
    pub fn init(&mut self) -> Result<(), InputError> {
        // Step 1-5: Perform common VirtIO initialization using shared core
        self.core.init(self.transport.as_ref()).map_err(|_| InputError::NotReady)?;

        // Step 6: Setup queues
        // Queue 0 = eventq, Queue 1 = statusq
        self.setup_queue(0)?;
        self.setup_queue(1)?;

        // Step 7: Driver OK
        self.transport.add_status(crate::io::virtio::status::VIRTIO_STATUS_DRIVER_OK);

        // Step 8: Post event buffers so the device has somewhere to write events
        self.post_event_buffers()?;

        self.ready.store(true, Ordering::Release);
        Ok(())
    }

    /// Setup a virtqueue (same pattern as blk.rs).
    fn setup_queue(&mut self, queue_idx: u16) -> Result<(), InputError> {
        // Select queue and read size
        self.transport.select_queue(queue_idx);
        let max_size = self.transport.get_queue_max_size();

        if max_size == 0 {
            return Err(InputError::NotReady);
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
            DmaMemoryAttributes::MMIO,
            self.iommu_device_id.as_ref(),
        )
        .ok_or(InputError::NotReady)?;

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
                0,
            )
        };

        let arc_queue = Arc::new(PoisonLock::new(virtqueue));

        match queue_idx {
            0 => self.event_queue = Some(arc_queue),
            1 => self.status_queue = Some(arc_queue),
            _ => {} // additional queues ignored
        }

        Ok(())
    }

    /// Post pre-allocated DMA buffers to the event queue so the device can
    /// write input events into them.
    ///
    /// Each buffer is `size_of::<VirtioInputEvent>()` bytes (8 bytes).
    /// We post `EVENT_BUFFER_COUNT` (32) buffers.
    fn post_event_buffers(&self) -> Result<(), InputError> {
        let event_queue = self.event_queue.as_ref().ok_or(InputError::NotReady)?;
        let mut queue_guard = event_queue.lock().expect("eventq lock poisoned");
        let mut buffers = self
            .event_buffers
            .lock()
            .expect("event_buffers lock poisoned");

        let event_size = core::mem::size_of::<VirtioInputEvent>();

        for _ in 0..EVENT_BUFFER_COUNT {
            let desc_idx = match queue_guard.alloc_desc() {
                Some(idx) => idx,
                None => break, // no more descriptors available
            };

            // Allocate a DMA-safe buffer for one event (IOMMU-aware)
            let dma_buf = crate::io::virtio::dma::alloc_virtio_dma_buffer(
                event_size,
                DmaMemoryAttributes::MMIO,
                self.iommu_device_id.as_ref(),
            )
            .ok_or(InputError::IoError)?;
            let phys_addr = dma_buf.device_addr();

            // Setup descriptor: device-writable buffer
            unsafe {
                let desc_table = queue_guard.desc_table_ptr();
                let desc = &mut *desc_table.add(desc_idx as usize);
                desc.addr = phys_addr;
                desc.len = event_size as u32;
                desc.flags = vring_flags::VRING_DESC_F_WRITE;
                desc.next = 0;
            }

            // Submit to available ring
            unsafe {
                queue_guard.submit(desc_idx);
            }

            // Track the DMA buffer
            buffers.insert(desc_idx, dma_buf);
        }

        // Notify device that buffers are available
        queue_guard.notify(&*self.transport);

        Ok(())
    }

    /// Repost a single event buffer after consuming an event.
    ///
    /// This keeps the event queue populated so the device always has
    /// buffers to write new events into.
    fn repost_event_buffer(&self, desc_idx: u16) -> Result<(), InputError> {
        let event_queue = self.event_queue.as_ref().ok_or(InputError::NotReady)?;
        let mut queue_guard = event_queue.lock().expect("event_queue lock poisoned");
        let mut buffers = self
            .event_buffers
            .lock()
            .expect("event_buffers lock poisoned");

        let event_size = core::mem::size_of::<VirtioInputEvent>();

        // Allocate a fresh DMA buffer (IOMMU-aware)
        let dma_buf = crate::io::virtio::dma::alloc_virtio_dma_buffer(
            event_size,
            DmaMemoryAttributes::MMIO,
            self.iommu_device_id.as_ref(),
        )
        .ok_or(InputError::IoError)?;
        let phys_addr = dma_buf.device_addr();

        // Reconfigure the descriptor
        unsafe {
            let desc_table = queue_guard.desc_table_ptr();
            let desc = &mut *desc_table.add(desc_idx as usize);
            desc.addr = phys_addr;
            desc.len = event_size as u32;
            desc.flags = vring_flags::VRING_DESC_F_WRITE;
            desc.next = 0;
        }

        // Submit to available ring
        unsafe {
            queue_guard.submit(desc_idx);
        }

        // Track the new buffer (replaces old if still present)
        buffers.insert(desc_idx, dma_buf);

        // Notify device
        queue_guard.notify(&*self.transport);

        Ok(())
    }

    /// Query the device configuration space using the select/subsel mechanism.
    pub fn query_config(&self, select: u8, subsel: u8) -> Option<Vec<u8>> {
        Some(self.core.query_config(self.transport.as_ref(), select, subsel))
    }

    /// Query the device name string.
    pub fn device_name(&self) -> Option<Vec<u8>> {
        Some(self.core.device_name(self.transport.as_ref()))
    }

    /// Handle a device interrupt by polling the event queue for completed events.
    ///
    /// For each completed event buffer:
    /// 1. Extract the `VirtioInputEvent` from the DMA buffer
    /// 2. Dispatch to the registered event handler (if any)
    /// 3. Repost the buffer so the device can write new events
    /// DMAバッファから入力イベントを抽出する
    fn extract_input_event(&self, desc_id: u16, len: u32) -> Option<VirtioInputEvent> {
        let buffers = self
            .event_buffers
            .lock()
            .expect("event_buffers lock poisoned");
        let dma_buf = buffers.get(&desc_id)?;
        let event_size = core::mem::size_of::<VirtioInputEvent>();
        if (len as usize) < event_size {
            return None;
        }
        let slice = unsafe { dma_buf.as_slice() };
        let event_ptr = slice.as_ptr() as *const VirtioInputEvent;
        Some(unsafe { core::ptr::read_volatile(event_ptr) })
    }

    pub fn handle_interrupt(&self) {
        let event_queue = match self.event_queue.as_ref() {
            Some(q) => q,
            None => return,
        };

        let mut queue_guard = event_queue.lock().expect("event_queue lock poisoned");
        let handler = self
            .event_handler
            .lock()
            .expect("event_handler lock poisoned")
            .clone();

        // Collect completions while holding the queue lock
        let mut completions: Vec<(u16, u32)> = Vec::new();
        queue_guard.poll_completions(|desc_id, len| {
            completions.push((desc_id, len));
        });

        // Release queue lock before processing events
        drop(queue_guard);

        for (desc_id, len) in completions {
            // Extract event from DMA buffer
            if let Some(event) = self.extract_input_event(desc_id, len) {
                if let Some(handler_fn) = handler {
                    handler_fn(event);
                }
            }

            // Remove old buffer and free descriptor before reposting
            {
                let mut buffers = self
                    .event_buffers
                    .lock()
                    .expect("event_buffers lock poisoned");
                buffers.remove(&desc_id);
            }
            let event_queue = match self.event_queue.as_ref() {
                Some(q) => q,
                None => continue,
            };
            let eq = event_queue.lock().expect("event_queue lock poisoned");
            eq.free_desc(desc_id);
            drop(eq);

            // Repost buffer for this descriptor slot
            if let Err(_) = self.repost_event_buffer(desc_id) {
                self.dropped_events.fetch_add(1, Ordering::Relaxed);
                log::warn!(
                    "[VIRTIO-INPUT] Failed to repost event buffer for desc {}",
                    desc_id
                );
            }
        }
    }

    /// Get the number of dropped events.
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    /// Register a callback to be invoked for each received input event.
    pub fn set_event_handler(&self, handler: fn(VirtioInputEvent)) {
        *self
            .event_handler
            .lock()
            .expect("event_handler lock poisoned") = Some(handler);
    }

    /// Check if the device is initialized and ready.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
}

// ============================================================================
// Global Device Instance
// ============================================================================

/// Primary (legacy) VirtIO input device slot kept for compatibility (`index=0`).
pub(crate) static VIRTIO_INPUT_DEVICE: crate::sync::PoisonLock<Option<Arc<VirtioInputDevice>>> =
    crate::sync::PoisonLock::new(None);

/// Additional VirtIO input devices (`index != 0`).
pub(crate) static VIRTIO_INPUT_DEVICES: spin::RwLock<
    alloc::collections::BTreeMap<u8, Arc<VirtioInputDevice>>,
> = spin::RwLock::new(alloc::collections::BTreeMap::new());

pub(crate) fn install_virtio_input_device(index: u8, device_arc: Arc<VirtioInputDevice>) {
    if index == 0 {
        *VIRTIO_INPUT_DEVICE
            .lock()
            .expect("VIRTIO_INPUT_DEVICE lock poisoned") = Some(device_arc);
    } else {
        VIRTIO_INPUT_DEVICES.write().insert(index, device_arc);
    }
}

/// Get a shared reference to the VirtIO input device by index.
pub fn get_virtio_input_device_at_index(index: u8) -> Option<Arc<VirtioInputDevice>> {
    if index == 0 {
        VIRTIO_INPUT_DEVICE
            .lock()
            .expect("VIRTIO_INPUT_DEVICE lock poisoned")
            .clone()
    } else {
        VIRTIO_INPUT_DEVICES.read().get(&index).cloned()
    }
}

/// Initialize the global VirtIO input device at a specific index.
pub unsafe fn init_virtio_input_at_index(index: u8, mmio_base: u64) -> Result<(), InputError> {
    let transport =
        unsafe { VirtioMmioTransport::new(mmio_base as usize).map_err(|_| InputError::NotReady)? };
    let mut dev = VirtioInputDevice::new(Box::new(transport));
    dev.init()?;

    let name = dev.device_name();
    let device_arc = Arc::new(dev);

    if let Some(name_bytes) = name {
        if let Ok(name_str) = core::str::from_utf8(&name_bytes) {
            log::info!(
                "VirtIO-input index={} initialized: \"{}\"\n",
                index,
                name_str
            );
        } else {
            log::info!(
                "VirtIO-input index={} initialized: (non-UTF8 name, {} bytes)\n",
                index,
                name_bytes.len()
            );
        }
    } else {
        log::info!("VirtIO-input index={} initialized\n", index);
    }

    install_virtio_input_device(index, device_arc);
    Ok(())
}

/// Initialize the global VirtIO input device (legacy `index=0`).
///
/// # Safety
/// Caller must ensure MMIO address is valid and device exists.
pub unsafe fn init_virtio_input(mmio_base: u64) -> Result<(), InputError> {
    init_virtio_input_at_index(0, mmio_base)
}

/// Initialize the global VirtIO input device with an IOMMU device ID at a specific index.
pub unsafe fn init_virtio_input_for_device_at_index(
    index: u8,
    mmio_base: u64,
    device: IommuDeviceId,
) -> Result<(), InputError> {
    let transport =
        unsafe { VirtioMmioTransport::new(mmio_base as usize).map_err(|_| InputError::NotReady)? };
    let mut dev = VirtioInputDevice::new_with_device(Box::new(transport), Some(device));
    dev.init()?;

    let name = dev.device_name();
    let device_arc = Arc::new(dev);

    if let Some(name_bytes) = name {
        if let Ok(name_str) = core::str::from_utf8(&name_bytes) {
            log::info!(
                "VirtIO-input index={} initialized: \"{}\"\n",
                index,
                name_str
            );
        } else {
            log::info!(
                "VirtIO-input index={} initialized: (non-UTF8 name, {} bytes)\n",
                index,
                name_bytes.len()
            );
        }
    } else {
        log::info!("VirtIO-input index={} initialized\n", index);
    }

    install_virtio_input_device(index, device_arc);
    Ok(())
}

/// Initialize the global VirtIO input device with an IOMMU device ID (legacy `index=0`).
///
/// # Safety
/// Caller must ensure MMIO address is valid and device exists.
pub unsafe fn init_virtio_input_for_device(
    mmio_base: u64,
    device: IommuDeviceId,
) -> Result<(), InputError> {
    init_virtio_input_for_device_at_index(0, mmio_base, device)
}
