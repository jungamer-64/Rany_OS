// ============================================================================
// drivers/virtio/src/input/mod.rs - VirtIO Input Device Driver
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

use crate::dma::{VirtioDmaBuffer, alloc_dma_buffer};
use crate::transport::{VirtioMmioTransport, VirtioTransport};
use crate::virtqueue::*;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use exorust_sync::{PoisonLock, PoisonRwLock};
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::dma::{CpuOwned, DmaSlice};

// ============================================================================
// VirtIO Input Config Select Constants
// ============================================================================

/// Config select values for querying input device configuration.
pub mod config_select {
    pub const VIRTIO_INPUT_CFG_UNSET: u8 = 0x00;
    pub const VIRTIO_INPUT_CFG_ID_NAME: u8 = 0x01;
    pub const VIRTIO_INPUT_CFG_ID_SERIAL: u8 = 0x02;
    pub const VIRTIO_INPUT_CFG_ID_DEVIDS: u8 = 0x03;
    pub const VIRTIO_INPUT_CFG_PROP_BITS: u8 = 0x10;
    pub const VIRTIO_INPUT_CFG_EV_BITS: u8 = 0x11;
    pub const VIRTIO_INPUT_CFG_ABS_INFO: u8 = 0x12;
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VirtioInputEvent {
    pub type_: u16,
    pub code: u16,
    pub value: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputError {
    NotReady,
    IoError,
    QueueFull,
}

impl core::fmt::Display for InputError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InputError::NotReady => write!(f, "Device not ready"),
            InputError::IoError => write!(f, "I/O error"),
            InputError::QueueFull => write!(f, "Queue full"),
        }
    }
}

pub trait InputRuntime: Send + Sync {
    fn alloc_dma(&self, size: usize) -> Result<DmaSlice<CpuOwned>, InputError>;
    fn schedule_wake(&self, queue_index: u16);
    fn log(&self, level: log::Level, msg: core::fmt::Arguments);
}

pub mod device;
mod global_init;
pub use global_init::*;
pub mod driver;
#[cfg(test)]
mod tests;

use self::device::VirtioInputDevice as CoreInputDevice;

// ============================================================================
// VirtIO Common Definitions (local copies, same as blk.rs)
// ============================================================================

// ============================================================================

// ============================================================================
// VirtIO Input Device
// ============================================================================

/// Number of event buffers to pre-allocate and post
const EVENT_BUFFER_COUNT: usize = 128;

/// VirtIO input device driver
pub struct VirtioInputDevice {
    /// Transport layer (MMIO or PCI)
    transport: Box<dyn VirtioTransport>,
    /// Event queue (index 0)
    event_queue: Option<Arc<PoisonLock<VirtQueue>>>,
    /// Status queue (index 1)
    status_queue: Option<Arc<PoisonLock<VirtQueue>>>,
    /// DMA buffers for inflight event reads, keyed by descriptor index
    event_buffers: PoisonLock<BTreeMap<u16, VirtioDmaBuffer>>,
    /// Shared core device logic
    core: CoreInputDevice,
    /// Device ready flag
    ready: AtomicBool,
    /// PCI locator used for device-scoped DMA mappings
    pci_locator: PackedPciLocation,
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
    pub fn new(transport: Box<dyn VirtioTransport>, pci_locator: PackedPciLocation) -> Self {
        Self::new_with_device(transport, pci_locator)
    }

    /// Create a new VirtIO input device with a PCI locator.
    pub fn new_with_device(
        transport: Box<dyn VirtioTransport>,
        pci_locator: PackedPciLocation,
    ) -> Self {
        Self {
            transport,
            event_queue: None,
            status_queue: None,
            event_buffers: PoisonLock::new(BTreeMap::new()),
            core: CoreInputDevice::default(),
            ready: AtomicBool::new(false),
            pci_locator,
            event_handler: PoisonLock::new(None),
            dropped_events: core::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Initialize the device
    pub fn init(&mut self) -> Result<(), InputError> {
        self.core
            .init(self.transport.as_ref())
            .map_err(|_| InputError::NotReady)?;

        // Queue 0 = eventq, Queue 1 = statusq
        self.setup_queue(0)?;
        self.setup_queue(1)?;

        self.transport
            .add_status(crate::defs::status::VIRTIO_STATUS_DRIVER_OK);

        self.post_event_buffers()?;

        self.ready.store(true, Ordering::Release);
        Ok(())
    }

    /// Setup a virtqueue
    fn setup_queue(&mut self, queue_idx: u16) -> Result<(), InputError> {
        self.transport.select_queue(queue_idx);
        let max_size = self.transport.get_queue_max_size();

        if max_size == 0 {
            return Err(InputError::NotReady);
        }

        let queue_size = max_size.min(VIRTQUEUE_MAX_SIZE);
        let (desc_size, _avail_size, used_offset, total_size) =
            VirtQueue::calculate_layout(queue_size);

        let buffer = alloc_dma_buffer(total_size, self.pci_locator).ok_or(InputError::NotReady)?;

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
                0,
            )
        }
        .map_err(|_| InputError::NotReady)?;

        let arc_queue = Arc::new(PoisonLock::new(virtqueue));

        match queue_idx {
            0 => self.event_queue = Some(arc_queue),
            1 => self.status_queue = Some(arc_queue),
            _ => {}
        }

        Ok(())
    }

    /// Post pre-allocated DMA buffers to the event queue
    fn post_event_buffers(&self) -> Result<(), InputError> {
        let event_queue = self.event_queue.as_ref().ok_or(InputError::NotReady)?;
        let queue_guard = event_queue.lock().unwrap_or_else(|e| e.into_inner());
        let mut buffers = self.event_buffers.lock().unwrap_or_else(|e| e.into_inner());

        let event_size = core::mem::size_of::<VirtioInputEvent>();

        for _ in 0..EVENT_BUFFER_COUNT {
            let desc_idx = match queue_guard.alloc_desc() {
                Some(idx) => idx,
                None => break,
            };

            let dma_buf =
                alloc_dma_buffer(event_size, self.pci_locator).ok_or(InputError::IoError)?;
            let phys_addr = dma_buf.device_address();

            unsafe {
                let desc_table = queue_guard.desc_table_ptr();
                let desc = &mut *desc_table.add(desc_idx as usize);
                desc.addr = phys_addr;
                desc.len = event_size as u32;
                desc.flags = vring_flags::VRING_DESC_F_WRITE;
                desc.next = 0;
            }

            queue_guard.submit(desc_idx);

            buffers.insert(desc_idx, dma_buf);
        }

        queue_guard.notify(&*self.transport);

        Ok(())
    }

    /// Repost a single event buffer
    fn repost_event_buffer(&self, desc_idx: u16) -> Result<(), InputError> {
        let event_queue = self.event_queue.as_ref().ok_or(InputError::NotReady)?;
        let queue_guard = event_queue.lock().unwrap_or_else(|e| e.into_inner());
        let mut buffers = self.event_buffers.lock().unwrap_or_else(|e| e.into_inner());

        let event_size = core::mem::size_of::<VirtioInputEvent>();

        let dma_buf = alloc_dma_buffer(event_size, self.pci_locator).ok_or(InputError::IoError)?;
        let phys_addr = dma_buf.device_address();

        unsafe {
            let desc_table = queue_guard.desc_table_ptr();
            let desc = &mut *desc_table.add(desc_idx as usize);
            desc.addr = phys_addr;
            desc.len = event_size as u32;
            desc.flags = vring_flags::VRING_DESC_F_WRITE;
            desc.next = 0;
        }

        queue_guard.submit(desc_idx);

        buffers.insert(desc_idx, dma_buf);

        queue_guard.notify(&*self.transport);

        Ok(())
    }

    pub fn query_config(&self, select: u8, subsel: u8) -> Option<Vec<u8>> {
        Some(
            self.core
                .query_config(self.transport.as_ref(), select, subsel),
        )
    }

    pub fn device_name(&self) -> Option<Vec<u8>> {
        Some(self.core.device_name(self.transport.as_ref()))
    }

    fn extract_input_event(&self, desc_id: u16, len: u32) -> Option<VirtioInputEvent> {
        let buffers = self.event_buffers.lock().unwrap_or_else(|e| e.into_inner());
        let dma_buf = buffers.get(&desc_id)?;
        let event_size = core::mem::size_of::<VirtioInputEvent>();
        if (len as usize) < event_size {
            return None;
        }
        let slice = dma_buf.as_slice();
        let event_ptr = slice.as_ptr() as *const VirtioInputEvent;
        Some(unsafe { core::ptr::read_volatile(event_ptr) })
    }

    pub fn handle_interrupt(&self) {
        let event_queue = match self.event_queue.as_ref() {
            Some(q) => q,
            None => return,
        };

        let queue_guard = event_queue.lock().unwrap_or_else(|e| e.into_inner());
        let handler = self
            .event_handler
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        let mut completions: Vec<(u16, u32)> = Vec::new();
        queue_guard.poll_completions(|desc_id, len| {
            completions.push((desc_id, len));
        });

        drop(queue_guard);

        for (desc_id, len) in completions {
            if let Some(event) = self.extract_input_event(desc_id, len) {
                if let Some(handler_fn) = handler {
                    handler_fn(event);
                }
            }

            {
                let mut buffers = self.event_buffers.lock().unwrap_or_else(|e| e.into_inner());
                buffers.remove(&desc_id);
            }
            let event_queue = match self.event_queue.as_ref() {
                Some(q) => q,
                None => continue,
            };
            let eq = event_queue.lock().unwrap_or_else(|e| e.into_inner());
            eq.free_desc(desc_id);
            drop(eq);

            if let Err(_) = self.repost_event_buffer(desc_id) {
                self.dropped_events.fetch_add(1, Ordering::Relaxed);
                log::warn!(
                    "[VIRTIO-INPUT] Failed to repost event buffer for desc {}",
                    desc_id
                );
            }
        }
    }

    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    pub fn set_event_handler(&self, handler: fn(VirtioInputEvent)) {
        *self.event_handler.lock().unwrap_or_else(|e| e.into_inner()) = Some(handler);
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
}

// ============================================================================
// Global Device Instance
// ============================================================================

/// Primary VirtIO input device slot (`index=0`).
pub(crate) static VIRTIO_INPUT_DEVICE: PoisonLock<Option<Arc<VirtioInputDevice>>> =
    PoisonLock::new(None);

/// Additional VirtIO input devices (`index != 0`).
pub(crate) static VIRTIO_INPUT_DEVICES: PoisonRwLock<
    alloc::collections::BTreeMap<u8, Arc<VirtioInputDevice>>,
> = PoisonRwLock::new(alloc::collections::BTreeMap::new());

pub(crate) fn install_virtio_input_device(index: u8, device_arc: Arc<VirtioInputDevice>) {
    if index == 0 {
        *VIRTIO_INPUT_DEVICE
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(device_arc);
    } else {
        VIRTIO_INPUT_DEVICES
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(index, device_arc);
    }
}

pub fn get_virtio_input_device_at_index(index: u8) -> Option<Arc<VirtioInputDevice>> {
    if index == 0 {
        VIRTIO_INPUT_DEVICE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    } else {
        VIRTIO_INPUT_DEVICES
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&index)
            .cloned()
    }
}

#[cfg(test)]
pub unsafe fn init_virtio_input_at_index(index: u8, mmio_base: u64) -> Result<(), InputError> {
    let transport =
        unsafe { VirtioMmioTransport::new(mmio_base as usize).map_err(|_| InputError::NotReady)? };
    let device = PackedPciLocation::new(0, 0, index, 0);
    let mut dev = VirtioInputDevice::new(Box::new(transport), device);
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

pub unsafe fn init_virtio_input_for_device_at_index(
    index: u8,
    mmio_base: u64,
    device: PackedPciLocation,
) -> Result<(), InputError> {
    let transport =
        unsafe { VirtioMmioTransport::new(mmio_base as usize).map_err(|_| InputError::NotReady)? };
    let mut dev = VirtioInputDevice::new_with_device(Box::new(transport), device);
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
