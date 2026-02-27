// ============================================================================
// kernel/src/io/iommu/amd/fault.rs
// ============================================================================

//! AMD-Vi fault event processing, deferred fault queue, and async fault handler.

use core::future::poll_fn;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::Poll;

use crate::io::iommu::tables::phys_to_virt_usize;
use crate::io::mmio::{mmio_read_u32, mmio_read_u64, mmio_write_u32, mmio_write_u64};
use crate::io::iommu::security::SecurityEvent;
use crate::io::iommu::types::IommuError;
use crate::io::iommu::IommuBackend;
use crate::io::iommu::registry::get_iommu_driver;
use crate::sync::WakerQueue;

use super::event_log::AmdEventEntry;
use super::registers::*;
use super::{AmdIommuDriver, AmdIommuUnit, devid_to_bdf};

// ---------------------------------------------------------------------------
// AmdFaultEvent
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub(super) struct AmdFaultEvent {
    pub(super) segment: u16,
    pub(super) devid: u16,
    pub(super) domain_id: u32,
    pub(super) flags: u16,
    pub(super) address: u64,
    pub(super) event_type: u8,
    pub(super) raw: [u32; 4],
    pub(super) is_overflow: bool,
}

impl AmdFaultEvent {
    pub(super) fn from_entry(segment: u16, entry: AmdEventEntry) -> Self {
        Self {
            segment,
            devid: entry.devid(),
            domain_id: entry.domain_id(),
            flags: entry.flags(),
            address: entry.address(),
            event_type: entry.event_type(),
            raw: entry.data,
            is_overflow: false,
        }
    }

    pub(super) fn overflow(segment: u16) -> Self {
        Self {
            segment,
            devid: 0,
            domain_id: 0,
            flags: 0,
            address: 0,
            event_type: 0,
            raw: [0; 4],
            is_overflow: true,
        }
    }
}

// ---------------------------------------------------------------------------
// AmdDeferredFaultQueue — lock-free ring buffer
// ---------------------------------------------------------------------------

pub(crate) struct AmdDeferredFaultQueue {
    events: [Option<AmdFaultEvent>; AMD_FAULT_QUEUE_SIZE],
    head: AtomicUsize,
    tail: AtomicUsize,
    dropped: AtomicUsize,
}

impl AmdDeferredFaultQueue {
    pub(crate) const fn new() -> Self {
        Self {
            events: [None; AMD_FAULT_QUEUE_SIZE],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
        }
    }

    pub(super) fn push(&self, event: AmdFaultEvent) {
        const MAX_RETRIES: usize = 16;
        for _ in 0..MAX_RETRIES {
            let tail = self.tail.load(Ordering::Relaxed);
            let next_tail = (tail + 1) % AMD_FAULT_QUEUE_SIZE;
            let head = self.head.load(Ordering::Acquire);
            if next_tail == head {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            if self
                .tail
                .compare_exchange_weak(tail, next_tail, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                unsafe {
                    let ptr = &self.events as *const _
                        as *mut [Option<AmdFaultEvent>; AMD_FAULT_QUEUE_SIZE];
                    core::ptr::write_volatile(&mut (*ptr)[tail], Some(event));
                }
                return;
            }
            core::hint::spin_loop();
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn pop(&self) -> Option<AmdFaultEvent> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let event = unsafe {
            let ptr =
                &self.events as *const _ as *mut [Option<AmdFaultEvent>; AMD_FAULT_QUEUE_SIZE];
            (*ptr)[head].take()
        };
        self.head
            .store((head + 1) % AMD_FAULT_QUEUE_SIZE, Ordering::Release);
        event
    }

    pub(super) fn take_dropped(&self) -> usize {
        self.dropped.swap(0, Ordering::Relaxed)
    }

    pub(super) fn is_empty(&self) -> bool {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head == tail
    }
}

// ---------------------------------------------------------------------------
// Global statics
// ---------------------------------------------------------------------------

pub(crate) static AMD_DEFERRED_FAULT_QUEUE: AmdDeferredFaultQueue = AmdDeferredFaultQueue::new();
pub(crate) static AMD_FAULT_WAKERS: WakerQueue = WakerQueue::new();
pub(crate) static AMD_CMD_WAITERS: WakerQueue = WakerQueue::new();

// ---------------------------------------------------------------------------
// Drain / async worker functions
// ---------------------------------------------------------------------------

pub fn drain_deferred_faults() -> usize {
    drain_deferred_faults_with_driver(None)
}

pub(crate) fn drain_deferred_faults_with_driver(driver: Option<&AmdIommuDriver>) -> usize {
    let mut count = 0usize;
    while let Some(event) = AMD_DEFERRED_FAULT_QUEUE.pop() {
        if event.is_overflow {
            log::warn!("[IOMMU][AMD-Vi] Event log overflow");
        } else {
            let (bus, device, function) = devid_to_bdf(event.devid);
            log::error!(
                "[IOMMU][AMD-Vi] Event {} seg={} devid={:02x}:{:02x}.{} domain=0x{:05x} addr=0x{:x} flags=0x{:03x} raw={:08x}:{:08x}:{:08x}:{:08x}",
                event_type_name(event.event_type),
                event.segment,
                bus,
                device,
                function,
                event.domain_id,
                event.address,
                event.flags,
                event.raw[0],
                event.raw[1],
                event.raw[2],
                event.raw[3],
            );
            if let Some(driver) = driver {
                driver.notify_security(SecurityEvent::DmaViolation {
                    source_id: event.devid,
                    fault_address: event.address,
                    reason: event.event_type,
                    domain_id: Some(event.domain_id),
                });
            }
        }
        count += 1;
    }

    let dropped = AMD_DEFERRED_FAULT_QUEUE.take_dropped();
    if dropped > 0 {
        log::warn!(
            "[IOMMU][AMD-Vi] {} event(s) dropped due to queue overflow",
            dropped
        );
        if let Some(driver) = driver {
            driver.notify_security(SecurityEvent::EventsDropped {
                count: dropped as u64,
            });
        }
    }

    count
}

async fn wait_for_fault_events() {
    poll_fn(|cx| {
        if !AMD_DEFERRED_FAULT_QUEUE.is_empty() {
            return Poll::Ready(());
        }
        AMD_FAULT_WAKERS.register(cx.waker());
        if !AMD_DEFERRED_FAULT_QUEUE.is_empty() {
            return Poll::Ready(());
        }
        Poll::Pending
    })
    .await;
}

pub async fn fault_handler_task() {
    loop {
        let driver = get_iommu_driver().and_then(|backend| match backend.as_ref() {
            IommuBackend::Amd(driver) => Some(driver),
            _ => None,
        });
        let _ = drain_deferred_faults_with_driver(driver);
        wait_for_fault_events().await;
    }
}

pub fn spawn_fault_handler_task() {
    crate::task::per_core_executor::spawn(fault_handler_task());
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

pub(super) fn msi_message(vector: u8) -> (u64, u32) {
    const MSI_ADDRESS_BASE: u64 = 0xFEE0_0000;
    let apic_id: u64 = {
        #[cfg(feature = "apic")]
        {
            crate::io::interrupt_manager::current_apic_id() as u64
        }
        #[cfg(not(feature = "apic"))]
        {
            0u64
        }
    };
    let address = MSI_ADDRESS_BASE | (apic_id << 12);
    let data = vector as u32;
    (address, data)
}

pub(super) fn event_type_name(event_type: u8) -> &'static str {
    match event_type {
        EVENT_TYPE_ILL_DEV => "ILLEGAL_DEVICE_TABLE_ENTRY",
        EVENT_TYPE_IO_FAULT => "IO_PAGE_FAULT",
        EVENT_TYPE_DEV_TAB_ERR => "DEV_TABLE_HARDWARE_ERROR",
        EVENT_TYPE_PAGE_TAB_ERR => "PAGE_TABLE_HARDWARE_ERROR",
        EVENT_TYPE_ILL_CMD => "ILLEGAL_COMMAND",
        EVENT_TYPE_CMD_HARD_ERR => "COMMAND_HARDWARE_ERROR",
        EVENT_TYPE_IOTLB_INV_TO => "IOTLB_INV_TIMEOUT",
        EVENT_TYPE_INV_DEV_REQ => "INVALID_DEVICE_REQUEST",
        EVENT_TYPE_INV_PPR_REQ => "INVALID_PPR_REQUEST",
        EVENT_TYPE_RMP_FAULT => "RMP_PAGE_FAULT",
        EVENT_TYPE_RMP_HW_ERR => "RMP_HARDWARE_ERROR",
        _ => "UNKNOWN",
    }
}

// ---------------------------------------------------------------------------
// FaultHandler impl on AmdIommuDriver
// ---------------------------------------------------------------------------

impl AmdIommuDriver {
    pub(crate) fn handle_fault(&self) {
        for (idx, unit) in self.units.iter().enumerate() {
            self.poll_event_log(idx, unit);
        }
        AMD_FAULT_WAKERS.wake_all_from_isr();
    }

    pub(crate) fn wake_invalidation_waiters(&self) {
        AMD_CMD_WAITERS.wake_all_from_isr();
    }

    /// Handle event log status bits: clear interrupts, restart/enable if needed.
    /// Returns `true` if the log is running and entries should be processed.
    fn handle_event_log_status(&self, mmio_base: usize, status: u32) -> bool {
        let clear_mask = status & (MMIO_STATUS_EVT_INT_MASK | MMIO_STATUS_EVT_OVERFLOW_MASK);
        if clear_mask != 0 {
            mmio_write_u32(mmio_base + MMIO_STATUS_OFFSET as usize, clear_mask);
        }

        if status & MMIO_STATUS_EVT_RUN_MASK != 0 {
            return true;
        }

        if status & MMIO_STATUS_EVT_OVERFLOW_MASK != 0 {
            self.restart_event_log(mmio_base);
        } else {
            self.enable_event_log(mmio_base);
        }
        false
    }

    pub(super) fn poll_event_log(&self, unit_idx: usize, unit: &AmdIommuUnit) {
        let log = match self.event_logs.get(unit_idx).and_then(|log| log.as_ref()) {
            Some(log) => log,
            None => return,
        };

        let _guard = match log.try_lock() {
            Some(guard) => guard,
            None => return,
        };

        let mmio_base = phys_to_virt_usize(unit.base_addr);
        let status = mmio_read_u32(mmio_base + MMIO_STATUS_OFFSET as usize);

        if !self.handle_event_log_status(mmio_base, status) {
            if status & MMIO_STATUS_EVT_OVERFLOW_MASK != 0 {
                AMD_DEFERRED_FAULT_QUEUE.push(AmdFaultEvent::overflow(unit.segment));
            }
            return;
        }

        let mut head = mmio_read_u32(mmio_base + MMIO_EVT_HEAD_OFFSET as usize);
        let tail = mmio_read_u32(mmio_base + MMIO_EVT_TAIL_OFFSET as usize);
        if head >= EVT_BUFFER_BYTES || tail >= EVT_BUFFER_BYTES {
            return;
        }

        let mut processed = 0usize;
        while head != tail && processed < AMD_FAULT_LOG_RATE_LIMIT {
            if let Some(entry) = log.read_entry(head) {
                if entry.event_type() == 0 {
                    break;
                }
                AMD_DEFERRED_FAULT_QUEUE.push(AmdFaultEvent::from_entry(unit.segment, entry));
            }
            head = (head + EVENT_ENTRY_SIZE) % EVT_BUFFER_BYTES;
            mmio_write_u32(mmio_base + MMIO_EVT_HEAD_OFFSET as usize, head);
            processed += 1;
        }

        if status & MMIO_STATUS_EVT_OVERFLOW_MASK != 0 {
            self.restart_event_log(mmio_base);
            AMD_DEFERRED_FAULT_QUEUE.push(AmdFaultEvent::overflow(unit.segment));
        }
    }

    pub(super) fn restart_event_log(&self, mmio_base: usize) {
        let mut control = mmio_read_u64(mmio_base + MMIO_CONTROL_OFFSET as usize);
        if (control & CONTROL_EVT_LOG_EN) != 0 {
            control &= !CONTROL_EVT_LOG_EN;
            mmio_write_u64(mmio_base + MMIO_CONTROL_OFFSET as usize, control);
        }
        mmio_write_u32(
            mmio_base + MMIO_STATUS_OFFSET as usize,
            MMIO_STATUS_EVT_OVERFLOW_MASK,
        );
        control |= CONTROL_EVT_LOG_EN;
        mmio_write_u64(mmio_base + MMIO_CONTROL_OFFSET as usize, control);
    }

    pub(super) fn enable_event_log(&self, mmio_base: usize) {
        let mut control = mmio_read_u64(mmio_base + MMIO_CONTROL_OFFSET as usize);
        if (control & CONTROL_EVT_LOG_EN) == 0 {
            control |= CONTROL_EVT_LOG_EN;
            mmio_write_u64(mmio_base + MMIO_CONTROL_OFFSET as usize, control);
        }
    }

    pub(super) fn program_event_log_interrupt(&self, unit: &AmdIommuUnit) -> Result<(), IommuError> {
        let (addr, data) = msi_message(AMD_IOMMU_FAULT_VECTOR);
        let mmio_base = phys_to_virt_usize(unit.base_addr);
        mmio_write_u32(
            mmio_base + MMIO_MSI_ADDR_LO_OFFSET as usize,
            (addr & 0xffff_ffff) as u32,
        );
        mmio_write_u32(
            mmio_base + MMIO_MSI_ADDR_HI_OFFSET as usize,
            (addr >> 32) as u32,
        );
        mmio_write_u32(mmio_base + MMIO_MSI_DATA_OFFSET as usize, data);
        Ok(())
    }
}
