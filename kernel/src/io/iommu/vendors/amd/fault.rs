// ============================================================================
// kernel/src/io/iommu/vendors/amd/fault.rs
// ============================================================================

//! AMD-Vi fault event processing, deferred fault queue, and async fault handler.

use core::future::poll_fn;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::Poll;

use crate::io::iommu::runtime::backend::IommuBackend;
use crate::io::iommu::runtime::registry::get_iommu_driver;
use crate::io::iommu::runtime::security::SecurityEvent;
use crate::io::iommu::types::IommuError;
use crate::sync::{MpscRingBuffer, WakerQueue};

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

const AMD_FAULT_QUEUE_BACKING_CAPACITY: usize = AMD_FAULT_QUEUE_SIZE + 1;

pub(crate) struct AmdDeferredFaultQueue {
    queue: MpscRingBuffer<AmdFaultEvent, AMD_FAULT_QUEUE_BACKING_CAPACITY>,
    dropped: AtomicUsize,
}

impl AmdDeferredFaultQueue {
    pub(crate) const CAPACITY: usize = AMD_FAULT_QUEUE_SIZE;

    pub(crate) const fn new() -> Self {
        Self {
            queue: MpscRingBuffer::new(),
            dropped: AtomicUsize::new(0),
        }
    }

    pub(super) fn push(&self, event: AmdFaultEvent) {
        const MAX_RETRIES: usize = 16;
        for _ in 0..MAX_RETRIES {
            if self.queue.try_push(event).is_ok() {
                return;
            }
            if self.len() >= self.capacity() {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            core::hint::spin_loop();
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn pop(&self) -> Option<AmdFaultEvent> {
        self.queue.pop()
    }

    pub(super) fn len(&self) -> usize {
        self.queue.len()
    }

    pub(super) const fn capacity(&self) -> usize {
        Self::CAPACITY
    }

    pub(super) fn take_dropped(&self) -> usize {
        self.dropped.swap(0, Ordering::Relaxed)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Global statics
// ---------------------------------------------------------------------------

pub(crate) static AMD_DEFERRED_FAULT_QUEUE: AmdDeferredFaultQueue = AmdDeferredFaultQueue::new();
pub(crate) static AMD_FAULT_WAKERS: WakerQueue = WakerQueue::new();
pub(crate) static AMD_CMD_WAITERS: WakerQueue = WakerQueue::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn amd_fault_queue_preserves_reserved_slot_capacity() {
        let queue = AmdDeferredFaultQueue::new();
        let event = AmdFaultEvent::overflow(0);

        for _ in 0..AMD_FAULT_QUEUE_SIZE {
            queue.push(event);
        }
        queue.push(event);

        assert_eq!(queue.take_dropped(), 1);
        assert_eq!(queue.len(), AMD_FAULT_QUEUE_SIZE);
        assert_eq!(queue.capacity(), AMD_FAULT_QUEUE_SIZE);

        for _ in 0..AMD_FAULT_QUEUE_SIZE {
            assert!(queue.pop().is_some());
        }
        assert!(queue.pop().is_none());
    }
}

// ---------------------------------------------------------------------------
// Drain / async worker functions
// ---------------------------------------------------------------------------

pub(crate) fn drain_deferred_faults_with_driver(driver: Option<&AmdIommuDriver>) -> usize {
    let mut count = 0usize;
    // LOOP_PROOF: mode=condition; reason=AMD deferred-fault drain processes one queued event at a time and exits when queue is empty.;
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

pub(crate) async fn fault_handler_task() -> Result<(), IommuError> {
    // LOOP_PROOF: mode=event; reason=AMD fault task runs continuously and awaits new events after each finite drain pass.;
    loop {
        let driver = get_iommu_driver().and_then(|backend| match backend.as_ref() {
            IommuBackend::Amd(driver) => Some(driver.as_ref()),
            _ => None,
        });
        let driver = driver.ok_or(IommuError::RuntimeUnavailable)?;
        let _processed = drain_deferred_faults_with_driver(Some(driver));
        wait_for_fault_events().await;
    }
}

/// Periodic service work also services units without an admitted MSI route.
/// Hardware reads and deferred event publication are bounded by the event ring.
pub(crate) fn poll_firmware_event_logs() {
    if let Some(backend) = get_iommu_driver()
        && let IommuBackend::Amd(driver) = backend.as_ref()
    {
        driver.handle_fault();
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

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
    fn handle_event_log_status(&self, registers: &AmdRegisters, status: u64) -> bool {
        let clear_mask = status & (MMIO_STATUS_EVT_INT_MASK | MMIO_STATUS_EVT_OVERFLOW_MASK);
        if clear_mask != 0 {
            registers.acknowledge_event_status(clear_mask);
        }

        if status & MMIO_STATUS_EVT_RUN_MASK != 0 {
            return true;
        }

        if status & MMIO_STATUS_EVT_OVERFLOW_MASK != 0 {
            registers.restart_event_log();
        } else {
            registers.update_control(|control| control | CONTROL_EVT_LOG_EN);
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

        let registers = &unit.registers;
        let status = registers.event_status();

        if !self.handle_event_log_status(registers, status) {
            if status & MMIO_STATUS_EVT_OVERFLOW_MASK != 0 {
                AMD_DEFERRED_FAULT_QUEUE.push(AmdFaultEvent::overflow(unit.segment));
            }
            return;
        }

        let Some((mut head, tail)) = registers.event_cursors() else {
            return;
        };

        let mut processed = 0usize;
        // LOOP_PROOF: mode=condition; reason=Each consumed hardware event increments processed and advances head, stopping at the tail, an empty event, or the ISR batch limit.;
        while head != tail && processed < AMD_FAULT_LOG_RATE_LIMIT {
            if let Some(entry) = log.read_entry(head) {
                if entry.event_type() == 0 {
                    break;
                }
                AMD_DEFERRED_FAULT_QUEUE.push(AmdFaultEvent::from_entry(unit.segment, entry));
            }
            head = (head + EVENT_ENTRY_SIZE) % EVT_BUFFER_BYTES;
            registers.advance_event_head(head);
            processed += 1;
        }

        if status & MMIO_STATUS_EVT_OVERFLOW_MASK != 0 {
            registers.restart_event_log();
            AMD_DEFERRED_FAULT_QUEUE.push(AmdFaultEvent::overflow(unit.segment));
        }
    }

    pub(super) fn program_event_log_interrupt(
        &self,
        unit: &AmdIommuUnit,
    ) -> Result<(), IommuError> {
        // A single-message assignment cannot address another message number.
        // Leave event interrupts disabled unless the admitted capability matches
        // this vector assignment; event-log storage remains live and readable.
        if unit.segment != 0 || unit.iommu_info & 0x1f != 0 {
            return Err(IommuError::NotSupported);
        }
        let destination = crate::io::interrupt_manager::current_apic_id()
            .map_err(|_| IommuError::NotInitialized)?;
        let destination =
            u8::try_from(destination.as_u32()).map_err(|_| IommuError::NotSupported)?;
        unit.pci
            .configure_msi(&pci_driver::MsiConfig::new(
                destination,
                AMD_IOMMU_FAULT_VECTOR,
            ))
            .map_err(|_| IommuError::NotSupported)?;
        Ok(())
    }
}
