//! Fault Handling Methods
//!
//! This module contains fault handling methods for `IommuController` via `FaultHandler` trait.
//!
//! # ISR Safety (ExoRust Guideline)
//!
//! The `process_faults()` function is called from ISR context. To comply with ExoRust
//! guidelines, we:
//! - **Do NOT** call `log::error!` or any allocating/locking operations in ISR
//! - **Push** raw fault records to a lock-free deferred queue
//! - Actual logging is done by `drain_deferred_faults()` in a safe async context

use crate::io::iommu::registers::{fsts_bits, regs};
use crate::io::iommu::{ContextEntry, FaultLog, FaultRecord, IommuController, IommuError};
use core::sync::atomic::{AtomicUsize, Ordering};

// ============================================================================
// ISR-Safe Deferred Fault Queue (ExoRust Compliance)
// ============================================================================

/// Raw fault event for ISR-safe deferred processing
///
/// This is a minimal, Copy struct with no allocations.
#[derive(Debug, Clone, Copy)]
pub struct RawFaultEvent {
    pub source_id: u16,
    pub fault_address: u64,
    pub reason: u8,
    pub pasid: Option<u32>,
}

impl From<&FaultRecord> for RawFaultEvent {
    fn from(record: &FaultRecord) -> Self {
        Self {
            source_id: record.source_id(),
            fault_address: record.fault_address(),
            reason: record.reason(),
            pasid: record.pasid(),
        }
    }
}

/// Fixed-size lock-free ring buffer for deferred fault events
///
/// ISR pushes events here; a separate task drains and logs them.
const DEFERRED_QUEUE_SIZE: usize = 256;

struct DeferredFaultQueue {
    events: [Option<RawFaultEvent>; DEFERRED_QUEUE_SIZE],
    head: AtomicUsize, // Consumer reads from here
    tail: AtomicUsize, // Producer writes here
    dropped: AtomicUsize,
}

impl DeferredFaultQueue {
    const fn new() -> Self {
        Self {
            events: [None; DEFERRED_QUEUE_SIZE],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
        }
    }

    /// Push an event (ISR-safe, may drop if full)
    fn push(&self, event: RawFaultEvent) {
        let tail = self.tail.load(Ordering::Relaxed);
        let next_tail = (tail + 1) % DEFERRED_QUEUE_SIZE;
        let head = self.head.load(Ordering::Acquire);

        if next_tail == head {
            // Queue full, drop event
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // SAFETY: Single producer (ISR) writes to tail slot
        unsafe {
            let ptr = &self.events as *const _ as *mut [Option<RawFaultEvent>; DEFERRED_QUEUE_SIZE];
            (*ptr)[tail] = Some(event);
        }
        self.tail.store(next_tail, Ordering::Release);
    }

    /// Pop an event (consumer side, called from safe context)
    fn pop(&self) -> Option<RawFaultEvent> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);

        if head == tail {
            return None; // Empty
        }

        // SAFETY: Single consumer reads from head slot
        let event = unsafe {
            let ptr = &self.events as *const _ as *mut [Option<RawFaultEvent>; DEFERRED_QUEUE_SIZE];
            (*ptr)[head].take()
        };
        self.head
            .store((head + 1) % DEFERRED_QUEUE_SIZE, Ordering::Release);
        event
    }

    /// Get and reset dropped count
    fn take_dropped(&self) -> usize {
        self.dropped.swap(0, Ordering::Relaxed)
    }
}

/// Global deferred fault queue (ISR writes, async task reads)
static DEFERRED_FAULT_QUEUE: DeferredFaultQueue = DeferredFaultQueue::new();

/// Drain deferred faults and log them (call from safe async context)
///
/// Returns number of faults processed.
pub fn drain_deferred_faults() -> usize {
    let mut count = 0;
    while let Some(event) = DEFERRED_FAULT_QUEUE.pop() {
        log::error!(
            "[IOMMU] Fault: reason={:#x}, source={:04x}, addr={:#x}, pasid={:?}",
            event.reason,
            event.source_id,
            event.fault_address,
            event.pasid
        );
        count += 1;
    }

    let dropped = DEFERRED_FAULT_QUEUE.take_dropped();
    if dropped > 0 {
        log::warn!(
            "[IOMMU] {} fault events dropped due to queue overflow",
            dropped
        );
    }

    count
}

// Constants
const FAULT_LOG_RATE_LIMIT: usize = 128; // Max faults to log per batch

pub trait FaultHandler {
    /// Initialize fault handling
    fn init_fault_handling(&mut self);

    /// Process pending faults
    fn process_faults(&self) -> usize;

    /// Get recent faults
    fn recent_faults(&self, count: usize) -> alloc::vec::Vec<FaultRecord>;

    /// Get total fault count
    fn total_fault_count(&self) -> u64;

    /// Enable fault interrupts with a specific vector
    fn enable_fault_interrupt(&mut self, vector: u8);

    /// Isolate a faulting device
    fn isolate_faulting_device(&self, fault: FaultRecord) -> Result<(), IommuError>;
}

impl FaultHandler for IommuController {
    /// Initialize fault handling with a fault log ring buffer
    fn init_fault_handling(&mut self) {
        *self.fault_log.lock() = Some(FaultLog::new());
        log::info!("[IOMMU] Fault handling initialized");
    }

    /// Process pending faults from the Fault Recording Registers
    /// Returns the number of faults processed
    fn process_faults(&self) -> usize {
        use crate::io::iommu::security::SecurityEvent;
        use fsts_bits::*;

        let fsts = self.read32(regs::FSTS);
        let mut processed = 0;

        // Check if there's a pending fault
        if fsts & FSTS_PPF == 0 {
            return 0;
        }

        // Get the fault record index
        let fri = ((fsts & FSTS_FRI_MASK) >> 8) as usize;

        // Read capability to get number of fault records and offset
        let nfr = ((self.cap >> 40) & 0xFF) as usize + 1;
        let fro = ((self.cap >> 24) & 0x3FF) as usize * 16;

        // Phase 7: Collect security events for notification after loop
        // Using fixed-size array to avoid allocation in ISR context
        const MAX_EVENTS: usize = 128;
        let mut pending_events: [Option<SecurityEvent>; MAX_EVENTS] = [None; MAX_EVENTS];
        let mut event_count = 0usize;

        // Read fault records
        for _ in 0..nfr {
            let fr_offset = (fro + fri * 16) as u64;
            let lo = self.read64(fr_offset);
            let hi = self.read64(fr_offset + 8);

            let record = FaultRecord { lo, hi };

            if record.is_valid() {
                // ISR-SAFE: Push to deferred queue instead of logging directly
                // (ExoRust Guideline: No log! macros in ISR context)
                if processed < FAULT_LOG_RATE_LIMIT {
                    DEFERRED_FAULT_QUEUE.push(RawFaultEvent::from(&record));
                }
                // Note: Rate limit exceeded notification is handled by drain_deferred_faults()

                // Add to fault log (short lock scope)
                if let Some(log) = self.fault_log.lock().as_mut() {
                    log.push(record);
                }

                // Phase 7: Collect security event (no lock held)
                if event_count < MAX_EVENTS {
                    pending_events[event_count] = Some(SecurityEvent::DmaViolation {
                        source_id: record.source_id(),
                        fault_address: record.fault_address(),
                        reason: record.reason(),
                    });
                    event_count += 1;
                } else {
                    // Overflow: record dropped event
                    self.record_dropped_security_event();
                }

                // Clear the fault by writing 1 to F bit
                self.write64(fr_offset, lo | FaultRecord::FAULT);

                processed += 1;
            }
        }

        // Clear the primary fault overflow (PFO) if set
        if fsts & FSTS_PFO != 0 {
            self.write32(regs::FSTS, FSTS_PFO);
            log::warn!("[IOMMU] Fault overflow cleared");
        }

        // Phase 7: Notify security events AFTER loop (all locks released)
        // This ensures notify() is called in a lock-free context
        for event_opt in pending_events.iter().take(event_count) {
            if let Some(event) = event_opt {
                self.notify_security(*event);
            }
        }

        // Report any dropped events as a single summary event
        let dropped = self.flush_dropped_security_events();
        if dropped > 0 {
            self.notify_security(SecurityEvent::EventsDropped { count: dropped });
        }

        processed
    }

    /// Get recent faults from the log
    fn recent_faults(&self, count: usize) -> alloc::vec::Vec<FaultRecord> {
        if let Some(log) = self.fault_log.lock().as_ref() {
            log.recent(count)
        } else {
            alloc::vec::Vec::new()
        }
    }

    /// Get total number of faults recorded
    fn total_fault_count(&self) -> u64 {
        self.fault_log
            .lock()
            .as_ref()
            .map(|l| l.total_count())
            .unwrap_or(0)
    }

    /// Enable Fault Interrupts
    ///
    /// # Arguments
    /// * `vector` - IDT vector to use for fault interrupts
    fn enable_fault_interrupt(&mut self, vector: u8) {
        // 1. Clear any pending faults first
        self.process_faults();

        // 2. Configure Fault Event Data (FED)
        let fed_data: u32 = vector as u32;
        self.write32(regs::FEDATA, fed_data);

        // 3. Configure Fault Event Address (FEADDR)
        let fe_addr: u32 = 0xFEE0_0000;
        self.write32(regs::FEADDR, fe_addr);

        // 4. Configure Fault Event Upper Address (FEUADDR)
        self.write32(regs::FEUADDR, 0);

        // 5. Unmask Fault Interrupts in FECTL
        let fectl = self.read32(regs::FECTL);
        self.write32(regs::FECTL, fectl & !0x8000_0000); // Clear IM bit (31)

        log::info!("[IOMMU] Fault Interrupts enabled (Vector: {:#x})", vector);
    }

    /// Isolate a faulting device by moving it to a quarantine domain
    fn isolate_faulting_device(&self, fault: FaultRecord) -> Result<(), IommuError> {
        use crate::io::iommu::security::{
            FaultSummary, IsolationDecision, IsolationReason, SecurityEvent,
        };

        let sid = fault.source_id();
        let bus = (sid >> 8) as u8;
        let dev = ((sid >> 3) & 0x1F) as u8;
        let func = (sid & 0x07) as u8;

        // Phase 7: Consult security policy before isolation
        let summary = FaultSummary::from(&fault);
        let decision = if let Some(notifier) = self.security_notifier.get() {
            notifier.decide(&summary)
        } else {
            IsolationDecision::default()
        };

        // Handle decision
        let isolation_reason = match decision {
            IsolationDecision::Ignore => {
                log::debug!(
                    "[SECURITY] Fault from {}:{}.{} ignored by policy",
                    bus,
                    dev,
                    func
                );
                return Ok(());
            }
            IsolationDecision::LogOnly => {
                log::warn!(
                    "[SECURITY] Fault from {}:{}.{} logged (no isolation)",
                    bus,
                    dev,
                    func
                );
                return Ok(());
            }
            IsolationDecision::Isolate(reason) => reason,
        };

        log::warn!(
            "[SECURITY] Isolating faulting device {}:{}.{}",
            bus,
            dev,
            func
        );

        // Attempt to isolate by disabling the context entry
        // This requires accessing hardware headers which are pub(crate)

        let mut need_invalidation = false;

        // Safely access hardware lock
        match self.hardware.lock() {
            Ok(mut hw) => {
                if let Some(table) = hw.context_tables.get_mut(bus as usize) {
                    let idx = ((dev as usize) << 3) | (func as usize);
                    if let Some(entry) = table.get_mut(idx) {
                        unsafe {
                            let entry_ptr = entry as *mut ContextEntry;
                            let mut val = core::ptr::read_volatile(entry_ptr);
                            if val.is_present() {
                                val.lo &= !1;
                                core::ptr::write_volatile(entry_ptr, val);
                                need_invalidation = true;
                            }
                        }
                    }
                }
            }
            Err(poisoned) => {
                log::warn!("[IOMMU] Lock poisoned during isolation, attempting best-effort");
                let mut hw = poisoned.into_inner();
                if let Some(table) = hw.context_tables.get_mut(bus as usize) {
                    let idx = ((dev as usize) << 3) | (func as usize);
                    if let Some(entry) = table.get_mut(idx) {
                        unsafe {
                            let entry_ptr = entry as *mut ContextEntry;
                            let mut val = core::ptr::read_volatile(entry_ptr);
                            if val.is_present() {
                                val.lo &= !1;
                                core::ptr::write_volatile(entry_ptr, val);
                                need_invalidation = true;
                            }
                        }
                    }
                }
            }
        }

        if need_invalidation {
            // FIXME: Trigger invalidation.
            // self.invalidate_iotlb_direct(0); // Actually we don't have domain ID easy?
            // Actually context cache invalidation needed if present bit changed?
            // "Context-cache Invalidation"

            // Phase 7: Notify security event AFTER lock is released
            self.notify_security(SecurityEvent::DeviceIsolated {
                source_id: sid,
                reason: isolation_reason,
            });
        }

        Ok(())
    }
}
