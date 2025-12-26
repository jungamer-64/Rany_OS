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

use super::qi_ops::InvalidationOps; // For qi_invalidate_context_global
use crate::io::iommu::registers::{fsts_bits, regs};
use crate::io::iommu::{ContextEntry, FaultLog, FaultRecord, IommuController, IommuError};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

// ============================================================================
// ISR-Safe Deferred Fault Queue (ExoRust Compliance)
// ============================================================================

/// Raw fault event for ISR-safe deferred processing
///
/// This is a minimal, Copy struct with no allocations.
/// Contains all information needed for post-ISR processing.
#[derive(Debug, Clone, Copy)]
pub struct RawFaultEvent {
    pub source_id: u16,
    pub fault_address: u64,
    pub reason: u8,
    pub pasid: Option<u32>,
    /// Raw lo/hi registers for FaultRecord reconstruction
    pub lo: u64,
    pub hi: u64,
    /// Flag indicating if this is a overflow-cleared event
    pub is_overflow: bool,
}

impl RawFaultEvent {
    /// Convert to FaultRecord for fault log
    pub fn to_fault_record(&self) -> FaultRecord {
        FaultRecord {
            lo: self.lo,
            hi: self.hi,
        }
    }
}

impl From<&FaultRecord> for RawFaultEvent {
    fn from(record: &FaultRecord) -> Self {
        Self {
            source_id: record.source_id(),
            fault_address: record.fault_address(),
            reason: record.reason(),
            pasid: record.pasid(),
            lo: record.lo,
            hi: record.hi,
            is_overflow: false,
        }
    }
}

/// Fixed-size MPSC lock-free ring buffer for deferred fault events
///
/// Multiple ISRs (on different cores) can push events concurrently.
/// Single consumer (async task) drains and processes them.
const DEFERRED_QUEUE_SIZE: usize = 256;

// ============================================================================
// Critical Fault Slot (Security Event Priority - Issue #4)
// ============================================================================

/// States for the critical fault slot
const SLOT_EMPTY: u8 = 0;
const SLOT_WRITING: u8 = 1;
const SLOT_READY: u8 = 2;

/// Reserved slot for critical security events
///
/// Under DDoS (fault flood) attack, normal queue may overflow and drop events.
/// This slot ensures at least ONE critical event is preserved for security audit.
/// Uses lock-free state machine: EMPTY -> WRITING -> READY -> (consumed) -> EMPTY
struct CriticalFaultSlot {
    state: AtomicU8,
    data: UnsafeCell<Option<RawFaultEvent>>,
}

// SAFETY: CriticalFaultSlot is only accessed via atomic state transitions
unsafe impl Sync for CriticalFaultSlot {}

impl CriticalFaultSlot {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(SLOT_EMPTY),
            data: UnsafeCell::new(None),
        }
    }

    /// Try to store a critical event. Returns true if successful.
    /// If slot is busy or full, returns false (event goes to normal queue or dropped).
    fn try_push(&self, event: RawFaultEvent) -> bool {
        // EMPTY -> WRITING transition (acquire exclusive access)
        if self
            .state
            .compare_exchange(
                SLOT_EMPTY,
                SLOT_WRITING,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            // We have exclusive access
            unsafe {
                *self.data.get() = Some(event);
            }
            // Publish: WRITING -> READY
            self.state.store(SLOT_READY, Ordering::Release);
            return true;
        }
        false
    }

    /// Try to take the critical event (single consumer).
    fn try_pop(&self) -> Option<RawFaultEvent> {
        // Only pop if READY
        if self.state.load(Ordering::Acquire) == SLOT_READY {
            // Atomically transition READY -> EMPTY and take data
            if self.state.swap(SLOT_EMPTY, Ordering::AcqRel) == SLOT_READY {
                return unsafe { (*self.data.get()).take() };
            }
        }
        None
    }
}

// ============================================================================
// Deferred Fault Queue
// ============================================================================

struct DeferredFaultQueue {
    events: [Option<RawFaultEvent>; DEFERRED_QUEUE_SIZE],
    head: AtomicUsize, // Consumer reads from here (single consumer)
    tail: AtomicUsize, // Producers reserve slots here (multi producer)
    dropped: AtomicUsize,
    /// Reserved slot for critical faults (Unknown reason, etc.)
    critical_slot: CriticalFaultSlot,
}

impl DeferredFaultQueue {
    const fn new() -> Self {
        Self {
            events: [None; DEFERRED_QUEUE_SIZE],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
            critical_slot: CriticalFaultSlot::new(),
        }
    }

    /// Check if an event is critical (deserves priority handling)
    #[inline]
    fn is_critical(event: &RawFaultEvent) -> bool {
        // Unknown fault reasons (0xFF or 0x00 with valid fault) are critical
        // Also overflow events are critical for security audit
        event.reason == 0xFF || event.reason == 0x00 || event.is_overflow
    }

    /// Push an event (MPSC-safe, ISR-safe, may drop if full)
    ///
    /// Uses compare_exchange_weak CAS loop to atomically reserve a slot.
    /// Multiple cores can push concurrently without data corruption.
    /// Critical events get priority slot if normal queue is full.
    fn push(&self, event: RawFaultEvent) {
        // For critical events, try reserved slot first if queue looks full
        if Self::is_critical(&event) {
            // Check if queue is nearly full (fast path check)
            let tail = self.tail.load(Ordering::Relaxed);
            let head = self.head.load(Ordering::Relaxed);
            let queue_len = (tail + DEFERRED_QUEUE_SIZE - head) % DEFERRED_QUEUE_SIZE;

            // If queue is > 75% full, try critical slot first
            if queue_len > (DEFERRED_QUEUE_SIZE * 3 / 4) {
                if self.critical_slot.try_push(event) {
                    return;
                }
            }
        }

        // Normal queue path
        // Retry limit to prevent infinite spin in pathological cases
        const MAX_RETRIES: usize = 16;

        for _ in 0..MAX_RETRIES {
            let tail = self.tail.load(Ordering::Relaxed);
            let next_tail = (tail + 1) % DEFERRED_QUEUE_SIZE;
            let head = self.head.load(Ordering::Acquire);

            if next_tail == head {
                // Queue full, drop event
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }

            // CAS to atomically reserve this slot
            // If another core reserved it first, tail will have changed and CAS fails
            match self.tail.compare_exchange_weak(
                tail,
                next_tail,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    // Successfully reserved slot at `tail`
                    // SAFETY: We exclusively own this slot until we write to it
                    unsafe {
                        let ptr = &self.events as *const _
                            as *mut [Option<RawFaultEvent>; DEFERRED_QUEUE_SIZE];
                        core::ptr::write_volatile(&mut (*ptr)[tail], Some(event));
                    }
                    return;
                }
                Err(_) => {
                    // Another producer won the race, retry with new tail
                    core::hint::spin_loop();
                    continue;
                }
            }
        }

        // Exceeded retry limit - extremely rare, but handle gracefully
        // Try to save critical events to reserved slot as last resort
        if Self::is_critical(&event) && self.critical_slot.try_push(event) {
            return; // Saved to critical slot
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Pop an event (consumer side, called from safe context)
    /// Drains critical_slot first to ensure critical events are processed.
    fn pop(&self) -> Option<RawFaultEvent> {
        // Priority: drain critical slot first
        if let Some(critical) = self.critical_slot.try_pop() {
            return Some(critical);
        }

        // Normal queue
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

/// Drain deferred faults and process them (call from safe async context)
///
/// This function handles ALL fault processing that was deferred from ISR:
/// - Logging faults to console
/// - Adding to fault history log
/// - Notifying security monitor
///
/// Returns number of faults processed.
pub fn drain_deferred_faults() -> usize {
    drain_deferred_faults_with_controller(None)
}

/// Drain deferred faults with optional controller access for full processing
///
/// When controller is provided, also updates fault_log and notifies security.
pub fn drain_deferred_faults_with_controller(
    controller: Option<&super::super::IommuController>,
) -> usize {
    use crate::io::iommu::security::SecurityEvent;

    let mut count = 0;
    let mut overflow_cleared = false;

    while let Some(event) = DEFERRED_FAULT_QUEUE.pop() {
        // 1. Log the fault (safe context)
        if event.is_overflow {
            log::warn!("[IOMMU] Fault overflow cleared");
            overflow_cleared = true;
        } else {
            log::error!(
                "[IOMMU] Fault: reason={:#x}, source={:04x}, addr={:#x}, pasid={:?}",
                event.reason,
                event.source_id,
                event.fault_address,
                event.pasid
            );

            // 2. Add to fault log (if controller available)
            if let Some(ctrl) = controller {
                if let Some(log) = ctrl.fault_log.lock().as_mut() {
                    log.push(event.to_fault_record());
                }

                // 3. Notify security monitor
                ctrl.notify_security(SecurityEvent::DmaViolation {
                    source_id: event.source_id,
                    fault_address: event.fault_address,
                    reason: event.reason,
                });
            }
        }
        count += 1;
    }

    // Report dropped events
    let dropped = DEFERRED_FAULT_QUEUE.take_dropped();
    if dropped > 0 {
        log::warn!(
            "[IOMMU] {} fault events dropped due to queue overflow",
            dropped
        );
        if let Some(ctrl) = controller {
            ctrl.notify_security(SecurityEvent::EventsDropped {
                count: dropped as u64,
            });
        }
    }

    count
}

// ============================================================================
// Fault Handler Task (ExoRust Async Pattern)
// ============================================================================

/// Interval for fault handler polling (milliseconds)
const FAULT_HANDLER_INTERVAL_MS: u64 = 100;

/// Async Fault Handler Task
///
/// This task runs periodically to drain the deferred fault queue and log
/// faults in a safe (non-ISR) context. It should be spawned during kernel
/// initialization.
///
/// # Cancellation
///
/// The task runs indefinitely. To stop it, the spawning code should hold
/// the task handle and cancel it when shutting down.
pub async fn fault_handler_task() {
    log::info!("[IOMMU] Fault handler task started");

    loop {
        // Drain any pending faults
        let count = drain_deferred_faults();
        if count > 0 {
            log::debug!("[IOMMU] Fault handler processed {} events", count);
        }

        // Yield to other tasks for the interval period
        // Using timer-based delay if available
        crate::task::sleep_ms(FAULT_HANDLER_INTERVAL_MS).await;
    }
}

/// Spawn the fault handler task
///
/// Call this during kernel initialization after the scheduler is ready.
/// The task will run in the background, draining ISR-queued faults.
pub fn spawn_fault_handler_task() {
    // Use kernel's per-core executor spawn mechanism
    crate::task::per_core_executor::spawn(fault_handler_task());
    log::info!("[IOMMU] Fault handler task spawned");
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

        // ====================================================================
        // ISR-SAFE: Read fault records and push to lock-free queue ONLY
        // No locks, no logging, no security notify - all deferred to async task
        // (ExoRust Guideline: ISR must be Wait-Free / Lock-Free)
        // ====================================================================

        // Read fault records
        for _ in 0..nfr {
            let fr_offset = (fro + fri * 16) as u64;
            let lo = self.read64(fr_offset);
            let hi = self.read64(fr_offset + 8);

            let record = FaultRecord { lo, hi };

            if record.is_valid() {
                // ISR-SAFE: Push to deferred queue (lock-free)
                // All processing (logging, fault_log, security) done by async task
                if processed < FAULT_LOG_RATE_LIMIT {
                    DEFERRED_FAULT_QUEUE.push(RawFaultEvent::from(&record));
                }
                // Note: Rate limit exceeded events tracked by queue's dropped counter

                // Clear the fault by writing 1 to F bit
                self.write64(fr_offset, lo | FaultRecord::FAULT);

                processed += 1;
            }
        }

        // Clear the primary fault overflow (PFO) if set
        // Push a special overflow event to queue instead of logging here
        if fsts & FSTS_PFO != 0 {
            self.write32(regs::FSTS, FSTS_PFO);
            // ISR-SAFE: Push overflow marker event (no log here!)
            DEFERRED_FAULT_QUEUE.push(RawFaultEvent {
                source_id: 0,
                fault_address: 0,
                reason: 0,
                pasid: None,
                lo: 0,
                hi: 0,
                is_overflow: true,
            });
        }

        // NOTE: security notification moved to drain_deferred_faults_with_controller()

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
        let mut isolated_domain_id: Option<u16> = None;

        // Safely access hardware lock
        match self.hardware.lock() {
            Ok(mut hw) => {
                if let Some(table) = hw.context_tables.get_mut(bus as usize) {
                    let idx = ((dev as usize) << 3) | (func as usize);
                    if let Some(entry) = table.get_mut(idx) {
                        unsafe {
                            let entry_ptr = entry as *mut ContextEntry;
                            let val = core::ptr::read_volatile(entry_ptr);
                            if val.is_present() {
                                // Capture domain_id BEFORE clearing Present bit
                                isolated_domain_id = Some(val.domain_id());
                                // Clear Present bit
                                let mut new_val = val;
                                new_val.lo &= !1;
                                core::ptr::write_volatile(entry_ptr, new_val);
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
                            let val = core::ptr::read_volatile(entry_ptr);
                            if val.is_present() {
                                isolated_domain_id = Some(val.domain_id());
                                let mut new_val = val;
                                new_val.lo &= !1;
                                core::ptr::write_volatile(entry_ptr, new_val);
                                need_invalidation = true;
                            }
                        }
                    }
                }
            }
        }

        if need_invalidation {
            // Intel VT-d: After modifying context entry, must invalidate caches
            // 1. Context Cache Invalidation (global - device-specific requires QI descriptor)
            // 2. IOTLB Invalidation (domain-specific or global)
            //
            // Since we may not have device-selective context cache invalidation via register,
            // use global invalidation as safe fallback.
            unsafe {
                // Global context cache and IOTLB invalidation
                // This is safe but may have performance impact on other devices
                self.qi_invalidate_context_global()
                    .unwrap_or_else(|e| log::warn!("[IOMMU] Context invalidation failed: {:?}", e));

                // IOTLB invalidation: prefer domain-specific if we have domain_id
                if let Some(did) = isolated_domain_id {
                    self.invalidate_iotlb(did);
                } else {
                    self.invalidate_iotlb_global();
                }
            }

            // Phase 7: Notify security event AFTER lock is released and invalidation done
            self.notify_security(SecurityEvent::DeviceIsolated {
                source_id: sid,
                reason: isolation_reason,
            });
        }

        Ok(())
    }
}
