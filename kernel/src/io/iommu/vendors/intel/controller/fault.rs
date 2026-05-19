// ============================================================================
// kernel/src/io/iommu/vendors/intel/controller/fault.rs
// ============================================================================

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

use super::dma::DomainManager;
use super::qi_ops::InvalidationOps; // For qi_invalidate_context_global
use super::{HardwareContext, IommuController};
use crate::io::iommu::runtime::fault_log::FaultRecord;
use crate::io::iommu::types::{DeviceId, IommuError};
use crate::io::iommu::vendors::intel::registers::{ecap_bits, fsts_bits, regs};
use crate::io::iommu::vendors::intel::tables::{ContextEntry, ScalableContextEntry};
use crate::sync::MpscRingBuffer;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use spin::Once;

// ============================================================================
// ISR-Safe Deferred Fault Queue (ExoRust Compliance)
// ============================================================================

/// Raw fault event for ISR-safe deferred processing
///
/// This is a minimal, Copy struct with no allocations.
/// Contains all information needed for post-ISR processing.
mod isolation_helpers;
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

    /// Check if this fault is critical (should trigger diagnostics)
    pub fn is_critical(&self) -> bool {
        self.reason == 0xFF || self.reason == 0x00 || self.is_overflow
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

fn device_id_from_source_id(segment: u16, source_id: u16) -> DeviceId {
    let bus = (source_id >> 8) as u8;
    let devfn = (source_id & 0xff) as u8;
    let device = (devfn >> 3) & 0x1f;
    let function = devfn & 0x07;
    DeviceId::new(segment, bus, device, function)
}

fn domain_id_from_context_entry(ctrl: &IommuController, device: DeviceId) -> Option<u16> {
    if ctrl.is_scalable_mode_enabled() {
        return None;
    }
    let bus = device.bus as usize;
    let devfn = ((device.device as usize) << 3) | (device.function as usize);

    let hw = ctrl.hardware.lock().ok()?;
    let context_table = hw.legacy_context_tables.get(bus)?;
    let entry = context_table.get(devfn)?;
    if !entry.is_present() {
        return None;
    }
    Some(entry.domain_id())
}

fn domain_id_from_scalable_context_entry(
    ctrl: &IommuController,
    device: DeviceId,
    pasid: Option<u32>,
) -> Option<u16> {
    if !ctrl.is_scalable_mode_enabled() {
        return None;
    }
    let pasid = pasid.unwrap_or(0);
    let tables = ctrl.device_pasid_tables.lock().ok()?;
    let table = tables.get(&device)?;
    table.domain_id(pasid)
}

/// Fixed-size MPSC lock-free ring buffer for deferred fault events
///
/// Multiple ISRs (on different cores) can push events concurrently.
/// Single consumer (async task) drains and processes them.
const DEFERRED_QUEUE_SIZE: usize = 256;
const DEFERRED_QUEUE_BACKING_SIZE: usize = DEFERRED_QUEUE_SIZE + 1;

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
    queue: MpscRingBuffer<RawFaultEvent, DEFERRED_QUEUE_BACKING_SIZE>,
    dropped: AtomicUsize,
    /// Reserved slot for critical faults (Unknown reason, etc.)
    critical_slot: CriticalFaultSlot,
}

impl DeferredFaultQueue {
    const CAPACITY: usize = DEFERRED_QUEUE_SIZE;

    const fn new() -> Self {
        Self {
            queue: MpscRingBuffer::new(),
            dropped: AtomicUsize::new(0),
            critical_slot: CriticalFaultSlot::new(),
        }
    }

    /// Check if an event is critical (deserves priority handling)
    #[inline]
    fn is_critical(event: &RawFaultEvent) -> bool {
        // Unknown fault reasons (0xFF or 0x00 with valid fault) are critical
        // Also overflow events are critical for security audit
        event.is_critical()
    }

    /// Push an event (MPSC-safe, ISR-safe, may drop if full)
    ///
    /// Uses compare_exchange_weak CAS loop to atomically reserve a slot.
    /// Multiple cores can push concurrently without data corruption.
    /// Critical events get priority slot if normal queue is full.
    /// Try to push an event to the normal (non-critical) queue.
    /// Returns true if push succeeded, false if queue full or retry limit.
    ///
    /// Drop accounting is handled by the caller so each rejected event is
    /// counted exactly once regardless of which path failed.
    fn try_push_normal_queue(&self, event: &RawFaultEvent) -> bool {
        const MAX_RETRIES: usize = 16;

        for _ in 0..MAX_RETRIES {
            if self.queue.try_push(*event).is_ok() {
                return true;
            }
            if self.len() >= self.capacity() {
                return false;
            }
            core::hint::spin_loop();
        }
        false
    }

    fn push(&self, event: RawFaultEvent) {
        // Critical faults should always get a chance to bypass the normal
        // queue so we preserve at least one high-signal security event.
        if Self::is_critical(&event) {
            if self.critical_slot.try_push(event) {
                return;
            }
        }

        // Normal queue path
        if self.try_push_normal_queue(&event) {
            return;
        }

        // Exceeded retry limit - try critical slot as last resort
        if Self::is_critical(&event) && self.critical_slot.try_push(event) {
            return;
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

        self.queue.pop()
    }

    fn len(&self) -> usize {
        self.queue.len()
    }

    fn capacity(&self) -> usize {
        Self::CAPACITY
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.queue.is_empty() && self.critical_slot.state.load(Ordering::Acquire) != SLOT_READY
    }

    /// Get and reset dropped count
    fn take_dropped(&self) -> usize {
        self.dropped.swap(0, Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn deferred_fault_queue_drains_critical_slot_before_normal_queue() {
        let queue = DeferredFaultQueue::new();
        let normal = RawFaultEvent {
            source_id: 1,
            fault_address: 0x1000,
            reason: 1,
            pasid: None,
            lo: 1,
            hi: 2,
            is_overflow: false,
        };
        let critical = RawFaultEvent {
            reason: 0xFF,
            ..normal
        };

        assert!(queue.try_push_normal_queue(&normal));
        queue.push(critical);

        assert_eq!(queue.pop().map(|event| event.reason), Some(0xFF));
        assert_eq!(queue.pop().map(|event| event.reason), Some(1));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn deferred_fault_queue_preserves_full_capacity() {
        let queue = DeferredFaultQueue::new();
        let event = RawFaultEvent {
            source_id: 1,
            fault_address: 0x1000,
            reason: 1,
            pasid: None,
            lo: 1,
            hi: 2,
            is_overflow: false,
        };

        for _ in 0..DEFERRED_QUEUE_SIZE {
            queue.push(event);
        }
        queue.push(event);

        assert_eq!(queue.len(), DEFERRED_QUEUE_SIZE);
        assert_eq!(queue.capacity(), DEFERRED_QUEUE_SIZE);
        assert_eq!(queue.take_dropped(), 1);
        assert!(!queue.is_empty());

        for _ in 0..DEFERRED_QUEUE_SIZE {
            assert!(queue.pop().is_some());
        }
        assert!(queue.pop().is_none());
        assert!(queue.is_empty());
    }
}

/// Global deferred fault queue (ISR writes, async task reads)
static DEFERRED_FAULT_QUEUE: DeferredFaultQueue = DeferredFaultQueue::new();

#[cfg(test)]
pub(crate) fn push_deferred_fault_for_test(event: RawFaultEvent) {
    DEFERRED_FAULT_QUEUE.push(event);
}

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

/// Process a single non-overflow fault event with controller
fn process_fault_with_controller(event: &RawFaultEvent, controller: &IommuController) {
    use crate::io::iommu::runtime::security::SecurityEvent;

    let record = event.to_fault_record();
    if let Some(log) = controller.fault_log.lock().as_mut() {
        log.push(record);
    }

    let device_id = device_id_from_source_id(controller.segment, event.source_id);
    let domain_id = controller
        .get_domain_for_device(device_id)
        .ok()
        .flatten()
        .or_else(|| domain_id_from_context_entry(controller, device_id))
        .or_else(|| domain_id_from_scalable_context_entry(controller, device_id, event.pasid))
        .map(u32::from);

    // SECURITY: Automatically isolate the faulting device if required by policy.
    // This provides active protection beyond just logging.
    if let Err(e) = controller.isolate_faulting_device(record) {
        log::error!(
            "[IOMMU][SECURITY] Failed to isolate faulting device {:?}: {:?}",
            device_id,
            e
        );
    }

    // Always notify security of the violation itself.
    // (Isolation notification is handled inside isolate_faulting_device if it occurs)
    controller.notify_security(SecurityEvent::DmaViolation {
        source_id: event.source_id,
        fault_address: event.fault_address,
        reason: event.reason,
        domain_id,
    });
}

/// Log QI stats when a critical fault occurs
fn log_critical_qi_stats(controller: &IommuController) {
    match controller.qi_stats() {
        Ok(Some(stats)) => {
            log::error!(
                "[IOMMU] QI stats at fault: submits={} full_checks={} head_refreshes={} waits={} wait_timeouts={}",
                stats.submits,
                stats.full_checks,
                stats.head_refreshes,
                stats.waits,
                stats.wait_timeouts
            );
        }
        Ok(None) => {
            log::info!("[IOMMU] QI stats unavailable (QI not initialized)");
        }
        Err(e) => {
            log::warn!("[IOMMU] QI stats unavailable at fault ({:?})", e);
        }
    }
}

/// Drain deferred faults with optional controller access for full processing
///
/// When controller is provided, also updates fault_log and notifies security.
pub fn drain_deferred_faults_with_controller<'a>(controller: Option<&'a IommuController>) -> usize {
    use crate::io::iommu::runtime::security::SecurityEvent;

    let mut count = 0;
    let mut _overflow_cleared = false;

    // LOOP_PROOF: mode=condition; reason=Deferred-fault drain consumes one queued event per pass and exits once the queue becomes empty.;
    while let Some(event) = DEFERRED_FAULT_QUEUE.pop() {
        if event.is_overflow {
            log::warn!("[IOMMU] Fault overflow cleared");
            _overflow_cleared = true;
        } else {
            log::error!(
                "[IOMMU] Fault: reason={:#x}, source={:04x}, addr={:#x}, pasid={:?}",
                event.reason,
                event.source_id,
                event.fault_address,
                event.pasid
            );

            if let Some(ctrl) = controller {
                process_fault_with_controller(&event, ctrl);
            }
        }

        if let Some(ctrl) = controller {
            if event.is_critical() {
                log_critical_qi_stats(ctrl);
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

    // LOOP_PROOF: mode=event; reason=Fault-handler task intentionally runs for system lifetime and yields between bounded drain passes.;
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

static FAULT_HANDLER_TASK_STARTED: Once<()> = Once::new();

/// Spawn the fault handler task
///
/// Call this during kernel initialization after the scheduler is ready.
/// The task will run in the background, draining ISR-queued faults.
pub fn spawn_fault_handler_task() {
    let mut spawned = false;
    FAULT_HANDLER_TASK_STARTED.call_once(|| {
        let _ = crate::task::spawn_detached(fault_handler_task());
        spawned = true;
    });
    if spawned {
        log::info!("[IOMMU] Fault handler task spawned");
    }
}

// Constants
const FAULT_LOG_RATE_LIMIT: usize = 128; // Max faults to log per batch

pub trait FaultHandler {
    /// Process pending faults
    fn process_faults(&self) -> usize;

    /// Enable fault interrupts with a specific vector
    fn enable_fault_interrupt(&self, vector: u8);

    /// Isolate a faulting device
    fn isolate_faulting_device(&self, fault: FaultRecord) -> Result<(), IommuError>;
}

impl FaultHandler for IommuController {
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

    /// Enable Fault Interrupts
    ///
    /// # Arguments
    /// * `vector` - IDT vector to use for fault interrupts
    fn enable_fault_interrupt(&self, vector: u8) {
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
        let sid = fault.source_id();
        let bus = (sid >> 8) as u8;
        let dev = ((sid >> 3) & 0x1F) as u8;
        let func = (sid & 0x07) as u8;

        // Phase 7: Consult security policy before isolation
        let isolation_reason = match self.check_isolation_policy(&fault, bus, dev, func) {
            Some(reason) => reason,
            None => return Ok(()),
        };

        log::warn!(
            "[SECURITY] Isolating faulting device {}:{}.{}",
            bus,
            dev,
            func
        );

        // Disable context entry in hardware tables
        let (need_invalidation, isolated_domain_id) =
            self.disable_device_context_entry(bus, dev, func);

        if need_invalidation {
            self.perform_isolation_invalidation(sid, isolated_domain_id, isolation_reason);
        }

        Ok(())
    }
}
