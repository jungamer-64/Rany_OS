// ============================================================================
// kernel/src/io/iommu/runtime/zombie/mod.rs
// ============================================================================
//! Lock-free Zombie DMA Handle Queue
//!
//! This module provides a lock-free queue for DMA handles that are dropped
//! without explicit unmap. Instead of synchronously unmapping in Drop
//! (which can block the executor or ISR), handles are enqueued here for
//! asynchronous cleanup by a background GC task.
//!
//! # Design Rationale
//!
//! The ExoRust architecture mandates:
//! - **No blocking in Drop**: Drop must complete in O(1) without locks or I/O
//! - **Async-First**: Cleanup operations should be deferred to async context
//! - **ISR-safe**: Drop may be called from interrupt context
//!
//! # Implementation
//!
//! Uses a bounded MPSC ring buffer with 2-phase publish protocol:
//!
//! ## Producer (Drop/ISR context):
//! 1. `Empty -> Writing` (CAS AcqRel) - claim slot exclusively
//! 2. Write payload data (non-atomic, exclusive ownership)
//! 3. `Writing -> Pending` (store Release) - publish to consumer
//!
//! ## Consumer (GC task):
//! 4. `Pending -> Processing` (CAS AcqRel) - acquire payload
//! 5. Read payload data (non-atomic, exclusive ownership)
//! 6. `Processing -> Empty` (store Release) - release slot
//!
//! This 2-phase protocol prevents publish-before-init races where the
//! consumer could observe partially initialized data.
//!
//! # O(1) Guarantee
//!
//! Enqueue probes a fixed number of slots (MAX_PROBE_COUNT) and gives up
//! if none are available. This guarantees O(1) worst-case for Drop/ISR.
//! Leaked handles are safe (IOVA stays mapped, memory not reused).
//!
//! # Memory Safety
//!
//! Zombie handles prevent memory reuse until unmapped. The GC task runs
//! periodically and on memory pressure to reclaim IOVAs.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::ipc::DomainId;
use crate::ipc::rref::RRefRawParts;

/// Maximum number of zombie entries.
/// Must be power of 2 for efficient modulo.
const ZOMBIE_QUEUE_CAPACITY: usize = 4096;

/// Mask for ring buffer index calculation.
const ZOMBIE_QUEUE_MASK: usize = ZOMBIE_QUEUE_CAPACITY - 1;

/// Maximum probe attempts before giving up (O(1) guarantee).
/// Must be small enough for Drop/ISR context.
const MAX_PROBE_COUNT: usize = 64;

/// Zombie entry state (2-phase publish protocol)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ZombieState {
    /// Slot is empty and available for claiming
    Empty = 0,
    /// Slot is being written by producer (exclusive ownership)
    Writing = 1,
    /// Slot contains valid data, ready for consumer
    Pending = 2,
    /// Slot is being processed by GC (exclusive ownership)
    Processing = 3,
}

/// Payload data stored in a zombie entry (non-atomic)
///
/// This struct is written/read under exclusive ownership guaranteed by
/// the state machine (Writing or Processing state).
#[derive(Clone, Copy)]
#[repr(C)]
struct ZombiePayload {
    /// IOVA base address
    iova: u64,
    /// Size in bytes
    size: u64,
    /// Domain ID (u16 for IOMMU domain)
    domain_id: u16,
    /// Device BDF (if applicable, else 0xFFFF)
    device_bdf: u16,
    /// Mapping kind (encoded)
    mapping_kind: u32,
    /// Raw RRef pointer (0 if none)
    raw_ptr: u64,
    /// Raw RRef owner DomainId
    raw_owner: u64,
    /// Raw RRef metadata
    raw_meta: u64,
    /// Raw RRef drop fn pointer
    /// NOTE: Pointer-to-integer conversion is intentional for lock-free storage.
    /// This breaks strict provenance but is acceptable in kernel context.
    raw_drop_fn: u64,
}

/// Compact zombie entry (64 bytes total, cache-line aligned)
///
/// Uses 2-phase publish protocol:
/// - Producer: Empty -> Writing (CAS) -> write payload -> Pending (Release)
/// - Consumer: Pending -> Processing (CAS) -> read payload -> Empty (Release)
#[repr(C, align(64))]
struct ZombieEntry {
    /// Entry state + generation counter for ABA prevention
    /// - Bits 0-7: ZombieState
    /// - Bits 8-31: generation counter (24 bits, wraps at 16M)
    state_gen: AtomicU32,
    /// Padding for payload alignment
    _pad: u32,
    /// Payload data (accessed only under exclusive ownership)
    payload: UnsafeCell<MaybeUninit<ZombiePayload>>,
}

// SAFETY: ZombieEntry is safe to share between threads because:
// - state_gen is atomic and controls exclusive access to payload
// - payload is only accessed when the thread owns the slot (Writing or Processing state)
unsafe impl Sync for ZombieEntry {}

impl ZombieEntry {
    const fn new() -> Self {
        Self {
            state_gen: AtomicU32::new(0),
            _pad: 0,
            payload: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// Extract state from a packed state_gen value.
    #[inline]
    const fn extract_state(state_gen: u32) -> ZombieState {
        match state_gen & 0xFF {
            0 => ZombieState::Empty,
            1 => ZombieState::Writing,
            2 => ZombieState::Pending,
            3 => ZombieState::Processing,
            _ => ZombieState::Empty,
        }
    }

    /// Extract generation from a packed state_gen value.
    #[inline]
    const fn extract_generation(state_gen: u32) -> u32 {
        state_gen >> 8
    }

    /// Load state_gen once and return (state, generation).
    /// Uses Relaxed ordering - caller decides if Acquire is needed.
    #[inline]
    fn load_state_gen_relaxed(&self) -> (ZombieState, u32) {
        let sg = self.state_gen.load(Ordering::Relaxed);
        (Self::extract_state(sg), Self::extract_generation(sg))
    }

    #[inline]
    fn pack_state_gen(state: ZombieState, generation: u32) -> u32 {
        ((generation & 0xFF_FFFF) << 8) | (state as u32)
    }

    /// Phase 1: Try to claim this slot for writing (Empty -> Writing).
    /// Takes pre-loaded generation to avoid double load in hot path.
    /// Returns the new generation on success.
    #[inline]
    fn try_claim_for_writing(&self, expected_gen: u32) -> Option<u32> {
        let expected = Self::pack_state_gen(ZombieState::Empty, expected_gen);
        let new_gen = expected_gen.wrapping_add(1);
        let desired = Self::pack_state_gen(ZombieState::Writing, new_gen);

        // AcqRel on success provides synchronization for any prior state
        self.state_gen
            .compare_exchange_weak(expected, desired, Ordering::AcqRel, Ordering::Relaxed)
            .ok()
            .map(|_| new_gen)
    }

    /// Phase 2: Publish the written data (Writing -> Pending).
    /// Must only be called by the thread that successfully claimed the slot.
    fn publish(&self, generation: u32) {
        let desired = Self::pack_state_gen(ZombieState::Pending, generation);
        // Release ensures all payload writes are visible before state change
        self.state_gen.store(desired, Ordering::Release);
    }

    /// Try to acquire a pending entry for processing (Pending -> Processing).
    /// Takes pre-loaded state_gen value to avoid double load.
    #[inline]
    fn try_acquire_for_processing_with(&self, current: u32) -> bool {
        if Self::extract_state(current) != ZombieState::Pending {
            return false;
        }
        let generation = Self::extract_generation(current);
        let desired = Self::pack_state_gen(ZombieState::Processing, generation);

        // Acquire on success is sufficient: we need to see producer's payload writes.
        // Producer used Release in publish(), so Acquire here forms the sync pair.
        self.state_gen
            .compare_exchange(current, desired, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Release a processed entry back to empty (Processing -> Empty).
    fn release(&self) {
        let current = self.state_gen.load(Ordering::Relaxed);
        let generation = Self::extract_generation(current).wrapping_add(1);
        let desired = Self::pack_state_gen(ZombieState::Empty, generation);
        // Release ordering: not strictly required here since we're done with payload,
        // but keeps the generation update visible to other threads promptly.
        self.state_gen.store(desired, Ordering::Release);
    }

    /// Write payload data to a claimed slot.
    /// SAFETY: Caller must have successfully called try_claim_for_writing().
    unsafe fn write_payload(&self, payload: ZombiePayload) { unsafe {
        let ptr = self.payload.get();
        (*ptr).write(payload);
    }}

    /// Read payload data from an acquired slot.
    /// SAFETY: Caller must have successfully called try_acquire_for_processing().
    unsafe fn read_payload(&self) -> ZombiePayload { unsafe {
        let ptr = self.payload.get();
        (*ptr).assume_init_read()
    }}
}

/// Components for RRef raw parts stored in zombie entry
#[derive(Clone, Copy)]
struct ZombieRawPartsComponents {
    ptr: u64,
    owner: u64,
    meta: u64,
    drop_fn: u64,
}

impl ZombieRawPartsComponents {
    fn from_raw_parts(raw: RRefRawParts) -> Self {
        let (ptr, owner, meta, drop_fn) = raw.into_components();
        Self {
            ptr: ptr.as_ptr() as u64,
            owner: owner.as_u64(),
            meta: meta as u64,
            drop_fn: drop_fn as usize as u64,
        }
    }

    /// Reconstruct the drop function and parts for cleanup.
    /// Returns None if no valid RRef was stored.
    fn into_drop_parts(self) -> Option<(NonNull<u8>, DomainId, usize, unsafe fn(NonNull<u8>, DomainId, usize))> {
        if self.ptr == 0 || self.drop_fn == 0 {
            return None;
        }
        let ptr = NonNull::new(self.ptr as *mut u8)?;
        let owner = DomainId::new(self.owner);
        let meta = self.meta as usize;
        // SAFETY: drop_fn was stored from a valid function pointer
        let drop_fn = unsafe {
            core::mem::transmute::<usize, unsafe fn(NonNull<u8>, DomainId, usize)>(
                self.drop_fn as usize,
            )
        };
        Some((ptr, owner, meta, drop_fn))
    }
}

/// Data extracted from a zombie entry for processing
#[derive(Debug, Clone, Copy)]
pub struct ZombieData {
    pub iova: u64,
    pub size: u64,
    /// IOMMU domain ID (u16)
    pub domain_id: u16,
    /// Optional Device ID
    pub device_id: Option<crate::io::iommu::core::types::DeviceId>,
    /// Encoded mapping kind (0=Identity, 1=Global, 2=Device, 3=Domain)
    pub mapping_kind: u32,
}

/// Global zombie queue (statically allocated)
pub struct ZombieQueue {
    entries: [ZombieEntry; ZOMBIE_QUEUE_CAPACITY],
    /// Producer sequence counter (fetch_add to distribute start positions)
    producer_seq: AtomicU64,
    /// Consumer position hint (helps resume scanning efficiently)
    consumer_pos: AtomicU64,
    /// Statistics: total entries successfully enqueued
    total_enqueued: AtomicU64,
    /// Statistics: total entries successfully processed (unmap succeeded)
    total_processed: AtomicU64,
    /// Statistics: total entries drained (processed + failed, for accurate pending_estimate)
    total_drained: AtomicU64,
    /// Statistics: total entries dropped due to queue full
    total_dropped: AtomicU64,
    /// Statistics: unmap failed (driver error)
    total_unmap_failed: AtomicU64,
    /// Statistics: no IOMMU driver available
    total_no_driver: AtomicU64,
    /// Statistics: identity mappings leaked (intentional)
    total_identity_leaked: AtomicU64,
}

impl ZombieQueue {
    /// Create a new zombie queue.
    pub const fn new() -> Self {
        const EMPTY_ENTRY: ZombieEntry = ZombieEntry::new();
        Self {
            entries: [EMPTY_ENTRY; ZOMBIE_QUEUE_CAPACITY],
            producer_seq: AtomicU64::new(0),
            consumer_pos: AtomicU64::new(0),
            total_enqueued: AtomicU64::new(0),
            total_processed: AtomicU64::new(0),
            total_drained: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
            total_unmap_failed: AtomicU64::new(0),
            total_no_driver: AtomicU64::new(0),
            total_identity_leaked: AtomicU64::new(0),
        }
    }

    /// Try to enqueue a zombie handle.
    ///
    /// This is O(1) worst-case: probes at most MAX_PROBE_COUNT slots.
    /// Lock-free and allocation-free. Safe to call from Drop or ISR context.
    ///
    /// Uses fetch_add on producer_seq to distribute start positions among
    /// concurrent producers, reducing collision rate when queue is contended.
    ///
    /// # Returns
    /// - `true` if enqueued successfully
    /// - `false` if no empty slot found (handle will be leaked, but safely)
    pub fn try_enqueue(
        &self,
        iova: u64,
        size: u64,
        domain_id: u16,
        device_id: Option<super::types::DeviceId>,
        mapping_kind: u32,
        raw: Option<RRefRawParts>,
    ) -> bool {
        // fetch_add gives each producer a unique starting position,
        // distributing them across the ring buffer to reduce collisions.
        let start = self.producer_seq.fetch_add(1, Ordering::Relaxed) as usize;

        // Probe up to MAX_PROBE_COUNT slots (O(1) guarantee)
        for offset in 0..MAX_PROBE_COUNT {
            let idx = start.wrapping_add(offset) & ZOMBIE_QUEUE_MASK;
            let entry = &self.entries[idx];

            // Single load, extract both state and generation
            let (state, current_gen) = entry.load_state_gen_relaxed();
            
            if state == ZombieState::Empty {
                if let Some(new_gen) = entry.try_claim_for_writing(current_gen) {
                    // Phase 1 complete: we own the slot exclusively
                    
                    // Build payload
                    let raw_components = raw.map(ZombieRawPartsComponents::from_raw_parts);
                    let payload = ZombiePayload {
                        iova,
                        size,
                        domain_id,
                        device_bdf: device_id.map(|d| d.bdf()).unwrap_or(0xFFFF),
                        mapping_kind,
                        raw_ptr: raw_components.map_or(0, |r| r.ptr),
                        raw_owner: raw_components.map_or(0, |r| r.owner),
                        raw_meta: raw_components.map_or(0, |r| r.meta),
                        raw_drop_fn: raw_components.map_or(0, |r| r.drop_fn),
                    };
                    
                    // SAFETY: We own the slot (Writing state)
                    unsafe { entry.write_payload(payload) };
                    
                    // Phase 2: publish to consumer (Writing -> Pending)
                    entry.publish(new_gen);
                    
                    self.total_enqueued.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
            }
        }

        // No empty slot found within probe limit - leak the handle
        // This is safe: IOVA stays mapped, memory won't be reused
        self.total_dropped.fetch_add(1, Ordering::Relaxed);
        false
    }

    /// Process pending zombie entries.
    ///
    /// This should only be called from the GC task (single consumer).
    /// Calls the provided callback for each zombie entry.
    ///
    /// # Arguments
    /// * `max_count` - Maximum number of entries to process
    /// * `callback` - Called for each zombie; returns true if unmap succeeded
    ///
    /// # Returns
    /// Number of entries processed (drained from queue).
    /// 単一のゾンビエントリを処理する
    fn process_single_zombie<F>(
        &self,
        entry: &ZombieEntry,
        sg: u32,
        callback: &mut F,
    ) -> bool
    where
        F: FnMut(ZombieData) -> bool,
    {
        if !entry.try_acquire_for_processing_with(sg) {
            return false;
        }
        // SAFETY: We own the slot (Processing state)
        let payload = unsafe { entry.read_payload() };
        
        let data = ZombieData {
            iova: payload.iova,
            size: payload.size,
            domain_id: payload.domain_id,
            device_id: if payload.device_bdf != 0xFFFF {
                Some(crate::io::iommu::core::types::DeviceId::from_bdf(payload.device_bdf))
            } else {
                None
            },
            mapping_kind: payload.mapping_kind,
        };

        let success = callback(data);
        
        if success {
            let raw = ZombieRawPartsComponents {
                ptr: payload.raw_ptr,
                owner: payload.raw_owner,
                meta: payload.raw_meta,
                drop_fn: payload.raw_drop_fn,
            };
            if let Some((ptr, owner, meta, drop_fn)) = raw.into_drop_parts() {
                unsafe { drop_fn(ptr, owner, meta) };
            }
            self.total_processed.fetch_add(1, Ordering::Relaxed);
        }

        entry.release();
        self.total_drained.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub fn process_pending<F>(&self, max_count: usize, mut callback: F) -> usize
    where
        F: FnMut(ZombieData) -> bool,
    {
        let mut processed = 0;
        let start = self.consumer_pos.load(Ordering::Relaxed) as usize;
        let mut last_offset = 0;

        let scan_limit = ZOMBIE_QUEUE_CAPACITY.min(max_count * 2);

        for offset in 0..scan_limit {
            if processed >= max_count {
                break;
            }

            let idx = (start + offset) & ZOMBIE_QUEUE_MASK;
            let entry = &self.entries[idx];

            let sg = entry.state_gen.load(Ordering::Relaxed);
            if ZombieEntry::extract_state(sg) == ZombieState::Pending {
                if self.process_single_zombie(entry, sg, &mut callback) {
                    processed += 1;
                    last_offset = offset;
                }
            }
        }

        if processed > 0 {
            self.consumer_pos.store(
                ((start + last_offset + 1) & ZOMBIE_QUEUE_MASK) as u64,
                Ordering::Relaxed,
            );
        }

        processed
    }

    /// Get queue statistics.
    pub fn stats(&self) -> ZombieQueueStats {
        ZombieQueueStats {
            total_enqueued: self.total_enqueued.load(Ordering::Relaxed),
            total_processed: self.total_processed.load(Ordering::Relaxed),
            total_drained: self.total_drained.load(Ordering::Relaxed),
            total_dropped: self.total_dropped.load(Ordering::Relaxed),
            total_unmap_failed: self.total_unmap_failed.load(Ordering::Relaxed),
            total_no_driver: self.total_no_driver.load(Ordering::Relaxed),
            total_identity_leaked: self.total_identity_leaked.load(Ordering::Relaxed),
            capacity: ZOMBIE_QUEUE_CAPACITY,
        }
    }

    /// Increment the unmap_failed counter.
    pub fn inc_unmap_failed(&self) {
        self.total_unmap_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the no_driver counter.
    pub fn inc_no_driver(&self) {
        self.total_no_driver.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the identity_leaked counter.
    pub fn inc_identity_leaked(&self) {
        self.total_identity_leaked.fetch_add(1, Ordering::Relaxed);
    }

    /// Estimate current pending count (accurate based on enqueued - drained).
    pub fn pending_estimate(&self) -> usize {
        let enqueued = self.total_enqueued.load(Ordering::Relaxed);
        let drained = self.total_drained.load(Ordering::Relaxed);
        enqueued.saturating_sub(drained) as usize
    }
}

/// Zombie queue statistics
#[derive(Debug, Clone, Copy)]
pub struct ZombieQueueStats {
    /// Total entries successfully enqueued
    pub total_enqueued: u64,
    /// Total entries where unmap succeeded
    pub total_processed: u64,
    /// Total entries drained (processed + failed cleanups)
    pub total_drained: u64,
    /// Total entries dropped due to queue full (leaked at enqueue)
    pub total_dropped: u64,
    /// Total unmap failures (driver returned error)
    pub total_unmap_failed: u64,
    /// Total entries leaked because no IOMMU driver was available
    pub total_no_driver: u64,
    /// Total identity mappings intentionally leaked
    pub total_identity_leaked: u64,
    /// Queue capacity
    pub capacity: usize,
}

// ============================================================================
// Global Zombie Queue Instance
// ============================================================================

/// Global zombie queue for DMA handles dropped without explicit unmap.
///
/// This is a static instance to avoid allocation in Drop context.
static ZOMBIE_QUEUE: ZombieQueue = ZombieQueue::new();

/// Enqueue a DMA handle for async cleanup.
///
/// Called from `DmaHandle::Drop` instead of synchronous unmap.
///
/// # Arguments
/// * `iova` - The IOVA to unmap
/// * `size` - Size of the mapping
/// * `domain_id` - IOMMU domain ID (u16)
/// * `mapping_kind` - Encoded mapping kind
///
/// # Returns
/// `true` if successfully enqueued, `false` if queue full (leaked).
#[inline]
pub fn enqueue_zombie(
    iova: u64,
    size: u64,
    domain_id: u16,
    device_id: Option<crate::io::iommu::core::types::DeviceId>,
    mapping_kind: u32,
    raw: Option<RRefRawParts>,
) -> bool {
    ZOMBIE_QUEUE.try_enqueue(iova, size, domain_id, device_id, mapping_kind, raw)
}

/// Process pending zombie handles.
///
/// Should be called periodically by the security monitor or on memory pressure.
///
/// # Arguments
/// * `max_count` - Maximum number of entries to process
/// * `callback` - Called for each zombie entry
///
/// # Returns
/// Number of entries processed.
pub fn process_zombies<F>(max_count: usize, callback: F) -> usize
where
    F: FnMut(ZombieData) -> bool,
{
    ZOMBIE_QUEUE.process_pending(max_count, callback)
}

/// Get zombie queue statistics.
pub fn zombie_stats() -> ZombieQueueStats {
    ZOMBIE_QUEUE.stats()
}

/// Check if zombie queue has pending entries.
pub fn has_pending_zombies() -> bool {
    ZOMBIE_QUEUE.pending_estimate() > 0
}

// ============================================================================
// Mapping Kind Encoding
// ============================================================================

/// Encode MappingKind for storage in zombie queue.
pub fn encode_mapping_kind(kind: &crate::io::iommu::core::dma::handle::MappingKind) -> u32 {
    use crate::io::iommu::core::dma::handle::MappingKind;
    match kind {
        MappingKind::Identity => 0,
        MappingKind::Global => 1,
        MappingKind::Device(device_id) => {
            // Store device BDF in upper 16 bits
            0x0002_0000 | (device_id.bdf() as u32)
        }
        MappingKind::Domain => 3,
    }
}

/// Decode MappingKind from zombie queue storage.
pub fn decode_mapping_kind(encoded: u32) -> crate::io::iommu::core::dma::handle::MappingKind {
    use crate::io::iommu::core::dma::handle::MappingKind;
    use crate::io::iommu::core::types::DeviceId;

    let kind = encoded & 0xFFFF;
    match kind {
        0 => MappingKind::Identity,
        1 => MappingKind::Global,
        3 => MappingKind::Domain,
        _ if (encoded >> 16) == 2 => {
            let bdf = (encoded & 0xFFFF) as u16;
            MappingKind::Device(DeviceId::from_bdf(bdf))
        }
        _ => MappingKind::Identity, // Fallback
    }
}

// ============================================================================
// GC Task Integration
// ============================================================================

/// Run zombie GC pass.
///
/// Called from security_monitor_task or on memory pressure.
/// Processes up to `max_count` zombie entries.
/// Updates failure reason statistics for monitoring.
pub fn run_zombie_gc(max_count: usize) -> usize {
    use crate::io::iommu::core::dma::handle::MappingKind;
    use crate::io::iommu::runtime::registry::get_iommu_driver;

    let driver = get_iommu_driver();

    process_zombies(max_count, |zombie| {
        let kind = decode_mapping_kind(zombie.mapping_kind);

        // If no IOMMU driver, we can't do any cleanup.
        // Return false to leak the entry safely (IOVA stays mapped).
        let Some(ref driver) = driver else {
            log::warn!(
                "[ZombieGC] No IOMMU driver, leaking: IOVA=0x{:x}, size={}, kind={:?}",
                zombie.iova,
                zombie.size,
                kind
            );
            ZOMBIE_QUEUE.inc_no_driver();
            return false;
        };

        let result = match &kind {
            MappingKind::Identity => {
                // Identity mappings don't need IOMMU cleanup, but we still
                // can't run the RRef drop without knowing if device DMA is complete.
                // Leak to be safe.
                log::warn!(
                    "[ZombieGC] Identity mapping leaked: IOVA=0x{:x}, size={}",
                    zombie.iova,
                    zombie.size
                );
                ZOMBIE_QUEUE.inc_identity_leaked();
                return false;
            }
            MappingKind::Global => {
                // Global DMA mapping
                driver.unmap_dma(zombie.iova, zombie.size)
            }
            MappingKind::Device(device_id) => {
                // Device-specific mapping
                driver.unmap_for_device(device_id, zombie.iova, zombie.size)
            }
            MappingKind::Domain => {
                // Domain-managed - try to get domain and unmap
                if let Ok(domain) = driver.get_domain(zombie.domain_id) {
                    let _ = domain.unregister_dma_mapping(zombie.iova);
                }
                
                // If we have a device ID, we can do a proper IOMMU unmap
                if let Some(device_id) = zombie.device_id {
                    driver.unmap_for_device(&device_id, zombie.iova, zombie.size)
                } else {
                    // Fallback: Global unmap if no device ID (less precise but better than leak)
                    driver.unmap_dma(zombie.iova, zombie.size)
                }
            }
        };

        match result {
            Ok(()) => {
                log::trace!(
                    "[ZombieGC] Cleaned: IOVA=0x{:x}, size={}, kind={:?}",
                    zombie.iova,
                    zombie.size,
                    kind
                );
                true
            }
            Err(e) => {
                log::error!(
                    "[ZombieGC] Failed to clean: IOVA=0x{:x}, size={}, error={:?}",
                    zombie.iova,
                    zombie.size,
                    e
                );
                ZOMBIE_QUEUE.inc_unmap_failed();
                false
            }
        }
    })
}

#[cfg(feature = "qemu-test-export")]
pub fn qemu_smoke_queue_basic() -> bool {
    let Some(queue) = qemu_alloc_queue_for_smoke() else {
        return false;
    };

    if !queue.try_enqueue(0x1000, 4096, 1u16, None, 0, None) {
        return false;
    }

    let stats = queue.stats();
    if stats.total_enqueued != 1
        || stats.total_processed != 0
        || stats.total_drained != 0
        || stats.total_dropped != 0
    {
        return false;
    }

    let mut processed_data: Option<ZombieData> = None;
    let count = queue.process_pending(10, |data| {
        processed_data = Some(data);
        true
    });
    if count != 1 {
        return false;
    }
    let Some(data) = processed_data else {
        return false;
    };
    if data.iova != 0x1000 || data.size != 4096 || data.domain_id != 1 {
        return false;
    }

    let stats = queue.stats();
    stats.total_processed == 1 && stats.total_drained == 1 && queue.pending_estimate() == 0
}

#[cfg(feature = "qemu-test-export")]
pub fn qemu_smoke_failed_cleanup() -> bool {
    let Some(queue) = qemu_alloc_queue_for_smoke() else {
        return false;
    };

    if !queue.try_enqueue(0x1000, 4096, 1u16, None, 0, None) {
        return false;
    }
    if !queue.try_enqueue(0x2000, 4096, 2u16, None, 0, None) {
        return false;
    }

    let count = queue.process_pending(10, |_| false);
    if count != 2 {
        return false;
    }

    let stats = queue.stats();
    stats.total_enqueued == 2
        && stats.total_processed == 0
        && stats.total_drained == 2
        && queue.pending_estimate() == 0
}

#[cfg(feature = "qemu-test-export")]
fn qemu_alloc_queue_for_smoke() -> Option<alloc::boxed::Box<ZombieQueue>> {
    let layout = core::alloc::Layout::new::<ZombieQueue>();
    let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) } as *mut ZombieQueue;
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { alloc::boxed::Box::from_raw(ptr) })
}

#[cfg(test)]
mod tests;
