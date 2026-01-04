// ============================================================================
// kernel/src/io/iommu/zombie_queue.rs
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
//! Uses a bounded MPSC ring buffer with CAS-based enqueue:
//! 1. Drop enqueues handle metadata (no alloc, O(1))
//! 2. Background task dequeues and performs actual unmap
//! 3. If queue full, handle is leaked with warning (safety preserved)
//!
//! # Memory Safety
//!
//! Zombie handles prevent memory reuse until unmapped. The GC task runs
//! periodically and on memory pressure to reclaim IOVAs.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Maximum number of zombie entries.
/// Must be power of 2 for efficient modulo.
const ZOMBIE_QUEUE_CAPACITY: usize = 4096;

/// Mask for ring buffer index calculation.
const ZOMBIE_QUEUE_MASK: usize = ZOMBIE_QUEUE_CAPACITY - 1;

/// Zombie entry state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ZombieState {
    /// Slot is empty and available
    Empty = 0,
    /// Slot contains a pending zombie handle
    Pending = 1,
    /// Slot is being processed by GC
    Processing = 2,
}

/// Compact zombie entry (40 bytes total)
///
/// Stores minimal information needed to perform async unmap.
#[repr(C, align(64))]
struct ZombieEntry {
    /// IOVA base address
    iova: AtomicU64,
    /// Size in bytes
    size: AtomicU64,
    /// Domain ID (u16 for IOMMU domain)
    domain_id: AtomicU32,
    /// Mapping kind (encoded)
    mapping_kind: AtomicU32,
    /// Entry state + generation for ABA prevention
    /// Lower 8 bits: ZombieState
    /// Upper 24 bits: generation counter
    state_gen: AtomicU32,
    /// Padding for alignment
    _pad: AtomicU32,
}

impl ZombieEntry {
    const fn new() -> Self {
        Self {
            iova: AtomicU64::new(0),
            size: AtomicU64::new(0),
            domain_id: AtomicU32::new(0),
            mapping_kind: AtomicU32::new(0),
            state_gen: AtomicU32::new(0),
            _pad: AtomicU32::new(0),
        }
    }

    #[inline]
    fn state(&self) -> ZombieState {
        let v = self.state_gen.load(Ordering::Acquire);
        match v & 0xFF {
            0 => ZombieState::Empty,
            1 => ZombieState::Pending,
            2 => ZombieState::Processing,
            _ => ZombieState::Empty,
        }
    }

    #[inline]
    fn generation(&self) -> u32 {
        self.state_gen.load(Ordering::Acquire) >> 8
    }

    #[inline]
    fn pack_state_gen(state: ZombieState, generation: u32) -> u32 {
        ((generation & 0xFF_FFFF) << 8) | (state as u32)
    }

    /// Try to claim this slot for a new zombie entry.
    /// Returns the generation on success.
    fn try_claim(&self, expected_gen: u32) -> Option<u32> {
        let expected = Self::pack_state_gen(ZombieState::Empty, expected_gen);
        let new_gen = expected_gen.wrapping_add(1);
        let desired = Self::pack_state_gen(ZombieState::Pending, new_gen);

        self.state_gen
            .compare_exchange_weak(expected, desired, Ordering::AcqRel, Ordering::Relaxed)
            .ok()
            .map(|_| new_gen)
    }

    /// Mark entry as being processed (for GC).
    fn try_start_processing(&self) -> bool {
        let current = self.state_gen.load(Ordering::Acquire);
        if current & 0xFF != ZombieState::Pending as u32 {
            return false;
        }
        let generation = current >> 8;
        let desired = Self::pack_state_gen(ZombieState::Processing, generation);

        self.state_gen
            .compare_exchange(current, desired, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }

    /// Mark entry as empty (after GC completes).
    fn complete_processing(&self) {
        let current = self.state_gen.load(Ordering::Acquire);
        let generation = (current >> 8).wrapping_add(1);
        let desired = Self::pack_state_gen(ZombieState::Empty, generation);
        self.state_gen.store(desired, Ordering::Release);
    }

    /// Write zombie data to claimed slot.
    fn write(&self, iova: u64, size: u64, domain_id: u16, mapping_kind: u32) {
        self.iova.store(iova, Ordering::Relaxed);
        self.size.store(size, Ordering::Relaxed);
        self.domain_id.store(domain_id as u32, Ordering::Relaxed);
        self.mapping_kind.store(mapping_kind, Ordering::Release);
    }

    /// Read zombie data from slot.
    fn read(&self) -> ZombieData {
        // mapping_kind is the "release" store, read it last
        let mapping_kind = self.mapping_kind.load(Ordering::Acquire);
        ZombieData {
            iova: self.iova.load(Ordering::Relaxed),
            size: self.size.load(Ordering::Relaxed),
            domain_id: self.domain_id.load(Ordering::Relaxed) as u16,
            mapping_kind,
        }
    }
}

/// Data extracted from a zombie entry
#[derive(Debug, Clone, Copy)]
pub struct ZombieData {
    pub iova: u64,
    pub size: u64,
    /// IOMMU domain ID (u16)
    pub domain_id: u16,
    /// Encoded mapping kind (0=Identity, 1=Global, 2=Device, 3=Domain)
    pub mapping_kind: u32,
}

/// Global zombie queue (statically allocated)
pub struct ZombieQueue {
    entries: [ZombieEntry; ZOMBIE_QUEUE_CAPACITY],
    /// Producer hint (not authoritative, just helps find empty slots)
    producer_hint: AtomicU64,
    /// Consumer position (only modified by GC task)
    consumer_pos: AtomicU64,
    /// Statistics
    total_enqueued: AtomicU64,
    total_processed: AtomicU64,
    total_dropped: AtomicU64,
}

impl ZombieQueue {
    /// Create a new zombie queue.
    pub const fn new() -> Self {
        const EMPTY_ENTRY: ZombieEntry = ZombieEntry::new();
        Self {
            entries: [EMPTY_ENTRY; ZOMBIE_QUEUE_CAPACITY],
            producer_hint: AtomicU64::new(0),
            consumer_pos: AtomicU64::new(0),
            total_enqueued: AtomicU64::new(0),
            total_processed: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
        }
    }

    /// Try to enqueue a zombie handle.
    ///
    /// This is O(1) amortized, lock-free, and allocation-free.
    /// Safe to call from Drop or ISR context.
    ///
    /// Returns `true` if enqueued successfully.
    /// Returns `false` if queue is full (handle will be leaked).
    pub fn try_enqueue(
        &self,
        iova: u64,
        size: u64,
        domain_id: u16,
        mapping_kind: u32,
    ) -> bool {
        // Try a few positions starting from hint
        let hint = self.producer_hint.load(Ordering::Relaxed) as usize;

        for offset in 0..32 {
            let idx = (hint + offset) & ZOMBIE_QUEUE_MASK;
            let entry = &self.entries[idx];

            if entry.state() == ZombieState::Empty {
                let current_gen = entry.generation();
                if let Some(_new_gen) = entry.try_claim(current_gen) {
                    // Successfully claimed slot
                    entry.write(iova, size, domain_id, mapping_kind);
                    self.producer_hint
                        .store((idx + 1) as u64, Ordering::Relaxed);
                    self.total_enqueued.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
            }
        }

        // Queue appears full, scan more aggressively
        for idx in 0..ZOMBIE_QUEUE_CAPACITY {
            let entry = &self.entries[idx];
            if entry.state() == ZombieState::Empty {
                let current_gen = entry.generation();
                if let Some(_new_gen) = entry.try_claim(current_gen) {
                    entry.write(iova, size, domain_id, mapping_kind);
                    self.producer_hint
                        .store((idx + 1) as u64, Ordering::Relaxed);
                    self.total_enqueued.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
            }
        }

        // Queue is truly full
        self.total_dropped.fetch_add(1, Ordering::Relaxed);
        false
    }

    /// Process pending zombie entries.
    ///
    /// This should only be called from the GC task (single consumer).
    /// Calls the provided callback for each zombie entry.
    ///
    /// Returns the number of entries processed.
    pub fn process_pending<F>(&self, max_count: usize, mut callback: F) -> usize
    where
        F: FnMut(ZombieData) -> bool,
    {
        let mut processed = 0;
        let start = self.consumer_pos.load(Ordering::Relaxed) as usize;

        for offset in 0..ZOMBIE_QUEUE_CAPACITY.min(max_count * 2) {
            if processed >= max_count {
                break;
            }

            let idx = (start + offset) & ZOMBIE_QUEUE_MASK;
            let entry = &self.entries[idx];

            if entry.state() == ZombieState::Pending {
                if entry.try_start_processing() {
                    let data = entry.read();

                    // Call callback - if it returns true, processing succeeded
                    if callback(data) {
                        self.total_processed.fetch_add(1, Ordering::Relaxed);
                    }

                    // Mark slot as empty regardless (data is consumed)
                    entry.complete_processing();
                    processed += 1;
                }
            }
        }

        // Update consumer position hint
        if processed > 0 {
            self.consumer_pos.store(
                ((start + processed) & ZOMBIE_QUEUE_MASK) as u64,
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
            total_dropped: self.total_dropped.load(Ordering::Relaxed),
            capacity: ZOMBIE_QUEUE_CAPACITY,
        }
    }

    /// Estimate current pending count (not exact due to concurrency).
    pub fn pending_estimate(&self) -> usize {
        let enqueued = self.total_enqueued.load(Ordering::Relaxed);
        let processed = self.total_processed.load(Ordering::Relaxed);
        enqueued.saturating_sub(processed) as usize
    }
}

/// Zombie queue statistics
#[derive(Debug, Clone, Copy)]
pub struct ZombieQueueStats {
    pub total_enqueued: u64,
    pub total_processed: u64,
    pub total_dropped: u64,
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
pub fn enqueue_zombie(iova: u64, size: u64, domain_id: u16, mapping_kind: u32) -> bool {
    ZOMBIE_QUEUE.try_enqueue(iova, size, domain_id, mapping_kind)
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
pub fn encode_mapping_kind(kind: &super::dma_handle::MappingKind) -> u32 {
    use super::dma_handle::MappingKind;
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
pub fn decode_mapping_kind(encoded: u32) -> super::dma_handle::MappingKind {
    use super::dma_handle::MappingKind;
    use super::types::DeviceId;

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
pub fn run_zombie_gc(max_count: usize) -> usize {
    use super::dma_handle::MappingKind;
    use crate::io::iommu::registry::get_iommu_driver;

    let Some(driver) = get_iommu_driver() else {
        // No IOMMU driver - identity mappings don't need cleanup
        return process_zombies(max_count, |_| true);
    };

    process_zombies(max_count, |zombie| {
        let kind = decode_mapping_kind(zombie.mapping_kind);

        let result = match &kind {
            MappingKind::Identity => {
                // Identity mappings don't need IOMMU cleanup
                Ok(())
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
                // Can't fully clean domain mappings without more context
                // Log and accept the leak
                log::warn!(
                    "[ZombieGC] Domain mapping leaked: IOVA=0x{:x}, size={}, domain={}",
                    zombie.iova,
                    zombie.size,
                    zombie.domain_id
                );
                Ok(())
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
                false
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zombie_queue_basic() {
        let queue = ZombieQueue::new();

        // Enqueue a zombie (domain_id is u16)
        assert!(queue.try_enqueue(0x1000, 4096, 1u16, 0));

        // Check stats
        let stats = queue.stats();
        assert_eq!(stats.total_enqueued, 1);
        assert_eq!(stats.total_processed, 0);
        assert_eq!(stats.total_dropped, 0);

        // Process the zombie
        let mut processed_data: Option<ZombieData> = None;
        let count = queue.process_pending(10, |data| {
            processed_data = Some(data);
            true
        });

        assert_eq!(count, 1);
        let data = processed_data.unwrap();
        assert_eq!(data.iova, 0x1000);
        assert_eq!(data.size, 4096);
        assert_eq!(data.domain_id, 1);
    }

    #[test]
    fn test_mapping_kind_encoding() {
        use super::super::dma_handle::MappingKind;
        use super::super::types::DeviceId;

        // Identity
        let encoded = encode_mapping_kind(&MappingKind::Identity);
        assert!(matches!(decode_mapping_kind(encoded), MappingKind::Identity));

        // Global
        let encoded = encode_mapping_kind(&MappingKind::Global);
        assert!(matches!(decode_mapping_kind(encoded), MappingKind::Global));

        // Device (using BDF encoding: bus=0x12, device=0x06, function=0x04 = 0x1234)
        let device_id = DeviceId::from_bdf(0x1234);
        let encoded = encode_mapping_kind(&MappingKind::Device(device_id));
        if let MappingKind::Device(decoded_id) = decode_mapping_kind(encoded) {
            assert_eq!(decoded_id.bdf(), 0x1234);
        } else {
            panic!("Expected Device mapping kind");
        }

        // Domain
        let encoded = encode_mapping_kind(&MappingKind::Domain);
        assert!(matches!(decode_mapping_kind(encoded), MappingKind::Domain));
    }
}
