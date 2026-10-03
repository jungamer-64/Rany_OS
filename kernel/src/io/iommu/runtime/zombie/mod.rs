//! Bounded deferred DMA retirement. A queued value owns the backing,
//! translation origin and unfinished phase. Rejection returns that same value.
//! Failed or interrupted reclamation retains its progress in the slot.
//! Completed translation ownership is consumed before running a backing
//! destructor, so unwinding cannot repeat retirement; Drop never waits for hardware.

use crate::io::iommu::common::dma::mapping_outcome::DeviceMappedRange;
use crate::io::iommu::types::IommuError;
use crate::ipc::rref::RRefRawParts;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

/// Maximum admitted DMA retirement owners. Registry metadata can use this
/// bound because every published mapping retains one reservation.
pub(crate) const DMA_RETIREMENT_CAPACITY: usize = 4096;
const MAX_PROBES: usize = 64;
const EMPTY: u8 = 0;
const RESERVED: u8 = 1;
const PENDING: u8 = 2;
const PROCESSING: u8 = 3;

struct Slot<T> {
    state: AtomicU8,
    payload: UnsafeCell<MaybeUninit<T>>,
}
impl<T> Slot<T> {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            payload: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }
}
// SAFETY: a successful state transition grants exclusive access to the payload;
// Release publication is paired with Acquire ownership before reading it.
unsafe impl<T: Send> Sync for Slot<T> {}

/// A consumer borrow returns its published owner on unwinding. Completion
/// consumes the payload before making the slot available to another producer.
struct ProcessingSlot<'a, T> {
    slot: Option<&'a Slot<T>>,
}
impl<T> ProcessingSlot<'_, T> {
    fn value(&mut self) -> &mut T {
        let slot = self.slot.expect("active consumer borrow");
        // SAFETY: this guard exclusively owns the Processing transition.
        unsafe { (*slot.payload.get()).assume_init_mut() }
    }
    fn complete(mut self) {
        let slot = self.slot.take().expect("unconsumed completion");
        // SAFETY: consume the published value before releasing its slot. The
        // returned value is independent of subsequent producer writes.
        let value = unsafe { (*slot.payload.get()).assume_init_read() };
        slot.state.store(EMPTY, Ordering::Release);
        // A destructor panic cannot cause a second payload read/drop.
        drop(value);
    }
}
impl<T> Drop for ProcessingSlot<'_, T> {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.take() {
            slot.state.store(PENDING, Ordering::Release);
        }
    }
}

/// Slots, rather than a reservation-order ring, bound producer work even when
/// another producer is interrupted between admission and publication.
struct ReclaimSlots<T, const N: usize> {
    slots: [Slot<T>; N],
    producer: AtomicU64,
    consumer: AtomicU64,
}
impl<T, const N: usize> ReclaimSlots<T, N> {
    const fn new() -> Self {
        assert!(N > 0);
        Self {
            slots: [const { Slot::new() }; N],
            producer: AtomicU64::new(0),
            consumer: AtomicU64::new(0),
        }
    }
    fn reserve(&self) -> Option<SlotReservation<'_, T, N>> {
        let start = self.producer.fetch_add(1, Ordering::Relaxed) as usize % N;
        for offset in 0..N.min(MAX_PROBES) {
            let index = (start + offset) % N;
            if self.slots[index]
                .state
                .compare_exchange(EMPTY, RESERVED, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return Some(SlotReservation {
                    queue: self,
                    index: Some(index),
                });
            }
        }
        None
    }
    /// Each attempted value counts against the pass budget, including failures.
    /// A failed callback's mutated progress remains owned by the same slot.
    fn process(
        &self,
        budget: usize,
        mut reclaim: impl FnMut(&mut T) -> Result<(), IommuError>,
    ) -> usize {
        let start = self.consumer.load(Ordering::Relaxed) as usize % N;
        let mut attempts = 0;
        let mut completed = 0;
        let mut scanned = 0;
        for offset in 0..N {
            if attempts >= budget {
                break;
            }
            scanned = offset + 1;
            let slot = &self.slots[(start + offset) % N];
            if slot
                .state
                .compare_exchange(PENDING, PROCESSING, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                continue;
            }
            attempts += 1;
            let mut claim = ProcessingSlot { slot: Some(slot) };
            if reclaim(claim.value()).is_ok() {
                claim.complete();
                completed += 1;
            }
        }
        self.consumer
            .store(((start + scanned) % N) as u64, Ordering::Relaxed);
        completed
    }
    fn has_pending(&self) -> bool {
        self.slots
            .iter()
            .any(|slot| matches!(slot.state.load(Ordering::Acquire), PENDING | PROCESSING))
    }
}
/// One absent payload slot admitted before an operation can publish DMA.
/// It cannot be cloned, and publication consumes the reservation.
struct SlotReservation<'a, T, const N: usize> {
    queue: &'a ReclaimSlots<T, N>,
    index: Option<usize>,
}
impl<T, const N: usize> SlotReservation<'_, T, N> {
    fn publish(mut self, value: T) {
        let index = self.index.take().expect("unconsumed reclamation admission");
        let slot = &self.queue.slots[index];
        // SAFETY: this reservation exclusively owns an absent payload slot.
        unsafe {
            (*slot.payload.get()).write(value);
        }
        slot.state.store(PENDING, Ordering::Release);
    }
}
impl<T, const N: usize> Drop for SlotReservation<'_, T, N> {
    fn drop(&mut self) {
        if let Some(index) = self.index.take() {
            self.queue.slots[index]
                .state
                .store(EMPTY, Ordering::Release);
        }
    }
}

impl<T, const N: usize> Drop for ReclaimSlots<T, N> {
    fn drop(&mut self) {
        for slot in &mut self.slots {
            if *slot.state.get_mut() == PENDING {
                // SAFETY: &mut self excludes producers and consumers.
                unsafe { slot.payload.get_mut().assume_init_drop() };
            }
        }
    }
}

/// Type erasure transfers exactly one backing owner; it never reduces a device
/// identity to BDF or reconstructs its domain from current global registration.
pub(in crate::io::iommu) struct DroppedDma {
    mapping: Option<DeviceMappedRange>,
    backing: Option<RRefRawParts>,
}
impl DroppedDma {
    /// # Safety
    /// The mapping covers this exact retained backing. Device access cannot
    /// invalidate its Rust values or access independent ownership metadata.
    /// CPU borrows are absent until retirement; neither owner has another
    /// reclaimer. Moving them together transfers this obligation to the queue.
    pub(in crate::io::iommu) unsafe fn new<T: Send + ?Sized + 'static>(
        mapping: DeviceMappedRange,
        backing: crate::ipc::RRef<T>,
    ) -> Self {
        Self {
            mapping: Some(mapping),
            backing: Some(backing.into_raw_parts()),
        }
    }
    fn reclaim(&mut self) -> Result<(), IommuError> {
        if let Some(mapping) = self.mapping.as_mut() {
            mapping.resume_retirement()?;
            self.mapping.take();
        }
        if let Some(backing) = self.backing.take() {
            // SAFETY: this owner detached the exact range and completed IOTLB,
            // paging-structure, ATS and DMA drain before making backing reusable.
            unsafe { backing.drop_erased() };
        }
        Ok(())
    }
}

static QUEUE: ReclaimSlots<DroppedDma, DMA_RETIREMENT_CAPACITY> = ReclaimSlots::new();
static ENQUEUED: AtomicU64 = AtomicU64::new(0);
static PROCESSED: AtomicU64 = AtomicU64::new(0);
static REJECTED: AtomicU64 = AtomicU64::new(0);

/// Admission occupies one of the finite retirement slots before any data leaf
/// can be published. Drop can then transfer ownership without failure or I/O.
pub(in crate::io::iommu) struct DmaRetirementReservation(
    SlotReservation<'static, DroppedDma, DMA_RETIREMENT_CAPACITY>,
);
impl core::fmt::Debug for DmaRetirementReservation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DmaRetirementReservation")
    }
}
impl DmaRetirementReservation {
    pub(in crate::io::iommu) fn publish(self, payload: DroppedDma) {
        self.0.publish(payload);
        ENQUEUED.fetch_add(1, Ordering::Relaxed);
    }
}
pub(in crate::io::iommu) fn reserve_retirement() -> Option<DmaRetirementReservation> {
    match QUEUE.reserve() {
        Some(reservation) => Some(DmaRetirementReservation(reservation)),
        None => {
            REJECTED.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

pub fn run_zombie_gc(budget: usize) -> usize {
    let completed = QUEUE.process(budget, |payload| {
        let result = payload.reclaim();
        if let Err(cause) = result {
            log::warn!("DMA retirement remains pending: {cause:?}");
        }
        result
    });
    PROCESSED.fetch_add(completed as u64, Ordering::Relaxed);
    completed
}
pub fn has_pending_zombies() -> bool {
    QUEUE.has_pending()
}
#[derive(Debug, Clone, Copy)]
pub struct ZombieQueueStats {
    pub total_enqueued: u64,
    pub total_processed: u64,
    /// CPU owners rejected before DMA publication because no slot was admitted.
    pub admission_refused: u64,
}
pub fn zombie_stats() -> ZombieQueueStats {
    ZombieQueueStats {
        total_enqueued: ENQUEUED.load(Ordering::Relaxed),
        total_processed: PROCESSED.load(Ordering::Relaxed),
        admission_refused: REJECTED.load(Ordering::Relaxed),
    }
}
#[cfg(test)]
mod tests;
