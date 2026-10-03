//! CPU cache entries retain an allocated block, not a globally free block.
//! Each class has one canonical Layout, including alignment. Returning a cached
//! allocation consumes its entry; failed insertion returns that same entry.
#![deny(unsafe_code)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::missing_safety_doc)]

use super::ExchangeBlocks;
use crate::sync::PoisonLock;
use alloc::sync::Arc;
use core::alloc::Layout;
use core::ptr::NonNull;

const CLASSES: usize = 6;
const CAPACITY: usize = 32;

#[derive(Clone, Copy)]
pub(crate) struct CacheClass(usize);

impl CacheClass {
    pub(crate) fn for_layout(layout: Layout) -> Option<Self> {
        let bytes = layout
            .size()
            .max(layout.align())
            .max(8)
            .checked_next_power_of_two()?;
        let index = bytes.trailing_zeros() as usize - 3;
        (index < CLASSES).then_some(Self(index))
    }

    pub(crate) fn layout(self) -> Layout {
        // The private checked index selects a small nonzero power of two; no
        // runtime request can reach an invalid Layout through this projection.
        let bytes = 8 << self.0;
        Layout::from_size_align(bytes, bytes).expect("checked canonical cache layout")
    }
}

pub(crate) struct CachedAllocation {
    ptr: NonNull<u8>,
    class: CacheClass,
}

#[expect(
    unsafe_code,
    reason = "cache entries move exclusive stable allocations between CPUs"
)]
// SAFETY: the private entry owns one live allocation without a borrow or
// reclaimer; moving it transfers exclusive reuse authority. The owning heap
// retains stable CPU-independent RAM; only the owner CPU mutates its magazine.
unsafe impl Send for CachedAllocation {}

impl CachedAllocation {
    /// # Safety
    /// Transfer one exclusive live block from the owning heap, using the class's
    /// canonical Layout. No aliases, independent cache entry or free operation
    /// may survive this transfer. The enclosing magazine retains its backing owner.
    #[expect(
        unsafe_code,
        reason = "allocation release is the unique raw allocator ownership boundary"
    )]
    pub(crate) unsafe fn retain(ptr: NonNull<u8>, class: CacheClass) -> Self {
        Self { ptr, class }
    }

    pub(crate) fn into_pointer(self) -> NonNull<u8> {
        self.ptr
    }
}

#[repr(align(128))]
pub(crate) struct ExchangeCache {
    blocks: [[Option<CachedAllocation>; CAPACITY]; CLASSES],
    counts: [usize; CLASSES],
}

impl ExchangeCache {
    pub(crate) const fn new() -> Self {
        Self {
            blocks: [const { [const { None }; CAPACITY] }; CLASSES],
            counts: [0; CLASSES],
        }
    }

    pub(crate) fn take(&mut self, class: CacheClass) -> Option<CachedAllocation> {
        let count = self.counts[class.0].checked_sub(1)?;
        let block = self.blocks[class.0][count].take();
        self.counts[class.0] = count;
        block
    }

    /// # Errors
    /// A full class returns the allocation unchanged for backing deallocation;
    /// failure never discards or duplicates its exclusive cache ownership.
    pub(crate) fn insert(&mut self, block: CachedAllocation) -> Result<(), CachedAllocation> {
        let class = block.class;
        let count = self.counts[class.0];
        if count == CAPACITY {
            return Err(block);
        }
        self.blocks[class.0][count] = Some(block);
        self.counts[class.0] = count + 1;
        Ok(())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.counts.iter().all(|&count| count == 0)
    }
    pub(crate) fn take_batch(&mut self) -> [Option<CachedAllocation>; CAPACITY] {
        core::array::from_fn(|_| (0..CLASSES).find_map(|index| self.take(CacheClass(index))))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExchangeDrainError {
    CacheBorrowed,
    AlreadyDraining,
    BackingBusy,
    BackingPoisoned,
}

struct BoundMagazine {
    backing: Arc<PoisonLock<ExchangeBlocks>>,
    cache: ExchangeCache,
}

enum MagazineState {
    Unbound,
    Bound(BoundMagazine),
    Draining,
}

/// A drain temporarily loans the contents to synchronous owner-CPU work.
/// While loaned, recursive allocation cannot bind or repopulate this storage.
/// Failed return restores the same backing and every cache entry before exit.
pub(crate) struct ExchangeMagazine {
    state: MagazineState,
}

impl ExchangeMagazine {
    pub(crate) const fn new() -> Self {
        Self {
            state: MagazineState::Unbound,
        }
    }

    pub(crate) fn matches(&self, backing: &Arc<PoisonLock<ExchangeBlocks>>) -> bool {
        matches!(&self.state, MagazineState::Bound(bound) if Arc::ptr_eq(&bound.backing, backing))
    }

    pub(crate) fn is_empty(&self) -> bool {
        match &self.state {
            MagazineState::Unbound => true,
            MagazineState::Bound(bound) => bound.cache.is_empty(),
            MagazineState::Draining => false,
        }
    }

    pub(crate) fn bind(
        &mut self,
        backing: Arc<PoisonLock<ExchangeBlocks>>,
    ) -> Result<(), Arc<PoisonLock<ExchangeBlocks>>> {
        if !matches!(self.state, MagazineState::Unbound) {
            return Err(backing);
        }
        self.state = MagazineState::Bound(BoundMagazine {
            backing,
            cache: ExchangeCache::new(),
        });
        Ok(())
    }

    pub(crate) fn take(
        &mut self,
        backing: &Arc<PoisonLock<ExchangeBlocks>>,
        class: CacheClass,
    ) -> Option<CachedAllocation> {
        match &mut self.state {
            MagazineState::Bound(bound) if Arc::ptr_eq(&bound.backing, backing) => {
                bound.cache.take(class)
            }
            _ => None,
        }
    }

    pub(crate) fn insert(
        &mut self,
        backing: &Arc<PoisonLock<ExchangeBlocks>>,
        allocation: CachedAllocation,
    ) -> Result<(), CachedAllocation> {
        match &mut self.state {
            MagazineState::Bound(bound) if Arc::ptr_eq(&bound.backing, backing) => {
                bound.cache.insert(allocation)
            }
            _ => Err(allocation),
        }
    }

    fn begin_drain(&mut self) -> Result<Option<BoundMagazine>, ExchangeDrainError> {
        match &self.state {
            MagazineState::Unbound => return Ok(None),
            MagazineState::Draining => return Err(ExchangeDrainError::AlreadyDraining),
            MagazineState::Bound(_) => {}
        }
        let MagazineState::Bound(bound) =
            core::mem::replace(&mut self.state, MagazineState::Draining)
        else {
            unreachable!("bound state was exclusively observed above")
        };
        Ok(Some(bound))
    }

    fn finish_drain(&mut self, retained: Option<BoundMagazine>) {
        assert!(matches!(self.state, MagazineState::Draining));
        self.state = retained.map_or(MagazineState::Unbound, MagazineState::Bound);
    }
}

impl BoundMagazine {
    /// No cache owner or backing lease is consumed on failure. A successful
    /// lock is the only fallible step and precedes all block-list mutations.
    #[expect(
        unsafe_code,
        reason = "consumption returns exclusive entries to their retained backing owner"
    )]
    fn release(&mut self) -> Result<usize, ExchangeDrainError> {
        if self.cache.is_empty() {
            return Ok(0);
        }
        use crate::sync::poison_lock::TryLockError;
        let mut blocks = match self.backing.try_lock() {
            Ok(blocks) => blocks,
            Err(TryLockError::WouldBlock) => return Err(ExchangeDrainError::BackingBusy),
            Err(TryLockError::Poisoned(_)) => return Err(ExchangeDrainError::BackingPoisoned),
        };
        let mut bytes = 0;
        for _ in 0..CLASSES {
            for allocation in self.cache.take_batch().into_iter().flatten() {
                let layout = allocation.class.layout();
                bytes += layout.size();
                // SAFETY: the sole entry is consumed; this exact backing and
                // canonical Layout survive through the complete return.
                unsafe { blocks.deallocate(allocation.into_pointer(), layout) };
            }
        }
        Ok(bytes)
    }
}

pub(crate) fn drain_current_cache() -> Result<usize, ExchangeDrainError> {
    let Some(cpu) = crate::cpu::CurrentCpu::acquire() else {
        return Ok(0); // an unbound bootstrap CPU cannot own a magazine
    };
    let Some(mut bound) = cpu
        .with_exchange_cache(ExchangeMagazine::begin_drain)
        .ok_or(ExchangeDrainError::CacheBorrowed)??
    else {
        return Ok(0);
    };
    let result = bound.release(); // outside IRQ/preemption-excluded cache borrow
    let mut retained = result.is_err().then_some(bound);
    cpu.with_exchange_cache(|cache| cache.finish_drain(retained.take()))
        .expect("synchronous owner cache loan cannot outlive its CPU or borrow");
    // On success the backing lease was dropped outside the short CPU borrow.
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[expect(
        unsafe_code,
        reason = "fixture transfers exclusive host RAM into the boot ownership boundary"
    )]
    fn backing() -> Arc<PoisonLock<ExchangeBlocks>> {
        let slab = boot_proto::BootstrapHeapLayout::new(4096, 256 * 1024).expect("slab Layout");
        // SAFETY: valid nonzero Layout transferred once to bootstrap ownership;
        // no source deallocation or independent user survives this transfer.
        let pointer = unsafe { alloc::alloc::alloc(slab.allocation()) };
        assert!(!pointer.is_null());
        let geometry = slab
            .at(pointer.expose_provenance() as u64, 0, u64::MAX)
            .expect("identity mapping");
        // SAFETY: fresh exclusive writable stable RAM with identity mapping.
        let heaps = unsafe {
            crate::heap::BootstrapHeaps::from_handoff(geometry.descriptor(), 0, u64::MAX)
        }
        .expect("bootstrap ownership transfer");
        let (_, memory, _) = heaps.into_parts();
        let backing = Arc::new(PoisonLock::new(ExchangeBlocks::empty()));
        backing
            .lock()
            .unwrap_or_else(|_| panic!("fixture backing lock poisoned"))
            .initialize(memory)
            .unwrap();
        backing
    }

    #[expect(
        unsafe_code,
        reason = "fixture transfers a fresh exclusive block into its retained magazine"
    )]
    fn retain_one(magazine: &mut ExchangeMagazine, backing: &Arc<PoisonLock<ExchangeBlocks>>) {
        let class = CacheClass::for_layout(Layout::new::<u64>()).unwrap();
        let pointer = backing
            .lock()
            .unwrap_or_else(|_| panic!("fixture backing lock poisoned"))
            .allocate(class.layout())
            .unwrap();
        // SAFETY: fresh canonical block transferred exactly once to its backing's magazine.
        let entry = unsafe { CachedAllocation::retain(pointer, class) };
        assert!(magazine.insert(backing, entry).is_ok());
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    #[expect(
        unsafe_code,
        reason = "fixture fills cache classes from uniquely allocated canonical blocks"
    )]
    fn draining_retains_every_class_and_backing_until_return_finishes() {
        let backing = backing();
        let initial = backing
            .lock()
            .unwrap_or_else(|_| panic!("fixture backing lock poisoned"))
            .stats()
            .free;
        let mut magazine = ExchangeMagazine::new();
        assert!(magazine.bind(Arc::clone(&backing)).is_ok());
        for bytes in [8, 16, 32, 64, 128, 256] {
            let class =
                CacheClass::for_layout(Layout::from_size_align(bytes, bytes).unwrap()).unwrap();
            for _ in 0..CAPACITY {
                let pointer = backing
                    .lock()
                    .unwrap_or_else(|_| panic!("fixture backing lock poisoned"))
                    .allocate(class.layout())
                    .unwrap();
                // SAFETY: unique canonical block; the magazine retains this exact backing.
                let entry = unsafe { CachedAllocation::retain(pointer, class) };
                assert!(magazine.insert(&backing, entry).is_ok());
            }
        }
        let mut loan = magazine.begin_drain().unwrap().unwrap();
        assert!(!magazine.is_empty());
        assert!(!magazine.matches(&backing));
        assert!(magazine.bind(Arc::clone(&backing)).is_err());
        assert!(matches!(
            magazine.begin_drain(),
            Err(ExchangeDrainError::AlreadyDraining)
        ));
        assert_eq!(
            loan.release(),
            Ok(CAPACITY * (8 + 16 + 32 + 64 + 128 + 256))
        );
        magazine.finish_drain(None);
        drop(loan);
        assert!(magazine.is_empty());
        assert_eq!(Arc::strong_count(&backing), 1);
        assert_eq!(
            backing
                .lock()
                .unwrap_or_else(|_| panic!("fixture backing lock poisoned"))
                .stats()
                .free,
            initial
        );
        assert_eq!(
            backing
                .lock()
                .unwrap_or_else(|_| panic!("fixture backing lock poisoned"))
                .stats()
                .allocated,
            0
        );
        assert!(magazine.bind(Arc::clone(&backing)).is_ok());
        retain_one(&mut magazine, &backing);
        let retained = Arc::downgrade(&backing);
        drop(backing);
        let mut loan = magazine.begin_drain().unwrap().unwrap();
        assert!(retained.upgrade().is_some());
        assert_eq!(loan.release(), Ok(8));
        magazine.finish_drain(None);
        drop(loan);
        assert!(retained.upgrade().is_none());
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn busy_backing_restores_the_same_magazine_without_reporting_a_return() {
        let backing = backing();
        let mut magazine = ExchangeMagazine::new();
        assert!(magazine.bind(Arc::clone(&backing)).is_ok());
        retain_one(&mut magazine, &backing);
        let mut loan = magazine.begin_drain().unwrap().unwrap();
        let locked = backing
            .lock()
            .unwrap_or_else(|_| panic!("fixture backing lock poisoned"));
        let allocated = locked.stats().allocated;
        assert_eq!(loan.release(), Err(ExchangeDrainError::BackingBusy));
        assert_eq!(locked.stats().allocated, allocated);
        magazine.finish_drain(Some(loan));
        assert!(magazine.matches(&backing));
        assert!(!magazine.is_empty());
        drop(locked);
        let mut loan = magazine.begin_drain().unwrap().unwrap();
        assert_eq!(loan.release(), Ok(8));
        magazine.finish_drain(None);
        drop(loan);
        assert!(magazine.is_empty());
        assert_eq!(
            backing
                .lock()
                .unwrap_or_else(|_| panic!("fixture backing lock poisoned"))
                .stats()
                .allocated,
            0
        );
    }
    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    #[expect(
        unsafe_code,
        reason = "fixture transfers an exclusive allocation into owner CPU storage"
    )]
    fn partial_owner_drain_keeps_returned_progress_and_failed_exchange_owners() {
        let Some(cpu) = crate::cpu::CurrentCpu::acquire() else {
            return;
        };
        super::super::reclaim::drain_local_caches().expect("initial owner drain");
        let layout = Layout::from_size_align(64, 64).unwrap();
        let block = super::super::raw::allocate(layout).expect("fixture slab reservation");
        super::super::raw::cache_or_release(block, layout);

        let backing = backing();
        let class = CacheClass::for_layout(Layout::new::<u64>()).unwrap();
        let pointer = backing
            .lock()
            .unwrap_or_else(|_| panic!("fixture backing poisoned"))
            .allocate(class.layout())
            .unwrap();
        // SAFETY: this freshly allocated canonical block is transferred once;
        // the owner CPU magazine retains the exact backing before publication.
        let entry = unsafe { CachedAllocation::retain(pointer, class) };
        let lease = Arc::clone(&backing);
        cpu.with_exchange_cache(|cache| {
            assert!(cache.bind(lease).is_ok());
            assert!(cache.insert(&backing, entry).is_ok());
        })
        .expect("owner storage");
        let held = backing
            .lock()
            .unwrap_or_else(|_| panic!("fixture backing poisoned"));
        let before = held.stats().allocated;
        let failure =
            super::super::reclaim::drain_local_caches().expect_err("busy exchange backing");
        assert_eq!(
            failure.cause,
            super::super::reclaim::LocalCacheDrainError::Exchange(ExchangeDrainError::BackingBusy)
        );
        assert!(failure.progress.heap_returned_bytes >= 64);
        assert!(failure.progress.made_progress());
        assert_eq!(held.stats().allocated, before);
        assert!(!cpu.memory_caches_empty());
        drop(held);
        let progress = super::super::reclaim::drain_local_caches().expect("owner retry");
        assert_eq!(progress.heap_returned_bytes, 8);
        assert_eq!(progress.physical_reclaimed_bytes, 0);
        assert!(cpu.memory_caches_empty());
        assert_eq!(
            backing
                .lock()
                .unwrap_or_else(|_| panic!("fixture backing poisoned"))
                .stats()
                .allocated,
            0
        );
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn empty_magazine_unbinds_without_acquiring_its_busy_backing() {
        let backing = backing();
        let mut magazine = ExchangeMagazine::new();
        assert!(magazine.bind(Arc::clone(&backing)).is_ok());
        let locked = backing
            .lock()
            .unwrap_or_else(|_| panic!("fixture backing lock poisoned"));
        let mut loan = magazine.begin_drain().unwrap().unwrap();
        assert_eq!(loan.release(), Ok(0));
        magazine.finish_drain(None);
        drop(loan);
        assert!(magazine.is_empty());
        assert_eq!(Arc::strong_count(&backing), 1);
        assert_eq!(locked.stats().allocated, 0);
    }
}
