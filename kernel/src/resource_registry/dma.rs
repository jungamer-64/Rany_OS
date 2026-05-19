use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::domain::DomainId;
use crate::sync::PoisonLock;

struct DmaEntry {
    _buffer: Box<dyn core::any::Any + Send>,
    phys: u64,
    size: usize,
    owner: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DmaCleanupStats {
    pub(crate) handles: usize,
    pub(crate) bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DmaReleaseError {
    UnknownHandle,
    ForeignOwner { owner: u64 },
}

struct DmaRegistry {
    buffers: PoisonLock<BTreeMap<usize, DmaEntry>>,
    next_id: AtomicU64,
}

impl DmaRegistry {
    const fn new() -> Self {
        Self {
            buffers: PoisonLock::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    fn register(
        &self,
        buffer: Box<dyn core::any::Any + Send>,
        phys: u64,
        size: usize,
        owner: u64,
    ) -> usize {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) as usize;
        self.buffers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                id,
                DmaEntry {
                    _buffer: buffer,
                    phys,
                    size,
                    owner,
                },
            );
        id
    }

    fn release_owned(
        &self,
        dma_handle_id: usize,
        caller: u64,
    ) -> Result<DmaEntry, DmaReleaseError> {
        let mut buffers = self.buffers.lock().unwrap_or_else(|e| e.into_inner());
        match buffers.get(&dma_handle_id) {
            Some(entry) if entry.owner != caller => {
                Err(DmaReleaseError::ForeignOwner { owner: entry.owner })
            }
            Some(_) => buffers
                .remove(&dma_handle_id)
                .ok_or(DmaReleaseError::UnknownHandle),
            None => Err(DmaReleaseError::UnknownHandle),
        }
    }

    fn reclaim_owner(&self, owner: u64) -> Vec<DmaEntry> {
        let mut buffers = self.buffers.lock().unwrap_or_else(|e| e.into_inner());
        let ids: Vec<usize> = buffers
            .iter()
            .filter_map(|(id, entry)| (entry.owner == owner).then_some(*id))
            .collect();
        let mut reclaimed = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(entry) = buffers.remove(&id) {
                reclaimed.push(entry);
            }
        }
        reclaimed
    }

    #[cfg(test)]
    fn contains(&self, dma_handle_id: usize) -> bool {
        self.buffers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&dma_handle_id)
    }

    #[cfg(test)]
    fn drain_all(&self) -> Vec<DmaEntry> {
        let mut buffers = self.buffers.lock().unwrap_or_else(|e| e.into_inner());
        core::mem::take(&mut *buffers).into_values().collect()
    }
}

struct PhysOwnershipRegistry {
    ranges: PoisonLock<BTreeMap<u64, (usize, u64)>>,
}

impl PhysOwnershipRegistry {
    const fn new() -> Self {
        Self {
            ranges: PoisonLock::new(BTreeMap::new()),
        }
    }

    fn register(&self, phys: u64, size: usize, owner: u64) {
        self.ranges
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(phys, (size, owner));
    }

    fn unregister(&self, phys: u64) {
        self.ranges
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&phys);
    }
}

static DMA_REGISTRY: DmaRegistry = DmaRegistry::new();
static PHYS_OWNERSHIP_REGISTRY: PhysOwnershipRegistry = PhysOwnershipRegistry::new();

pub(crate) fn register_allocation(
    buffer: Box<dyn core::any::Any + Send>,
    phys: u64,
    size: usize,
    owner: u64,
) -> u64 {
    PHYS_OWNERSHIP_REGISTRY.register(phys, size, owner);
    DMA_REGISTRY.register(buffer, phys, size, owner) as u64
}

pub(crate) fn release_owned(dma_handle_id: u64, caller: u64) -> Result<(), DmaReleaseError> {
    let entry = DMA_REGISTRY.release_owned(dma_handle_id as usize, caller)?;
    PHYS_OWNERSHIP_REGISTRY.unregister(entry.phys);
    Ok(())
}

pub(crate) fn cleanup_owner(owner: DomainId) -> DmaCleanupStats {
    let reclaimed = DMA_REGISTRY.reclaim_owner(owner.as_u64());
    let stats = DmaCleanupStats {
        handles: reclaimed.len(),
        bytes: reclaimed.iter().map(|entry| entry.size).sum(),
    };

    for entry in &reclaimed {
        PHYS_OWNERSHIP_REGISTRY.unregister(entry.phys);
    }

    stats
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    static DMA_TEST_STATE_LOCK: spin::Mutex<()> = spin::Mutex::new(());

    struct TestDmaDropProbe {
        drop_counter: &'static core::sync::atomic::AtomicUsize,
    }

    impl Drop for TestDmaDropProbe {
        fn drop(&mut self) {
            self.drop_counter
                .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        }
    }

    fn reset_test_dma_state() {
        let entries = DMA_REGISTRY.drain_all();
        PHYS_OWNERSHIP_REGISTRY
            .ranges
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        drop(entries);
    }

    pub(crate) struct TestDmaStateGuard {
        _lock: spin::MutexGuard<'static, ()>,
    }

    impl Drop for TestDmaStateGuard {
        fn drop(&mut self) {
            reset_test_dma_state();
        }
    }

    pub(crate) fn acquire_test_dma_state_guard() -> TestDmaStateGuard {
        let lock = DMA_TEST_STATE_LOCK.lock();
        reset_test_dma_state();
        TestDmaStateGuard { _lock: lock }
    }

    pub(crate) fn register_test_dma_entry(
        owner: u64,
        phys: u64,
        size: usize,
        drop_counter: &'static core::sync::atomic::AtomicUsize,
    ) -> u64 {
        let buffer: Box<dyn core::any::Any + Send> = Box::new(TestDmaDropProbe { drop_counter });
        register_allocation(buffer, phys, size, owner)
    }

    pub(crate) fn test_dma_handle_exists(dma_handle_id: u64) -> bool {
        DMA_REGISTRY.contains(dma_handle_id as usize)
    }

    pub(crate) fn test_dma_phys_owned_by(phys: u64, size: usize, owner: u64) -> bool {
        PHYS_OWNERSHIP_REGISTRY.is_owned_by(phys, size, owner)
    }
}
