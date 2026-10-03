//! Owner-CPU drain preserves partial progress and every failed cache owner.
use super::{exchange_cache, raw};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalCacheDrainError {
    Exchange(exchange_cache::ExchangeDrainError),
    OwnerStorageBorrowed,
}

/// Heap reservation bytes returned to their source pools and physical bytes
/// actually returned to PMM are distinct observations. A slab return can count
/// in both when the last reservation retires its whole backing page; neither
/// number is a domain quota refund or an estimate of currently free RAM.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CacheDrainProgress {
    pub(crate) heap_returned_bytes: usize,
    pub(crate) physical_reclaimed_bytes: usize,
}

impl CacheDrainProgress {
    pub(crate) fn made_progress(self) -> bool {
        self.heap_returned_bytes != 0 || self.physical_reclaimed_bytes != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalCacheDrainFailure {
    pub(crate) progress: CacheDrainProgress,
    pub(crate) cause: LocalCacheDrainError,
}

/// Pressure may defer a failed return; offline observes successful owner drain
/// before acknowledging park. Independent caches still return their reservations
/// and RAM if Exchange backing is busy/poisoned. Failure preserves that progress.
pub(crate) fn drain_local_caches() -> Result<CacheDrainProgress, LocalCacheDrainFailure> {
    let exchange = exchange_cache::drain_current_cache();
    let mut progress = raw::drain_current_cache();
    progress.physical_reclaimed_bytes += crate::mm::phys::frame_allocator::drain_current_cache();
    match exchange {
        Ok(bytes) => progress.heap_returned_bytes += bytes,
        Err(cause) => {
            return Err(LocalCacheDrainFailure {
                progress,
                cause: LocalCacheDrainError::Exchange(cause),
            });
        }
    }
    if crate::cpu::CurrentCpu::acquire().is_some_and(|cpu| !cpu.memory_caches_empty()) {
        return Err(LocalCacheDrainFailure {
            progress,
            cause: LocalCacheDrainError::OwnerStorageBorrowed,
        });
    }
    Ok(progress)
}

pub(crate) fn reclaim_local_caches() -> CacheDrainProgress {
    match drain_local_caches() {
        Ok(progress) => progress,
        Err(failure) => {
            // Pressure recovery retains failed entries in owner storage for a
            // later pass; the returned progress never claims successful drain.
            log::warn!("owner CPU cache reclaim deferred: {failure:?}");
            failure.progress
        }
    }
}
