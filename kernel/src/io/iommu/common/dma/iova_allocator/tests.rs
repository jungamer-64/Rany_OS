use super::*;
use crate::mm::phys::fast_allocator::PAGE_SIZE_4K;

#[expect(
    unsafe_code,
    reason = "these private address spaces never acquire a hardware translation user"
)]
fn complete_unpublished_allocator_flush(allocator: &Arc<IovaAllocator>) {
    let pending = allocator.begin_global_flush().expect("local flush capture");
    // SAFETY: these local address-space fixtures are never installed in a
    // controller or device context. They have no IOTLB/ATS translation users.
    unsafe { pending.complete_after_global_invalidation() };
}

#[cfg_attr(any(feature = "std", target_os = "linux"), test)]
#[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
fn large_extent_uses_one_retirement_admission() {
    let size = (QUARANTINE_CAPACITY as u64 + 1) * PAGE_SIZE_4K;
    let allocator = Arc::new(IovaAllocator::new(PAGE_SIZE_4K, size).unwrap());
    let extent = allocator.allocate_contiguous(size, PAGE_SIZE_4K).unwrap();
    allocator.free(extent, size).unwrap();
    assert_eq!(allocator.stats.quarantine_pushes.load(Ordering::Relaxed), 1);
    assert!(allocator.allocate_4k().is_none());
    complete_unpublished_allocator_flush(&allocator);
    assert_eq!(
        allocator.allocate_contiguous(size, PAGE_SIZE_4K),
        Some(extent)
    );
}

#[cfg_attr(any(feature = "std", target_os = "linux"), test)]
#[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
fn full_quarantine_rejection_retains_the_complete_extent_for_retry() {
    let prefix_size = (QUARANTINE_CAPACITY as u64 - 1) * PAGE_SIZE_4K;
    let range_size = 3 * PAGE_SIZE_4K;
    let allocator =
        Arc::new(IovaAllocator::new(PAGE_SIZE_4K, prefix_size + 2 * range_size).unwrap());
    let prefix = allocator
        .allocate_contiguous(prefix_size, PAGE_SIZE_4K)
        .unwrap();
    let accepted = allocator
        .allocate_contiguous(range_size, PAGE_SIZE_4K)
        .unwrap();
    let retained = allocator
        .allocate_contiguous(range_size, PAGE_SIZE_4K)
        .unwrap();
    // LOOP_PROOF: mode=bounded; reason=The prefix contains QUARANTINE_CAPACITY minus one pages.;
    for index in 0..QUARANTINE_CAPACITY - 1 {
        allocator
            .free(prefix + index as u64 * PAGE_SIZE_4K, PAGE_SIZE_4K)
            .unwrap();
    }
    // One remaining queue slot must admit this entire multi-page range.
    allocator.free(accepted, range_size).unwrap();
    assert_eq!(
        allocator.stats.quarantine_pushes.load(Ordering::Relaxed),
        QUARANTINE_CAPACITY as u64
    );
    assert_eq!(
        allocator.free(retained, range_size),
        Err(IommuError::OutOfMemory)
    );
    assert_eq!(
        allocator.stats.quarantine_pushes.load(Ordering::Relaxed),
        QUARANTINE_CAPACITY as u64
    );
    complete_unpublished_allocator_flush(&allocator);
    let reused = allocator.allocate_contiguous(prefix_size + range_size, PAGE_SIZE_4K);
    assert_eq!(reused, Some(prefix));
    assert!(allocator.allocate_4k().is_none());
    allocator.free(retained, range_size).unwrap();
    complete_unpublished_allocator_flush(&allocator);
    assert_eq!(
        allocator.allocate_contiguous(range_size, PAGE_SIZE_4K),
        Some(retained)
    );
}

#[cfg_attr(any(feature = "std", target_os = "linux"), test)]
#[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
fn invalid_extent_transfers_no_retirement_progress() {
    let size = 4 * PAGE_SIZE_4K;
    let allocator = Arc::new(IovaAllocator::new(PAGE_SIZE_4K, size).unwrap());
    let extent = allocator.allocate_contiguous(size, PAGE_SIZE_4K).unwrap();
    assert_eq!(allocator.free(extent, 0), Err(IommuError::InvalidAddress));
    assert_eq!(
        allocator.free(extent + 1, size),
        Err(IommuError::InvalidAlignment)
    );
    assert_eq!(
        allocator.free(extent, size + 1),
        Err(IommuError::InvalidAlignment)
    );
    assert_eq!(
        allocator.free(extent, size + PAGE_SIZE_4K),
        Err(IommuError::InvalidAddress)
    );
    assert_eq!(
        allocator.free(u64::MAX - PAGE_SIZE_4K + 1, PAGE_SIZE_4K),
        Err(IommuError::InvalidAddress)
    );
    assert_eq!(allocator.stats.quarantine_pushes.load(Ordering::Relaxed), 0);
    assert!(allocator.allocate_4k().is_none());
    allocator.free(extent, size).unwrap();
    complete_unpublished_allocator_flush(&allocator);
    assert_eq!(
        allocator.allocate_contiguous(size, PAGE_SIZE_4K),
        Some(extent)
    );
}
