use super::*;
use crate::mm::phys::fast_allocator::PAGE_SIZE_4K;

#[cfg_attr(any(feature = "std", target_os = "linux"), test)]
#[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
fn dma_limit_includes_the_final_byte_without_consuming_rejected_extents() {
    for (limit, accepted) in [(0x2fff, true), (0x2ffe, false), (u64::MAX, true)] {
        let allocator = IovaAllocator::new(0x1000, 0x2000).unwrap();
        let result = allocator.allocate_with_limit(0x2000, PageGranularity::Page4K, limit);
        assert_eq!(result, accepted.then_some(0x1000));
        if !accepted {
            assert_eq!(
                allocator.allocate_contiguous(0x2000, PAGE_SIZE_4K),
                Some(0x1000)
            );
        }
    }
}

#[cfg_attr(any(feature = "std", target_os = "linux"), test)]
#[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
fn invalid_release_leaves_the_entire_reservation_occupied() {
    let size = 3 * PAGE_SIZE_4K;
    let allocator = IovaAllocator::new(PAGE_SIZE_4K, size).unwrap();
    let base = allocator.allocate_contiguous(size, PAGE_SIZE_4K).unwrap();
    assert_eq!(
        allocator.free_immediate(base, size + PAGE_SIZE_4K),
        Err(IommuError::InvalidAddress)
    );
    assert_eq!(
        allocator.allocate_contiguous(PAGE_SIZE_4K, PAGE_SIZE_4K),
        None
    );
    allocator.free_immediate(base, size).unwrap();
    assert_eq!(
        allocator.allocate_contiguous(size, PAGE_SIZE_4K),
        Some(base)
    );
}
