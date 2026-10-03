use super::*;
use crate::mm::phys::frame_allocator::alloc_contiguous_frames_aligned;

fn pool(pages: usize, alignment: usize) -> FreeListBuddyAllocator {
    let loan = alloc_contiguous_frames_aligned(pages, alignment).expect("owned fixture RAM");
    FreeListBuddyAllocator::from_allocation(loan).expect("metadata admission")
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn mixed_orders_match_independent_occupancy() {
    let mut pool = pool(1027, PAGE_SIZE_4K);
    let base = pool.base_frame;
    let mut occupied = alloc::vec![false; pool.total_count()];
    let mut active = Vec::new();
    let mut rng = 7919u64;
    for _ in 0..10000 {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        if rng & 3 == 0 && !active.is_empty() {
            let index = rng as usize % active.len();
            let allocation: MobilityAllocation = active.swap_remove(index);
            let first = allocation.frame.as_usize() - base;
            let count = allocation.page_count();
            assert!(occupied[first..first + count].iter().all(|&used| used));
            occupied[first..first + count].fill(false);
            pool.deallocate(allocation).expect("originating pool");
        } else {
            let order = (rng as usize >> 8) % 10;
            let mt = [
                MigrateType::Movable,
                MigrateType::Unmovable,
                MigrateType::Reclaimable,
            ][rng as usize % 3];
            match pool.allocate(order, mt) {
                Ok(allocation) => {
                    let absolute = allocation.frame.as_usize();
                    let first = absolute - base;
                    let count = allocation.page_count();
                    assert_eq!(absolute % count, 0, "absolute alignment");
                    assert!(first + count <= occupied.len());
                    assert!(occupied[first..first + count].iter().all(|&used| !used));
                    occupied[first..first + count].fill(true);
                    active.push(allocation);
                }
                Err(FrameAllocError::Exhausted) => {
                    let count = 1 << order;
                    let possible = (0..occupied.len()).any(|index| {
                        (base + index) % count == 0
                            && index + count <= occupied.len()
                            && occupied[index..index + count].iter().all(|&used| !used)
                    });
                    assert!(!possible, "allocator missed a free aligned block");
                }
                Err(error) => panic!("unexpected allocation error: {error:?}"),
            }
        }
        assert_eq!(
            pool.free_count() as usize,
            occupied.iter().filter(|&&used| !used).count()
        );
    }
    for allocation in active {
        pool.deallocate(allocation).expect("return");
    }
    assert_eq!(pool.free_count() as usize, occupied.len());
    pool.into_allocation()
        .expect("all children retired")
        .release();
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn huge_alignment_color_and_reclamation() {
    let mut pool = pool(1024, PAGE_SIZE_2M);
    let huge = pool.allocate(9, MigrateType::Movable).expect("huge child");
    assert_eq!(huge.start_address().as_u64() % PAGE_SIZE_2M as u64, 0);
    let colored = pool
        .allocate_with_color(0, MigrateType::Unmovable, 3)
        .expect("colored child");
    assert_eq!(frame_to_color(colored.frame.as_usize()), 3);
    let mut pool = pool
        .into_allocation()
        .expect_err("live children reject reclamation");
    pool.deallocate(huge).expect("huge return");
    pool.deallocate(colored).expect("colored return");
    pool.into_allocation().expect("empty loan").release();
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn rejection_preserves_unaccepted_owner() {
    let mut origin = pool(8, PAGE_SIZE_4K);
    let mut other = pool(8, PAGE_SIZE_4K);
    let allocation = origin.allocate(0, MigrateType::Reclaimable).expect("child");
    let address = allocation.start_address();
    let allocation = other
        .deallocate(allocation)
        .expect_err("wrong return destination");
    assert_eq!(allocation.start_address(), address);
    assert!(matches!(
        origin.allocate(MAX_ORDER + 1, MigrateType::Movable),
        Err(FrameAllocError::InvalidRange)
    ));
    assert!(matches!(
        origin.allocate_with_color(0, MigrateType::Movable, 64),
        Err(FrameAllocError::InvalidRange)
    ));
    origin
        .deallocate(allocation)
        .expect("original return authority");
    origin.into_allocation().expect("empty origin").release();
    other.into_allocation().expect("empty other").release();
}
