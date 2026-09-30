use super::{
    BootstrapHeaps, CacheClass, CachedAllocation, ExchangeBlocks, ExchangeCache, HeapMemory,
};
use core::alloc::Layout;

fn owned_ram(bytes: usize) -> HeapMemory {
    let slab = boot_proto::BootstrapHeapLayout::new(4096, bytes).expect("slab layout");
    // SAFETY: nonzero page-exact Layout; allocation is transferred once and
    // retained without any source reclaimer or outstanding mutable borrow.
    let base = unsafe { alloc::alloc::alloc(slab.allocation()) };
    assert!(!base.is_null());
    let geometry = slab
        .at(base.expose_provenance() as u64, 0, u64::MAX)
        .expect("identity mapping");
    // SAFETY: fresh exclusive stable RAM, no device/allocator alias. The two
    // disjoint owners retain the original allocation for this execution.
    let heaps = unsafe { BootstrapHeaps::from_handoff(geometry.descriptor(), 0, u64::MAX) }
        .expect("unique ownership admission");
    let (_kernel, exchange, _) = heaps.into_parts();
    exchange
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn payload_writes_never_change_adjacency_or_allocation_metadata() {
    let mut blocks = ExchangeBlocks::empty();
    blocks.initialize(owned_ram(64 * 1024)).expect("admission");
    let initial = blocks.stats();
    let mut live = alloc::vec::Vec::new();
    for (bytes, align) in [(1, 1), (17, 8), (31, 16), (63, 64), (65, 8), (1024, 4096)] {
        let layout = Layout::from_size_align(bytes, align).expect("layout");
        let ptr = blocks.allocate(layout).expect("allocation");
        assert_eq!(ptr.as_ptr().addr() % align, 0);
        // SAFETY: this exclusive live payload contains exactly the requested
        // bytes, none of which are allocator metadata.
        unsafe { ptr.as_ptr().write_bytes(0xff, bytes) };
        live.push((ptr, layout));
    }
    for index in [1, 3, 0, 5, 2, 4] {
        let (ptr, layout) = live[index];
        // SAFETY: this allocation was written above, remains live until this
        // one release, and every index is consumed exactly once.
        let payload = unsafe { core::slice::from_raw_parts(ptr.as_ptr(), layout.size()) };
        assert!(payload.iter().all(|byte| *byte == 0xff));
        // SAFETY: original pointer/Layout from these blocks, no remaining borrow.
        unsafe { blocks.deallocate(ptr, layout) };
    }
    let after = blocks.stats();
    assert_eq!(after.allocated, 0);
    assert_eq!(after.free, initial.free);
    assert_eq!(after.alloc_count, after.dealloc_count);
    assert!(after.split_count > 0);
    assert!(after.coalesce_count > 0);
    assert_eq!(after.non_empty_classes.count_ones(), 1);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn allocation_failure_has_no_partial_list_mutation() {
    let mut blocks = ExchangeBlocks::empty();
    let small = Layout::new::<u64>();
    assert!(blocks.allocate(small).is_none());
    blocks.initialize(owned_ram(4096)).expect("admission");
    let before = blocks.stats();
    let overflow = Layout::from_size_align(isize::MAX as usize, 1).expect("valid caller Layout");
    assert!(blocks.allocate(overflow).is_none());
    assert!(
        blocks
            .allocate(Layout::from_size_align(8192, 8).unwrap())
            .is_none()
    );
    let after = blocks.stats();
    assert_eq!(before.free, after.free);
    assert_eq!(before.non_empty_classes, after.non_empty_classes);
    assert_eq!(before.alloc_count, after.alloc_count);
    let ptr = blocks.allocate(small).expect("failure did not consume RAM");
    // SAFETY: one exclusive live allocation and its exact Layout.
    unsafe { blocks.deallocate(ptr, small) };
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn zero_size_and_high_alignment_do_not_share_metadata() {
    let mut blocks = ExchangeBlocks::empty();
    blocks.initialize(owned_ram(64 * 1024)).expect("admission");
    for align in [1, 16, 4096, 8192] {
        let layout = Layout::from_size_align(0, align).expect("zero-size Layout");
        let ptr = blocks.allocate(layout).expect("aligned allocation");
        assert_eq!(ptr.as_ptr().addr() % align, 0);
        // SAFETY: original zero-size allocation/Layout, consumed once.
        unsafe { blocks.deallocate(ptr, layout) };
        assert_eq!(blocks.stats().allocated, 0);
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn duplicate_block_admission_preserves_live_payload_and_incoming_owner() {
    let mut blocks = ExchangeBlocks::empty();
    blocks.initialize(owned_ram(4096)).expect("first admission");
    let layout = Layout::from_size_align(127, 16).unwrap();
    let ptr = blocks.allocate(layout).expect("allocation");
    // SAFETY: exclusive live payload, exact requested extent.
    unsafe { ptr.as_ptr().write_bytes(0xff, layout.size()) };
    let incoming = owned_ram(8192);
    let start = incoming.start();
    let returned = blocks
        .initialize(incoming)
        .expect_err("duplicate admission");
    assert_eq!(returned.start(), start);
    // SAFETY: rejected initialization touched neither backing nor this live allocation.
    let payload = unsafe { core::slice::from_raw_parts(ptr.as_ptr(), layout.size()) };
    assert!(payload.iter().all(|byte| *byte == 0xff));
    // SAFETY: original pointer/Layout, no surviving borrow.
    unsafe { blocks.deallocate(ptr, layout) };
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn cache_classes_cover_both_requested_size_and_alignment() {
    for bytes in [0, 1, 7, 8, 9, 65, 127, 128, 255, 256] {
        for align in [1, 8, 16, 64, 128, 256] {
            let requested = Layout::from_size_align(bytes, align).unwrap();
            let canonical = CacheClass::for_layout(requested)
                .expect("small class")
                .layout();
            assert!(canonical.size() >= requested.size());
            assert!(canonical.align() >= requested.align());
            assert_eq!(canonical.size(), canonical.align());
        }
    }
    assert!(CacheClass::for_layout(Layout::from_size_align(1, 4096).unwrap()).is_none());
    assert!(CacheClass::for_layout(Layout::from_size_align(257, 1).unwrap()).is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn cache_capacity_failure_and_steal_preserve_exclusive_blocks() {
    let mut blocks = ExchangeBlocks::empty();
    blocks.initialize(owned_ram(64 * 1024)).expect("admission");
    let class = CacheClass::for_layout(Layout::from_size_align(65, 64).unwrap()).unwrap();
    let layout = class.layout();
    let mut cache = ExchangeCache::new();
    for _ in 0..32 {
        let ptr = blocks.allocate(layout).expect("allocation");
        // SAFETY: exclusive canonical-layout block; no caller alias or free
        // survives. This cache is used only with its retained backing allocator.
        let block = unsafe { CachedAllocation::retain(ptr, class) };
        assert!(cache.insert(block).is_ok());
    }
    let ptr = blocks.allocate(layout).expect("overflow entry");
    // SAFETY: same canonical Layout and exclusive transfer as above.
    let block = unsafe { CachedAllocation::retain(ptr, class) };
    let returned = match cache.insert(block) {
        Err(block) => block.into_pointer(),
        Ok(()) => panic!("full cache must return the incoming allocation"),
    };
    assert_eq!(returned, ptr);
    // SAFETY: failed insertion returned exclusive ownership, no cached alias.
    unsafe { blocks.deallocate(returned, layout) };
    let mut stolen = 0;
    // LOOP_PROOF: mode=condition; reason=Each steal consumes one of at most 32 cached allocations and stops at the victim reserve.;
    while let Some(block) = cache.steal(class) {
        // SAFETY: consumption removes this sole entry before backing release.
        unsafe { blocks.deallocate(block.into_pointer(), layout) };
        stolen += 1;
    }
    assert_eq!(stolen, 16);
    let mut local = 0;
    // LOOP_PROOF: mode=condition; reason=Each take consumes one of the finite remaining cached entries.;
    while let Some(block) = cache.take(class) {
        // SAFETY: consumption removes this sole entry before backing release.
        unsafe { blocks.deallocate(block.into_pointer(), layout) };
        local += 1;
    }
    assert_eq!(local, 16);
    assert_eq!(blocks.stats().allocated, 0);
    assert_eq!(blocks.stats().free, 64 * 1024);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn mixed_layout_churn_preserves_all_live_payloads_and_recovers_the_slab() {
    let mut blocks = ExchangeBlocks::empty();
    blocks.initialize(owned_ram(64 * 1024)).expect("admission");
    let mut live: [Option<(core::ptr::NonNull<u8>, Layout, u8)>; 24] = [None; 24];
    let mut seed = 1u64;
    for step in 0..2000u64 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let slot = ((seed >> 32) % live.len() as u64) as usize;
        if let Some((ptr, layout, pattern)) = live[slot].take() {
            // SAFETY: the exclusive live allocation was fully written at
            // publication below; no other slot owns or mutates its bytes.
            let payload = unsafe { core::slice::from_raw_parts(ptr.as_ptr(), layout.size()) };
            assert!(payload.iter().all(|byte| *byte == pattern));
            // SAFETY: taking the slot consumes its sole allocation and exact Layout.
            unsafe { blocks.deallocate(ptr, layout) };
        } else {
            let bytes = ((seed >> 16) % 1024 + 1) as usize;
            let align = 1 << ((seed >> 8) % 10);
            let layout = Layout::from_size_align(bytes, align).unwrap();
            if let Some(ptr) = blocks.allocate(layout) {
                for (other, other_layout, _) in live.iter().flatten() {
                    let start = ptr.as_ptr().addr();
                    let end = start + bytes;
                    let other_start = other.as_ptr().addr();
                    let other_end = other_start + other_layout.size();
                    assert!(
                        end <= other_start || other_end <= start,
                        "live payloads overlap"
                    );
                }
                assert_eq!(ptr.as_ptr().addr() % align, 0);
                let pattern = (step as u8).wrapping_add(1);
                // SAFETY: exclusive writable payload, bounded by requested Layout.
                unsafe { ptr.as_ptr().write_bytes(pattern, bytes) };
                live[slot] = Some((ptr, layout, pattern));
            }
        }
    }
    for (ptr, layout, pattern) in live.into_iter().flatten() {
        // SAFETY: initialized, exclusive live payload; no independent cache/reclaimer.
        let payload = unsafe { core::slice::from_raw_parts(ptr.as_ptr(), layout.size()) };
        assert!(payload.iter().all(|byte| *byte == pattern));
        // SAFETY: sole original allocation/Layout, consumed once by this iteration.
        unsafe { blocks.deallocate(ptr, layout) };
    }
    assert_eq!(blocks.stats().allocated, 0);
    assert_eq!(blocks.stats().free, 64 * 1024);
    assert_eq!(blocks.stats().non_empty_classes.count_ones(), 1);
}
