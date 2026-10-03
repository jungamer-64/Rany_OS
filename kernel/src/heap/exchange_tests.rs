use crate::mm::cache::exchange_heap::ExchangeHeap;
use core::alloc::Layout;

fn owned_exchange(bytes: usize) -> crate::heap::HeapMemory {
    let layout = boot_proto::BootstrapHeapLayout::new(4096, bytes).expect("fixture slab layout");
    // SAFETY: valid page-aligned nonzero allocation; no alias or source
    // reclaimer survives the ownership transfer into the two heap owners.
    let base = unsafe { alloc::alloc::alloc(layout.allocation()) };
    assert!(!base.is_null());
    let geometry = layout
        .at(base.expose_provenance() as u64, 0, u64::MAX)
        .expect("identity-mapped fixture");
    // SAFETY: fresh exclusive RAM is stable for the test/kernel lifetime and
    // remains retained; identity mapping covers this exact allocation.
    let heaps =
        unsafe { crate::heap::BootstrapHeaps::from_handoff(geometry.descriptor(), 0, u64::MAX) }
            .expect("fixture ownership admission");
    let (_kernel, exchange, _) = heaps.into_parts();
    exchange
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn initialized_slices_track_one_prefix_and_drop_only_live_elements() {
    use crate::mm::cache::exchange_heap::{EXCHANGE_HEAP, InitializedSlice, UninitializedSlice};
    use core::sync::atomic::{AtomicUsize, Ordering};
    EXCHANGE_HEAP
        .initialize(owned_exchange(64 * 1024))
        .expect("exchange admission");
    let mut words = InitializedSlice::<[u64; 4]>::zeroed(8).expect("zero array values");
    assert!(words.iter().all(|word| *word == [0; 4]));
    words.fill([u64::MAX; 4]);
    drop(words);
    let reused = InitializedSlice::<[u64; 4]>::zeroed(8).expect("zero reused RAM");
    assert!(reused.iter().all(|word| *word == [0; 4]));
    drop(reused);
    let flags = InitializedSlice::<bool>::zeroed(17).expect("zero-valid booleans");
    assert!(flags.iter().all(|flag| !flag));
    drop(flags);
    let chars = InitializedSlice::<char>::zeroed(3).expect("zero-valid Unicode scalars");
    assert!(chars.iter().all(|value| *value == '\0'));
    drop(chars);
    assert!(InitializedSlice::<u64>::zeroed(0).is_none());
    assert!(InitializedSlice::<u64>::zeroed(usize::MAX).is_none());
    use crate::domain::DomainId;
    use crate::ipc::RRef;
    let moved = RRef::new_slice_with_aligned(DomainId::KERNEL, 5, 4096, |index| index as u64)
        .expect("aligned Exchange RRef");
    assert_eq!(moved.as_ptr().addr() % 4096, 0);
    let erased = moved.into_raw_parts();
    // SAFETY: this test's exclusively owned allocation has no DMA mapping.
    let rejected = unsafe { erased.into_rref::<[u32]>() }.expect_err("exact type mismatch");
    assert_eq!(rejected.kind, crate::ipc::rref::RawPartsError::TypeMismatch);
    // SAFETY: rejection returns the original owner, before accessing its data.
    let recovered =
        unsafe { rejected.parts.into_rref::<[u64]>() }.expect("owner survives rejection");
    assert_eq!(&*recovered, &[0, 1, 2, 3, 4]);
    assert_eq!(recovered.as_ptr().addr() % 4096, 0);
    drop(recovered);
    struct Element<'a>(u64, &'a AtomicUsize);
    impl Drop for Element<'_> {
        fn drop(&mut self) {
            self.1.fetch_add(1, Ordering::Relaxed);
        }
    }
    let dropped = AtomicUsize::new(0);
    let mut partial = UninitializedSlice::new(4).unwrap();
    partial.init_next(Element(11, &dropped)).unwrap();
    assert_eq!(partial.initialized_count(), 1);
    partial.init_next(Element(22, &dropped)).unwrap();
    assert_eq!(partial.initialized_count(), 2);
    let partial = match partial.try_into_initialized() {
        Ok(_) => panic!("two initialized elements cannot complete a four-element slice"),
        Err(partial) => partial,
    };
    drop(partial);
    assert_eq!(dropped.load(Ordering::Relaxed), 2);
    let mut continued = UninitializedSlice::new(3).unwrap();
    continued.init_next(Element(33, &dropped)).unwrap();
    let initialized = match continued.init_from_iter([Element(44, &dropped), Element(55, &dropped)])
    {
        Ok(initialized) => initialized,
        Err(_) => panic!("the remaining two elements must complete the prefix"),
    };
    assert_eq!(
        initialized
            .iter()
            .map(|element| element.0)
            .collect::<alloc::vec::Vec<_>>(),
        [33, 44, 55]
    );
    drop(initialized);
    assert_eq!(dropped.load(Ordering::Relaxed), 5);
    super::exchange_cache::drain_current_cache().expect("owner cache drain");
    assert_eq!(EXCHANGE_HEAP.stats().allocated, 0);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_exchange_heap() {
    let heap = ExchangeHeap::new();
    heap.initialize(owned_exchange(4096))
        .expect("heap admission");

    // アロケーション
    let layout = Layout::from_size_align(64, 8).unwrap();
    let ptr = heap.allocate(layout).expect("Allocation failed");

    // 統計確認
    let stats = heap.stats();
    assert!(stats.allocated > 0);

    // SAFETY: exclusive allocation from this heap, with the exact original layout.
    unsafe {
        heap.deallocate(ptr, layout);
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn duplicate_admission_preserves_existing_allocations_and_returns_owner() {
    let heap = ExchangeHeap::new();
    heap.initialize(owned_exchange(4096))
        .expect("first admission");
    let layout = Layout::from_size_align(64, 8).expect("allocation layout");
    let ptr = heap.allocate(layout).expect("allocation");
    // SAFETY: this live exclusive allocation contains at least 64 bytes.
    unsafe {
        ptr.as_ptr().write_bytes(0x5a, 64);
    }
    let incoming = owned_exchange(8192);
    let incoming_start = incoming.start();
    let retained = heap
        .initialize(incoming)
        .expect_err("duplicate admission must fail");
    assert_eq!(retained.start(), incoming_start);
    // SAFETY: duplicate admission did not free or reinitialize the first heap;
    // the allocation stays exclusively owned and fully initialized above.
    let payload = unsafe { core::slice::from_raw_parts(ptr.as_ptr(), 64) };
    assert!(payload.iter().all(|byte| *byte == 0x5a));
    // SAFETY: same allocation and exact original Layout, no remaining borrow.
    unsafe {
        heap.deallocate(ptr, layout);
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_block_coalescing() {
    let heap = ExchangeHeap::new();
    heap.initialize(owned_exchange(8192))
        .expect("heap admission");

    // Allocate three blocks
    // Coalescing is a backing-allocator contract, not a cache eviction policy.
    // Use an uncached size so CPU availability cannot change this test's meaning.
    let layout = Layout::from_size_align(512, 8).unwrap();
    let ptr1 = heap.allocate(layout).expect("Allocation 1 failed");
    let ptr2 = heap.allocate(layout).expect("Allocation 2 failed");
    let ptr3 = heap.allocate(layout).expect("Allocation 3 failed");

    // Get initial stats
    let stats_before = heap.extended_stats().unwrap();
    let coalesce_before = stats_before.coalesce_count;

    // Free middle block first
    // SAFETY: exact original allocation/layout from this heap; no live borrow.
    unsafe {
        heap.deallocate(ptr2, layout);
    }

    // Free first block - should coalesce with ptr2's freed block
    // SAFETY: exact original allocation/layout from this heap; no live borrow.
    unsafe {
        heap.deallocate(ptr1, layout);
    }

    // Free third block - should coalesce with the combined block
    // SAFETY: exact original allocation/layout from this heap; no live borrow.
    unsafe {
        heap.deallocate(ptr3, layout);
    }

    // Check that coalescing occurred
    let stats_after = heap.extended_stats().unwrap();
    assert!(
        stats_after.coalesce_count > coalesce_before,
        "Expected coalescing to occur: before={}, after={}",
        coalesce_before,
        stats_after.coalesce_count
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn every_cache_class_reuses_blocks_and_owner_drain_restores_backing() {
    let heap = ExchangeHeap::new();
    heap.initialize(owned_exchange(256 * 1024)).unwrap();
    for bytes in [8, 16, 32, 64, 128, 256] {
        let layout = Layout::from_size_align(bytes - 1, bytes).unwrap();
        let pointer = heap.allocate(layout).unwrap();
        assert_eq!(pointer.as_ptr().addr() % bytes, 0);
        // SAFETY: live exclusive payload returned once with its original Layout.
        unsafe { heap.deallocate(pointer, layout) };
        let before = heap.extended_stats().unwrap().alloc_count;
        for pattern in 0..100u8 {
            let pointer = heap.allocate(layout).unwrap();
            assert_eq!(pointer.as_ptr().addr() % bytes, 0);
            // SAFETY: this exclusive allocation covers the requested payload.
            unsafe {
                pointer.as_ptr().write_bytes(pattern, layout.size());
                heap.deallocate(pointer, layout);
            }
        }
        if crate::cpu::CurrentCpu::acquire().is_some() {
            assert_eq!(heap.extended_stats().unwrap().alloc_count, before);
        }
    }
    super::exchange_cache::drain_current_cache().expect("owner cache drain");
    assert_eq!(heap.stats().allocated, 0);
    assert_eq!(heap.stats().free, 256 * 1024);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn changing_cpu_backing_returns_old_cache_before_rebinding() {
    let first = ExchangeHeap::new();
    let second = ExchangeHeap::new();
    first.initialize(owned_exchange(64 * 1024)).unwrap();
    second.initialize(owned_exchange(64 * 1024)).unwrap();
    let layout = Layout::from_size_align(63, 64).unwrap();
    for _ in 0..3 {
        let pointer = first.allocate(layout).unwrap();
        // SAFETY: sole live allocation with exact original layout and source.
        unsafe { first.deallocate(pointer, layout) };
        let pointer = second.allocate(layout).unwrap();
        assert_eq!(first.stats().allocated, 0);
        // SAFETY: binding changes return old cached blocks, never this live block.
        unsafe {
            pointer.as_ptr().write_bytes(0x5a, layout.size());
            second.deallocate(pointer, layout)
        };
    }
    super::exchange_cache::drain_current_cache().expect("owner cache drain");
    assert_eq!(first.stats().allocated, 0);
    assert_eq!(second.stats().allocated, 0);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn exchange_drain_returns_heap_capacity_without_claiming_physical_ram() {
    super::reclaim::drain_local_caches().expect("initial owner cache drain");
    let heap = ExchangeHeap::new();
    heap.initialize(owned_exchange(64 * 1024)).unwrap();
    let layout = Layout::from_size_align(63, 64).unwrap();
    let pointer = heap.allocate(layout).unwrap();
    // SAFETY: this sole live allocation returns once with the original Layout.
    unsafe { heap.deallocate(pointer, layout) };
    let progress = super::reclaim::drain_local_caches().expect("owner cache drain");
    assert_eq!(progress.physical_reclaimed_bytes, 0);
    if crate::cpu::CurrentCpu::acquire().is_some() {
        // Refill may reserve additional canonical blocks. Admission bounds
        // this one class to 32 entries, independent of its refill strategy.
        assert!((64..=32 * 64).contains(&progress.heap_returned_bytes));
        assert_eq!(progress.heap_returned_bytes % 64, 0);
        assert!(progress.made_progress());
    } else {
        assert_eq!(progress.heap_returned_bytes, 0);
    }
    assert_eq!(heap.stats().allocated, 0);
    assert_eq!(heap.stats().free, 64 * 1024);
}
