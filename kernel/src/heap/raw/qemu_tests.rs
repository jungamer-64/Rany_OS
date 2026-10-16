use super::*;

pub(crate) fn return_ownership_smoke() {
    slab_pressure_reclaims_delayed_empty_pages_and_preserves_live_payload();
    buddy_return_snapshot_preserves_layout_and_cannot_retire_a_live_block();
    physical_slab_progress_counts_only_the_last_reservations_whole_page();
    rejected_buddy_publication_retains_the_owner_for_retry();
    shared_buddy_reclaim_defers_busy_owners_and_never_retires_a_live_block();
    slab_ranges_are_disjoint_and_magazine_full_returns_the_owner();
    locality_change_detaches_old_reservations_before_reuse();
    buddy_and_direct_extents_obey_actual_alignment();
}

fn fixture_slab(class: SlabClass, next: Option<NonNull<SlabPage>>) -> NonNull<SlabPage> {
    let backing = pmm::alloc_contiguous_frames_aligned_on_node(NumaNodeId::NODE_0, 1, PAGE)
        .expect("fixture slab RAM");
    let address =
        crate::mm::virt::mapping::phys_to_virt(backing.start_address()).as_mut_ptr::<SlabPage>();
    let mask = (1u64 << SlabPage::count(class)) - 1;
    // SAFETY: the fixture transfers one exclusive mapped page into an
    // initialized header; its caller exclusively owns the not-yet-linked
    // page until publication into the fixture's private pool.
    unsafe {
        address.write(SlabPage {
            backing,
            class,
            free: AtomicU64::new(mask),
            mask,
            next,
        });
        NonNull::new_unchecked(address)
    }
}

fn slab_pressure_reclaims_delayed_empty_pages_and_preserves_live_payload() {
    let class = SlabClass(2);
    let pages = [
        fixture_slab(class, None),
        fixture_slab(class, None),
        fixture_slab(class, None),
    ];
    // SAFETY: no page is published yet; the fixture owns all three headers.
    unsafe {
        (*pages[0].as_ptr()).next = Some(pages[1]);
        (*pages[1].as_ptr()).next = Some(pages[2]);
    }
    let pool = IrqPoisonLock::new(SlabPool {
        head: Some(pages[0]),
    });
    let held = pool
        .lock()
        .unwrap_or_else(|_| panic!("fixture pool poisoned"));
    let blocks = pages.map(|page| claim_block(page, CpuId::BOOTSTRAP).unwrap());
    let [first, second, live] = blocks;
    // SAFETY: the live reservation exclusively owns its writable payload.
    unsafe { live.pointer.as_ptr().write_bytes(0x37, class.size()) };
    let return_to_pool = |block: RawBlock| {
        let AllocationSource::Slab(reservation) = block.source else {
            panic!("slab fixture")
        };
        slab_return(block.pointer, reservation.page(), &pool)
    };
    assert_eq!(return_to_pool(first), 0);
    assert_eq!(return_to_pool(second), 0);
    assert_eq!(
        reclaim_slab_pool(&pool),
        PoolReclaim {
            busy_pools: 1,
            ..Default::default()
        }
    );
    assert_eq!(held.head, Some(pages[0]));
    drop(held);
    assert_eq!(reclaim_slab_pool(&pool).reclaimed_bytes, 2 * PAGE);
    assert_eq!(reclaim_slab_pool(&pool), PoolReclaim::default());
    // SAFETY: pressure must preserve the entire live block and its page.
    let payload = unsafe { core::slice::from_raw_parts(live.pointer.as_ptr(), class.size()) };
    assert!(payload.iter().all(|byte| *byte == 0x37));
    assert_eq!(return_to_pool(live), PAGE);
    assert!(
        pool.lock()
            .unwrap_or_else(|_| panic!("fixture pool poisoned"))
            .head
            .is_none()
    );
}

fn buddy_return_snapshot_preserves_layout_and_cannot_retire_a_live_block() {
    let layout = Layout::from_size_align(7000, 4096).unwrap();
    let prepared = PreparedBuddyRegion::allocate(NumaNodeId::NODE_0, layout).unwrap();
    let pool = IrqPoisonLock::new(BuddyPool { head: None });
    let live = prepared
        .publish(&pool, layout)
        .unwrap_or_else(|_| panic!("fixture publish failed"));
    let AllocationSource::Buddy(live_source) = &live.source else {
        panic!("Buddy fixture")
    };
    let region = live_source.region;
    // SAFETY: the live reservation owns payload access until return.
    unsafe { live.pointer.as_ptr().write_bytes(0x37, layout.size()) };
    let held = pool
        .lock()
        .unwrap_or_else(|_| panic!("fixture pool poisoned"));
    // SAFETY: this exact node guard grants exclusive access to state;
    // private fixture allocations maintain the production live-count rule.
    let retained = unsafe { region.as_ref() };
    // SAFETY: no other consumer can borrow state while held is retained.
    let state = unsafe { &mut *retained.state.get() };
    let bytes = state.heap.heap_size + retained.metadata.size_bytes() as usize;
    let vectors = [(1, 8), (63, 64), (511, 256), (4000, 8192), (13000, 16384)];
    let blocks = vectors.map(|(bytes, alignment)| {
        let layout = Layout::from_size_align(bytes, alignment).unwrap();
        let pointer = NonNull::new(state.heap.allocate(layout)).expect("fixture capacity");
        state.live += 1;
        (pointer, BuddyReservation { region }, layout)
    });
    // Independent interval model includes the actual Buddy reservation
    // extent rather than just each caller's requested payload bytes.
    let spans = blocks.each_ref().map(|(pointer, _, layout)| {
        let reserved = layout
            .size()
            .max(layout.align())
            .max(64)
            .next_power_of_two();
        (pointer.as_ptr().addr(), pointer.as_ptr().addr() + reserved)
    });
    for (index, &(start, end)) in spans.iter().enumerate() {
        assert!(end > start);
        assert_eq!(start % vectors[index].1, 0);
        for &(other_start, other_end) in &spans[..index] {
            assert!(end <= other_start || other_end <= start);
        }
    }
    let free_before = state.heap.free_bytes();
    for (pointer, reservation, layout) in blocks {
        publish_buddy_return(pointer, reservation, layout);
    }
    assert_eq!(state.live, vectors.len() + 1);
    assert_eq!(state.heap.free_bytes(), free_before);
    assert_eq!(
        reclaim_buddy_pool(&pool),
        PoolReclaim {
            busy_pools: 1,
            ..Default::default()
        }
    );
    drop(held);
    let recovered = vectors
        .iter()
        .map(|&(bytes, align)| bytes.max(align).max(64).next_power_of_two())
        .sum();
    let progress = reclaim_buddy_pool(&pool);
    assert_eq!(
        progress,
        PoolReclaim {
            heap_recovered_bytes: recovered,
            ..Default::default()
        }
    );
    assert!(progress.made_progress()); // Retained live RAM still yielded usable heap capacity.
    let held = pool
        .lock()
        .unwrap_or_else(|_| panic!("fixture pool poisoned"));
    // SAFETY: the surviving live reservation retains metadata; this guard
    // grants state observation independently of concurrent queue producers.
    let state = unsafe { &*retained.state.get() };
    assert_eq!(state.live, 1);
    assert!(state.heap.free_bytes() > free_before);
    assert!(retained.pending.load(Ordering::Acquire).is_null());
    // SAFETY: the original live payload was never returned or reused.
    let payload = unsafe { core::slice::from_raw_parts(live.pointer.as_ptr(), layout.size()) };
    assert!(payload.iter().all(|byte| *byte == 0x37));
    let AllocationSource::Buddy(reservation) = live.source else {
        panic!("Buddy fixture")
    };
    publish_buddy_return(live.pointer, reservation, layout);
    drop(held);
    assert_eq!(
        collect_buddy_pool(&pool, BuddyRetention::WarmLoan),
        PoolReclaim {
            heap_recovered_bytes: 8192,
            ..Default::default()
        }
    );
    assert_eq!(reclaim_buddy_pool(&pool).reclaimed_bytes, bytes);
    assert_eq!(reclaim_buddy_pool(&pool), PoolReclaim::default());
}

fn physical_slab_progress_counts_only_the_last_reservations_whole_page() {
    let backing = pmm::alloc_contiguous_frames_aligned_on_node(NumaNodeId::NODE_0, 1, PAGE)
        .expect("fixture RAM");
    let address =
        crate::mm::virt::mapping::phys_to_virt(backing.start_address()).as_u64() as *mut SlabPage;
    let class = SlabClass::for_layout(Layout::from_size_align(256, 64).unwrap()).unwrap();
    let mask = (1u64 << SlabPage::count(class)) - 1;
    // SAFETY: the fixture transfers one retained writable physical page
    // into a disjoint header and payload, then publishes its sole pool link.
    let page = unsafe {
        address.write(SlabPage {
            backing,
            class,
            free: AtomicU64::new(mask),
            mask,
            next: None,
        });
        NonNull::new_unchecked(address)
    };
    let pool = IrqPoisonLock::new(SlabPool { head: Some(page) });
    let first = claim_block(page, CpuId::BOOTSTRAP).expect("first reservation");
    let second = claim_block(page, CpuId::BOOTSTRAP).expect("second reservation");
    // SAFETY: the second reservation exclusively retains its whole payload.
    unsafe { second.pointer.as_ptr().write_bytes(0x37, 256) };
    let return_to_pool = |block: RawBlock| {
        let AllocationSource::Slab(reservation) = block.source else {
            panic!("fixture requires a slab reservation");
        };
        slab_return(block.pointer, reservation.page(), &pool)
    };
    assert_eq!(return_to_pool(first), 0);
    assert_eq!(reclaim_slab_pool(&pool).reclaimed_bytes, 0);
    // SAFETY: the second reservation remains live across the first return.
    unsafe { assert_eq!(second.pointer.as_ptr().read(), 0x37) };
    assert_eq!(return_to_pool(second), 4096);
    assert!(
        pool.lock()
            .unwrap_or_else(|_| panic!("fixture pool poisoned"))
            .head
            .is_none()
    );
    assert_eq!(reclaim_slab_pool(&pool).reclaimed_bytes, 0);
}

fn rejected_buddy_publication_retains_the_owner_for_retry() {
    let layout = Layout::from_size_align(7000, 4096).unwrap();
    let mut prepared = PreparedBuddyRegion::allocate(NumaNodeId::NODE_0, layout).unwrap();
    let retained = prepared.region.as_mut().unwrap();
    let addresses = (
        retained.metadata.start_address(),
        retained.state.get_mut().heap.heap_start,
    );
    let bytes = retained.metadata.size_bytes() as usize + retained.state.get_mut().heap.heap_size;
    let pool = IrqPoisonLock::new(BuddyPool { head: None });
    let held = pool
        .lock()
        .unwrap_or_else(|_| panic!("fixture pool poisoned"));
    let mut prepared = prepared
        .publish(&pool, layout)
        .err()
        .expect("busy publication must preserve its owner");
    assert!(held.head.is_none());
    let retained = prepared.region.as_mut().unwrap();
    assert_eq!(
        (
            retained.metadata.start_address(),
            retained.state.get_mut().heap.heap_start
        ),
        addresses
    );
    assert_eq!(retained.state.get_mut().live, 0);
    drop(held);

    let too_large = Layout::from_size_align(bytes * 2, 4096).unwrap();
    let prepared = prepared
        .publish(&pool, too_large)
        .err()
        .expect("unsatisfied layout must preserve its owner");
    assert!(
        pool.lock()
            .unwrap_or_else(|_| panic!("fixture pool poisoned"))
            .head
            .is_none()
    );
    let block = prepared
        .publish(&pool, layout)
        .unwrap_or_else(|_| panic!("retry should publish the same loan"));
    let AllocationSource::Buddy(reservation) = block.source else {
        panic!("fixture requires a buddy reservation");
    };
    let region = reservation.region;
    let held = pool
        .lock()
        .unwrap_or_else(|_| panic!("fixture pool poisoned"));
    assert_eq!(held.head, Some(region));
    // SAFETY: the pool and reservation retain immutable metadata.
    unsafe { assert_eq!(region.as_ref().metadata.start_address(), addresses.0) };
    publish_buddy_return(block.pointer, reservation, layout);
    drop(held);
    assert_eq!(reclaim_buddy_pool(&pool).reclaimed_bytes, bytes);
    assert_eq!(reclaim_buddy_pool(&pool), PoolReclaim::default());
}

fn shared_buddy_reclaim_defers_busy_owners_and_never_retires_a_live_block() {
    let layout = Layout::from_size_align(7000, 4096).unwrap();
    let prepared = PreparedBuddyRegion::allocate(NumaNodeId::NODE_0, layout).unwrap();
    let pool = IrqPoisonLock::new(BuddyPool { head: None });
    let block = prepared
        .publish(&pool, layout)
        .unwrap_or_else(|_| panic!("fixture region publication rejected"));
    let AllocationSource::Buddy(reservation) = block.source else {
        panic!("fixture requires a buddy reservation");
    };
    let region = reservation.region;
    let pointer = block.pointer;
    // SAFETY: this fixture exclusively retains the live reservation and
    // its writable payload, disjoint from region metadata.
    unsafe { pointer.as_ptr().write_bytes(0x37, layout.size()) };
    assert_eq!(reclaim_buddy_pool(&pool), PoolReclaim::default());
    let held = pool
        .lock()
        .unwrap_or_else(|_| panic!("fixture pool poisoned"));
    assert_eq!(held.head, Some(region));
    assert_eq!(
        reclaim_buddy_pool(&pool),
        PoolReclaim {
            busy_pools: 1,
            ..Default::default()
        }
    );
    // SAFETY: the live reservation owns payload access; the held pool
    // guard excludes other state access and keeps the metadata retained.
    let bytes = unsafe {
        assert_eq!(pointer.as_ptr().read(), 0x37);
        let retained = region.as_ref();
        (&*retained.state.get()).heap.heap_size + retained.metadata.size_bytes() as usize
    };
    publish_buddy_return(pointer, reservation, layout);
    drop(held);
    assert_eq!(
        reclaim_buddy_pool(&pool),
        PoolReclaim {
            reclaimed_bytes: bytes,
            heap_recovered_bytes: 8192,
            ..Default::default()
        }
    );
    assert!(
        pool.lock()
            .unwrap_or_else(|_| panic!("fixture pool poisoned"))
            .head
            .is_none()
    );
    assert_eq!(reclaim_buddy_pool(&pool), PoolReclaim::default());
}

fn slab_ranges_are_disjoint_and_magazine_full_returns_the_owner() {
    let mut model = alloc::vec::Vec::new();
    for class in 0..CLASSES {
        let mut magazine = Magazine::new();
        let layout = Layout::from_size_align(64 << class, 64).unwrap();
        for _ in 0..MAGAZINE {
            let block = slab_block(NumaNodeId::NODE_0, SlabClass(class), CpuId::BOOTSTRAP)
                .expect("mapped test RAM");
            let start = block.pointer.as_ptr().addr();
            assert!(start.is_multiple_of(64));
            assert!(
                model
                    .iter()
                    .all(|&(first, last)| start + layout.size() <= first || last <= start)
            );
            model.push((start, start + layout.size()));
            assert!(magazine.put(block).is_ok());
        }
        let block = slab_block(NumaNodeId::NODE_0, SlabClass(class), CpuId::BOOTSTRAP).unwrap();
        let block = magazine
            .put(block)
            .err()
            .expect("full magazine returns unaccepted ownership");
        release(block, layout);
        // LOOP_PROOF: mode=condition; reason=Each take consumes one of the at most 32 retained magazine entries.;
        while let Some(block) = magazine.take() {
            release(block, layout);
        }
        model.clear();
    }
}

fn locality_change_detaches_old_reservations_before_reuse() {
    let mut cache = HeapCache::new();
    assert!(cache.bind_node(NumaNodeId::NODE_0).unwrap().is_empty());
    let layout = Layout::from_size_align(256, 64).unwrap();
    for _ in 0..MAGAZINE {
        let block = slab_block(NumaNodeId::NODE_0, SlabClass(2), CpuId::BOOTSTRAP).unwrap();
        assert!(cache.magazines[2].put(block).is_ok());
    }
    assert!(cache.bind_node(NumaNodeId::NODE_0).is_none());
    let retired = cache.bind_node(NumaNodeId::new(1)).unwrap();
    assert!(cache.magazines[2].take().is_none());
    let progress = retired.release();
    assert_eq!(progress.heap_returned_bytes, MAGAZINE * layout.size());
    assert!(progress.physical_reclaimed_bytes <= MAGAZINE * PAGE);
    assert!(cache.bind_node(NumaNodeId::NODE_0).unwrap().is_empty());
    assert!(cache.is_empty());
}

fn buddy_and_direct_extents_obey_actual_alignment() {
    for alignment in [128, 4096, 8192, 65536] {
        let layout = Layout::from_size_align(7000, alignment).unwrap();
        let block = buddy_block(NumaNodeId::NODE_0, layout).expect("buddy-backed test RAM");
        assert!(block.pointer.as_ptr().addr().is_multiple_of(alignment));
        release(block, layout);
        let block = direct_block(NumaNodeId::NODE_0, layout).expect("direct test extent");
        assert!(block.pointer.as_ptr().addr().is_multiple_of(alignment));
        release(block, layout);
    }
}
