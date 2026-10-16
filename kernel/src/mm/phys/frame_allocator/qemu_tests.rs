use super::*;
use alloc::boxed::Box;

pub(crate) fn zeroed_refill_ownership_smoke() {
    let backing = alloc_contiguous_frames(25).expect("zeroed refill fixture RAM");
    let start = backing.as_u64();
    let bytes = backing.size_bytes();
    // SAFETY: no suballocation has been admitted yet; this owner exclusively
    // retains the entire extent through its permanent writable direct map.
    unsafe {
        crate::mm::virt::mapping::phys_to_virt(backing.start_address())
            .as_mut_ptr::<u8>()
            .write_bytes(0xa5, bytes as usize);
    }
    let pool = Box::new(NodePool {
        node: backing.node(),
        bitmap: FastBitmapAllocator::try_new(start, bytes).expect("fixture occupancy"),
        usable: alloc::vec![(start, start + bytes)],
        huge: IrqPoisonLock::new(HugeFrameCache::new()),
    });
    // SAFETY: the boxed subpool is stationary throughout all synchronous cases.
    // Its retained PMM loan excludes other users of the entire mapped extent.
    // These private cases publish no owner/reference, release every child and
    // empty their local caches before returning. The final occupancy assertion
    // precedes destruction of the subpool and return of its backing loan.
    let borrowed: &'static NodePool = unsafe { &*core::ptr::from_ref(pool.as_ref()) };
    partial_refill_retains_demand(borrowed);
    failed_refill_preserves_live_ram(borrowed);
    full_cache_returns_unpublished_frames(borrowed);
    assert_eq!(pool.bitmap.free_count(), 25);
    drop(pool);
    backing.release();
}

fn partial_refill_retains_demand(pool: &'static NodePool) {
    let retained = pool
        .allocate(22, PAGE_SIZE_4K)
        .expect("partial refill pressure");
    let prepared = PreparedZeroedRefill::prepare(pool, ZERO_BATCH).expect("partial demand");
    assert_eq!(pool.bitmap.free_count(), 0);
    let (demand, refill) = prepared.into_parts();
    let address = demand.as_u64();
    assert_zeroed(&demand);
    drop(refill);
    assert_eq!(pool.bitmap.free_count(), 2);
    assert_eq!(demand.as_u64(), address);
    // SAFETY: this unpublished demand exclusively retains the complete page.
    unsafe {
        crate::mm::virt::mapping::phys_to_virt(demand.start_address())
            .as_mut_ptr::<u8>()
            .write_bytes(0x37, PAGE_SIZE_4K);
    }
    demand.release();
    assert_eq!(pool.bitmap.free_count(), 3);
    let (demand, retry) = PreparedZeroedRefill::prepare(pool, 3)
        .expect("retry after partial return")
        .into_parts();
    assert_eq!(pool.bitmap.free_count(), 0);
    for frame in core::iter::once(&demand).chain(retry.frames.iter().flatten()) {
        assert_zeroed(frame);
    }
    drop(retry);
    demand.release();
    assert_eq!(pool.bitmap.free_count(), 3);
    retained.release();
    assert_eq!(pool.bitmap.free_count(), 25);
}

fn failed_refill_preserves_live_ram(pool: &'static NodePool) {
    let live = pool.allocate(25, PAGE_SIZE_4K).expect("exhausted fixture");
    let address = live.as_u64();
    // SAFETY: this unique live owner retains all writable fixture RAM.
    unsafe {
        crate::mm::virt::mapping::phys_to_virt(live.start_address())
            .as_mut_ptr::<u8>()
            .write_bytes(0xa5, live.size_bytes() as usize);
    }
    assert!(matches!(
        PreparedZeroedRefill::prepare(pool, 0),
        Err(FrameAllocError::InvalidRange)
    ));
    assert!(matches!(
        PreparedZeroedRefill::prepare(pool, ZERO_BATCH + 1),
        Err(FrameAllocError::InvalidRange)
    ));
    assert!(matches!(
        PreparedZeroedRefill::prepare(pool, ZERO_BATCH),
        Err(FrameAllocError::Exhausted)
    ));
    assert_eq!(pool.bitmap.free_count(), 0);
    assert_eq!(live.as_u64(), address);
    // SAFETY: rejected preparation acquired no part of this retained extent.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            crate::mm::virt::mapping::phys_to_virt(live.start_address()).as_ptr::<u8>(),
            live.size_bytes() as usize,
        )
    };
    assert!(bytes.iter().all(|&byte| byte == 0xa5));
    live.release();
    assert_eq!(pool.bitmap.free_count(), 25);
}

fn full_cache_returns_unpublished_frames(pool: &'static NodePool) {
    let mut cache = LocalFrameCache::new();
    // LOOP_PROOF: mode=bounded; reason=Two eight-page refills fill the fixed sixteen-page zeroed cache.;
    for _ in 0..2 {
        let (demand, mut spare) = PreparedZeroedRefill::prepare(pool, ZERO_BATCH)
            .expect("cache fill")
            .into_parts();
        assert!(cache.zeroed.push(demand).is_ok());
        spare.populate(&mut cache);
    }
    assert_eq!(cache.zeroed.len, ZERO_CACHE_CAPACITY);
    assert_eq!(pool.bitmap.free_count(), 9);
    let (demand, mut refill) = PreparedZeroedRefill::prepare(pool, ZERO_BATCH)
        .expect("demand with full cache")
        .into_parts();
    refill.populate(&mut cache);
    assert_eq!(cache.zeroed.len, ZERO_CACHE_CAPACITY);
    assert_eq!(pool.bitmap.free_count(), 1);
    assert_zeroed(&demand);
    drop(refill);
    assert_eq!(pool.bitmap.free_count(), 8);
    for frame in cache.take_batch().into_iter().flatten() {
        assert_ne!(frame.as_u64(), demand.as_u64());
        assert_zeroed(&frame);
        frame.release();
    }
    assert!(cache.is_empty());
    assert_eq!(pool.bitmap.free_count(), 24);
    demand.release();
    assert_eq!(pool.bitmap.free_count(), 25);
}

fn assert_zeroed(frame: &PhysicalAllocation) {
    // SAFETY: each caller retains this unpublished page's unique owner through
    // the observation; the permanent HHDM covers the exact allocation extent.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            crate::mm::virt::mapping::phys_to_virt(frame.start_address()).as_ptr::<u8>(),
            frame.size_bytes() as usize,
        )
    };
    assert!(bytes.iter().all(|&byte| byte == 0));
}
