use super::super::*;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize};

const PRODUCERS: usize = 8;
const RETURNS: usize = 1024;

struct Returns {
    start: AtomicBool,
    remaining: AtomicUsize,
}

impl Returns {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            start: AtomicBool::new(false),
            remaining: AtomicUsize::new(PRODUCERS),
        })
    }
}

pub(crate) async fn concurrent_returns_smoke() {
    buddy_returns().await;
    slab_returns().await;
}

async fn finish_workers(domain: crate::domain::DomainId) {
    let deadline = crate::time::precise_time_nanos().saturating_add(20_000_000_000);
    // LOOP_PROOF: mode=event; reason=The test owns a finite producer domain, and typed incomplete shutdown is retried after a timer wait until completion or the nanosecond deadline.;
    loop {
        match crate::domain::terminate_domain(domain) {
            Ok(()) => return,
            Err(
                crate::domain::DomainLifecycleError::Busy(_)
                | crate::domain::DomainLifecycleError::CodeBusy { .. }
                | crate::domain::DomainLifecycleError::ReclamationInProgress,
            ) if crate::time::precise_time_nanos() < deadline => {
                crate::task::sleep_ms(1)
                    .await
                    .expect("worker retirement timer");
            }
            Err(error) => panic!("heap producer domain retirement: {error:?}"),
        }
    }
}

fn fill(block: &RawBlock, bytes: usize, value: u8) {
    // SAFETY: each caller retains this unpublished allocation's unique payload
    // reservation. Neither the shared pool nor another producer may reuse it.
    unsafe { block.pointer.as_ptr().write_bytes(value, bytes) };
}

fn assert_payload(block: &RawBlock, bytes: usize, value: u8) {
    // SAFETY: the caller retains the sentinel's live reservation through every
    // concurrent return, and no worker receives a borrow of this payload.
    let payload = unsafe { core::slice::from_raw_parts(block.pointer.as_ptr(), bytes) };
    assert!(payload.iter().all(|byte| *byte == value));
}

fn reuse_buddy(pool: &IrqPoisonLock<BuddyPool>, sentinel: &RawBlock) {
    let AllocationSource::Buddy(reservation) = &sentinel.source else {
        panic!("Buddy sentinel")
    };
    let held = pool
        .lock()
        .unwrap_or_else(|_| panic!("private Buddy pool poisoned"));
    // SAFETY: the sentinel retains the region and the private pool guard grants
    // this sole consumer mutable state access, disjoint from pending producers.
    let retained = unsafe { reservation.region.as_ref() };
    // SAFETY: no other state borrower exists while this pool guard is held.
    let state = unsafe { &mut *retained.state.get() };
    drain_buddy_returns(retained, state);
    let layout = Layout::from_size_align(127, 64).unwrap();
    let pointer = NonNull::new(state.heap.allocate(layout)).expect("reusable Buddy RAM");
    state.live += 1;
    let returned = BuddyReservation {
        region: reservation.region,
    };
    // SAFETY: this fresh reservation exclusively owns its writable payload.
    unsafe { pointer.as_ptr().write_bytes(0xa5, layout.size()) };
    drop(held);
    publish_buddy_return(pointer, returned, layout);
}

async fn buddy_returns() {
    let cpus: Vec<_> = crate::cpu::snapshot().online().iter().collect();
    assert!(!cpus.is_empty());
    let layout = Layout::from_size_align(7000, 4096).unwrap();
    let pool = Arc::new(IrqPoisonLock::new(BuddyPool { head: None }));
    let sentinel = PreparedBuddyRegion::allocate(NumaNodeId::NODE_0, layout)
        .expect("Buddy fixture RAM")
        .publish(&pool, layout)
        .unwrap_or_else(|_| panic!("Buddy fixture publication"));
    fill(&sentinel, layout.size(), 0x37);
    let mut buckets: [Vec<(RawBlock, Layout)>; PRODUCERS] = core::array::from_fn(|_| Vec::new());
    let bytes = {
        let _held = pool
            .lock()
            .unwrap_or_else(|_| panic!("private Buddy pool poisoned"));
        let AllocationSource::Buddy(reservation) = &sentinel.source else {
            panic!("Buddy sentinel")
        };
        // SAFETY: the sentinel and sole private pool guard retain the region.
        let retained = unsafe { reservation.region.as_ref() };
        // SAFETY: this is the only state borrower, before producer publication.
        let state = unsafe { &mut *retained.state.get() };
        let mut spans = Vec::new();
        // LOOP_PROOF: mode=bounded; reason=Exactly RETURNS reservations are prepared before admitting the finite producer batch.;
        for index in 0..RETURNS {
            let item_layout = Layout::from_size_align(1 + (index % 7) * 55, 64).unwrap();
            let pointer = NonNull::new(state.heap.allocate(item_layout)).expect("Buddy capacity");
            state.live += 1;
            let start = pointer.as_ptr().addr();
            let end = start + item_layout.size().max(64).next_power_of_two();
            assert!(
                spans
                    .iter()
                    .all(|&(first, last)| end <= first || last <= start)
            );
            spans.push((start, end));
            let block = RawBlock {
                pointer,
                source: AllocationSource::Buddy(BuddyReservation {
                    region: reservation.region,
                }),
            };
            fill(&block, item_layout.size(), (index % 251) as u8);
            buckets[index % PRODUCERS].push((block, item_layout));
        }
        state.heap.heap_size + retained.metadata.size_bytes() as usize
    };
    let domain =
        crate::domain::create_domain("heap-buddy-returns".into()).expect("producer domain");
    let progress = Returns::new();
    for (index, bucket) in buckets.into_iter().enumerate() {
        let cpu = cpus[index % cpus.len()];
        let progress = Arc::clone(&progress);
        let retained_pool = Arc::clone(&pool);
        crate::task::spawn_in_domain(
            async move {
                let _retained_pool = retained_pool;
                // LOOP_PROOF: mode=condition; reason=The owner publishes start after admitting the finite producer batch, and each unsuccessful observation yields.;
                while !progress.start.load(Ordering::Acquire) {
                    crate::task::yield_now().await;
                }
                assert_eq!(CurrentCpu::acquire().expect("producer CPU").id(), cpu);
                for (block, item_layout) in bucket {
                    let AllocationSource::Buddy(reservation) = block.source else {
                        panic!("Buddy producer reservation")
                    };
                    publish_buddy_return(block.pointer, reservation, item_layout);
                    crate::task::yield_now().await;
                }
                assert_eq!(CurrentCpu::acquire().expect("producer CPU").id(), cpu);
                progress.remaining.fetch_sub(1, Ordering::Release);
            },
            crate::task::TaskOptions::pinned(cpu),
            domain,
        )
        .expect("Buddy producer admission");
    }
    progress.start.store(true, Ordering::Release);
    let deadline = crate::time::precise_time_nanos().saturating_add(20_000_000_000);
    // LOOP_PROOF: mode=condition; reason=The finite producer batch decrements remaining, and the independent nanosecond deadline bounds observation with timer waits.;
    while progress.remaining.load(Ordering::Acquire) != 0
        && crate::time::precise_time_nanos() < deadline
    {
        reuse_buddy(&pool, &sentinel);
        assert_payload(&sentinel, layout.size(), 0x37);
        crate::task::sleep_ms(1)
            .await
            .expect("Buddy observation timer");
    }
    assert_eq!(progress.remaining.load(Ordering::Acquire), 0);
    finish_workers(domain).await;
    assert_eq!(reclaim_buddy_pool(&pool).reclaimed_bytes, 0);
    {
        let _held = pool
            .lock()
            .unwrap_or_else(|_| panic!("private Buddy pool poisoned"));
        let AllocationSource::Buddy(reservation) = &sentinel.source else {
            panic!("Buddy sentinel")
        };
        // SAFETY: producers have retired; this guard and the live sentinel
        // retain the region and grant exclusive observation of its state.
        let retained = unsafe { reservation.region.as_ref() };
        // SAFETY: the private pool guard excludes mutable state borrowers.
        let state = unsafe { &*retained.state.get() };
        assert_eq!(state.live, 1);
        assert_eq!(state.heap.free_bytes(), state.heap.heap_size - 8192);
        assert!(retained.pending.load(Ordering::Acquire).is_null());
    }
    assert_payload(&sentinel, layout.size(), 0x37);
    let AllocationSource::Buddy(reservation) = sentinel.source else {
        panic!("Buddy sentinel")
    };
    publish_buddy_return(sentinel.pointer, reservation, layout);
    assert_eq!(reclaim_buddy_pool(&pool).reclaimed_bytes, bytes);
    assert_eq!(reclaim_buddy_pool(&pool), PoolReclaim::default());
}

async fn slab_returns() {
    let cpus: Vec<_> = crate::cpu::snapshot().online().iter().collect();
    assert!(!cpus.is_empty());
    let home = CurrentCpu::acquire().expect("slab owner CPU").id();
    let layout = Layout::from_size_align(256, 64).unwrap();
    let mut sentinels = Vec::new();
    let mut pages = alloc::collections::BTreeSet::new();
    let mut buckets: [Vec<RawBlock>; PRODUCERS] = core::array::from_fn(|_| Vec::new());
    // LOOP_PROOF: mode=bounded; reason=Exactly RETURNS slab reservations are prepared, retaining one sentinel for every observed physical slab page.;
    for index in 0..RETURNS {
        let block = slab_block(NumaNodeId::NODE_0, SlabClass(2), home).expect("slab fixture RAM");
        let AllocationSource::Slab(reservation) = &block.source else {
            panic!("slab fixture reservation")
        };
        if pages.insert(reservation.page().as_ptr().addr()) {
            fill(&block, layout.size(), 0x37);
            sentinels.push(block);
        } else {
            buckets[index % PRODUCERS].push(block);
        }
    }
    let domain = crate::domain::create_domain("heap-slab-returns".into()).expect("producer domain");
    let progress = Returns::new();
    for (index, bucket) in buckets.into_iter().enumerate() {
        let cpu = cpus[index % cpus.len()];
        let progress = Arc::clone(&progress);
        crate::task::spawn_in_domain(
            async move {
                // LOOP_PROOF: mode=condition; reason=The owner publishes start after admitting the finite producer batch, and each unsuccessful observation yields.;
                while !progress.start.load(Ordering::Acquire) {
                    crate::task::yield_now().await;
                }
                assert_eq!(CurrentCpu::acquire().expect("producer CPU").id(), cpu);
                for block in bucket {
                    fill(&block, layout.size(), 0xa5);
                    release(block, layout);
                    crate::task::yield_now().await;
                }
                assert_eq!(CurrentCpu::acquire().expect("producer CPU").id(), cpu);
                progress.remaining.fetch_sub(1, Ordering::Release);
            },
            crate::task::TaskOptions::pinned(cpu),
            domain,
        )
        .expect("slab producer admission");
    }
    progress.start.store(true, Ordering::Release);
    let deadline = crate::time::precise_time_nanos().saturating_add(20_000_000_000);
    // LOOP_PROOF: mode=condition; reason=The finite producer batch decrements remaining, and the nanosecond deadline bounds pressure and observation with timer waits.;
    while progress.remaining.load(Ordering::Acquire) != 0
        && crate::time::precise_time_nanos() < deadline
    {
        reclaim_shared_pools();
        for sentinel in &sentinels {
            assert_payload(sentinel, layout.size(), 0x37);
        }
        crate::task::sleep_ms(1)
            .await
            .expect("slab observation timer");
    }
    assert_eq!(progress.remaining.load(Ordering::Acquire), 0);
    finish_workers(domain).await;
    for sentinel in sentinels {
        assert_payload(&sentinel, layout.size(), 0x37);
        release(sentinel, layout);
    }
    reclaim_shared_pools();
}
