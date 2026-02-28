use super::*;
use alloc::sync::Arc;
use alloc::vec::Vec;

#[cfg_attr(test, test_case)]
pub fn test_pool_id() {
    let id = PoolId::new(42);
    assert_eq!(id.as_u32(), 42);
}

#[cfg_attr(test, test_case)]
pub fn test_sg_list() {
    let pool = MemoryPool::new(PoolId::new(200), 128, 2);
    let b1 = pool.alloc().unwrap();
    let b2 = pool.alloc().unwrap();
    let mut sg = SgList::new();
    sg.push(b1.clone_ref());
    sg.push(b2.clone_ref());
    assert!(!sg.is_empty());
    assert_eq!(sg.len(), 2);
    assert_eq!(sg.total_len(), 0); // both buffers empty by default

    // entries returns SG descriptors derived from owned buffers
    let entries = sg.entries();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].len, 0);

    // dropping original buffers must not invalidate sg list entries
    drop(b1);
    drop(b2);
    // we can still retrieve addresses from sg (should not crash)
    let _ = sg.entries();
}

#[cfg_attr(test, test_case)]
pub fn test_packet_chain() {
    let pool = MemoryPool::new(PoolId::new(201), 128, 2);
    let mut b1 = pool.alloc().unwrap();
    b1.set_len(10);
    let mut b2 = pool.alloc().unwrap();
    b2.set_len(20);

    let mut chain = PacketChain::new();
    assert!(chain.is_empty());
    chain.push(b1);
    chain.push(b2);
    assert_eq!(chain.len(), 2);
    assert_eq!(chain.total_len, 30);
    assert_eq!(chain.total_len(), 30);

    let first = chain.pop().expect("first packet");
    assert_eq!(first.len(), 10);
    let second = chain.pop().expect("second packet");
    assert_eq!(second.len(), 20);
    assert!(chain.is_empty());
}

#[cfg_attr(test, test_case)]
pub fn test_zero_copy_clone_drop_returns_once() {
    let pool = MemoryPool::new(PoolId::new(100), 256, 2);
    let Some(buf) = pool.alloc() else {
        return;
    };
    let clone = buf.clone_ref();

    assert_eq!(buf.debug_ref_count(), 2);
    assert_eq!(pool.stats().in_use.load(core::sync::atomic::Ordering::Acquire), 1);

    drop(clone);
    assert_eq!(buf.debug_ref_count(), 1);
    assert_eq!(pool.stats().frees.load(core::sync::atomic::Ordering::Acquire), 0);
    assert_eq!(pool.stats().in_use.load(core::sync::atomic::Ordering::Acquire), 1);

    drop(buf);
    assert_eq!(pool.stats().frees.load(core::sync::atomic::Ordering::Acquire), 1);
    assert_eq!(pool.stats().in_use.load(core::sync::atomic::Ordering::Acquire), 0);
}

#[cfg_attr(test, test_case)]
pub fn test_zero_copy_split_drop_uses_same_slot() {
    let pool = MemoryPool::new(PoolId::new(101), 256, 1);
    let Some(mut first) = pool.alloc() else {
        return;
    };
    first.set_len(32);
    let second = first.split_at(16).expect("split should succeed");

    assert_eq!(first.debug_ref_count(), 2);
    drop(second);
    assert_eq!(first.debug_ref_count(), 1);
    assert_eq!(pool.stats().frees.load(core::sync::atomic::Ordering::Acquire), 0);

    drop(first);
    assert_eq!(pool.available(), 1);
    assert_eq!(pool.stats().frees.load(core::sync::atomic::Ordering::Acquire), 1);
}

#[cfg_attr(test, test_case)]
pub fn test_zero_copy_try_as_mut_slice_rejects_shared() {
    let pool = MemoryPool::new(PoolId::new(102), 256, 1);
    let Some(mut buf) = pool.alloc() else {
        return;
    };
    buf.set_len(8);
    let _clone = buf.clone_ref();

    let err = buf.try_as_mut_slice().unwrap_err();
    assert_eq!(err, ZeroCopyError::SharedMutationDenied);
}

#[cfg_attr(test, test_case)]
pub fn test_reserve_headroom_only_checks_headroom() {
    let pool = MemoryPool::new(PoolId::new(202), 256, 1);
    let mut buf = pool.alloc().unwrap();
    // fill to capacity
    let cap = buf.capacity();
    buf.set_len(cap);
    // there is headroom initial
    let orig_head = buf.headroom;
    assert!(buf.reserve_headroom(16).is_ok());
    assert_eq!(buf.headroom, orig_head - 16);
    // len should not change
    assert_eq!(buf.len(), cap);
    // trying to reserve more than available fails
    assert!(buf.reserve_headroom(orig_head).is_err());
}

#[cfg_attr(test, test_case)]
pub fn test_consume_headroom_shrinks_capacity_and_reserve_restores() {
    let pool = MemoryPool::new(PoolId::new(203), 256, 1);
    let mut buf = pool.alloc().unwrap();
    let base_cap = buf.capacity();
    let base_head = buf.headroom;

    buf.set_len(64);
    buf.consume_headroom(16).expect("consume within len");
    assert_eq!(buf.headroom, base_head + 16);
    assert_eq!(buf.capacity(), base_cap - 16);
    assert_eq!(buf.len(), 48);

    // `set_len` must be clamped by the reduced capacity after front-trim.
    buf.set_len(base_cap);
    assert_eq!(buf.len(), base_cap - 16);

    buf.reserve_headroom(16).expect("restore headroom");
    assert_eq!(buf.headroom, base_head);
    assert_eq!(buf.capacity(), base_cap);
}

#[cfg_attr(test, test_case)]
pub fn test_per_cpu_cache_spill_and_refill() {
    // make a pool with a handful of buffers so we can exercise caching
    let total = LOCAL_FREE_CACHE_CAPACITY + 2;
    let pool = MemoryPool::new(PoolId::new(300), 128, total);
    assert_eq!(pool.available(), total);

    // First alloc drains one from a refill batch, so freeing it back leaves a
    // batch-sized local cache (not just 1 entry).
    let buf = pool.alloc().unwrap();
    pool.free(buf);
    let expected_local = LOCAL_FREE_REFILL_BATCH.min(total);
    assert_eq!(pool.local_cache_len(0), expected_local);
    assert_eq!(pool.global_cache_len(), total - expected_local);

    // Drain the pool completely, then return all buffers. Returning more than
    // LOCAL_FREE_CACHE_CAPACITY entries forces spill from local -> global.
    let mut held = Vec::new();
    while let Some(b) = pool.alloc() {
        held.push(b);
    }
    assert_eq!(held.len(), total);
    assert_eq!(pool.available(), 0);

    for b in held.drain(..) {
        pool.free(b);
    }
    assert_eq!(pool.available(), total);
    assert!(pool.local_cache_len(0) <= LOCAL_FREE_CACHE_CAPACITY);
    assert!(pool.global_cache_len() >= 1);

    // Drain current local cache and allocate one more to force global->local refill.
    let local_before = pool.local_cache_len(0);
    let global_before = pool.global_cache_len();
    assert!(global_before > 0);

    let mut drained = Vec::new();
    for _ in 0..(local_before + 1) {
        drained.push(pool.alloc().expect("refill path should supply buffer"));
    }

    assert!(pool.local_cache_len(0) <= LOCAL_FREE_CACHE_CAPACITY);
    assert!(pool.global_cache_len() < global_before);
    assert_eq!(pool.available(), total - drained.len());

    for b in drained {
        pool.free(b);
    }
    assert_eq!(pool.available(), total);
}

#[cfg_attr(test, test_case)]
pub fn test_zero_copy_try_as_mut_slice_unique_write() {
    let pool = MemoryPool::new(PoolId::new(103), 256, 1);
    let Some(mut buf) = pool.alloc() else {
        return;
    };
    buf.set_len(4);
    let slice = buf.try_as_mut_slice().expect("unique buffer should be mutable");
    slice.copy_from_slice(b"TEST");
    assert_eq!(buf.as_slice(), b"TEST");
}

#[cfg_attr(test, test_case)]
pub fn test_zero_copy_reader_queues_multiple_buffers() {
    let pool = Arc::new(MemoryPool::new(PoolId::new(104), 256, 2));
    let mut reader = ZeroCopyReader::new(pool.clone());

    let mut b1 = pool.alloc().unwrap();
    b1.set_len(1);
    let mut b2 = pool.alloc().unwrap();
    b2.set_len(2);

    reader.on_data(b1);
    reader.on_data(b2);

    assert_eq!(reader.pending.len(), 2);
    assert_eq!(reader.pending.front().map(ZeroCopyBuffer::len), Some(1));
}
