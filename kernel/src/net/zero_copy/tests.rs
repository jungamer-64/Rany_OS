use super::*;

#[cfg_attr(test, test_case)]
pub fn test_pool_id() {
    let id = PoolId::new(42);
    assert_eq!(id.as_u32(), 42);
}

#[cfg_attr(test, test_case)]
pub fn test_sg_list() {
    let sg = SgList::new();
    assert!(sg.is_empty());
    assert_eq!(sg.total_len(), 0);
}

#[cfg_attr(test, test_case)]
pub fn test_packet_chain() {
    let chain = PacketChain::new();
    assert!(chain.is_empty());
    assert_eq!(chain.len(), 0);
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
