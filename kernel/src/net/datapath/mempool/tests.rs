use super::*;
use crate::sync::set_panicking;
use core::sync::atomic::Ordering;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_mempool_poisoned_alloc_fails() {
    let pool = Box::leak(Box::new(Mempool::new(1)));
    pool.init(1).expect("init should succeed");

    // Poison the free_list by simulating a panic while holding the lock
    set_panicking(true);
    {
        let _guard = pool.free_list.lock().unwrap();
    }
    set_panicking(false);

    // Allocation should fail and increment alloc_failed
    assert!(pool.alloc().is_none());
    assert!(pool.alloc_failed.load(Ordering::Relaxed) > 0);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_mempool_stats() {
    let pool = Box::leak(Box::new(Mempool::new(1)));
    let stats = pool.stats();
    assert_eq!(stats.total_buffers, 0);
    assert_eq!(stats.free_buffers, 0);
}
