use super::*;
use crate::sync::set_panicking;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_per_core_alloc_poisoned_fallbacks_to_global() {
    // Initialize per-core caches for CPU 0
    init_per_core_caches(1);

    // Poison the lock for CPU 0
    set_panicking(true);
    {
        let _guard = PER_CORE_CACHES[0].lock().unwrap();
    }
    set_panicking(false);

    let layout = Layout::from_size_align(128, 8).unwrap();
    let ptr = per_core_alloc(0, layout).expect("should fall back to global alloc");

    // Deallocate via per_core_dealloc (should detect poisoned and use global dealloc)
    unsafe { per_core_dealloc(0, ptr, layout) };
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_slab_cache() {
    let mut cache = SlabCache::new(64);

    // 複数回割り当て
    let ptr1 = cache.allocate();
    assert!(ptr1.is_some());

    let ptr2 = cache.allocate();
    assert!(ptr2.is_some());

    // 異なるアドレス
    assert_ne!(ptr1.unwrap().as_ptr(), ptr2.unwrap().as_ptr());

    // 解放
    unsafe {
        cache.deallocate(ptr1.unwrap());
        cache.deallocate(ptr2.unwrap());
    }

    // 統計確認
    let stats = cache.stats();
    assert_eq!(stats.alloc_count, 2);
    assert_eq!(stats.dealloc_count, 2);
}
