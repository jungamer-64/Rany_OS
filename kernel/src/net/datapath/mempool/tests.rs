// ============================================================================
// kernel/src/net/datapath/mempool/tests.rs - データパス / メモリプール / テスト
// ============================================================================

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
    assert_eq!(
        pool.alloc(),
        Err(MempoolError::LockPoisoned(MempoolLock::FreeList))
    );
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

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn packet_window_rejects_advance_past_visible_len() {
    let mut window = PacketWindow::new(64, 16, 8).expect("valid packet window");

    assert!(!window.advance(9));
    assert_eq!(
        window,
        PacketWindow::new(64, 16, 8).expect("valid packet window")
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn packet_window_rejects_retreat_without_headroom() {
    let mut window = PacketWindow::new(64, 4, 8).expect("valid packet window");

    assert!(!window.retreat(5));
    assert_eq!(
        window,
        PacketWindow::new(64, 4, 8).expect("valid packet window")
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn packet_window_rejects_retreat_past_capacity() {
    let mut window = PacketWindow::new(16, 4, 12).expect("valid packet window");

    assert!(!window.retreat(1));
    assert_eq!(
        window,
        PacketWindow::new(16, 4, 12).expect("valid packet window")
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn packet_window_preserves_bounds_across_valid_moves() {
    let mut window = PacketWindow::new(64, 16, 24).expect("valid packet window");

    assert!(window.advance(8));
    assert_eq!(
        window,
        PacketWindow::new(64, 24, 16).expect("valid packet window")
    );
    assert!(window.retreat(8));
    assert_eq!(
        window,
        PacketWindow::new(64, 16, 24).expect("valid packet window")
    );
}
