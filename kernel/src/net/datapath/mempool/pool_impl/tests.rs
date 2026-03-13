use super::*;
use alloc::vec;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_packet_pool_alloc_and_free_smoke() {
    let pool = PacketPool::new(2, 128);
    assert_eq!(pool.available(), 2);

    let buf = pool.alloc().expect("pool must return a buffer");
    assert_eq!(buf.len(), 0);
    assert_eq!(pool.available(), 1);

    pool.free(buf);
    assert_eq!(pool.available(), 2);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_packet_pool_free_rebuilds_wrong_capacity_buffer() {
    let pool = PacketPool::new(1, 64);
    let _ = pool.alloc().expect("pool must return a buffer");
    assert_eq!(pool.available(), 0);

    pool.free(vec![1u8, 2, 3, 4]);
    assert_eq!(pool.available(), 1);

    let recycled = pool.alloc().expect("pool must return recycled buffer");
    assert_eq!(recycled.len(), 0);
    assert!(recycled.capacity() >= 64);
}
