use super::*;
use crate::mm::types::FrameIndex;
use core::sync::atomic::Ordering;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_memcg_counter() {
    let counter = MemcgCounter::new();
    assert_eq!(counter.current(), 0);

    counter.add(100);
    assert_eq!(counter.current(), 100);
    assert_eq!(counter.peak(), 100);

    counter.sub(50);
    assert_eq!(counter.current(), 50);
    assert_eq!(counter.peak(), 100); // ピークは変わらない
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_memcg_id() {
    let id = MemcgId::new(42);
    assert_eq!(id.as_u64(), 42);
    assert_eq!(MemcgId::ROOT.as_u64(), 0);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_memcg_page_track_and_untrack() {
    // Ensure manager initialized
    init_memcg();

    let id = memcg_create(String::from("test"), memcg_root()).expect("create memcg");

    // Initially zero
    let s = memcg_stats(id).expect("stats");
    assert_eq!(s.anon_pages, 0);

    // Charge and track one anonymous page
    assert!(memcg_charge(id, 1, ChargeType::Anon).is_ok());
    let frame = FrameIndex::new(42);
    memcg_track_page(frame, id, ChargeType::Anon);

    let s = memcg_stats(id).expect("stats");
    assert_eq!(s.anon_pages, 1);

    // Untrack + uncharge
    if let Some(info) = memcg_untrack_page(frame) {
        memcg_uncharge(info.memcg_id, 1, info.charge_type);
    } else {
        panic!("expected page to be tracked");
    }

    let s = memcg_stats(id).expect("stats");
    assert_eq!(s.anon_pages, 0);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_memcg_untrack_returns_none_if_not_tracked() {
    init_memcg();
    let frame = FrameIndex::new(1234);
    assert!(memcg_untrack_page(frame).is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_memcg_charge_rollup_to_parent() {
    init_memcg();
    let child = memcg_create(String::from("child"), memcg_root()).expect("create child");
    assert!(memcg_charge(child, 2, ChargeType::Anon).is_ok());

    let s_child = memcg_stats(child).expect("child stats");
    assert_eq!(s_child.anon_pages, 2);

    if let Some(s_root) = memcg_stats(memcg_root()) {
        assert!(s_root.anon_pages >= 2);
    }

    memcg_uncharge(child, 2, ChargeType::Anon);
    let s_child2 = memcg_stats(child).expect("child stats");
    assert_eq!(s_child2.anon_pages, 0);
}
