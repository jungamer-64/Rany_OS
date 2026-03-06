use super::*;

#[test_case]
fn test_remote_free_entry_basics() {
    let empty = RemoteFreeEntry::empty();
    assert!(empty.is_empty());
    assert_eq!(empty.count, 0);

    let single = RemoteFreeEntry::single(0x1000, 0);
    assert!(!single.is_empty());
    assert_eq!(single.count, 1);
    assert_eq!(single.page_size(), PAGE_SIZE_4K as u64);
    assert_eq!(single.total_bytes(), PAGE_SIZE_4K as u64);

    let range = RemoteFreeEntry::range(0x200000, 8, 1); // 8 x 2MB
    assert_eq!(range.count, 8);
    assert_eq!(range.page_size(), PAGE_SIZE_2M as u64);
    assert_eq!(range.total_bytes(), (8 * PAGE_SIZE_2M) as u64);
}

#[test_case]
fn test_quarantine_ring_push_drain() {
    let mut ring: QuarantineRing<8> = QuarantineRing::new();

    // Push entries with different epochs
    assert!(ring.push(0x1000, 0, 1));
    assert!(ring.push(0x2000, 0, 2));
    assert!(ring.push(0x3000, 0, 3));
    assert_eq!(ring.len(), 3);

    // Drain entries older than epoch 2
    let mut out = [QuarantineEntry::empty(); 8];
    let drained = ring.drain_older_than(2, 8, &mut out);
    assert_eq!(drained, 2); // epoch 1 and 2
    assert_eq!(ring.len(), 1);

    // Remaining entry is epoch 3
    assert_eq!(ring.oldest_epoch(), Some(3));
}

#[test_case]
fn test_quarantine_ring_full() {
    let mut ring: QuarantineRing<4> = QuarantineRing::new();

    assert!(ring.push(0x1000, 0, 1));
    assert!(ring.push(0x2000, 0, 2));
    assert!(ring.push(0x3000, 0, 3));
    assert!(ring.push(0x4000, 0, 4));
    assert!(ring.is_full());

    // Should fail when full
    assert!(!ring.push(0x5000, 0, 5));

    // Drain one
    let mut out = [QuarantineEntry::empty(); 1];
    ring.drain_older_than(1, 1, &mut out);

    // Now can push again
    assert!(ring.push(0x5000, 0, 5));
}

#[test_case]
fn test_quarantine_epoch_wraparound() {
    let mut ring: QuarantineRing<8> = QuarantineRing::new();

    // Push entry near u32::MAX
    ring.push(0x1000, 0, u32::MAX - 1);
    ring.push(0x2000, 0, u32::MAX);
    ring.push(0x3000, 0, 0); // Wrapped
    ring.push(0x4000, 0, 1);

    // Drain with completed epoch = 0 (wrapped)
    // Should drain u32::MAX - 1, u32::MAX, 0
    let mut out = [QuarantineEntry::empty(); 8];
    let drained = ring.drain_older_than(0, 8, &mut out);
    assert_eq!(drained, 3);
    assert_eq!(ring.len(), 1);
    assert_eq!(ring.oldest_epoch(), Some(1));
}
