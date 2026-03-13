use super::*;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_basic_allocation() {
    let bitmap = HierarchicalBitmap::new(1000);
    assert_eq!(bitmap.free_count(), 1000);

    let idx = bitmap.allocate_one().unwrap();
    assert!(idx < 1000);
    assert_eq!(bitmap.free_count(), 999);
    assert!(!bitmap.is_free(idx));

    bitmap.mark_free(idx);
    assert_eq!(bitmap.free_count(), 1000);
    assert!(bitmap.is_free(idx));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_mark_allocated_free() {
    let bitmap = HierarchicalBitmap::new(100);

    assert!(bitmap.mark_allocated(50));
    assert!(!bitmap.is_free(50));
    assert!(!bitmap.mark_allocated(50)); // Already allocated

    assert!(bitmap.mark_free(50));
    assert!(bitmap.is_free(50));
    assert!(!bitmap.mark_free(50)); // Already free
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_exhaustion() {
    let bitmap = HierarchicalBitmap::new(64);
    let mut allocated = Vec::new();

    // Allocate all
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while let Some(idx) = bitmap.allocate_one() {
        allocated.push(idx);
    }

    assert_eq!(allocated.len(), 64);
    assert_eq!(bitmap.free_count(), 0);
    assert!(bitmap.allocate_one().is_none());

    // Free all
    for idx in allocated {
        bitmap.mark_free(idx);
    }

    assert_eq!(bitmap.free_count(), 64);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_range_free() {
    let bitmap = HierarchicalBitmap::new(200);

    assert!(bitmap.is_range_free(0, 64));
    assert!(bitmap.is_range_free(100, 50));

    bitmap.mark_allocated(110);
    assert!(!bitmap.is_range_free(100, 50));
    assert!(bitmap.is_range_free(100, 10));
    assert!(bitmap.is_range_free(111, 39));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_claim_word() {
    let bitmap = HierarchicalBitmap::new(128);

    let claimed = bitmap.try_claim_word(0);
    assert_eq!(claimed, u64::MAX);
    assert_eq!(bitmap.free_count(), 64);

    // Second claim should return 0
    let claimed2 = bitmap.try_claim_word(0);
    assert_eq!(claimed2, 0);

    // Return the word
    bitmap.return_word(0, claimed);
    assert_eq!(bitmap.free_count(), 128);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_last_word_partial() {
    // 100 units = 1 full word + 36 bits in last word
    let bitmap = HierarchicalBitmap::new(100);

    // Last word should only have 36 valid bits
    let mask = bitmap.valid_mask(1);
    assert_eq!(mask, (1u64 << 36) - 1);

    // Allocate all 100 units
    let mut count = 0;
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while bitmap.allocate_one().is_some() {
        count += 1;
    }
    assert_eq!(count, 100);
}
