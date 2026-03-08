use super::*;

pub fn basic_allocation_smoke() -> bool {
    let bitmap = HierarchicalBitmap::new(1000);
    if bitmap.free_count() != 1000 {
        return false;
    }

    let idx = match bitmap.allocate_one() {
        Some(i) => i,
        None => return false,
    };
    if idx >= 1000 {
        return false;
    }
    if bitmap.free_count() != 999 {
        return false;
    }
    if bitmap.is_free(idx) {
        return false;
    }

    bitmap.mark_free(idx);
    bitmap.free_count() == 1000 && bitmap.is_free(idx)
}

pub fn mark_allocated_free_smoke() -> bool {
    let bitmap = HierarchicalBitmap::new(100);

    if !bitmap.mark_allocated(50) {
        return false;
    }
    if bitmap.is_free(50) {
        return false;
    }
    if bitmap.mark_allocated(50) {
        return false;
    }

    if !bitmap.mark_free(50) {
        return false;
    }
    if !bitmap.is_free(50) {
        return false;
    }
    !bitmap.mark_free(50)
}

pub fn exhaustion_smoke() -> bool {
    let bitmap = HierarchicalBitmap::new(64);
    let mut allocated = alloc::vec::Vec::new();

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while let Some(idx) = bitmap.allocate_one() {
        allocated.push(idx);
    }

    if allocated.len() != 64 {
        return false;
    }
    if bitmap.free_count() != 0 {
        return false;
    }
    if bitmap.allocate_one().is_some() {
        return false;
    }

    for idx in allocated {
        bitmap.mark_free(idx);
    }
    bitmap.free_count() == 64
}

pub fn range_free_smoke() -> bool {
    let bitmap = HierarchicalBitmap::new(200);

    if !bitmap.is_range_free(0, 64) {
        return false;
    }
    if !bitmap.is_range_free(100, 50) {
        return false;
    }

    bitmap.mark_allocated(110);
    !bitmap.is_range_free(100, 50) && bitmap.is_range_free(100, 10) && bitmap.is_range_free(111, 39)
}

pub fn claim_word_smoke() -> bool {
    let bitmap = HierarchicalBitmap::new(128);

    let claimed = bitmap.try_claim_word(0);
    if claimed != u64::MAX {
        return false;
    }
    if bitmap.free_count() != 64 {
        return false;
    }

    let claimed2 = bitmap.try_claim_word(0);
    if claimed2 != 0 {
        return false;
    }

    bitmap.return_word(0, claimed);
    bitmap.free_count() == 128
}

pub fn last_word_partial_smoke() -> bool {
    let bitmap = HierarchicalBitmap::new(100);

    let mask = bitmap.valid_mask(1);
    if mask != (1u64 << 36) - 1 {
        return false;
    }

    let mut count = 0;
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while bitmap.allocate_one().is_some() {
        count += 1;
    }
    count == 100
}
