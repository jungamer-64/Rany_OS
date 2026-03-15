fn bounded_missing_update(mut index: usize, limit: usize) {
    // LOOP_PROOF: mode=bounded; reason=Claims a bounded proof without updating the controlling counter.;
    while index < limit {
        core::hint::black_box(limit);
    }
}
