fn bounded_ok(mut index: usize, limit: usize) {
    // LOOP_PROOF: mode=bounded; reason=Loop counter index advances monotonically toward the explicit upper bound.;
    while index < limit {
        index += 1;
    }
}
