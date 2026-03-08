fn ok_condition_loop(mut n: usize) {
    // LOOP_PROOF: mode=condition; reason=Loop condition monotonically decreases n to zero.;
    while n > 0 {
        n -= 1;
    }
}
