fn bad_condition_loop() {
    // LOOP_PROOF: mode=condition; reason=Claims a condition proof on an unconditional loop.;
    loop {
        break;
    }
}
