fn bad_reason_loop() {
    // LOOP_PROOF: mode=event; reason=TODO later.;
    loop {
        break;
    }
}
