fn bad_fuel_loop() {
    // LOOP_PROOF: mode=fuel; reason=Busy loop requires cooperative budget checks.;
    loop {
        core::hint::spin_loop();
        break;
    }
}
