fn ok_halt_loop() -> ! {
    // LOOP_PROOF: mode=halt; reason=Fatal path intentionally halts forever after reporting the unrecoverable state.;
    loop {
        core::hint::spin_loop();
    }
}
