fn bad_halt_loop(should_exit: bool) -> ! {
    // LOOP_PROOF: mode=halt; reason=Claims halt semantics even though the loop still has an escape path.;
    loop {
        if should_exit {
            break;
        }
        core::hint::spin_loop();
    }
    panic!("unexpected escape")
}
