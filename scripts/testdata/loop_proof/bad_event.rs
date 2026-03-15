fn bad_event_loop() {
    // LOOP_PROOF: mode=event; reason=Claims event-driven progress without any exit or yield site.;
    loop {
        core::hint::black_box(1usize);
    }
}
