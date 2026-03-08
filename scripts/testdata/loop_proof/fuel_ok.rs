fn ok_fuel_loop() {
    // LOOP_PROOF: mode=fuel; reason=Work queue polling is bounded by per-iteration fuel checks.;
    loop {
        if !crate::task::fuel::Fuel::consume(1) {
            break;
        }
        break;
    }
}
