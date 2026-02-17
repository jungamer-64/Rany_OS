use super::*;

#[test_case]
fn exchange_heap_after_global_heap() {
    // Exchange heap must be placed after the global heap (no overlap)
    let heap_end = heap_start().saturating_add(HEAP_SIZE as u64);
    assert!(exchange_heap_start() >= heap_end);
}
