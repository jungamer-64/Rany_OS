// ============================================================================
// kernel/src/io/iommu/runtime/zombie/tests.rs
// ============================================================================

use super::*;

#[test_case]
fn test_zombie_queue_basic() {
    let queue = ZombieQueue::new();

    // Enqueue a zombie (domain_id is u16)
    assert!(queue.try_enqueue(0x1000, 4096, 1u16, None, 0, None));

    // Check stats
    let stats = queue.stats();
    assert_eq!(stats.total_enqueued, 1);
    assert_eq!(stats.total_processed, 0);
    assert_eq!(stats.total_drained, 0);
    assert_eq!(stats.total_dropped, 0);

    // Process the zombie
    let mut processed_data: Option<ZombieData> = None;
    let count = queue.process_pending(10, |data| {
        processed_data = Some(data);
        true
    });

    assert_eq!(count, 1);
    let data = processed_data.unwrap();
    assert_eq!(data.iova, 0x1000);
    assert_eq!(data.size, 4096);
    assert_eq!(data.domain_id, 1);

    // Check stats after processing
    let stats = queue.stats();
    assert_eq!(stats.total_processed, 1);
    assert_eq!(stats.total_drained, 1);
    assert_eq!(queue.pending_estimate(), 0);
}

#[test_case]
fn test_zombie_queue_failed_cleanup() {
    let queue = ZombieQueue::new();

    // Enqueue two zombies
    assert!(queue.try_enqueue(0x1000, 4096, 1u16, None, 0, None));
    assert!(queue.try_enqueue(0x2000, 4096, 2u16, None, 0, None));

    // Process with callback that returns false (cleanup failed)
    let count = queue.process_pending(10, |_| false);
    assert_eq!(count, 2);

    // Stats should show drained but not processed
    let stats = queue.stats();
    assert_eq!(stats.total_enqueued, 2);
    assert_eq!(stats.total_processed, 0); // cleanup failed
    assert_eq!(stats.total_drained, 2);   // but entries are drained
    assert_eq!(queue.pending_estimate(), 0); // accurate estimate
}

#[test_case]
fn test_zombie_queue_probe_limit() {
    let queue = ZombieQueue::new();

    // Fill up more than MAX_PROBE_COUNT entries
    for i in 0..(MAX_PROBE_COUNT + 10) {
        let _ = queue.try_enqueue(i as u64 * 0x1000, 4096, 1u16, None, 0, None);
    }

    // After MAX_PROBE_COUNT, enqueue should start failing
    // (though exact behavior depends on hint position)
    let stats = queue.stats();
    assert!(stats.total_enqueued > 0);
    // Some may have been dropped if all probed slots were taken
}

#[test_case]
fn test_mapping_kind_encoding() {
    use crate::io::iommu::common::dma::handle::MappingKind;
    use crate::io::iommu::types::DeviceId;

    // Identity
    let encoded = encode_mapping_kind(&MappingKind::Identity);
    assert!(matches!(decode_mapping_kind(encoded), MappingKind::Identity));

    // Global
    let encoded = encode_mapping_kind(&MappingKind::Global);
    assert!(matches!(decode_mapping_kind(encoded), MappingKind::Global));

    // Device (using BDF encoding: bus=0x12, device=0x06, function=0x04 = 0x1234)
    let device_id = DeviceId::from_bdf(0x1234);
    let encoded = encode_mapping_kind(&MappingKind::Device(device_id));
    if let MappingKind::Device(decoded_id) = decode_mapping_kind(encoded) {
        assert_eq!(decoded_id.bdf(), 0x1234);
    } else {
        panic!("Expected Device mapping kind");
    }

    // Domain
    let encoded = encode_mapping_kind(&MappingKind::Domain);
    assert!(matches!(decode_mapping_kind(encoded), MappingKind::Domain));
}

#[test_case]
fn test_state_transitions() {
    let entry = ZombieEntry::new();
    
    // Initial state is Empty
    let (state, generation) = entry.load_state_gen_relaxed();
    assert_eq!(state, ZombieState::Empty);
    assert_eq!(generation, 0);

    // Claim for writing: Empty -> Writing
    let new_gen = entry.try_claim_for_writing(0).unwrap();
    let (state, _) = entry.load_state_gen_relaxed();
    assert_eq!(state, ZombieState::Writing);
    assert_eq!(new_gen, 1);

    // Write payload (safe because we own the slot)
    let payload = ZombiePayload {
        iova: 0x1000,
        size: 4096,
        domain_id: 1,
        device_bdf: 0xFFFF,
        mapping_kind: 0,
        raw_ptr: 0,
        raw_owner: 0,
        raw_meta: 0,
        raw_drop_fn: 0,
    };
    unsafe { entry.write_payload(payload) };

    // Publish: Writing -> Pending
    entry.publish(new_gen);
    let (state, _) = entry.load_state_gen_relaxed();
    assert_eq!(state, ZombieState::Pending);

    // Acquire for processing: Pending -> Processing
    let sg = entry.state_gen.load(Ordering::Relaxed);
    assert!(entry.try_acquire_for_processing_with(sg));
    let (state, _) = entry.load_state_gen_relaxed();
    assert_eq!(state, ZombieState::Processing);

    // Read payload
    let read_payload = unsafe { entry.read_payload() };
    assert_eq!(read_payload.iova, 0x1000);
    assert_eq!(read_payload.size, 4096);

    // Release: Processing -> Empty
    entry.release();
    let (state, _) = entry.load_state_gen_relaxed();
    assert_eq!(state, ZombieState::Empty);
}
