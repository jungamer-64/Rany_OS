use super::*;
use crate::mm::virt::higher_half::{VirtAddr, global_translate};

pub(crate) fn owned_physical_storage_smoke() -> bool {
    let mut queue = InvalidationQueue::new(9).expect("owned invalidation queue RAM");
    let queue_bytes = queue.size * core::mem::size_of::<InvalidationQueueEntry>();
    // LOOP_PROOF: mode=bounded; reason=The queue owns exactly queue_bytes / 4096 contiguous pages, bounded by its admitted descriptor encoding.;
    for offset in (0..queue_bytes).step_by(4096) {
        let translated = global_translate(VirtAddr::new((queue.queue_virt + offset) as u64))
            .expect("CPU translation of retained queue storage");
        assert_eq!(translated.as_u64(), queue.base_address() + offset as u64);
    }
    assert_eq!(queue.base_address() & 4095, 0);
    let status_physical = global_translate(VirtAddr::new(queue.status_virt as u64))
        .expect("CPU translation of retained status storage")
        .as_u64();
    assert_eq!(status_physical & 4095, 0);
    assert!(
        status_physical < queue.base_address()
            || status_physical >= queue.base_address() + queue_bytes as u64
    );
    // SAFETY: both unique PMM owners remain in this unpublished local queue.
    // No IQA register, hardware consumer or other CPU received its storage.
    let entries = unsafe {
        core::slice::from_raw_parts(
            queue.queue_virt as *const InvalidationQueueEntry,
            queue.size,
        )
    };
    assert!(entries.iter().all(|entry| entry.lo == 0 && entry.hi == 0));
    let (wait, sequence) = queue.wait_entry();
    assert_eq!(wait.hi, status_physical);
    let (submitted, submitted_sequence) = queue.wait_entry();
    assert_eq!(submitted.hi, status_physical);
    assert_eq!(submitted_sequence, sequence + 1);
    queue.submit(submitted);
    assert_eq!(queue.tail(), 1);
    // SAFETY: the synchronous submit finished writing the retained first
    // descriptor, and this queue was never published to a hardware consumer.
    assert_eq!(
        unsafe { (*(queue.queue_virt as *const InvalidationQueueEntry)).hi },
        status_physical
    );
    // No controller ever acquired this queue, so Drop can return both backing
    // owners after the final CPU observation without device invalidation.
    drop(queue);
    true
}
