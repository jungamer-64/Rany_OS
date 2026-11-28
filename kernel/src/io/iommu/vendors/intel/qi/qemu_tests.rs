use super::*;
use crate::mm::virt::higher_half::{VirtAddr, global_translate};

pub(crate) fn owned_physical_storage_smoke() -> bool {
    check_queue(DescriptorWidth::Bits128, 16, 0);
    check_queue(DescriptorWidth::Bits256, 32, 0x800);
    true
}

fn check_queue(width: DescriptorWidth, stride: u64, iqa_width: u64) {
    let mut queue = InvalidationQueue::new(width, 1).expect("owned invalidation queue RAM");
    let queue_bytes = 8192;
    let base = queue.queue_phys;
    assert_eq!(queue.configuration_register(), base | iqa_width | 1);
    for offset in [0, 4096] {
        let translated = global_translate(VirtAddr::new((queue.queue_virt + offset) as u64))
            .expect("CPU translation of retained queue storage");
        assert_eq!(translated.as_u64(), base + offset as u64);
    }
    assert_eq!(base & 4095, 0);
    let status_physical = global_translate(VirtAddr::new(queue.status_virt as u64))
        .expect("CPU translation of retained status storage")
        .as_u64();
    assert_eq!(status_physical & 4095, 0);
    assert!(status_physical < base || status_physical >= base + queue_bytes);
    assert!(matches!(
        queue.submit_wait(WaitNotification::Poll, |_, _| Err(
            IommuError::HardwareError
        )),
        Err(IommuError::HardwareError)
    ));
    let publish = |queue: &mut InvalidationQueue, entry| {
        queue.submit(entry);
        Ok(())
    };
    let first = queue.submit_wait(WaitNotification::Poll, publish).unwrap();
    let second = queue
        .submit_wait(WaitNotification::Interrupt, publish)
        .unwrap();
    assert_eq!(queue.tail_offset(), stride * 2);
    assert!(queue.refresh_head(stride - 1).is_err());
    queue.refresh_head(stride).expect("aligned hardware head");
    assert_eq!(queue.cached_head_offset(), stride);
    // SAFETY: this unpublished queue uniquely owns the entire initialized
    // ring. It remains retained while these integer words are observed.
    let words = unsafe {
        core::slice::from_raw_parts(queue.queue_virt as *const u64, queue_bytes as usize / 8)
    };
    let second_index = stride as usize / 8;
    assert_eq!(words[0..2], [0x1_0000_0065, status_physical]);
    assert_eq!(
        words[second_index..second_index + 2],
        [0x2_0000_0075, status_physical]
    );
    assert!(words[2..second_index].iter().all(|&word| word == 0));
    assert!(words[second_index + 2..].iter().all(|&word| word == 0));
    // SAFETY: the unpublished queue retains its status word and there is no
    // hardware writer. A later fenced wait certifies the earlier batch too.
    unsafe {
        assert!(!first.is_complete());
        assert!(!second.is_complete());
        core::ptr::write_volatile(queue.status_virt as *mut u32, 2);
        assert!(first.is_complete());
        assert!(second.is_complete());
    }
}
