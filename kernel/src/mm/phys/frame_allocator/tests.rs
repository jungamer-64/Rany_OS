use super::*;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_bitmap_allocator() {
    let mut allocator = BitmapFrameAllocator::new();

    // テスト用のメモリ領域（1MiB）
    let regions = [(PhysAddr::new(0x100000), 0x100000u64)];
    unsafe {
        allocator.init(&regions);
    }

    // フレーム割り当て
    let frame1 = allocator.allocate_4k_frame();
    assert!(frame1.is_some());

    let frame2 = allocator.allocate_4k_frame();
    assert!(frame2.is_some());

    // 異なるフレームが割り当てられていることを確認
    assert_ne!(
        frame1.unwrap().start_address(),
        frame2.unwrap().start_address()
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_alloc_frame_numa_prefers_local_or_fallback() {
    let regions = [(PhysAddr::new(0x100000), 0x200000u64)];
    unsafe {
        init_frame_allocator(&regions);
    }
    reset_frame_local_alloc_metrics();
    let frame = alloc_frame();
    assert!(frame.is_some(), "alloc_frame failed to allocate a frame");
    let (attempts, successes) = get_frame_local_alloc_metrics();
    assert!(successes <= attempts);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_alloc_frame_2m_numa_prefers_local_or_fallback() {
    let regions = [(PhysAddr::new(0x100000), 0x200000u64)];
    unsafe {
        init_frame_allocator(&regions);
    }
    reset_frame2m_local_alloc_metrics();
    let _frame = alloc_frame_2m(); // may be None on small test region
    let (attempts, successes) = get_frame2m_local_alloc_metrics();
    assert!(successes <= attempts);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_alloc_dealloc_contiguous_wrapper() {
    // Try to allocate a single contiguous 4KiB frame; if not available, test is a no-op
    if let Some(start) = alloc_contiguous_frames(1) {
        // Map to virtual address using HHDM offset
        let virt = crate::memory::physical_memory_offset() + start.as_u64();
        let ptr = virt as *mut u8;
        unsafe {
            core::ptr::write_volatile(ptr, 0xA5u8);
            let v = core::ptr::read_volatile(ptr);
            assert_eq!(v, 0xA5u8);
        }
        dealloc_contiguous_frames(start, 1);
    }
}
