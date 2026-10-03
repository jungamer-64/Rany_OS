use super::*;
use crate::mm::phys::frame_allocator::{PhysicalAllocation, alloc_frame};

fn inactive_root() -> (PageTableManager, PhysicalAllocation) {
    let backing = alloc_frame().expect("owned root RAM");
    let physical = PhysAddr::new(backing.as_u64());
    let mapped = crate::mm::virt::mapping::phys_to_virt(backing.start_address());
    // SAFETY: uniquely owned, aligned writable backing for an inactive root.
    unsafe { mapped.as_mut_ptr::<PageTable>().write(PageTable::empty()) };
    // SAFETY: the fixture retains this root's owner throughout all operations.
    let manager = unsafe { PageTableManager::new(physical, crate::heap::physical_memory_offset()) };
    (manager, backing)
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn partial_mapping_reports_prefix_and_finishes_translation_sync() {
    let (mut manager, _root) = inactive_root();
    let start = VirtAddr::new(0x4000);
    let flags = PageFlags::kernel_data();
    unsafe { manager.map_page(VirtAddr::new(0x5000), PhysAddr::new(0x9000), flags) }
        .expect("existing conflict");
    let error = unsafe { manager.map_range(start, PhysAddr::new(0x200000), 8192, flags) }
        .expect_err("second leaf conflicts");
    assert_eq!(error.cause, MapError::AlreadyMapped);
    assert_eq!(error.modified_size, 4096);
    assert_eq!(error.tlb_sync, TlbSyncState::Pending);
    assert_eq!(manager.translate(start).unwrap().as_u64(), 0x200000);
    assert_eq!(
        manager.translate(VirtAddr::new(0x5000)).unwrap().as_u64(),
        0x9000
    );
    let synchronized =
        finish_range_update(start, 8192, Err(error)).expect_err("outcome retains failure");
    assert_eq!(synchronized.modified_size, 4096);
    assert_eq!(synchronized.tlb_sync, TlbSyncState::Complete);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn mixed_leaf_sizes_pat_permissions_and_huge_unmap() {
    let (mut manager, _root) = inactive_root();
    let huge = VirtAddr::new(0x200000);
    unsafe { manager.map_2mb_page(huge, PhysAddr::new(0x400000), PageFlags::write_combining()) }
        .expect("2MiB leaf");
    assert_eq!(
        manager.translate(VirtAddr::new(0x201234)).unwrap().as_u64(),
        0x401234
    );
    let error = unsafe { manager.unmap_range(VirtAddr::new(0x201000), 4096) }
        .expect_err("partial huge boundary");
    assert_eq!(error.modified_size, 0);
    assert!(manager.translate(huge).is_some());
    unsafe {
        manager.update_flags_range(
            huge,
            PageSize::Size2MiB.as_bytes(),
            PageFlags::kernel_code(),
        )
    }
    .expect("whole leaf permissions");
    let (entry, size) = PageTableWalker::new(manager.pml4_phys(), &manager.mapper)
        .walk_mapping(huge)
        .unwrap();
    assert_eq!(size, PageSize::Size2MiB);
    assert_eq!(
        entry.as_u64() & PageFlags::PAT_LARGE,
        0,
        "old PAT encoding is cleared"
    );
    assert_eq!(manager.translate(huge).unwrap().as_u64(), 0x400000);
    let page = unsafe { manager.unmap_page(huge) }.expect("whole huge unmap");
    assert_eq!(page.size, PageSize::Size2MiB);
    assert_eq!(page.physical.as_u64(), 0x400000);
    assert!(manager.translate(huge).is_none());
    if supports_1g_pages() {
        let giant = VirtAddr::new(0x40000000);
        unsafe {
            manager.map_1gb_page(
                giant,
                PhysAddr::new(0x80000000),
                PageFlags::write_combining(),
            )
        }
        .expect("1GiB leaf");
        let page =
            unsafe { manager.unmap_page(VirtAddr::new(0x40001000)) }.expect("actual giant extent");
        assert_eq!(page.physical.as_u64(), 0x80000000);
        assert_eq!(page.virtual_start, giant);
        assert_eq!(page.size, PageSize::Size1GiB);
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn range_rejects_overflow_hole_and_alignment_before_changes() {
    let (mut manager, _root) = inactive_root();
    for (start, size) in [
        (0x1001, 4096),
        (0x1000, 1),
        (0xfffffffffffff000, 8192),
        (0x00007ffffffff000, 8192),
    ] {
        let error =
            unsafe { manager.unmap_range(VirtAddr::new(start), size) }.expect_err("invalid extent");
        assert_eq!(error.modified_size, 0);
        assert_eq!(error.tlb_sync, TlbSyncState::Complete);
    }
    let error = unsafe {
        manager.map_range(
            VirtAddr::new(0x1000),
            PhysAddr::new((1u64 << 52) - 4096),
            8192,
            PageFlags::kernel_data(),
        )
    }
    .expect_err("physical overflow");
    assert_eq!(error.cause, MapError::InvalidAddress);
    assert_eq!(error.modified_size, 0);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn permission_failure_retains_changed_prefix() {
    let (mut manager, _root) = inactive_root();
    let start = VirtAddr::new(0x1000);
    unsafe { manager.map_page(start, PhysAddr::new(0x8000), PageFlags::kernel_data()) }
        .expect("first leaf");
    let error = unsafe { manager.update_flags_range(start, 8192, PageFlags::kernel_code()) }
        .expect_err("second leaf absent");
    assert_eq!(error.cause, MapError::NotMapped);
    assert_eq!(error.modified_size, 4096);
    assert_eq!(error.tlb_sync, TlbSyncState::Pending);
    let entry = PageTableWalker::new(manager.pml4_phys(), &manager.mapper)
        .walk(start)
        .unwrap();
    assert!(!entry.flags().contains(PageFlags::WRITABLE));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn owned_leaf_replacement_preserves_flags_and_rejects_stale_source() {
    let (mut manager, _root) = inactive_root();
    let source = alloc_frame().unwrap();
    let destination = alloc_frame().unwrap();
    let unrelated = alloc_frame().unwrap();
    let address = VirtAddr::new(0x1000);
    let flags = PageFlags::kernel_data()
        .set(PageFlags::GLOBAL)
        .set(PageFlags::PAT);
    // SAFETY: inactive test mapping is exclusively managed with retained owners.
    unsafe { manager.map_page(address, PhysAddr::new(source.as_u64()), flags) }.unwrap();
    // SAFETY: same exclusive root with no payload borrower or DMA access.
    assert_eq!(
        unsafe { manager.replace_owned_page(address, &unrelated, &destination) },
        Err(MapError::MappingChanged)
    );
    assert_eq!(
        manager.translate(address).unwrap().as_u64(),
        source.as_u64()
    );
    // SAFETY: exact source and destination owners retained across publication.
    unsafe { manager.replace_owned_page(address, &source, &destination) }.unwrap();
    assert_eq!(
        manager.translate(address).unwrap().as_u64(),
        destination.as_u64()
    );
    let entry = PageTableWalker::new(manager.pml4_phys(), &manager.mapper)
        .walk(address)
        .unwrap();
    assert_eq!(entry.flags().as_u64(), flags.as_u64());
    // SAFETY: repeated expected-source comparison must reject without a change.
    assert_eq!(
        unsafe { manager.replace_owned_page(address, &source, &unrelated) },
        Err(MapError::MappingChanged)
    );
    // SAFETY: inactive mapping has no CPU/device translations and is fully removed.
    unsafe { manager.unmap_page(address) }.unwrap();
    source.release();
    destination.release();
    unrelated.release();
}
