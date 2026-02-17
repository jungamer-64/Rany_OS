use super::*;

#[test_case]
fn test_alloc_page_table_prefers_numa_local_or_buddy() {
    // Verify alloc_page_table succeeds regardless of NUMA availability
    let manager = unsafe { PageTableManager::from_current_cr3(0) };
    let res = manager.alloc_page_table();
    assert!(res.is_ok());
}

#[test_case]
fn test_global_map_page_poisoned_returns_hardware_error() {
    // Poison the PAGE_TABLE_MANAGER lock
    {
        let _guard = PAGE_TABLE_MANAGER.lock().unwrap();
        crate::sync::set_panicking(true);
    }
    crate::sync::set_panicking(false);

    let res = unsafe {
        global_map_page(
            VirtAddr::new(0x1000),
            PhysAddr::new(0x2000),
            PageFlags::new(PageFlags::PRESENT),
        )
    };

    assert_eq!(res, Err(MapError::HardwareError));
}

#[test_case]
fn test_global_unmap_page_poisoned_returns_hardware_error() {
    // Poison the PAGE_TABLE_MANAGER lock
    {
        let _guard = PAGE_TABLE_MANAGER.lock().unwrap();
        crate::sync::set_panicking(true);
    }
    crate::sync::set_panicking(false);

    let res = unsafe { global_unmap_page(VirtAddr::new(0x1000)) };
    assert_eq!(res, Err(MapError::HardwareError));
}
