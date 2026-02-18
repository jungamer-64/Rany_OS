use super::*;

#[test_case]
fn test_protection_conversion() {
    let prot = Protection::READ_WRITE;
    let flags = prot.to_page_flags();
    assert!(flags.bits() & PageFlags::PRESENT != 0);
    assert!(flags.bits() & PageFlags::WRITABLE != 0);
}

#[test_case]
fn test_region_contains() {
    let region = MemoryRegion::new(
        VirtAddr::new(0x1000),
        VirtAddr::new(0x2000),
        RegionType::Data,
        Protection::READ_WRITE,
    );
    
    assert!(region.contains(VirtAddr::new(0x1000)));
    assert!(region.contains(VirtAddr::new(0x1500)));
    assert!(!region.contains(VirtAddr::new(0x2000)));
    assert!(!region.contains(VirtAddr::new(0x0FFF)));
}

#[test_case]
fn test_clone_region_with_range_adjusts_file_info() {
    let mut base = MemoryRegion::new(
        VirtAddr::new(0x1000),
        VirtAddr::new(0x9000),
        RegionType::FileBacked,
        Protection::READ,
    );
    base.cow = true;
    base.file_info = Some(FileBackingInfo {
        inode: 42,
        offset: 0x2000,
        size: 0x8000,
    });

    let sub_start = VirtAddr::new(0x3000);
    let sub_end = VirtAddr::new(0x5000);
    let sub = clone_region_with_range(&base, sub_start, sub_end, Protection::READ_WRITE);

    assert_eq!(sub.start, sub_start);
    assert_eq!(sub.end, sub_end);
    assert_eq!(sub.region_type, base.region_type);
    assert!(sub.cow);
    assert_eq!(sub.protection, Protection::READ_WRITE);

    let info = sub.file_info.expect("file info");
    assert_eq!(info.inode, 42);
    assert_eq!(info.offset, 0x2000 + (0x3000 - 0x1000));
    assert_eq!(info.size, 0x2000);
}
