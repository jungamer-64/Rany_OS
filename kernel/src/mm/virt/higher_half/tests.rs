use super::*;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn virtual_range_validation_preserves_canonical_and_alignment_boundaries() {
    assert_eq!(validate_range(VirtAddr::new(0x1000), 0), Ok(0x1000));
    assert_eq!(validate_range(VirtAddr::new(0x1000), 4096), Ok(0x2000));
    for (start, size, cause) in [
        (0x1001, 4096, MapError::AlignmentError),
        (0x1000, 1, MapError::AlignmentError),
        (0xfffffffffffff000, 8192, MapError::InvalidAddress),
        (0x00007ffffffff000, 8192, MapError::InvalidAddress),
    ] {
        assert_eq!(validate_range(VirtAddr::new(start), size), Err(cause));
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn physical_range_validation_accepts_the_last_complete_page() {
    let last_page = PhysAddr::new((1u64 << 52) - 4096);
    assert_eq!(validate_physical_range(last_page, 4096), Ok(()));
    assert_eq!(
        validate_physical_range(last_page, 8192),
        Err(MapError::InvalidAddress)
    );
    assert_eq!(
        validate_physical_range(PhysAddr::new(0x1001), 4096),
        Err(MapError::AlignmentError)
    );
}
