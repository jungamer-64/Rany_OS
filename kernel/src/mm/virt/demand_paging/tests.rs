use super::*;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_prot_flags() {
    let prot = ProtFlags::READ | ProtFlags::WRITE;
    assert!(prot.readable());
    assert!(prot.writable());
    assert!(!prot.executable());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_vm_region_contains() {
    let region = VmRegion::new_anonymous(
        VirtAddr::new(0x1000),
        VirtAddr::new(0x5000),
        ProtFlags::READ | ProtFlags::WRITE,
    );

    assert!(region.contains(VirtAddr::new(0x1000)));
    assert!(region.contains(VirtAddr::new(0x3000)));
    assert!(!region.contains(VirtAddr::new(0x5000)));
    assert!(!region.contains(VirtAddr::new(0x0FFF)));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_config_default() {
    let config = DemandPagingConfig::default();
    assert!(config.use_zero_page_cow);
    assert_eq!(config.prefault_pages, 4);
}
