use super::*;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_virtio_net_header() {
    let header = VirtioNetHeader::new_tx();
    assert_eq!(header.flags, 0);
    assert_eq!(VirtioNetHeader::SIZE, 12);
}
