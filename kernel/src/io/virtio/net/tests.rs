use super::*;

#[test_case]
fn test_virtio_net_header() {
    let header = VirtioNetHeader::new_tx();
    assert_eq!(header.flags, 0);
    assert_eq!(VirtioNetHeader::SIZE, 12);
}
