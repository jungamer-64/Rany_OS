use super::*;

#[test_case]
fn test_anonymous_region_map() {
    let addr = map_anonymous_region(
        None,
        MappingSize::new(4096),
        Protection::READ_WRITE,
        MappingFlags::anonymous_private(),
    )
    .unwrap();

    assert!(addr.is_page_aligned());

    unmap_region(addr, MappingSize::new(4096)).unwrap();
}

#[test_case]
fn test_mapping_read_write() {
    let addr = map_anonymous_region(
        None,
        MappingSize::new(8192),
        Protection::READ_WRITE,
        MappingFlags::anonymous_private(),
    )
    .unwrap();

    let mapping = MAPPING_MANAGER.get_mapping(addr).unwrap();
    {
        let mut m = mapping.write();
        m.write(0, b"Hello, mmap!").unwrap();
    }

    {
        let m = mapping.read();
        let mut buf = [0u8; 12];
        m.read(0, &mut buf).unwrap();
        assert_eq!(&buf, b"Hello, mmap!");
    }
}
