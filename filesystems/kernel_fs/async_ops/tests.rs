use super::*;

#[cfg_attr(test, test_case)]
pub fn test_async_file_seek() {
    let attr = FileAttr {
        size: 1000,
        ..Default::default()
    };
    let file = AsyncFile::new(1, attr, true, true);

    // Start
    assert_eq!(file.seek(SeekFrom::Start(100)).unwrap(), 100);
    assert_eq!(file.position(), 100);

    // Current
    assert_eq!(file.seek(SeekFrom::Current(50)).unwrap(), 150);
    assert_eq!(file.seek(SeekFrom::Current(-30)).unwrap(), 120);

    // End
    assert_eq!(file.seek(SeekFrom::End(0)).unwrap(), 1000);
    assert_eq!(file.seek(SeekFrom::End(-100)).unwrap(), 900);
}

#[cfg_attr(test, test_case)]
pub fn test_direct_block_handle() {
    let handle = DirectBlockHandle::new(0, 0, 1000, 512);
    assert_eq!(handle.qemu_test_block_size(), 512);
    assert_eq!(handle.qemu_test_block_count(), 1000);
}
