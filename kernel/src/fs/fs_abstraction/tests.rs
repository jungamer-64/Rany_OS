use super::*;

#[test_case]
fn test_file_mode() {
    let mode = FileMode::DEFAULT_FILE;
    assert!(mode.owner_read());
    assert!(mode.owner_write());
    assert!(!mode.owner_execute());
}

#[test_case]
fn test_open_flags() {
    let flags = OpenFlags(OpenFlags::O_RDWR | OpenFlags::O_CREAT);
    assert!(flags.can_read());
    assert!(flags.can_write());
    assert!(flags.create());
}
