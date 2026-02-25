#![allow(clippy::wildcard_imports)]
use super::*;

#[cfg_attr(test, test_case)]
pub fn test_file_mode() {
    let mode = FileMode::DEFAULT_FILE;
    assert!(mode.owner_read());
    assert!(mode.owner_write());
    assert!(!mode.owner_execute());
}

#[cfg_attr(test, test_case)]
pub fn test_open_flags() {
    let flags = OpenFlags(OpenFlags::O_RDWR | OpenFlags::O_CREAT);
    assert!(flags.can_read());
    assert!(flags.can_write());
    assert!(flags.create());
}
