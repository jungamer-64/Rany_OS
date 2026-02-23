use super::*;

#[cfg_attr(test, test_case)]
pub fn test_superblock_block_size() {
    // block_size = 1024 << 0 = 1024
    let mut sb: Superblock = unsafe { core::mem::zeroed() };
    sb.log_block_size = 0;
    assert_eq!(sb.block_size(), 1024);

    // block_size = 1024 << 2 = 4096
    sb.log_block_size = 2;
    assert_eq!(sb.block_size(), 4096);
}

#[cfg_attr(test, test_case)]
pub fn test_inode_file_type() {
    let mut inode: Ext2Inode = unsafe { core::mem::zeroed() };

    inode.mode = S_IFREG;
    assert_eq!(inode.file_type(), FileType::Regular);

    inode.mode = S_IFDIR;
    assert_eq!(inode.file_type(), FileType::Directory);

    inode.mode = S_IFLNK;
    assert_eq!(inode.file_type(), FileType::Symlink);
}
