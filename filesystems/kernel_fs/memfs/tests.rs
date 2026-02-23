use super::*;
use alloc::vec;

#[cfg_attr(test, test_case)]
pub fn test_paged_content_in_inode() {
    let inode = MemoryInode::new_file(1, "test.txt", FileMode::DEFAULT_FILE);

    // 書き込み
    inode.write(0, b"Hello, World!").unwrap();

    // 読み取り
    let mut buf = [0u8; 13];
    let n = inode.read(0, &mut buf).unwrap();
    assert_eq!(n, 13);
    assert_eq!(&buf, b"Hello, World!");
}

#[cfg_attr(test, test_case)]
pub fn test_large_file_paging() {
    use super::super::page::PAGE_SIZE;

    let inode = MemoryInode::new_file(1, "large.bin", FileMode::DEFAULT_FILE);

    // 複数ページにまたがるデータ
    let data = vec![0xABu8; PAGE_SIZE * 3 + 100];
    inode.write(0, &data).unwrap();

    // サイズ確認
    let attr = inode.getattr().unwrap();
    assert_eq!(attr.size, data.len() as u64);

    // 読み取り確認
    let mut buf = vec![0u8; data.len()];
    inode.read(0, &mut buf).unwrap();
    assert_eq!(buf, data);
}

#[cfg_attr(test, test_case)]
pub fn test_cow_copy() {
    let src = MemoryInode::new_file(1, "src.txt", FileMode::DEFAULT_FILE);
    src.write(0, b"Original content").unwrap();

    let dst = MemoryInode::new_file(2, "dst.txt", FileMode::DEFAULT_FILE);

    // CoWコピー
    copy_file_cow(&src, &dst);

    // 内容が一致
    let mut buf = [0u8; 16];
    dst.read(0, &mut buf).unwrap();
    assert_eq!(&buf, b"Original content");

    // ソースを変更してもdstに影響なし（CoW）
    src.write(0, b"Modified content").unwrap();

    let mut buf2 = [0u8; 16];
    dst.read(0, &mut buf2).unwrap();
    assert_eq!(&buf2, b"Original content");
}

#[cfg_attr(test, test_case)]
pub fn test_sparse_file() {
    let inode = MemoryInode::new_file(1, "sparse.bin", FileMode::DEFAULT_FILE);

    // オフセット1MBに書き込み（中間領域はスパース）
    let offset = 1024 * 1024;
    inode.write(offset, b"sparse data").unwrap();

    // 中間領域はゼロ
    let mut buf = [0xFFu8; 10];
    inode.read(1000, &mut buf).unwrap();
    assert_eq!(&buf, &[0u8; 10]);

    // 書き込み領域は正常
    let mut buf2 = [0u8; 11];
    inode.read(offset, &mut buf2).unwrap();
    assert_eq!(&buf2, b"sparse data");
}

#[cfg_attr(test, test_case)]
pub fn test_truncate_releases_pages() {
    use super::super::page::PAGE_SIZE;

    let inode = MemoryInode::new_file(1, "truncate.bin", FileMode::DEFAULT_FILE);

    // 3ページ分書き込み
    let data = vec![0xCDu8; PAGE_SIZE * 3];
    inode.write(0, &data).unwrap();

    // 1ページに切り詰め
    inode.truncate(PAGE_SIZE as u64).unwrap();

    let attr = inode.getattr().unwrap();
    assert_eq!(attr.size, PAGE_SIZE as u64);
}

#[cfg_attr(test, test_case)]
pub fn test_get_page_zero_copy() {
    let inode = MemoryInode::new_file(1, "zero_copy.bin", FileMode::DEFAULT_FILE);
    inode.write(0, b"Page data for test").unwrap();

    // ページ直接取得
    let page = inode.get_page(0);
    assert!(page.is_some());
    assert_eq!(&page.unwrap()[..18], b"Page data for test");

    // 存在しないページ
    let no_page = inode.get_page(100);
    assert!(no_page.is_none());
}
