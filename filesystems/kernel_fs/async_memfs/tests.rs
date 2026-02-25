use alloc::sync::Arc;
use super::{Bytes, split_path_async};

#[cfg_attr(test, test_case)]
pub fn test_bytes_creation() {
    let data = vec![1, 2, 3, 4, 5];
    let bytes = Bytes::new(data.clone());

    assert_eq!(bytes.len(), 5);
    assert_eq!(bytes.as_slice(), &[1, 2, 3, 4, 5]);
}

#[cfg_attr(test, test_case)]
pub fn test_bytes_clone_shares_data() {
    let data = vec![1, 2, 3, 4, 5];
    let bytes1 = Bytes::new(data);
    let bytes2 = bytes1.clone();

    // 両方とも同じデータを参照
    assert_eq!(bytes1.as_slice(), bytes2.as_slice());
    // 内部のArcがクローンされている（参照カウント増加）
    assert_eq!(Arc::strong_count(&bytes1.inner), 2);
}

#[cfg_attr(test, test_case)]
pub fn test_bytes_empty() {
    let bytes = Bytes::empty();
    assert!(bytes.is_empty());
    assert_eq!(bytes.len(), 0);
}

#[cfg_attr(test, test_case)]
pub fn test_bytes_from_slice() {
    let slice: &[u8] = &[10, 20, 30];
    let bytes: Bytes = slice.into();
    assert_eq!(bytes.as_slice(), &[10, 20, 30]);
}

#[cfg_attr(test, test_case)]
pub fn test_split_path_absolute() {
    let (parent, name) = split_path_async("/home/user/file.txt", "/");
    assert_eq!(parent, "/home/user");
    assert_eq!(name, "file.txt");
}

#[cfg_attr(test, test_case)]
pub fn test_split_path_relative() {
    let (parent, name) = split_path_async("file.txt", "/home/user");
    assert_eq!(parent, "/home/user");
    assert_eq!(name, "file.txt");
}

#[cfg_attr(test, test_case)]
pub fn test_split_path_root() {
    let (parent, name) = split_path_async("/file.txt", "/");
    assert_eq!(parent, "/");
    assert_eq!(name, "file.txt");
}
