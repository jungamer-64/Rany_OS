use super::*;
use alloc::vec::Vec;
use alloc::vec;

#[test_case]
fn test_empty() {
    let xa: XArray<u32> = XArray::new();
    assert!(xa.is_empty());
    assert_eq!(xa.len(), 0);
    assert_eq!(xa.load(0), None);
    assert_eq!(xa.load(100), None);
}

#[test_case]
fn test_store_load() {
    let mut xa: XArray<u32> = XArray::new();
    
    assert_eq!(xa.store(0, 42), None);
    assert_eq!(xa.len(), 1);
    assert_eq!(xa.load(0), Some(&42));
    
    // 上書き
    assert_eq!(xa.store(0, 100), Some(42));
    assert_eq!(xa.len(), 1);
    assert_eq!(xa.load(0), Some(&100));
}

#[test_case]
fn test_sparse() {
    let mut xa: XArray<u32> = XArray::new();
    
    xa.store(0, 1);
    xa.store(100, 2);
    xa.store(10000, 3);
    
    assert_eq!(xa.len(), 3);
    assert_eq!(xa.load(0), Some(&1));
    assert_eq!(xa.load(50), None);  // スパース
    assert_eq!(xa.load(100), Some(&2));
    assert_eq!(xa.load(5000), None);  // スパース
    assert_eq!(xa.load(10000), Some(&3));
}

#[test_case]
fn test_erase() {
    let mut xa: XArray<u32> = XArray::new();
    
    xa.store(10, 42);
    assert_eq!(xa.len(), 1);
    
    assert_eq!(xa.erase(10), Some(42));
    assert_eq!(xa.len(), 0);
    assert_eq!(xa.load(10), None);
    
    // 存在しないエントリの削除
    assert_eq!(xa.erase(10), None);
}

#[test_case]
fn test_large_indices() {
    let mut xa: XArray<u32> = XArray::new();
    
    let indices = [0, 63, 64, 4095, 4096, 262143, 262144];
    
    for (i, &idx) in indices.iter().enumerate() {
        xa.store(idx, i as u32);
    }
    
    assert_eq!(xa.len(), indices.len());
    
    for (i, &idx) in indices.iter().enumerate() {
        assert_eq!(xa.load(idx), Some(&(i as u32)), "Failed at index {}", idx);
    }
}

#[test_case]
fn test_iter() {
    let mut xa: XArray<u32> = XArray::new();
    
    xa.store(5, 50);
    xa.store(10, 100);
    xa.store(15, 150);
    
    let collected: Vec<(usize, u32)> = xa.iter().map(|(i, v)| (i, *v)).collect();
    assert_eq!(collected, vec![(5, 50), (10, 100), (15, 150)]);
}

#[test_case]
fn test_load_mut() {
    let mut xa: XArray<u32> = XArray::new();
    
    xa.store(0, 100);
    
    if let Some(v) = xa.load_mut(0) {
        *v = 200;
    }
    
    assert_eq!(xa.load(0), Some(&200));
}

#[test_case]
fn test_marks() {
    let mut xa: XArray<u32> = XArray::new();
    
    xa.store(0, 100);
    xa.store(1, 200);
    
    // 初期状態: マークなし
    assert!(!xa.has_mark(0, super::XA_MARK_0));
    assert!(!xa.has_mark(1, super::XA_MARK_1));
    
    // マーク設定
    assert!(xa.set_mark(0, super::XA_MARK_0));
    assert!(xa.set_mark(1, super::XA_MARK_1));
    
    assert!(xa.has_mark(0, super::XA_MARK_0));
    assert!(xa.has_mark(1, super::XA_MARK_1));
    assert!(!xa.has_mark(0, super::XA_MARK_1));
    
    // マーククリア
    assert!(xa.clear_mark(0, super::XA_MARK_0));
    assert!(!xa.has_mark(0, super::XA_MARK_0));
}
