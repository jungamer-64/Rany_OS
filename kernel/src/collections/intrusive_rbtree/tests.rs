use super::*;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

struct TestEntry {
    link: RBLink,
    key: u64,
    value: u32,
}

impl TestEntry {
    fn new(key: u64, value: u32) -> Self {
        Self {
            link: RBLink::new(),
            key,
            value,
        }
    }
}

struct TestAdapter;

unsafe impl KeyAdapter for TestAdapter {
    type Key = u64;
    type Entry = TestEntry;

    fn get_key(entry: &Self::Entry) -> &Self::Key {
        &entry.key
    }

    fn get_link(entry: &Self::Entry) -> &RBLink {
        &entry.link
    }

    fn get_link_mut(entry: &mut Self::Entry) -> &mut RBLink {
        &mut entry.link
    }

    unsafe fn entry_from_link(link: *mut RBLink) -> *mut Self::Entry {
        let offset = offset_of!(TestEntry, link);
        (link as *mut u8).sub(offset) as *mut Self::Entry
    }
}

#[test_case]
fn test_empty_tree() {
    let tree: RBTree<TestAdapter> = RBTree::new();
    assert!(tree.is_empty());
    assert_eq!(tree.len(), 0);
    assert!(tree.first().is_none());
    assert!(tree.last().is_none());
}

#[test_case]
fn test_insert_find() {
    let mut tree: RBTree<TestAdapter> = RBTree::new();
    let mut entry = Box::new(TestEntry::new(42, 100));

    unsafe {
        assert!(tree.insert(entry.as_mut()));
    }

    assert_eq!(tree.len(), 1);
    assert!(!tree.is_empty());

    // 検索
    let found = tree.find(&42);
    assert!(found.is_some());
    unsafe {
        assert_eq!((*found.unwrap()).value, 100);
    }

    // 存在しないキー
    assert!(tree.find(&999).is_none());

    // クリーンアップ
    unsafe {
        tree.remove(entry.as_mut());
    }
}

#[test_case]
fn test_multiple_inserts() {
    let mut tree: RBTree<TestAdapter> = RBTree::new();
    let mut entries: Vec<Box<TestEntry>> = (0..10)
        .map(|i| Box::new(TestEntry::new(i * 10, i as u32)))
        .collect();

    // 挿入
    for entry in entries.iter_mut() {
        unsafe {
            assert!(tree.insert(entry.as_mut()));
        }
    }

    assert_eq!(tree.len(), 10);

    // 全て検索可能
    for i in 0..10u64 {
        assert!(tree.find(&(i * 10)).is_some());
    }

    // クリーンアップ
    for entry in entries.iter_mut() {
        unsafe {
            tree.remove(entry.as_mut());
        }
    }
}

#[test_case]
fn test_ordering() {
    let mut tree: RBTree<TestAdapter> = RBTree::new();
    let keys = [50, 30, 70, 20, 40, 60, 80];
    let mut entries: Vec<Box<TestEntry>> = keys
        .iter()
        .map(|&k| Box::new(TestEntry::new(k, k as u32)))
        .collect();

    for entry in entries.iter_mut() {
        unsafe {
            tree.insert(entry.as_mut());
        }
    }

    // first は最小
    unsafe {
        assert_eq!((*tree.first().unwrap()).key, 20);
    }

    // last は最大
    unsafe {
        assert_eq!((*tree.last().unwrap()).key, 80);
    }

    // イテレータは昇順（ポインタを返すので unsafe でデリファレンス）
    let collected: Vec<u64> = tree.iter().map(|e| unsafe { (*e).key }).collect();
    assert_eq!(collected, vec![20, 30, 40, 50, 60, 70, 80]);

    // クリーンアップ
    for entry in entries.iter_mut() {
        unsafe {
            tree.remove(entry.as_mut());
        }
    }
}

#[test_case]
fn test_duplicate_key() {
    let mut tree: RBTree<TestAdapter> = RBTree::new();
    let mut entry1 = Box::new(TestEntry::new(42, 100));
    let mut entry2 = Box::new(TestEntry::new(42, 200));

    unsafe {
        assert!(tree.insert(entry1.as_mut()));
        // 重複は拒否
        assert!(!tree.insert(entry2.as_mut()));
    }

    assert_eq!(tree.len(), 1);

    // クリーンアップ
    unsafe {
        tree.remove(entry1.as_mut());
    }
}

#[test_case]
fn test_remove() {
    let mut tree: RBTree<TestAdapter> = RBTree::new();
    let mut entries: Vec<Box<TestEntry>> = (0..5)
        .map(|i| Box::new(TestEntry::new(i, i as u32)))
        .collect();

    for entry in entries.iter_mut() {
        unsafe {
            tree.insert(entry.as_mut());
        }
    }

    assert_eq!(tree.len(), 5);

    // 中間を削除
    unsafe {
        tree.remove(entries[2].as_mut());
    }
    assert_eq!(tree.len(), 4);
    assert!(tree.find(&2).is_none());

    // 最初を削除
    unsafe {
        tree.remove(entries[0].as_mut());
    }
    assert_eq!(tree.len(), 3);

    // 最後を削除
    unsafe {
        tree.remove(entries[4].as_mut());
    }
    assert_eq!(tree.len(), 2);

    // 残りを確認
    assert!(tree.find(&1).is_some());
    assert!(tree.find(&3).is_some());

    // クリーンアップ
    unsafe {
        tree.remove(entries[1].as_mut());
        tree.remove(entries[3].as_mut());
    }
}
