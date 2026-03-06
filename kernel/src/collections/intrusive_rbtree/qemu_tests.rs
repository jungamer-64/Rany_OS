use super::*;
use alloc::boxed::Box;
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
        let offset = crate::offset_of!(TestEntry, link);
        unsafe { (link as *mut u8).sub(offset) as *mut Self::Entry }
    }
}

pub fn rbtree_empty_smoke() -> bool {
    let tree: RBTree<TestAdapter> = RBTree::new();
    tree.is_empty() && tree.len() == 0 && tree.first().is_none() && tree.last().is_none()
}

pub fn rbtree_insert_find_smoke() -> bool {
    let mut tree: RBTree<TestAdapter> = RBTree::new();
    let mut entry = Box::new(TestEntry::new(42, 100));

    unsafe {
        if !tree.insert(entry.as_mut()) {
            return false;
        }
    }

    if tree.len() != 1 {
        return false;
    }
    if tree.is_empty() {
        return false;
    }

    let found = tree.find(&42);
    if found.is_none() {
        return false;
    }
    let ok = unsafe { (*found.unwrap()).value == 100 };
    if !ok {
        return false;
    }

    if tree.find(&999).is_some() {
        return false;
    }

    unsafe {
        tree.remove(entry.as_mut());
    }
    true
}

pub fn rbtree_multiple_inserts_smoke() -> bool {
    let mut tree: RBTree<TestAdapter> = RBTree::new();
    let mut entries: Vec<Box<TestEntry>> = (0..10)
        .map(|i| Box::new(TestEntry::new(i * 10, i as u32)))
        .collect();

    for entry in entries.iter_mut() {
        unsafe {
            if !tree.insert(entry.as_mut()) {
                return false;
            }
        }
    }

    if tree.len() != 10 {
        return false;
    }

    for i in 0..10u64 {
        if tree.find(&(i * 10)).is_none() {
            return false;
        }
    }

    for entry in entries.iter_mut() {
        unsafe {
            tree.remove(entry.as_mut());
        }
    }
    true
}

pub fn rbtree_ordering_smoke() -> bool {
    let mut tree: RBTree<TestAdapter> = RBTree::new();
    let keys = [50u64, 30, 70, 20, 40, 60, 80];
    let mut entries: Vec<Box<TestEntry>> = keys
        .iter()
        .map(|&k| Box::new(TestEntry::new(k, k as u32)))
        .collect();

    for entry in entries.iter_mut() {
        unsafe {
            tree.insert(entry.as_mut());
        }
    }

    let first_ok = unsafe { (*tree.first().unwrap()).key == 20 };
    let last_ok = unsafe { (*tree.last().unwrap()).key == 80 };

    let collected: Vec<u64> = tree.iter().map(|e| unsafe { (*e).key }).collect();
    let order_ok = collected == alloc::vec![20, 30, 40, 50, 60, 70, 80];

    for entry in entries.iter_mut() {
        unsafe {
            tree.remove(entry.as_mut());
        }
    }

    first_ok && last_ok && order_ok
}

pub fn rbtree_duplicate_key_smoke() -> bool {
    let mut tree: RBTree<TestAdapter> = RBTree::new();
    let mut entry1 = Box::new(TestEntry::new(42, 100));
    let mut entry2 = Box::new(TestEntry::new(42, 200));

    unsafe {
        if !tree.insert(entry1.as_mut()) {
            return false;
        }
        if tree.insert(entry2.as_mut()) {
            return false;
        } // should reject
    }

    let ok = tree.len() == 1;

    unsafe {
        tree.remove(entry1.as_mut());
    }
    ok
}

pub fn rbtree_remove_smoke() -> bool {
    let mut tree: RBTree<TestAdapter> = RBTree::new();
    let mut entries: Vec<Box<TestEntry>> = (0..5)
        .map(|i| Box::new(TestEntry::new(i, i as u32)))
        .collect();

    for entry in entries.iter_mut() {
        unsafe {
            tree.insert(entry.as_mut());
        }
    }

    if tree.len() != 5 {
        return false;
    }

    unsafe {
        tree.remove(entries[2].as_mut());
    }
    if tree.len() != 4 {
        return false;
    }
    if tree.find(&2).is_some() {
        return false;
    }

    unsafe {
        tree.remove(entries[0].as_mut());
    }
    if tree.len() != 3 {
        return false;
    }

    unsafe {
        tree.remove(entries[4].as_mut());
    }
    if tree.len() != 2 {
        return false;
    }

    tree.find(&1).is_some() && tree.find(&3).is_some()
}
