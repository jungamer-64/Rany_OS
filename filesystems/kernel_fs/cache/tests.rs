use super::*;

#[cfg_attr(test, test_case)]
pub fn test_cached_page() {
    let page = CachedPage::new_empty(0);
    assert_eq!(page.page_num(), 0);
    assert_eq!(page.state(), PageState::Clean);
    assert!(!page.is_dirty());

    page.mark_dirty();
    assert!(page.is_dirty());
    assert_eq!(page.state(), PageState::Dirty);
}

#[cfg_attr(test, test_case)]
pub fn test_page_pin() {
    let page = CachedPage::new_empty(0);
    assert!(!page.is_pinned());

    page.pin();
    assert!(page.is_pinned());

    page.unpin();
    assert!(!page.is_pinned());
}

#[cfg_attr(test, test_case)]
pub fn test_page_cache() {
    let cache = PageCache::new(64 * 1024);

    // Insert a page
    let data = alloc::vec![0x42u8; PAGE_SIZE];
    cache.insert(1, 0, data, PAGE_SIZE as u64);

    // Read from cache
    let mut buf = [0u8; 10];
    let result = cache.read(1, 0, &mut buf, PAGE_SIZE as u64);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), 10);
    assert_eq!(buf, [0x42u8; 10]);

    // Check stats
    let stats = cache.stats();
    assert_eq!(stats.hits, 1);
    assert_eq!(stats.pages, 1);
}

#[cfg_attr(test, test_case)]
pub fn test_sync_page() {
    let cache = PageCache::new(64 * 1024);

    // Insert and dirty a page
    let data = alloc::vec![0x55u8; PAGE_SIZE];
    cache.insert(2, 1, data, PAGE_SIZE as u64);
    assert!(cache.mark_dirty(2, 1));

    // Writer that records the offset and first byte
    let mut recorded_offset = 0u64;
    let mut recorded_first = 0u8;

    let res = cache.sync_page(2, 1, |offset, data| {
        recorded_offset = offset;
        recorded_first = data[0];
        Ok(())
    }).expect("sync_page failed");

    assert!(res);
    assert_eq!(recorded_offset, 1 * PAGE_SIZE as u64);
    assert_eq!(recorded_first, 0x55u8);

    // Page should be clean now
    let files = cache.files.read();
    if let Some(file_cache) = files.get(&2) {
        if let Some(page) = file_cache.get_page(1) {
            assert!(!page.is_dirty());
        } else {
            panic!("page not found");
        }
    } else {
        panic!("file cache not found");
    }
}
