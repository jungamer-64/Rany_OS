/// Snapshot of one slab size class.
#[derive(Debug, Clone)]
pub struct SlabStats {
    pub object_size: usize,
    pub free_count: usize,
    pub page_count: usize,
    pub alloc_count: usize,
    pub dealloc_count: usize,
    pub refill_pages: usize,
    pub partial_page_count: usize,
    pub empty_page_count: usize,
    pub full_page_count: usize,
    pub partial_alloc_count: usize,
    pub empty_alloc_count: usize,
}
