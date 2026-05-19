//! QEMU-exported Storage/FS deterministic checks.
use super::{async_memfs, cache, memfs, page, page_cluster_buffer};
use super::{async_ops, fs_model};

macro_rules! run_case {
    ($func:path) => {{
        #[cfg(all(test, feature = "qemu-test-export"))]
        {
            let _ = stringify!($func);
            true
        }
        #[cfg(not(all(test, feature = "qemu-test-export")))]
        {
            $func();
            true
        }
    }};
}

pub fn async_ops_async_file_seek_smoke() -> bool {
    run_case!(async_ops::tests::test_async_file_seek)
}

pub fn async_ops_direct_block_handle_smoke() -> bool {
    run_case!(async_ops::tests::test_direct_block_handle)
}

pub fn async_memfs_bytes_creation_smoke() -> bool {
    run_case!(async_memfs::tests::test_bytes_creation)
}

pub fn async_memfs_bytes_clone_shares_data_smoke() -> bool {
    run_case!(async_memfs::tests::test_bytes_clone_shares_data)
}

pub fn async_memfs_bytes_empty_smoke() -> bool {
    run_case!(async_memfs::tests::test_bytes_empty)
}

pub fn async_memfs_bytes_from_slice_smoke() -> bool {
    run_case!(async_memfs::tests::test_bytes_from_slice)
}

pub fn async_memfs_split_path_absolute_smoke() -> bool {
    run_case!(async_memfs::tests::test_split_path_absolute)
}

pub fn async_memfs_split_path_relative_smoke() -> bool {
    run_case!(async_memfs::tests::test_split_path_relative)
}

pub fn async_memfs_split_path_root_smoke() -> bool {
    run_case!(async_memfs::tests::test_split_path_root)
}

pub fn cache_core_cached_page_smoke() -> bool {
    run_case!(cache::tests::test_cached_page)
}

pub fn cache_core_page_pin_smoke() -> bool {
    run_case!(cache::tests::test_page_pin)
}

pub fn cache_core_page_cache_smoke() -> bool {
    run_case!(cache::tests::test_page_cache)
}

pub fn cache_core_sync_page_smoke() -> bool {
    run_case!(cache::tests::test_sync_page)
}

pub fn fs_model_file_mode_smoke() -> bool {
    run_case!(fs_model::tests::test_file_mode)
}

pub fn fs_model_open_flags_smoke() -> bool {
    run_case!(fs_model::tests::test_open_flags)
}

pub fn memfs_paged_content_in_inode_smoke() -> bool {
    run_case!(memfs::tests::test_paged_content_in_inode)
}

pub fn memfs_large_file_paging_smoke() -> bool {
    run_case!(memfs::tests::test_large_file_paging)
}

pub fn memfs_cow_copy_smoke() -> bool {
    run_case!(memfs::tests::test_cow_copy)
}

pub fn memfs_sparse_file_smoke() -> bool {
    run_case!(memfs::tests::test_sparse_file)
}

pub fn memfs_truncate_releases_pages_smoke() -> bool {
    run_case!(memfs::tests::test_truncate_releases_pages)
}

pub fn memfs_get_page_zero_copy_smoke() -> bool {
    run_case!(memfs::tests::test_get_page_zero_copy)
}

pub fn page_page_constants_smoke() -> bool {
    run_case!(page::tests::test_page_constants)
}

pub fn page_paged_content_basic_write_read_smoke() -> bool {
    run_case!(page::tests::test_paged_content_basic_write_read)
}

pub fn page_paged_content_sparse_smoke() -> bool {
    run_case!(page::tests::test_paged_content_sparse)
}

pub fn page_paged_content_cross_page_write_smoke() -> bool {
    run_case!(page::tests::test_paged_content_cross_page_write)
}

pub fn page_cow_clone_smoke() -> bool {
    run_case!(page::tests::test_cow_clone)
}

pub fn page_truncate_smoke() -> bool {
    run_case!(page::tests::test_truncate)
}

pub fn page_get_page_zero_copy_smoke() -> bool {
    run_case!(page::tests::test_get_page_zero_copy)
}

pub fn page_cluster_buffer_page_cluster_buffer_alloc_fallback_or_contig_smoke() -> bool {
    run_case!(page_cluster_buffer::tests::test_page_cluster_buffer_alloc_or_contig)
}

pub fn page_cluster_buffer_impl_zero_copy_traits_smoke() -> bool {
    run_case!(page_cluster_buffer::tests::test_impl_zero_copy_traits)
}

pub fn page_cluster_buffer_page_cluster_buffer_dma_info_smoke() -> bool {
    run_case!(page_cluster_buffer::tests::test_page_cluster_buffer_dma_info)
}

pub fn page_cluster_buffer_page_cluster_buffer_physical_alloc_and_write_smoke() -> bool {
    run_case!(page_cluster_buffer::tests::test_page_cluster_buffer_physical_alloc_and_write)
}
