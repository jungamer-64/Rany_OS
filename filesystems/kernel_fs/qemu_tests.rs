//! QEMU-exported Storage/FS deterministic checks.
use super::{async_memfs, cache, devfs, memfs, page, page_cluster_buffer};
use super::{async_ops, ext2, fs_abstraction};
#[cfg(feature = "posix-compat")]
use super::procfs;

macro_rules! run_case {
    ($func:path) => {{
        $func();
        true
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

pub fn cache_block_block_cache_basic_smoke() -> bool {
    run_case!(cache::cached_block_impl::block_cache_tests::test_block_cache_basic)
}

pub fn cache_block_block_cache_lru_eviction_smoke() -> bool {
    run_case!(cache::cached_block_impl::block_cache_tests::test_block_cache_lru_eviction)
}

pub fn cache_block_block_cache_dirty_tracking_smoke() -> bool {
    run_case!(cache::cached_block_impl::block_cache_tests::test_block_cache_dirty_tracking)
}

pub fn cache_block_block_cache_flush_smoke() -> bool {
    run_case!(cache::cached_block_impl::block_cache_tests::test_block_cache_flush)
}

pub fn devfs_null_device_smoke() -> bool {
    run_case!(devfs::tests::test_null_device)
}

pub fn devfs_zero_device_smoke() -> bool {
    run_case!(devfs::tests::test_zero_device)
}

pub fn devfs_random_device_smoke() -> bool {
    run_case!(devfs::tests::test_random_device)
}

pub fn devfs_dev_open_with_token_reclaim_smoke() -> bool {
    run_case!(devfs::tests::test_dev_open_with_token_reclaim)
}

pub fn devfs_devfs_structure_smoke() -> bool {
    run_case!(devfs::tests::test_devfs_structure)
}

pub fn devfs_find_block_device_by_number_smoke() -> bool {
    run_case!(devfs::tests::test_find_block_device_by_number)
}

pub fn ext2_superblock_block_size_smoke() -> bool {
    run_case!(ext2::tests::test_superblock_block_size)
}

pub fn ext2_inode_file_type_smoke() -> bool {
    run_case!(ext2::tests::test_inode_file_type)
}

pub fn fs_abstraction_file_mode_smoke() -> bool {
    run_case!(fs_abstraction::tests::test_file_mode)
}

pub fn fs_abstraction_open_flags_smoke() -> bool {
    run_case!(fs_abstraction::tests::test_open_flags)
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
    run_case!(page_cluster_buffer::tests::test_page_cluster_buffer_alloc_fallback_or_contig)
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

pub fn page_cluster_buffer_fat_mount_with_page_allocator_zero_copy_smoke() -> bool {
    run_case!(page_cluster_buffer::tests::test_fat_mount_with_page_allocator_zero_copy)
}

#[cfg(feature = "posix-compat")]
mod procfs_exports {
    use super::*;

    pub fn procfs_procfs_read_smoke() -> bool {
        run_case!(procfs::tests::test_procfs_read)
    }

    pub fn procfs_procfs_directory_smoke() -> bool {
        run_case!(procfs::tests::test_procfs_directory)
    }

    pub fn procfs_process_entries_smoke() -> bool {
        run_case!(procfs::tests::test_process_entries)
    }

    pub fn procfs_proc_mem_open_with_token_reclaim_smoke() -> bool {
        run_case!(procfs::tests::test_proc_mem_open_with_token_reclaim)
    }

    pub fn procfs_proc_mem_revoke_reclaim_stress_smoke() -> bool {
        run_case!(procfs::tests::test_proc_mem_revoke_reclaim_stress)
    }

    pub fn procfs_proc_maps_open_with_token_reclaim_smoke() -> bool {
        run_case!(procfs::tests::test_proc_maps_open_with_token_reclaim)
    }

    pub fn procfs_proc_maps_revoke_reclaim_stress_smoke() -> bool {
        run_case!(procfs::tests::test_proc_maps_revoke_reclaim_stress)
    }

    pub fn procfs_proc_cmdline_open_with_token_reclaim_smoke() -> bool {
        run_case!(procfs::tests::test_proc_cmdline_open_with_token_reclaim)
    }

    pub fn procfs_proc_cmdline_revoke_reclaim_stress_smoke() -> bool {
        run_case!(procfs::tests::test_proc_cmdline_revoke_reclaim_stress)
    }

    pub fn procfs_proc_fd_open_with_token_reclaim_smoke() -> bool {
        run_case!(procfs::tests::test_proc_fd_open_with_token_reclaim)
    }

    pub fn procfs_proc_fd_revoke_reclaim_stress_smoke() -> bool {
        run_case!(procfs::tests::test_proc_fd_revoke_reclaim_stress)
    }

    pub fn procfs_proc_exe_open_with_token_reclaim_smoke() -> bool {
        run_case!(procfs::tests::test_proc_exe_open_with_token_reclaim)
    }

    pub fn procfs_proc_exe_revoke_reclaim_stress_smoke() -> bool {
        run_case!(procfs::tests::test_proc_exe_revoke_reclaim_stress)
    }

    pub fn procfs_proc_fd_listing_shows_open_handles_smoke() -> bool {
        run_case!(procfs::tests::test_proc_fd_listing_shows_open_handles)
    }

}

#[cfg(feature = "posix-compat")]
pub fn procfs_procfs_read_smoke() -> bool {
    procfs_exports::procfs_procfs_read_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn procfs_procfs_directory_smoke() -> bool {
    procfs_exports::procfs_procfs_directory_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn procfs_process_entries_smoke() -> bool {
    procfs_exports::procfs_process_entries_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn procfs_proc_mem_open_with_token_reclaim_smoke() -> bool {
    procfs_exports::procfs_proc_mem_open_with_token_reclaim_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn procfs_proc_mem_revoke_reclaim_stress_smoke() -> bool {
    procfs_exports::procfs_proc_mem_revoke_reclaim_stress_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn procfs_proc_maps_open_with_token_reclaim_smoke() -> bool {
    procfs_exports::procfs_proc_maps_open_with_token_reclaim_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn procfs_proc_maps_revoke_reclaim_stress_smoke() -> bool {
    procfs_exports::procfs_proc_maps_revoke_reclaim_stress_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn procfs_proc_cmdline_open_with_token_reclaim_smoke() -> bool {
    procfs_exports::procfs_proc_cmdline_open_with_token_reclaim_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn procfs_proc_cmdline_revoke_reclaim_stress_smoke() -> bool {
    procfs_exports::procfs_proc_cmdline_revoke_reclaim_stress_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn procfs_proc_fd_open_with_token_reclaim_smoke() -> bool {
    procfs_exports::procfs_proc_fd_open_with_token_reclaim_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn procfs_proc_fd_revoke_reclaim_stress_smoke() -> bool {
    procfs_exports::procfs_proc_fd_revoke_reclaim_stress_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn procfs_proc_exe_open_with_token_reclaim_smoke() -> bool {
    procfs_exports::procfs_proc_exe_open_with_token_reclaim_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn procfs_proc_exe_revoke_reclaim_stress_smoke() -> bool {
    procfs_exports::procfs_proc_exe_revoke_reclaim_stress_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn procfs_proc_fd_listing_shows_open_handles_smoke() -> bool {
    procfs_exports::procfs_proc_fd_listing_shows_open_handles_smoke()
}

