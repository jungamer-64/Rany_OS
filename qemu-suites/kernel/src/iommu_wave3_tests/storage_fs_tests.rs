use super::*;

pub(crate) fn test_storage_fs_async_ops_exports() -> bool {
    run_check(
        "storage_fs_async_ops_async_file_seek_smoke",
        rany_os::qemu_tests::storage_fs_async_ops_async_file_seek_smoke,
    ) && run_check(
        "storage_fs_async_ops_direct_block_handle_smoke",
        rany_os::qemu_tests::storage_fs_async_ops_direct_block_handle_smoke,
    )
}

pub(crate) fn test_storage_fs_async_memfs_exports() -> bool {
    run_check(
        "storage_fs_async_memfs_bytes_creation_smoke",
        rany_os::qemu_tests::storage_fs_async_memfs_bytes_creation_smoke,
    ) && run_check(
        "storage_fs_async_memfs_bytes_clone_shares_data_smoke",
        rany_os::qemu_tests::storage_fs_async_memfs_bytes_clone_shares_data_smoke,
    ) && run_check(
        "storage_fs_async_memfs_bytes_empty_smoke",
        rany_os::qemu_tests::storage_fs_async_memfs_bytes_empty_smoke,
    ) && run_check(
        "storage_fs_async_memfs_bytes_from_slice_smoke",
        rany_os::qemu_tests::storage_fs_async_memfs_bytes_from_slice_smoke,
    ) && run_check(
        "storage_fs_async_memfs_split_path_absolute_smoke",
        rany_os::qemu_tests::storage_fs_async_memfs_split_path_absolute_smoke,
    ) && run_check(
        "storage_fs_async_memfs_split_path_relative_smoke",
        rany_os::qemu_tests::storage_fs_async_memfs_split_path_relative_smoke,
    ) && run_check(
        "storage_fs_async_memfs_split_path_root_smoke",
        rany_os::qemu_tests::storage_fs_async_memfs_split_path_root_smoke,
    )
}

pub(crate) fn test_storage_fs_cache_core_exports() -> bool {
    run_check(
        "storage_fs_cache_core_cached_page_smoke",
        rany_os::qemu_tests::storage_fs_cache_core_cached_page_smoke,
    ) && run_check(
        "storage_fs_cache_core_page_pin_smoke",
        rany_os::qemu_tests::storage_fs_cache_core_page_pin_smoke,
    ) && run_check(
        "storage_fs_cache_core_page_cache_smoke",
        rany_os::qemu_tests::storage_fs_cache_core_page_cache_smoke,
    ) && run_check(
        "storage_fs_cache_core_sync_page_smoke",
        rany_os::qemu_tests::storage_fs_cache_core_sync_page_smoke,
    )
}

pub(crate) fn test_storage_fs_cache_block_exports() -> bool {
    run_check(
        "storage_fs_cache_block_block_cache_basic_smoke",
        rany_os::qemu_tests::storage_fs_cache_block_block_cache_basic_smoke,
    ) && run_check(
        "storage_fs_cache_block_block_cache_lru_eviction_smoke",
        rany_os::qemu_tests::storage_fs_cache_block_block_cache_lru_eviction_smoke,
    ) && run_check(
        "storage_fs_cache_block_block_cache_dirty_tracking_smoke",
        rany_os::qemu_tests::storage_fs_cache_block_block_cache_dirty_tracking_smoke,
    ) && run_check(
        "storage_fs_cache_block_block_cache_flush_smoke",
        rany_os::qemu_tests::storage_fs_cache_block_block_cache_flush_smoke,
    )
}

pub(crate) fn test_storage_fs_devfs_exports() -> bool {
    run_check(
        "storage_fs_devfs_null_device_smoke",
        rany_os::qemu_tests::storage_fs_devfs_null_device_smoke,
    ) && run_check(
        "storage_fs_devfs_zero_device_smoke",
        rany_os::qemu_tests::storage_fs_devfs_zero_device_smoke,
    ) && run_check(
        "storage_fs_devfs_random_device_smoke",
        rany_os::qemu_tests::storage_fs_devfs_random_device_smoke,
    ) && run_check(
        "storage_fs_devfs_dev_open_with_token_reclaim_smoke",
        rany_os::qemu_tests::storage_fs_devfs_dev_open_with_token_reclaim_smoke,
    ) && run_check(
        "storage_fs_devfs_devfs_structure_smoke",
        rany_os::qemu_tests::storage_fs_devfs_devfs_structure_smoke,
    ) && run_check(
        "storage_fs_devfs_find_block_device_by_number_smoke",
        rany_os::qemu_tests::storage_fs_devfs_find_block_device_by_number_smoke,
    )
}

pub(crate) fn test_storage_fs_ext2_exports() -> bool {
    run_check(
        "storage_fs_ext2_superblock_block_size_smoke",
        rany_os::qemu_tests::storage_fs_ext2_superblock_block_size_smoke,
    ) && run_check(
        "storage_fs_ext2_inode_file_type_smoke",
        rany_os::qemu_tests::storage_fs_ext2_inode_file_type_smoke,
    )
}

pub(crate) fn test_storage_fs_fs_abstraction_exports() -> bool {
    run_check(
        "storage_fs_fs_abstraction_file_mode_smoke",
        rany_os::qemu_tests::storage_fs_fs_abstraction_file_mode_smoke,
    ) && run_check(
        "storage_fs_fs_abstraction_open_flags_smoke",
        rany_os::qemu_tests::storage_fs_fs_abstraction_open_flags_smoke,
    )
}

pub(crate) fn test_storage_fs_memfs_exports() -> bool {
    run_check(
        "storage_fs_memfs_paged_content_in_inode_smoke",
        rany_os::qemu_tests::storage_fs_memfs_paged_content_in_inode_smoke,
    ) && run_check(
        "storage_fs_memfs_large_file_paging_smoke",
        rany_os::qemu_tests::storage_fs_memfs_large_file_paging_smoke,
    ) && run_check(
        "storage_fs_memfs_cow_copy_smoke",
        rany_os::qemu_tests::storage_fs_memfs_cow_copy_smoke,
    ) && run_check(
        "storage_fs_memfs_sparse_file_smoke",
        rany_os::qemu_tests::storage_fs_memfs_sparse_file_smoke,
    ) && run_check(
        "storage_fs_memfs_truncate_releases_pages_smoke",
        rany_os::qemu_tests::storage_fs_memfs_truncate_releases_pages_smoke,
    ) && run_check(
        "storage_fs_memfs_get_page_zero_copy_smoke",
        rany_os::qemu_tests::storage_fs_memfs_get_page_zero_copy_smoke,
    )
}

pub(crate) fn test_storage_fs_page_exports() -> bool {
    run_check(
        "storage_fs_page_page_constants_smoke",
        rany_os::qemu_tests::storage_fs_page_page_constants_smoke,
    ) && run_check(
        "storage_fs_page_paged_content_basic_write_read_smoke",
        rany_os::qemu_tests::storage_fs_page_paged_content_basic_write_read_smoke,
    ) && run_check(
        "storage_fs_page_paged_content_sparse_smoke",
        rany_os::qemu_tests::storage_fs_page_paged_content_sparse_smoke,
    ) && run_check(
        "storage_fs_page_paged_content_cross_page_write_smoke",
        rany_os::qemu_tests::storage_fs_page_paged_content_cross_page_write_smoke,
    ) && run_check(
        "storage_fs_page_cow_clone_smoke",
        rany_os::qemu_tests::storage_fs_page_cow_clone_smoke,
    ) && run_check(
        "storage_fs_page_truncate_smoke",
        rany_os::qemu_tests::storage_fs_page_truncate_smoke,
    ) && run_check(
        "storage_fs_page_get_page_zero_copy_smoke",
        rany_os::qemu_tests::storage_fs_page_get_page_zero_copy_smoke,
    )
}

pub(crate) fn test_storage_fs_page_cluster_buffer_exports() -> bool {
    run_check("storage_fs_page_cluster_buffer_page_cluster_buffer_alloc_fallback_or_contig_smoke", rany_os::qemu_tests::storage_fs_page_cluster_buffer_page_cluster_buffer_alloc_fallback_or_contig_smoke) &&
    run_check("storage_fs_page_cluster_buffer_impl_zero_copy_traits_smoke", rany_os::qemu_tests::storage_fs_page_cluster_buffer_impl_zero_copy_traits_smoke) &&
    run_check("storage_fs_page_cluster_buffer_page_cluster_buffer_dma_info_smoke", rany_os::qemu_tests::storage_fs_page_cluster_buffer_page_cluster_buffer_dma_info_smoke) &&
    run_check("storage_fs_page_cluster_buffer_page_cluster_buffer_physical_alloc_and_write_smoke", rany_os::qemu_tests::storage_fs_page_cluster_buffer_page_cluster_buffer_physical_alloc_and_write_smoke) &&
    run_check("storage_fs_page_cluster_buffer_fat_mount_with_page_allocator_zero_copy_smoke", rany_os::qemu_tests::storage_fs_page_cluster_buffer_fat_mount_with_page_allocator_zero_copy_smoke)
}

pub(crate) fn test_storage_fs_procfs_exports() -> bool {
    run_check(
        "storage_fs_procfs_procfs_read_smoke",
        rany_os::qemu_tests::storage_fs_procfs_procfs_read_smoke,
    ) && run_check(
        "storage_fs_procfs_procfs_directory_smoke",
        rany_os::qemu_tests::storage_fs_procfs_procfs_directory_smoke,
    ) && run_check(
        "storage_fs_procfs_process_entries_smoke",
        rany_os::qemu_tests::storage_fs_procfs_process_entries_smoke,
    ) && run_check(
        "storage_fs_procfs_proc_mem_open_with_token_reclaim_smoke",
        rany_os::qemu_tests::storage_fs_procfs_proc_mem_open_with_token_reclaim_smoke,
    ) && run_check(
        "storage_fs_procfs_proc_mem_revoke_reclaim_stress_smoke",
        rany_os::qemu_tests::storage_fs_procfs_proc_mem_revoke_reclaim_stress_smoke,
    ) && run_check(
        "storage_fs_procfs_proc_maps_open_with_token_reclaim_smoke",
        rany_os::qemu_tests::storage_fs_procfs_proc_maps_open_with_token_reclaim_smoke,
    ) && run_check(
        "storage_fs_procfs_proc_maps_revoke_reclaim_stress_smoke",
        rany_os::qemu_tests::storage_fs_procfs_proc_maps_revoke_reclaim_stress_smoke,
    ) && run_check(
        "storage_fs_procfs_proc_cmdline_open_with_token_reclaim_smoke",
        rany_os::qemu_tests::storage_fs_procfs_proc_cmdline_open_with_token_reclaim_smoke,
    ) && run_check(
        "storage_fs_procfs_proc_cmdline_revoke_reclaim_stress_smoke",
        rany_os::qemu_tests::storage_fs_procfs_proc_cmdline_revoke_reclaim_stress_smoke,
    ) && run_check(
        "storage_fs_procfs_proc_fd_open_with_token_reclaim_smoke",
        rany_os::qemu_tests::storage_fs_procfs_proc_fd_open_with_token_reclaim_smoke,
    ) && run_check(
        "storage_fs_procfs_proc_fd_revoke_reclaim_stress_smoke",
        rany_os::qemu_tests::storage_fs_procfs_proc_fd_revoke_reclaim_stress_smoke,
    ) && run_check(
        "storage_fs_procfs_proc_exe_open_with_token_reclaim_smoke",
        rany_os::qemu_tests::storage_fs_procfs_proc_exe_open_with_token_reclaim_smoke,
    ) && run_check(
        "storage_fs_procfs_proc_exe_revoke_reclaim_stress_smoke",
        rany_os::qemu_tests::storage_fs_procfs_proc_exe_revoke_reclaim_stress_smoke,
    ) && run_check(
        "storage_fs_procfs_proc_fd_listing_shows_open_handles_smoke",
        rany_os::qemu_tests::storage_fs_procfs_proc_fd_listing_shows_open_handles_smoke,
    )
}
