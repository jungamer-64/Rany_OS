pub fn storage_fs_async_ops_async_file_seek_smoke() -> bool {
    crate::fs::qemu_tests::async_ops_async_file_seek_smoke()
}

pub fn storage_fs_async_ops_direct_block_handle_smoke() -> bool {
    crate::fs::qemu_tests::async_ops_direct_block_handle_smoke()
}

pub fn storage_fs_async_memfs_bytes_creation_smoke() -> bool {
    crate::fs::qemu_tests::async_memfs_bytes_creation_smoke()
}

pub fn storage_fs_async_memfs_bytes_clone_shares_data_smoke() -> bool {
    crate::fs::qemu_tests::async_memfs_bytes_clone_shares_data_smoke()
}

pub fn storage_fs_async_memfs_bytes_empty_smoke() -> bool {
    crate::fs::qemu_tests::async_memfs_bytes_empty_smoke()
}

pub fn storage_fs_async_memfs_bytes_from_slice_smoke() -> bool {
    crate::fs::qemu_tests::async_memfs_bytes_from_slice_smoke()
}

pub fn storage_fs_async_memfs_split_path_absolute_smoke() -> bool {
    crate::fs::qemu_tests::async_memfs_split_path_absolute_smoke()
}

pub fn storage_fs_async_memfs_split_path_relative_smoke() -> bool {
    crate::fs::qemu_tests::async_memfs_split_path_relative_smoke()
}

pub fn storage_fs_async_memfs_split_path_root_smoke() -> bool {
    crate::fs::qemu_tests::async_memfs_split_path_root_smoke()
}

pub fn storage_fs_cache_core_cached_page_smoke() -> bool {
    crate::fs::qemu_tests::cache_core_cached_page_smoke()
}

pub fn storage_fs_cache_core_page_pin_smoke() -> bool {
    crate::fs::qemu_tests::cache_core_page_pin_smoke()
}

pub fn storage_fs_cache_core_page_cache_smoke() -> bool {
    crate::fs::qemu_tests::cache_core_page_cache_smoke()
}

pub fn storage_fs_cache_core_sync_page_smoke() -> bool {
    crate::fs::qemu_tests::cache_core_sync_page_smoke()
}

pub fn storage_fs_cache_block_block_cache_basic_smoke() -> bool {
    crate::fs::qemu_tests::cache_block_block_cache_basic_smoke()
}

pub fn storage_fs_cache_block_block_cache_lru_eviction_smoke() -> bool {
    crate::fs::qemu_tests::cache_block_block_cache_lru_eviction_smoke()
}

pub fn storage_fs_cache_block_block_cache_dirty_tracking_smoke() -> bool {
    crate::fs::qemu_tests::cache_block_block_cache_dirty_tracking_smoke()
}

pub fn storage_fs_cache_block_block_cache_flush_smoke() -> bool {
    crate::fs::qemu_tests::cache_block_block_cache_flush_smoke()
}

pub fn storage_fs_devfs_null_device_smoke() -> bool {
    crate::fs::qemu_tests::devfs_null_device_smoke()
}

pub fn storage_fs_devfs_zero_device_smoke() -> bool {
    crate::fs::qemu_tests::devfs_zero_device_smoke()
}

pub fn storage_fs_devfs_random_device_smoke() -> bool {
    crate::fs::qemu_tests::devfs_random_device_smoke()
}

pub fn storage_fs_devfs_dev_open_with_token_reclaim_smoke() -> bool {
    crate::fs::qemu_tests::devfs_dev_open_with_token_reclaim_smoke()
}

pub fn storage_fs_devfs_devfs_structure_smoke() -> bool {
    crate::fs::qemu_tests::devfs_devfs_structure_smoke()
}

pub fn storage_fs_devfs_find_block_device_by_number_smoke() -> bool {
    crate::fs::qemu_tests::devfs_find_block_device_by_number_smoke()
}

pub fn storage_fs_ext2_superblock_block_size_smoke() -> bool {
    crate::fs::qemu_tests::ext2_superblock_block_size_smoke()
}

pub fn storage_fs_ext2_inode_file_type_smoke() -> bool {
    crate::fs::qemu_tests::ext2_inode_file_type_smoke()
}

pub fn storage_fs_fs_abstraction_file_mode_smoke() -> bool {
    crate::fs::qemu_tests::fs_abstraction_file_mode_smoke()
}

pub fn storage_fs_fs_abstraction_open_flags_smoke() -> bool {
    crate::fs::qemu_tests::fs_abstraction_open_flags_smoke()
}

pub fn storage_fs_memfs_paged_content_in_inode_smoke() -> bool {
    crate::fs::qemu_tests::memfs_paged_content_in_inode_smoke()
}

pub fn storage_fs_memfs_large_file_paging_smoke() -> bool {
    crate::fs::qemu_tests::memfs_large_file_paging_smoke()
}

pub fn storage_fs_memfs_cow_copy_smoke() -> bool {
    crate::fs::qemu_tests::memfs_cow_copy_smoke()
}

pub fn storage_fs_memfs_sparse_file_smoke() -> bool {
    crate::fs::qemu_tests::memfs_sparse_file_smoke()
}

pub fn storage_fs_memfs_truncate_releases_pages_smoke() -> bool {
    crate::fs::qemu_tests::memfs_truncate_releases_pages_smoke()
}

pub fn storage_fs_memfs_get_page_zero_copy_smoke() -> bool {
    crate::fs::qemu_tests::memfs_get_page_zero_copy_smoke()
}

pub fn storage_fs_page_page_constants_smoke() -> bool {
    crate::fs::qemu_tests::page_page_constants_smoke()
}

pub fn storage_fs_page_paged_content_basic_write_read_smoke() -> bool {
    crate::fs::qemu_tests::page_paged_content_basic_write_read_smoke()
}

pub fn storage_fs_page_paged_content_sparse_smoke() -> bool {
    crate::fs::qemu_tests::page_paged_content_sparse_smoke()
}

pub fn storage_fs_page_paged_content_cross_page_write_smoke() -> bool {
    crate::fs::qemu_tests::page_paged_content_cross_page_write_smoke()
}

pub fn storage_fs_page_cow_clone_smoke() -> bool {
    crate::fs::qemu_tests::page_cow_clone_smoke()
}

pub fn storage_fs_page_truncate_smoke() -> bool {
    crate::fs::qemu_tests::page_truncate_smoke()
}

pub fn storage_fs_page_get_page_zero_copy_smoke() -> bool {
    crate::fs::qemu_tests::page_get_page_zero_copy_smoke()
}

pub fn storage_fs_page_cluster_buffer_page_cluster_buffer_alloc_fallback_or_contig_smoke() -> bool {
    crate::fs::qemu_tests::page_cluster_buffer_page_cluster_buffer_alloc_fallback_or_contig_smoke()
}

pub fn storage_fs_page_cluster_buffer_impl_zero_copy_traits_smoke() -> bool {
    crate::fs::qemu_tests::page_cluster_buffer_impl_zero_copy_traits_smoke()
}

pub fn storage_fs_page_cluster_buffer_page_cluster_buffer_dma_info_smoke() -> bool {
    crate::fs::qemu_tests::page_cluster_buffer_page_cluster_buffer_dma_info_smoke()
}

pub fn storage_fs_page_cluster_buffer_page_cluster_buffer_physical_alloc_and_write_smoke() -> bool {
    crate::fs::qemu_tests::page_cluster_buffer_page_cluster_buffer_physical_alloc_and_write_smoke()
}

pub fn storage_fs_page_cluster_buffer_fat_mount_with_page_allocator_zero_copy_smoke() -> bool {
    crate::fs::qemu_tests::page_cluster_buffer_fat_mount_with_page_allocator_zero_copy_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn storage_fs_procfs_procfs_read_smoke() -> bool {
    crate::fs::qemu_tests::procfs_procfs_read_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn storage_fs_procfs_procfs_directory_smoke() -> bool {
    crate::fs::qemu_tests::procfs_procfs_directory_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn storage_fs_procfs_process_entries_smoke() -> bool {
    crate::fs::qemu_tests::procfs_process_entries_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn storage_fs_procfs_proc_mem_open_with_token_reclaim_smoke() -> bool {
    crate::fs::qemu_tests::procfs_proc_mem_open_with_token_reclaim_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn storage_fs_procfs_proc_mem_revoke_reclaim_stress_smoke() -> bool {
    crate::fs::qemu_tests::procfs_proc_mem_revoke_reclaim_stress_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn storage_fs_procfs_proc_maps_open_with_token_reclaim_smoke() -> bool {
    crate::fs::qemu_tests::procfs_proc_maps_open_with_token_reclaim_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn storage_fs_procfs_proc_maps_revoke_reclaim_stress_smoke() -> bool {
    crate::fs::qemu_tests::procfs_proc_maps_revoke_reclaim_stress_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn storage_fs_procfs_proc_cmdline_open_with_token_reclaim_smoke() -> bool {
    crate::fs::qemu_tests::procfs_proc_cmdline_open_with_token_reclaim_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn storage_fs_procfs_proc_cmdline_revoke_reclaim_stress_smoke() -> bool {
    crate::fs::qemu_tests::procfs_proc_cmdline_revoke_reclaim_stress_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn storage_fs_procfs_proc_fd_open_with_token_reclaim_smoke() -> bool {
    crate::fs::qemu_tests::procfs_proc_fd_open_with_token_reclaim_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn storage_fs_procfs_proc_fd_revoke_reclaim_stress_smoke() -> bool {
    crate::fs::qemu_tests::procfs_proc_fd_revoke_reclaim_stress_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn storage_fs_procfs_proc_exe_open_with_token_reclaim_smoke() -> bool {
    crate::fs::qemu_tests::procfs_proc_exe_open_with_token_reclaim_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn storage_fs_procfs_proc_exe_revoke_reclaim_stress_smoke() -> bool {
    crate::fs::qemu_tests::procfs_proc_exe_revoke_reclaim_stress_smoke()
}

#[cfg(feature = "posix-compat")]
pub fn storage_fs_procfs_proc_fd_listing_shows_open_handles_smoke() -> bool {
    crate::fs::qemu_tests::procfs_proc_fd_listing_shows_open_handles_smoke()
}

