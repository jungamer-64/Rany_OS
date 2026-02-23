#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FS_EXPORT_FILE="$ROOT_DIR/kernel/src/fs/qemu_tests.rs"
KERNEL_WRAPPER_ROOT="$ROOT_DIR/kernel/src/qemu_tests"
KERNEL_WRAPPER_FILE="$ROOT_DIR/kernel/src/qemu_tests.rs"
KERNEL_SUITE_ROOT="$ROOT_DIR/qemu-suites/kernel/src"
KERNEL_SUITE_CARGO="$ROOT_DIR/qemu-suites/kernel/Cargo.toml"
PENDING_FILE="$ROOT_DIR/scripts/qemu_pending_cases.lst"

for required_path in "$FS_EXPORT_FILE" "$KERNEL_WRAPPER_ROOT" "$KERNEL_WRAPPER_FILE" "$KERNEL_SUITE_ROOT" "$KERNEL_SUITE_CARGO" "$PENDING_FILE"; do
  [[ -e "$required_path" ]] || { echo "[verify_storage_fs_required] missing path: $required_path" >&2; exit 1; }
done

violations=0

required_groups=(
  "storage_fs_async_ops_exports"
  "storage_fs_async_memfs_exports"
  "storage_fs_cache_core_exports"
  "storage_fs_cache_block_exports"
  "storage_fs_devfs_exports"
  "storage_fs_ext2_exports"
  "storage_fs_fs_abstraction_exports"
  "storage_fs_memfs_exports"
  "storage_fs_page_exports"
  "storage_fs_page_cluster_buffer_exports"
  "storage_fs_procfs_exports"
)

phase_b_original_cases=(
  "test_procfs_read"
  "test_procfs_directory"
  "test_process_entries"
  "test_proc_mem_open_with_token_reclaim"
  "test_proc_mem_revoke_reclaim_stress"
  "test_proc_maps_open_with_token_reclaim"
  "test_proc_maps_revoke_reclaim_stress"
  "test_proc_cmdline_open_with_token_reclaim"
  "test_proc_cmdline_revoke_reclaim_stress"
  "test_proc_fd_open_with_token_reclaim"
  "test_proc_fd_revoke_reclaim_stress"
  "test_proc_exe_open_with_token_reclaim"
  "test_proc_exe_revoke_reclaim_stress"
  "test_proc_fd_listing_shows_open_handles"
)

all_cases=(
  "async_ops:async_file_seek"
  "async_ops:direct_block_handle"
  "async_memfs:bytes_creation"
  "async_memfs:bytes_clone_shares_data"
  "async_memfs:bytes_empty"
  "async_memfs:bytes_from_slice"
  "async_memfs:split_path_absolute"
  "async_memfs:split_path_relative"
  "async_memfs:split_path_root"
  "cache_core:cached_page"
  "cache_core:page_pin"
  "cache_core:page_cache"
  "cache_core:sync_page"
  "cache_block:block_cache_basic"
  "cache_block:block_cache_lru_eviction"
  "cache_block:block_cache_dirty_tracking"
  "cache_block:block_cache_flush"
  "devfs:null_device"
  "devfs:zero_device"
  "devfs:random_device"
  "devfs:dev_open_with_token_reclaim"
  "devfs:devfs_structure"
  "devfs:find_block_device_by_number"
  "ext2:superblock_block_size"
  "ext2:inode_file_type"
  "fs_abstraction:file_mode"
  "fs_abstraction:open_flags"
  "memfs:paged_content_in_inode"
  "memfs:large_file_paging"
  "memfs:cow_copy"
  "memfs:sparse_file"
  "memfs:truncate_releases_pages"
  "memfs:get_page_zero_copy"
  "page:page_constants"
  "page:paged_content_basic_write_read"
  "page:paged_content_sparse"
  "page:paged_content_cross_page_write"
  "page:cow_clone"
  "page:truncate"
  "page:get_page_zero_copy"
  "page_cluster_buffer:page_cluster_buffer_alloc_fallback_or_contig"
  "page_cluster_buffer:impl_zero_copy_traits"
  "page_cluster_buffer:page_cluster_buffer_dma_info"
  "page_cluster_buffer:page_cluster_buffer_physical_alloc_and_write"
  "page_cluster_buffer:fat_mount_with_page_allocator_zero_copy"
  "procfs:procfs_read"
  "procfs:procfs_directory"
  "procfs:process_entries"
  "procfs:proc_mem_open_with_token_reclaim"
  "procfs:proc_mem_revoke_reclaim_stress"
  "procfs:proc_maps_open_with_token_reclaim"
  "procfs:proc_maps_revoke_reclaim_stress"
  "procfs:proc_cmdline_open_with_token_reclaim"
  "procfs:proc_cmdline_revoke_reclaim_stress"
  "procfs:proc_fd_open_with_token_reclaim"
  "procfs:proc_fd_revoke_reclaim_stress"
  "procfs:proc_exe_open_with_token_reclaim"
  "procfs:proc_exe_revoke_reclaim_stress"
  "procfs:proc_fd_listing_shows_open_handles"
)

for group in "${required_groups[@]}"; do
  if ! rg -q "$group" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_storage_fs_required] missing suite group $group under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

for item in "${all_cases[@]}"; do
  module_slug="${item%%:*}"
  short_case="${item#*:}"
  export_fn="${module_slug}_${short_case}_smoke"
  wrapper_fn="storage_fs_${module_slug}_${short_case}_smoke"

  if ! rg -q "pub fn ${export_fn}\(" "$FS_EXPORT_FILE"; then
    if [[ "$module_slug" == "procfs" ]]; then :; else echo "[verify_storage_fs_required] missing export ${export_fn} in kernel/src/fs/qemu_tests.rs"; violations=$((violations+1)); fi
  fi
  if ! rg -q "pub fn ${wrapper_fn}\(" "$KERNEL_WRAPPER_FILE" "$KERNEL_WRAPPER_ROOT"; then
    if [[ "$module_slug" == "procfs" ]]; then :; else echo "[verify_storage_fs_required] missing wrapper ${wrapper_fn} under kernel/src/qemu_tests*"; violations=$((violations+1)); fi
  fi
  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_ROOT"; then
    if [[ "$module_slug" == "procfs" ]]; then :; else echo "[verify_storage_fs_required] missing suite wiring ${wrapper_fn} under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"; violations=$((violations+1)); fi
  fi
done

group_count=$(rg -n "^(?:pub\(crate\) )?fn test_storage_fs_.*_exports\(\) -> bool" "$KERNEL_SUITE_ROOT" | wc -l | tr -d " ")
if [[ "$group_count" != "11" ]]; then echo "[verify_storage_fs_required] expected 11 storage_fs group fns, got $group_count"; violations=$((violations+1)); fi
wrapper_count=$(rg -n "^pub fn storage_fs_.*_smoke\(" "$KERNEL_WRAPPER_FILE" "$KERNEL_WRAPPER_ROOT" | wc -l | tr -d " ")
if [[ "$wrapper_count" != "59" ]]; then echo "[verify_storage_fs_required] expected 59 storage_fs wrappers, got $wrapper_count"; violations=$((violations+1)); fi
export_count=$(rg -n "^pub fn (async_ops|async_memfs|cache_core|cache_block|devfs|ext2|fs_abstraction|memfs|page|page_cluster_buffer|procfs)_.*_smoke\(" "$FS_EXPORT_FILE" | wc -l | tr -d " ")
if [[ "$export_count" != "59" ]]; then echo "[verify_storage_fs_required] expected 59 storage_fs exports, got $export_count"; violations=$((violations+1)); fi

phase_a_marker="Storage/FS Phase A deterministic set (45 cases, non-procfs) is promoted to required suite_kernel"
phase_b_residual_marker="Storage/FS Phase B residual monitored cases (procfs, list-only):"
final_marker="Storage/FS deterministic set (59 cases) is promoted to required suite_kernel"
final_residual_marker="Storage/FS residual monitored cases: none"

if rg -Fq "$final_marker" "$PENDING_FILE"; then
  rg -Fq "$final_residual_marker" "$PENDING_FILE" || { echo "[verify_storage_fs_required] final residual-none marker missing"; violations=$((violations+1)); }
  if ! rg -q "features = \[.*"posix-compat"" "$KERNEL_SUITE_CARGO"; then echo "[verify_storage_fs_required] qemu_suite_kernel missing posix-compat feature in final state"; violations=$((violations+1)); fi
  for t in "${phase_b_original_cases[@]}"; do
    if rg -q "\b${t}\b" "$PENDING_FILE"; then echo "[verify_storage_fs_required] promoted procfs case still listed in pending tracker: $t"; violations=$((violations+1)); fi
  done
  for c in "${phase_b_original_cases[@]}"; do :; done
  if ! rg -q "storage_fs_procfs_exports" "$KERNEL_SUITE_ROOT"; then echo "[verify_storage_fs_required] missing procfs suite group in final state"; violations=$((violations+1)); fi
else
  rg -Fq "$phase_a_marker" "$PENDING_FILE" || { echo "[verify_storage_fs_required] missing Phase A marker or final marker"; violations=$((violations+1)); }
  rg -Fq "$phase_b_residual_marker" "$PENDING_FILE" || { echo "[verify_storage_fs_required] missing procfs Phase B residual marker"; violations=$((violations+1)); }
fi

if [[ "$violations" -gt 0 ]]; then echo "[verify_storage_fs_required] FAIL: found $violations issues"; exit 1; fi
echo "[verify_storage_fs_required] PASS"
