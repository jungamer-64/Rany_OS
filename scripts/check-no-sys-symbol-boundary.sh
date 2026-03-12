#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SEARCH_DIRS=(kernel interfaces)
FN_PATTERN='\bfn[[:space:]]+sys_(log|alloc|dealloc|sleep|panic)\b'
SYM_PATTERN='"sys_(log|alloc|dealloc|sleep|panic)"'
KAPI_PATTERN='__exorust_kernel_api_v3|KERNEL_API_SYMBOL'
DMA_SEARCH_DIRS=(kernel interfaces drivers filesystems docs scripts)
DMA_BANNED_PATTERN='map_for_dma\(|map_for_dma_with_perms|MappingKind::Global|get_global_map_count|allow_global_mappings|set_global_dma_mapping_allowed|is_global_dma_mapping_allowed|map_rref_for_domain|map_rref_slice_for_domain|GlobalDmaAllocator|global_dma_allocator\(|DeviceDmaContext::new\(|DmaHandle::map_rref\(|DmaHandle::map_rref_slice\(|\bunmap_dma\('

if command -v rg >/dev/null 2>&1; then
  fn_hits="$(rg -n -e "$FN_PATTERN" "${SEARCH_DIRS[@]}" || true)"
  sym_hits="$(rg -n -e "$SYM_PATTERN" "${SEARCH_DIRS[@]}" || true)"
  kapi_hits="$(rg -n -e "$KAPI_PATTERN" "${SEARCH_DIRS[@]}" || true)"
  dma_hits="$(rg -n -g '!docs/archive/**' -e "$DMA_BANNED_PATTERN" "${DMA_SEARCH_DIRS[@]}" | rg -v '^scripts/check-no-sys-symbol-boundary.sh:' || true)"
  iommu_global_hits="$(rg -n -g '!docs/archive/**' -e 'iommu_global' "${DMA_SEARCH_DIRS[@]}" | rg -v '^kernel/src/kernel_content.rs:' | rg -v '^scripts/check-no-sys-symbol-boundary.sh:' || true)"
else
  fn_hits="$(grep -RInE "$FN_PATTERN" "${SEARCH_DIRS[@]}" || true)"
  sym_hits="$(grep -RInE "$SYM_PATTERN" "${SEARCH_DIRS[@]}" || true)"
  kapi_hits="$(grep -RInE "$KAPI_PATTERN" "${SEARCH_DIRS[@]}" || true)"
  dma_hits="$(grep -RInE "$DMA_BANNED_PATTERN" "${DMA_SEARCH_DIRS[@]}" | grep -v '^docs/archive/' | grep -v '^scripts/check-no-sys-symbol-boundary.sh:' || true)"
  iommu_global_hits="$(grep -RInE 'iommu_global' "${DMA_SEARCH_DIRS[@]}" | grep -v '^docs/archive/' | grep -v '^kernel/src/kernel_content.rs:' | grep -v '^scripts/check-no-sys-symbol-boundary.sh:' || true)"
fi

failed=0

if [ -n "$fn_hits" ]; then
  echo "ERROR: legacy sys_* function boundary found:"
  echo "$fn_hits"
  failed=1
fi

if [ -n "$sym_hits" ]; then
  echo "ERROR: legacy sys_* symbol string found:"
  echo "$sym_hits"
  failed=1
fi

if [ -z "$kapi_hits" ]; then
  echo "ERROR: Kernel API symbol bridge missing (__exorust_kernel_api_v3|KERNEL_API_SYMBOL)"
  failed=1
fi

if [ -n "$dma_hits" ]; then
  echo "ERROR: removed global DMA surface reintroduced:"
  echo "$dma_hits"
  failed=1
fi

if [ -n "$iommu_global_hits" ]; then
  echo "ERROR: deprecated iommu_global references found outside kernel cmdline compatibility warning:"
  echo "$iommu_global_hits"
  failed=1
fi

if [ "$failed" -ne 0 ]; then
  exit 1
fi

echo "PASS: no legacy sys_* boundary, KernelApi v3 symbol bridge detected, and removed global DMA surface is absent."
