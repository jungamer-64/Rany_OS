#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SEARCH_DIRS=(kernel interfaces)
FN_PATTERN='\bfn[[:space:]]+sys_(log|alloc|dealloc|sleep|panic)\b'
SYM_PATTERN='"sys_(log|alloc|dealloc|sleep|panic)"'
KAPI_PATTERN='__exorust_kernel_api_v4|KERNEL_API_SYMBOL'
DMA_SEARCH_DIRS=(kernel interfaces drivers docs scripts)
DMA_BANNED_PATTERN='map_for_dma\(|map_for_dma_with_perms|MappingKind::Global|get_global_map_count|allow_global_mappings|set_global_dma_mapping_allowed|is_global_dma_mapping_allowed|map_rref_for_domain|map_rref_slice_for_domain|GlobalDmaAllocator|global_dma_allocator\(|DeviceDmaContext::new\(|DmaHandle::map_rref\(|DmaHandle::map_rref_slice\(|\bunmap_dma\('
REMOVED_IOMMU_KNOB_PATTERN='(^IOMMU[[:space:]]*\?=)|\bNoIommu\b|\bIOMMU=1\b'

search_matches() {
  local status=0
  "$@" || status=$?
  if (( status > 1 )); then
    return "$status"
  fi
}

if command -v rg >/dev/null 2>&1; then
  fn_hits="$(search_matches rg -n -e "$FN_PATTERN" "${SEARCH_DIRS[@]}")"
  sym_hits="$(search_matches rg -n -e "$SYM_PATTERN" "${SEARCH_DIRS[@]}")"
  kapi_hits="$(search_matches rg -n -e "$KAPI_PATTERN" "${SEARCH_DIRS[@]}")"
  dma_hits="$(search_matches rg -n -g '!docs/archive/**' -e "$DMA_BANNED_PATTERN" "${DMA_SEARCH_DIRS[@]}" | sed '/^scripts\/check-no-sys-symbol-boundary\.sh:/d')"
  iommu_global_hits="$(search_matches rg -n -g '!docs/archive/**' -e 'iommu_global' Makefile README.md "${DMA_SEARCH_DIRS[@]}" | sed '/^kernel\/src\/kernel_content\.rs:/d; /^scripts\/check-no-sys-symbol-boundary\.sh:/d')"
  removed_iommu_knob_hits="$(search_matches rg -n -g '!docs/archive/**' -e "$REMOVED_IOMMU_KNOB_PATTERN" Makefile README.md "${DMA_SEARCH_DIRS[@]}" | sed '/^scripts\/check-no-sys-symbol-boundary\.sh:/d')"
else
  fn_hits="$(search_matches grep -RInE "$FN_PATTERN" "${SEARCH_DIRS[@]}")"
  sym_hits="$(search_matches grep -RInE "$SYM_PATTERN" "${SEARCH_DIRS[@]}")"
  kapi_hits="$(search_matches grep -RInE "$KAPI_PATTERN" "${SEARCH_DIRS[@]}")"
  dma_hits="$(search_matches grep -RInE "$DMA_BANNED_PATTERN" "${DMA_SEARCH_DIRS[@]}" | sed '/^docs\/archive\//d; /^scripts\/check-no-sys-symbol-boundary\.sh:/d')"
  iommu_global_hits="$(search_matches grep -RInE 'iommu_global' Makefile README.md "${DMA_SEARCH_DIRS[@]}" | sed '/^docs\/archive\//d; /^kernel\/src\/kernel_content\.rs:/d; /^scripts\/check-no-sys-symbol-boundary\.sh:/d')"
  removed_iommu_knob_hits="$(search_matches grep -RInE "$REMOVED_IOMMU_KNOB_PATTERN" Makefile README.md "${DMA_SEARCH_DIRS[@]}" | sed '/^docs\/archive\//d; /^scripts\/check-no-sys-symbol-boundary\.sh:/d')"
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
  echo "ERROR: Kernel API symbol bridge missing (__exorust_kernel_api_v4|KERNEL_API_SYMBOL)"
  failed=1
fi

if [ -n "$dma_hits" ]; then
  echo "ERROR: removed global DMA surface reintroduced:"
  echo "$dma_hits"
  failed=1
fi

if [ -n "$iommu_global_hits" ]; then
  echo "ERROR: deprecated iommu_global references found outside the mandatory cmdline parser:"
  echo "$iommu_global_hits"
  failed=1
fi

if [ -n "$removed_iommu_knob_hits" ]; then
  echo "ERROR: removed IOMMU compatibility knob surfaces reintroduced:"
  echo "$removed_iommu_knob_hits"
  failed=1
fi

if [ "$failed" -ne 0 ]; then
  exit 1
fi

echo "PASS: no legacy sys_* boundary, KernelApi v4 symbol bridge detected, and removed global DMA surface is absent."
