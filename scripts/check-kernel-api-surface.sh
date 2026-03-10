#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

patterns=(
  'kernel_api::kapi'
  'kernel_api::services::kernel'
  'kernel_api::kernel\('
  'kernel_api::driver_abi::'
  'kernel_api::security::'
  'kernel_api::types::'
  'kernel_api::gui::'
  'kernel_api::shell::'
  'kernel_api::time::'
  'kernel_api::DmaBuffer\b'
  'kernel_api::service::kernel::instance\(\)\.free_dma'
  '\.free_dma\('
  'AbiDmaBuffer\b'
  'KernelApiV1\b'
  '__exorust_kernel_api_v1\b'
  'pub unsafe fn grant_'
  'pub const unsafe fn new\('
)

exclude=(
  '-g' '!target'
  '-g' '!scripts/check-kernel-api-surface.sh'
  '-g' '!docs/archive/**'
  '-g' '!docs/API_REFERENCE.md'
)

status=0

for pattern in "${patterns[@]}"; do
  if rg -n "${exclude[@]}" -- "$pattern" interfaces kernel drivers libs apps docs qemu-tests tools; then
    status=1
  fi
done

driver_dma_patterns=(
  'kernel_api::service::kernel::instance\(\)\.alloc_dma\('
  '\bkernel\.alloc_dma\('
)

driver_locator_patterns=(
  '\([[:space:]]*.*segment.*as[[:space:]]+u64\)[[:space:]]*<<[[:space:]]*32'
  '\([[:space:]]*.*bus.*as[[:space:]]+u64\)[[:space:]]*<<[[:space:]]*16'
  '\([[:space:]]*.*device.*as[[:space:]]+u64\)[[:space:]]*<<[[:space:]]*8'
)

driver_dma_audit_patterns=(
  '\.physical_address\('
)

for pattern in "${driver_dma_patterns[@]}"; do
  if rg -n -g '!target' -- "$pattern" drivers; then
    status=1
  fi
done

for pattern in "${driver_locator_patterns[@]}"; do
  if rg -n -g '!target' -- "$pattern" drivers; then
    status=1
  fi
done

for pattern in "${driver_dma_audit_patterns[@]}"; do
  if rg -n -g '!target' -- "$pattern" drivers; then
    status=1
  fi
done

initramfs_path="target/initramfs.tar"
required_initramfs_entries=(
  'drivers/driver_cell_probe.cell'
  'drivers/driver_cell_probe_pci.cell'
  'drivers/ahci_driver.cell'
  'drivers/nvme_driver.cell'
  'drivers/usb_xhci_driver.cell'
  'drivers/hda_driver.cell'
  'cells/driver_cell_probe_v1.cell'
  'cells/driver_cell_probe_v2.cell'
)

if [[ ! -f "$initramfs_path" ]]; then
  echo "missing merged runtime initramfs: $initramfs_path" >&2
  status=1
else
  for entry in "${required_initramfs_entries[@]}"; do
    if ! tar -tf "$initramfs_path" | grep -Fxq "$entry"; then
      echo "missing initramfs entry: $entry" >&2
      status=1
    fi
  done

  if ! tar -tf "$initramfs_path" | grep -Eq '^drivers/mlx5_driver_[0-9a-f]+\.cell$'; then
    echo "missing initramfs mlx5 standalone driver pack" >&2
    status=1
  fi
fi

exit "$status"
