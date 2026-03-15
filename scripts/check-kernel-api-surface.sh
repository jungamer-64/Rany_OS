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

boot_artifacts_root="target/x86_64-exorust/release/boot_artifacts"
required_boot_artifact_entries=(
  'drivers/driver_cell_probe.cell'
  'drivers/driver_cell_probe_pci.cell'
  'drivers/ahci_driver.cell'
  'drivers/nvme_driver.cell'
  'drivers/usb_xhci_driver.cell'
  'drivers/hda_driver.cell'
  'cells/driver_cell_probe_v1.cell'
  'cells/driver_cell_probe_v2.cell'
)

boot_artifacts_complete() {
  [[ -d "$boot_artifacts_root" ]] || return 1

  for entry in "${required_boot_artifact_entries[@]}"; do
    [[ -f "$boot_artifacts_root/$entry" ]] || return 1
  done

  find "$boot_artifacts_root/drivers" -maxdepth 1 -type f | grep -Eq '/mlx5_driver_[0-9a-f]+\.cell$'
}

ensure_release_boot_artifacts() {
  if boot_artifacts_complete; then
    return 0
  fi

  echo "[check-kernel-api-surface] release boot artifacts missing or incomplete; building them now..." >&2
  if ! bash scripts/build_runtime_boot_artifacts.sh --profile release; then
    echo "ERROR: failed to build release runtime boot artifacts" >&2
    exit 1
  fi
}

ensure_release_boot_artifacts

if [[ ! -d "$boot_artifacts_root" ]]; then
  echo "missing runtime boot artifacts: $boot_artifacts_root" >&2
  status=1
else
  for entry in "${required_boot_artifact_entries[@]}"; do
    if [[ ! -f "$boot_artifacts_root/$entry" ]]; then
      echo "missing boot artifact entry: $entry" >&2
      status=1
    fi
  done

  if ! find "$boot_artifacts_root/drivers" -maxdepth 1 -type f | grep -Eq '/mlx5_driver_[0-9a-f]+\.cell$'; then
    echo "missing boot artifact mlx5 standalone driver pack" >&2
    status=1
  fi
fi

legacy_initramfs_refs=(
  'initramfs\.tar'
  'build_runtime_initramfs'
  'standalone_driver_initramfs'
)

legacy_exclude=(
  '-g' '!target'
  '-g' '!scripts/check-kernel-api-surface.sh'
  '-g' '!docs/archive/**'
  '-g' '!libs/boot_config/src/lib.rs'
)

for pattern in "${legacy_initramfs_refs[@]}"; do
  if rg -n "${legacy_exclude[@]}" -- "$pattern" .; then
    status=1
  fi
done

exit "$status"
