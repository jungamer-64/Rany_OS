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

exit "$status"
