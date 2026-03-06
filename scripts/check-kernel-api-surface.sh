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
  'pub unsafe fn grant_'
  'pub const unsafe fn new\('
)

exclude=(
  '-g' '!target'
  '-g' '!scripts/check-kernel-api-surface.sh'
)

status=0

for pattern in "${patterns[@]}"; do
  if rg -n "${exclude[@]}" -- "$pattern" interfaces kernel drivers libs apps docs qemu-tests tools; then
    status=1
  fi
done

exit "$status"
