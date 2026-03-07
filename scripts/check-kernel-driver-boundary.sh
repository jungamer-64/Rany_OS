#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Transitional allowlist:
# - kernel-owned device wrappers under kernel/src/io
# - provider bootstrap adapters under kernel/src/platform
# - staged kernel-resident bridge zones that are not migrated yet
exclude=(
  '-g' '!target'
  '-g' '!kernel/src/io/**'
  '-g' '!kernel/src/platform/**'
  '-g' '!kernel/src/provider_registry.rs'
  '-g' '!kernel/src/drivers/time.rs'
  '-g' '!kernel/src/lib.rs'
  '-g' '!kernel/src/graphics/**'
  '-g' '!kernel/src/integration/system_impl/virtio_gpu_init.rs'
  '-g' '!kernel/src/net/drivers/mlx5_registry.rs'
  '-g' '!kernel/src/net/runtime/bridge/mlx5_bridge.rs'
  '-g' '!kernel/src/shell/exoshell/namespaces/mlx5.rs'
  '-g' '!kernel/src/sync/poison_lock.rs'
  '-g' '!kernel/src/task/timer.rs'
  '-g' '!scripts/check-kernel-driver-boundary.sh'
)

pattern='\b(acpi|apic|ahci|blk|console|gpu|hda|hid|ide|input|mlx5|nvme|pci|rtc|serial|time|usb|virtio)_driver::'

if matches=$(rg -n "${exclude[@]}" -- "$pattern" kernel/src); then
  echo "ERROR: direct *_driver crate references remain outside the kernel provider boundary allowlist:"
  echo "$matches"
  exit 1
fi

echo "PASS: kernel driver boundary check passed."
