#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v rg >/dev/null 2>&1; then
  echo "ERROR: rg is required for check-kernel-structure-guard.sh"
  exit 1
fi

failed=0

check_no_match() {
  local label="$1"
  local pattern="$2"
  shift 2
  local matches
  matches="$(rg -n -e "$pattern" "$@" || true)"
  if [ -n "$matches" ]; then
    echo "ERROR: Found forbidden ${label}:"
    echo "$matches"
    failed=1
  fi
}

check_path_absent() {
  local path="$1"
  if [ -e "$path" ]; then
    echo "ERROR: Removed path reintroduced: $path"
    failed=1
  fi
}

workspace_member_paths=(
  qemu-tests
  tools/qemu_runner
  kernel
  hal
  interfaces/kernel_api
  libs/app_sdk
  libs/ap_trampoline
  libs/security
  libs/boot_config
  libs/graphic_types
  libs/sync
  libs/boot_proto
  drivers/pci
  drivers/ahci
  drivers/usb
  drivers/nvme
  drivers/serial
  drivers/hid
  drivers/virtio
  drivers/acpi
  drivers/rtc
  drivers/ide
  drivers/time
  drivers/example_abi
  drivers/mlx5
  bootloader
  tools/driver_cell_probe
  tools/driver_pack_builder
  tools/standalone_driver_wrapper
  tools/cap_harness
)

check_no_match \
  "dead/unused warning suppression in workspace members" \
  '#!?\[(allow\([^]]*\b(dead_code|warnings|unused(_[[:alnum:]_]+)?)\b|cfg_attr\([^]]*allow\([^]]*\b(dead_code|warnings|unused(_[[:alnum:]_]+)?)\b)' \
  --glob '*.rs' "${workspace_member_paths[@]}"

check_no_match \
  "kernel_content include! usage" \
  'include!\s*\(\s*"kernel_content\.rs"\s*\)' \
  kernel/src

check_no_match \
  "cross-tree filesystems/kernel_fs path includes" \
  '#\[path\s*=\s*"\.\./\.\./filesystems/kernel_fs/mod\.rs"\s*\]' \
  kernel/src

check_no_match \
  "cross-tree path includes under kernel/src" \
  '#\[path\s*=\s*"\.\./\.\./(filesystems|drivers|interfaces|libs|bootloader|tools|apps)/' \
  kernel/src

check_no_match \
  "inline crate-root host shims in lib.rs" \
  '^\s*(pub\s+)?mod\s+(mm|per_cpu|ipc|smp|cpu|task|io)\s*\{' \
  kernel/src/lib.rs

check_no_match \
  "legacy root memory/domain modules in lib.rs" \
  '^\s*pub\s+mod\s+(memory|domain_system)\s*;' \
  kernel/src/lib.rs

check_no_match \
  "legacy root service/runtime modules in lib.rs" \
  '^\s*pub\s+mod\s+(service_impl|runtime_bridge)\s*;' \
  kernel/src/lib.rs

check_no_match \
  "legacy canonical names in architecture docs" \
  'crate::(memory|domain_system)|\bmemory::init\(\)|\bdomain_system::' \
  docs/architecture.md docs/kernel-boot-sequence.md

check_no_match \
  "legacy kapi/resource registry names in source and docs" \
  'crate::(service_impl|runtime_bridge)|\bservice_impl::|\bruntime_bridge::' \
  kernel/src docs tools .github

check_path_absent kernel/src/kernel_content.rs
check_path_absent kernel/src/memory.rs
check_path_absent kernel/src/domain_system.rs
check_path_absent kernel/src/memory
check_path_absent kernel/src/domain_system

if [ ! -d kernel/src/boot ]; then
  echo "ERROR: canonical boot/ module directory is missing"
  failed=1
fi

if [ ! -d kernel/src/fs ]; then
  echo "ERROR: canonical fs/ module directory is missing"
  failed=1
fi

if [ ! -d kernel/src/heap ]; then
  echo "ERROR: canonical heap/ module directory is missing"
  failed=1
fi

if [ "$failed" -ne 0 ]; then
  exit 1
fi

echo "PASS: kernel structure guard confirms canonical boot/fs/heap layout and lib.rs boundaries."
