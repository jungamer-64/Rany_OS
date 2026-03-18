#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v rg >/dev/null 2>&1; then
  echo "ERROR: rg is required for check-exorust-reduction-guard.sh"
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

ACTIVE_DOCS=(
  README.md
  docs/ARCHITECTURE.md
  docs/API_REFERENCE.md
)

ACTIVE_MANIFESTS=(
  kernel/Cargo.toml
  tests/pure_tiers.toml
  tests/migration_case_map.toml
  drivers/usb/Cargo.toml
)

ACTIVE_CODE=(
  kernel/src
  interfaces
  filesystems/kernel_fs
  drivers/usb
  tools/standalone_driver_wrapper
)

check_no_match \
  "VFS surface references" \
  'filesystems/vfs|\bvfs_integration\b|\bvfs::' \
  "${ACTIVE_DOCS[@]}" "${ACTIVE_MANIFESTS[@]}" "${ACTIVE_CODE[@]}" .github/workflows

metadata_json="$(cargo metadata --format-version 1 --no-deps 2>/dev/null || true)"
if [ -z "$metadata_json" ]; then
  echo "ERROR: cargo metadata failed while checking workspace membership"
  failed=1
elif ! METADATA_JSON="$metadata_json" python3 - <<'PY'
import json
import os
import sys

data = json.loads(os.environ["METADATA_JSON"])
for item in data.get("workspace_members", []):
    if (
        "/filesystems/vfs#" in item
        or "/filesystems/vfs@" in item
        or "/filesystems/vfs" in item
        or "/filesystems/fat32#" in item
        or "/filesystems/fat32@" in item
        or "/filesystems/fat32" in item
        or "/filesystems/nvme_ns#" in item
        or "/filesystems/nvme_ns@" in item
        or "/filesystems/nvme_ns" in item
        or "/drivers/hda#" in item
        or "/drivers/hda@" in item
        or "/drivers/hda" in item
        or "/apps#" in item
        or "/apps@" in item
        or "/apps" in item
    ):
        sys.exit(1)
sys.exit(0)
PY
then
  echo "ERROR: removed filesystem/audio/app crates are still part of the Cargo workspace"
  failed=1
fi

check_no_match \
  "legacy fs_abstraction references" \
  '\bfs_abstraction\b' \
  "${ACTIVE_DOCS[@]}" "${ACTIVE_MANIFESTS[@]}" "${ACTIVE_CODE[@]}" .github/workflows

check_no_match \
  "legacy per-process VM references" \
  '\bProcessAddressSpace\b' \
  "${ACTIVE_DOCS[@]}" "${ACTIVE_MANIFESTS[@]}" "${ACTIVE_CODE[@]}" .github/workflows

check_no_match \
  "legacy fork API references" \
  '\bfork\s*\(' \
  "${ACTIVE_DOCS[@]}" "${ACTIVE_CODE[@]}" interfaces tests .github/workflows

check_no_match \
  "legacy exec API references" \
  '\bexec\s*\(' \
  "${ACTIVE_DOCS[@]}" "${ACTIVE_CODE[@]}" interfaces tests .github/workflows

check_no_match \
  "removed reclaim/swap shell namespaces" \
  '\basync_swapout\.|\breclaim\.' \
  "${ACTIVE_DOCS[@]}" kernel/src/shell tests .github/workflows

check_no_match \
  "boot-time demo runtime tasks" \
  '\bspawn_demo_runtime_tasks\b' \
  kernel/src/kernel_main kernel/src/kernel_content.rs docs "${ACTIVE_DOCS[@]}"

check_no_match \
  "boot-time auto HTTP startup" \
  'net::services::http::server::start_once\s*\(' \
  kernel/src/kernel_main docs "${ACTIVE_DOCS[@]}"

check_no_match \
  "removed application module references" \
  '\bmod application;|\bkernel/src/application\b|\bapplication/mod\.rs\b' \
  kernel/src interfaces docs "${ACTIVE_DOCS[@]}"

check_no_match \
  "removed GUI/audio/shell service reexports" \
  'service::(gui|graphics|audio|shell)\b' \
  kernel/src interfaces docs "${ACTIVE_DOCS[@]}"

check_no_match \
  "removed dual shell mode" \
  'BootShellMode::Both|ShellLaunchMode::Both' \
  kernel/src interfaces libs "${ACTIVE_DOCS[@]}"

check_no_match \
  "removed shell namespace modules referenced from code/docs" \
  'namespaces/(cap|fs|mlx5|shell|dynamic_driver)\.rs|namespaces::(cap|fs|mlx5|shell|dynamic_driver)\b|is_namespace\("(fs|cap|mlx5|shell)"\)|String::from\("(fs|cap|mlx5|shell)"\)|Unknown namespace: (fs|cap|mlx5|shell)|有効な名前空間:.*\b(fs|cap|mlx5|shell)\b' \
  kernel/src/shell/exoshell docs "${ACTIVE_DOCS[@]}"

mapfile -t DEVICE_BOUNDARY_FILES < <(
  rg --files kernel/src -g '*.rs' \
    | grep -Ev '^kernel/src/io/' \
    | grep -Ev '^kernel/src/drivers\.rs$' \
    | grep -Ev '^kernel/src/lib\.rs$'
)

if [ "${#DEVICE_BOUNDARY_FILES[@]}" -gt 0 ]; then
  check_no_match \
    "device-facing crate::io::* references outside the I/O framework" \
    'crate::io::(ahci|gpu|hid|ide|nvme|pci|serial|usb|virtio|acpi|apic)' \
    "${DEVICE_BOUNDARY_FILES[@]}"
fi

check_no_match \
  "crate root device reexports through crate::io::*" \
  'crate::io::(nvme|pci|acpi|apic|ahci|gpu|hid|ide|serial|usb|virtio)' \
  kernel/src/lib.rs

check_path_absent kernel/src/mm/virt/address_space.rs
check_path_absent kernel/src/mm/virt/cow.rs
check_path_absent kernel/src/mm/reclaim/async_swapout.rs
check_path_absent kernel/src/mm/reclaim/page_reclaim.rs
check_path_absent kernel/src/mm/reclaim/workingset.rs
check_path_absent kernel/src/mm/reclaim/zswap.rs
check_path_absent kernel/src/mm/reclaim/shrinker.rs
check_path_absent kernel/src/mm/async_swapout/qemu_tests.rs
check_path_absent kernel/src/mm/page_reclaim/qemu_tests.rs
check_path_absent kernel/src/shell/exoshell/namespaces/async_swapout.rs
check_path_absent kernel/src/shell/exoshell/namespaces/reclaim.rs
check_path_absent kernel/src/shell/exoshell/namespaces/cap.rs
check_path_absent kernel/src/shell/exoshell/namespaces/fs.rs
check_path_absent kernel/src/shell/exoshell/namespaces/mlx5.rs
check_path_absent kernel/src/shell/exoshell/namespaces/shell.rs
check_path_absent kernel/src/shell/exoshell/namespaces/dynamic_driver.rs
check_path_absent kernel/src/application/mod.rs
check_path_absent filesystems/fat32
check_path_absent filesystems/nvme_ns
check_path_absent filesystems/vfs
check_path_absent drivers/hda
check_path_absent kernel/src/io/audio

if [ "$failed" -ne 0 ]; then
  exit 1
fi

echo "PASS: reduced ExoRust surface remains aligned with the trimmed boot/runtime and API surface."
