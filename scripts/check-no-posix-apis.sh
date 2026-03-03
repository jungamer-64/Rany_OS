#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v rg >/dev/null 2>&1; then
  echo "ERROR: rg is required for check-no-posix-apis.sh"
  exit 1
fi

check_no_match() {
  local label="$1"
  local pattern="$2"
  shift 2
  local paths=("$@")
  local matches
  matches="$(rg -n "$pattern" "${paths[@]}" || true)"
  if [ -n "$matches" ]; then
    echo "ERROR: Found forbidden ${label}:"
    echo "$matches"
    exit 1
  fi
}

# 1) legacy feature flag must not exist.
check_no_match "feature flag legacy-posix" '^\s*legacy-posix\s*=' kernel/Cargo.toml

# 2) Removed directory-based POSIX management surfaces.
check_no_match "procfs module usage" '\bprocfs\b' kernel/src filesystems
check_no_match "proc namespace calls" '\bproc\.' kernel/src/shell/exoshell

# 3) Removed POSIX compatibility entry-points in IPC + VM APIs.
check_no_match "pipe2 API" '\bpipe2\s*\(' kernel/src/ipc filesystems
check_no_match "mkfifo API" '\bmkfifo\s*\(' kernel/src/ipc filesystems
check_no_match "shmget API" '\bshmget\s*\(' kernel/src/ipc filesystems
check_no_match "shmat API" '\bshmat\s*\(' kernel/src/ipc filesystems
check_no_match "shm_open API" '\bshm_open\s*\(' kernel/src/ipc filesystems
check_no_match "mmap API" '\bmmap\s*\(' kernel/src/mm/virt filesystems
check_no_match "mmap_manager API" '\bmmap_manager\s*\(' kernel/src/mm/virt filesystems
check_no_match "Mmap* type names" '\bMmap[A-Za-z0-9_]*\b' kernel/src/mm/virt filesystems

echo "No forbidden POSIX compatibility surfaces found."
