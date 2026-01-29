#!/usr/bin/env bash
set -euo pipefail

ALLOW_RE='kernel/src/(compat/|fs/procfs/|task/process\.rs|task/mod\.rs|lib\.rs)'

if command -v rg >/dev/null 2>&1; then
  matches=$(rg -n --glob 'kernel/src/**/*.rs' '\bProcessId\b' kernel/src || true)
  if [ -z "${matches}" ]; then
    echo "ProcessId: no matches"
    exit 0
  fi
  filtered=$(echo "${matches}" | rg -v "${ALLOW_RE}" || true)
else
  matches=$(grep -RIn --include='*.rs' 'ProcessId' kernel/src || true)
  if [ -z "${matches}" ]; then
    echo "ProcessId: no matches"
    exit 0
  fi
  filtered=$(echo "${matches}" | grep -Ev "${ALLOW_RE}" || true)
fi

if [ -n "${filtered}" ]; then
  echo "ProcessId found outside allowlist:"
  echo "${filtered}"
  exit 1
fi

echo "ProcessId usage limited to allowlist."
