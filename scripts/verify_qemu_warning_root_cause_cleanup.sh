#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

KERNEL_QEMU_ROOT="$ROOT_DIR/kernel/src/qemu_tests.rs"
KERNEL_QEMU_SUB1="$ROOT_DIR/kernel/src/qemu_tests/wave8_net_tests.rs"
KERNEL_QEMU_SUB2="$ROOT_DIR/kernel/src/qemu_tests/wave8_net_tests/net_endpoint_tests.rs"
KERNEL_QEMU_SUB3="$ROOT_DIR/kernel/src/qemu_tests/wave8_net_tests/iommu_wave2_tests.rs"
SUITE_MAIN="$ROOT_DIR/qemu-suites/kernel/src/main.rs"
SUITE_SUB1="$ROOT_DIR/qemu-suites/kernel/src/iommu_wave3_tests.rs"
SUITE_SUB2="$ROOT_DIR/qemu-suites/kernel/src/iommu_wave3_tests/tls_wave8_tests.rs"

for f in \
  "$KERNEL_QEMU_ROOT" "$KERNEL_QEMU_SUB1" "$KERNEL_QEMU_SUB2" "$KERNEL_QEMU_SUB3" \
  "$SUITE_MAIN" "$SUITE_SUB1" "$SUITE_SUB2"
do
  if [[ ! -f "$f" ]]; then
    echo "[verify_qemu_warning_root_cause_cleanup] missing file: $f" >&2
    exit 1
  fi
done

python3 - "$KERNEL_QEMU_ROOT" "$KERNEL_QEMU_SUB1" "$KERNEL_QEMU_SUB2" "$KERNEL_QEMU_SUB3" "$SUITE_MAIN" "$SUITE_SUB1" "$SUITE_SUB2" <<'PY'
import re
import sys
from pathlib import Path

k_root, k_s1, k_s2, k_s3, s_main, s_s1, s_s2 = [Path(x) for x in sys.argv[1:]]

pub_fn_pat = re.compile(r'^pub fn ([A-Za-z0-9_]+)\(', re.M)
any_fn_pat = re.compile(r'^(?:pub\(crate\)\s+)?fn\s+([A-Za-z0-9_]+)\(', re.M)

k_root_names = set(pub_fn_pat.findall(k_root.read_text()))
k_sub_names = set()
for p in (k_s1, k_s2, k_s3):
    k_sub_names.update(pub_fn_pat.findall(p.read_text()))
k_dups = sorted(k_root_names & k_sub_names)

s_main_names = set(any_fn_pat.findall(s_main.read_text()))
s_sub_names = set()
for p in (s_s1, s_s2):
    s_sub_names.update(any_fn_pat.findall(p.read_text()))
s_dups = sorted(s_main_names & s_sub_names)

failed = False
if k_dups:
    failed = True
    print('[verify_qemu_warning_root_cause_cleanup] kernel qemu wrapper duplicates detected:')
    for n in k_dups:
        print(f'  - {n}')
if s_dups:
    failed = True
    print('[verify_qemu_warning_root_cause_cleanup] qemu_suite_kernel helper/group duplicates detected:')
    for n in s_dups:
        print(f'  - {n}')

if failed:
    sys.exit(1)
print('[verify_qemu_warning_root_cause_cleanup] PASS')
PY
