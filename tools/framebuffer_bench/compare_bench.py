#!/usr/bin/env python3
"""Compare current Criterion bench medians against stored baseline.

If any median exceeds the baseline by the provided threshold (fraction), the
script exits with status 1 to indicate a regression.
"""
import json
import os
import sys
from pathlib import Path

import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--baseline", default="BENCH_BASELINE.json")
parser.add_argument("--criterion-dir", default="target/criterion")
parser.add_argument("--threshold", type=float, default=0.10, help="allowed regression fraction (e.g. 0.10 = 10 percent)")
args = parser.parse_args()

root = Path(__file__).parent
baseline_path = root / args.baseline
crit_dir = Path(args.criterion_dir)

if not baseline_path.exists():
    print(f"Baseline file {baseline_path} not found", file=sys.stderr)
    sys.exit(2)

with open(baseline_path, "r", encoding="utf-8") as f:
    baseline = json.load(f)

failed = False
for name, base_val in baseline.items():
    bench_path = crit_dir / name / "new" / "estimates.json"
    if not bench_path.exists():
        print(f"Bench result for '{name}' not found at {bench_path}")
        failed = True
        continue

    with open(bench_path, "r", encoding="utf-8") as bf:
        data = json.load(bf)

    median = None
    try:
        median = data["median"]["point_estimate"]
    except Exception:
        print(f"Unexpected estimates.json format for '{name}'", file=sys.stderr)
        failed = True
        continue

    ratio = median / float(base_val)
    pct = (ratio - 1.0) * 100.0
    print(f"{name}: baseline={base_val:.3f} ns  current={median:.3f} ns  change={pct:+.2f}%")

    if ratio > 1.0 + args.threshold:
        print(f"REGRESSION: '{name}' exceeded threshold (+{args.threshold*100:.1f}%).", file=sys.stderr)
        failed = True

if failed:
    sys.exit(1)
print("All benchmarks within baseline thresholds.")
sys.exit(0)
