#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tomllib
from pathlib import Path

VALID_TIERS = ("pr-required", "nightly-required")


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def load_config() -> dict:
    path = repo_root() / "tests" / "pure_tiers.toml"
    with path.open("rb") as f:
        return tomllib.load(f)


def tier_allows(requested: str, entry_tier: str) -> bool:
    if requested == "pr-required":
        return entry_tier == "pr-required"
    # nightly tier is inclusive (expanded run).
    return entry_tier in VALID_TIERS


def build_cargo_cmd(entry: dict, include_ignored: bool) -> list[str] | None:
    if entry["run_ignored"] and not include_ignored:
        return None

    cmd = ["cargo", "test", "-p", entry["name"]]
    features = entry.get("features", [])
    if features:
        cmd.extend(["--features", ",".join(features)])
    if entry["test_filter"]:
        cmd.append(entry["test_filter"])

    test_args: list[str] = ["--nocapture"]
    if entry["run_ignored"]:
        test_args.insert(0, "--ignored")
    if entry["exact"]:
        test_args.insert(0, "--exact")
    if entry["serial"]:
        test_args.append("--test-threads=1")

    cmd.append("--")
    cmd.extend(test_args)
    return cmd


def main() -> int:
    parser = argparse.ArgumentParser(description="Run pure host/std tier from tests/pure_tiers.toml")
    parser.add_argument("--tier", required=True, choices=VALID_TIERS)
    parser.add_argument("--include-ignored", action="store_true")
    args = parser.parse_args()

    cfg = load_config()
    if cfg.get("schema_version") != 1:
        print("[pure-tier] unsupported schema_version", file=sys.stderr)
        return 2

    entries = cfg.get("package", [])
    if not isinstance(entries, list):
        print("[pure-tier] invalid package table shape", file=sys.stderr)
        return 2

    root = repo_root()
    for entry in entries:
        if not tier_allows(args.tier, entry["tier"]):
            continue

        cmd = build_cargo_cmd(entry, args.include_ignored)
        if cmd is None:
            print(
                f"[pure-tier] skip package={entry['name']} filter={entry['test_filter'] or '*'} "
                f"(requires --include-ignored)"
            )
            continue

        label = entry["test_filter"] or "*"
        feat_label = ",".join(entry.get("features", [])) or "-"
        print(
            f"[pure-tier] run tier={args.tier} package={entry['name']} "
            f"filter={label} features={feat_label}"
        )
        env = os.environ.copy()
        # Default serial execution for package-local test threads can still be overridden.
        if entry["serial"]:
            env.setdefault("RUST_TEST_THREADS", "1")
        proc = subprocess.run(cmd, cwd=root, env=env)
        if proc.returncode != 0:
            print(
                f"[pure-tier] FAIL package={entry['name']} filter={label} exit={proc.returncode}",
                file=sys.stderr,
            )
            return proc.returncode

    print(f"[pure-tier] PASS tier={args.tier}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
