#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path

VALID_TIERS = {"pr-required", "nightly-required"}
REQUIRED_PACKAGE_KEYS = {
    "name",
    "tier",
    "root_default",
    "run_ignored",
    "test_filter",
    "exact",
    "serial",
}
OPTIONAL_PACKAGE_KEYS = {"features"}


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def load_toml(path: Path) -> dict:
    with path.open("rb") as f:
        return tomllib.load(f)


def fail(msg: str) -> int:
    print(f"[verify_pure_tier_map] FAIL: {msg}", file=sys.stderr)
    return 1


def cargo_metadata(root: Path) -> dict:
    proc = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "cargo metadata failed")
    return json.loads(proc.stdout)


def main() -> int:
    root = repo_root()
    pure_map = load_toml(root / "tests" / "pure_tiers.toml")
    cargo_root = load_toml(root / "Cargo.toml")

    if pure_map.get("schema_version") != 1:
        return fail("schema_version must be 1")

    root_default = pure_map.get("root_default")
    if not isinstance(root_default, dict) or not isinstance(root_default.get("packages"), list):
        return fail("root_default.packages must be a list")

    pkg_entries = pure_map.get("package")
    if not isinstance(pkg_entries, list):
        return fail("[[package]] entries are missing")

    workspace = cargo_root.get("workspace", {})
    default_members = workspace.get("default-members")
    if root_default["packages"] != default_members:
        return fail("root_default.packages must exactly match Cargo.toml workspace.default-members")

    try:
        md = cargo_metadata(root)
    except RuntimeError as e:
        return fail(str(e))

    package_names = {pkg["name"] for pkg in md["packages"]}
    lib_target_names = {}
    for pkg in md["packages"]:
        for target in pkg.get("targets", []):
            if "lib" in target.get("kind", []):
                lib_target_names[pkg["name"]] = target["name"]
                break

    seen = set()
    for idx, entry in enumerate(pkg_entries):
        entry_keys = set(entry.keys())
        missing = REQUIRED_PACKAGE_KEYS - entry_keys
        if missing:
            return fail(f"package[{idx}] missing keys: {sorted(missing)}")
        unknown = entry_keys - REQUIRED_PACKAGE_KEYS - OPTIONAL_PACKAGE_KEYS
        if unknown:
            return fail(f"package[{idx}] unknown keys: {sorted(unknown)}")
        if entry["tier"] not in VALID_TIERS:
            return fail(f"package[{idx}] invalid tier: {entry['tier']}")
        if entry["name"] not in package_names:
            return fail(f"package[{idx}] unknown package name: {entry['name']}")
        features = entry.get("features", [])
        if not isinstance(features, list) or not all(isinstance(v, str) and v for v in features):
            return fail(f"package[{idx}] features must be a list of non-empty strings")
        key = (
            entry["name"],
            entry["tier"],
            entry["test_filter"],
            entry["run_ignored"],
            tuple(features),
        )
        if key in seen:
            return fail(f"duplicate package entry: {key}")
        seen.add(key)

    pure_tests_src = (root / "pure-tests" / "src" / "lib.rs").read_text(encoding="utf-8")
    migrated_lib_crates = {
        lib_target_names[e["name"]]
        for e in pkg_entries
        if e["name"] != "pure_tests" and e["name"] in lib_target_names
    }
    for crate_name in sorted(migrated_lib_crates):
        needle = f"{crate_name}::qemu_tests::"
        if needle in pure_tests_src:
            return fail(f"pure-tests residual must not call migrated wrapper exports: '{needle}'")

    print("[verify_pure_tier_map] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
