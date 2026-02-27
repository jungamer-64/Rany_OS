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
    workspace_root = Path(md["workspace_root"]).resolve()
    workspace_member_ids = set(md.get("workspace_members", []))
    member_path_to_name = {}
    for pkg in md["packages"]:
        if pkg["id"] not in workspace_member_ids:
            continue
        manifest_path = Path(pkg["manifest_path"]).resolve()
        try:
            member_rel = manifest_path.parent.relative_to(workspace_root).as_posix()
        except ValueError:
            continue
        member_path_to_name[member_rel] = pkg["name"]

    root_default_name_set = set()
    for member_path in root_default["packages"]:
        pkg_name = member_path_to_name.get(member_path)
        if pkg_name is None:
            return fail(f"root_default.packages contains unknown workspace member path: {member_path}")
        root_default_name_set.add(pkg_name)

    seen = set()
    root_default_entry_names = set()
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
        if entry["root_default"] and entry["name"] not in root_default_name_set:
            return fail(
                f"package[{idx}] has root_default=true but package '{entry['name']}' is not in root_default.packages"
            )
        if entry["root_default"]:
            root_default_entry_names.add(entry["name"])
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

    missing_root_default_entries = sorted(root_default_name_set - root_default_entry_names)
    if missing_root_default_entries:
        return fail(
            "root_default.packages contain packages without any root_default=true [[package]] entry: "
            + ", ".join(missing_root_default_entries)
        )

    print("[verify_pure_tier_map] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
