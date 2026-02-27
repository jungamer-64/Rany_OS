#!/usr/bin/env python3
from __future__ import annotations

import json
import re
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
VALID_MIGRATION_DEST_KINDS = {"crate-test", "qemu-fullboot", "dropped"}
VALID_MIGRATION_CLASSIFICATIONS = {"pure", "qemu_fullboot", "dropped"}
BANNED_MIGRATION_CASE_TAGS = {"pending", "runtime_pending"}
BANNED_PURE_RS_RE = re.compile(r"\b(qemu_tests|qemu_smoke_tests)\b")
BANNED_PURE_CARGO_RE = re.compile(r"\bqemu-test-export\b")
BANNED_WORKFLOW_PURE_TEST_RE = re.compile(r"cargo\s+test\s+-p\s+([A-Za-z0-9_-]+)")
BANNED_QEMU_SUITE_CMD_RE = re.compile(
    r"cargo\s+test\s+-p\s+qemu-tests[^\n]*\bsuite_(?:core|drivers|fs|kernel|graphics|tools)\b"
)


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


def tracked_python_cache_files(root: Path) -> list[str]:
    proc = subprocess.run(
        [
            "git",
            "ls-files",
            "--",
            "*.pyc",
            "*/__pycache__/*",
        ],
        cwd=root,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "git ls-files failed")
    return [line for line in proc.stdout.splitlines() if line]


def workflow_hardcoded_pure_tests(
    root: Path, pure_package_names: set[str]
) -> list[tuple[Path, int, str]]:
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.exists():
        return []

    findings: list[tuple[Path, int, str]] = []
    for path in sorted(workflow_dir.glob("*.yml")) + sorted(workflow_dir.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        for match in BANNED_WORKFLOW_PURE_TEST_RE.finditer(text):
            package = match.group(1)
            if package not in pure_package_names:
                continue
            line = text.count("\n", 0, match.start()) + 1
            findings.append((path.relative_to(root), line, package))
    return findings


def stale_qemu_suite_command_refs(root: Path) -> list[tuple[Path, int, str]]:
    candidates: list[Path] = [root / "README.md"]
    candidates.extend((root / "docs").rglob("*.md"))
    candidates.extend((root / "tools").rglob("*.md"))

    findings: list[tuple[Path, int, str]] = []
    for path in sorted({p for p in candidates if p.exists()}):
        text = path.read_text(encoding="utf-8")
        for match in BANNED_QEMU_SUITE_CMD_RE.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append((path.relative_to(root), line, match.group(0)))
    return findings


def validate_migration_case_map(root: Path, pure_package_names: set[str]) -> str | None:
    migration = load_toml(root / "tests" / "migration_case_map.toml")

    if migration.get("version") != 2:
        return "migration_case_map.toml version must be 2"
    if migration.get("strategy") != "2-layer":
        return "migration_case_map.toml strategy must be '2-layer'"
    if migration.get("pure_mode") != "crate-local-std-tests":
        return "migration_case_map.toml pure_mode must be 'crate-local-std-tests'"

    cases = migration.get("case")
    if not isinstance(cases, list) or not cases:
        return "migration_case_map.toml must contain at least one [[case]]"

    seen_ids: set[str] = set()
    for idx, case in enumerate(cases):
        if not isinstance(case, dict):
            return f"migration case[{idx}] must be a table"

        for key in ("id", "source", "classification", "reason", "destination"):
            if key not in case:
                return f"migration case[{idx}] missing key: {key}"

        case_id = case["id"]
        if not isinstance(case_id, str) or not case_id:
            return f"migration case[{idx}] id must be a non-empty string"
        if case_id in seen_ids:
            return f"migration case[{idx}] duplicate id: {case_id}"
        seen_ids.add(case_id)

        if any(tag in case_id for tag in BANNED_MIGRATION_CASE_TAGS):
            return f"migration case[{idx}] id contains banned legacy tag: {case_id}"

        source = case["source"]
        if not isinstance(source, str) or not source:
            return f"migration case[{idx}] source must be a non-empty string"

        classification = case["classification"]
        if classification not in VALID_MIGRATION_CLASSIFICATIONS:
            return (
                f"migration case[{idx}] invalid classification: {classification} "
                f"(allowed: {sorted(VALID_MIGRATION_CLASSIFICATIONS)})"
            )

        reason = case["reason"]
        if not isinstance(reason, str) or not reason.strip():
            return f"migration case[{idx}] reason must be a non-empty string"
        if any(tag in reason for tag in BANNED_MIGRATION_CASE_TAGS):
            return f"migration case[{idx}] reason contains banned legacy tag"

        destination = case["destination"]
        if not isinstance(destination, dict):
            return f"migration case[{idx}] destination must be a table"
        for key in ("kind", "package", "test_filter"):
            if key not in destination:
                return f"migration case[{idx}] destination missing key: {key}"

        dest_kind = destination["kind"]
        if dest_kind not in VALID_MIGRATION_DEST_KINDS:
            return (
                f"migration case[{idx}] invalid destination.kind: {dest_kind} "
                f"(allowed: {sorted(VALID_MIGRATION_DEST_KINDS)})"
            )

        dest_package = destination["package"]
        dest_test_filter = destination["test_filter"]
        if not isinstance(dest_package, str):
            return f"migration case[{idx}] destination.package must be a string"
        if not isinstance(dest_test_filter, str):
            return f"migration case[{idx}] destination.test_filter must be a string"

        if classification == "pure":
            if case.get("tier") not in VALID_TIERS:
                return f"migration case[{idx}] pure case must set tier in {sorted(VALID_TIERS)}"
            if not isinstance(case.get("root_default"), bool):
                return f"migration case[{idx}] pure case must set boolean root_default"
            if dest_kind != "crate-test":
                return f"migration case[{idx}] pure case must use destination.kind=crate-test"
            if dest_package not in pure_package_names:
                return (
                    f"migration case[{idx}] pure destination.package '{dest_package}' "
                    "must be listed in tests/pure_tiers.toml [[package]].name"
                )

        elif classification == "qemu_fullboot":
            profiles = case.get("profiles")
            if not isinstance(profiles, list) or not profiles or not all(
                isinstance(v, str) and v for v in profiles
            ):
                return f"migration case[{idx}] qemu_fullboot case must define non-empty profiles"
            if dest_kind != "qemu-fullboot":
                return f"migration case[{idx}] qemu_fullboot case must use destination.kind=qemu-fullboot"
            if dest_package != "qemu-tests":
                return (
                    f"migration case[{idx}] qemu_fullboot destination.package must be 'qemu-tests'"
                )
            if not dest_test_filter:
                return (
                    f"migration case[{idx}] qemu_fullboot destination.test_filter must be non-empty"
                )

        elif classification == "dropped":
            if dest_kind != "dropped":
                return f"migration case[{idx}] dropped case must use destination.kind=dropped"
            if dest_package or dest_test_filter:
                return (
                    f"migration case[{idx}] dropped case must keep destination.package/test_filter empty"
                )

    return None


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
    try:
        pycache_files = tracked_python_cache_files(root)
    except RuntimeError as e:
        return fail(str(e))
    if pycache_files:
        return fail(
            "tracked python cache files must be removed: "
            + ", ".join(pycache_files)
        )

    package_names = {pkg["name"] for pkg in md["packages"]}
    pure_package_names = {entry["name"] for entry in pkg_entries}
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

    migration_error = validate_migration_case_map(root, pure_package_names)
    if migration_error:
        return fail(migration_error)

    workflow_findings = workflow_hardcoded_pure_tests(root, pure_package_names)
    if workflow_findings:
        details = ", ".join(
            f"{path}:{line} (package={package})"
            for path, line, package in workflow_findings
        )
        return fail(
            "workflow must not hardcode pure package tests via `cargo test -p`; "
            "use scripts/run_pure_tier.py instead: " + details
        )

    stale_suite_refs = stale_qemu_suite_command_refs(root)
    if stale_suite_refs:
        details = ", ".join(f"{path}:{line}" for path, line, _ in stale_suite_refs)
        return fail(
            "documentation contains legacy qemu-tests suite_* commands; "
            "use full-boot profiles instead: " + details
        )

    # Pure tier regression guard:
    # root-default pure packages must not reintroduce qemu-test-export wrappers.
    for member_path in root_default["packages"]:
        pkg_root = (root / member_path).resolve()
        cargo_toml = pkg_root / "Cargo.toml"
        if not cargo_toml.exists():
            return fail(f"missing Cargo.toml for root_default package path: {member_path}")

        cargo_text = cargo_toml.read_text(encoding="utf-8")
        if BANNED_PURE_CARGO_RE.search(cargo_text):
            return fail(
                f"root_default package '{member_path}' reintroduced banned token "
                f"'qemu-test-export' in {cargo_toml.relative_to(root)}"
            )

        for rs_path in pkg_root.rglob("*.rs"):
            rs_text = rs_path.read_text(encoding="utf-8")
            if BANNED_PURE_RS_RE.search(rs_text):
                return fail(
                    f"root_default package '{member_path}' reintroduced banned test wrapper token "
                    f"in {rs_path.relative_to(root)}"
                )

    print("[verify_pure_tier_map] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
