#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required for check-adr-structure-guard.sh"
  exit 1
fi

mapfile -t ADR_FILES < <(find docs/decisions -maxdepth 1 -type f -name 'ADR-*.md' | sort)

if [ "${#ADR_FILES[@]}" -eq 0 ]; then
  echo "ERROR: no ADR files found under docs/decisions"
  exit 1
fi

failed=0

required_headers=(
  "- Status:"
  "- Audience:"
  "- Related:"
  "- Supersedes:"
  "- Superseded-By:"
  "- Date:"
)

required_sections=(
  "## Context"
  "## Decision"
  "## Consequences"
  "## Alternatives Considered"
)

for file in "${ADR_FILES[@]}"; do
  for header in "${required_headers[@]}"; do
    if ! grep -qF -- "$header" "$file"; then
      echo "ERROR: missing header '$header' in $file"
      failed=1
    fi
  done

  for section in "${required_sections[@]}"; do
    if ! grep -qF "$section" "$file"; then
      echo "ERROR: missing section '$section' in $file"
      failed=1
    fi
  done
done

if ! python3 - <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

root = Path.cwd().resolve()
decisions_dir = root / "docs" / "decisions"
adr_files = sorted(decisions_dir.glob("ADR-*.md"))

ok = True

number_pattern = re.compile(r"^ADR-(\d{4})-[a-z0-9-]+\.md$")
nums: list[int] = []

for adr in adr_files:
    matched = number_pattern.match(adr.name)
    if matched is None:
        print(f"ERROR: invalid ADR file name format: {adr.relative_to(root)}")
        ok = False
        continue
    nums.append(int(matched.group(1)))

if nums:
    expected = list(range(1, len(nums) + 1))
    if nums != expected:
        print(
            "ERROR: ADR numbering is not sequential from ADR-0001. "
            f"found={nums}, expected={expected}"
        )
        ok = False

link_pattern = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
skip_prefixes = ("http://", "https://", "mailto:", "#")

files_for_link_check = adr_files + [
    decisions_dir / "README.md",
    decisions_dir / "_template.md",
    decisions_dir / "archive" / "README.md",
]

for md_file in files_for_link_check:
    if not md_file.exists():
        print(f"ERROR: required file missing for ADR checks: {md_file.relative_to(root)}")
        ok = False
        continue

    content = md_file.read_text(encoding="utf-8")
    for target in link_pattern.findall(content):
        if target.startswith(skip_prefixes):
            continue

        target_no_anchor = target.split("#", 1)[0]
        if target_no_anchor == "":
            continue

        resolved = (md_file.parent / target_no_anchor).resolve()
        if not resolved.exists():
            print(
                "ERROR: broken relative link in "
                f"{md_file.relative_to(root)} -> {target}"
            )
            ok = False

if not ok:
    sys.exit(1)

print("PASS: ADR numbering, mandatory sections, and relative links are valid.")
PY
then
  failed=1
fi

if [ "$failed" -ne 0 ]; then
  exit 1
fi

echo "PASS: ADR structure guard is aligned with the repository policy."
