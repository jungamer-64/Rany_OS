#!/usr/bin/env python3
"""Loop boundary proof static checker.

Enforces the repository-wide rule:

    // LOOP_PROOF: mode=<bounded|condition|event|fuel|halt>; reason=<concrete reason>;

immediately above every `while` / `loop` token in Rust source files.
"""

from __future__ import annotations

import argparse
import bisect
import re
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

TARGET_DIRS = [
    "kernel",
    "drivers",
    "filesystems",
    "interfaces",
    "apps",
    "libs",
    "bootloader",
    "hal",
    "tools",
]

ALLOWED_MODES = {"bounded", "condition", "event", "fuel", "halt"}
ANNOTATION_RE = re.compile(
    r"^\s*//\s*LOOP_PROOF:\s*mode=(bounded|condition|event|fuel|halt);\s*reason=([^;]+);\s*$"
)
BAD_REASON_RE = re.compile(r"\b(?:TODO|TBD|XXX)\b|\?\?\?", re.IGNORECASE)
FUEL_PROOF_RE = re.compile(r"check_fuel!|require_fuel\s*\(|Fuel::consume\s*\(")
LOOP_TOKEN_RE = re.compile(r"\b(?:while|loop)\b")


@dataclass
class LoopToken:
    kind: str
    offset: int
    line: int


@dataclass
class CheckError:
    path: Path
    line: int
    message: str

    def format(self, root: Path) -> str:
        rel = self.path.relative_to(root)
        return f"{rel}:{self.line}: {self.message}"


def line_starts(text: str) -> list[int]:
    starts = [0]
    for idx, ch in enumerate(text):
        if ch == "\n":
            starts.append(idx + 1)
    return starts


def offset_to_line(offset: int, starts: list[int]) -> int:
    return bisect.bisect_right(starts, offset)


def mask_non_code(text: str) -> str:
    chars = list(text)
    n = len(chars)
    i = 0
    state = "code"
    block_depth = 0
    raw_hashes = 0

    while i < n:
        ch = chars[i]

        if state == "code":
            if ch == "/" and i + 1 < n and chars[i + 1] == "/":
                chars[i] = " "
                chars[i + 1] = " "
                i += 2
                state = "line_comment"
                continue
            if ch == "/" and i + 1 < n and chars[i + 1] == "*":
                chars[i] = " "
                chars[i + 1] = " "
                i += 2
                state = "block_comment"
                block_depth = 1
                continue
            if ch == '"':
                chars[i] = " "
                i += 1
                state = "string"
                continue
            if ch == "'":
                chars[i] = " "
                i += 1
                state = "char"
                continue
            if ch == "r":
                j = i + 1
                hash_count = 0
                while j < n and chars[j] == "#":
                    hash_count += 1
                    j += 1
                if j < n and chars[j] == '"':
                    for k in range(i, j + 1):
                        chars[k] = " "
                    i = j + 1
                    state = "raw_string"
                    raw_hashes = hash_count
                    continue

            i += 1
            continue

        if state == "line_comment":
            if ch == "\n":
                state = "code"
                i += 1
            else:
                chars[i] = " "
                i += 1
            continue

        if state == "block_comment":
            if ch == "\n":
                i += 1
                continue
            chars[i] = " "
            if ch == "/" and i + 1 < n and chars[i + 1] == "*":
                chars[i + 1] = " "
                block_depth += 1
                i += 2
                continue
            if ch == "*" and i + 1 < n and chars[i + 1] == "/":
                chars[i + 1] = " "
                block_depth -= 1
                i += 2
                if block_depth == 0:
                    state = "code"
                continue
            i += 1
            continue

        if state == "string":
            if ch == "\\" and i + 1 < n:
                chars[i] = " "
                if chars[i + 1] != "\n":
                    chars[i + 1] = " "
                i += 2
                continue
            if ch == '"':
                chars[i] = " "
                i += 1
                state = "code"
                continue
            if ch != "\n":
                chars[i] = " "
            i += 1
            continue

        if state == "char":
            if ch == "\\" and i + 1 < n:
                chars[i] = " "
                if chars[i + 1] != "\n":
                    chars[i + 1] = " "
                i += 2
                continue
            if ch == "'":
                chars[i] = " "
                i += 1
                state = "code"
                continue
            if ch != "\n":
                chars[i] = " "
            i += 1
            continue

        if state == "raw_string":
            if ch == '"':
                j = i + 1
                count = 0
                while j < n and chars[j] == "#" and count < raw_hashes:
                    count += 1
                    j += 1
                if count == raw_hashes:
                    chars[i] = " "
                    for k in range(i + 1, j):
                        chars[k] = " "
                    i = j
                    state = "code"
                    continue
            if ch != "\n":
                chars[i] = " "
            i += 1
            continue

    return "".join(chars)


def find_tokens(masked: str) -> list[LoopToken]:
    starts = line_starts(masked)
    tokens: list[LoopToken] = []
    for m in LOOP_TOKEN_RE.finditer(masked):
        tokens.append(LoopToken(kind=m.group(0), offset=m.start(), line=offset_to_line(m.start(), starts)))
    return tokens


def parse_annotation(lines: list[str], loop_line: int) -> tuple[str, str] | None:
    idx = loop_line - 2
    while idx >= 0:
        content = lines[idx].strip()
        if not content:
            idx -= 1
            continue
        m = ANNOTATION_RE.match(lines[idx])
        if not m:
            return None
        mode = m.group(1)
        reason = m.group(2).strip()
        if mode not in ALLOWED_MODES:
            return None
        if not reason or BAD_REASON_RE.search(reason):
            return None
        return mode, reason
    return None


def find_loop_block(masked: str, token_offset: int) -> tuple[int, int] | None:
    open_brace = masked.find("{", token_offset)
    if open_brace < 0:
        return None

    depth = 0
    for idx in range(open_brace, len(masked)):
        ch = masked[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return open_brace, idx
    return None


def check_file(path: Path, root: Path) -> list[CheckError]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    masked = mask_non_code(text)
    tokens = find_tokens(masked)
    errors: list[CheckError] = []

    for token in tokens:
        annotation = parse_annotation(lines, token.line)
        if annotation is None:
            errors.append(
                CheckError(
                    path=path,
                    line=token.line,
                    message="missing/invalid LOOP_PROOF annotation immediately above loop",
                )
            )
            continue

        mode, _reason = annotation
        if mode != "fuel":
            continue

        block = find_loop_block(masked, token.offset)
        if block is None:
            errors.append(
                CheckError(
                    path=path,
                    line=token.line,
                    message="mode=fuel requires a braced loop body",
                )
            )
            continue

        body = text[block[0] : block[1] + 1]
        if FUEL_PROOF_RE.search(body) is None:
            errors.append(
                CheckError(
                    path=path,
                    line=token.line,
                    message="mode=fuel requires check_fuel!/require_fuel()/Fuel::consume() in loop body",
                )
            )

    return errors


def collect_rs_files(root: Path, dirs: Iterable[str]) -> list[Path]:
    files: list[Path] = []
    for name in dirs:
        base = root / name
        if not base.exists():
            continue
        files.extend(sorted(base.rglob("*.rs")))
    return files


def run_check(root: Path, dirs: Iterable[str]) -> int:
    errors: list[CheckError] = []
    for path in collect_rs_files(root, dirs):
        errors.extend(check_file(path, root))

    if errors:
        for error in errors:
            print(error.format(root))
        print(f"FAIL: loop boundary proof check found {len(errors)} violation(s)", file=sys.stderr)
        return 1

    print("PASS: loop boundary proof check passed")
    return 0


class LoopProofCheckerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1]
        self.fixture_root = self.root / "scripts" / "testdata" / "loop_proof"

    def run_fixture(self, fixture: str) -> list[CheckError]:
        return check_file(self.fixture_root / fixture, self.root)

    def test_valid_condition_fixture(self) -> None:
        errors = self.run_fixture("ok_condition.rs")
        self.assertEqual(errors, [])

    def test_missing_annotation_fixture(self) -> None:
        errors = self.run_fixture("missing_annotation.rs")
        self.assertTrue(errors)

    def test_bad_reason_fixture(self) -> None:
        errors = self.run_fixture("bad_reason.rs")
        self.assertTrue(errors)

    def test_fuel_without_gate_fixture(self) -> None:
        errors = self.run_fixture("fuel_missing_call.rs")
        self.assertTrue(errors)

    def test_fuel_with_gate_fixture(self) -> None:
        errors = self.run_fixture("fuel_ok.rs")
        self.assertEqual(errors, [])

    def test_mask_non_code_preserves_escaped_newline_count(self) -> None:
        text = 'let _ = "hello\\\\\\nworld";\\nloop { break; }\\n'
        masked = mask_non_code(text)
        self.assertEqual(text.count("\n"), masked.count("\n"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Check LOOP_PROOF annotations for while/loop")
    parser.add_argument("--self-test", action="store_true", help="run script unit tests")
    parser.add_argument("--dir", action="append", default=[], help="override target directories")
    args = parser.parse_args()

    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(LoopProofCheckerTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1

    root = Path(__file__).resolve().parents[1]
    dirs = args.dir if args.dir else TARGET_DIRS
    return run_check(root, dirs)


if __name__ == "__main__":
    raise SystemExit(main())
