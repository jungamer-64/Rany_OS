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
EVENT_GATE_RE = re.compile(
    r"\bbreak\b|\breturn\b|\.await\b|\bsleep\s*\(|yield[_A-Za-z0-9]*\s*\("
)
HALT_PROOF_RE = re.compile(r"spin_loop\s*\(|\bhlt\s*\(")
ASM_TEMPLATES_RE = re.compile(r'\basm!\s*\(\s*((?:"(?:\\.|[^"\\])*"\s*,?\s*)+)')
ASM_STRING_RE = re.compile(r'"((?:\\.|[^"\\])*)"')
BOUNDED_COMPARISON_RE = re.compile(r"(<=|>=|<|>|!=)")
IDENT_RE = re.compile(r"\b[_A-Za-z][_A-Za-z0-9]*\b")
LOOP_TOKEN_RE = re.compile(r"\b(?:while|loop)\b")
RESERVED_IDENTIFIERS = {
    "Self",
    "Ok",
    "Err",
    "None",
    "Some",
    "alloc",
    "as",
    "break",
    "const",
    "continue",
    "core",
    "crate",
    "else",
    "false",
    "for",
    "if",
    "let",
    "loop",
    "match",
    "mut",
    "return",
    "self",
    "static",
    "super",
    "true",
    "unsafe",
    "while",
}


@dataclass
class LoopToken:
    kind: str
    offset: int
    line: int
    column: int


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
                # Lifetimes and labels start with an apostrophe too. Only a
                # one-character identifier followed by a closing apostrophe
                # is a character literal; a lifetime must not mask later code.
                if i + 1 < n and (chars[i + 1].isalpha() or chars[i + 1] == "_"):
                    j = i + 2
                    while j < n and (chars[j].isalnum() or chars[j] == "_"):
                        j += 1
                    if j != i + 2 or j >= n or chars[j] != "'":
                        i = j
                        continue
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


def contains_halt_operation(body: str) -> bool:
    """Recognize a Rust halt primitive or a direct x86 HLT instruction.

    Match macro positions against masked code so a comment or diagnostic string
    mentioning inline assembly cannot satisfy the terminal-operation contract.
    """
    masked = mask_non_code(body)
    if HALT_PROOF_RE.search(masked) is not None:
        return True
    for match in ASM_TEMPLATES_RE.finditer(body):
        if not masked[match.start():].startswith("asm!"):
            continue
        for template in ASM_STRING_RE.finditer(match.group(1)):
            # Rust templates may contain multiple instructions or the macro
            # may have several templates. A comment/operand mention is not HLT.
            instructions = re.split(r";|\\n|\n", template.group(1))
            if any(instruction.split("#", 1)[0].strip().lower() == "hlt"
                   for instruction in instructions):
                return True
    return False


def find_tokens(masked: str) -> list[LoopToken]:
    starts = line_starts(masked)
    tokens: list[LoopToken] = []
    for m in LOOP_TOKEN_RE.finditer(masked):
        line = offset_to_line(m.start(), starts)
        tokens.append(
            LoopToken(
                kind=m.group(0),
                offset=m.start(),
                line=line,
                column=m.start() - starts[line - 1],
            )
        )
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


def loop_header(text: str, masked: str, token_offset: int) -> str | None:
    open_brace = masked.find("{", token_offset)
    if open_brace < 0:
        return None
    return text[token_offset:open_brace]


def bounded_progress_identifier(header: str) -> str | None:
    match = BOUNDED_COMPARISON_RE.search(header)
    if match is None:
        return None

    lhs = header[: match.start()]
    identifiers = [
        ident
        for ident in IDENT_RE.findall(lhs)
        if ident not in RESERVED_IDENTIFIERS and not ident.isupper()
    ]
    if not identifiers:
        return None
    return identifiers[-1]


def has_monotonic_update(body: str, ident: str) -> bool:
    escaped = re.escape(ident)
    patterns = [
        rf"\b{escaped}\b\s*(?:\+=|-=)\s*",
        rf"\b{escaped}\b\s*=\s*\b{escaped}\b\s*[+\-]",
        rf"\b{escaped}\b\s*=\s*\b{escaped}\b\s*\.(?:wrapping_add|wrapping_sub|saturating_add|saturating_sub|checked_add|checked_sub)\s*\(",
    ]
    return any(re.search(pattern, body) for pattern in patterns)


def check_file(path: Path, root: Path) -> list[CheckError]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    masked = mask_non_code(text)
    tokens = find_tokens(masked)
    errors: list[CheckError] = []

    for token in tokens:
        line_prefix = lines[token.line - 1][: token.column]
        if "//" in line_prefix:
            continue

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
        block = find_loop_block(masked, token.offset)
        header = loop_header(text, masked, token.offset)

        if mode == "condition":
            if token.kind != "while":
                errors.append(
                    CheckError(
                        path=path,
                        line=token.line,
                        message="mode=condition requires a while loop",
                    )
                )
            continue

        if mode == "event":
            if token.kind != "loop":
                errors.append(
                    CheckError(
                        path=path,
                        line=token.line,
                        message="mode=event requires a loop with explicit event-driven exits or yields",
                    )
                )
                continue
            if block is None:
                errors.append(
                    CheckError(
                        path=path,
                        line=token.line,
                        message="mode=event requires a braced loop body",
                    )
                )
                continue
            body = text[block[0] : block[1] + 1]
            if EVENT_GATE_RE.search(body) is None:
                errors.append(
                    CheckError(
                        path=path,
                        line=token.line,
                        message="mode=event requires break/return/.await/sleep()/yield in loop body",
                    )
                )
            continue

        if mode == "halt":
            if token.kind != "loop":
                errors.append(
                    CheckError(
                        path=path,
                        line=token.line,
                        message="mode=halt requires a loop that never returns",
                    )
                )
                continue
            if block is None:
                errors.append(
                    CheckError(
                        path=path,
                        line=token.line,
                        message="mode=halt requires a braced loop body",
                    )
                )
                continue
            body = text[block[0] : block[1] + 1]
            if not contains_halt_operation(body):
                errors.append(
                    CheckError(
                        path=path,
                        line=token.line,
                        message="mode=halt requires hlt()/spin_loop() or direct HLT assembly in loop body",
                    )
                )
            if re.search(r"\bbreak\b|\breturn\b", body):
                errors.append(
                    CheckError(
                        path=path,
                        line=token.line,
                        message="mode=halt cannot contain break/return in loop body",
                    )
                )
            continue

        if mode == "bounded":
            if token.kind != "while":
                errors.append(
                    CheckError(
                        path=path,
                        line=token.line,
                        message="mode=bounded currently requires a while loop with an explicit bound",
                    )
                )
                continue
            if block is None or header is None:
                errors.append(
                    CheckError(
                        path=path,
                        line=token.line,
                        message="mode=bounded requires a braced loop body",
                    )
                )
                continue

            progress_ident = bounded_progress_identifier(header)
            if progress_ident is None:
                errors.append(
                    CheckError(
                        path=path,
                        line=token.line,
                        message="mode=bounded requires an explicit comparison in the while condition",
                    )
                )
                continue

            body = text[block[0] : block[1] + 1]
            if not has_monotonic_update(body, progress_ident):
                errors.append(
                    CheckError(
                        path=path,
                        line=token.line,
                        message=f"mode=bounded requires monotonic updates to controlling variable '{progress_ident}'",
                    )
                )
            continue

        if mode == "fuel":
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
        if not base.is_dir():
            raise ValueError(f"loop proof target is not a directory: {name}")
        files.extend(sorted(base.rglob("*.rs")))
    return files


def run_check(root: Path, dirs: Iterable[str]) -> int:
    errors: list[CheckError] = []
    try:
        paths = collect_rs_files(root, dirs)
    except ValueError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    if not paths:
        print("FAIL: loop proof targets contain no Rust source", file=sys.stderr)
        return 1
    for path in paths:
        errors.extend(check_file(path, root))

    if errors:
        for error in errors:
            print(error.format(root))
        print(f"FAIL: loop boundary proof check found {len(errors)} violation(s)", file=sys.stderr)
        return 1

    print("PASS: loop boundary proof check passed")
    return 0


class LoopProofCheckerTests(unittest.TestCase):
    def test_verification_requires_directory_targets_with_rust_source(self) -> None:
        import contextlib
        import io
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "input.rs").write_text("fn main() {}", encoding="utf-8")
            (root / "empty").mkdir()
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(run_check(root, ["input.rs"]), 1)
                self.assertEqual(run_check(root, ["missing"]), 1)
                self.assertEqual(run_check(root, ["empty"]), 1)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run_check(root, ["."]), 0)

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

    def test_lifetimes_and_labels_do_not_hide_unannotated_loops(self) -> None:
        text = (
            "fn visit<'a>(value: &'a str, other: &'_ str) {\n"
            "    let character = 'a';\n"
            "    let escaped = '\\'';\n"
            "    let message = r#\"while loop\"#;\n"
            "    'again: loop { break 'again; }\n"
            "    while value.len() > other.len() { break; }\n"
            "}\n"
        )
        path = self.fixture_root / "lifetime_loops.rs"
        path.write_text(text, encoding="utf-8")
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        errors = check_file(path, self.root)
        self.assertEqual([error.line for error in errors], [5, 6])

    def test_bad_reason_fixture(self) -> None:
        errors = self.run_fixture("bad_reason.rs")
        self.assertTrue(errors)

    def test_fuel_without_gate_fixture(self) -> None:
        errors = self.run_fixture("fuel_missing_call.rs")
        self.assertTrue(errors)

    def test_fuel_with_gate_fixture(self) -> None:
        errors = self.run_fixture("fuel_ok.rs")
        self.assertEqual(errors, [])

    def test_event_fixture_requires_gate(self) -> None:
        errors = self.run_fixture("bad_event.rs")
        self.assertTrue(errors)

    def test_halt_fixture_accepts_spin(self) -> None:
        errors = self.run_fixture("ok_halt.rs")
        self.assertEqual(errors, [])

    def test_halt_fixture_rejects_escape_path(self) -> None:
        errors = self.run_fixture("bad_halt.rs")
        self.assertTrue(errors)

    def test_halt_accepts_direct_cpu_instruction(self) -> None:
        self.assertTrue(contains_halt_operation('unsafe { core::arch::asm!("hlt", options(nomem, nostack)); }'))

    def test_halt_accepts_interruptible_instruction_sequences(self) -> None:
        self.assertTrue(contains_halt_operation('unsafe { core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack)); }'))
        self.assertTrue(contains_halt_operation('unsafe { core::arch::asm!("sti; hlt; cli", options(nostack)); }'))
        self.assertTrue(contains_halt_operation(r'unsafe { core::arch::asm!("sti\nhlt\ncli", options(nostack)); }'))

    def test_halt_rejects_assembly_in_comments_and_strings(self) -> None:
        self.assertFalse(contains_halt_operation('// asm!("hlt", options(nostack));'))
        self.assertFalse(contains_halt_operation('let message = r#"asm!("hlt", options(nostack))"#;'))
        self.assertFalse(contains_halt_operation('// hlt(); spin_loop();'))
        self.assertFalse(contains_halt_operation('// asm!("sti", "hlt", "cli");'))
        self.assertFalse(contains_halt_operation('unsafe { asm!("# hlt", "nop"); }'))
        self.assertFalse(contains_halt_operation(r'unsafe { asm!(".ascii \"hlt\""); }'))

    def test_halt_rejects_nonhalting_cpu_instruction(self) -> None:
        self.assertFalse(contains_halt_operation('unsafe { core::arch::asm!("nop", options(nomem, nostack)); }'))

    def test_condition_fixture_rejects_unconditional_loop(self) -> None:
        errors = self.run_fixture("bad_condition_loop.rs")
        self.assertTrue(errors)

    def test_bounded_fixture_accepts_monotonic_progress(self) -> None:
        errors = self.run_fixture("bounded_ok.rs")
        self.assertEqual(errors, [])

    def test_bounded_fixture_rejects_missing_progress(self) -> None:
        errors = self.run_fixture("bounded_missing_update.rs")
        self.assertTrue(errors)

    def test_mask_non_code_preserves_escaped_newline_count(self) -> None:
        text = 'let _ = "hello\\\\\\nworld";\\nloop { break; }\\n'
        masked = mask_non_code(text)
        self.assertEqual(text.count("\n"), masked.count("\n"))

    def test_comment_token_is_not_reported(self) -> None:
        text = (
            "/// executor's polling loop is documented here\\n"
            "fn demo() {\\n"
            "    // LOOP_PROOF: mode=event; reason=Loop exits via explicit break once work completes.;\\n"
            "    loop {\\n"
            "        break;\\n"
            "    }\\n"
            "}\\n"
        )
        path = self.fixture_root / "comment_guard.rs"
        path.write_text(text, encoding="utf-8")
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        self.assertEqual(check_file(path, self.root), [])


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
