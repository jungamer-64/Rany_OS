#!/usr/bin/env python3
"""
Check ELF sections and program headers for overlapping file offsets.

Usage:
    python scripts/check_linker_layout.py [path/to/binary]

If no path is provided, searches target/*/debug and target/*/release for the first ELF executable.
Returns exit code 0 on success (no overlaps), non-zero on failure.
"""
import argparse
import os
import sys
from typing import Tuple

import subprocess
try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    print("pyelftools not found, attempting to install via pip...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyelftools"])  # noqa: S603
        from elftools.elf.elffile import ELFFile
    except (subprocess.CalledProcessError, ImportError) as e:
        print("Error: pyelftools not installed and automatic install failed. Please run 'pip install pyelftools' and try again.")
        sys.exit(2)


def _is_elf_file(path: str) -> bool:
    """Return True if *path* starts with the ELF magic bytes."""
    try:
        with open(path, 'rb') as fh:
            return fh.read(4) == b'\x7fELF'
    except Exception:
        return False


def _collect_elf_candidates() -> list:
    """Walk *target/* and return paths to every ELF file found."""
    candidates = []
    for root, _dirs, files in os.walk('target'):
        for f in files:
            path = os.path.join(root, f)
            if _is_elf_file(path):
                candidates.append(path)
    return candidates


_KERNEL_KEYWORDS = ('exorust', 'rany', 'kernel')


def _pick_preferred(candidates: list) -> str:
    """Pick the preferred ELF from *candidates*, favouring debug kernel builds."""
    for p in candidates:
        name = os.path.basename(p).lower()
        if any(kw in name for kw in _KERNEL_KEYWORDS):
            if '/debug/' in p.replace('\\', '/'):
                return p
    return candidates[0] if candidates else ''


def find_candidate_binary() -> str:
    candidates = _collect_elf_candidates()
    return _pick_preferred(candidates)


def ranges_overlap(a: Tuple[int, int], b: Tuple[int, int]) -> bool:
    a0, a1 = a
    b0, b1 = b
    return a0 < b1 and b0 < a1


Section = Tuple[str, int, int, int, str, int]  # (name, start, end, flags, sh_type, idx)

_SHF_ALLOC = 0x2


def _gather_sections(elf) -> list:
    """Collect non-empty, file-backed sections from *elf*."""
    secs: list[Section] = []
    for idx, sec in enumerate(elf.iter_sections()):
        sh_type = sec['sh_type']
        sh_size = sec['sh_size']
        if sh_type == 'SHT_NOBITS' or sh_size == 0:
            continue
        start = sec['sh_offset']
        secs.append((sec.name, start, start + sh_size, sec['sh_flags'], sh_type, idx))
    secs.sort(key=lambda s: s[1])
    return secs


def _gather_pt_loads(elf) -> list:
    """Collect file-offset ranges for every PT_LOAD segment."""
    loads = []
    for seg in elf.iter_segments():
        p_type = seg.header.p_type
        if p_type in ('PT_LOAD', 1):
            p_offset = seg.header.p_offset
            loads.append((p_offset, p_offset + seg.header.p_filesz))
    return loads


def _check_section_overlaps(secs: list) -> int:
    """Return the number of adjacent-section overlaps found."""
    errors = 0
    for i in range(len(secs) - 1):
        name_i, s_i0, s_i1, flags_i, sh_type_i, idx_i = secs[i]
        name_j, s_j0, s_j1, flags_j, sh_type_j, idx_j = secs[i + 1]
        if ranges_overlap((s_i0, s_i1), (s_j0, s_j1)):
            print('ERROR: section overlap detected:')
            print(f'  idx {idx_i}: {name_i or "<unnamed>"} (type={sh_type_i}, flags={hex(flags_i)}): [{hex(s_i0)}, {hex(s_i1)}]')
            print(f'  idx {idx_j}: {name_j or "<unnamed>"} (type={sh_type_j}, flags={hex(flags_j)}): [{hex(s_j0)}, {hex(s_j1)}]')
            errors += 1
    return errors


def _check_non_alloc_in_load(secs: list, loads: list) -> int:
    """Warn about non-ALLOC sections that fall inside a PT_LOAD range."""
    errors = 0
    for name, s0, s1, flags, sh_type, idx in secs:
        if (flags & _SHF_ALLOC) != 0:
            continue
        for p0, p1 in loads:
            if ranges_overlap((s0, s1), (p0, p1)):
                print('WARNING: non-ALLOC section lies inside PT_LOAD range:')
                print(f'  idx {idx}: section {name or "<unnamed>"} (type={sh_type}): [{hex(s0)}, {hex(s1)}]')
                print(f'  PT_LOAD: [{hex(p0)}, {hex(p1)}]')
                errors += 1
    return errors


def _check_load_overlaps(loads: list) -> int:
    """Return the number of overlapping PT_LOAD segments."""
    errors = 0
    loads_sorted = sorted(loads, key=lambda r: r[0])
    for i in range(len(loads_sorted) - 1):
        a0, a1 = loads_sorted[i]
        b0, b1 = loads_sorted[i + 1]
        if ranges_overlap((a0, a1), (b0, b1)):
            print('ERROR: PT_LOAD segment overlap:')
            print(f'  [{hex(a0)}, {hex(a1)}] overlaps [{hex(b0)}, {hex(b1)}]')
            errors += 1
    return errors


def _resolve_binary(binary_arg: str) -> str:
    """Resolve the ELF binary path, exiting on failure."""
    path = binary_arg or find_candidate_binary()
    if not path:
        print('Error: no binary provided and none found in target/*/debug or target/*/release')
        sys.exit(2)
    if not os.path.exists(path):
        print(f'Error: binary not found: {path}')
        sys.exit(2)
    return path


def _analyse_elf(path: str) -> int:
    """Open *path* as an ELF binary and return the total number of issues found."""
    with open(path, 'rb') as fh:
        try:
            elf = ELFFile(fh)
        except Exception as e:
            print('Error: failed to parse ELF file:', e)
            sys.exit(2)

        secs = _gather_sections(elf)
        loads = _gather_pt_loads(elf)

        errors = _check_section_overlaps(secs)
        errors += _check_non_alloc_in_load(secs, loads)
        errors += _check_load_overlaps(loads)
    return errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('binary', nargs='?')
    args = ap.parse_args()

    path = _resolve_binary(args.binary)
    print(f'Checking ELF: {path}')

    errors = _analyse_elf(path)

    if errors == 0:
        print('No overlaps detected. Linker layout appears sane.')
        sys.exit(0)
    else:
        print(f'Found {errors} issue(s) (errors/warnings).')
        sys.exit(1)


if __name__ == '__main__':
    main()
