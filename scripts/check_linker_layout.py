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
from typing import List, Tuple

import subprocess
try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.constants import SH_FLAGS
except Exception:
    print("pyelftools not found, attempting to install via pip...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyelftools"])  # type: ignore
        from elftools.elf.elffile import ELFFile
        from elftools.elf.constants import SH_FLAGS
    except Exception as e:
        print("Error: pyelftools not installed and automatic install failed. Please run 'pip install pyelftools' and try again.")
        sys.exit(2)


def find_candidate_binary() -> str:
    candidates = []
    for root, dirs, files in os.walk('target'):
        for f in files:
            path = os.path.join(root, f)
            # Try to open as ELF
            try:
                with open(path, 'rb') as fh:
                    magic = fh.read(4)
                    if magic != b'\x7fELF':
                        continue
                candidates.append(path)
            except Exception:
                continue
    # Prefer debug builds and explicit names
    for p in candidates:
        name = os.path.basename(p)
        if 'exorust' in name.lower() or 'rany' in name.lower() or 'kernel' in name.lower():
            if '/debug/' in p.replace('\\', '/'):
                return p
    # fallback to first candidate
    if candidates:
        return candidates[0]
    return ''


def ranges_overlap(a: Tuple[int, int], b: Tuple[int, int]) -> bool:
    a0, a1 = a
    b0, b1 = b
    return a0 < b1 and b0 < a1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('binary', nargs='?')
    args = ap.parse_args()

    path = args.binary or find_candidate_binary()
    if not path:
        print('Error: no binary provided and none found in target/*/debug or target/*/release')
        sys.exit(2)

    if not os.path.exists(path):
        print(f'Error: binary not found: {path}')
        sys.exit(2)

    print(f'Checking ELF: {path}')

    with open(path, 'rb') as fh:
        try:
            elf = ELFFile(fh)
        except Exception as e:
            print('Error: failed to parse ELF file:', e)
            sys.exit(2)

        # Gather sections
        secs = []  # (name, start, end, flags)
        for idx, sec in enumerate(elf.iter_sections()):
            sh_offset = sec['sh_offset']
            sh_size = sec['sh_size']
            name = sec.name
            flags = sec['sh_flags']
            sh_type = sec['sh_type']
            # SHT_NOBITS sections do not occupy file space (e.g., .bss). Skip them
            if sh_type == 'SHT_NOBITS':
                continue
            if sh_size == 0:
                continue
            start = sh_offset
            end = sh_offset + sh_size
            secs.append((name, start, end, flags, sh_type, idx))

        # adjust unpacking later to also include type and index
        # update usages accordingly

        secs.sort(key=lambda s: s[1])

        # normalize tuple structure (name, start, end, flags, sh_type, idx)

        errors = 0

        # Check section overlaps
        for i in range(len(secs) - 1):
            name_i, s_i0, s_i1, flags_i, sh_type_i, idx_i = secs[i]
            name_j, s_j0, s_j1, flags_j, sh_type_j, idx_j = secs[i + 1]
            if ranges_overlap((s_i0, s_i1), (s_j0, s_j1)):
                print('ERROR: section overlap detected:')
                print(f'  idx {idx_i}: {name_i or '<unnamed>'} (type={sh_type_i}, flags={hex(flags_i)}): [{hex(s_i0)}, {hex(s_i1)}]')
                print(f'  idx {idx_j}: {name_j or '<unnamed>'} (type={sh_type_j}, flags={hex(flags_j)}): [{hex(s_j0)}, {hex(s_j1)}]')
                errors += 1

        # Gather PT_LOAD ranges
        loads = []
        for seg in elf.iter_segments():
            hdr = seg.header
            p_type = hdr.p_type
            if p_type == 'PT_LOAD' or p_type == 1:
                p_offset = hdr.p_offset
                p_filesz = hdr.p_filesz
                loads.append((p_offset, p_offset + p_filesz))

        # Check that non-ALLOC sections aren't inside PT_LOAD
        for name, s0, s1, flags, sh_type, idx in secs:
            sh_flags = flags
            SHF_ALLOC = 0x2
            is_alloc = (sh_flags & SHF_ALLOC) != 0
            if not is_alloc:
                for p0, p1 in loads:
                    if ranges_overlap((s0, s1), (p0, p1)):
                        print('WARNING: non-ALLOC section lies inside PT_LOAD range:')
                        print(f'  idx {idx}: section {name or '<unnamed>'} (type={sh_type}): [{hex(s0)}, {hex(s1)}]')
                        print(f'  PT_LOAD: [{hex(p0)}, {hex(p1)}]')
                        errors += 1

        # Check program header overlaps
        loads_sorted = sorted(loads, key=lambda r: r[0])
        for i in range(len(loads_sorted) - 1):
            a0, a1 = loads_sorted[i]
            b0, b1 = loads_sorted[i + 1]
            if ranges_overlap((a0, a1), (b0, b1)):
                print('ERROR: PT_LOAD segment overlap:')
                print(f'  [{hex(a0)}, {hex(a1)}] overlaps [{hex(b0)}, {hex(b1)}]')
                errors += 1

        if errors == 0:
            print('No overlaps detected. Linker layout appears sane.')
            sys.exit(0)
        else:
            print(f'Found {errors} issue(s) (errors/warnings).')
            sys.exit(1)


if __name__ == '__main__':
    main()
