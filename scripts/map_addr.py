#!/usr/bin/env python3
"""
Map a kernel VMA address to a symbol using kernel.map file.
Usage: python scripts/map_addr.py <hex_addr>
"""
import sys
import re

if len(sys.argv) < 2:
    print('Usage: map_addr.py <hex_addr>')
    sys.exit(1)

addr = int(sys.argv[1], 16)
mapfile = 'kernel.map'

# Pattern: parse lines extracting the first three hex numbers (VMA, offset, size) where available and use them to find containing symbol ranges.

best = None
hex_num_re = re.compile(r"\b([0-9a-fA-F]+)\b")
with open(mapfile,'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        line = line.rstrip('\n')
        if not line or not re.match(r'^[0-9a-fA-F]', line):
            continue
        # Find hex numbers in the line
        nums = hex_num_re.findall(line)
        if len(nums) >= 3:
            try:
                vma = int(nums[0], 16)
                # second number may be LMA/offset, third is size
                size = int(nums[2], 16)
            except Exception:
                continue
            sym_start = vma
            sym_end = vma + size
            if sym_start <= addr < sym_end:
                # try to extract mangled name between ':(.text.' and ')' or use the last token
                m = re.search(r":\((?P<sym>[^)]+)\)", line)
                if m:
                    name = m.group('sym')
                else:
                    name = line.split()[-1]
                print(f'Address {addr:#x} is inside symbol range {sym_start:#x}-{sym_end:#x}: {name}')
                sys.exit(0)
        # Keep track of the last seen start address <= addr
        first_token = line.split()[0]
        try:
            vma_token = int(first_token, 16)
            if vma_token <= addr:
                best = (vma_token, line)
        except Exception:
            pass

if best:
    vma, line = best
    m = re.search(r":\((?P<sym>[^)]+)\)", line)
    if m:
        name = m.group('sym')
    else:
        name = line.split()[-1]
    print(f'Closest symbol start <= addr: start={vma:#x} line: {name}')
else:
    print('No matching symbol found in kernel.map')
