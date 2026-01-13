#!/usr/bin/env python3
"""
Simple symbol lookup and addr->file:line helper using pyelftools.
Usage:
  python scripts/symlookup.py <hex-address> [path-to-binary]

Prints closest symbol and optional DWARF file/line info if available.
"""
import sys
from elftools.elf.elffile import ELFFile


def find_closest_symbol(elffile, addr):
    best = None
    for section in elffile.iter_sections():
        if not section.header['sh_type'] in ('SHT_SYMTAB', 'SHT_DYNSYM'):
            continue
        for sym in section.iter_symbols():
            if sym['st_value'] == 0:
                continue
            sym_addr = sym['st_value']
            if sym_addr <= addr:
                dist = addr - sym_addr
                if best is None or dist < best[0]:
                    best = (dist, sym.name, sym_addr)
    return best


def addr_to_line(elffile, addr):
    try:
        dwarfinfo = elffile.get_dwarf_info()
    except Exception:
        return None

    for cu in dwarfinfo.iter_CUs():
        top = cu.get_top_DIE()
        low_pc = None
        high_pc = None

        # Try to get ranges from DIE
        if 'DW_AT_low_pc' in top.attributes:
            low_pc = top.attributes['DW_AT_low_pc'].value
        if 'DW_AT_high_pc' in top.attributes:
            hi_attr = top.attributes['DW_AT_high_pc']
            # high_pc can be offset or absolute
            if hi_attr.form == 'DW_FORM_addr':
                high_pc = hi_attr.value
            else:
                # DW_FORM_data* => offset from low_pc
                if low_pc is not None:
                    high_pc = low_pc + hi_attr.value

        if low_pc is not None and high_pc is not None and low_pc <= addr <= high_pc:
            # Search line programs for file/line
            lineprog = dwarfinfo.line_program_for_CU(cu)
            prev_state = None
            for entry in lineprog.get_entries():
                if entry.state is None:
                    continue
                state = entry.state
                if state.address == addr:
                    file = lineprog['file_entry'][state.file - 1].name.decode('utf-8')
                    return (file, state.line)
                if state.address > addr:
                    if prev_state is not None:
                        file = lineprog['file_entry'][prev_state.file - 1].name.decode('utf-8')
                        return (file, prev_state.line)
                prev_state = state
    return None


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: symlookup.py <hex-addr> [binary]')
        sys.exit(1)

    addr_str = sys.argv[1]
    if addr_str.startswith('0x') or addr_str.startswith('0X'):
        addr = int(addr_str, 16)
    else:
        addr = int(addr_str, 16)

    binpath = sys.argv[2] if len(sys.argv) > 2 else 'target/x86_64-exorust/debug/exorust_kernel'

    with open(binpath, 'rb') as f:
        elffile = ELFFile(f)

        sym = find_closest_symbol(elffile, addr)
        if sym:
            dist, name, sym_addr = sym
            print(f'Closest symbol: {name} + {dist:#x} (sym_addr={sym_addr:#x})')
        else:
            print('No symbol found')

        line = addr_to_line(elffile, addr)
        if line:
            file, ln = line
            print(f'Approx source: {file}:{ln}')
        else:
            print('No DWARF line info available for this address')
