#!/usr/bin/env python3
"""
Simple symbol lookup and addr->file:line helper using pyelftools.
Usage:
  python scripts/symlookup.py <hex-address> [path-to-binary]

Prints closest symbol and optional DWARF file/line info if available.
"""
import sys
from elftools.elf.elffile import ELFFile


def find_closest_symbol(elf, target_addr):
    best = None
    for section in elf.iter_sections():
        if not section.header['sh_type'] in ('SHT_SYMTAB', 'SHT_DYNSYM'):
            continue
        for sym in section.iter_symbols():
            if sym['st_value'] == 0:
                continue
            sym_addr = sym['st_value']
            if sym_addr <= target_addr:
                dist = target_addr - sym_addr
                if best is None or dist < best[0]:
                    best = (dist, sym.name, sym_addr)
    return best


def _get_cu_address_range(top_die):
    """Extract (low_pc, high_pc) from a compilation unit's top DIE."""
    if 'DW_AT_low_pc' not in top_die.attributes:
        return None, None
    low_pc = top_die.attributes['DW_AT_low_pc'].value
    if 'DW_AT_high_pc' not in top_die.attributes:
        return low_pc, None
    hi_attr = top_die.attributes['DW_AT_high_pc']
    if hi_attr.form == 'DW_FORM_addr':
        return low_pc, hi_attr.value
    return low_pc, low_pc + hi_attr.value


def _search_line_program(lineprog, target_addr):
    """Search a line program for file/line matching target_addr."""
    prev_state = None
    for entry in lineprog.get_entries():
        if entry.state is None:
            continue
        state = entry.state
        if state.address == target_addr:
            file_entry = lineprog.header.file_entry[state.file - 1]
            return (file_entry.name.decode('utf-8'), state.line)
        if state.address > target_addr and prev_state is not None:
            file_entry = lineprog.header.file_entry[prev_state.file - 1]
            return (file_entry.name.decode('utf-8'), prev_state.line)
        prev_state = state
    return None


def addr_to_line(elf, target_addr):
    try:
        dwarfinfo = elf.get_dwarf_info()
    except (AttributeError, KeyError):
        return None

    for cu in dwarfinfo.iter_CUs():
        top = cu.get_top_DIE()
        low_pc, high_pc = _get_cu_address_range(top)
        if low_pc is None or high_pc is None:
            continue
        if not (low_pc <= target_addr <= high_pc):
            continue
        lineprog = dwarfinfo.line_program_for_CU(cu)
        result = _search_line_program(lineprog, target_addr)
        if result is not None:
            return result
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
        elf = ELFFile(f)

        sym = find_closest_symbol(elf, addr)
        if sym:
            dist, name, sym_addr = sym
            print(f'Closest symbol: {name} + {dist:#x} (sym_addr={sym_addr:#x})')
        else:
            print('No symbol found')

        line_info = addr_to_line(elf, addr)
        if line_info:
            src_file, ln = line_info
            print(f'Approx source: {src_file}:{ln}')
        else:
            print('No DWARF line info available for this address')
