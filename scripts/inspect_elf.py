#!/usr/bin/env python3
from elftools.elf.elffile import ELFFile
import sys

path = sys.argv[1] if len(sys.argv)>1 else 'target/x86_64-exorust/debug/exorust_kernel'
with open(path,'rb') as f:
    elf = ELFFile(f)
    print('Sections:')
    for sec in elf.iter_sections():
        print(sec.name, sec.header['sh_type'])
    print('\nSymbol tables:')
    for sec in elf.iter_sections():
        if sec.header['sh_type'] in ('SHT_SYMTAB','SHT_DYNSYM'):
            print('SYMTAB', sec.name, 'num symbols', sec.num_symbols())
            for i, sym in enumerate(sec.iter_symbols()):
                if i>=20:
                    break
                print(hex(sym['st_value']), sym.name)
