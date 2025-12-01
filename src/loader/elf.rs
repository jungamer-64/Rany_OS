// ============================================================================
// src/loader/elf.rs - ELF Parser and Loader
// 設計書 3.1: 動的リンクとシンボル解決
// ============================================================================
#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;
use core::mem;
use super::LoadError;

/// ELF Magic Number
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// ELF Class
const ELFCLASS64: u8 = 2;

/// ELF Data Encoding
const ELFDATA2LSB: u8 = 1; // Little Endian

/// ELF Type
const ET_DYN: u16 = 3; // Shared object file (Position Independent)
const ET_EXEC: u16 = 2; // Executable file

/// Program Header Type
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;

/// Section Header Type
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_DYNSYM: u32 = 11;

/// Symbol Binding
const STB_GLOBAL: u8 = 1;

/// ELF64 Header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Header {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

/// ELF64 Program Header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

/// ELF64 Section Header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64SectionHeader {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

/// ELF64 Symbol
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Symbol {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

impl Elf64Symbol {
    pub fn binding(&self) -> u8 {
        self.st_info >> 4
    }
    
    pub fn symbol_type(&self) -> u8 {
        self.st_info & 0xf
    }
}

/// ELF64 Relocation with Addend
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Rela {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64,
}

impl Elf64Rela {
    pub fn symbol(&self) -> u32 {
        (self.r_info >> 32) as u32
    }
    
    pub fn reloc_type(&self) -> u32 {
        self.r_info as u32
    }
}

/// ロードされたセルの情報
#[derive(Debug)]
pub struct LoadedCell {
    /// ベースアドレス
    pub base_address: usize,
    /// 合計サイズ
    pub size: usize,
    /// エントリポイント（あれば）
    pub entry_point: Option<usize>,
}

/// パース結果のセル情報
#[derive(Debug)]
pub struct CellInfo {
    /// エントリポイントのオフセット
    pub entry_offset: u64,
    /// 必要なメモリサイズ
    pub memory_size: usize,
    /// アライメント要件
    pub alignment: usize,
    /// エクスポートされたシンボル
    pub exports: Vec<String>,
    /// インポートしているシンボル
    pub imports: Vec<String>,
    /// ロードするセグメント情報
    pub segments: Vec<SegmentInfo>,
}

/// セグメント情報
#[derive(Debug)]
pub struct SegmentInfo {
    /// ファイル内オフセット
    pub file_offset: usize,
    /// 仮想アドレス（相対）
    pub vaddr: usize,
    /// ファイル内サイズ
    pub file_size: usize,
    /// メモリ内サイズ
    pub mem_size: usize,
    /// フラグ（読み取り/書き込み/実行）
    pub flags: u32,
}

/// ELFローダー
pub struct ElfLoader<'a> {
    data: &'a [u8],
    header: Elf64Header,
}

impl<'a> ElfLoader<'a> {
    /// 新しいELFローダーを作成
    pub fn new(data: &'a [u8]) -> Result<Self, LoadError> {
        if data.len() < mem::size_of::<Elf64Header>() {
            return Err(LoadError::InvalidFormat("File too small".into()));
        }
        
        // ヘッダーを読み取り
        let header: Elf64Header = unsafe {
            core::ptr::read(data.as_ptr() as *const Elf64Header)
        };
        
        // マジックナンバーの検証
        if header.e_ident[0..4] != ELF_MAGIC {
            return Err(LoadError::InvalidFormat("Invalid ELF magic".into()));
        }
        
        // 64ビットELFであることを確認
        if header.e_ident[4] != ELFCLASS64 {
            return Err(LoadError::InvalidFormat("Not 64-bit ELF".into()));
        }
        
        // リトルエンディアンであることを確認
        if header.e_ident[5] != ELFDATA2LSB {
            return Err(LoadError::InvalidFormat("Not little endian".into()));
        }
        
        // x86_64であることを確認
        if header.e_machine != 0x3E {
            return Err(LoadError::InvalidFormat("Not x86_64".into()));
        }
        
        Ok(Self { data, header })
    }
    
    /// ELFをパースしてセル情報を取得
    pub fn parse(&self) -> Result<CellInfo, LoadError> {
        let mut segments = Vec::new();
        let mut exports = Vec::new();
        let mut imports = Vec::new();
        let mut max_addr = 0usize;
        let mut alignment = 4096usize;
        
        // プログラムヘッダーを解析
        for i in 0..self.header.e_phnum {
            let ph_offset = self.header.e_phoff as usize 
                + (i as usize * self.header.e_phentsize as usize);
            
            if ph_offset + mem::size_of::<Elf64ProgramHeader>() > self.data.len() {
                return Err(LoadError::InvalidFormat("Program header out of bounds".into()));
            }
            
            let ph: Elf64ProgramHeader = unsafe {
                core::ptr::read(self.data.as_ptr().add(ph_offset) as *const _)
            };
            
            if ph.p_type == PT_LOAD {
                let end_addr = ph.p_vaddr as usize + ph.p_memsz as usize;
                max_addr = max_addr.max(end_addr);
                alignment = alignment.max(ph.p_align as usize);
                
                segments.push(SegmentInfo {
                    file_offset: ph.p_offset as usize,
                    vaddr: ph.p_vaddr as usize,
                    file_size: ph.p_filesz as usize,
                    mem_size: ph.p_memsz as usize,
                    flags: ph.p_flags,
                });
            }
        }
        
        // シンボルテーブルを解析
        self.parse_symbols(&mut exports, &mut imports)?;
        
        Ok(CellInfo {
            entry_offset: self.header.e_entry,
            memory_size: max_addr,
            alignment,
            exports,
            imports,
            segments,
        })
    }
    
    /// シンボルを解析
    fn parse_symbols(&self, exports: &mut Vec<String>, imports: &mut Vec<String>) -> Result<(), LoadError> {
        // セクションヘッダーを探索
        for i in 0..self.header.e_shnum {
            let sh_offset = self.header.e_shoff as usize
                + (i as usize * self.header.e_shentsize as usize);
            
            if sh_offset + mem::size_of::<Elf64SectionHeader>() > self.data.len() {
                continue;
            }
            
            let sh: Elf64SectionHeader = unsafe {
                core::ptr::read(self.data.as_ptr().add(sh_offset) as *const _)
            };
            
            // シンボルテーブルを処理
            if sh.sh_type == SHT_SYMTAB || sh.sh_type == SHT_DYNSYM {
                self.process_symbol_table(&sh, exports, imports)?;
            }
        }
        
        Ok(())
    }
    
    /// シンボルテーブルを処理
    fn process_symbol_table(
        &self,
        sh: &Elf64SectionHeader,
        exports: &mut Vec<String>,
        imports: &mut Vec<String>,
    ) -> Result<(), LoadError> {
        let sym_count = sh.sh_size as usize / mem::size_of::<Elf64Symbol>();
        let strtab = self.get_string_table(sh.sh_link as usize)?;
        
        for j in 0..sym_count {
            let sym_offset = sh.sh_offset as usize + j * mem::size_of::<Elf64Symbol>();
            
            if sym_offset + mem::size_of::<Elf64Symbol>() > self.data.len() {
                continue;
            }
            
            let sym: Elf64Symbol = unsafe {
                core::ptr::read(self.data.as_ptr().add(sym_offset) as *const _)
            };
            
            // グローバルシンボルのみ処理
            if sym.binding() == STB_GLOBAL && sym.st_name != 0 {
                if let Some(name) = self.get_string(strtab, sym.st_name as usize) {
                    if sym.st_shndx == 0 {
                        // 未定義シンボル = インポート
                        imports.push(name);
                    } else {
                        // 定義済みシンボル = エクスポート
                        exports.push(name);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// 文字列テーブルを取得
    fn get_string_table(&self, index: usize) -> Result<&[u8], LoadError> {
        let sh_offset = self.header.e_shoff as usize
            + (index * self.header.e_shentsize as usize);
        
        if sh_offset + mem::size_of::<Elf64SectionHeader>() > self.data.len() {
            return Err(LoadError::InvalidFormat("String table section out of bounds".into()));
        }
        
        let sh: Elf64SectionHeader = unsafe {
            core::ptr::read(self.data.as_ptr().add(sh_offset) as *const _)
        };
        
        let start = sh.sh_offset as usize;
        let end = start + sh.sh_size as usize;
        
        if end > self.data.len() {
            return Err(LoadError::InvalidFormat("String table data out of bounds".into()));
        }
        
        Ok(&self.data[start..end])
    }
    
    /// 文字列テーブルから文字列を取得
    fn get_string(&self, strtab: &[u8], offset: usize) -> Option<String> {
        if offset >= strtab.len() {
            return None;
        }
        
        let mut end = offset;
        while end < strtab.len() && strtab[end] != 0 {
            end += 1;
        }
        
        core::str::from_utf8(&strtab[offset..end])
            .ok()
            .map(String::from)
    }
    
    /// セルをメモリにロード
    pub fn load(&self, info: &CellInfo) -> Result<LoadedCell, LoadError> {
        // メモリを割り当て
        // TODO: 実際のフレームアロケータを使用
        let base_address = self.allocate_memory(info.memory_size, info.alignment)?;
        
        // 各セグメントをロード
        for segment in &info.segments {
            let dest = base_address + segment.vaddr;
            let src_start = segment.file_offset;
            let src_end = src_start + segment.file_size;
            
            if src_end > self.data.len() {
                return Err(LoadError::InvalidFormat("Segment data out of bounds".into()));
            }
            
            // データをコピー
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.data.as_ptr().add(src_start),
                    dest as *mut u8,
                    segment.file_size,
                );
                
                // BSS領域をゼロで初期化
                if segment.mem_size > segment.file_size {
                    let bss_start = dest + segment.file_size;
                    let bss_size = segment.mem_size - segment.file_size;
                    core::ptr::write_bytes(bss_start as *mut u8, 0, bss_size);
                }
            }
        }
        
        let entry_point = if info.entry_offset != 0 {
            Some(base_address + info.entry_offset as usize)
        } else {
            None
        };
        
        Ok(LoadedCell {
            base_address,
            size: info.memory_size,
            entry_point,
        })
    }
    
    /// メモリを割り当て（仮実装）
    fn allocate_memory(&self, size: usize, _alignment: usize) -> Result<usize, LoadError> {
        // TODO: フレームアロケータを使用した実装
        // 現在は単純な静的アドレスを返す（実際には動的に割り当てる必要がある）
        use alloc::alloc::{alloc_zeroed, Layout};
        
        let layout = Layout::from_size_align(size, 4096)
            .map_err(|_| LoadError::OutOfMemory)?;
        
        let ptr = unsafe { alloc_zeroed(layout) };
        
        if ptr.is_null() {
            Err(LoadError::OutOfMemory)
        } else {
            Ok(ptr as usize)
        }
    }
    
    /// リロケーションを適用
    pub fn relocate<F>(&self, loaded: &LoadedCell, resolve: F) -> Result<(), LoadError>
    where
        F: Fn(&str) -> Option<usize>,
    {
        // セクションヘッダーを探索してリロケーションセクションを処理
        for i in 0..self.header.e_shnum {
            let sh_offset = self.header.e_shoff as usize
                + (i as usize * self.header.e_shentsize as usize);
            
            if sh_offset + mem::size_of::<Elf64SectionHeader>() > self.data.len() {
                continue;
            }
            
            let sh: Elf64SectionHeader = unsafe {
                core::ptr::read(self.data.as_ptr().add(sh_offset) as *const _)
            };
            
            if sh.sh_type == SHT_RELA {
                self.apply_relocations(&sh, loaded, &resolve)?;
            }
        }
        
        Ok(())
    }
    
    /// リロケーションを適用
    fn apply_relocations<F>(
        &self,
        sh: &Elf64SectionHeader,
        loaded: &LoadedCell,
        resolve: &F,
    ) -> Result<(), LoadError>
    where
        F: Fn(&str) -> Option<usize>,
    {
        let rela_count = sh.sh_size as usize / mem::size_of::<Elf64Rela>();
        
        // シンボルテーブルと文字列テーブルを取得
        let symtab_sh = self.get_section_header(sh.sh_link as usize)?;
        let strtab = self.get_string_table(symtab_sh.sh_link as usize)?;
        
        for j in 0..rela_count {
            let rela_offset = sh.sh_offset as usize + j * mem::size_of::<Elf64Rela>();
            
            if rela_offset + mem::size_of::<Elf64Rela>() > self.data.len() {
                continue;
            }
            
            let rela: Elf64Rela = unsafe {
                core::ptr::read(self.data.as_ptr().add(rela_offset) as *const _)
            };
            
            // シンボルを取得
            let sym_idx = rela.symbol() as usize;
            let sym_offset = symtab_sh.sh_offset as usize + sym_idx * mem::size_of::<Elf64Symbol>();
            
            if sym_offset + mem::size_of::<Elf64Symbol>() > self.data.len() {
                continue;
            }
            
            let sym: Elf64Symbol = unsafe {
                core::ptr::read(self.data.as_ptr().add(sym_offset) as *const _)
            };
            
            // シンボル値を解決
            let sym_value = if sym.st_shndx == 0 {
                // 外部シンボル
                let name = self.get_string(strtab, sym.st_name as usize)
                    .ok_or_else(|| LoadError::InvalidFormat("Invalid symbol name".into()))?;
                resolve(&name).ok_or_else(|| LoadError::UnresolvedDependency(name))?
            } else {
                // 内部シンボル
                loaded.base_address + sym.st_value as usize
            };
            
            // リロケーションを適用
            self.apply_relocation(&rela, loaded.base_address, sym_value)?;
        }
        
        Ok(())
    }
    
    /// セクションヘッダーを取得
    fn get_section_header(&self, index: usize) -> Result<Elf64SectionHeader, LoadError> {
        let sh_offset = self.header.e_shoff as usize
            + (index * self.header.e_shentsize as usize);
        
        if sh_offset + mem::size_of::<Elf64SectionHeader>() > self.data.len() {
            return Err(LoadError::InvalidFormat("Section header out of bounds".into()));
        }
        
        Ok(unsafe {
            core::ptr::read(self.data.as_ptr().add(sh_offset) as *const _)
        })
    }
    
    /// 単一のリロケーションを適用
    fn apply_relocation(
        &self,
        rela: &Elf64Rela,
        base: usize,
        sym_value: usize,
    ) -> Result<(), LoadError> {
        let target = base + rela.r_offset as usize;
        
        // x86_64リロケーションタイプ
        match rela.reloc_type() {
            1 => { // R_X86_64_64: 64-bit absolute
                let value = sym_value.wrapping_add(rela.r_addend as usize);
                unsafe { *(target as *mut u64) = value as u64; }
            }
            2 => { // R_X86_64_PC32: 32-bit PC-relative
                let value = (sym_value as i64)
                    .wrapping_add(rela.r_addend)
                    .wrapping_sub(target as i64);
                unsafe { *(target as *mut i32) = value as i32; }
            }
            10 => { // R_X86_64_32: 32-bit absolute
                let value = sym_value.wrapping_add(rela.r_addend as usize);
                unsafe { *(target as *mut u32) = value as u32; }
            }
            _ => {
                // 未対応のリロケーションタイプは無視（警告を出すべき）
            }
        }
        
        Ok(())
    }
}
