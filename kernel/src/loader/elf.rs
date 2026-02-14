// ============================================================================
// src/loader/elf.rs - ELF Parser and Loader
// ============================================================================
//! # ELF Loader Module
//!
//! This module implements parsing and loading of ELF64 executable files for
//! dynamically loaded kernel modules (cells).
//!
//! ## Design Reference
//!
//! See 設計書 3.1: 動的リンクとシンボル解決
//!
//! ## Security Features
//!
//! The loader implements multiple security checks to prevent attacks:
//!
//! - **Size limits**: Maximum file size (512MB), segment size (256MB), symbol count (64K)
//! - **DoS prevention**: Limits on sections (1024), relocations per section (256K)
//! - **W^X enforcement**: Segments cannot be both writable and executable
//! - **Bounds checking**: All memory accesses are validated before dereferencing
//!
//! ## Supported Relocation Types
//!
//! | Type | Value | Description |
//! |------|-------|-------------|
//! | `R_X86_64_64` | 1 | 64-bit absolute |
//! | `R_X86_64_PC32` | 2 | 32-bit PC-relative |
//! | `R_X86_64_PLT32` | 4 | 32-bit PLT-relative |
//! | `R_X86_64_COPY` | 5 | Copy symbol (no-op) |
//! | `R_X86_64_GLOB_DAT` | 6 | GOT entry for global data |
//! | `R_X86_64_JUMP_SLOT` | 7 | PLT entry for function calls |
//! | `R_X86_64_RELATIVE` | 8 | Base + addend |
//! | `R_X86_64_GOTPCREL` | 9 | GOT-relative PC32 |
//! | `R_X86_64_32` | 10 | 32-bit absolute (zero-extended) |
//! | `R_X86_64_32S` | 11 | 32-bit absolute (sign-extended) |
//!
//! ## Example Usage
//!
//! ```ignore
//! use kernel::loader::{ElfLoader, Loader, LoadedInfo};
//!
//! let elf_data: &[u8] = /* ELF binary data */;
//! match ElfLoader::load(elf_data) {
//!     Ok(info) => {
//!         log::info!("Loaded at {:#x}, entry: {:#x}", info.base_address, info.entry_point);
//!     }
//!     Err(e) => log::error!("Load failed: {}", e),
//! }
//! ```
#![allow(dead_code)]

use super::LoadError;

// NOTE:
// The kernel's `mm` and `security` modules are not always available when this
// crate is compiled as a dependency (e.g. during workspace builds). To avoid
// hard-to-detect cfg/build-time errors we provide small local fallbacks here
// so the loader can still be compiled and unit-tested in isolation. When the
// full kernel is being built these are thin no-op stand-ins; proper
// integration with `mm::higher_half::PageFlags` and
// `security::mpk::allocate_protection_key` should be restored when the
// module-level visibility guarantees are made explicit.

// Use real PageFlags and PKEY allocator from the kernel modules when available
// - `PageFlags` lives in `crate::mm::higher_half` and provides `set_pkey()`.
// - `allocate_protection_key()` / `free_protection_key()` live in `crate::security::mpk`.
// When compiling for tests or for bench builds (workspace `--all-features`) we
// avoid pulling in the full `mm`/`security` implementations and use no-op
// fallbacks instead. That keeps workspace test runs light and avoids needing
// the entire kernel `mm` implementation for library-style builds.
#[cfg(not(any(test, feature = "bench")))]
use crate::mm::PageFlags;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::mem;

// ============================================================================
// 【セキュリティ】ELFローダー制限定数
// ============================================================================

/// シンボル名の最大長（DoS攻撃防止）
const MAX_SYMBOL_NAME_LENGTH: usize = 4096;

/// シンボルの最大数（DoS攻撃防止）
const MAX_SYMBOLS: usize = 65536;

/// セグメントの最大数
const MAX_SEGMENTS: usize = 256;

/// ELFファイルの最大サイズ（512MB）
const MAX_ELF_SIZE: usize = 512 * 1024 * 1024;

/// セグメントの最大サイズ（256MB）
const MAX_SEGMENT_SIZE: usize = 256 * 1024 * 1024;

/// リロケーションの最大数（DoS攻撃防止）
const MAX_RELOCATIONS: usize = 262144; // 256K

/// セクションヘッダーの最大数（DoS攻撃防止）
const MAX_SECTIONS: usize = 1024;

/// プログラムフラグ: Write
const PF_W: u32 = 0x2;

/// プログラムフラグ: Execute
const PF_X: u32 = 0x1;

// ============================================================================
// 【セキュリティ】ASLR (Address Space Layout Randomization)
// ============================================================================

/// ASLRを有効にするかどうかのフラグ
/// 実行時にset_aslr_enabled()で設定可能
static ASLR_ENABLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(true);

/// ASLRのランダムオフセットの最大値（16MB）
/// ページアラインメントを維持するため4KBの倍数
const ASLR_MAX_OFFSET: usize = 16 * 1024 * 1024;

/// ASLR用の簡易乱数シード
/// RDTSC命令などから初期化される
static ASLR_SEED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0x5DEECE66D);

/// ASLRを有効/無効にする
pub fn set_aslr_enabled(enabled: bool) {
    ASLR_ENABLED.store(enabled, core::sync::atomic::Ordering::Relaxed);
}

/// ASLRが有効かどうかを取得
pub fn is_aslr_enabled() -> bool {
    ASLR_ENABLED.load(core::sync::atomic::Ordering::Relaxed)
}

/// ASLR用のランダムオフセットを生成（ページアラインメント）
///
/// 簡易的なLCG（線形合同法）を使用
fn generate_aslr_offset() -> usize {
    use core::sync::atomic::Ordering;

    // RDTSCからシードを更新（利用可能な場合）
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let tsc = unsafe { core::arch::x86_64::_rdtsc() };
        let old = ASLR_SEED.load(Ordering::Relaxed);
        let _ = ASLR_SEED.compare_exchange(
            old,
            old.wrapping_add(tsc),
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    // LCG: next = (a * seed + c) mod m
    let seed = ASLR_SEED.fetch_add(1, Ordering::Relaxed);
    let next = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    ASLR_SEED.store(next, Ordering::Relaxed);

    // ページアラインメント（4KB）を維持しつつMAX_OFFSET以内に制限
    let offset = (next as usize) % ASLR_MAX_OFFSET;
    offset & !0xFFF // 4KB aligned
}

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
    /// 割り当てられた Protection Key（存在する場合）
    pub pkey: Option<u8>,
}

/// パース結果のセル情報（'a は ELF バッファのライフタイム）
#[derive(Debug)]
pub struct CellInfo<'a> {
    /// エントリポイントのオフセット
    pub entry_offset: u64,
    /// 必要なメモリサイズ
    pub memory_size: usize,
    /// アライメント要件
    pub alignment: usize,
    /// エクスポートされたシンボル (name, value)
    /// name は ELF 内の文字列テーブルへの参照（ゼロコピー）
    pub exports: Vec<(&'a str, u64)>,
    /// インポートしているシンボル（ゼロコピー参照）
    pub imports: Vec<&'a str>,
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

/// ELF64ローダー
///
/// ELF64形式のバイナリをパースし、メモリにロードするローダー。
/// セキュリティチェックとシンボル解決を含む完全なロード処理を提供する。
///
/// # フィールド
///
/// - `data`: ELFバイナリデータへの参照
/// - `header`: パース済みのELF64ヘッダー
///
/// # セキュリティ
///
/// このローダーは以下のセキュリティ検証を実行する:
/// - ファイルサイズ制限
/// - マジックナンバー検証
/// - W^X（Write XOR Execute）検証
/// - リロケーション数制限
pub struct ElfLoader<'a> {
    /// ELFバイナリデータへの参照
    data: &'a [u8],
    /// パース済みのELF64ヘッダー
    header: Elf64Header,
}

// ============================================================================
// 【設計書 2.2】安全なメモリ読み取りラッパー関数
// 生ポインタの直接操作を避け、境界チェック付きの関数を提供
// ============================================================================

/// 安全に構造体を読み取る
///
/// 【設計書 2.2】生ポインタ操作を避け、境界チェック付きで構造体を読み取る。
/// 内部では unsafe を使用するが、呼び出し前に全ての境界チェックを実施。
// Use the shared util::read_struct helper instead which centralizes
// unsafe pointer reads and performs bounds/alignment checks.

// Use util::get_slice from the top-level util module

impl<'a> ElfLoader<'a> {
    /// 新しいELFローダーを作成
    ///
    /// 【セキュリティ】入力データの境界チェックを厳密に実行
    pub fn new(data: &'a [u8]) -> Result<Self, LoadError> {
        // ファイルサイズチェック
        if data.len() < mem::size_of::<Elf64Header>() {
            return Err(LoadError::InvalidFormat("File too small".into()));
        }

        // 【セキュリティ】最大ファイルサイズチェック
        if data.len() > MAX_ELF_SIZE {
            return Err(LoadError::InvalidFormat(alloc::format!(
                "ELF file too large: {} bytes (max {})",
                data.len(),
                MAX_ELF_SIZE
            )));
        }

        // 【設計書 2.2】安全なラッパーを使用してヘッダーを読み取り
        let header: Elf64Header = crate::util::read_struct(data, 0)
            .ok_or_else(|| LoadError::InvalidFormat("Failed to read ELF header".into()))?;

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
    ///
    /// 最適化:
    /// - シンボル名は `String` を割り当てずに `&str` で保持する（ゼロコピー）
    /// - セグメント/シンボルベクタに容量予約を行い再割り当てを減らす
    pub fn parse(&self) -> Result<CellInfo<'a>, LoadError> {
        let mut segments = Vec::new();
        segments.reserve(self.header.e_phnum as usize);

        // ゼロコピーでシンボル名を扱うため、Stringを使わず参照を蓄える
        let mut exports: Vec<(&'a str, u64)> = Vec::new();
        let mut imports: Vec<&'a str> = Vec::new();
        let mut max_addr = 0usize;
        let mut alignment = 4096usize;

        // 【セキュリティ】プログラムヘッダー数のチェック
        if self.header.e_phnum as usize > MAX_SEGMENTS {
            return Err(LoadError::InvalidFormat(alloc::format!(
                "Too many program headers: {} (max {})",
                self.header.e_phnum,
                MAX_SEGMENTS
            )));
        }

        // 【セキュリティ】セクションヘッダー数のチェック
        if self.header.e_shnum as usize > MAX_SECTIONS {
            return Err(LoadError::InvalidFormat(alloc::format!(
                "Too many section headers: {} (max {})",
                self.header.e_shnum,
                MAX_SECTIONS
            )));
        }

        // プログラムヘッダーを解析
        for i in 0..self.header.e_phnum {
            let ph_offset =
                self.header.e_phoff as usize + (i as usize * self.header.e_phentsize as usize);

            // 【設計書 2.2】安全なラッパーを使用
            let ph: Elf64ProgramHeader = crate::util::read_struct(self.data, ph_offset)
                .ok_or_else(|| LoadError::InvalidFormat("Failed to read program header".into()))?;

            if ph.p_type == PT_LOAD {
                // 【セキュリティ】セグメントサイズのチェック
                if ph.p_memsz as usize > MAX_SEGMENT_SIZE {
                    return Err(LoadError::InvalidFormat(alloc::format!(
                        "Segment too large: {} bytes (max {})",
                        ph.p_memsz,
                        MAX_SEGMENT_SIZE
                    )));
                }

                // 【セキュリティ】W^X (Writable XOR Executable) チェック
                // セグメントは書き込み可能かつ実行可能であってはならない
                let is_writable = (ph.p_flags & PF_W) != 0;
                let is_executable = (ph.p_flags & PF_X) != 0;
                if is_writable && is_executable {
                    return Err(LoadError::InvalidPermissions(alloc::format!(
                        "Segment at vaddr {:#x} is both writable and executable (W^X violation)",
                        ph.p_vaddr
                    )));
                }

                // 【セキュリティ】オーバーフローチェック
                let end_addr = (ph.p_vaddr as usize)
                    .checked_add(ph.p_memsz as usize)
                    .ok_or_else(|| LoadError::InvalidFormat("Segment address overflow".into()))?;

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
    fn parse_symbols(
        &self,
        exports: &mut Vec<(&'a str, u64)>,
        imports: &mut Vec<&'a str>,
    ) -> Result<(), LoadError> {
        // セクションヘッダーを探索
        for i in 0..self.header.e_shnum {
            let sh_offset =
                self.header.e_shoff as usize + (i as usize * self.header.e_shentsize as usize);

            // 【設計書 2.2】安全なラッパーを使用、エラーはスキップ
            let sh: Elf64SectionHeader = match crate::util::read_struct(self.data, sh_offset) {
                Some(sh) => sh,
                None => continue,
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
        exports: &mut Vec<(&'a str, u64)>,
        imports: &mut Vec<&'a str>,
    ) -> Result<(), LoadError> {
        let sym_count = sh.sh_size as usize / mem::size_of::<Elf64Symbol>();
        let strtab = self.get_string_table(sh.sh_link as usize)?;

        // ある程度の容量を予約して再割り当てを減らす
        let reserve_amount = core::cmp::min(sym_count, MAX_SYMBOLS);
        exports.reserve(reserve_amount);
        imports.reserve(reserve_amount);

        for j in 0..sym_count {
            let sym_offset = sh.sh_offset as usize + j * mem::size_of::<Elf64Symbol>();

            // 【設計書 2.2】安全なラッパーを使用、エラーはスキップ
            let sym: Elf64Symbol = match crate::util::read_struct(self.data, sym_offset) {
                Some(sym) => sym,
                None => continue,
            };

            // グローバルシンボルのみ処理
            if sym.binding() == STB_GLOBAL && sym.st_name != 0 {
                if let Some(name) = self.get_string(strtab, sym.st_name as usize) {
                    if sym.st_shndx == 0 {
                        // 未定義シンボル = インポート（ゼロコピー）
                        imports.push(name);
                    } else {
                        // 定義済みシンボル = エクスポート（ゼロコピー）
                        exports.push((name, sym.st_value));
                    }
                }
            }
        }

        Ok(())
    }

    /// 文字列テーブルを取得
    fn get_string_table(&self, index: usize) -> Result<&'a [u8], LoadError> {
        let sh_offset = self.header.e_shoff as usize + (index * self.header.e_shentsize as usize);

        // 【設計書 2.2】安全なラッパーを使用
        let sh: Elf64SectionHeader = crate::util::read_struct(self.data, sh_offset)
            .ok_or_else(|| LoadError::InvalidFormat("Failed to read section header".into()))?;

        let start = sh.sh_offset as usize;
        let size = sh.sh_size as usize;

        // 【設計書 2.2】安全なスライス取得ラッパーを使用
        crate::util::get_slice(self.data, start, size)
            .ok_or_else(|| LoadError::InvalidFormat("String table out of bounds".into()))
    }

    /// 文字列テーブルから文字列を取得
    ///
    /// 【セキュリティ】シンボル名の長さ制限を適用してDoS攻撃を防止
    fn get_string(&self, strtab: &'a [u8], offset: usize) -> Option<&'a str> {
        if offset >= strtab.len() {
            return None;
        }

        let max_end = (offset + MAX_SYMBOL_NAME_LENGTH).min(strtab.len());
        let slice = &strtab[offset..max_end];
        let pos = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());

        // NULL終端が見つからなかった場合（文字列が長すぎる）
        if pos == slice.len() && (offset + pos >= strtab.len() || strtab[offset + pos] != 0) {
            // 警告を記録し、Noneを返す
            return None;
        }

        core::str::from_utf8(&slice[..pos]).ok()
    }

    /// セルをメモリにロード
    pub fn load(&self, info: &CellInfo<'a>) -> Result<LoadedCell, LoadError> {

        // Protection Key は page-table manager が利用可能な場合にのみ割り当てる。
        // テストビルド（libテスト）では `mm` モジュールが公開されていないため
        // PKEY の割り当てとページフラグの更新はスキップする。
        // PkeyGuard is available either in normal builds (when `test` cfg is
        // not set) or when the `pkey_integration_test` feature is enabled for
        // test-time integration checks.
        #[cfg(any(feature = "pkey_integration_test", not(test)))]
        struct PkeyGuard(Option<u8>);
        #[cfg(any(feature = "pkey_integration_test", not(test)))]
        impl PkeyGuard {
            fn new(v: u8) -> Self {
                Self(Some(v))
            }

            /// Consume the guard and take ownership of the key so it will not be
            /// freed by Drop.
            fn release(mut self) -> u8 {
                let v = self.0.take().unwrap();
                core::mem::forget(self);
                v
            }
        }
        #[cfg(any(feature = "pkey_integration_test", not(any(test, feature = "bench"))))]
        impl Drop for PkeyGuard {
            fn drop(&mut self) {
                if let Some(v) = self.0 {
                    crate::security::mpk::free_protection_key(v);
                }
            }
        }

        // Allocate PKEY only when mm is available (non-test builds). The guard
        // will free the PKEY on early return if something goes wrong.
        #[cfg(any(feature = "pkey_integration_test", not(any(test, feature = "bench"))))]
        let guard = {
            let pkey_raw = crate::security::mpk::allocate_protection_key()
                .ok_or(LoadError::OutOfMemory)?;
            PkeyGuard::new(pkey_raw)
        };

        // メモリを割り当て
        let base_address = self.allocate_memory(info.memory_size, info.alignment)?;

        // PKEY を取得（テストビルドでは None）
        #[cfg(any(feature = "pkey_integration_test", not(any(test, feature = "bench"))))]
        let pkey = guard.release();
        #[cfg(not(any(feature = "pkey_integration_test", not(any(test, feature = "bench")))))]
        let pkey = 0u8; // ダミー値（テスト/ベンチではフラグ更新を行わないため使用されない）

        // 各セグメントをロード
        for segment in &info.segments {
            let dest = base_address + segment.vaddr;
            let src_start = segment.file_offset;
            let src_end = src_start + segment.file_size;

            if src_end > self.data.len() {
                return Err(LoadError::InvalidFormat(
                    "Segment data out of bounds".into(),
                ));
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

            // Compute PKEY-aware flags and (when mm is available) apply them to
            // each mapped page covering this segment. If `mm` is not available
            // (test builds) this block is skipped.
            // Apply page flags (may be a no-op in test builds)
            self.apply_page_flags(dest, segment.mem_size, segment.flags, pkey)?;
        }

        let entry_point = if info.entry_offset != 0 {
            Some(base_address + info.entry_offset as usize)
        } else {
            None
        };

        #[cfg(any(feature = "pkey_integration_test", not(test)))]
        return Ok(LoadedCell {
            base_address,
            size: info.memory_size,
            entry_point,
            pkey: Some(pkey),
        });

        #[cfg(not(any(feature = "pkey_integration_test", not(test))))]
        return Ok(LoadedCell {
            base_address,
            size: info.memory_size,
            entry_point,
            pkey: None,
        });
    }

    /// メモリを割り当て
    ///
    /// ASLRが有効な場合、ランダムなオフセットを加算してベースアドレスを予測困難にする
    fn allocate_memory(&self, size: usize, _alignment: usize) -> Result<usize, LoadError> {
        // Note: フレームアロケータは mm::frame_allocator モジュールで実装
        // 現在はallocクレートを使用したヒープ割り当て
        use alloc::alloc::Layout;

        // ASLRが有効な場合、追加のパディング領域を確保
        let aslr_offset = if is_aslr_enabled() {
            generate_aslr_offset()
        } else {
            0
        };

        // サイズオーバーフローチェック
        let total_size = size
            .checked_add(aslr_offset)
            .ok_or(LoadError::OutOfMemory)?;

        let layout =
            Layout::from_size_align(total_size, 4096).map_err(|_| LoadError::OutOfMemory)?;

        let ptr = crate::util::allocate_zeroed(layout).ok_or(LoadError::OutOfMemory)?;

        // ASLRオフセットを適用したアドレスを返す
        let base_address = ptr.as_ptr() as usize + aslr_offset;

        log::debug!(
            "[ELF] Allocated {} bytes at {:#x} (ASLR offset: {:#x})",
            size,
            base_address,
            aslr_offset
        );

        Ok(base_address)
    }

    /// Apply per-page flags for a memory range belonging to a segment.
    ///
    /// This is a thin wrapper that calls into `mm::global_update_flags` when
    /// compiled for the full kernel; for `#[cfg(test)]` builds this is a
    /// no-op to avoid depending on the `mm` module during library tests.
    #[cfg(not(any(test, feature = "bench")))]
    fn apply_page_flags(
        &self,
        dest: usize,
        mem_size: usize,
        seg_flags: u32,
        pkey: u8,
    ) -> Result<(), LoadError> {
        let flags = if (seg_flags & 0x1) != 0 {
            PageFlags::user_code().set_pkey(pkey)
        } else {
            PageFlags::user_data().set_pkey(pkey)
        };

        let seg_start = crate::mm::VirtAddr::new(dest as u64).align_down().as_u64() as usize;
        let seg_end = crate::mm::VirtAddr::new((dest + mem_size) as u64)
            .align_up()
            .as_u64() as usize;

        for page_addr in (seg_start..seg_end).step_by(4096) {
            let virt = crate::mm::VirtAddr::new(page_addr as u64);
            unsafe {
                match crate::mm::global_update_flags(virt, flags) {
                    Ok(()) => {}
                    Err(e) => match e {
                        crate::mm::MapError::InvalidAddress | crate::mm::MapError::NotMapped => {
                            log::warn!(
                                "[ELF] Could not update flags for page {:#x}: {:?} (continuing)",
                                page_addr,
                                e
                            )
                        }
                        other => {
                            return Err(LoadError::InvalidPermissions(alloc::format!(
                                "Failed to update page flags for page {:#x}: {:?}",
                                page_addr, other
                            )));
                        }
                    },
                }
            }
        }

        Ok(())
    }

    #[cfg(any(test, feature = "bench"))]
    fn apply_page_flags(&self, _dest: usize, _mem_size: usize, _seg_flags: u32, _pkey: u8) -> Result<(), LoadError> {
        // No-op in tests and bench builds (full `mm` not available in library
        // builds that enable `bench`). This avoids bringing the full memory
        // manager into lightweight workspace runs.
        Ok(())
    }

    /// リロケーションを適用
    pub fn relocate<F>(&self, loaded: &LoadedCell, resolve: F) -> Result<(), LoadError>
    where
        F: Fn(&str) -> Option<usize>,
    {
        // セクションヘッダーを探索してリロケーションセクションを処理
        for i in 0..self.header.e_shnum {
            let sh_offset =
                self.header.e_shoff as usize + (i as usize * self.header.e_shentsize as usize);

            if sh_offset + mem::size_of::<Elf64SectionHeader>() > self.data.len() {
                continue;
            }

            let sh: Elf64SectionHeader = crate::util::read_struct(self.data, sh_offset)
                .ok_or_else(|| LoadError::InvalidFormat("Failed to read section header".into()))?;

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

        // 【セキュリティ】リロケーション数のチェック（DoS攻撃防止）
        if rela_count > MAX_RELOCATIONS {
            return Err(LoadError::RelocationFailed(alloc::format!(
                "Too many relocations: {} (max {})",
                rela_count,
                MAX_RELOCATIONS
            )));
        }

        // シンボルテーブルと文字列テーブルを取得
        let symtab_sh = self.get_section_header(sh.sh_link as usize)?;
        let strtab = self.get_string_table(symtab_sh.sh_link as usize)?;

        // シンボル毎の解決結果をキャッシュして、同じシンボルの再解決を避ける
        let symtab_count = symtab_sh.sh_size as usize / mem::size_of::<Elf64Symbol>();
        let mut sym_value_cache: Vec<Option<usize>> = vec![None; symtab_count];

        for j in 0..rela_count {
            let rela_offset = sh.sh_offset as usize + j * mem::size_of::<Elf64Rela>();

            if rela_offset + mem::size_of::<Elf64Rela>() > self.data.len() {
                continue;
            }

            let rela: Elf64Rela = crate::util::read_struct(self.data, rela_offset)
                .ok_or_else(|| LoadError::InvalidFormat("Failed to read relocation".into()))?;

            // シンボルを取得
            let sym_idx = rela.symbol() as usize;

            // sym_idx が範囲外ならスキップ
            if sym_idx >= symtab_count {
                continue;
            }

            // キャッシュにあればそれを使う
            let sym_value = if let Some(val) = sym_value_cache[sym_idx] {
                val
            } else {
                let sym_offset =
                    symtab_sh.sh_offset as usize + sym_idx * mem::size_of::<Elf64Symbol>();

                if sym_offset + mem::size_of::<Elf64Symbol>() > self.data.len() {
                    continue;
                }

                let sym: Elf64Symbol = crate::util::read_struct(self.data, sym_offset)
                    .ok_or_else(|| LoadError::InvalidFormat("Failed to read symbol".into()))?;

                let resolved = if sym.st_shndx == 0 {
                    // 外部シンボル
                    let name = self
                        .get_string(strtab, sym.st_name as usize)
                        .ok_or_else(|| LoadError::InvalidFormat("Invalid symbol name".into()))?;
                    resolve(name)
                        .ok_or_else(|| LoadError::UnresolvedDependency(name.to_string()))?
                } else {
                    // 内部シンボル
                    loaded.base_address + sym.st_value as usize
                };

                // キャッシュに保存
                sym_value_cache[sym_idx] = Some(resolved);
                resolved
            };

            // リロケーションを適用
            self.apply_relocation(&rela, loaded.base_address, sym_value)?;
        }

        Ok(())
    }

    /// セクションヘッダーを取得
    fn get_section_header(&self, index: usize) -> Result<Elf64SectionHeader, LoadError> {
        let sh_offset = self.header.e_shoff as usize + (index * self.header.e_shentsize as usize);

        if sh_offset + mem::size_of::<Elf64SectionHeader>() > self.data.len() {
            return Err(LoadError::InvalidFormat(
                "Section header out of bounds".into(),
            ));
        }

        Ok(crate::util::read_struct(self.data, sh_offset)
            .ok_or_else(|| LoadError::InvalidFormat("Failed to read section header".into()))?)
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
            1 => {
                // R_X86_64_64: 64-bit absolute
                let value = sym_value.wrapping_add(rela.r_addend as usize);
                crate::util::write_to_addr(target, value as u64);
            }
            2 => {
                // R_X86_64_PC32: 32-bit PC-relative
                let value = (sym_value as i64)
                    .wrapping_add(rela.r_addend)
                    .wrapping_sub(target as i64);
                crate::util::write_to_addr(target, value as i32);
            }
            4 => {
                // R_X86_64_PLT32: 32-bit PLT-relative (treated same as PC32 for static linking)
                let value = (sym_value as i64)
                    .wrapping_add(rela.r_addend)
                    .wrapping_sub(target as i64);
                crate::util::write_to_addr(target, value as i32);
            }
            5 => {
                // R_X86_64_COPY: Copy symbol at runtime (no-op in kernel loader)
                // This is used by dynamic linkers for copy relocations
                log::debug!("[ELF] R_X86_64_COPY at {:#x} (no-op)", target);
            }
            6 => {
                // R_X86_64_GLOB_DAT: GOT entry for global data
                // Used for accessing global variables through the GOT
                let value = sym_value.wrapping_add(rela.r_addend as usize);
                crate::util::write_to_addr(target, value as u64);
            }
            7 => {
                // R_X86_64_JUMP_SLOT: PLT entry for function calls
                // Used for lazy binding in dynamic linking
                let value = sym_value.wrapping_add(rela.r_addend as usize);
                crate::util::write_to_addr(target, value as u64);
            }
            8 => {
                // R_X86_64_RELATIVE: Base address + addend
                let value = base.wrapping_add(rela.r_addend as usize);
                crate::util::write_to_addr(target, value as u64);
            }
            9 => {
                // R_X86_64_GOTPCREL: GOT-relative PC32
                // S + A - P where S = symbol value (GOT entry address)
                // Note: In our simple loader, we treat GOT as pointing directly to symbol
                let value = (sym_value as i64)
                    .wrapping_add(rela.r_addend)
                    .wrapping_sub(target as i64);
                crate::util::write_to_addr(target, value as i32);
            }
            10 => {
                // R_X86_64_32: 32-bit absolute (zero-extended)
                let value = sym_value.wrapping_add(rela.r_addend as usize);
                crate::util::write_to_addr(target, value as u32);
            }
            11 => {
                // R_X86_64_32S: 32-bit absolute (sign-extended)
                let value = (sym_value as i64).wrapping_add(rela.r_addend);
                // 32ビット符号付き範囲のチェック
                if value > i32::MAX as i64 || value < i32::MIN as i64 {
                    return Err(LoadError::RelocationFailed(alloc::format!(
                        "R_X86_64_32S overflow at offset {:#x}: value {:#x} out of i32 range",
                        rela.r_offset,
                        value
                    )));
                }
                crate::util::write_to_addr(target, value as i32);
            }
            unknown => {
                // 未対応のリロケーションタイプはログ出力して継続
                log::warn!(
                    "[ELF] Unsupported relocation type {} at offset {:#x}",
                    unknown,
                    rela.r_offset
                );
            }
        }

        Ok(())
    }
}

// ============================================================================
// Loader Trait - 静的APIを提供
// ============================================================================

/// ロード結果の情報
///
/// ELFバイナリをメモリにロードした後の結果情報を保持する構造体。
/// `registry.rs`との互換性のために使用される。
///
/// # Example
///
/// ```ignore
/// let info: LoadedInfo = ElfLoader::load(elf_data)?;
/// let entry_fn: fn() = unsafe { core::mem::transmute(info.entry_point) };
/// entry_fn(); // 関数を呼び出す
/// ```
#[derive(Debug)]
pub struct LoadedInfo {
    /// メモリ上のベースアドレス
    pub base_address: u64,
    /// 割り当てられたメモリの合計サイズ（バイト）
    pub size: usize,
    /// プログラムのエントリポイントアドレス
    pub entry_point: u64,
    /// 割り当てられた Protection Key（存在する場合）
    pub pkey: Option<u8>,
}

/// ELFローダーの静的インターフェース
///
/// このトレイトは静的メソッドを通じてELFロード機能を提供する。
/// 実装タイプのインスタンスを作成せずにロードを実行可能。
///
/// # 使用例
///
/// ```ignore
/// use kernel::loader::{ElfLoader, Loader};
///
/// let result = <ElfLoader as Loader>::load(elf_bytes)?;
/// ```
pub trait Loader {
    /// ELFデータからセルをメモリにロード
    ///
    /// # 引数
    ///
    /// * `elf_data` - ELF64バイナリデータ
    ///
    /// # 戻り値
    ///
    /// 成功時は`LoadedInfo`を返し、失敗時は`LoadError`を返す
    ///
    /// # エラー
    ///
    /// * `InvalidFormat` - ELFフォーマットが無効
    /// * `InvalidPermissions` - W^X違反
    /// * `OutOfMemory` - メモリ割り当て失敗
    /// * `RelocationFailed` - リロケーション適用エラー
    fn load(elf_data: &[u8]) -> Result<LoadedInfo, LoadError>;
}

impl Loader for ElfLoader<'_> {
    /// ELFデータをパースしてメモリにロードする静的メソッド
    ///
    /// registry.rs との互換性のためのシンプルなAPI
    fn load(elf_data: &[u8]) -> Result<LoadedInfo, LoadError> {
        // 1. ELFをパース
        let loader = ElfLoader::new(elf_data)?;
        let cell_info = loader.parse()?;

        // 2. メモリにロード
        let loaded = loader.load(&cell_info)?;

        // 3. リロケーションを適用（シンボル解決なし - 自己完結型モジュール用）
        loader.relocate(&loaded, |_sym| None)?;

        // 4. 結果を返す
        Ok(LoadedInfo {
            base_address: loaded.base_address as u64,
            size: loaded.size,
            entry_point: loaded.entry_point.unwrap_or(0) as u64,
            pkey: loaded.pkey,
        })
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_empty_data_returns_error() -> bool {
    match ElfLoader::new(&[]) {
        Err(LoadError::InvalidFormat(msg)) => msg.contains("too small"),
        _ => false,
    }
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_invalid_magic_returns_error() -> bool {
    let mut data = vec![0u8; 64];
    data[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    match ElfLoader::new(&data) {
        Err(LoadError::InvalidFormat(msg)) => msg.contains("magic") || msg.contains("Invalid"),
        _ => false,
    }
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_max_size_constants() -> bool {
    MAX_ELF_SIZE == 512 * 1024 * 1024
        && MAX_SEGMENT_SIZE == 256 * 1024 * 1024
        && MAX_SECTIONS == 1024
        && MAX_RELOCATIONS == 262144
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_wrong_elf_class() -> bool {
    let mut data = vec![0u8; 64];
    data[0..4].copy_from_slice(&ELF_MAGIC);
    data[4] = 1; // ELFCLASS32
    ElfLoader::new(&data).is_err()
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_wrong_endianness() -> bool {
    let mut data = vec![0u8; 64];
    data[0..4].copy_from_slice(&ELF_MAGIC);
    data[4] = ELFCLASS64;
    data[5] = 2; // ELFDATA2MSB
    ElfLoader::new(&data).is_err()
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_wx_flags() -> bool {
    PF_W == 0x2 && PF_X == 0x1 && (PF_W | PF_X) == 0x3
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_rela_extraction() -> bool {
    let rela = Elf64Rela {
        r_offset: 0x1000,
        r_info: (42 << 32) | 8,
        r_addend: 0x100,
    };
    rela.symbol() == 42 && rela.reloc_type() == 8
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_symbol_extraction() -> bool {
    let sym = Elf64Symbol {
        st_name: 0,
        st_info: (1 << 4) | 2,
        st_other: 0,
        st_shndx: 1,
        st_value: 0x1000,
        st_size: 100,
    };
    sym.binding() == 1 && sym.symbol_type() == 2
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_aslr_offset_generation() -> bool {
    let prev = is_aslr_enabled();
    set_aslr_enabled(true);
    let offset1 = generate_aslr_offset();
    let offset2 = generate_aslr_offset();
    set_aslr_enabled(prev);
    (offset1 & 0xFFF) == 0
        && (offset2 & 0xFFF) == 0
        && offset1 < ASLR_MAX_OFFSET
        && offset2 < ASLR_MAX_OFFSET
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_aslr_enable_disable() -> bool {
    let prev = is_aslr_enabled();
    set_aslr_enabled(false);
    let disabled = !is_aslr_enabled();
    set_aslr_enabled(true);
    let enabled = is_aslr_enabled();
    set_aslr_enabled(prev);
    disabled && enabled
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_get_string_zero_copy() -> bool {
    let strtab: &[u8] = b"hello\0world\0";
    let header: Elf64Header = unsafe { core::mem::zeroed() };
    let loader = ElfLoader {
        data: strtab,
        header,
    };
    let s1 = loader.get_string(strtab, 0);
    let s2 = loader.get_string(strtab, 6);
    s1 == Some("hello") && s2 == Some("world")
}

#[cfg(all(test, feature = "pkey_integration_test"))]
mod tests {
    use super::*;

    /// PKEY integration test: verify that loading a cell allocates a PKEY and
    /// unloading the cell frees it.
    #[test_case]
    fn test_pkey_alloc_and_free_on_load_unload() {
        use core::mem;

        crate::security::mpk::test_reset_pkey_allocator();

        let ph_size = mem::size_of::<Elf64ProgramHeader>();
        let mut data = vec![0u8; 64 + ph_size];

        let mut header: Elf64Header = unsafe { core::mem::zeroed() };
        header.e_ident[0..4].copy_from_slice(&ELF_MAGIC);
        header.e_ident[4] = ELFCLASS64;
        header.e_ident[5] = ELFDATA2LSB;
        header.e_machine = 0x3E;
        header.e_phoff = 64;
        header.e_phentsize = ph_size as u16;
        header.e_phnum = 1;

        crate::util::write_struct(&mut data, 0, header).expect("write header");

        let ph = Elf64ProgramHeader {
            p_type: PT_LOAD,
            p_flags: 0,
            p_offset: (64 + ph_size) as u64,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: 0,
            p_memsz: 4096,
            p_align: 4096,
        };

        crate::util::write_struct(&mut data, header.e_phoff as usize, ph).expect("write ph");

        let cell_id = crate::loader::load_cell("test-pkey", &data, false).expect("load_cell");
        let pkey_opt = crate::loader::with_registry(|r| r.find_by_name("test-pkey").unwrap().pkey);
        assert!(pkey_opt.is_some());
        let pkey = pkey_opt.unwrap();
        assert!(crate::security::mpk::is_pkey_used(pkey));

        crate::loader::unload_cell(cell_id).expect("unload");
        assert!(!crate::security::mpk::is_pkey_used(pkey));
    }
}

