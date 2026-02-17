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
mod _split_1;
use _split_1::*;
mod _split_2;
use _split_2::*;
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

/// Validate ELF file size constraints.
fn validate_elf_size(data: &[u8]) -> Result<(), LoadError> {
    if data.len() < mem::size_of::<Elf64Header>() {
        return Err(LoadError::InvalidFormat("File too small".into()));
    }
    if data.len() > MAX_ELF_SIZE {
        return Err(LoadError::InvalidFormat(alloc::format!(
            "ELF file too large: {} bytes (max {})",
            data.len(),
            MAX_ELF_SIZE
        )));
    }
    Ok(())
}
