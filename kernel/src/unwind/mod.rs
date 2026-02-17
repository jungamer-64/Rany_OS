// src/unwind/mod.rs
//! スタックアンワインドモジュール (ExoRust)
//!
//! # 設計書 8.1: スタックアンワインド
//!
//! ## 安全性に関する注記
//! - 可能な限り `gimli` feature を有効にして使用してください
//! - 手動パース実装はフォールバック用であり、厳密な境界チェックを行いますが、
//!   複雑なDWARF式の評価には対応していません
//!
//! ## 機能
//! - DWARFベースのアンワインド情報解析
//! - .eh_frame セクション解析
//! - パニック時のバックトレース生成
//! - フレームポインタベースのアンワインド（フォールバック）

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
//! - gimliベースの高精度アンワインド（オプション）
//!
//! ## アーキテクチャ
//! ```text
//! +------------------+
//! |  gimli_unwinder  |  <- 推奨: 型安全・高精度
//! +------------------+
//!         |
//!         v (フォールバック)
//! +------------------+
//! |  SafeEhFrameParser |  <- MemoryReaderベース・境界チェック付き
//! +------------------+
//!         |
//!         v (フォールバック)
//! +------------------+
//! |  Frame Pointer   |  <- RBPチェーン追跡
//! +------------------+
//! ```

// ============================================================================
// サブモジュール
// ============================================================================

// gimliベースの高精度アンワインダー
// feature = "gimli_unwind" で有効化
#[cfg(feature = "gimli_unwind")]
pub mod gimli_unwinder;

// 型安全なメモリリーダー
pub mod reader;

// 型安全なレジスタ定義
pub mod registers;

// ============================================================================
// Re-exports
// ============================================================================

pub use reader::MemoryReader;
pub use registers::DwarfRegister;

// Drop guard関連のエクスポート（gimli feature有効時）
#[cfg(feature = "gimli_unwind")]
pub use gimli_unwinder::{
    DomainLockInfo, DomainUnwinder, DropGuard, register_domain_lock, register_drop_guard,
    unregister_domain_lock, unregister_drop_guard,
};

// catch_panic機構のエクスポート
// 設計書 8.1/8.2: ドメイン境界でのパニック捕捉
// pub use catch_panic::{...} は後方で定義されているため、ここでは宣言のみ

use core::fmt;
use core::ptr;

/// アンワインドエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwindError {
    /// 不正なフレームポインタ
    InvalidFramePointer,
    /// フレームの終端に到達
    EndOfStack,
    /// .eh_frame セクションが見つからない
    NoEhFrame,
    /// 不正なDWARFデータ
    InvalidDwarf,
    /// CIEが見つからない
    CieNotFound,
    /// 不明な命令
    UnknownInstruction,
    /// メモリ読み取りエラー
    MemoryReadError,
    /// アンワインド情報が見つからない
    NoUnwindInfo,
    /// サポートされていないDWARF式
    UnsupportedDwarfExpression,
}

/// スタックフレーム情報
#[derive(Debug, Clone, Copy)]
pub struct StackFrame {
    /// 命令ポインタ (リターンアドレス)
    pub instruction_pointer: usize,
    /// スタックポインタ
    pub stack_pointer: usize,
    /// フレームポインタ (RBP)
    pub frame_pointer: usize,
}

/// シンボル情報（オプション）
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    /// シンボル名
    pub name: Option<&'static str>,
    /// シンボルのベースアドレス
    pub base_address: usize,
    /// シンボル内のオフセット
    pub offset: usize,
}

/// バックトレースエントリ
#[derive(Debug, Clone)]
pub struct BacktraceEntry {
    /// フレーム番号
    pub frame_number: usize,
    /// スタックフレーム情報
    pub frame: StackFrame,
    /// シンボル情報（利用可能な場合）
    pub symbol: Option<SymbolInfo>,
}

impl fmt::Display for BacktraceEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{:2}: ", self.frame_number)?;

        if let Some(ref sym) = self.symbol {
            if let Some(name) = sym.name {
                write!(f, "{} + {:#x}", name, sym.offset)?;
            } else {
                write!(f, "{:#018x}", self.frame.instruction_pointer)?;
            }
        } else {
            write!(f, "{:#018x}", self.frame.instruction_pointer)?;
        }

        write!(f, " (SP: {:#018x})", self.frame.stack_pointer)
    }
}

/// バックトレース
pub struct Backtrace {
    entries: [Option<BacktraceEntry>; MAX_FRAMES],
    count: usize,
}

const MAX_FRAMES: usize = 64;

impl Backtrace {
    /// 新しいバックトレースを作成
    pub fn new() -> Self {
        const NONE: Option<BacktraceEntry> = None;
        Self {
            entries: [NONE; MAX_FRAMES],
            count: 0,
        }
    }

    /// 現在の位置からバックトレースをキャプチャ
    pub fn capture() -> Self {
        let mut bt = Self::new();
        bt.capture_frames();
        bt
    }

    /// フレームをキャプチャ
    fn capture_frames(&mut self) {
        // 現在のフレームポインタを取得
        let mut rbp: usize;
        unsafe {
            core::arch::asm!(
                "mov {}, rbp",
                out(reg) rbp,
                options(nostack, preserves_flags)
            );
        }

        let mut frame_num = 0;

        // フレームポインタチェーンをたどる
        while frame_num < MAX_FRAMES {
            // フレームポインタの有効性チェック
            if !is_valid_stack_address(rbp) {
                break;
            }

            // リターンアドレスとスタックポインタを取得
            let return_addr = read_usize_checked(rbp + 8).unwrap_or(0);
            let next_rbp = read_usize_checked(rbp).unwrap_or(0);

            // 無効なリターンアドレスで終了
            if return_addr == 0 || !is_valid_code_address(return_addr) {
                break;
            }

            let frame = StackFrame {
                instruction_pointer: return_addr,
                stack_pointer: rbp + 16,
                frame_pointer: rbp,
            };

            // シンボル情報を解決（可能な場合）
            let symbol = resolve_symbol(return_addr);

            self.entries[frame_num] = Some(BacktraceEntry {
                frame_number: frame_num,
                frame,
                symbol,
            });

            frame_num += 1;

            // 次のフレームへ
            if next_rbp == 0 || next_rbp <= rbp {
                break;
            }
            rbp = next_rbp;
        }

        self.count = frame_num;
    }

    /// フレーム数を取得
    pub fn len(&self) -> usize {
        self.count
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// イテレータを取得
    pub fn iter(&self) -> impl Iterator<Item = &BacktraceEntry> {
        self.entries
            .iter()
            .take(self.count)
            .filter_map(|e| e.as_ref())
    }
}

impl fmt::Display for Backtrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Stack backtrace:")?;
        for entry in self.iter() {
            writeln!(f, "  {}", entry)?;
        }
        Ok(())
    }
}

impl Default for Backtrace {
    fn default() -> Self {
        Self::new()
    }
}

/// 有効なスタックアドレスかチェック
fn is_valid_stack_address(addr: usize) -> bool {
    // スタックは通常高位アドレスにある
    // カーネルスタックの範囲をチェック
    if addr == 0 || addr > 0xFFFF_FFFF_FFFF_0000 {
        return false;
    }

    // アライメントチェック
    if addr % 8 != 0 {
        return false;
    }

    true
}

/// 有効なコードアドレスかチェック
fn is_valid_code_address(addr: usize) -> bool {
    // カーネルコードセグメントの範囲をチェック
    // 実際の実装ではカーネルのロードアドレス範囲を確認
    if addr == 0 {
        return false;
    }

    // 高位カノニカルアドレスはカーネル空間
    addr >= 0xFFFF_8000_0000_0000 || addr < 0x0000_8000_0000_0000
}

/// 安全なポインタ読み取り: usize
pub(crate) fn read_usize_checked(addr: usize) -> Option<usize> {
    if !is_valid_stack_address(addr) {
        return None;
    }
    // Use centralized util to read from an address, which performs the unsafe read internally
    Some(crate::util::read_unaligned_from_addr::<usize>(addr))
}

/// 安全なポインタ読み取り: u64
pub(crate) fn read_u64_checked(addr: usize) -> Option<u64> {
    if !is_valid_stack_address(addr) {
        return None;
    }
    Some(crate::util::read_unaligned_from_addr::<u64>(addr))
}

// ============================================================================
// カーネルシンボルテーブル
// 設計書 8.1: バックトレース解決用
// ============================================================================

/// シンボルテーブル（リンカスクリプトで提供）
///
/// NOTE: __ksym_start/__ksym_end はリンカスクリプトで定義される必要があります。
/// 現在はダミーのシンボルを提供して、シンボルテーブルが利用できない場合は
/// gracefulに処理します。

// カーネルシンボルテーブルのダミー定義
// 実際のシンボルテーブルはリンカスクリプトで上書きされる
#[cfg(not(test))]
#[unsafe(no_mangle)]
#[used]
#[unsafe(link_section = ".ksymtab")]
static __KSYM_DUMMY: u8 = 0;

// .eh_frameセクション境界（リンカスクリプトで定義）
#[allow(improper_ctypes)]
unsafe extern "C" {
    #[link_name = "__eh_frame_start"]
    static EH_FRAME_START: u8;
    #[link_name = "__eh_frame_end"]
    static EH_FRAME_END: u8;
}

// シンボルテーブル境界のダミー（テーブルがない場合は空）
static mut KSYM_START_ADDR: usize = 0;
static mut KSYM_END_ADDR: usize = 0;

/// シンボルテーブルエントリ
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KernelSymbol {
    /// シンボルのアドレス
    pub address: usize,
    /// シンボル名の長さ
    pub name_len: u16,
    /// シンボルサイズ
    pub size: u32,
    /// シンボルタイプ (0=func, 1=data)
    pub sym_type: u8,
    /// パディング
    _padding: u8,
    // 名前はこの構造体の直後に続く
}

/// カーネルシンボルテーブル
pub struct KernelSymbolTable {
    /// シンボルの開始アドレス
    base: usize,
    /// シンボルテーブルの終了アドレス
    end: usize,
    /// シンボル数（キャッシュ）
    count: usize,
}

impl KernelSymbolTable {
    /// シンボルテーブルを初期化
    pub fn new() -> Option<Self> {
        unsafe {
            // ダミーアドレスを使用（実際はリンカスクリプトで設定される）
            let start = KSYM_START_ADDR;
            let end = KSYM_END_ADDR;

            if start == 0 || end == 0 || end <= start {
                return None;
            }

            // シンボル数をカウント
            let mut offset = 0;
            let mut count = 0;
            while start + offset < end {
                let sym = &*((start + offset) as *const KernelSymbol);
                let entry_size = core::mem::size_of::<KernelSymbol>() + sym.name_len as usize;
                // 8バイトアライメント
                let aligned_size = (entry_size + 7) & !7;
                offset += aligned_size;
                count += 1;
            }

            Some(Self {
                base: start,
                end,
                count,
            })
        }
    }

    /// アドレスからシンボルを検索
    pub fn lookup(&self, address: usize) -> Option<(&KernelSymbol, &str)> {
        let mut best_match: Option<(&KernelSymbol, &str)> = None;
        let mut best_distance = usize::MAX;

        let mut offset = 0;
        while self.base + offset < self.end {
            let (sym, name, aligned_size) = match self.symbol_at(offset) {
                Some(value) => value,
                None => break,
            };

            // アドレスがこのシンボルの範囲内かチェック
            if address >= sym.address {
                let distance = address - sym.address;

                // サイズが分かる場合は範囲内かチェック
                if sym.size > 0 && distance < sym.size as usize {
                    return Some((sym, name));
                }

                // 最も近いシンボルを記録
                if distance < best_distance {
                    best_distance = distance;
                    best_match = Some((sym, name));
                }
            }

            // 次のエントリへ
            offset += aligned_size;
        }

        // 距離が大きすぎる場合は無効
        if best_distance > 0x10000 {
            return None;
        }

        best_match
    }

    /// シンボル数を取得
    pub fn symbol_count(&self) -> usize {
        self.count
    }

    /// イテレータを取得
    pub fn iter(&self) -> KernelSymbolIter<'_> {
        KernelSymbolIter {
            table: self,
            offset: 0,
        }
    }

    /// シンボル名をアドレスから読み取る
    fn read_symbol_name(&self, sym_end: usize, name_len: usize) -> Option<(&str, usize)> {
        let name_start = sym_end;
        let name_end = name_start.checked_add(name_len)?;
        if name_end > self.end {
            return None;
        }

        let name_bytes = unsafe { core::slice::from_raw_parts(name_start as *const u8, name_len) };
        let name = core::str::from_utf8(name_bytes).ok()?;

        let entry_size = core::mem::size_of::<KernelSymbol>().checked_add(name_len)?;
        let aligned_size = entry_size.checked_add(7)? & !7;
        if aligned_size == 0 {
            return None;
        }

        Some((name, aligned_size))
    }

    fn symbol_at(&self, offset: usize) -> Option<(&KernelSymbol, &str, usize)> {
        let base = self.base.checked_add(offset)?;
        let sym_end = base.checked_add(core::mem::size_of::<KernelSymbol>())?;
        if sym_end > self.end {
            return None;
        }

        let sym = unsafe { &*(base as *const KernelSymbol) };
        let (name, aligned_size) = self.read_symbol_name(sym_end, sym.name_len as usize)?;

        Some((sym, name, aligned_size))
    }
}

impl Default for KernelSymbolTable {
    fn default() -> Self {
        Self::new().unwrap_or(Self {
            base: 0,
            end: 0,
            count: 0,
        })
    }
}

/// シンボルイテレータ
pub struct KernelSymbolIter<'a> {
    table: &'a KernelSymbolTable,
    offset: usize,
}

impl<'a> Iterator for KernelSymbolIter<'a> {
    type Item = (&'a KernelSymbol, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        if self.table.base + self.offset >= self.table.end {
            return None;
        }

        let (sym, name, aligned_size) = self.table.symbol_at(self.offset)?;
        self.offset += aligned_size;
        Some((sym, name))
    }
}

/// グローバルシンボルテーブル
static KERNEL_SYMBOLS: spin::Once<Option<KernelSymbolTable>> = spin::Once::new();

/// シンボルテーブルを初期化
pub fn init_symbol_table() {
    KERNEL_SYMBOLS.call_once(|| KernelSymbolTable::new());

    if let Some(Some(table)) = KERNEL_SYMBOLS.get() {
        log::info!(
            "[UNWIND] Kernel symbol table loaded: {} symbols\n",
            table.symbol_count()
        );
    } else {
        log::info!("[UNWIND] No kernel symbol table available\n");
    }
}

/// シンボル情報を解決(内部)
fn resolve_symbol(address: usize) -> Option<SymbolInfo> {
    // まずシンボルテーブルから検索
    if let Some(Some(table)) = KERNEL_SYMBOLS.get() {
        if let Some((sym, name)) = table.lookup(address) {
            return Some(SymbolInfo {
                name: Some(unsafe {
                    // 'static ライフタイムに変換（シンボルテーブルは静的）
                    core::mem::transmute::<&str, &'static str>(name)
                }),
                base_address: sym.address,
                offset: address - sym.address,
            });
        }
    }

    // シンボルテーブルがない場合はNone
    None
}

/// ヘルパー: アドレスからシンボル名（存在する場合）を返す
/// 診断用に外部から呼べるように公開
pub fn resolve_symbol_name(address: usize) -> Option<&'static str> {
    resolve_symbol(address).and_then(|s| s.name)
}

/// パニックハンドラ用バックトレース表示
pub fn print_backtrace() {
    let bt = Backtrace::capture();

    // VGAまたはシリアルに出力
    // ここでは単にバックトレースを生成
    for entry in bt.iter() {
        // 実際の出力処理
        let _ = entry;
    }
}

/// レジスタ状態からバックトレースをキャプチャ
pub fn capture_from_context(rip: usize, rsp: usize, rbp: usize) -> Backtrace {
    let mut bt = Backtrace::new();
    let mut current_rbp = rbp;
    let mut frame_num = 1;

    // 最初のフレーム（クラッシュ位置）
    bt.entries[0] = Some(BacktraceEntry {
        frame_number: 0,
        frame: StackFrame {
            instruction_pointer: rip,
            stack_pointer: rsp,
            frame_pointer: rbp,
        },
        symbol: resolve_symbol(rip),
    });

    // フレームチェーンをたどる
    while frame_num < MAX_FRAMES && is_valid_stack_address(current_rbp) {
        let return_addr = read_usize_checked(current_rbp + 8).unwrap_or(0);
        let next_rbp = read_usize_checked(current_rbp).unwrap_or(0);

        if return_addr == 0 || !is_valid_code_address(return_addr) {
            break;
        }

        bt.entries[frame_num] = Some(BacktraceEntry {
            frame_number: frame_num,
            frame: StackFrame {
                instruction_pointer: return_addr,
                stack_pointer: current_rbp + 16,
                frame_pointer: current_rbp,
            },
            symbol: resolve_symbol(return_addr),
        });

        frame_num += 1;

        if next_rbp == 0 || next_rbp <= current_rbp {
            break;
        }
        current_rbp = next_rbp;
    }

    bt.count = frame_num;
    bt
}

/// グローバルな .eh_frame データを取得
pub fn get_eh_frame_data() -> Option<&'static [u8]> {
    unsafe {
        let start = &EH_FRAME_START as *const u8 as usize;
        let end = &EH_FRAME_END as *const u8 as usize;

        if start != 0 && end > start {
            Some(core::slice::from_raw_parts(start as *const u8, end - start))
        } else {
            None
        }
    }
}

/// CFA（Canonical Frame Address）を計算する
fn compute_cfa(ctx: &registers::UnwindContext, frame: &StackFrame) -> Result<u64, UnwindError> {
    match ctx.cfa() {
        registers::CfaRule::RegisterOffset { register, offset } => {
            let base = match register {
                DwarfRegister::Rsp => frame.stack_pointer as u64,
                DwarfRegister::Rbp => frame.frame_pointer as u64,
                _ => return Err(UnwindError::InvalidDwarf),
            };
            Ok((base as i64 + offset) as u64)
        }
        registers::CfaRule::Expression { .. } => {
            Err(UnwindError::UnsupportedDwarfExpression)
        }
    }
}

/// リターンアドレスをCFAから解決する
fn resolve_return_address(ctx: &registers::UnwindContext, cfa: u64) -> Result<u64, UnwindError> {
    match ctx.get_register_rule(DwarfRegister::ReturnAddress) {
        registers::RegisterRule::Offset(off) => {
            let addr = (cfa as i64 + off) as usize;
            Ok(read_u64_checked(addr).unwrap_or(0))
        }
        _ => Err(UnwindError::InvalidDwarf),
    }
}

/// RBPをCFAから解決する
fn resolve_rbp(ctx: &registers::UnwindContext, cfa: u64, current_rbp: u64) -> u64 {
    match ctx.get_register_rule(DwarfRegister::Rbp) {
        registers::RegisterRule::Offset(off) => {
            let addr = (cfa as i64 + off) as usize;
            read_u64_checked(addr).unwrap_or(0)
        }
        registers::RegisterRule::SameValue => current_rbp,
        _ => 0,
    }
}

/// DWARF命令を実行する共通ヘルパー
fn execute_dwarf_instructions(
    parser: &mut SafeEhFrameParser,
    interpreter: &mut SafeCfiInterpreter,
    data_alignment_factor: i64,
    start: usize,
    end: usize,
    pc_limit: Option<u64>,
) {
    parser.reader.set_position(start);
    while parser.reader.position() < end {
        if let Some(target_pc) = pc_limit {
            if interpreter.location() > target_pc {
                break;
            }
        }
        if let Some(instr) = parser.parse_instruction(data_alignment_factor) {
            interpreter.execute(instr);
        }
    }
}

/// DWARFベースのアンワインドを実行
pub fn unwind_frame(frame: &StackFrame) -> Result<StackFrame, UnwindError> {
    // .eh_frame データを取得
    let eh_frame = get_eh_frame_data().ok_or(UnwindError::NoEhFrame)?;

    let mut parser = SafeEhFrameParser::new(eh_frame);

    // FDEを検索
    let fde = parser
        .find_fde(frame.instruction_pointer as u64)
        .ok_or(UnwindError::NoUnwindInfo)?;

    // CIEを取得し、必要な値をコピー（借用を解放するため）
    let (code_alignment_factor, data_alignment_factor, initial_start, initial_len) = {
        let cie = parser
            .get_cached_cie(fde.cie_offset)
            .ok_or(UnwindError::InvalidDwarf)?;
        (
            cie.code_alignment_factor,
            cie.data_alignment_factor,
            cie.initial_instructions_offset,
            cie.initial_instructions_len,
        )
    };

    // インタプリタを作成
    let mut interpreter = SafeCfiInterpreter::new(code_alignment_factor, data_alignment_factor);

    // CIEの初期命令を実行
    execute_dwarf_instructions(
        &mut parser, &mut interpreter, data_alignment_factor,
        initial_start, initial_start + initial_len, None,
    );

    // FDEの命令を実行（PCまで）
    let pc_offset = (frame.instruction_pointer as u64).saturating_sub(fde.initial_location);
    execute_dwarf_instructions(
        &mut parser, &mut interpreter, data_alignment_factor,
        fde.instructions_offset, fde.instructions_offset + fde.instructions_len, Some(pc_offset),
    );

    // CFAを計算
    let ctx = interpreter.context();
    let cfa = compute_cfa(ctx, frame)?;
    let return_address = resolve_return_address(ctx, cfa)?;
    let new_rbp = resolve_rbp(ctx, cfa, frame.frame_pointer as u64);

    Ok(StackFrame {
        instruction_pointer: return_address as usize,
        stack_pointer: cfa as usize,
        frame_pointer: new_rbp as usize,
    })
}

// ============================================================================
// 型安全版 .eh_frame パーサー（MemoryReader使用）
// ============================================================================

/// 型安全な .eh_frame パーサー
///
/// `MemoryReader` を使用して境界チェック付きの安全なパースを行う
pub struct SafeEhFrameParser<'a> {
    reader: MemoryReader<'a>,
    /// 解析されたCIEのキャッシュ（オフセットとCIEのペア）
    cie_cache_offsets: [u64; 16],
    cie_cache_entries: [Option<SafeCie>; 16],
    cie_cache_len: usize,
}

/// 型安全なCIE（Common Information Entry）
#[derive(Debug, Clone)]
pub struct SafeCie {
    pub version: u8,
    pub augmentation: AugmentationData,
    pub code_alignment_factor: u64,
    pub data_alignment_factor: i64,
    pub return_address_register: DwarfRegister,
    pub initial_instructions_offset: usize,
    pub initial_instructions_len: usize,
}

/// 型安全なFDE（Frame Description Entry）
#[derive(Debug, Clone)]
pub struct SafeFde {
    pub cie_offset: u64,
    pub initial_location: u64,
    pub address_range: u64,
    pub instructions_offset: usize,
    pub instructions_len: usize,
}

/// Augmentation データ
#[derive(Debug, Clone, Default)]
pub struct AugmentationData {
    pub has_lsda: bool,
    pub lsda_encoding: Option<u8>,
    pub has_personality: bool,
    pub personality_encoding: Option<u8>,
    pub personality_address: Option<u64>,
    pub fde_encoding: Option<u8>,
    pub is_signal_frame: bool,
}

/// 型安全なCFI命令
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeCfiInstruction {
    /// CFA定義: register + offset
    DefCfa {
        register: DwarfRegister,
        offset: u64,
    },
    /// CFAレジスタ変更
    DefCfaRegister { register: DwarfRegister },
    /// CFAオフセット変更
    DefCfaOffset { offset: u64 },
    /// レジスタをCFA相対オフセットで復元
    Offset {
        register: DwarfRegister,
        offset: i64,
    },
    /// レジスタ値維持
    SameValue { register: DwarfRegister },
    /// レジスタ状態未定義
    Undefined { register: DwarfRegister },
    /// 別レジスタに格納
    Register {
        register: DwarfRegister,
        source: DwarfRegister,
    },
    /// ロケーション進行
    AdvanceLoc { delta: u64 },
    /// 行状態保存
    RememberState,
    /// 行状態復元
    RestoreState,
    /// NOP
    Nop,
}

impl<'a> SafeEhFrameParser<'a> {
    /// 新しいパーサーを作成
    pub fn new(data: &'a [u8]) -> Self {
        const NONE_CIE: Option<SafeCie> = None;
        Self {
            reader: MemoryReader::new(data),
            cie_cache_offsets: [0; 16],
            cie_cache_entries: [NONE_CIE; 16],
            cie_cache_len: 0,
        }
    }

    /// 特定のPCに対応するFDEを検索
    /// 単一の eh_frame エントリを解析し、CIEならキャッシュ、FDEなら返す。
    /// pc にマッチしなFDEは `Ok(None)` 、マッチするものは `Ok(Some(fde))`。
    fn process_eh_frame_entry(&mut self, entry_start: usize, length: u64, pc: u64) -> Option<Option<SafeFde>> {
        let entry_end = self.reader.position() + length as usize;

        let cie_id = self.reader.read_u32().ok()?;

        if cie_id == 0 {
            // CIE: キャッシュして次へ
            let cie = self.parse_cie_content(length as usize - 4)?;
            self.cache_cie(entry_start as u64, cie);
            self.reader.set_position(entry_end);
            return Some(None);
        }

        // FDE
        let cie_offset = entry_start as u64 + 4 - cie_id as u64;

        let fde_encoding = self
            .get_cached_cie(cie_offset)
            .and_then(|c| c.augmentation.fde_encoding)
            .unwrap_or(0x03);

        let initial_location = self.read_encoded_value(fde_encoding)?;
        let address_range = self.read_encoded_value(fde_encoding & 0x0F)?;

        if pc >= initial_location && pc < initial_location + address_range {
            let instructions_offset = self.reader.position();
            let instructions_len = entry_end.saturating_sub(instructions_offset);
            return Some(Some(SafeFde {
                cie_offset,
                initial_location,
                address_range,
                instructions_offset,
                instructions_len,
            }));
        }

        self.reader.set_position(entry_end);
        Some(None)
    }

    pub fn find_fde(&mut self, pc: u64) -> Option<SafeFde> {
        self.reader.set_position(0);

        while !self.reader.is_empty() {
            let entry_start = self.reader.position();

            // 長さを読む
            let length = self.reader.read_u32().ok()? as u64;
            if length == 0 {
                break; // 終端
            }

            // 拡張長さ (64-bit format)
            let length = if length == 0xFFFFFFFF {
                self.reader.read_u64().ok()?
            } else {
                length
            };

            match self.process_eh_frame_entry(entry_start, length, pc) {
                Some(Some(fde)) => return Some(fde),
                Some(None) => continue,
                None => return None,
            }
        }

        None
    }

    /// CIE内容をパース
    fn parse_cie_content(&mut self, remaining_len: usize) -> Option<SafeCie> {
        let content_start = self.reader.position();

        let version = self.reader.read_u8().ok()?;
        if version != 1 && version != 3 {
            return None; // サポート外バージョン
        }

        // Augmentation string
        let mut augmentation = AugmentationData::default();
        let aug_string = self.read_null_terminated_string()?;

        let code_alignment_factor = self.reader.read_uleb128().ok()?;
        let data_alignment_factor = self.reader.read_sleb128().ok()?;

        // Return address register
        let ra_reg = if version == 1 {
            self.reader.read_u8().ok()? as u64
        } else {
            self.reader.read_uleb128().ok()?
        };
        let return_address_register = DwarfRegister::from_dwarf_number(ra_reg as u8)?;

        // Augmentation dataを解析
        if aug_string.starts_with(b"z") {
            let aug_len = self.reader.read_uleb128().ok()? as usize;
            let aug_end = self.reader.position() + aug_len;

            for &ch in aug_string.iter().skip(1) {
                match ch {
                    b'L' => {
                        augmentation.has_lsda = true;
                        augmentation.lsda_encoding = Some(self.reader.read_u8().ok()?);
                    }
                    b'P' => {
                        augmentation.has_personality = true;
                        let encoding = self.reader.read_u8().ok()?;
                        augmentation.personality_encoding = Some(encoding);
                        augmentation.personality_address = Some(self.read_encoded_value(encoding)?);
                    }
                    b'R' => {
                        augmentation.fde_encoding = Some(self.reader.read_u8().ok()?);
                    }
                    b'S' => {
                        augmentation.is_signal_frame = true;
                    }
                    _ => {}
                }
            }

            self.reader.set_position(aug_end);
        }

        let initial_instructions_offset = self.reader.position();
        let initial_instructions_len = content_start + remaining_len - initial_instructions_offset;

        Some(SafeCie {
            version,
            augmentation,
            code_alignment_factor,
            data_alignment_factor,
            return_address_register,
            initial_instructions_offset,
            initial_instructions_len,
        })
    }

    /// CIEをキャッシュに追加
    fn cache_cie(&mut self, offset: u64, cie: SafeCie) {
        if self.cie_cache_len < self.cie_cache_offsets.len() {
            self.cie_cache_offsets[self.cie_cache_len] = offset;
            self.cie_cache_entries[self.cie_cache_len] = Some(cie);
            self.cie_cache_len += 1;
        }
    }

    /// キャッシュからCIEを取得
    fn get_cached_cie(&self, offset: u64) -> Option<&SafeCie> {
        for i in 0..self.cie_cache_len {
            if self.cie_cache_offsets[i] == offset {
                return self.cie_cache_entries[i].as_ref();
            }
        }
        None
    }

    /// NULL終端文字列を読む
    fn read_null_terminated_string(&mut self) -> Option<&'a [u8]> {
        let start = self.reader.position();
        loop {
            let b = self.reader.read_u8().ok()?;
            if b == 0 {
                break;
            }
        }
        let end = self.reader.position() - 1;
        Some(&self.reader.data()[start..end])
    }

    /// 符号なしフォーマットでエンコードされた値を読む
    fn read_unsigned_format(&mut self, format: u8) -> Option<u64> {
        match format {
            0x00 | 0x04 => Some(self.reader.read_u64().ok()?),
            0x01 => Some(self.reader.read_uleb128().ok()?),
            0x02 => Some(self.reader.read_u16().ok()? as u64),
            0x03 => Some(self.reader.read_u32().ok()? as u64),
            _ => None,
        }
    }

    /// 符号付きフォーマットでエンコードされた値を読む
    fn read_signed_format(&mut self, format: u8) -> Option<u64> {
        match format {
            0x09 => Some(self.reader.read_sleb128().ok()? as u64),
            0x0A => Some(self.reader.read_i16().ok()? as u64),
            0x0B => Some(self.reader.read_i32().ok()? as u64),
            0x0C => Some(self.reader.read_i64().ok()? as u64),
            _ => None,
        }
    }

    /// エンコードされた値を読む
    fn read_encoded_value(&mut self, encoding: u8) -> Option<u64> {
        let format = encoding & 0x0F;
        if format <= 0x04 {
            self.read_unsigned_format(format)
        } else {
            self.read_signed_format(format)
        }
    }

    /// CFI命令をパース
    pub fn parse_instruction(&mut self, data_align: i64) -> Option<SafeCfiInstruction> {
        let opcode = self.reader.read_u8().ok()?;
        let high2 = opcode & 0xC0;
        let low6 = opcode & 0x3F;

        match high2 {
            0x00 => self.parse_extended_instruction(low6, data_align),
            0x40 => {
                // DW_CFA_advance_loc
                Some(SafeCfiInstruction::AdvanceLoc { delta: low6 as u64 })
            }
            0x80 => {
                // DW_CFA_offset
                let register = DwarfRegister::from_dwarf_number(low6)?;
                let offset = self.reader.read_uleb128().ok()? as i64 * data_align;
                Some(SafeCfiInstruction::Offset { register, offset })
            }
            0xC0 => {
                // DW_CFA_restore (簡易版: SameValueとして扱う)
                let register = DwarfRegister::from_dwarf_number(low6)?;
                Some(SafeCfiInstruction::SameValue { register })
            }
            _ => None,
        }
    }

    /// 拡張CFI命令をパース
    fn parse_extended_instruction(
        &mut self,
        opcode: u8,
        data_align: i64,
    ) -> Option<SafeCfiInstruction> {
        match opcode {
            0x00 => Some(SafeCfiInstruction::Nop),
            0x02..=0x04 => self.parse_advance_loc_extended(opcode),
            0x05..=0x09 => self.parse_register_rule_instruction(opcode, data_align),
            0x0A => Some(SafeCfiInstruction::RememberState),
            0x0B => Some(SafeCfiInstruction::RestoreState),
            0x0C..=0x0E => self.parse_cfa_instruction(opcode),
            _ => None,
        }
    }

    /// AdvanceLoc拡張命令（1/2/4バイト）をパース
    fn parse_advance_loc_extended(&mut self, opcode: u8) -> Option<SafeCfiInstruction> {
        let delta = match opcode {
            0x02 => self.reader.read_u8().ok()? as u64,
            0x03 => self.reader.read_u16().ok()? as u64,
            0x04 => self.reader.read_u32().ok()? as u64,
            _ => return None,
        };
        Some(SafeCfiInstruction::AdvanceLoc { delta })
    }

    /// レジスタルール命令（offset_extended, restore_extended, undefined, same_value, register）をパース
    fn parse_register_rule_instruction(
        &mut self,
        opcode: u8,
        data_align: i64,
    ) -> Option<SafeCfiInstruction> {
        let reg = self.reader.read_uleb128().ok()? as u8;
        let register = DwarfRegister::from_dwarf_number(reg)?;
        match opcode {
            0x05 => {
                // DW_CFA_offset_extended
                let offset = self.reader.read_uleb128().ok()? as i64 * data_align;
                Some(SafeCfiInstruction::Offset { register, offset })
            }
            0x06 => Some(SafeCfiInstruction::SameValue { register }),
            0x07 => Some(SafeCfiInstruction::Undefined { register }),
            0x08 => Some(SafeCfiInstruction::SameValue { register }),
            0x09 => {
                // DW_CFA_register
                let src = self.reader.read_uleb128().ok()? as u8;
                let source = DwarfRegister::from_dwarf_number(src)?;
                Some(SafeCfiInstruction::Register { register, source })
            }
            _ => None,
        }
    }

    /// CFA定義命令（def_cfa, def_cfa_register, def_cfa_offset）をパース
    fn parse_cfa_instruction(&mut self, opcode: u8) -> Option<SafeCfiInstruction> {
        match opcode {
            0x0C => {
                // DW_CFA_def_cfa
                let reg = self.reader.read_uleb128().ok()? as u8;
                let register = DwarfRegister::from_dwarf_number(reg)?;
                let offset = self.reader.read_uleb128().ok()?;
                Some(SafeCfiInstruction::DefCfa { register, offset })
            }
            0x0D => {
                // DW_CFA_def_cfa_register
                let reg = self.reader.read_uleb128().ok()? as u8;
                let register = DwarfRegister::from_dwarf_number(reg)?;
                Some(SafeCfiInstruction::DefCfaRegister { register })
            }
            0x0E => {
                // DW_CFA_def_cfa_offset
                let offset = self.reader.read_uleb128().ok()?;
                Some(SafeCfiInstruction::DefCfaOffset { offset })
            }
            _ => None,
        }
    }
}

/// 型安全なCFIインタプリタ
///
/// state_stack は Clone の代わりに直接配列 + 有効フラグを使用。
/// これにより RememberState/RestoreState 時に copy_from() で
/// インプレースコピーが可能になり、アロケーションが不要。
pub struct SafeCfiInterpreter {
    context: registers::UnwindContext,
    /// 状態スタック（Clone不要、直接コピー用）
    state_stack: [registers::UnwindContext; 4],
    /// 各スタックエントリの有効フラグ
    state_stack_valid: [bool; 4],
    state_stack_len: usize,
    location: u64,
    code_alignment_factor: u64,
}

impl SafeCfiInterpreter {
    /// 新しいインタプリタを作成
    pub fn new(code_alignment_factor: u64, _data_alignment_factor: i64) -> Self {
        Self {
            context: registers::UnwindContext::new(),
            state_stack: [
                registers::UnwindContext::new(),
                registers::UnwindContext::new(),
                registers::UnwindContext::new(),
                registers::UnwindContext::new(),
            ],
            state_stack_valid: [false; 4],
            state_stack_len: 0,
            location: 0,
            code_alignment_factor,
        }
    }

    /// CFI命令を実行
    pub fn execute(&mut self, instruction: SafeCfiInstruction) {
        match instruction {
            SafeCfiInstruction::DefCfa { register, offset } => {
                self.context.set_cfa(registers::CfaRule::RegisterOffset {
                    register,
                    offset: offset as i64,
                });
            }
            SafeCfiInstruction::DefCfaRegister { register } => {
                if let registers::CfaRule::RegisterOffset { offset, .. } = self.context.cfa() {
                    self.context.set_cfa(registers::CfaRule::RegisterOffset {
                        register,
                        offset: *offset,
                    });
                }
            }
            SafeCfiInstruction::DefCfaOffset { offset } => {
                if let registers::CfaRule::RegisterOffset { register, .. } = self.context.cfa() {
                    self.context.set_cfa(registers::CfaRule::RegisterOffset {
                        register: *register,
                        offset: offset as i64,
                    });
                }
            }
            SafeCfiInstruction::Offset { register, offset } => {
                self.context
                    .set_register_rule(register, registers::RegisterRule::Offset(offset));
            }
            SafeCfiInstruction::SameValue { register } => {
                self.context
                    .set_register_rule(register, registers::RegisterRule::SameValue);
            }
            SafeCfiInstruction::Undefined { register } => {
                self.context
                    .set_register_rule(register, registers::RegisterRule::Undefined);
            }
            SafeCfiInstruction::Register { register, source } => {
                self.context
                    .set_register_rule(register, registers::RegisterRule::Register(source));
            }
            SafeCfiInstruction::AdvanceLoc { delta } => {
                self.location += delta * self.code_alignment_factor;
            }
            SafeCfiInstruction::RememberState => {
                // clone() ではなく copy_from() を使用
                // これにより新規メモリ確保が不要になり、CPUサイクルを削減
                if self.state_stack_len < self.state_stack.len() {
                    self.state_stack[self.state_stack_len].copy_from(&self.context);
                    self.state_stack_valid[self.state_stack_len] = true;
                    self.state_stack_len += 1;
                }
            }
            SafeCfiInstruction::RestoreState => {
                // copy_from() でインプレース復元
                if self.state_stack_len > 0 {
                    self.state_stack_len -= 1;
                    if self.state_stack_valid[self.state_stack_len] {
                        self.context
                            .copy_from(&self.state_stack[self.state_stack_len]);
                        self.state_stack_valid[self.state_stack_len] = false;
                    }
                }
            }
            SafeCfiInstruction::Nop => {}
        }
    }

    /// 現在のロケーション
    pub fn location(&self) -> u64 {
        self.location
    }

    /// 現在のコンテキスト
    pub fn context(&self) -> &registers::UnwindContext {
        &self.context
    }
}

// ============================================================================
// Catch Panic Mechanism - 設計書 8.1/8.2: ドメイン境界でのパニック捕捉
// ============================================================================
//
// no_std環境では std::panic::catch_unwind() が使用できないため、
// パニックハンドラとの協調によりパニック捕捉をエミュレートする。
//
// ## 設計
// 1. PanicCatcher: 現在の「捕捉ポイント」を表す構造体
// 2. パニックハンドラがPANIC_CATCH_ACTIVE をチェック
// 3. 捕捉可能な場合、パニックメッセージを保存してHALT/継続
//
// ## 制限事項
// - 真のスタックアンワインドは行われない（Drop トレイトは呼ばれない）
// - パニックしたドメインのリソースはリーク可能性あり
// - 設計書 8.1 のリソース回収機構と組み合わせて使用すること

use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// パニック捕捉が有効かどうか
static PANIC_CATCH_ACTIVE: AtomicBool = AtomicBool::new(false);

/// 捕捉されたパニックがあるかどうか
static PANIC_CAUGHT: AtomicBool = AtomicBool::new(false);

/// 捕捉されたパニックメッセージ（簡易版: 固定長バッファ）
/// 
/// 注意: パニックコンテキストでの動的メモリ確保を避けるため固定長バッファを使用
const PANIC_MESSAGE_BUFFER_SIZE: usize = 256;
static PANIC_MESSAGE_BUFFER: spin::Mutex<[u8; PANIC_MESSAGE_BUFFER_SIZE]> =
    spin::Mutex::new([0u8; PANIC_MESSAGE_BUFFER_SIZE]);
static PANIC_MESSAGE_LEN: AtomicUsize = AtomicUsize::new(0);

/// パニック情報を保持する構造体
#[derive(Debug, Clone)]
pub struct PanicPayload {
    /// パニックメッセージ
    pub message: String,
    /// パニック発生場所（ファイル名）
    pub file: Option<String>,
    /// 行番号
    pub line: Option<u32>,
    /// 列番号
    pub column: Option<u32>,
}

impl PanicPayload {
    /// 空のペイロードを作成
    pub fn empty() -> Self {
        Self {
            message: String::new(),
            file: None,
            line: None,
            column: None,
        }
    }
    
    /// メッセージからペイロードを作成
    pub fn from_message(message: String) -> Self {
        Self {
            message,
            file: None,
            line: None,
            column: None,
        }
    }
}

impl core::fmt::Display for PanicPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.message)?;
        if let (Some(file), Some(line)) = (&self.file, self.line) {
            write!(f, " at {}:{}", file, line)?;
            if let Some(col) = self.column {
                write!(f, ":{}", col)?;
            }
        }
        Ok(())
    }
}

/// パニック捕捉の結果
pub type CatchResult<T> = Result<T, PanicPayload>;

/// パニック捕捉が有効かどうかをチェック
/// 
/// パニックハンドラから呼び出される
#[inline]
pub fn is_panic_catch_active() -> bool {
    PANIC_CATCH_ACTIVE.load(Ordering::SeqCst)
}

/// パニックを記録（パニックハンドラから呼び出される）
/// 
/// # 安全性
/// この関数はパニックハンドラのコンテキストから呼び出されるため、
/// 動的メモリ確保を避け、固定長バッファを使用する。
pub fn record_caught_panic(message: &str, file: Option<&str>, line: Option<u32>, column: Option<u32>) {
    PANIC_CAUGHT.store(true, Ordering::SeqCst);
    
    // メッセージを固定長バッファにコピー
    let bytes = message.as_bytes();
    let copy_len = bytes.len().min(PANIC_MESSAGE_BUFFER_SIZE - 1);
    
    if let Some(mut guard) = PANIC_MESSAGE_BUFFER.try_lock() {
        guard[..copy_len].copy_from_slice(&bytes[..copy_len]);
        guard[copy_len] = 0; // null終端
        PANIC_MESSAGE_LEN.store(copy_len, Ordering::Release);
    }
    
    // ファイル情報は現時点では破棄（将来的には別バッファに保存）
    let _ = (file, line, column);
}

/// 捕捉されたパニックを取得してクリア
fn take_caught_panic() -> Option<PanicPayload> {
    if !PANIC_CAUGHT.swap(false, Ordering::SeqCst) {
        return None;
    }
    
    let len = PANIC_MESSAGE_LEN.load(Ordering::Acquire);
    let message = if let Some(guard) = PANIC_MESSAGE_BUFFER.try_lock() {
        let bytes = &guard[..len];
        String::from_utf8_lossy(bytes).into_owned()
    } else {
        String::from("(panic message unavailable)")
    };
    
    // バッファをクリア
    PANIC_MESSAGE_LEN.store(0, Ordering::Release);
    
    Some(PanicPayload::from_message(message))
}

/// パニックを捕捉して実行
/// 
/// no_std環境での `std::panic::catch_unwind` 相当の機能を提供する。
/// 
/// # 設計書 8.2: ドメイン境界でのパニック捕捉
/// 
/// プロキシ呼び出し時にこの関数を使用することで、ドメインのパニックを
/// 捕捉し、呼び出し元ドメインに `Result::Err` として伝播させる。
/// 
/// # 使用例
/// ```
/// let result = catch_panic(|| {
///     // パニックする可能性のあるコード
///     risky_operation()
/// });
/// 
/// match result {
///     Ok(value) => println!("Success: {:?}", value),
///     Err(payload) => println!("Caught panic: {}", payload),
/// }
/// ```
/// 
/// # 制限事項
/// - 真のスタックアンワインドは行われない
/// - パニックしたコードのDropトレイトは呼ばれない
/// - パニックハンドラがこの機構と統合されている必要がある
/// 
/// # 安全性
/// この関数自体はsafeだが、パニック時のリソースリークに注意が必要。
/// 設計書 8.1 のリソース回収機構と組み合わせて使用すること。
pub fn catch_panic<F, T>(f: F) -> CatchResult<T>
where
    F: FnOnce() -> T,
{
    // パニック捕捉を有効化
    let was_active = PANIC_CATCH_ACTIVE.swap(true, Ordering::SeqCst);
    
    // 前の捕捉状態をクリア
    PANIC_CAUGHT.store(false, Ordering::SeqCst);
    
    // 関数を実行
    let result = f();
    
    // パニック捕捉を復元
    PANIC_CATCH_ACTIVE.store(was_active, Ordering::SeqCst);
    
    // パニックが捕捉されたかチェック
    if let Some(payload) = take_caught_panic() {
        return Err(payload);
    }
    
    Ok(result)
}

/// パニック捕捉付きで関数を実行し、AssertUnwindSafe相当の保証を提供
/// 
/// `catch_panic` との違い:
/// - 明示的にUnwindSafeでないクロージャを受け入れる
/// - 「このコードはパニック後も安全」という意図を示す
pub fn catch_panic_unwind_safe<F, T>(f: F) -> CatchResult<T>
where
    F: FnOnce() -> T,
{
    catch_panic(f)
}

/// パニック捕捉スコープガード
/// 
/// RAII パターンでパニック捕捉の有効/無効を管理する。
/// Drop時に自動的に以前の状態に復元される。
pub struct PanicCatchGuard {
    was_active: bool,
}

impl PanicCatchGuard {
    /// 新しいパニック捕捉スコープを開始
    pub fn new() -> Self {
        let was_active = PANIC_CATCH_ACTIVE.swap(true, Ordering::SeqCst);
        PANIC_CAUGHT.store(false, Ordering::SeqCst);
        Self { was_active }
    }
    
    /// パニックが捕捉されたかチェック
    pub fn caught_panic(&self) -> bool {
        PANIC_CAUGHT.load(Ordering::SeqCst)
    }
    
    /// 捕捉されたパニック情報を取得
    pub fn take_panic(&self) -> Option<PanicPayload> {
        take_caught_panic()
    }
}

impl Drop for PanicCatchGuard {
    fn drop(&mut self) {
        PANIC_CATCH_ACTIVE.store(self.was_active, Ordering::SeqCst);
    }
}

impl Default for PanicCatchGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_uleb128() {
        let mut reader = MemoryReader::new(&[0x00]);
        assert_eq!(reader.read_uleb128().unwrap(), 0);

        let mut reader = MemoryReader::new(&[0x01]);
        assert_eq!(reader.read_uleb128().unwrap(), 1);

        let mut reader = MemoryReader::new(&[0x7F]);
        assert_eq!(reader.read_uleb128().unwrap(), 127);

        let mut reader = MemoryReader::new(&[0x80, 0x01]);
        assert_eq!(reader.read_uleb128().unwrap(), 128);

        let mut reader = MemoryReader::new(&[0xE5, 0x8E, 0x26]);
        assert_eq!(reader.read_uleb128().unwrap(), 624485);
    }

    #[test_case]
    fn test_sleb128() {
        let mut reader = MemoryReader::new(&[0x00]);
        assert_eq!(reader.read_sleb128().unwrap(), 0);

        let mut reader = MemoryReader::new(&[0x01]);
        assert_eq!(reader.read_sleb128().unwrap(), 1);

        let mut reader = MemoryReader::new(&[0x7F]);
        assert_eq!(reader.read_sleb128().unwrap(), -1);

        let mut reader = MemoryReader::new(&[0x80, 0x7F]);
        assert_eq!(reader.read_sleb128().unwrap(), -128);
    }
}

