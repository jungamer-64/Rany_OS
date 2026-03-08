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
mod eh_frame_parser;
pub use eh_frame_parser::*;
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
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
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
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
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
        registers::CfaRule::Expression { .. } => Err(UnwindError::UnsupportedDwarfExpression),
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
        &mut parser,
        &mut interpreter,
        data_alignment_factor,
        initial_start,
        initial_start + initial_len,
        None,
    );

    // FDEの命令を実行（PCまで）
    let pc_offset = (frame.instruction_pointer as u64).saturating_sub(fde.initial_location);
    execute_dwarf_instructions(
        &mut parser,
        &mut interpreter,
        data_alignment_factor,
        fde.instructions_offset,
        fde.instructions_offset + fde.instructions_len,
        Some(pc_offset),
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
