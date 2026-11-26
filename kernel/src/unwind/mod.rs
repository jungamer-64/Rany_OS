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

use core::fmt;

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
        let registers = StackRegisters::read();
        let mut trace = Self::new();
        trace.capture_frames(registers);
        trace
    }

    fn capture_frames(&mut self, registers: StackRegisters) {
        let Some(stack) = ActiveStack::containing(registers.rsp) else {
            return;
        };
        let mut rbp = registers.rbp;
        // LOOP_PROOF: mode=bounded; reason=Each recorded frame consumes one slot and any invalid frame terminates the walk.;
        for frame_number in self.count..MAX_FRAMES {
            let Some((next_rbp, return_address, next_rsp)) = stack.frame_at(rbp) else {
                break;
            };
            if !is_valid_code_address(return_address) {
                break;
            }

            self.entries[frame_number] = Some(BacktraceEntry {
                frame_number,
                frame: StackFrame {
                    instruction_pointer: return_address,
                    stack_pointer: next_rsp,
                    frame_pointer: rbp,
                },
                symbol: resolve_symbol(return_address),
            });
            self.count += 1;

            if next_rbp <= rbp {
                break;
            }
            rbp = next_rbp;
        }
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

struct StackRegisters {
    rsp: usize,
    rbp: usize,
}

impl StackRegisters {
    #[inline(always)]
    fn read() -> Self {
        let rsp: usize;
        let rbp: usize;
        // SAFETY: only snapshots the current CPU's frame and stack registers.
        unsafe {
            core::arch::asm!(
                "mov {rsp}, rsp",
                "mov {rbp}, rbp",
                rsp = out(reg) rsp,
                rbp = out(reg) rbp,
                options(nomem, nostack, preserves_flags),
            );
        }
        Self { rsp, rbp }
    }
}

/// Reads only from a mapped stack whose backing is retained by this CPU.
struct ActiveStack(core::ops::Range<usize>);

impl ActiveStack {
    fn containing(rsp: usize) -> Option<Self> {
        let cpu = crate::cpu::CurrentCpu::acquire()?;
        if let Some(bounds) = crate::task::context::task_stack_bounds(&cpu)
            && bounds.contains(&(rsp as u64))
        {
            return Some(Self(rsp..bounds.end as usize));
        }
        if let Some(bounds) = cpu.descriptor_tables().ist_bounds_containing(rsp) {
            return Some(Self(rsp..bounds.end));
        }
        if cpu.id() == crate::cpu::CpuId::BOOTSTRAP {
            let bounds = crate::boot::entry::bootstrap_stack_bounds();
            if bounds.contains(&rsp) {
                return Some(Self(rsp..bounds.end));
            }
        }
        None
    }

    fn record_end(&self, address: usize, size: usize) -> Option<usize> {
        let end = address.checked_add(size)?;
        (address.is_multiple_of(size_of::<u64>()) && address >= self.0.start && end <= self.0.end)
            .then_some(end)
    }

    fn frame_at(&self, rbp: usize) -> Option<(usize, usize, usize)> {
        let next_rsp = self.record_end(rbp, 2 * size_of::<u64>())?;
        Some((
            self.read_word(rbp)? as usize,
            self.read_word(rbp + size_of::<u64>())? as usize,
            next_rsp,
        ))
    }

    fn read_word(&self, address: usize) -> Option<u64> {
        self.record_end(address, size_of::<u64>())?;
        let word: u64;
        // SAFETY: the range belongs to a live, mapped stack on this CPU.
        // Reading through an integer register also permits inspecting padding or
        // inactive stack slots without constructing a Rust value in stack memory.
        unsafe {
            core::arch::asm!(
                "mov {word}, qword ptr [{address}]",
                word = lateout(reg) word,
                address = in(reg) address,
                options(readonly, nostack, preserves_flags),
            );
        }
        Some(word)
    }
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

/// Returns a word only when it lies within the current mapped stack.
pub(crate) fn read_u64_checked(addr: usize) -> Option<u64> {
    ActiveStack::containing(StackRegisters::read().rsp)?.read_word(addr)
}

// ============================================================================
// カーネルシンボルテーブル
// 設計書 8.1: バックトレース解決用
// ============================================================================

// Reserved section marker. No symbol-table parser is enabled until the image
// format supplies validated bounds and entry metadata.
#[cfg(not(test))]
#[unsafe(no_mangle)]
#[used]
#[unsafe(link_section = ".ksymtab")]
static __KSYM_DUMMY: u8 = 0;

// .eh_frameセクション境界（リンカスクリプトで定義）
#[cfg(target_os = "none")]
unsafe extern "C" {
    #[link_name = "__eh_frame_start"]
    static EH_FRAME_START: u8;
    #[link_name = "__eh_frame_end"]
    static EH_FRAME_END: u8;
}

/// シンボルテーブルを初期化
pub fn init_symbol_table() {
    log::info!("[UNWIND] No validated kernel symbol table is present\n");
}

fn resolve_symbol(_address: usize) -> Option<SymbolInfo> {
    None
}

/// ヘルパー: アドレスからシンボル名（存在する場合）を返す
/// 診断用に外部から呼べるように公開
pub fn resolve_symbol_name(_address: usize) -> Option<&'static str> {
    None
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

    bt.count = 1;
    bt.capture_frames(StackRegisters { rsp, rbp });
    bt
}

/// グローバルな .eh_frame データを取得
pub fn get_eh_frame_data() -> Option<&'static [u8]> {
    #[cfg(target_os = "none")]
    unsafe {
        let start = &EH_FRAME_START as *const u8 as usize;
        let end = &EH_FRAME_END as *const u8 as usize;

        if start != 0 && end > start {
            Some(core::slice::from_raw_parts(start as *const u8, end - start))
        } else {
            None
        }
    }
    #[cfg(not(target_os = "none"))]
    None
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
    instructions: &[u8],
    interpreter: &mut SafeCfiInterpreter,
    data_alignment_factor: i64,
    pc_limit: Option<u64>,
) -> Result<(), UnwindError> {
    let mut parser = SafeEhFrameParser::new(instructions);
    // LOOP_PROOF: mode=condition; reason=Every decoded instruction consumes an opcode within the bounded instruction slice, and a malformed or unsupported instruction returns an error.;
    while !parser.reader.is_exhausted() {
        if let Some(target_pc) = pc_limit
            && interpreter.location() > target_pc
        {
            break;
        }
        let instruction = parser
            .parse_instruction(data_alignment_factor)
            .ok_or(UnwindError::InvalidDwarf)?;
        interpreter.execute(instruction);
    }
    Ok(())
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
        parser
            .reader
            .data()
            .get(
                initial_start
                    ..initial_start
                        .checked_add(initial_len)
                        .ok_or(UnwindError::InvalidDwarf)?,
            )
            .ok_or(UnwindError::InvalidDwarf)?,
        &mut interpreter,
        data_alignment_factor,
        None,
    )?;

    // FDEの命令を実行（PCまで）
    let pc_offset = (frame.instruction_pointer as u64).saturating_sub(fde.initial_location);
    execute_dwarf_instructions(
        parser
            .reader
            .data()
            .get(
                fde.instructions_offset
                    ..fde
                        .instructions_offset
                        .checked_add(fde.instructions_len)
                        .ok_or(UnwindError::InvalidDwarf)?,
            )
            .ok_or(UnwindError::InvalidDwarf)?,
        &mut interpreter,
        data_alignment_factor,
        Some(pc_offset),
    )?;

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

#[cfg(test)]
mod instruction_tests {
    use super::*;

    #[test]
    fn malformed_instruction_cannot_consume_an_adjacent_instruction_range() {
        let records = [0x02, 0x40]; // advance_loc1 lacks its operand in the first range
        let mut interpreter = SafeCfiInterpreter::new(1, -8);
        assert_eq!(
            execute_dwarf_instructions(&records[..1], &mut interpreter, -8, None),
            Err(UnwindError::InvalidDwarf)
        );
        assert_eq!(interpreter.location(), 0);
        assert_eq!(
            execute_dwarf_instructions(&records[1..], &mut interpreter, -8, None),
            Ok(())
        );
    }

    #[test]
    fn unsupported_instruction_ends_decode_after_a_valid_prefix() {
        let mut interpreter = SafeCfiInterpreter::new(1, -8);
        assert_eq!(
            execute_dwarf_instructions(&[0x41, 0x3f], &mut interpreter, -8, None),
            Err(UnwindError::InvalidDwarf)
        );
        assert_eq!(interpreter.location(), 1);
        assert_eq!(
            execute_dwarf_instructions(&[], &mut interpreter, -8, None),
            Ok(())
        );
    }

    #[test]
    fn entry_fields_cannot_read_the_following_record() {
        // The four-byte CIE payload ends immediately after its ID. Bytes of the
        // following record could otherwise form a valid CIE header.
        let records = [4, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0x78, 16];
        let mut parser = SafeEhFrameParser::new(&records);
        assert!(parser.find_fde(0).is_none());
        assert!(parser.get_cached_cie(0).is_none());
    }
}

#[cfg(test)]
mod stack_bounds_tests {
    use super::ActiveStack;

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn saved_frame_must_fit_completely_inside_the_mapped_stack() {
        let stack = ActiveStack(0x1000..0x2000);
        assert_eq!(stack.record_end(0x1000, 16), Some(0x1010));
        assert_eq!(stack.record_end(0x1ff0, 16), Some(0x2000));
        assert_eq!(stack.record_end(0x0ff8, 16), None);
        assert_eq!(stack.record_end(0x1001, 16), None);
        assert_eq!(stack.record_end(0x1ff8, 16), None);
        assert_eq!(stack.record_end(usize::MAX - 7, 16), None);
    }
}
