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

pub use reader::{MemoryReader, DwarfPointerEncoding, DwarfPointerApplication, read_encoded_pointer};
pub use registers::{DwarfRegister, RegisterRule, RegisterSet, CfaRule, UnwindContext};

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
            let return_addr = unsafe { ptr::read((rbp + 8) as *const usize) };
            let next_rbp = unsafe { ptr::read(rbp as *const usize) };
            
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
        self.entries.iter().take(self.count).filter_map(|e| e.as_ref())
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
#[unsafe(no_mangle)]
#[used]
#[unsafe(link_section = ".ksymtab")]
static __KSYM_DUMMY: u8 = 0;

/// .eh_frameセクション境界（リンカスクリプトで定義）
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
            let sym = unsafe { &*((self.base + offset) as *const KernelSymbol) };
            
            // シンボル名を取得
            let name_ptr = (self.base + offset + core::mem::size_of::<KernelSymbol>()) as *const u8;
            let name = unsafe {
                core::str::from_utf8_unchecked(
                    core::slice::from_raw_parts(name_ptr, sym.name_len as usize)
                )
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
            let entry_size = core::mem::size_of::<KernelSymbol>() + sym.name_len as usize;
            let aligned_size = (entry_size + 7) & !7;
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
    pub fn iter(&self) -> KernelSymbolIter {
        KernelSymbolIter {
            table: self,
            offset: 0,
        }
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
        
        let sym = unsafe { &*((self.table.base + self.offset) as *const KernelSymbol) };
        let name_ptr = (self.table.base + self.offset + core::mem::size_of::<KernelSymbol>()) as *const u8;
        let name = unsafe {
            core::str::from_utf8_unchecked(
                core::slice::from_raw_parts(name_ptr, sym.name_len as usize)
            )
        };
        
        let entry_size = core::mem::size_of::<KernelSymbol>() + sym.name_len as usize;
        let aligned_size = (entry_size + 7) & !7;
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
        crate::log!("[UNWIND] Kernel symbol table loaded: {} symbols\n", table.symbol_count());
    } else {
        crate::log!("[UNWIND] No kernel symbol table available\n");
    }
}

/// シンボル情報を解決
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
    let mut frame_num = 0;
    
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
    frame_num = 1;
    
    // フレームチェーンをたどる
    while frame_num < MAX_FRAMES && is_valid_stack_address(current_rbp) {
        let return_addr = unsafe { ptr::read((current_rbp + 8) as *const usize) };
        let next_rbp = unsafe { ptr::read(current_rbp as *const usize) };
        
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

/// DWARFベースのアンワインドを実行
/// 
/// 型安全な `SafeEhFrameParser` を使用してスタックフレームを巻き戻す
pub fn unwind_frame(frame: &StackFrame) -> Result<StackFrame, UnwindError> {
    // .eh_frame データを取得
    let eh_frame = get_eh_frame_data().ok_or(UnwindError::NoEhFrame)?;
    
    let mut parser = SafeEhFrameParser::new(eh_frame);
    
    // FDEを検索
    let fde = parser.find_fde(frame.instruction_pointer as u64)
        .ok_or(UnwindError::NoUnwindInfo)?;
    
    // CIEを取得し、必要な値をコピー（借用を解放するため）
    let (code_alignment_factor, data_alignment_factor, initial_start, initial_len) = {
        let cie = parser.get_cached_cie(fde.cie_offset)
            .ok_or(UnwindError::InvalidDwarf)?;
        (
            cie.code_alignment_factor,
            cie.data_alignment_factor,
            cie.initial_instructions_offset,
            cie.initial_instructions_len,
        )
    };
    
    // インタプリタを作成
    let mut interpreter = SafeCfiInterpreter::new(
        code_alignment_factor,
        data_alignment_factor,
    );
    
    // CIEの初期命令を実行
    let initial_end = initial_start + initial_len;
    parser.reader.set_position(initial_start);
    
    while parser.reader.position() < initial_end {
        if let Some(instr) = parser.parse_instruction(data_alignment_factor) {
            interpreter.execute(instr);
        }
    }
    
    // FDEの命令を実行（PCまで）
    parser.reader.set_position(fde.instructions_offset);
    let fde_end = fde.instructions_offset + fde.instructions_len;
    
    while parser.reader.position() < fde_end {
        let pc_offset = (frame.instruction_pointer as u64).saturating_sub(fde.initial_location);
        if interpreter.location() > pc_offset {
            break;
        }
        if let Some(instr) = parser.parse_instruction(data_alignment_factor) {
            interpreter.execute(instr);
        }
    }
    
    // CFAを計算
    let ctx = interpreter.context();
    let cfa = match ctx.cfa() {
        registers::CfaRule::RegisterOffset { register, offset } => {
            let base = match register {
                DwarfRegister::Rsp => frame.stack_pointer as u64,
                DwarfRegister::Rbp => frame.frame_pointer as u64,
                _ => return Err(UnwindError::InvalidDwarf),
            };
            (base as i64 + offset) as u64
        }
        registers::CfaRule::Expression { .. } => {
            return Err(UnwindError::UnsupportedDwarfExpression);
        }
    };
    
    // リターンアドレスを取得
    let return_address = match ctx.get_register_rule(DwarfRegister::ReturnAddress) {
        registers::RegisterRule::Offset(off) => {
            let addr = (cfa as i64 + off) as *const u64;
            // Safety: CFAから計算されたアドレスからの読み取り
            unsafe { core::ptr::read(addr) }
        }
        _ => return Err(UnwindError::InvalidDwarf),
    };
    
    // 新しいRBPを取得
    let new_rbp = match ctx.get_register_rule(DwarfRegister::Rbp) {
        registers::RegisterRule::Offset(off) => {
            let addr = (cfa as i64 + off) as *const u64;
            unsafe { core::ptr::read(addr) }
        }
        registers::RegisterRule::SameValue => frame.frame_pointer as u64,
        _ => 0,
    };
    
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
    DefCfa { register: DwarfRegister, offset: u64 },
    /// CFAレジスタ変更
    DefCfaRegister { register: DwarfRegister },
    /// CFAオフセット変更
    DefCfaOffset { offset: u64 },
    /// レジスタをCFA相対オフセットで復元
    Offset { register: DwarfRegister, offset: i64 },
    /// レジスタ値維持
    SameValue { register: DwarfRegister },
    /// レジスタ状態未定義
    Undefined { register: DwarfRegister },
    /// 別レジスタに格納
    Register { register: DwarfRegister, source: DwarfRegister },
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
            let (length, _is_64bit) = if length == 0xFFFFFFFF {
                (self.reader.read_u64().ok()?, true)
            } else {
                (length, false)
            };
            
            let entry_end = self.reader.position() + length as usize;
            
            // CIE IDを読む
            let cie_id = self.reader.read_u32().ok()?;
            
            if cie_id == 0 {
                // CIE: キャッシュして次へ
                let cie = self.parse_cie_content(length as usize - 4)?;
                self.cache_cie(entry_start as u64, cie);
            } else {
                // FDE
                let cie_offset = entry_start as u64 + 4 - cie_id as u64;
                
                // FDEの位置情報を読む
                let fde_encoding = self.get_cached_cie(cie_offset)
                    .and_then(|c| c.augmentation.fde_encoding)
                    .unwrap_or(0x03); // DW_EH_PE_udata4
                
                let initial_location = self.read_encoded_value(fde_encoding)?;
                let address_range = self.read_encoded_value(fde_encoding & 0x0F)?;
                
                // PCが範囲内か確認
                if pc >= initial_location && pc < initial_location + address_range {
                    let instructions_offset = self.reader.position();
                    let instructions_len = entry_end.saturating_sub(instructions_offset);
                    
                    return Some(SafeFde {
                        cie_offset,
                        initial_location,
                        address_range,
                        instructions_offset,
                        instructions_len,
                    });
                }
            }
            
            // 次のエントリへ
            self.reader.set_position(entry_end);
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

    /// エンコードされた値を読む
    fn read_encoded_value(&mut self, encoding: u8) -> Option<u64> {
        let format = encoding & 0x0F;
        match format {
            0x00 => Some(self.reader.read_u64().ok()?), // absptr
            0x01 => Some(self.reader.read_uleb128().ok()?),
            0x02 => Some(self.reader.read_u16().ok()? as u64),
            0x03 => Some(self.reader.read_u32().ok()? as u64),
            0x04 => Some(self.reader.read_u64().ok()?),
            0x09 => Some(self.reader.read_sleb128().ok()? as u64),
            0x0A => Some(self.reader.read_i16().ok()? as u64),
            0x0B => Some(self.reader.read_i32().ok()? as u64),
            0x0C => Some(self.reader.read_i64().ok()? as u64),
            _ => None,
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
    fn parse_extended_instruction(&mut self, opcode: u8, data_align: i64) -> Option<SafeCfiInstruction> {
        match opcode {
            0x00 => Some(SafeCfiInstruction::Nop),
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
            0x02 => {
                // DW_CFA_advance_loc1
                let delta = self.reader.read_u8().ok()? as u64;
                Some(SafeCfiInstruction::AdvanceLoc { delta })
            }
            0x03 => {
                // DW_CFA_advance_loc2
                let delta = self.reader.read_u16().ok()? as u64;
                Some(SafeCfiInstruction::AdvanceLoc { delta })
            }
            0x04 => {
                // DW_CFA_advance_loc4
                let delta = self.reader.read_u32().ok()? as u64;
                Some(SafeCfiInstruction::AdvanceLoc { delta })
            }
            0x05 => {
                // DW_CFA_offset_extended
                let reg = self.reader.read_uleb128().ok()? as u8;
                let register = DwarfRegister::from_dwarf_number(reg)?;
                let offset = self.reader.read_uleb128().ok()? as i64 * data_align;
                Some(SafeCfiInstruction::Offset { register, offset })
            }
            0x06 => {
                // DW_CFA_restore_extended
                let reg = self.reader.read_uleb128().ok()? as u8;
                let register = DwarfRegister::from_dwarf_number(reg)?;
                Some(SafeCfiInstruction::SameValue { register })
            }
            0x07 => {
                // DW_CFA_undefined
                let reg = self.reader.read_uleb128().ok()? as u8;
                let register = DwarfRegister::from_dwarf_number(reg)?;
                Some(SafeCfiInstruction::Undefined { register })
            }
            0x08 => {
                // DW_CFA_same_value
                let reg = self.reader.read_uleb128().ok()? as u8;
                let register = DwarfRegister::from_dwarf_number(reg)?;
                Some(SafeCfiInstruction::SameValue { register })
            }
            0x09 => {
                // DW_CFA_register
                let reg = self.reader.read_uleb128().ok()? as u8;
                let register = DwarfRegister::from_dwarf_number(reg)?;
                let src = self.reader.read_uleb128().ok()? as u8;
                let source = DwarfRegister::from_dwarf_number(src)?;
                Some(SafeCfiInstruction::Register { register, source })
            }
            0x0A => Some(SafeCfiInstruction::RememberState),
            0x0B => Some(SafeCfiInstruction::RestoreState),
            _ => None,
        }
    }
}

/// 型安全なCFIインタプリタ
pub struct SafeCfiInterpreter {
    context: registers::UnwindContext,
    state_stack: [Option<registers::UnwindContext>; 4],
    state_stack_len: usize,
    location: u64,
    code_alignment_factor: u64,
}

impl SafeCfiInterpreter {
    /// 新しいインタプリタを作成
    pub fn new(code_alignment_factor: u64, _data_alignment_factor: i64) -> Self {
        Self {
            context: registers::UnwindContext::new(),
            state_stack: [None, None, None, None],
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
                self.context.set_register_rule(register, registers::RegisterRule::Offset(offset));
            }
            SafeCfiInstruction::SameValue { register } => {
                self.context.set_register_rule(register, registers::RegisterRule::SameValue);
            }
            SafeCfiInstruction::Undefined { register } => {
                self.context.set_register_rule(register, registers::RegisterRule::Undefined);
            }
            SafeCfiInstruction::Register { register, source } => {
                self.context.set_register_rule(register, registers::RegisterRule::Register(source));
            }
            SafeCfiInstruction::AdvanceLoc { delta } => {
                self.location += delta * self.code_alignment_factor;
            }
            SafeCfiInstruction::RememberState => {
                if self.state_stack_len < self.state_stack.len() {
                    self.state_stack[self.state_stack_len] = Some(self.context.clone());
                    self.state_stack_len += 1;
                }
            }
            SafeCfiInstruction::RestoreState => {
                if self.state_stack_len > 0 {
                    self.state_stack_len -= 1;
                    if let Some(ctx) = self.state_stack[self.state_stack_len].take() {
                        self.context = ctx;
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
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
    
    #[test]
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
