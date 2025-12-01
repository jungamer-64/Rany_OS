//! スタックアンワインドモジュール
//! 
//! 設計書8.1: スタックアンワインド
//! - DWARFベースのアンワインド情報解析
//! - .eh_frame セクション解析
//! - パニック時のバックトレース生成
//! - フレームポインタベースのアンワインド（フォールバック）

use core::fmt;
use core::ptr;
use core::mem;

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

/// DWARF Common Information Entry (CIE)
#[derive(Debug, Clone)]
pub struct Cie {
    /// CIEの長さ
    pub length: u32,
    /// バージョン
    pub version: u8,
    /// コードアライメント係数
    pub code_alignment_factor: u64,
    /// データアライメント係数
    pub data_alignment_factor: i64,
    /// リターンアドレスレジスタ
    pub return_address_register: u64,
    /// 初期命令列のオフセット
    pub initial_instructions_offset: usize,
    /// 初期命令列の長さ
    pub initial_instructions_length: usize,
}

/// DWARF Frame Description Entry (FDE)
#[derive(Debug, Clone)]
pub struct Fde {
    /// FDEの長さ
    pub length: u32,
    /// 対応するCIEへのポインタ
    pub cie_pointer: u32,
    /// PCの開始アドレス
    pub pc_begin: usize,
    /// PCの範囲
    pub pc_range: usize,
    /// 命令列のオフセット
    pub instructions_offset: usize,
    /// 命令列の長さ
    pub instructions_length: usize,
}

/// DWARF CFI (Call Frame Information) レジスタルール
#[derive(Debug, Clone, Copy)]
pub enum RegisterRule {
    /// 未定義
    Undefined,
    /// 同一値
    SameValue,
    /// オフセット
    Offset(i64),
    /// 値オフセット
    ValOffset(i64),
    /// レジスタ
    Register(u64),
    /// 式
    Expression,
    /// 値式
    ValExpression,
    /// アーキテクチャ固有
    Architectural,
}

/// アンワインドコンテキスト
#[derive(Debug, Clone)]
pub struct UnwindContext {
    /// レジスタルール (0=RAX, ..., 16=RIP, 17=RSP, 18=RBP, etc.)
    pub registers: [RegisterRule; 32],
    /// CFAルール: レジスタ + オフセット
    pub cfa_register: u64,
    pub cfa_offset: i64,
}

impl Default for UnwindContext {
    fn default() -> Self {
        Self {
            registers: [RegisterRule::Undefined; 32],
            cfa_register: 0,
            cfa_offset: 0,
        }
    }
}

/// .eh_frame パーサー
pub struct EhFrameParser {
    /// .eh_frame セクションの開始アドレス
    base: usize,
    /// .eh_frame セクションの長さ
    len: usize,
}

impl EhFrameParser {
    /// 新しいパーサーを作成
    pub fn new(base: usize, len: usize) -> Self {
        Self { base, len }
    }

    /// 指定アドレスに対応するFDEを検索
    pub fn find_fde(&self, address: usize) -> Result<Fde, UnwindError> {
        let mut offset = 0;
        
        while offset < self.len {
            let entry_base = self.base + offset;
            
            // 長さを読み取り
            let length = unsafe { ptr::read(entry_base as *const u32) };
            if length == 0 {
                // 終端マーカー
                break;
            }
            
            let entry_len = if length == 0xFFFFFFFF {
                // 64ビット長
                let len64 = unsafe { ptr::read((entry_base + 4) as *const u64) };
                offset += 12;
                len64 as usize
            } else {
                offset += 4;
                length as usize
            };
            
            let entry_start = self.base + offset;
            
            // CIE IDを確認
            let cie_id = unsafe { ptr::read(entry_start as *const u32) };
            
            if cie_id != 0 {
                // これはFDE
                // pc_beginを読み取り（pcrel）
                let pc_begin_offset = unsafe { ptr::read((entry_start + 4) as *const i32) };
                let pc_begin = (entry_start + 4).wrapping_add(pc_begin_offset as usize);
                
                // pc_rangeを読み取り
                let pc_range = unsafe { ptr::read((entry_start + 8) as *const u32) } as usize;
                
                // アドレスがこのFDEの範囲内かチェック
                if address >= pc_begin && address < pc_begin + pc_range {
                    return Ok(Fde {
                        length,
                        cie_pointer: cie_id,
                        pc_begin,
                        pc_range,
                        instructions_offset: entry_start + 16,
                        instructions_length: entry_len - 16,
                    });
                }
            }
            
            offset += entry_len;
        }
        
        Err(UnwindError::CieNotFound)
    }

    /// CIEを解析
    pub fn parse_cie(&self, offset: usize) -> Result<Cie, UnwindError> {
        let cie_base = self.base + offset;
        
        let length = unsafe { ptr::read(cie_base as *const u32) };
        if length == 0 {
            return Err(UnwindError::InvalidDwarf);
        }
        
        let content_start = cie_base + 4;
        
        // CIE IDを確認（0であるべき）
        let cie_id = unsafe { ptr::read(content_start as *const u32) };
        if cie_id != 0 {
            return Err(UnwindError::InvalidDwarf);
        }
        
        let version = unsafe { ptr::read((content_start + 4) as *const u8) };
        
        // 以降はLEB128エンコード値を読み取る必要がある
        // 簡略化のため、一般的な値を仮定
        Ok(Cie {
            length,
            version,
            code_alignment_factor: 1,
            data_alignment_factor: -8,
            return_address_register: 16, // RIP
            initial_instructions_offset: content_start + 16,
            initial_instructions_length: length as usize - 16,
        })
    }
}

/// DWARF CFI 命令インタープリター
pub struct CfiInterpreter {
    context: UnwindContext,
}

impl CfiInterpreter {
    /// 新しいインタープリターを作成
    pub fn new() -> Self {
        Self {
            context: UnwindContext::default(),
        }
    }

    /// CFI命令を実行
    pub fn execute(&mut self, instructions: &[u8], target_pc: usize, cie: &Cie) -> Result<(), UnwindError> {
        let mut offset = 0;
        
        while offset < instructions.len() {
            let opcode = instructions[offset];
            offset += 1;
            
            // 高位2ビットで命令タイプを判定
            match opcode >> 6 {
                0b01 => {
                    // DW_CFA_advance_loc
                    let delta = (opcode & 0x3F) as u64 * cie.code_alignment_factor;
                    // PCを進める
                    let _ = delta;
                }
                0b10 => {
                    // DW_CFA_offset
                    let reg = (opcode & 0x3F) as usize;
                    let uleb = read_uleb128(&instructions[offset..]);
                    offset += uleb.1;
                    self.context.registers[reg] = RegisterRule::Offset(
                        (uleb.0 as i64) * cie.data_alignment_factor
                    );
                }
                0b11 => {
                    // DW_CFA_restore
                    let reg = (opcode & 0x3F) as usize;
                    self.context.registers[reg] = RegisterRule::Undefined;
                }
                _ => {
                    // 低位6ビットで命令を判定
                    match opcode {
                        0x00 => { /* DW_CFA_nop */ }
                        0x0C => {
                            // DW_CFA_def_cfa
                            let reg = read_uleb128(&instructions[offset..]);
                            offset += reg.1;
                            let off = read_uleb128(&instructions[offset..]);
                            offset += off.1;
                            self.context.cfa_register = reg.0;
                            self.context.cfa_offset = off.0 as i64;
                        }
                        0x0E => {
                            // DW_CFA_def_cfa_offset
                            let off = read_uleb128(&instructions[offset..]);
                            offset += off.1;
                            self.context.cfa_offset = off.0 as i64;
                        }
                        _ => {
                            // 未知の命令はスキップ
                        }
                    }
                }
            }
        }
        
        Ok(())
    }

    /// 現在のコンテキストを取得
    pub fn context(&self) -> &UnwindContext {
        &self.context
    }
}

impl Default for CfiInterpreter {
    fn default() -> Self {
        Self::new()
    }
}

/// ULEB128をデコード
fn read_uleb128(data: &[u8]) -> (u64, usize) {
    let mut result: u64 = 0;
    let mut shift = 0;
    let mut offset = 0;
    
    loop {
        if offset >= data.len() {
            break;
        }
        
        let byte = data[offset];
        offset += 1;
        
        result |= ((byte & 0x7F) as u64) << shift;
        
        if byte & 0x80 == 0 {
            break;
        }
        
        shift += 7;
    }
    
    (result, offset)
}

/// SLEB128をデコード
fn read_sleb128(data: &[u8]) -> (i64, usize) {
    let mut result: i64 = 0;
    let mut shift = 0;
    let mut offset = 0;
    
    loop {
        if offset >= data.len() {
            break;
        }
        
        let byte = data[offset];
        offset += 1;
        
        result |= ((byte & 0x7F) as i64) << shift;
        shift += 7;
        
        if byte & 0x80 == 0 {
            // 符号拡張
            if shift < 64 && (byte & 0x40) != 0 {
                result |= !0i64 << shift;
            }
            break;
        }
    }
    
    (result, offset)
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

/// グローバルなEhFrameパーサーを取得
pub fn get_eh_frame_parser() -> Option<EhFrameParser> {
    unsafe {
        let start = &EH_FRAME_START as *const u8 as usize;
        let end = &EH_FRAME_END as *const u8 as usize;
        
        if start != 0 && end > start {
            Some(EhFrameParser::new(start, end - start))
        } else {
            None
        }
    }
}

/// DWARFベースのアンワインドを実行
pub fn unwind_frame(frame: &StackFrame) -> Result<StackFrame, UnwindError> {
    // .eh_frameパーサーを取得
    let parser = get_eh_frame_parser().ok_or(UnwindError::NoEhFrame)?;
    
    // FDEを検索
    let fde = parser.find_fde(frame.instruction_pointer)?;
    
    // CIEを取得
    let cie_offset = (fde.instructions_offset - 4 - fde.cie_pointer as usize) - parser.base;
    let cie = parser.parse_cie(cie_offset)?;
    
    // CFI命令を実行
    let mut interpreter = CfiInterpreter::new();
    
    // CIEの初期命令を実行
    let initial_instructions = unsafe {
        core::slice::from_raw_parts(
            cie.initial_instructions_offset as *const u8,
            cie.initial_instructions_length,
        )
    };
    interpreter.execute(initial_instructions, frame.instruction_pointer, &cie)?;
    
    // FDEの命令を実行
    let fde_instructions = unsafe {
        core::slice::from_raw_parts(
            fde.instructions_offset as *const u8,
            fde.instructions_length,
        )
    };
    interpreter.execute(fde_instructions, frame.instruction_pointer, &cie)?;
    
    // コンテキストから次のフレームを計算
    let ctx = interpreter.context();
    
    // CFAを計算
    let cfa = match ctx.cfa_register {
        7 => frame.stack_pointer as i64 + ctx.cfa_offset, // RSP
        6 => frame.frame_pointer as i64 + ctx.cfa_offset, // RBP
        _ => return Err(UnwindError::InvalidDwarf),
    } as usize;
    
    // リターンアドレスを取得
    let return_address = match ctx.registers[16] { // RIP
        RegisterRule::Offset(off) => {
            let addr = (cfa as i64 + off) as usize;
            unsafe { ptr::read(addr as *const usize) }
        }
        _ => return Err(UnwindError::InvalidDwarf),
    };
    
    // 新しいRBPを取得
    let new_rbp = match ctx.registers[6] { // RBP
        RegisterRule::Offset(off) => {
            let addr = (cfa as i64 + off) as usize;
            unsafe { ptr::read(addr as *const usize) }
        }
        RegisterRule::SameValue => frame.frame_pointer,
        _ => 0,
    };
    
    Ok(StackFrame {
        instruction_pointer: return_address,
        stack_pointer: cfa,
        frame_pointer: new_rbp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_uleb128() {
        assert_eq!(read_uleb128(&[0x00]), (0, 1));
        assert_eq!(read_uleb128(&[0x01]), (1, 1));
        assert_eq!(read_uleb128(&[0x7F]), (127, 1));
        assert_eq!(read_uleb128(&[0x80, 0x01]), (128, 2));
        assert_eq!(read_uleb128(&[0xE5, 0x8E, 0x26]), (624485, 3));
    }
    
    #[test]
    fn test_sleb128() {
        assert_eq!(read_sleb128(&[0x00]), (0, 1));
        assert_eq!(read_sleb128(&[0x01]), (1, 1));
        assert_eq!(read_sleb128(&[0x7F]), (-1, 1));
        assert_eq!(read_sleb128(&[0x80, 0x7F]), (-128, 2));
    }
}
