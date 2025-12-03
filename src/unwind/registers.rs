//! x86_64 DWARF レジスタ定義
//!
//! マジックナンバー（0, 6, 7, 16等）を排除し、型安全なレジスタ操作を提供する。

use core::fmt;

/// x86_64 DWARF レジスタ番号
/// 
/// DWARF標準で定義されたx86_64のレジスタ番号マッピング。
/// System V AMD64 ABI に準拠。
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwarfRegister {
    // 汎用レジスタ (0-15)
    Rax = 0,
    Rdx = 1,
    Rcx = 2,
    Rbx = 3,
    Rsi = 4,
    Rdi = 5,
    Rbp = 6,
    Rsp = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
    
    // 特殊レジスタ
    /// リターンアドレスレジスタ（RIP）
    ReturnAddress = 16,
    
    // XMM レジスタ (17-32)
    Xmm0 = 17,
    Xmm1 = 18,
    Xmm2 = 19,
    Xmm3 = 20,
    Xmm4 = 21,
    Xmm5 = 22,
    Xmm6 = 23,
    Xmm7 = 24,
    Xmm8 = 25,
    Xmm9 = 26,
    Xmm10 = 27,
    Xmm11 = 28,
    Xmm12 = 29,
    Xmm13 = 30,
    Xmm14 = 31,
    Xmm15 = 32,
    
    // セグメントレジスタなど (拡張用)
    // ST0-ST7, MM0-MM7, RFLAGS, ES, CS, SS, DS, FS, GS などは
    // アンワインドでは通常使用しないため省略
}

impl DwarfRegister {
    /// DWARF番号からレジスタを取得（エイリアス）
    #[inline]
    pub const fn from_dwarf_number(val: u8) -> Option<Self> {
        Self::from_u8(val)
    }

    /// 数値からレジスタを取得
    #[inline]
    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Rax),
            1 => Some(Self::Rdx),
            2 => Some(Self::Rcx),
            3 => Some(Self::Rbx),
            4 => Some(Self::Rsi),
            5 => Some(Self::Rdi),
            6 => Some(Self::Rbp),
            7 => Some(Self::Rsp),
            8 => Some(Self::R8),
            9 => Some(Self::R9),
            10 => Some(Self::R10),
            11 => Some(Self::R11),
            12 => Some(Self::R12),
            13 => Some(Self::R13),
            14 => Some(Self::R14),
            15 => Some(Self::R15),
            16 => Some(Self::ReturnAddress),
            17 => Some(Self::Xmm0),
            18 => Some(Self::Xmm1),
            19 => Some(Self::Xmm2),
            20 => Some(Self::Xmm3),
            21 => Some(Self::Xmm4),
            22 => Some(Self::Xmm5),
            23 => Some(Self::Xmm6),
            24 => Some(Self::Xmm7),
            25 => Some(Self::Xmm8),
            26 => Some(Self::Xmm9),
            27 => Some(Self::Xmm10),
            28 => Some(Self::Xmm11),
            29 => Some(Self::Xmm12),
            30 => Some(Self::Xmm13),
            31 => Some(Self::Xmm14),
            32 => Some(Self::Xmm15),
            _ => None,
        }
    }

    /// u64からレジスタを取得
    #[inline]
    pub const fn from_u64(val: u64) -> Option<Self> {
        if val <= u8::MAX as u64 {
            Self::from_u8(val as u8)
        } else {
            None
        }
    }

    /// レジスタ番号を取得
    #[inline]
    pub const fn number(self) -> u8 {
        self as u8
    }

    /// CFAレジスタとして有効かどうか
    /// 
    /// CFA (Canonical Frame Address) として使用できるのは
    /// 通常 RSP または RBP のみ
    #[inline]
    pub const fn is_valid_cfa_register(self) -> bool {
        matches!(self, Self::Rsp | Self::Rbp)
    }

    /// 呼び出し規約で保存されるレジスタかどうか (callee-saved)
    /// 
    /// System V AMD64 ABI では RBX, RBP, R12-R15 が callee-saved
    #[inline]
    pub const fn is_callee_saved(self) -> bool {
        matches!(
            self,
            Self::Rbx | Self::Rbp | Self::R12 | Self::R13 | Self::R14 | Self::R15
        )
    }

    /// 引数レジスタかどうか
    /// 
    /// System V AMD64 ABI では RDI, RSI, RDX, RCX, R8, R9 が引数用
    #[inline]
    pub const fn is_argument_register(self) -> bool {
        matches!(
            self,
            Self::Rdi | Self::Rsi | Self::Rdx | Self::Rcx | Self::R8 | Self::R9
        )
    }

    /// レジスタ名を取得
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rax => "rax",
            Self::Rdx => "rdx",
            Self::Rcx => "rcx",
            Self::Rbx => "rbx",
            Self::Rsi => "rsi",
            Self::Rdi => "rdi",
            Self::Rbp => "rbp",
            Self::Rsp => "rsp",
            Self::R8 => "r8",
            Self::R9 => "r9",
            Self::R10 => "r10",
            Self::R11 => "r11",
            Self::R12 => "r12",
            Self::R13 => "r13",
            Self::R14 => "r14",
            Self::R15 => "r15",
            Self::ReturnAddress => "rip",
            Self::Xmm0 => "xmm0",
            Self::Xmm1 => "xmm1",
            Self::Xmm2 => "xmm2",
            Self::Xmm3 => "xmm3",
            Self::Xmm4 => "xmm4",
            Self::Xmm5 => "xmm5",
            Self::Xmm6 => "xmm6",
            Self::Xmm7 => "xmm7",
            Self::Xmm8 => "xmm8",
            Self::Xmm9 => "xmm9",
            Self::Xmm10 => "xmm10",
            Self::Xmm11 => "xmm11",
            Self::Xmm12 => "xmm12",
            Self::Xmm13 => "xmm13",
            Self::Xmm14 => "xmm14",
            Self::Xmm15 => "xmm15",
        }
    }
}

impl fmt::Display for DwarfRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// レジスタルール（型安全版）
// ============================================================================

/// DWARF CFI レジスタルール
/// 
/// 各レジスタの復元方法を定義する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterRule {
    /// 未定義（値は不明）
    Undefined,
    
    /// 同一値（呼び出し元と同じ値を保持）
    SameValue,
    
    /// オフセット: CFA + offset の位置に保存されている
    Offset(i64),
    
    /// 値オフセット: CFA + offset が値そのもの
    ValOffset(i64),
    
    /// レジスタ: 別のレジスタに保存されている
    Register(DwarfRegister),
    
    /// 式: DWARF式で計算（複雑なケース）
    Expression {
        /// 式データへのオフセット
        offset: usize,
        /// 式の長さ
        length: usize,
    },
    
    /// 値式: DWARF式の結果が値そのもの
    ValExpression {
        /// 式データへのオフセット
        offset: usize,
        /// 式の長さ
        length: usize,
    },
    
    /// アーキテクチャ固有
    Architectural,
}

impl Default for RegisterRule {
    fn default() -> Self {
        Self::Undefined
    }
}

// ============================================================================
// レジスタセット（型安全なコレクション）
// ============================================================================

/// アンワインドコンテキストのレジスタセット
/// 
/// 固定サイズの配列を内部に持ち、`DwarfRegister` による型安全なアクセスを提供
pub struct RegisterSet {
    /// レジスタルール（最大33個: 0-32）
    rules: [RegisterRule; Self::MAX_REGISTERS],
}

impl RegisterSet {
    /// サポートするレジスタの最大数
    pub const MAX_REGISTERS: usize = 33;

    /// 新しいレジスタセットを作成（全て未定義）
    pub const fn new() -> Self {
        Self {
            rules: [RegisterRule::Undefined; Self::MAX_REGISTERS],
        }
    }

    /// レジスタのルールを取得
    #[inline]
    pub fn get(&self, reg: DwarfRegister) -> RegisterRule {
        self.rules[reg.number() as usize]
    }

    /// レジスタのルールを設定
    #[inline]
    pub fn set(&mut self, reg: DwarfRegister, rule: RegisterRule) {
        self.rules[reg.number() as usize] = rule;
    }

    /// 番号でレジスタのルールを取得（境界チェック付き）
    #[inline]
    pub fn get_by_number(&self, num: u8) -> Option<RegisterRule> {
        self.rules.get(num as usize).copied()
    }

    /// 番号でレジスタのルールを設定（境界チェック付き）
    #[inline]
    pub fn set_by_number(&mut self, num: u8, rule: RegisterRule) -> bool {
        if let Some(slot) = self.rules.get_mut(num as usize) {
            *slot = rule;
            true
        } else {
            false
        }
    }

    /// 全てのルールをリセット
    pub fn reset(&mut self) {
        self.rules = [RegisterRule::Undefined; Self::MAX_REGISTERS];
    }

    /// 別のセットからコピー
    pub fn copy_from(&mut self, other: &Self) {
        self.rules.copy_from_slice(&other.rules);
    }
}

impl Default for RegisterSet {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for RegisterSet {
    fn clone(&self) -> Self {
        Self {
            rules: self.rules,
        }
    }
}

impl fmt::Debug for RegisterSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("RegisterSet");
        
        // 未定義以外のルールのみ表示
        for i in 0..Self::MAX_REGISTERS {
            if self.rules[i] != RegisterRule::Undefined {
                if let Some(reg) = DwarfRegister::from_u8(i as u8) {
                    debug.field(reg.name(), &self.rules[i]);
                }
            }
        }
        
        debug.finish()
    }
}

// ============================================================================
// CFAルール（型安全版）
// ============================================================================

/// CFA (Canonical Frame Address) ルール
/// 
/// フレームの基準アドレスの計算方法を定義
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfaRule {
    /// レジスタ + オフセット
    RegisterOffset {
        register: DwarfRegister,
        offset: i64,
    },
    
    /// DWARF式で計算
    Expression {
        offset: usize,
        length: usize,
    },
}

impl Default for CfaRule {
    fn default() -> Self {
        // デフォルトは RSP + 0
        Self::RegisterOffset {
            register: DwarfRegister::Rsp,
            offset: 0,
        }
    }
}

// ============================================================================
// 統合アンワインドコンテキスト
// ============================================================================

/// 型安全なアンワインドコンテキスト
#[derive(Clone)]
pub struct UnwindContext {
    /// レジスタルール
    pub registers: RegisterSet,
    /// CFAルール
    pub cfa: CfaRule,
    /// 現在のPC（プログラムカウンタ）
    pub pc: usize,
}

impl UnwindContext {
    /// 新しいコンテキストを作成
    pub const fn new() -> Self {
        Self {
            registers: RegisterSet::new(),
            cfa: CfaRule::RegisterOffset {
                register: DwarfRegister::Rsp,
                offset: 0,
            },
            pc: 0,
        }
    }

    /// 新しいコンテキストを作成（データアライメントファクター付き - 互換性用）
    pub const fn with_data_alignment(_data_alignment_factor: i64) -> Self {
        Self::new()
    }

    /// CFAルールへの参照を取得
    #[inline]
    pub const fn cfa(&self) -> &CfaRule {
        &self.cfa
    }

    /// CFAルールを設定
    #[inline]
    pub fn set_cfa(&mut self, cfa: CfaRule) {
        self.cfa = cfa;
    }

    /// レジスタルールを取得
    #[inline]
    pub fn get_register_rule(&self, reg: DwarfRegister) -> RegisterRule {
        self.registers.get(reg)
    }

    /// レジスタルールを設定
    #[inline]
    pub fn set_register_rule(&mut self, reg: DwarfRegister, rule: RegisterRule) {
        self.registers.set(reg, rule);
    }

    /// CIEの初期状態を設定
    pub fn set_initial_state(&mut self, return_register: DwarfRegister) {
        // 通常、リターンアドレスは CFA-8 に保存される
        self.registers.set(return_register, RegisterRule::Offset(-8));
    }

    /// CFAをレジスタ+オフセットで定義
    pub fn define_cfa(&mut self, reg: DwarfRegister, offset: i64) {
        self.cfa = CfaRule::RegisterOffset {
            register: reg,
            offset,
        };
    }

    /// CFAオフセットのみ変更
    pub fn set_cfa_offset(&mut self, offset: i64) {
        if let CfaRule::RegisterOffset { register, .. } = self.cfa {
            self.cfa = CfaRule::RegisterOffset { register, offset };
        }
    }

    /// CFAレジスタのみ変更
    pub fn set_cfa_register(&mut self, register: DwarfRegister) {
        if let CfaRule::RegisterOffset { offset, .. } = self.cfa {
            self.cfa = CfaRule::RegisterOffset { register, offset };
        }
    }

    /// 別のコンテキストから状態をコピー（clone()より高速）
    /// 
    /// clone() は新しいメモリを確保するが、copy_from() は既存のメモリに上書きするため、
    /// アロケーションコストが発生しない。スタック状態の保存/復元に最適。
    #[inline]
    pub fn copy_from(&mut self, other: &Self) {
        self.registers.copy_from(&other.registers);
        self.cfa = other.cfa;
        self.pc = other.pc;
    }
}

impl Default for UnwindContext {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for UnwindContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnwindContext")
            .field("pc", &format_args!("{:#x}", self.pc))
            .field("cfa", &self.cfa)
            .field("registers", &self.registers)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_from_u8() {
        assert_eq!(DwarfRegister::from_u8(0), Some(DwarfRegister::Rax));
        assert_eq!(DwarfRegister::from_u8(6), Some(DwarfRegister::Rbp));
        assert_eq!(DwarfRegister::from_u8(7), Some(DwarfRegister::Rsp));
        assert_eq!(DwarfRegister::from_u8(16), Some(DwarfRegister::ReturnAddress));
        assert_eq!(DwarfRegister::from_u8(100), None);
    }

    #[test]
    fn test_register_set() {
        let mut regs = RegisterSet::new();
        
        // 初期状態は全て未定義
        assert_eq!(regs.get(DwarfRegister::Rax), RegisterRule::Undefined);
        
        // ルールを設定
        regs.set(DwarfRegister::Rbp, RegisterRule::Offset(-16));
        assert_eq!(regs.get(DwarfRegister::Rbp), RegisterRule::Offset(-16));
        
        // 番号でアクセス
        assert!(regs.set_by_number(7, RegisterRule::SameValue));
        assert_eq!(regs.get(DwarfRegister::Rsp), RegisterRule::SameValue);
        
        // 範囲外
        assert!(!regs.set_by_number(100, RegisterRule::SameValue));
    }

    #[test]
    fn test_callee_saved() {
        assert!(DwarfRegister::Rbx.is_callee_saved());
        assert!(DwarfRegister::Rbp.is_callee_saved());
        assert!(DwarfRegister::R12.is_callee_saved());
        assert!(!DwarfRegister::Rax.is_callee_saved());
        assert!(!DwarfRegister::Rcx.is_callee_saved());
    }
}
