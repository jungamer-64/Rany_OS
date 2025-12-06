// ============================================================================
// src/application/browser/script/vm/instructions.rs - Bytecode Instructions
// ============================================================================
//!
//! バイトコード命令と定数プール。

use alloc::string::String;
use alloc::vec::Vec;

use super::super::value::{NativeFunctionId, ScriptValue};

// ============================================================================
// Bytecode Instructions
// ============================================================================

/// バイトコード命令
#[derive(Debug, Clone)]
pub enum Instruction {
    // スタック操作
    /// 定数をプッシュ
    Const(usize),
    /// スタックトップを破棄
    Pop,
    /// スタックトップを複製
    Dup,
    /// スタックのn番目を複製
    DupN(usize),
    /// スタックの2つの値を交換
    Swap,

    // 変数操作
    /// ローカル変数をロード
    LoadLocal(usize),
    /// ローカル変数にストア
    StoreLocal(usize),
    /// グローバル変数をロード
    LoadGlobal(String),
    /// グローバル変数にストア
    StoreGlobal(String),
    /// キャプチャ変数をロード（クロージャ用）
    LoadCapture(String),
    /// キャプチャ変数にストア
    StoreCapture(String),

    // オブジェクト/配列操作
    /// 配列を生成
    MakeArray(usize),
    /// オブジェクトを生成
    MakeObject(usize),
    /// フィールドを取得
    GetField(String),
    /// フィールドを設定
    SetField(String),
    /// インデックスアクセス
    GetIndex,
    /// インデックス設定
    SetIndex,

    // 算術演算
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Neg,

    // ビット演算
    BitAnd,
    BitOr,
    BitXor,
    BitNot,
    Shl,
    Shr,

    // 比較演算
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,

    // 論理演算
    And,
    Or,
    Not,

    // 制御フロー
    /// 無条件ジャンプ
    Jump(usize),
    /// 条件付きジャンプ（falseの場合）
    JumpIfFalse(usize),
    /// 条件付きジャンプ（trueの場合）
    JumpIfTrue(usize),
    /// ループの開始
    LoopStart,
    /// ループの終了
    LoopEnd,
    /// ループを抜ける
    Break,
    /// ループの次のイテレーションへ
    Continue,

    // 関数
    /// 関数呼び出し
    Call(usize),
    /// メソッド呼び出し
    CallMethod(String, usize),
    /// ネイティブ関数呼び出し
    CallNative(NativeFunctionId, usize),
    /// リターン
    Return,

    // クロージャ
    /// クロージャを生成
    MakeClosure(usize, Vec<String>),

    // イテレータ
    /// イテレータを生成
    MakeIterator,
    /// 次の値を取得
    IterNext,
    /// イテレータが終了したかチェック
    IterDone,

    // 範囲
    /// 範囲を生成（排他）
    MakeRange,
    /// 範囲を生成（包含）
    MakeRangeInclusive,

    // その他
    /// 何もしない
    Nop,
    /// プログラム終了
    Halt,
}

// ============================================================================
// Constant Pool
// ============================================================================

/// 定数プール
#[derive(Debug, Clone, Default)]
pub struct ConstantPool {
    constants: Vec<ScriptValue>,
}

impl ConstantPool {
    pub fn new() -> Self {
        Self { constants: Vec::new() }
    }

    pub fn add(&mut self, value: ScriptValue) -> usize {
        let index = self.constants.len();
        self.constants.push(value);
        index
    }

    pub fn get(&self, index: usize) -> Option<&ScriptValue> {
        self.constants.get(index)
    }
}
