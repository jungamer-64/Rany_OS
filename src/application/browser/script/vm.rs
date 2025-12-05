// ============================================================================
// src/application/browser/script/vm.rs - Virtual Machine
// ============================================================================
//!
//! # 仮想マシン
//!
//! RustScriptのバイトコードを実行するスタックベースの仮想マシン。

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use alloc::vec;

use super::value::{ScriptValue, ElementRef, FunctionValue, NativeFunction, NativeFunctionId, IteratorValue, RangeValue};
use super::{ScriptError, ErrorKind};

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

// ============================================================================
// Call Frame
// ============================================================================

/// 呼び出しフレーム
#[derive(Debug, Clone)]
pub struct CallFrame {
    /// 戻りアドレス
    pub return_addr: usize,
    /// ローカル変数のベースポインタ
    pub base_pointer: usize,
    /// 関数名（デバッグ用）
    pub function_name: String,
    /// キャプチャされた変数（クロージャ用）
    pub captures: BTreeMap<String, ScriptValue>,
}

// ============================================================================
// Loop Info
// ============================================================================

/// ループ情報
#[derive(Debug, Clone)]
struct LoopInfo {
    /// ループの開始位置
    start: usize,
    /// ループの終了位置（break時のジャンプ先）
    end: usize,
}

// ============================================================================
// Virtual Machine
// ============================================================================

/// 仮想マシン
pub struct VirtualMachine {
    /// 命令列
    instructions: Vec<Instruction>,
    /// 定数プール
    constants: ConstantPool,
    /// プログラムカウンタ
    pc: usize,
    /// スタック
    stack: Vec<ScriptValue>,
    /// グローバル変数
    globals: BTreeMap<String, ScriptValue>,
    /// 呼び出しスタック
    call_stack: Vec<CallFrame>,
    /// ループスタック
    loop_stack: Vec<LoopInfo>,
    /// ローカル変数
    locals: Vec<ScriptValue>,
    /// 実行中フラグ
    running: bool,
    /// DOM要素へのコールバック
    dom_callback: Option<Box<dyn Fn(DomOperation) -> ScriptValue>>,
}

/// DOM操作
#[derive(Debug, Clone)]
pub enum DomOperation {
    GetElementById(String),
    GetElementsByClass(String),
    GetElementsByTag(String),
    CreateElement(String),
    AppendChild(usize, usize),
    RemoveChild(usize, usize),
    SetAttribute(usize, String, String),
    GetAttribute(usize, String),
    SetText(usize, String),
    GetText(usize),
    SetStyle(usize, String, String),
    GetStyle(usize, String),
    AddClass(usize, String),
    RemoveClass(usize, String),
    AddEventListener(usize, String, usize),
}

impl VirtualMachine {
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
            constants: ConstantPool::new(),
            pc: 0,
            stack: Vec::new(),
            globals: BTreeMap::new(),
            call_stack: Vec::new(),
            loop_stack: Vec::new(),
            locals: Vec::new(),
            running: false,
            dom_callback: None,
        }
    }

    /// 命令列を設定
    pub fn load(&mut self, instructions: Vec<Instruction>, constants: ConstantPool) {
        self.instructions = instructions;
        self.constants = constants;
        self.pc = 0;
        self.stack.clear();
        self.call_stack.clear();
        self.loop_stack.clear();
        self.locals.clear();
    }

    /// DOMコールバックを設定
    pub fn set_dom_callback<F>(&mut self, callback: F)
    where
        F: Fn(DomOperation) -> ScriptValue + 'static,
    {
        self.dom_callback = Some(Box::new(callback));
    }

    /// グローバル変数を設定
    pub fn set_global(&mut self, name: &str, value: ScriptValue) {
        self.globals.insert(String::from(name), value);
    }

    /// グローバル変数を取得
    pub fn get_global(&self, name: &str) -> Option<&ScriptValue> {
        self.globals.get(name)
    }

    /// ネイティブ関数を登録
    pub fn register_native_function(&mut self, name: &str, id: NativeFunctionId, arity: i32) {
        let native = NativeFunction::new(name, id, arity);
        self.globals.insert(String::from(name), ScriptValue::NativeFunction(native));
    }

    /// 実行
    pub fn run(&mut self) -> Result<ScriptValue, ScriptError> {
        self.running = true;
        self.pc = 0;

        while self.running && self.pc < self.instructions.len() {
            self.execute_instruction()?;
        }

        // スタックの最後の値を返す
        Ok(self.stack.pop().unwrap_or(ScriptValue::Nil))
    }

    /// 1命令を実行
    fn execute_instruction(&mut self) -> Result<(), ScriptError> {
        let instruction = self.instructions[self.pc].clone();
        self.pc += 1;

        match instruction {
            // スタック操作
            Instruction::Const(index) => {
                let value = self.constants.get(index)
                    .cloned()
                    .ok_or_else(|| ScriptError::new(ErrorKind::Runtime, "Invalid constant index", 0, 0))?;
                self.stack.push(value);
            }
            Instruction::Pop => {
                self.stack.pop();
            }
            Instruction::Dup => {
                if let Some(value) = self.stack.last().cloned() {
                    self.stack.push(value);
                }
            }
            Instruction::DupN(n) => {
                if self.stack.len() > n {
                    let value = self.stack[self.stack.len() - 1 - n].clone();
                    self.stack.push(value);
                }
            }
            Instruction::Swap => {
                let len = self.stack.len();
                if len >= 2 {
                    self.stack.swap(len - 1, len - 2);
                }
            }

            // 変数操作
            Instruction::LoadLocal(index) => {
                let base = self.current_base_pointer();
                let value = self.locals.get(base + index)
                    .cloned()
                    .unwrap_or(ScriptValue::Nil);
                self.stack.push(value);
            }
            Instruction::StoreLocal(index) => {
                let base = self.current_base_pointer();
                let value = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let target = base + index;
                while self.locals.len() <= target {
                    self.locals.push(ScriptValue::Nil);
                }
                self.locals[target] = value;
            }
            Instruction::LoadGlobal(name) => {
                let value = self.globals.get(&name)
                    .cloned()
                    .unwrap_or(ScriptValue::Nil);
                self.stack.push(value);
            }
            Instruction::StoreGlobal(name) => {
                let value = self.stack.pop().unwrap_or(ScriptValue::Nil);
                self.globals.insert(name, value);
            }
            Instruction::LoadCapture(name) => {
                let value = if let Some(frame) = self.call_stack.last() {
                    frame.captures.get(&name).cloned().unwrap_or(ScriptValue::Nil)
                } else {
                    ScriptValue::Nil
                };
                self.stack.push(value);
            }
            Instruction::StoreCapture(name) => {
                let value = self.stack.pop().unwrap_or(ScriptValue::Nil);
                if let Some(frame) = self.call_stack.last_mut() {
                    frame.captures.insert(name, value);
                }
            }

            // オブジェクト/配列操作
            Instruction::MakeArray(count) => {
                let mut arr = Vec::new();
                for _ in 0..count {
                    if let Some(value) = self.stack.pop() {
                        arr.push(value);
                    }
                }
                arr.reverse();
                self.stack.push(ScriptValue::Array(arr));
            }
            Instruction::MakeObject(count) => {
                let mut obj = BTreeMap::new();
                for _ in 0..count {
                    let value = self.stack.pop().unwrap_or(ScriptValue::Nil);
                    if let Some(ScriptValue::String(key)) = self.stack.pop() {
                        obj.insert(key, value);
                    }
                }
                self.stack.push(ScriptValue::Object(obj));
            }
            Instruction::GetField(name) => {
                let obj = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let value = match obj {
                    ScriptValue::Object(map) => {
                        map.get(&name).cloned().unwrap_or(ScriptValue::Nil)
                    }
                    ScriptValue::Element(elem) => {
                        match name.as_str() {
                            "id" => ScriptValue::Int(elem.id as i64),
                            "tag" => ScriptValue::String(elem.tag_name),
                            "html_id" => elem.html_id.map(ScriptValue::String).unwrap_or(ScriptValue::Nil),
                            _ => ScriptValue::Nil,
                        }
                    }
                    _ => ScriptValue::Nil,
                };
                self.stack.push(value);
            }
            Instruction::SetField(name) => {
                let value = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let obj = self.stack.pop().unwrap_or(ScriptValue::Nil);
                if let ScriptValue::Object(mut map) = obj {
                    map.insert(name, value.clone());
                    self.stack.push(ScriptValue::Object(map));
                } else {
                    self.stack.push(ScriptValue::Nil);
                }
            }
            Instruction::GetIndex => {
                let index = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let container = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let value = match (&container, &index) {
                    (ScriptValue::Array(arr), ScriptValue::Int(i)) => {
                        let idx = *i as usize;
                        arr.get(idx).cloned().unwrap_or(ScriptValue::Nil)
                    }
                    (ScriptValue::String(s), ScriptValue::Int(i)) => {
                        let chars: Vec<char> = s.chars().collect();
                        let idx = *i as usize;
                        if idx < chars.len() {
                            ScriptValue::String(String::from(chars[idx]))
                        } else {
                            ScriptValue::Nil
                        }
                    }
                    (ScriptValue::Object(map), ScriptValue::String(key)) => {
                        map.get(key).cloned().unwrap_or(ScriptValue::Nil)
                    }
                    _ => ScriptValue::Nil,
                };
                self.stack.push(value);
            }
            Instruction::SetIndex => {
                let value = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let index = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let container = self.stack.pop().unwrap_or(ScriptValue::Nil);
                match (container, &index) {
                    (ScriptValue::Array(mut arr), ScriptValue::Int(i)) => {
                        let idx = *i as usize;
                        if idx < arr.len() {
                            arr[idx] = value;
                        }
                        self.stack.push(ScriptValue::Array(arr));
                    }
                    (ScriptValue::Object(mut map), ScriptValue::String(key)) => {
                        map.insert(key.clone(), value);
                        self.stack.push(ScriptValue::Object(map));
                    }
                    _ => {
                        self.stack.push(ScriptValue::Nil);
                    }
                }
            }

            // 算術演算
            Instruction::Add => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let result = self.op_add(a, b)?;
                self.stack.push(result);
            }
            Instruction::Sub => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let result = self.op_sub(a, b)?;
                self.stack.push(result);
            }
            Instruction::Mul => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let result = self.op_mul(a, b)?;
                self.stack.push(result);
            }
            Instruction::Div => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let result = self.op_div(a, b)?;
                self.stack.push(result);
            }
            Instruction::Mod => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let result = self.op_mod(a, b)?;
                self.stack.push(result);
            }
            Instruction::Neg => {
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let result = match a {
                    ScriptValue::Int(i) => ScriptValue::Int(-i),
                    ScriptValue::Float(f) => ScriptValue::Float(-f),
                    _ => ScriptValue::Nil,
                };
                self.stack.push(result);
            }

            // ビット演算
            Instruction::BitAnd => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                if let (ScriptValue::Int(a), ScriptValue::Int(b)) = (a, b) {
                    self.stack.push(ScriptValue::Int(a & b));
                } else {
                    self.stack.push(ScriptValue::Nil);
                }
            }
            Instruction::BitOr => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                if let (ScriptValue::Int(a), ScriptValue::Int(b)) = (a, b) {
                    self.stack.push(ScriptValue::Int(a | b));
                } else {
                    self.stack.push(ScriptValue::Nil);
                }
            }
            Instruction::BitXor => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                if let (ScriptValue::Int(a), ScriptValue::Int(b)) = (a, b) {
                    self.stack.push(ScriptValue::Int(a ^ b));
                } else {
                    self.stack.push(ScriptValue::Nil);
                }
            }
            Instruction::BitNot => {
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                if let ScriptValue::Int(a) = a {
                    self.stack.push(ScriptValue::Int(!a));
                } else {
                    self.stack.push(ScriptValue::Nil);
                }
            }
            Instruction::Shl => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                if let (ScriptValue::Int(a), ScriptValue::Int(b)) = (a, b) {
                    self.stack.push(ScriptValue::Int(a << b));
                } else {
                    self.stack.push(ScriptValue::Nil);
                }
            }
            Instruction::Shr => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                if let (ScriptValue::Int(a), ScriptValue::Int(b)) = (a, b) {
                    self.stack.push(ScriptValue::Int(a >> b));
                } else {
                    self.stack.push(ScriptValue::Nil);
                }
            }

            // 比較演算
            Instruction::Eq => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let result = self.op_eq(&a, &b);
                self.stack.push(ScriptValue::Bool(result));
            }
            Instruction::Ne => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let result = !self.op_eq(&a, &b);
                self.stack.push(ScriptValue::Bool(result));
            }
            Instruction::Lt => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let result = self.op_lt(&a, &b);
                self.stack.push(ScriptValue::Bool(result));
            }
            Instruction::Le => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let result = self.op_lt(&a, &b) || self.op_eq(&a, &b);
                self.stack.push(ScriptValue::Bool(result));
            }
            Instruction::Gt => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let result = !self.op_lt(&a, &b) && !self.op_eq(&a, &b);
                self.stack.push(ScriptValue::Bool(result));
            }
            Instruction::Ge => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let result = !self.op_lt(&a, &b);
                self.stack.push(ScriptValue::Bool(result));
            }

            // 論理演算
            Instruction::And => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                self.stack.push(ScriptValue::Bool(a.is_truthy() && b.is_truthy()));
            }
            Instruction::Or => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                self.stack.push(ScriptValue::Bool(a.is_truthy() || b.is_truthy()));
            }
            Instruction::Not => {
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                self.stack.push(ScriptValue::Bool(!a.is_truthy()));
            }

            // 制御フロー
            Instruction::Jump(addr) => {
                self.pc = addr;
            }
            Instruction::JumpIfFalse(addr) => {
                let cond = self.stack.pop().unwrap_or(ScriptValue::Nil);
                if !cond.is_truthy() {
                    self.pc = addr;
                }
            }
            Instruction::JumpIfTrue(addr) => {
                let cond = self.stack.pop().unwrap_or(ScriptValue::Nil);
                if cond.is_truthy() {
                    self.pc = addr;
                }
            }
            Instruction::LoopStart => {
                // ループスタックに現在位置を記録
                let start = self.pc;
                // 対応するLoopEndを探す
                let mut depth = 1;
                let mut end = self.pc;
                while depth > 0 && end < self.instructions.len() {
                    match &self.instructions[end] {
                        Instruction::LoopStart => depth += 1,
                        Instruction::LoopEnd => depth -= 1,
                        _ => {}
                    }
                    end += 1;
                }
                self.loop_stack.push(LoopInfo { start, end });
            }
            Instruction::LoopEnd => {
                self.loop_stack.pop();
            }
            Instruction::Break => {
                if let Some(loop_info) = self.loop_stack.last() {
                    self.pc = loop_info.end;
                }
            }
            Instruction::Continue => {
                if let Some(loop_info) = self.loop_stack.last() {
                    self.pc = loop_info.start;
                }
            }

            // 関数呼び出し
            Instruction::Call(argc) => {
                // 関数を取得
                let func = self.stack.pop().unwrap_or(ScriptValue::Nil);
                match func {
                    ScriptValue::Function(f) => {
                        // 引数を収集
                        let mut args = Vec::new();
                        for _ in 0..argc {
                            args.push(self.stack.pop().unwrap_or(ScriptValue::Nil));
                        }
                        args.reverse();

                        // 呼び出しフレームを作成
                        let frame = CallFrame {
                            return_addr: self.pc,
                            base_pointer: self.locals.len(),
                            function_name: f.name.clone(),
                            captures: f.captures.clone(),
                        };
                        self.call_stack.push(frame);

                        // 引数をローカル変数として設定
                        for arg in args {
                            self.locals.push(arg);
                        }

                        // 関数本体へジャンプ
                        self.pc = f.body_addr;
                    }
                    ScriptValue::NativeFunction(native) => {
                        // 引数を収集
                        let mut args = Vec::new();
                        for _ in 0..argc {
                            args.push(self.stack.pop().unwrap_or(ScriptValue::Nil));
                        }
                        args.reverse();

                        // ネイティブ関数を実行
                        let result = self.call_native(native.id, args)?;
                        self.stack.push(result);
                    }
                    _ => {
                        return Err(ScriptError::new(
                            ErrorKind::Runtime,
                            "Not a function",
                            0, 0,
                        ));
                    }
                }
            }
            Instruction::CallMethod(name, argc) => {
                // 引数を収集
                let mut args = Vec::new();
                for _ in 0..argc {
                    args.push(self.stack.pop().unwrap_or(ScriptValue::Nil));
                }
                args.reverse();

                // レシーバーを取得
                let receiver = self.stack.pop().unwrap_or(ScriptValue::Nil);

                // メソッドを実行
                let result = self.call_method(receiver, &name, args)?;
                self.stack.push(result);
            }
            Instruction::CallNative(id, argc) => {
                let mut args = Vec::new();
                for _ in 0..argc {
                    args.push(self.stack.pop().unwrap_or(ScriptValue::Nil));
                }
                args.reverse();

                let result = self.call_native(id, args)?;
                self.stack.push(result);
            }
            Instruction::Return => {
                let return_value = self.stack.pop().unwrap_or(ScriptValue::Nil);

                if let Some(frame) = self.call_stack.pop() {
                    // ローカル変数をクリーンアップ
                    self.locals.truncate(frame.base_pointer);
                    // 戻りアドレスへジャンプ
                    self.pc = frame.return_addr;
                } else {
                    // トップレベルでのreturn
                    self.running = false;
                }

                self.stack.push(return_value);
            }

            // クロージャ
            Instruction::MakeClosure(body_addr, capture_names) => {
                let mut captures = BTreeMap::new();
                for name in capture_names {
                    // 現在のスコープから変数をキャプチャ
                    if let Some(value) = self.globals.get(&name) {
                        captures.insert(name, value.clone());
                    }
                }
                let func = FunctionValue::closure(Vec::new(), body_addr, captures);
                self.stack.push(ScriptValue::Function(func));
            }

            // イテレータ
            Instruction::MakeIterator => {
                let value = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let iter = match value {
                    ScriptValue::Array(arr) => IteratorValue::from_array(arr),
                    ScriptValue::Range(r) => r.to_iterator(),
                    ScriptValue::String(s) => IteratorValue::from_string(s),
                    _ => {
                        return Err(ScriptError::new(
                            ErrorKind::Runtime,
                            "Value is not iterable",
                            0, 0,
                        ));
                    }
                };
                self.stack.push(ScriptValue::Iterator(iter));
            }
            Instruction::IterNext => {
                let iter = self.stack.pop().unwrap_or(ScriptValue::Nil);
                if let ScriptValue::Iterator(mut iter_val) = iter {
                    if let Some(value) = iter_val.next() {
                        self.stack.push(ScriptValue::Iterator(iter_val));
                        self.stack.push(value);
                        self.stack.push(ScriptValue::Bool(false)); // done = false
                    } else {
                        self.stack.push(ScriptValue::Iterator(iter_val));
                        self.stack.push(ScriptValue::Nil);
                        self.stack.push(ScriptValue::Bool(true)); // done = true
                    }
                } else {
                    self.stack.push(ScriptValue::Nil);
                    self.stack.push(ScriptValue::Bool(true));
                }
            }
            Instruction::IterDone => {
                let done = self.stack.pop().unwrap_or(ScriptValue::Bool(true));
                self.stack.push(done);
            }

            // 範囲
            Instruction::MakeRange => {
                let end = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let start = self.stack.pop().unwrap_or(ScriptValue::Nil);
                if let (ScriptValue::Int(s), ScriptValue::Int(e)) = (start, end) {
                    self.stack.push(ScriptValue::Range(RangeValue::new(s, e, false)));
                } else {
                    self.stack.push(ScriptValue::Nil);
                }
            }
            Instruction::MakeRangeInclusive => {
                let end = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let start = self.stack.pop().unwrap_or(ScriptValue::Nil);
                if let (ScriptValue::Int(s), ScriptValue::Int(e)) = (start, end) {
                    self.stack.push(ScriptValue::Range(RangeValue::new(s, e, true)));
                } else {
                    self.stack.push(ScriptValue::Nil);
                }
            }

            // その他
            Instruction::Nop => {}
            Instruction::Halt => {
                self.running = false;
            }
        }

        Ok(())
    }

    // 算術演算ヘルパー
    fn op_add(&self, a: ScriptValue, b: ScriptValue) -> Result<ScriptValue, ScriptError> {
        match (a, b) {
            (ScriptValue::Int(a), ScriptValue::Int(b)) => Ok(ScriptValue::Int(a + b)),
            (ScriptValue::Float(a), ScriptValue::Float(b)) => Ok(ScriptValue::Float(a + b)),
            (ScriptValue::Int(a), ScriptValue::Float(b)) => Ok(ScriptValue::Float(a as f64 + b)),
            (ScriptValue::Float(a), ScriptValue::Int(b)) => Ok(ScriptValue::Float(a + b as f64)),
            (ScriptValue::String(a), ScriptValue::String(b)) => {
                let mut result = a;
                result.push_str(&b);
                Ok(ScriptValue::String(result))
            }
            (ScriptValue::String(a), b) => {
                let mut result = a;
                result.push_str(&b.to_string_value());
                Ok(ScriptValue::String(result))
            }
            _ => Ok(ScriptValue::Nil),
        }
    }

    fn op_sub(&self, a: ScriptValue, b: ScriptValue) -> Result<ScriptValue, ScriptError> {
        match (a, b) {
            (ScriptValue::Int(a), ScriptValue::Int(b)) => Ok(ScriptValue::Int(a - b)),
            (ScriptValue::Float(a), ScriptValue::Float(b)) => Ok(ScriptValue::Float(a - b)),
            (ScriptValue::Int(a), ScriptValue::Float(b)) => Ok(ScriptValue::Float(a as f64 - b)),
            (ScriptValue::Float(a), ScriptValue::Int(b)) => Ok(ScriptValue::Float(a - b as f64)),
            _ => Ok(ScriptValue::Nil),
        }
    }

    fn op_mul(&self, a: ScriptValue, b: ScriptValue) -> Result<ScriptValue, ScriptError> {
        match (a, b) {
            (ScriptValue::Int(a), ScriptValue::Int(b)) => Ok(ScriptValue::Int(a * b)),
            (ScriptValue::Float(a), ScriptValue::Float(b)) => Ok(ScriptValue::Float(a * b)),
            (ScriptValue::Int(a), ScriptValue::Float(b)) => Ok(ScriptValue::Float(a as f64 * b)),
            (ScriptValue::Float(a), ScriptValue::Int(b)) => Ok(ScriptValue::Float(a * b as f64)),
            _ => Ok(ScriptValue::Nil),
        }
    }

    fn op_div(&self, a: ScriptValue, b: ScriptValue) -> Result<ScriptValue, ScriptError> {
        match (a, b) {
            (ScriptValue::Int(a), ScriptValue::Int(b)) => {
                if b == 0 {
                    return Err(ScriptError::new(ErrorKind::Runtime, "Division by zero", 0, 0));
                }
                Ok(ScriptValue::Int(a / b))
            }
            (ScriptValue::Float(a), ScriptValue::Float(b)) => {
                if b == 0.0 {
                    return Err(ScriptError::new(ErrorKind::Runtime, "Division by zero", 0, 0));
                }
                Ok(ScriptValue::Float(a / b))
            }
            (ScriptValue::Int(a), ScriptValue::Float(b)) => {
                if b == 0.0 {
                    return Err(ScriptError::new(ErrorKind::Runtime, "Division by zero", 0, 0));
                }
                Ok(ScriptValue::Float(a as f64 / b))
            }
            (ScriptValue::Float(a), ScriptValue::Int(b)) => {
                if b == 0 {
                    return Err(ScriptError::new(ErrorKind::Runtime, "Division by zero", 0, 0));
                }
                Ok(ScriptValue::Float(a / b as f64))
            }
            _ => Ok(ScriptValue::Nil),
        }
    }

    fn op_mod(&self, a: ScriptValue, b: ScriptValue) -> Result<ScriptValue, ScriptError> {
        match (a, b) {
            (ScriptValue::Int(a), ScriptValue::Int(b)) => {
                if b == 0 {
                    return Err(ScriptError::new(ErrorKind::Runtime, "Division by zero", 0, 0));
                }
                Ok(ScriptValue::Int(a % b))
            }
            _ => Ok(ScriptValue::Nil),
        }
    }

    fn op_eq(&self, a: &ScriptValue, b: &ScriptValue) -> bool {
        match (a, b) {
            (ScriptValue::Nil, ScriptValue::Nil) => true,
            (ScriptValue::Bool(a), ScriptValue::Bool(b)) => a == b,
            (ScriptValue::Int(a), ScriptValue::Int(b)) => a == b,
            (ScriptValue::Float(a), ScriptValue::Float(b)) => a == b,
            (ScriptValue::Int(a), ScriptValue::Float(b)) => *a as f64 == *b,
            (ScriptValue::Float(a), ScriptValue::Int(b)) => *a == *b as f64,
            (ScriptValue::String(a), ScriptValue::String(b)) => a == b,
            _ => false,
        }
    }

    fn op_lt(&self, a: &ScriptValue, b: &ScriptValue) -> bool {
        match (a, b) {
            (ScriptValue::Int(a), ScriptValue::Int(b)) => a < b,
            (ScriptValue::Float(a), ScriptValue::Float(b)) => a < b,
            (ScriptValue::Int(a), ScriptValue::Float(b)) => (*a as f64) < *b,
            (ScriptValue::Float(a), ScriptValue::Int(b)) => *a < (*b as f64),
            (ScriptValue::String(a), ScriptValue::String(b)) => a < b,
            _ => false,
        }
    }

    fn current_base_pointer(&self) -> usize {
        self.call_stack.last().map(|f| f.base_pointer).unwrap_or(0)
    }

    // ネイティブ関数の実行
    fn call_native(&mut self, id: NativeFunctionId, args: Vec<ScriptValue>) -> Result<ScriptValue, ScriptError> {
        match id {
            NativeFunctionId::ConsoleLog => {
                // 実際のログ出力は実装依存
                let msg = args.iter()
                    .map(|v| v.to_string_value())
                    .collect::<Vec<_>>()
                    .join(" ");
                // ここでログを出力
                Ok(ScriptValue::Nil)
            }
            NativeFunctionId::ConsoleWarn => {
                Ok(ScriptValue::Nil)
            }
            NativeFunctionId::ConsoleError => {
                Ok(ScriptValue::Nil)
            }

            // DOM操作
            NativeFunctionId::DomGetElementById => {
                if let Some(ScriptValue::String(id)) = args.get(0) {
                    if let Some(callback) = &self.dom_callback {
                        return Ok(callback(DomOperation::GetElementById(id.clone())));
                    }
                }
                Ok(ScriptValue::Nil)
            }
            NativeFunctionId::DomCreateElement => {
                if let Some(ScriptValue::String(tag)) = args.get(0) {
                    if let Some(callback) = &self.dom_callback {
                        return Ok(callback(DomOperation::CreateElement(tag.clone())));
                    }
                }
                Ok(ScriptValue::Nil)
            }
            NativeFunctionId::DomSetText => {
                if let (Some(ScriptValue::Element(elem)), Some(ScriptValue::String(text))) = (args.get(0), args.get(1)) {
                    if let Some(callback) = &self.dom_callback {
                        return Ok(callback(DomOperation::SetText(elem.id, text.clone())));
                    }
                }
                Ok(ScriptValue::Nil)
            }
            NativeFunctionId::DomGetText => {
                if let Some(ScriptValue::Element(elem)) = args.get(0) {
                    if let Some(callback) = &self.dom_callback {
                        return Ok(callback(DomOperation::GetText(elem.id)));
                    }
                }
                Ok(ScriptValue::Nil)
            }
            NativeFunctionId::DomSetStyle => {
                if let (Some(ScriptValue::Element(elem)), Some(ScriptValue::String(prop)), Some(ScriptValue::String(value))) = (args.get(0), args.get(1), args.get(2)) {
                    if let Some(callback) = &self.dom_callback {
                        return Ok(callback(DomOperation::SetStyle(elem.id, prop.clone(), value.clone())));
                    }
                }
                Ok(ScriptValue::Nil)
            }

            // 文字列操作
            NativeFunctionId::StringLength => {
                if let Some(ScriptValue::String(s)) = args.get(0) {
                    Ok(ScriptValue::Int(s.len() as i64))
                } else {
                    Ok(ScriptValue::Int(0))
                }
            }
            NativeFunctionId::StringCharAt => {
                if let (Some(ScriptValue::String(s)), Some(ScriptValue::Int(i))) = (args.get(0), args.get(1)) {
                    let chars: Vec<char> = s.chars().collect();
                    let idx = *i as usize;
                    if idx < chars.len() {
                        Ok(ScriptValue::String(String::from(chars[idx])))
                    } else {
                        Ok(ScriptValue::Nil)
                    }
                } else {
                    Ok(ScriptValue::Nil)
                }
            }
            NativeFunctionId::StringSubstring => {
                if let (Some(ScriptValue::String(s)), Some(ScriptValue::Int(start)), Some(ScriptValue::Int(end))) = (args.get(0), args.get(1), args.get(2)) {
                    let start = *start as usize;
                    let end = *end as usize;
                    let chars: Vec<char> = s.chars().collect();
                    if start <= end && end <= chars.len() {
                        let sub: String = chars[start..end].iter().collect();
                        Ok(ScriptValue::String(sub))
                    } else {
                        Ok(ScriptValue::Nil)
                    }
                } else {
                    Ok(ScriptValue::Nil)
                }
            }

            // 配列操作
            NativeFunctionId::ArrayLength => {
                if let Some(ScriptValue::Array(arr)) = args.get(0) {
                    Ok(ScriptValue::Int(arr.len() as i64))
                } else {
                    Ok(ScriptValue::Int(0))
                }
            }
            NativeFunctionId::ArrayPush => {
                if let (Some(ScriptValue::Array(arr)), Some(value)) = (args.get(0), args.get(1)) {
                    let mut new_arr = arr.clone();
                    new_arr.push(value.clone());
                    Ok(ScriptValue::Array(new_arr))
                } else {
                    Ok(ScriptValue::Nil)
                }
            }
            NativeFunctionId::ArrayPop => {
                if let Some(ScriptValue::Array(arr)) = args.get(0) {
                    let mut new_arr = arr.clone();
                    let value = new_arr.pop().unwrap_or(ScriptValue::Nil);
                    Ok(value)
                } else {
                    Ok(ScriptValue::Nil)
                }
            }

            // 数学関数
            NativeFunctionId::MathAbs => {
                match args.get(0) {
                    Some(ScriptValue::Int(i)) => Ok(ScriptValue::Int(i.abs())),
                    Some(ScriptValue::Float(f)) => Ok(ScriptValue::Float(if *f < 0.0 { -*f } else { *f })),
                    _ => Ok(ScriptValue::Nil),
                }
            }
            NativeFunctionId::MathFloor => {
                if let Some(ScriptValue::Float(f)) = args.get(0) {
                    Ok(ScriptValue::Int(*f as i64))
                } else if let Some(ScriptValue::Int(i)) = args.get(0) {
                    Ok(ScriptValue::Int(*i))
                } else {
                    Ok(ScriptValue::Nil)
                }
            }
            NativeFunctionId::MathMin => {
                if args.is_empty() {
                    return Ok(ScriptValue::Nil);
                }
                let mut min = args[0].clone();
                for arg in args.iter().skip(1) {
                    if self.op_lt(arg, &min) {
                        min = arg.clone();
                    }
                }
                Ok(min)
            }
            NativeFunctionId::MathMax => {
                if args.is_empty() {
                    return Ok(ScriptValue::Nil);
                }
                let mut max = args[0].clone();
                for arg in args.iter().skip(1) {
                    if self.op_lt(&max, arg) {
                        max = arg.clone();
                    }
                }
                Ok(max)
            }

            // 型変換
            NativeFunctionId::ParseInt => {
                if let Some(ScriptValue::String(s)) = args.get(0) {
                    if let Ok(i) = s.parse::<i64>() {
                        Ok(ScriptValue::Int(i))
                    } else {
                        Ok(ScriptValue::Nil)
                    }
                } else {
                    Ok(ScriptValue::Nil)
                }
            }
            NativeFunctionId::ParseFloat => {
                if let Some(ScriptValue::String(s)) = args.get(0) {
                    if let Ok(f) = s.parse::<f64>() {
                        Ok(ScriptValue::Float(f))
                    } else {
                        Ok(ScriptValue::Nil)
                    }
                } else {
                    Ok(ScriptValue::Nil)
                }
            }
            NativeFunctionId::ToString => {
                if let Some(value) = args.get(0) {
                    Ok(ScriptValue::String(value.to_string_value()))
                } else {
                    Ok(ScriptValue::String(String::new()))
                }
            }

            NativeFunctionId::TypeOf => {
                if let Some(value) = args.get(0) {
                    Ok(ScriptValue::String(String::from(value.type_name())))
                } else {
                    Ok(ScriptValue::String(String::from("undefined")))
                }
            }
            NativeFunctionId::Print => {
                let msg = args.iter()
                    .map(|v| v.to_string_value())
                    .collect::<Vec<_>>()
                    .join(" ");
                // 実際の出力は実装依存
                Ok(ScriptValue::Nil)
            }

            // その他は未実装としてNilを返す
            _ => Ok(ScriptValue::Nil),
        }
    }

    // メソッド呼び出し
    fn call_method(&mut self, receiver: ScriptValue, name: &str, args: Vec<ScriptValue>) -> Result<ScriptValue, ScriptError> {
        match receiver {
            ScriptValue::String(s) => {
                match name {
                    "len" | "length" => Ok(ScriptValue::Int(s.len() as i64)),
                    "to_uppercase" => Ok(ScriptValue::String(s.to_uppercase())),
                    "to_lowercase" => Ok(ScriptValue::String(s.to_lowercase())),
                    "trim" => Ok(ScriptValue::String(String::from(s.trim()))),
                    "contains" => {
                        if let Some(ScriptValue::String(substr)) = args.get(0) {
                            Ok(ScriptValue::Bool(s.contains(substr.as_str())))
                        } else {
                            Ok(ScriptValue::Bool(false))
                        }
                    }
                    "starts_with" => {
                        if let Some(ScriptValue::String(prefix)) = args.get(0) {
                            Ok(ScriptValue::Bool(s.starts_with(prefix.as_str())))
                        } else {
                            Ok(ScriptValue::Bool(false))
                        }
                    }
                    "ends_with" => {
                        if let Some(ScriptValue::String(suffix)) = args.get(0) {
                            Ok(ScriptValue::Bool(s.ends_with(suffix.as_str())))
                        } else {
                            Ok(ScriptValue::Bool(false))
                        }
                    }
                    "split" => {
                        if let Some(ScriptValue::String(delim)) = args.get(0) {
                            let parts: Vec<ScriptValue> = s.split(delim.as_str())
                                .map(|p| ScriptValue::String(String::from(p)))
                                .collect();
                            Ok(ScriptValue::Array(parts))
                        } else {
                            Ok(ScriptValue::Array(vec![ScriptValue::String(s)]))
                        }
                    }
                    "replace" => {
                        if let (Some(ScriptValue::String(from)), Some(ScriptValue::String(to))) = (args.get(0), args.get(1)) {
                            Ok(ScriptValue::String(s.replace(from.as_str(), to.as_str())))
                        } else {
                            Ok(ScriptValue::String(s))
                        }
                    }
                    _ => Ok(ScriptValue::Nil),
                }
            }
            ScriptValue::Array(arr) => {
                match name {
                    "len" | "length" => Ok(ScriptValue::Int(arr.len() as i64)),
                    "push" => {
                        let mut new_arr = arr.clone();
                        for arg in args {
                            new_arr.push(arg);
                        }
                        Ok(ScriptValue::Array(new_arr))
                    }
                    "pop" => {
                        let mut new_arr = arr.clone();
                        let value = new_arr.pop().unwrap_or(ScriptValue::Nil);
                        Ok(value)
                    }
                    "first" => {
                        Ok(arr.first().cloned().unwrap_or(ScriptValue::Nil))
                    }
                    "last" => {
                        Ok(arr.last().cloned().unwrap_or(ScriptValue::Nil))
                    }
                    "get" => {
                        if let Some(ScriptValue::Int(i)) = args.get(0) {
                            Ok(arr.get(*i as usize).cloned().unwrap_or(ScriptValue::Nil))
                        } else {
                            Ok(ScriptValue::Nil)
                        }
                    }
                    "contains" => {
                        if let Some(value) = args.get(0) {
                            Ok(ScriptValue::Bool(arr.iter().any(|v| self.op_eq(v, value))))
                        } else {
                            Ok(ScriptValue::Bool(false))
                        }
                    }
                    "join" => {
                        let delim = args.get(0)
                            .and_then(|v| v.as_string())
                            .unwrap_or(",");
                        let result: Vec<String> = arr.iter()
                            .map(|v| v.to_string_value())
                            .collect();
                        Ok(ScriptValue::String(result.join(delim)))
                    }
                    "reverse" => {
                        let mut new_arr = arr.clone();
                        new_arr.reverse();
                        Ok(ScriptValue::Array(new_arr))
                    }
                    "iter" => {
                        Ok(ScriptValue::Iterator(IteratorValue::from_array(arr)))
                    }
                    _ => Ok(ScriptValue::Nil),
                }
            }
            ScriptValue::Object(obj) => {
                match name {
                    "keys" => {
                        let keys: Vec<ScriptValue> = obj.keys()
                            .map(|k| ScriptValue::String(k.clone()))
                            .collect();
                        Ok(ScriptValue::Array(keys))
                    }
                    "values" => {
                        let values: Vec<ScriptValue> = obj.values().cloned().collect();
                        Ok(ScriptValue::Array(values))
                    }
                    "get" => {
                        if let Some(ScriptValue::String(key)) = args.get(0) {
                            Ok(obj.get(key).cloned().unwrap_or(ScriptValue::Nil))
                        } else {
                            Ok(ScriptValue::Nil)
                        }
                    }
                    "contains_key" | "has" => {
                        if let Some(ScriptValue::String(key)) = args.get(0) {
                            Ok(ScriptValue::Bool(obj.contains_key(key)))
                        } else {
                            Ok(ScriptValue::Bool(false))
                        }
                    }
                    _ => Ok(ScriptValue::Nil),
                }
            }
            ScriptValue::Element(elem) => {
                // DOM要素のメソッドはDOMコールバック経由で処理
                if let Some(callback) = &self.dom_callback {
                    match name {
                        "set_text" => {
                            if let Some(ScriptValue::String(text)) = args.get(0) {
                                return Ok(callback(DomOperation::SetText(elem.id, text.clone())));
                            }
                        }
                        "get_text" => {
                            return Ok(callback(DomOperation::GetText(elem.id)));
                        }
                        "set_style" => {
                            if let (Some(ScriptValue::String(prop)), Some(ScriptValue::String(value))) = (args.get(0), args.get(1)) {
                                return Ok(callback(DomOperation::SetStyle(elem.id, prop.clone(), value.clone())));
                            }
                        }
                        "get_style" => {
                            if let Some(ScriptValue::String(prop)) = args.get(0) {
                                return Ok(callback(DomOperation::GetStyle(elem.id, prop.clone())));
                            }
                        }
                        "set_attribute" => {
                            if let (Some(ScriptValue::String(name)), Some(ScriptValue::String(value))) = (args.get(0), args.get(1)) {
                                return Ok(callback(DomOperation::SetAttribute(elem.id, name.clone(), value.clone())));
                            }
                        }
                        "get_attribute" => {
                            if let Some(ScriptValue::String(attr)) = args.get(0) {
                                return Ok(callback(DomOperation::GetAttribute(elem.id, attr.clone())));
                            }
                        }
                        "add_class" => {
                            if let Some(ScriptValue::String(class)) = args.get(0) {
                                return Ok(callback(DomOperation::AddClass(elem.id, class.clone())));
                            }
                        }
                        "remove_class" => {
                            if let Some(ScriptValue::String(class)) = args.get(0) {
                                return Ok(callback(DomOperation::RemoveClass(elem.id, class.clone())));
                            }
                        }
                        "on" => {
                            if let (Some(ScriptValue::String(event)), Some(ScriptValue::Function(f))) = (args.get(0), args.get(1)) {
                                return Ok(callback(DomOperation::AddEventListener(elem.id, event.clone(), f.body_addr)));
                            }
                        }
                        _ => {}
                    }
                }
                Ok(ScriptValue::Nil)
            }
            ScriptValue::Range(r) => {
                match name {
                    "contains" => {
                        if let Some(ScriptValue::Int(v)) = args.get(0) {
                            Ok(ScriptValue::Bool(r.contains(*v)))
                        } else {
                            Ok(ScriptValue::Bool(false))
                        }
                    }
                    "iter" => {
                        Ok(ScriptValue::Iterator(r.to_iterator()))
                    }
                    _ => Ok(ScriptValue::Nil),
                }
            }
            _ => Ok(ScriptValue::Nil),
        }
    }
}

impl Default for VirtualMachine {
    fn default() -> Self {
        Self::new()
    }
}
