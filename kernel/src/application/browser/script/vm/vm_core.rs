// ============================================================================
// src/application/browser/script/vm/vm_core.rs - Virtual Machine Core
// ============================================================================
//!
//! 仮想マシンの構造体定義と基本メソッド。

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::super::value::{NativeFunction, NativeFunctionId, ScriptValue};
use super::super::ScriptError;
use super::dom::DomOperation;
use super::frame::{CallFrame, LoopInfo};
use super::instructions::{ConstantPool, Instruction};

// ============================================================================
// Virtual Machine
// ============================================================================

/// 仮想マシン
pub struct VirtualMachine {
    /// 命令列
    pub(crate) instructions: Vec<Instruction>,
    /// 定数プール
    pub(crate) constants: ConstantPool,
    /// プログラムカウンタ
    pub(crate) pc: usize,
    /// スタック
    pub(crate) stack: Vec<ScriptValue>,
    /// グローバル変数
    pub(crate) globals: BTreeMap<String, ScriptValue>,
    /// 呼び出しスタック
    pub(crate) call_stack: Vec<CallFrame>,
    /// ループスタック
    pub(crate) loop_stack: Vec<LoopInfo>,
    /// ローカル変数
    pub(crate) locals: Vec<ScriptValue>,
    /// 実行中フラグ
    pub(crate) running: bool,
    /// DOM要素へのコールバック
    pub(crate) dom_callback: Option<Box<dyn Fn(DomOperation) -> ScriptValue>>,
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
        self.globals
            .insert(String::from(name), ScriptValue::NativeFunction(native));
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

    /// 現在のベースポインタを取得
    pub(crate) fn current_base_pointer(&self) -> usize {
        self.call_stack.last().map(|f| f.base_pointer).unwrap_or(0)
    }
}

impl Default for VirtualMachine {
    fn default() -> Self {
        Self::new()
    }
}
