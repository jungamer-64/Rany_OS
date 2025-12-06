// ============================================================================
// src/application/browser/script/vm/exec.rs - Instruction Execution
// ============================================================================
//!
//! 命令の実行。

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::super::value::{FunctionValue, IteratorValue, RangeValue, ScriptValue};
use super::super::{ErrorKind, ScriptError};
use super::frame::{CallFrame, LoopInfo};
use super::instructions::Instruction;
use super::ops;
use super::vm_core::VirtualMachine;

impl VirtualMachine {
    /// 1命令を実行
    pub(crate) fn execute_instruction(&mut self) -> Result<(), ScriptError> {
        let instruction = self.instructions[self.pc].clone();
        self.pc += 1;

        match instruction {
            // スタック操作
            Instruction::Const(index) => {
                let value = self
                    .constants
                    .get(index)
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
                let value = self
                    .locals
                    .get(base + index)
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
                let value = self.globals.get(&name).cloned().unwrap_or(ScriptValue::Nil);
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
                    ScriptValue::Object(map) => map.get(&name).cloned().unwrap_or(ScriptValue::Nil),
                    ScriptValue::Element(elem) => match name.as_str() {
                        "id" => ScriptValue::Int(elem.id as i64),
                        "tag" => ScriptValue::String(elem.tag_name),
                        "html_id" => elem.html_id.map(ScriptValue::String).unwrap_or(ScriptValue::Nil),
                        _ => ScriptValue::Nil,
                    },
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
                let result = ops::op_add(a, b)?;
                self.stack.push(result);
            }
            Instruction::Sub => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let result = ops::op_sub(a, b)?;
                self.stack.push(result);
            }
            Instruction::Mul => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let result = ops::op_mul(a, b)?;
                self.stack.push(result);
            }
            Instruction::Div => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let result = ops::op_div(a, b)?;
                self.stack.push(result);
            }
            Instruction::Mod => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let result = ops::op_mod(a, b)?;
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
                let result = ops::op_eq(&a, &b);
                self.stack.push(ScriptValue::Bool(result));
            }
            Instruction::Ne => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let result = !ops::op_eq(&a, &b);
                self.stack.push(ScriptValue::Bool(result));
            }
            Instruction::Lt => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let result = ops::op_lt(&a, &b);
                self.stack.push(ScriptValue::Bool(result));
            }
            Instruction::Le => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let result = ops::op_lt(&a, &b) || ops::op_eq(&a, &b);
                self.stack.push(ScriptValue::Bool(result));
            }
            Instruction::Gt => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let result = !ops::op_lt(&a, &b) && !ops::op_eq(&a, &b);
                self.stack.push(ScriptValue::Bool(result));
            }
            Instruction::Ge => {
                let b = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let a = self.stack.pop().unwrap_or(ScriptValue::Nil);
                let result = !ops::op_lt(&a, &b);
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
                        return Err(ScriptError::new(ErrorKind::Runtime, "Not a function", 0, 0));
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
                            0,
                            0,
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
}
