// ============================================================================
// src/application/browser/script/runtime.rs - Script Runtime
// ============================================================================
//!
//! # スクリプトランタイム
//!
//! RustScriptの実行環境を提供する。
//! DOM操作、イベント処理、タイマー管理を統合。

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use alloc::vec;

use super::lexer::Lexer;
use super::parser::Parser;
use super::ast::*;
use super::value::{ScriptValue, NativeFunction, NativeFunctionId, FunctionValue};
use super::vm::{VirtualMachine, Instruction, ConstantPool, DomOperation};
use super::dom_binding::{DomBinding, DocumentNode};
use super::{ScriptResult, ScriptError, ErrorKind};

// ============================================================================
// Script Runtime
// ============================================================================

/// スクリプトランタイム
pub struct ScriptRuntime {
    /// 仮想マシン
    vm: VirtualMachine,
    /// DOMバインディング
    dom: DomBinding,
    /// コンパイル済みコード
    compiled_scripts: Vec<CompiledScript>,
    /// グローバル変数
    globals: BTreeMap<String, ScriptValue>,
    /// タイマー（ID -> タイマー情報）
    timers: BTreeMap<usize, TimerInfo>,
    /// 次のタイマーID
    next_timer_id: usize,
    /// イベントキュー
    event_queue: Vec<Event>,
    /// 登録済みイベントハンドラ
    event_handlers: BTreeMap<String, Vec<RegisteredHandler>>,
    /// 実行状態
    running: bool,
}

/// コンパイル済みスクリプト
struct CompiledScript {
    /// 命令列
    instructions: Vec<Instruction>,
    /// 定数プール
    constants: ConstantPool,
    /// 関数テーブル（関数名 -> バイトコード位置）
    functions: BTreeMap<String, usize>,
}

/// タイマー情報
#[derive(Debug, Clone)]
struct TimerInfo {
    /// タイマーID
    id: usize,
    /// コールバックのバイトコード位置
    callback_addr: usize,
    /// 実行予定時刻（ティック）
    execute_at: u64,
    /// 繰り返し間隔（setIntervalの場合）
    interval: Option<u64>,
}

/// イベント
#[derive(Debug, Clone)]
pub struct Event {
    /// イベントタイプ（click, input, submit等）
    pub event_type: String,
    /// ターゲット要素ID
    pub target_id: usize,
    /// イベントデータ
    pub data: BTreeMap<String, ScriptValue>,
    /// 伝播停止フラグ
    pub propagation_stopped: bool,
    /// デフォルト動作防止フラグ
    pub default_prevented: bool,
}

/// 登録済みハンドラ
#[derive(Debug, Clone)]
struct RegisteredHandler {
    /// 要素ID
    element_id: usize,
    /// コールバックのバイトコード位置
    callback_addr: usize,
    /// キャプチャフェーズか
    use_capture: bool,
}

impl ScriptRuntime {
    pub fn new() -> Self {
        let mut runtime = Self {
            vm: VirtualMachine::new(),
            dom: DomBinding::new(),
            compiled_scripts: Vec::new(),
            globals: BTreeMap::new(),
            timers: BTreeMap::new(),
            next_timer_id: 1,
            event_queue: Vec::new(),
            event_handlers: BTreeMap::new(),
            running: false,
        };

        // グローバル関数を登録
        runtime.register_builtin_functions();

        runtime
    }

    /// DOMを初期化
    pub fn initialize_dom(&mut self, root: &DocumentNode) {
        self.dom.initialize_from_html(root);

        // documentオブジェクトをグローバルに登録
        let doc = self.dom.create_document_object();
        self.globals.insert(String::from("document"), doc);
    }

    /// スクリプトを実行
    pub fn execute(&mut self, source: &str) -> ScriptResult<ScriptValue> {
        // レキサー
        let mut lexer = Lexer::new(source);
        let tokens = lexer.tokenize()?;

        // パーサー
        let mut parser = Parser::new(tokens);
        let ast = parser.parse()?;

        // コンパイラ
        let (instructions, constants, _functions) = self.compile(&ast)?;

        // 実行
        self.vm.load(instructions, constants);

        // グローバル変数を設定
        for (name, value) in &self.globals {
            self.vm.set_global(name, value.clone());
        }

        // TODO: DOMコールバックを設定（FnMut対応が必要）
        // 現時点ではDOM操作は直接DomBindingを通じて行う

        let result = self.vm.run()?;

        Ok(result)
    }

    /// ASTをバイトコードにコンパイル
    fn compile(&mut self, ast: &Ast) -> Result<(Vec<Instruction>, ConstantPool, BTreeMap<String, usize>), ScriptError> {
        let mut compiler = Compiler::new();
        compiler.compile(ast)?;
        Ok((compiler.instructions, compiler.constants, compiler.functions))
    }

    /// 組み込み関数を登録
    fn register_builtin_functions(&mut self) {
        // コンソール関数
        self.vm.register_native_function("console_log", NativeFunctionId::ConsoleLog, -1);
        self.vm.register_native_function("console_warn", NativeFunctionId::ConsoleWarn, -1);
        self.vm.register_native_function("console_error", NativeFunctionId::ConsoleError, -1);
        self.vm.register_native_function("print", NativeFunctionId::Print, -1);

        // DOM関数
        for (name, func) in DomBinding::register_native_functions() {
            self.globals.insert(name, ScriptValue::NativeFunction(func));
        }

        // 数学関数
        self.vm.register_native_function("abs", NativeFunctionId::MathAbs, 1);
        self.vm.register_native_function("floor", NativeFunctionId::MathFloor, 1);
        self.vm.register_native_function("ceil", NativeFunctionId::MathCeil, 1);
        self.vm.register_native_function("round", NativeFunctionId::MathRound, 1);
        self.vm.register_native_function("min", NativeFunctionId::MathMin, -1);
        self.vm.register_native_function("max", NativeFunctionId::MathMax, -1);

        // 型変換
        self.vm.register_native_function("parse_int", NativeFunctionId::ParseInt, 1);
        self.vm.register_native_function("parse_float", NativeFunctionId::ParseFloat, 1);
        self.vm.register_native_function("to_string", NativeFunctionId::ToString, 1);
        self.vm.register_native_function("type_of", NativeFunctionId::TypeOf, 1);

        // 配列関数
        self.vm.register_native_function("len", NativeFunctionId::ArrayLength, 1);
        self.vm.register_native_function("push", NativeFunctionId::ArrayPush, 2);
        self.vm.register_native_function("pop", NativeFunctionId::ArrayPop, 1);
    }

    /// イベントを発火
    pub fn dispatch_event(&mut self, event: Event) {
        self.event_queue.push(event);
    }

    /// イベントキューを処理
    pub fn process_events(&mut self) -> ScriptResult<()> {
        while let Some(event) = self.event_queue.pop() {
            self.handle_event(&event)?;
        }
        Ok(())
    }

    /// 単一イベントを処理
    fn handle_event(&mut self, event: &Event) -> ScriptResult<()> {
        // 要素に登録されたハンドラを取得
        let handlers = self.dom.dispatch_event(event.target_id, &event.event_type);

        for handler_addr in handlers {
            if event.propagation_stopped {
                break;
            }

            // イベントオブジェクトを作成
            let mut event_obj = BTreeMap::new();
            event_obj.insert(String::from("type"), ScriptValue::String(event.event_type.clone()));
            event_obj.insert(String::from("target"), ScriptValue::Int(event.target_id as i64));
            for (key, value) in &event.data {
                event_obj.insert(key.clone(), value.clone());
            }

            // ハンドラを実行
            // 実際の実装ではVMを使って実行
            // TODO: ハンドラ実行の実装
        }

        Ok(())
    }

    /// タイマーを設定
    pub fn set_timeout(&mut self, callback_addr: usize, delay_ms: u64, current_tick: u64) -> usize {
        let id = self.next_timer_id;
        self.next_timer_id += 1;

        let timer = TimerInfo {
            id,
            callback_addr,
            execute_at: current_tick + delay_ms,
            interval: None,
        };

        self.timers.insert(id, timer);
        id
    }

    /// インターバルを設定
    pub fn set_interval(&mut self, callback_addr: usize, interval_ms: u64, current_tick: u64) -> usize {
        let id = self.next_timer_id;
        self.next_timer_id += 1;

        let timer = TimerInfo {
            id,
            callback_addr,
            execute_at: current_tick + interval_ms,
            interval: Some(interval_ms),
        };

        self.timers.insert(id, timer);
        id
    }

    /// タイマーをクリア
    pub fn clear_timer(&mut self, id: usize) {
        self.timers.remove(&id);
    }

    /// タイマーを処理
    pub fn process_timers(&mut self, current_tick: u64) -> ScriptResult<()> {
        let mut to_execute = Vec::new();
        let mut to_reschedule = Vec::new();

        for (&id, timer) in &self.timers {
            if current_tick >= timer.execute_at {
                to_execute.push(timer.callback_addr);
                if let Some(interval) = timer.interval {
                    to_reschedule.push((id, timer.execute_at + interval));
                }
            }
        }

        // 一回限りのタイマーを削除
        for addr in &to_execute {
            let mut ids_to_remove = Vec::new();
            for (&id, timer) in &self.timers {
                if timer.callback_addr == *addr && timer.interval.is_none() {
                    ids_to_remove.push(id);
                }
            }
            for id in ids_to_remove {
                self.timers.remove(&id);
            }
        }

        // インターバルを再スケジュール
        for (id, new_time) in to_reschedule {
            if let Some(timer) = self.timers.get_mut(&id) {
                timer.execute_at = new_time;
            }
        }

        // コールバックを実行
        // TODO: 実際のコールバック実行

        Ok(())
    }

    /// グローバル変数を設定
    pub fn set_global(&mut self, name: &str, value: ScriptValue) {
        self.globals.insert(String::from(name), value);
    }

    /// グローバル変数を取得
    pub fn get_global(&self, name: &str) -> Option<&ScriptValue> {
        self.globals.get(name)
    }

    /// DOMバインディングへの参照を取得
    pub fn dom(&mut self) -> &mut DomBinding {
        &mut self.dom
    }
}

impl Default for ScriptRuntime {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Compiler
// ============================================================================

/// ASTをバイトコードにコンパイルするコンパイラ
struct Compiler {
    /// 生成された命令列
    instructions: Vec<Instruction>,
    /// 定数プール
    constants: ConstantPool,
    /// 関数テーブル
    functions: BTreeMap<String, usize>,
    /// ローカル変数（スコープスタック）
    locals: Vec<BTreeMap<String, usize>>,
    /// 次のローカル変数インデックス
    next_local: usize,
}

impl Compiler {
    fn new() -> Self {
        Self {
            instructions: Vec::new(),
            constants: ConstantPool::new(),
            functions: BTreeMap::new(),
            locals: vec![BTreeMap::new()],
            next_local: 0,
        }
    }

    fn compile(&mut self, ast: &Ast) -> Result<(), ScriptError> {
        for stmt in &ast.statements {
            self.compile_statement(stmt)?;
        }
        self.emit(Instruction::Halt);
        Ok(())
    }

    fn compile_statement(&mut self, stmt: &Stmt) -> Result<(), ScriptError> {
        match stmt {
            Stmt::Let { name, value, .. } => {
                // 初期化子をコンパイル
                if let Some(init) = value {
                    self.compile_expression(init)?;
                } else {
                    let const_idx = self.constants.add(ScriptValue::Nil);
                    self.emit(Instruction::Const(const_idx));
                }

                // ローカル変数に格納
                let local_idx = self.define_local(name);
                self.emit(Instruction::StoreLocal(local_idx));
            }
            Stmt::Assign { target, value } => {
                self.compile_expression(value)?;

                match target {
                    Expr::Identifier(var_name) => {
                        if let Some(local_idx) = self.resolve_local(var_name) {
                            self.emit(Instruction::StoreLocal(local_idx));
                        } else {
                            self.emit(Instruction::StoreGlobal(var_name.clone()));
                        }
                    }
                    Expr::FieldAccess { object, field } => {
                        self.compile_expression(object)?;
                        self.emit(Instruction::SetField(field.clone()));
                    }
                    Expr::Index { object, index } => {
                        self.compile_expression(object)?;
                        self.compile_expression(index)?;
                        self.emit(Instruction::SetIndex);
                    }
                    _ => {}
                }
            }
            Stmt::Expression(expr) => {
                self.compile_expression(expr)?;
                self.emit(Instruction::Pop);
            }
            Stmt::Block(statements) => {
                self.enter_scope();
                for s in statements {
                    self.compile_statement(s)?;
                }
                self.exit_scope();
            }
            Stmt::If { condition, then_branch, else_branch } => {
                self.compile_expression(condition)?;

                let jump_if_false = self.emit(Instruction::JumpIfFalse(0));

                self.compile_statement(then_branch)?;

                if let Some(else_stmt) = else_branch {
                    let jump_over_else = self.emit(Instruction::Jump(0));
                    self.patch_jump(jump_if_false);
                    self.compile_statement(else_stmt)?;
                    self.patch_jump(jump_over_else);
                } else {
                    self.patch_jump(jump_if_false);
                }
            }
            Stmt::While { condition, body } => {
                self.emit(Instruction::LoopStart);
                let loop_start = self.instructions.len();

                self.compile_expression(condition)?;
                let exit_jump = self.emit(Instruction::JumpIfFalse(0));

                self.compile_statement(body)?;
                self.emit(Instruction::Jump(loop_start));

                self.patch_jump(exit_jump);
                self.emit(Instruction::LoopEnd);
            }
            Stmt::For { variable, iterator, body } => {
                // イテラブルをスタックにプッシュ
                self.compile_expression(iterator)?;
                self.emit(Instruction::MakeIterator);

                self.emit(Instruction::LoopStart);
                let loop_start = self.instructions.len();

                // 次の値を取得
                self.emit(Instruction::IterNext);
                let exit_jump = self.emit(Instruction::JumpIfTrue(0));

                // 変数に束縛
                let local_idx = self.define_local(variable);
                self.emit(Instruction::StoreLocal(local_idx));

                // 本体を実行
                self.compile_statement(body)?;

                self.emit(Instruction::Jump(loop_start));
                self.patch_jump(exit_jump);
                self.emit(Instruction::LoopEnd);
            }
            Stmt::Loop(body) => {
                self.emit(Instruction::LoopStart);
                let loop_start = self.instructions.len();

                self.compile_statement(body)?;

                self.emit(Instruction::Jump(loop_start));
                self.emit(Instruction::LoopEnd);
            }
            Stmt::Function { name, params, body, .. } => {
                // 関数本体へのジャンプを記録
                let func_addr = self.instructions.len() + 1;
                self.functions.insert(name.clone(), func_addr);

                // 関数本体をスキップするジャンプ
                let skip_jump = self.emit(Instruction::Jump(0));

                // 新しいスコープを開始
                self.enter_scope();

                // パラメータをローカル変数として定義
                for param in params {
                    self.define_local(&param.name);
                }

                // 本体をコンパイル
                self.compile_statement(body)?;

                // 暗黙のreturn
                let nil_idx = self.constants.add(ScriptValue::Nil);
                self.emit(Instruction::Const(nil_idx));
                self.emit(Instruction::Return);

                self.exit_scope();
                self.patch_jump(skip_jump);

                // 関数オブジェクトをグローバルに登録
                let param_names: Vec<String> = params.iter().map(|p| p.name.clone()).collect();
                let func = FunctionValue::new(name, param_names, func_addr);
                let const_idx = self.constants.add(ScriptValue::Function(func));
                self.emit(Instruction::Const(const_idx));
                self.emit(Instruction::StoreGlobal(name.clone()));
            }
            Stmt::Return(value_opt) => {
                if let Some(v) = value_opt {
                    self.compile_expression(v)?;
                } else {
                    let nil_idx = self.constants.add(ScriptValue::Nil);
                    self.emit(Instruction::Const(nil_idx));
                }
                self.emit(Instruction::Return);
            }
            Stmt::Break => {
                self.emit(Instruction::Break);
            }
            Stmt::Continue => {
                self.emit(Instruction::Continue);
            }
            Stmt::Empty => {}
            _ => {}
        }
        Ok(())
    }

    fn compile_expression(&mut self, expr: &Expr) -> Result<(), ScriptError> {
        match expr {
            Expr::Literal(lit) => {
                let value = match lit {
                    Literal::Nil => ScriptValue::Nil,
                    Literal::Bool(b) => ScriptValue::Bool(*b),
                    Literal::Integer(i) => ScriptValue::Int(*i),
                    Literal::Float(f) => ScriptValue::Float(*f),
                    Literal::String(s) => ScriptValue::String(s.clone()),
                };
                let const_idx = self.constants.add(value);
                self.emit(Instruction::Const(const_idx));
            }
            Expr::Identifier(name) => {
                if let Some(local_idx) = self.resolve_local(name) {
                    self.emit(Instruction::LoadLocal(local_idx));
                } else {
                    self.emit(Instruction::LoadGlobal(name.clone()));
                }
            }
            Expr::Unary { op, operand } => {
                self.compile_expression(operand)?;
                match op {
                    UnaryOp::Neg => self.emit(Instruction::Neg),
                    UnaryOp::Not => self.emit(Instruction::Not),
                    UnaryOp::BitNot => self.emit(Instruction::BitNot),
                };
            }
            Expr::Binary { left, op, right } => {
                self.compile_expression(left)?;
                self.compile_expression(right)?;
                match op {
                    BinaryOp::Add => self.emit(Instruction::Add),
                    BinaryOp::Sub => self.emit(Instruction::Sub),
                    BinaryOp::Mul => self.emit(Instruction::Mul),
                    BinaryOp::Div => self.emit(Instruction::Div),
                    BinaryOp::Mod => self.emit(Instruction::Mod),
                    BinaryOp::Eq => self.emit(Instruction::Eq),
                    BinaryOp::NotEq => self.emit(Instruction::Ne),
                    BinaryOp::Lt => self.emit(Instruction::Lt),
                    BinaryOp::LtEq => self.emit(Instruction::Le),
                    BinaryOp::Gt => self.emit(Instruction::Gt),
                    BinaryOp::GtEq => self.emit(Instruction::Ge),
                    BinaryOp::And => self.emit(Instruction::And),
                    BinaryOp::Or => self.emit(Instruction::Or),
                    BinaryOp::BitAnd => self.emit(Instruction::BitAnd),
                    BinaryOp::BitOr => self.emit(Instruction::BitOr),
                    BinaryOp::BitXor => self.emit(Instruction::BitXor),
                    BinaryOp::Shl => self.emit(Instruction::Shl),
                    BinaryOp::Shr => self.emit(Instruction::Shr),
                };
            }
            Expr::Call { callee, args } => {
                // 引数をプッシュ
                for arg in args {
                    self.compile_expression(arg)?;
                }
                // 関数をプッシュ
                self.compile_expression(callee)?;
                // 呼び出し
                self.emit(Instruction::Call(args.len()));
            }
            Expr::MethodCall { object, method, args } => {
                // 引数をプッシュ
                for arg in args {
                    self.compile_expression(arg)?;
                }
                // オブジェクトをプッシュ
                self.compile_expression(object)?;
                // メソッド呼び出し
                self.emit(Instruction::CallMethod(method.clone(), args.len()));
            }
            Expr::FieldAccess { object, field } => {
                self.compile_expression(object)?;
                self.emit(Instruction::GetField(field.clone()));
            }
            Expr::Index { object, index } => {
                self.compile_expression(object)?;
                self.compile_expression(index)?;
                self.emit(Instruction::GetIndex);
            }
            Expr::Array(elements) => {
                for elem in elements {
                    self.compile_expression(elem)?;
                }
                self.emit(Instruction::MakeArray(elements.len()));
            }
            Expr::StructLit { name: _, fields } => {
                for (key, value) in fields {
                    let key_const = self.constants.add(ScriptValue::String(key.clone()));
                    self.emit(Instruction::Const(key_const));
                    self.compile_expression(value)?;
                }
                self.emit(Instruction::MakeObject(fields.len()));
            }
            Expr::If { condition, then_branch, else_branch } => {
                self.compile_expression(condition)?;
                let jump_if_false = self.emit(Instruction::JumpIfFalse(0));

                self.compile_expression(then_branch)?;

                if let Some(else_expr) = else_branch {
                    let jump_over_else = self.emit(Instruction::Jump(0));
                    self.patch_jump(jump_if_false);
                    self.compile_expression(else_expr)?;
                    self.patch_jump(jump_over_else);
                } else {
                    self.patch_jump(jump_if_false);
                    let nil_idx = self.constants.add(ScriptValue::Nil);
                    self.emit(Instruction::Const(nil_idx));
                }
            }
            Expr::Block { statements, value } => {
                self.enter_scope();
                for s in statements {
                    self.compile_statement(s)?;
                }
                if let Some(val_expr) = value {
                    self.compile_expression(val_expr)?;
                } else {
                    let nil_idx = self.constants.add(ScriptValue::Nil);
                    self.emit(Instruction::Const(nil_idx));
                }
                self.exit_scope();
            }
            Expr::Closure { params, body, .. } => {
                // クロージャ本体をスキップするジャンプ
                let skip_jump = self.emit(Instruction::Jump(0));
                let closure_addr = self.instructions.len();

                self.enter_scope();

                // パラメータをローカル変数として定義
                for param in params {
                    self.define_local(&param.name);
                }

                // 本体をコンパイル
                self.compile_expression(body)?;
                self.emit(Instruction::Return);

                self.exit_scope();
                self.patch_jump(skip_jump);

                // クロージャを作成
                let capture_names: Vec<String> = Vec::new(); // TODO: キャプチャ変数の分析
                self.emit(Instruction::MakeClosure(closure_addr, capture_names));
            }
            Expr::Range { start, end, inclusive } => {
                if let Some(s) = start {
                    self.compile_expression(s)?;
                } else {
                    let zero = self.constants.add(ScriptValue::Int(0));
                    self.emit(Instruction::Const(zero));
                }

                if let Some(e) = end {
                    self.compile_expression(e)?;
                } else {
                    let max = self.constants.add(ScriptValue::Int(i64::MAX));
                    self.emit(Instruction::Const(max));
                }

                if *inclusive {
                    self.emit(Instruction::MakeRangeInclusive);
                } else {
                    self.emit(Instruction::MakeRange);
                }
            }
            Expr::Tuple(elements) => {
                for elem in elements {
                    self.compile_expression(elem)?;
                }
                self.emit(Instruction::MakeArray(elements.len()));
            }
            _ => {
                // 未対応の式はNilを返す
                let nil_idx = self.constants.add(ScriptValue::Nil);
                self.emit(Instruction::Const(nil_idx));
            }
        }
        Ok(())
    }

    fn emit(&mut self, instruction: Instruction) -> usize {
        let idx = self.instructions.len();
        self.instructions.push(instruction);
        idx
    }

    fn patch_jump(&mut self, idx: usize) {
        let target = self.instructions.len();
        match &mut self.instructions[idx] {
            Instruction::Jump(addr) => *addr = target,
            Instruction::JumpIfFalse(addr) => *addr = target,
            Instruction::JumpIfTrue(addr) => *addr = target,
            _ => {}
        }
    }

    fn enter_scope(&mut self) {
        self.locals.push(BTreeMap::new());
    }

    fn exit_scope(&mut self) {
        if let Some(scope) = self.locals.pop() {
            self.next_local = self.next_local.saturating_sub(scope.len());
        }
    }

    fn define_local(&mut self, name: &str) -> usize {
        let idx = self.next_local;
        self.next_local += 1;
        if let Some(scope) = self.locals.last_mut() {
            scope.insert(String::from(name), idx);
        }
        idx
    }

    fn resolve_local(&self, name: &str) -> Option<usize> {
        for scope in self.locals.iter().rev() {
            if let Some(&idx) = scope.get(name) {
                return Some(idx);
            }
        }
        None
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_basic() {
        let mut runtime = ScriptRuntime::new();
        let result = runtime.execute("let x = 42; x").unwrap();
        assert_eq!(result.as_int(), Some(42));
    }

    #[test]
    fn test_runtime_arithmetic() {
        let mut runtime = ScriptRuntime::new();
        let result = runtime.execute("1 + 2 * 3").unwrap();
        assert_eq!(result.as_int(), Some(7));
    }

    #[test]
    fn test_runtime_function() {
        let mut runtime = ScriptRuntime::new();
        let result = runtime.execute("
            fn add(a: i32, b: i32) -> i32 {
                a + b
            }
            add(3, 4)
        ").unwrap();
        assert_eq!(result.as_int(), Some(7));
    }
}
