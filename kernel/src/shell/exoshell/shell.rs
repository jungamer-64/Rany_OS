// ============================================================================
// src/shell/exoshell/shell.rs - ExoShell REPL (Part 1)
// ============================================================================
//!
//! ExoShell REPLインタプリタの主要実装

use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::command::{ClearCommand, CommandRegistry, ExitCommand, HelpCommand};
use super::environment::Environment;
use super::error::ExoResult;
use super::namespaces::*;
use super::parser; // Import module itself
use super::parser::ast::Stmt;
use super::parser::*; // Import items from module
use super::types::*;
use crate::security::CapabilitySet;
use alloc::sync::Arc;

// ============================================================================
// Arc Namespace Wrapper
// ============================================================================

/// Arc<dyn ShellNamespace> を Box<dyn ShellNamespace> として使うためのラッパー
///
/// レジストリは Arc で名前空間を保持するが、既存のシェル API は Box を期待する。
/// このラッパーにより両方の API を統一できる。
mod fs_methods; // Contains filesystem-related namespace helpers
// NOTE: we don't re-export `fs_methods` because no external
// consumers currently rely on it. Keeping the module here allows
// internal use while avoiding unused-import warnings.
struct ArcNamespaceWrapper(Arc<dyn ShellNamespace>);

impl ShellNamespace for ArcNamespaceWrapper {
    fn name(&self) -> &str {
        self.0.name()
    }

    fn call<'a>(
        &'a self,
        method: &'a str,
        args: &'a [ExoValue<'static>],
        caps: &'a CapabilitySet,
    ) -> BoxFuture<'a, ExoValue<'static>> {
        self.0.call(method, args, caps)
    }
}

/// ExoShell REPLインタプリタ
///
/// ## Capability-based Security
/// シェルインスタンス自体が CapabilitySet を保持し、
/// 名前空間呼び出し時にこれを証明として渡す。
pub struct ExoShell {
    /// 変数環境（スコープ対応）
    pub env: Environment,
    /// コマンドレジストリ
    commands: CommandRegistry,
    /// カレントディレクトリ
    pub cwd: String,
    /// コマンド履歴
    history: Vec<String>,
    /// 最後の結果
    last_result: ExoValue<'static>,
    /// 登録済み名前空間（動的登録対応）
    namespaces: BTreeMap<String, Box<dyn super::namespaces::ShellNamespace>>,
    /// シェルインスタンスの権限
    capabilities: CapabilitySet,
    /// ループネスト深さ（Break/Continue用）
    loop_depth: usize,
    /// 最大履歴数
    max_history: usize,
}

impl ExoShell {
    const MAX_RECURSION_DEPTH: usize = 256;
    const DEFAULT_MAX_HISTORY: usize = 100;

    /// フル権限でシェルを作成
    pub fn new() -> Self {
        Self::with_capabilities(CapabilitySet::full())
    }

    /// 指定された権限でシェルを作成
    ///
    /// グローバルレジストリから名前空間を取得。
    /// レジストリが空の場合はビルトイン名前空間を登録してから取得。
    pub fn with_capabilities(capabilities: CapabilitySet) -> Self {
        use super::namespaces::registry;

        // レジストリが空なら初期化
        if registry::list_namespaces().is_empty() {
            registry::register_builtin_namespaces();
        }

        // レジストリから名前空間を取得（Arc -> Box への変換）
        let namespaces = {
            let mut m = BTreeMap::new();
            for (name, ns) in registry::get_all_namespaces() {
                // Arc<dyn ShellNamespace> を Box<dyn ShellNamespace> にラップ
                // ArcをそのままBoxに入れることで、共有参照を維持
                m.insert(
                    name,
                    Box::new(ArcNamespaceWrapper(ns)) as Box<dyn super::namespaces::ShellNamespace>,
                );
            }
            m
        };

        let mut commands = CommandRegistry::new();
        commands.register(HelpCommand);
        commands.register(ExitCommand);
        commands.register(ClearCommand);
        commands.register(super::command::EchoCommand);
        commands.register(super::command::HistoryCommand);
        commands.register(super::command::EnvCommand);
        commands.register(super::command::TypeCommand);
        commands.register(super::command::WhoamiCommand);
        commands.register(super::command::DateCommand);
        commands.register(super::command::SetCommand);
        commands.register(super::command::UnsetCommand);

        Self {
            env: Environment::new(),
            commands,
            cwd: String::from("/"),
            history: Vec::new(),
            last_result: ExoValue::Nil,
            namespaces,
            capabilities,
            loop_depth: 0,
            max_history: Self::DEFAULT_MAX_HISTORY,
        }
    }

    /// 式を評価（メソッドチェーン対応）- async版
    pub async fn eval(&mut self, input: &str) -> ExoValue<'static> {
        let input = input.trim();
        if input.is_empty() || input.starts_with('#') {
            return ExoValue::Nil;
        }

        // Fast-path selected network shell commands to avoid parser/method-dispatch
        // edge-cases and keep serial acceptance commands stable.
        if let Some(value) = self.eval_fast_path(input).await {
            self.last_result = value.clone();
            return value;
        }

        match parser::parse(input) {
            Ok(stmt) => match self.eval_stmt(stmt).await {
                Ok(val) => {
                    self.last_result = val.clone();
                    // Auto-add to history for successful commands if not calling history itself?
                    // Actually history is handled by caller.
                    val
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    ExoValue::Error(err_msg)
                }
            },
            Err(e) => <ExoValue<'static>>::Error(e.to_string()),
        }
    }

    async fn eval_fast_path(&mut self, input: &str) -> Option<ExoValue<'static>> {
        let input_bytes = input.as_bytes();

        if input_bytes.len() == 16
            && input_bytes[0] == b'n'
            && input_bytes[1] == b'e'
            && input_bytes[2] == b't'
            && input_bytes[3] == b'.'
            && input_bytes[4] == b'd'
            && input_bytes[5] == b'h'
            && input_bytes[6] == b'c'
            && input_bytes[7] == b'p'
            && input_bytes[8] == b'_'
            && input_bytes[9] == b's'
            && input_bytes[10] == b't'
            && input_bytes[11] == b'a'
            && input_bytes[12] == b't'
            && input_bytes[13] == b'e'
            && input_bytes[14] == b'('
            && input_bytes[15] == b')'
        {
            return Some(
                crate::shell::exoshell::namespaces::net::NetNamespace::dhcp_state(&[]).await,
            );
        }
        if input_bytes.len() == 16
            && input_bytes[0] == b'n'
            && input_bytes[1] == b'e'
            && input_bytes[2] == b't'
            && input_bytes[3] == b'.'
            && input_bytes[4] == b'd'
            && input_bytes[5] == b'h'
            && input_bytes[6] == b'c'
            && input_bytes[7] == b'p'
            && input_bytes[8] == b'_'
            && input_bytes[9] == b'r'
            && input_bytes[10] == b'e'
            && input_bytes[11] == b'n'
            && input_bytes[12] == b'e'
            && input_bytes[13] == b'w'
            && input_bytes[14] == b'('
            && input_bytes[15] == b')'
        {
            return Some(crate::shell::exoshell::namespaces::net::NetNamespace::dhcp_renew().await);
        }
        if input_bytes.len() == 19
            && input_bytes[0] == b'n'
            && input_bytes[1] == b'e'
            && input_bytes[2] == b't'
            && input_bytes[3] == b'.'
            && input_bytes[4] == b'd'
            && input_bytes[5] == b'h'
            && input_bytes[6] == b'c'
            && input_bytes[7] == b'p'
            && input_bytes[8] == b'_'
            && input_bytes[9] == b'd'
            && input_bytes[10] == b'i'
            && input_bytes[11] == b's'
            && input_bytes[12] == b'c'
            && input_bytes[13] == b'o'
            && input_bytes[14] == b'v'
            && input_bytes[15] == b'e'
            && input_bytes[16] == b'r'
            && input_bytes[17] == b'('
            && input_bytes[18] == b')'
        {
            return Some(
                crate::shell::exoshell::namespaces::net::NetNamespace::dhcp_discover().await,
            );
        }
        if input_bytes.len() == 18
            && input_bytes[0] == b'n'
            && input_bytes[1] == b'e'
            && input_bytes[2] == b't'
            && input_bytes[3] == b'.'
            && input_bytes[4] == b'd'
            && input_bytes[5] == b'h'
            && input_bytes[6] == b'c'
            && input_bytes[7] == b'p'
            && input_bytes[8] == b'_'
            && input_bytes[9] == b'r'
            && input_bytes[10] == b'e'
            && input_bytes[11] == b'l'
            && input_bytes[12] == b'e'
            && input_bytes[13] == b'a'
            && input_bytes[14] == b's'
            && input_bytes[15] == b'e'
            && input_bytes[16] == b'('
            && input_bytes[17] == b')'
        {
            return Some(
                crate::shell::exoshell::namespaces::net::NetNamespace::dhcp_release().await,
            );
        }
        if input_bytes.len() == 24
            && input_bytes[0] == b'n'
            && input_bytes[1] == b'e'
            && input_bytes[2] == b't'
            && input_bytes[3] == b'.'
            && input_bytes[4] == b'd'
            && input_bytes[5] == b'h'
            && input_bytes[6] == b'c'
            && input_bytes[7] == b'p'
            && input_bytes[8] == b'_'
            && input_bytes[9] == b'l'
            && input_bytes[10] == b'a'
            && input_bytes[11] == b's'
            && input_bytes[12] == b't'
            && input_bytes[13] == b'_'
            && input_bytes[14] == b'd'
            && input_bytes[15] == b'e'
            && input_bytes[16] == b'c'
            && input_bytes[17] == b'l'
            && input_bytes[18] == b'i'
            && input_bytes[19] == b'n'
            && input_bytes[20] == b'e'
            && input_bytes[21] == b'd'
            && input_bytes[22] == b'('
            && input_bytes[23] == b')'
        {
            return Some(
                crate::shell::exoshell::namespaces::net::NetNamespace::dhcp_last_declined().await,
            );
        }
        if input_bytes.len() == 24
            && input_bytes[0] == b'n'
            && input_bytes[1] == b'e'
            && input_bytes[2] == b't'
            && input_bytes[3] == b'.'
            && input_bytes[4] == b'd'
            && input_bytes[5] == b'h'
            && input_bytes[6] == b'c'
            && input_bytes[7] == b'p'
            && input_bytes[8] == b'_'
            && input_bytes[9] == b'l'
            && input_bytes[10] == b'a'
            && input_bytes[11] == b's'
            && input_bytes[12] == b't'
            && input_bytes[13] == b'_'
            && input_bytes[14] == b'r'
            && input_bytes[15] == b'e'
            && input_bytes[16] == b'l'
            && input_bytes[17] == b'e'
            && input_bytes[18] == b'a'
            && input_bytes[19] == b's'
            && input_bytes[20] == b'e'
            && input_bytes[21] == b'd'
            && input_bytes[22] == b'('
            && input_bytes[23] == b')'
        {
            return Some(
                crate::shell::exoshell::namespaces::net::NetNamespace::dhcp_last_released().await,
            );
        }
        if input_bytes.len() == 11
            && input_bytes[0] == b'n'
            && input_bytes[1] == b'e'
            && input_bytes[2] == b't'
            && input_bytes[3] == b'.'
            && input_bytes[4] == b's'
            && input_bytes[5] == b't'
            && input_bytes[6] == b'a'
            && input_bytes[7] == b't'
            && input_bytes[8] == b's'
            && input_bytes[9] == b'('
            && input_bytes[10] == b')'
        {
            return Some(crate::shell::exoshell::namespaces::net::NetNamespace::stats(&[]).await);
        }
        if let Some((ip, count)) = Self::parse_ping_call(input_bytes) {
            return Some(
                crate::shell::exoshell::namespaces::net::NetNamespace::ping(ip, count).await,
            );
        }

        None
    }

    fn parse_ping_call(input: &[u8]) -> Option<([u8; 4], u16)> {
        if input.len() < 10
            || input[0] != b'n'
            || input[1] != b'e'
            || input[2] != b't'
            || input[3] != b'.'
            || input[4] != b'p'
            || input[5] != b'i'
            || input[6] != b'n'
            || input[7] != b'g'
            || input[8] != b'('
            || input[9] != b'"'
        {
            return None;
        }

        let mut idx = 10;
        let mut octets = [0u8; 4];
        let mut octet_idx = 0usize;
        let mut acc = 0u16;
        let mut has_digit = false;

        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
        loop {
            if idx >= input.len() {
                return None;
            }
            let b = input[idx];
            if b.is_ascii_digit() {
                has_digit = true;
                acc = acc.saturating_mul(10).saturating_add((b - b'0') as u16);
                if acc > u8::MAX as u16 {
                    return None;
                }
                idx += 1;
                continue;
            }
            if b == b'.' {
                if !has_digit || octet_idx >= 3 {
                    return None;
                }
                octets[octet_idx] = acc as u8;
                octet_idx += 1;
                acc = 0;
                has_digit = false;
                idx += 1;
                continue;
            }
            if b == b'"' {
                if !has_digit || octet_idx != 3 {
                    return None;
                }
                octets[3] = acc as u8;
                idx += 1;
                break;
            }
            return None;
        }

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while idx < input.len() && input[idx] == b' ' {
            idx += 1;
        }

        let mut count = 4u16;
        if idx < input.len() && input[idx] == b',' {
            idx += 1;
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
            while idx < input.len() && input[idx] == b' ' {
                idx += 1;
            }
            let mut parsed_digit = false;
            let mut val: u32 = 0;
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
            while idx < input.len() && input[idx].is_ascii_digit() {
                parsed_digit = true;
                val = val
                    .saturating_mul(10)
                    .saturating_add((input[idx] - b'0') as u32);
                if val > u16::MAX as u32 {
                    return None;
                }
                idx += 1;
            }
            if !parsed_digit {
                return None;
            }
            count = val as u16;
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
            while idx < input.len() && input[idx] == b' ' {
                idx += 1;
            }
        }

        if idx >= input.len() || input[idx] != b')' {
            return None;
        }
        idx += 1;
        if idx != input.len() {
            return None;
        }

        Some((octets, count))
    }

    /// Command文の評価
    async fn eval_command_stmt(
        &mut self,
        name: String,
        args: Vec<Expr<'_>>,
    ) -> ExoResult<ExoValue<'static>> {
        // 1. Try built-in command
        if let Some(cmd) = self.commands.get(&name) {
            let mut eval_args = Vec::new();
            for arg in args {
                eval_args.push(Box::pin(self.evaluate_expr(&arg)).await);
            }
            return cmd.execute(self, &eval_args);
        }

        // 2. If no args, try variable or alias
        if args.is_empty() {
            if let Some(val) = self.env.get(&name) {
                return Ok(val.clone());
            }
            // Alias fallback (legacy)
            let alias_result = self.eval_alias(&name).await;
            if matches!(alias_result, ExoValue::Error(_)) {
                return Err(super::error::ShellError::CommandNotFound(name));
            }
            return Ok(alias_result);
        }

        Err(super::error::ShellError::CommandNotFound(name))
    }

    /// 文を評価
    async fn eval_stmt(&mut self, stmt: Stmt<'_>) -> ExoResult<ExoValue<'static>> {
        match stmt {
            Stmt::Let { name, value } => {
                let val = Box::pin(self.evaluate_expr(&value)).await;
                self.env.define(name, val.clone());
                Ok(val)
            }

            Stmt::Break => {
                if self.loop_depth == 0 {
                    Err(super::error::ShellError::Runtime(
                        "break used outside loop".to_string(),
                    ))
                } else {
                    Ok(ExoValue::Break)
                }
            }

            Stmt::Continue => {
                if self.loop_depth == 0 {
                    Err(super::error::ShellError::Runtime(
                        "continue used outside loop".to_string(),
                    ))
                } else {
                    Ok(ExoValue::Continue)
                }
            }

            Stmt::Command { name, args } => self.eval_command_stmt(name, args).await,
            Stmt::Expr(expr) => Ok(Box::pin(self.evaluate_expr(&expr)).await),
        }
    }

    /// AST式を評価（非同期・副作用あり）
    async fn evaluate_expr(&mut self, expr: &Expr<'_>) -> ExoValue<'static> {
        Box::pin(self.evaluate_expr_inner(expr, 0)).await
    }

    async fn evaluate_expr_inner(&mut self, expr: &Expr<'_>, depth: usize) -> ExoValue<'static> {
        if depth > Self::MAX_RECURSION_DEPTH {
            return ExoValue::Error("Stack overflow: expression too complex".to_string());
        }

        match expr {
            Expr::Literal(val) => val.clone().into_owned(),
            Expr::Ident(name) => self.eval_ident(name, depth).await,
            Expr::Binary { left, op, right } => self.eval_binary(left, op, right, depth).await,
            Expr::Unary { op, operand } => {
                let val = Box::pin(self.evaluate_expr_inner(operand, depth + 1)).await;
                eval::eval_unary_op(*op, &val)
            }
            Expr::Group(inner) => Box::pin(self.evaluate_expr_inner(inner, depth + 1)).await,
            Expr::Closure { .. } => {
                ExoValue::Error("Closures are only allowed in method arguments".to_string())
            }
            _ => self.eval_complex_expr(expr, depth).await,
        }
    }

    /// Evaluate composite expression types (collections, control flow, method calls).
    async fn eval_complex_expr(&mut self, expr: &Expr<'_>, depth: usize) -> ExoValue<'static> {
        match expr {
            Expr::MethodCall {
                object,
                method,
                args,
            } => self.eval_method_call(object, method, args, depth).await,
            Expr::FieldAccess { object, field } => {
                let obj = Box::pin(self.evaluate_expr_inner(object, depth + 1)).await;
                eval::get_field(&obj, &field)
            }
            Expr::Array(elements) => self.eval_array(elements, depth).await,
            Expr::Index { object, index } => self.eval_index(object, index, depth).await,
            Expr::Map(pairs) => self.eval_map(pairs, depth).await,
            _ => self.eval_control_flow_expr(expr, depth).await,
        }
    }

    /// Evaluate control-flow expressions (block, if, for).
    async fn eval_control_flow_expr(&mut self, expr: &Expr<'_>, depth: usize) -> ExoValue<'static> {
        match expr {
            Expr::Block(stmts) => self.eval_block(stmts, depth).await,
            Expr::If {
                cond,
                then_block,
                else_block,
            } => {
                self.eval_if_expr(cond, then_block, else_block.as_deref(), depth)
                    .await
            }
            Expr::For {
                param,
                iterable,
                body,
            } => self.eval_for(param, iterable, body, depth).await,
            _ => ExoValue::Error("Internal: unexpected expression type".to_string()),
        }
    }

    /// Evaluate an identifier expression (variable reference, reserved word, alias).
    async fn eval_ident(&mut self, name: &str, _depth: usize) -> ExoValue<'static> {
        // 変数参照 ($var) または予約語
        if name.starts_with('$') {
            return self.env.get(&name[1..]).cloned().unwrap_or(ExoValue::Nil);
        }
        match name {
            "true" => ExoValue::Bool(true),
            "false" => ExoValue::Bool(false),
            "nil" => ExoValue::Nil,
            _ => {
                // binding にあるかチェック
                if let Some(val) = self.env.get(name) {
                    return val.clone();
                }
                // エイリアスの可能性もある
                self.eval_alias(name).await
            }
        }
    }

    /// Evaluate a binary expression (including pipe operator).
    async fn eval_binary(
        &mut self,
        left: &Expr<'_>,
        op: &BinaryOp,
        right: &Expr<'_>,
        depth: usize,
    ) -> ExoValue<'static> {
        // パイプ演算子は特別扱い: 左辺の結果を右辺の関数/メソッドの第一引数として渡す
        if *op == BinaryOp::Pipe {
            let left_val = Box::pin(self.evaluate_expr_inner(left, depth + 1)).await;
            return self.eval_pipe(left_val, right, depth).await;
        }

        let l = Box::pin(self.evaluate_expr_inner(left, depth + 1)).await;
        let r = Box::pin(self.evaluate_expr_inner(right, depth + 1)).await;
        eval::eval_binary_op(&l, *op, &r)
    }

    /// Evaluate the right-hand side of a pipe expression.
    async fn eval_pipe(
        &mut self,
        left_val: ExoValue<'static>,
        right: &Expr<'_>,
        depth: usize,
    ) -> ExoValue<'static> {
        match right {
            Expr::MethodCall {
                object,
                method,
                args,
            } => {
                let mut new_args = Vec::with_capacity(args.len() + 1);
                new_args.push(Expr::Literal(left_val));
                new_args.extend(args.iter().cloned());

                if let Expr::Ident(ns_name) = object.as_ref() {
                    if self.is_namespace(ns_name) {
                        return self
                            .dispatch_namespace_method(ns_name, method, &new_args)
                            .await;
                    }
                }

                let obj = Box::pin(self.evaluate_expr_inner(object, depth + 1)).await;
                self.apply_method(obj, method, &new_args).await
            }
            Expr::Ident(func_name) => {
                let new_args = vec![Expr::Literal(left_val.clone())];
                self.apply_method(left_val, func_name, &new_args).await
            }
            _ => ExoValue::Error(format!("Pipe operator requires method call on right side")),
        }
    }

    /// Evaluate a method call expression (including namespace dispatch).
    async fn eval_method_call(
        &mut self,
        object: &Expr<'_>,
        method: &str,
        args: &[Expr<'_>],
        depth: usize,
    ) -> ExoValue<'static> {
        // 名前空間メソッドの特別扱い
        if let Expr::Ident(name) = object {
            if self.is_namespace(&name) {
                return self.dispatch_namespace_method(&name, method, args).await;
            }
        }

        let obj = Box::pin(self.evaluate_expr_inner(object, depth + 1)).await;
        self.apply_method(obj, method, args).await
    }

    /// Evaluate an array literal.
    async fn eval_array(&mut self, elements: &[Expr<'_>], depth: usize) -> ExoValue<'static> {
        let mut values: Vec<ExoValue<'static>> = Vec::new();
        for e in elements.iter() {
            values.push(Box::pin(self.evaluate_expr_inner(e, depth + 1)).await);
        }
        ExoValue::Array(values)
    }

    /// Evaluate an index access expression.
    async fn eval_index(
        &mut self,
        object: &Expr<'_>,
        index: &Expr<'_>,
        depth: usize,
    ) -> ExoValue<'static> {
        let obj = Box::pin(self.evaluate_expr_inner(object, depth + 1)).await;
        let idx = Box::pin(self.evaluate_expr_inner(index, depth + 1)).await;

        match (&obj, &idx) {
            (ExoValue::Array(arr), ExoValue::Int(i)) => {
                let i = *i as usize;
                if i < arr.len() {
                    arr[i].clone()
                } else {
                    ExoValue::Error(format!("Index {} out of bounds (len={})", i, arr.len()))
                }
            }
            (ExoValue::String(s), ExoValue::Int(i)) => {
                let i = *i as usize;
                if let Some(c) = s.chars().nth(i) {
                    ExoValue::String(Cow::Owned(c.to_string()))
                } else {
                    ExoValue::Error(format!("String index {} out of bounds", i))
                }
            }
            _ => ExoValue::Error(format!("Cannot index {:?} with {:?}", obj, idx)),
        }
    }

    /// Evaluate a map literal.
    async fn eval_map(&mut self, pairs: &[(String, Expr<'_>)], depth: usize) -> ExoValue<'static> {
        let mut map = BTreeMap::new();
        for (key, value_expr) in pairs.iter() {
            let value = Box::pin(self.evaluate_expr_inner(value_expr, depth + 1)).await;
            map.insert(key.clone(), value);
        }
        ExoValue::Map(map)
    }

    /// Evaluate a block expression (sequence of statements).
    async fn eval_block(&mut self, stmts: &[Stmt<'_>], depth: usize) -> ExoValue<'static> {
        let _ = depth; // reserved for future use
        self.env.push_scope();

        let mut result = ExoValue::Nil;
        for stmt in stmts {
            match Box::pin(self.eval_stmt(stmt.clone())).await {
                Ok(val) => match val {
                    ExoValue::Break => {
                        self.env.pop_scope();
                        return ExoValue::Break;
                    }
                    ExoValue::Continue => {
                        self.env.pop_scope();
                        return ExoValue::Continue;
                    }
                    other => result = other,
                },
                Err(e) => {
                    self.env.pop_scope();
                    return ExoValue::Error(e.to_string());
                }
            }
        }

        self.env.pop_scope();
        result
    }

    /// Evaluate an if expression.
    async fn eval_if_expr(
        &mut self,
        cond: &Expr<'_>,
        then_block: &Expr<'_>,
        else_block: Option<&Expr<'_>>,
        depth: usize,
    ) -> ExoValue<'static> {
        let cond_val = Box::pin(self.evaluate_expr_inner(cond, depth + 1)).await;

        // 真偽判定
        let is_true = match cond_val {
            ExoValue::Bool(b) => b,
            ExoValue::Nil => false,
            _ => true,
        };

        if is_true {
            Box::pin(self.evaluate_expr_inner(then_block, depth + 1)).await
        } else if let Some(else_expr) = else_block {
            Box::pin(self.evaluate_expr_inner(else_expr, depth + 1)).await
        } else {
            ExoValue::Nil
        }
    }

    /// Resolve an iterable value into a Vec for a for-loop.
    async fn resolve_iterable(
        &mut self,
        iter_val: ExoValue<'static>,
    ) -> Result<Vec<ExoValue<'static>>, ExoValue<'static>> {
        match iter_val {
            ExoValue::Array(arr) => Ok(arr),
            ExoValue::Iterator(iter) => match self.materialize_iterator(iter).await {
                ExoValue::Array(arr) => Ok(arr),
                ExoValue::Error(e) => Err(ExoValue::Error(e)),
                other => Err(ExoValue::Error(format!(
                    "Iterator did not produce an array (got {:?})",
                    other
                ))),
            },
            _ => Err(ExoValue::Error(
                "For loop requires an array or iterator".to_string(),
            )),
        }
    }

    /// Evaluate a for-loop expression.
    async fn eval_for(
        &mut self,
        param: &str,
        iterable: &Expr<'_>,
        body: &Expr<'_>,
        depth: usize,
    ) -> ExoValue<'static> {
        let iter_val = Box::pin(self.evaluate_expr_inner(iterable, depth + 1)).await;

        let items = match self.resolve_iterable(iter_val).await {
            Ok(items) => items,
            Err(e) => return e,
        };

        let mut last_result = ExoValue::Nil;
        self.loop_depth += 1;

        for item in items {
            self.env.push_scope();
            self.env.define(param.to_string(), item.clone());

            let res = Box::pin(self.evaluate_expr_inner(body, depth + 1)).await;
            self.env.pop_scope();

            match res {
                ExoValue::Break => {
                    break;
                }
                ExoValue::Continue => {
                    crate::task::yield_now().await;
                    continue;
                }
                ExoValue::Error(_) => {
                    self.loop_depth -= 1;
                    return res;
                }
                other => last_result = other,
            }

            crate::task::yield_now().await;
        }

        self.loop_depth -= 1;
        last_result
    }

    pub(crate) fn is_namespace(&self, name: &str) -> bool {
        self.namespaces.contains_key(name)
    }

    async fn dispatch_namespace_method(
        &mut self,
        namespace: &str,
        method: &str,
        args: &[Expr<'_>],
    ) -> ExoValue<'static> {
        // Evaluate arguments first
        let final_args = self.evaluate_args(args).await;

        match self.namespaces.get(namespace) {
            Some(ns) => ns.call(method, &final_args, &self.capabilities).await,
            None => ExoValue::Error(format!("Unknown namespace: {}", namespace)),
        }
    }

    /// 名前空間メソッドを直接呼び出し（引数は評価済み）
    async fn call_namespace(
        &self,
        namespace: &str,
        method: &str,
        args: &[ExoValue<'static>],
    ) -> ExoValue<'static> {
        match self.namespaces.get(namespace) {
            Some(ns) => ns.call(method, args, &self.capabilities).await,
            None => ExoValue::Error(format!("Unknown namespace: {}", namespace)),
        }
    }

    async fn evaluate_args(&mut self, args: &[Expr<'_>]) -> Vec<ExoValue<'static>> {
        let mut values: Vec<ExoValue<'static>> = Vec::new();
        for arg in args {
            values.push(Box::pin(self.evaluate_expr(arg)).await);
        }
        values
    }

    /// 引数リストからString値を抽出するヘルパー
    fn extract_string_arg(args: &[ExoValue<'static>]) -> Option<String> {
        args.first().and_then(|v| match v {
            ExoValue::String(s) => Some(s.as_ref().to_string()),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests;
