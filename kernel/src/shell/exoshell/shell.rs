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

use super::namespaces::*;
use super::parser; // Import module itself
use super::parser::*; // Import items from module
use super::types::*;
use super::environment::Environment;
use super::command::{CommandRegistry, HelpCommand, ExitCommand, ClearCommand};
use super::error::ExoResult;
use super::parser::ast::Stmt;
use crate::security::CapabilitySet;
use alloc::sync::Arc;

// ============================================================================
// Arc Namespace Wrapper
// ============================================================================

/// Arc<dyn ShellNamespace> を Box<dyn ShellNamespace> として使うためのラッパー
/// 
/// レジストリは Arc で名前空間を保持するが、既存のシェル API は Box を期待する。
/// このラッパーにより両方の API を統一できる。
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
                m.insert(name, Box::new(ArcNamespaceWrapper(ns)) as Box<dyn super::namespaces::ShellNamespace>);
            }
            m
        };
        

        let mut commands = CommandRegistry::new();
        commands.register(HelpCommand);
        commands.register(ExitCommand);
        commands.register(ClearCommand);

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
                    Err(super::error::ShellError::Runtime("break used outside loop".to_string()))
                } else {
                    Ok(ExoValue::Break)
                }
            }

            Stmt::Continue => {
                if self.loop_depth == 0 {
                    Err(super::error::ShellError::Runtime("continue used outside loop".to_string()))
                } else {
                    Ok(ExoValue::Continue)
                }
            }

            Stmt::Command { name, args } => {
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
                    // If alias returns generic error, it usually means not found or failed.
                    // But eval_alias returns ExoValue.
                    // If it returns Error, we wrap it?
                    if matches!(alias_result, ExoValue::Error(_)) {
                         return Err(super::error::ShellError::CommandNotFound(name));
                    }
                    return Ok(alias_result);
                }

                Err(super::error::ShellError::CommandNotFound(name))
            }
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
            Expr::MethodCall { object, method, args } => {
                self.eval_method_call(object, method, args, depth).await
            }
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
            Expr::If { cond, then_block, else_block } => {
                self.eval_if_expr(cond, then_block, else_block.as_deref(), depth).await
            }
            Expr::For { param, iterable, body } => {
                self.eval_for(param, iterable, body, depth).await
            }
            _ => ExoValue::Error("Internal: unexpected expression type".to_string()),
        }
    }

    /// Evaluate an identifier expression (variable reference, reserved word, alias).
    async fn eval_ident(&mut self, name: &str, _depth: usize) -> ExoValue<'static> {
        // 変数参照 ($var) または予約語
        if name.starts_with('$') {
            return self
                .env
                .get(&name[1..])
                .cloned()
                .unwrap_or(ExoValue::Nil);
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
            Expr::MethodCall { object, method, args } => {
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
            _ => ExoValue::Error(format!(
                "Pipe operator requires method call on right side"
            )),
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
                    ExoValue::Error(format!(
                        "Index {} out of bounds (len={})",
                        i,
                        arr.len()
                    ))
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
    async fn eval_map(
        &mut self,
        pairs: &[(String, Expr<'_>)],
        depth: usize,
    ) -> ExoValue<'static> {
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
                ExoValue::Break => { break; }
                ExoValue::Continue => { crate::task::yield_now().await; continue; }
                ExoValue::Error(_) => { self.loop_depth -= 1; return res; }
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
        let evaluated = self.evaluate_args(args).await;

        // If FS.entries and no args were passed, default to shell cwd to preserve legacy behavior
        let mut final_args = evaluated;
        if namespace == "fs" && method == "entries" && final_args.is_empty() {
            final_args.push(ExoValue::String(Cow::Owned(self.cwd.clone())));
        }

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

    /// fs.* メソッド（構造化版）- async版
    async fn eval_fs_method(&mut self, name: &str, args: &[Expr<'_>]) -> ExoValue<'static> {
        let args = self.evaluate_args(args).await;

        match name {
            "entries" => {
                let path = Self::extract_string_arg(&args)
                    .unwrap_or_else(|| self.cwd.clone());
                FsNamespace::entries(&path).await
            }
            "read" => {
                let path = Self::extract_string_arg(&args).unwrap_or_default();
                FsNamespace::read(&path).await
            }
            "stat" => {
                let path = Self::extract_string_arg(&args).unwrap_or_default();
                FsNamespace::stat(&path).await
            }
            "mkdir" => {
                let path = Self::extract_string_arg(&args).unwrap_or_default();
                FsNamespace::mkdir(&path).await
            }
            "remove" | "rm" => {
                let path = Self::extract_string_arg(&args).unwrap_or_default();
                FsNamespace::remove(&path).await
            }
            "cd" => {
                let path = Self::extract_string_arg(&args)
                    .unwrap_or_else(|| String::from("/"));
                self.cwd = if path.starts_with('/') {
                    path
                } else {
                    format!("{}/{}", self.cwd, path)
                };
                ExoValue::String(Cow::Owned(self.cwd.clone()))
            }
            "pwd" => ExoValue::String(Cow::Owned(self.cwd.clone())),
            _ => ExoValue::Error(
                ParseError::UnknownMethod {
                    namespace: String::from("fs"),
                    method: name.to_string(),
                }
                .to_string()
                    + "\n有効なメソッド: entries, read, stat, mkdir, remove, cd, pwd",
            ),
        }
    }

    /// net.* メソッド（構造化版）- async版
    async fn eval_net_method(&mut self, name: &str, args: &[Expr<'_>]) -> ExoValue<'static> {
        let args = self.evaluate_args(args).await;

        match name {
            "config" => NetNamespace::config(),
            "stats" => NetNamespace::stats(),
            "arp" => NetNamespace::arp_cache(),
            "ping" => {
                let ip_str = match args.first() {
                    Some(ExoValue::String(s)) => s.as_ref().to_string(),
                    Some(other) => {
                        return ExoValue::Error(
                            ParseError::InvalidArgumentType {
                                method: String::from("ping"),
                                expected: "文字列 (IPアドレス)",
                                found: format!("{:?}", other),
                            }
                            .to_string(),
                        );
                    }
                    None => {
                        return ExoValue::Error(
                            ParseError::MissingArgument {
                                method: String::from("ping"),
                                argument: "IPアドレス",
                            }
                            .to_string()
                                + "\n使用法: net.ping(\"10.0.2.2\", 4)",
                        );
                    }
                };
                let count = args
                    .get(1)
                    .and_then(|v| match v {
                        ExoValue::Int(n) => Some(*n as u16),
                        _ => None,
                    })
                    .unwrap_or(4);

                let parts: Vec<&str> = ip_str.split('.').collect();
                if parts.len() != 4 {
                    return ExoValue::Error(
                        ParseError::InvalidIpAddress { value: ip_str }.to_string(),
                    );
                }
                let ip: Result<Vec<u8>, _> = parts.iter().map(|p| p.parse::<u8>()).collect();
                match ip {
                    Ok(o) if o.len() == 4 => {
                        NetNamespace::ping([o[0], o[1], o[2], o[3]], count).await
                    }
                    _ => {
                        ExoValue::Error(ParseError::InvalidIpAddress { value: ip_str }.to_string())
                    }
                }
            }
            _ => ExoValue::Error(
                ParseError::UnknownMethod {
                    namespace: String::from("net"),
                    method: name.to_string(),
                }
                .to_string()
                    + "\n有効なメソッド: config, stats, arp, ping",
            ),
        }
    }

    /// proc.* メソッド（構造化版）
    async fn eval_proc_method(&mut self, name: &str, args: &[Expr<'_>]) -> ExoValue<'static> {
        let args = self.evaluate_args(args).await;

        match name {
            "list" | "ps" => ProcNamespace::list(),
            "info" => {
                let id = args
                    .first()
                    .and_then(|v| match v {
                        ExoValue::Int(n) => Some(*n as u64),
                        _ => None,
                    })
                    .unwrap_or(0);
                ProcNamespace::info(id)
            }
            _ => ExoValue::Error(
                ParseError::UnknownMethod {
                    namespace: String::from("proc"),
                    method: name.to_string(),
                }
                .to_string()
                    + "\n有効なメソッド: list, ps, info",
            ),
        }
    }

    /// cap.* メソッド（構造化版）
    async fn eval_cap_method(&mut self, name: &str, args: &[Expr<'_>]) -> ExoValue<'static> {
        let args = self.evaluate_args(args).await;

        match name {
            "list" => CapNamespace::list(),
            "revoke" => {
                let id = args
                    .first()
                    .and_then(|v| match v {
                        ExoValue::Int(n) => Some(*n as u64),
                        _ => None,
                    })
                    .unwrap_or(0);
                CapNamespace::revoke(id)
            }
            "grant" => Self::eval_cap_grant(&args),
            "tokens" => {
                // Optional domain id as first arg
                let domain = args
                    .first()
                    .and_then(|v| match v {
                        ExoValue::Int(n) => Some(*n as u64),
                        ExoValue::String(s) => s.parse().ok(),
                        _ => None,
                    });
                CapNamespace::tokens(domain)
            },
            _ => ExoValue::Error(
                ParseError::UnknownMethod {
                    namespace: String::from("cap"),
                    method: name.to_string(),
                }
                .to_string()
                    + "\n有効なメソッド: list, tokens, grant, revoke",
            ),
        }
    }

    /// cap.grant の引数を解析して実行する
    fn eval_cap_grant(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        // grant(resource, [ops], target, [expires], [delegatable])
        let resource = args
            .get(0)
            .and_then(|v| match v {
                ExoValue::String(s) => Some(s.as_ref()),
                _ => None,
            })
            .unwrap_or("");
        if resource.is_empty() {
            return ExoValue::Error(String::from(
                "grant(resource, [ops], target) requires a resource string",
            ));
        }

        let ops = Self::parse_cap_ops(args.get(1));

        // Determine target: either args[2] or args[1] if ops omitted
        let target = match Self::resolve_grant_target(args) {
            Ok(t) => t,
            Err(e) => return e,
        };

        // Parse optional arguments after target
        let (expires, delegatable) = Self::parse_grant_options(args);

        CapNamespace::grant(resource, &ops, target.as_str(), expires, delegatable)
    }

    /// 操作文字列をCapOperationに変換する
    fn parse_op(s: &str) -> Option<CapOperation> {
        match s.to_lowercase().as_str() {
            "read" => Some(CapOperation::Read),
            "write" => Some(CapOperation::Write),
            "execute" => Some(CapOperation::Execute),
            "delete" => Some(CapOperation::Delete),
            "grant" => Some(CapOperation::Grant),
            "revoke" => Some(CapOperation::Revoke),
            "create" => Some(CapOperation::Create),
            "list" => Some(CapOperation::List),
            _ => None,
        }
    }

    /// 引数からCapOperation配列を抽出する
    fn parse_cap_ops(arg: Option<&ExoValue<'static>>) -> Vec<CapOperation> {
        let mut ops = Vec::new();
        if let Some(v) = arg {
            match v {
                ExoValue::Array(arr) => {
                    for item in arr {
                        if let ExoValue::String(s) = item {
                            if let Some(op) = Self::parse_op(s.as_ref()) {
                                ops.push(op);
                            }
                        }
                    }
                }
                ExoValue::String(s) => {
                    if let Some(op) = Self::parse_op(s.as_ref()) {
                        ops.push(op);
                    }
                }
                _ => {}
            }
        }
        ops
    }

    /// grant対象のターゲットを解決する
    fn resolve_grant_target(args: &[ExoValue<'static>]) -> Result<String, ExoValue<'static>> {
        let target_arg = if args.len() >= 3 {
            args.get(2)
        } else if args.len() == 2 {
            match args.get(1) {
                Some(ExoValue::String(_)) | Some(ExoValue::Int(_)) => args.get(1),
                _ => None,
            }
        } else {
            None
        };

        match target_arg {
            Some(ExoValue::Int(n)) => Ok(n.to_string()),
            Some(ExoValue::String(s)) => Ok(s.to_string()),
            _ => Err(ExoValue::Error(String::from(
                "grant requires target domain id as second or third argument",
            ))),
        }
    }

    /// grantのオプション引数（expires, delegatable）を解析する
    fn parse_grant_options(args: &[ExoValue<'static>]) -> (Option<u64>, bool) {
        let mut expires: Option<u64> = None;
        let mut delegatable: bool = false;

        if args.len() > 3 {
            if let Some(v) = args.get(3) {
                match v {
                    ExoValue::Int(n) => expires = Some(*n as u64),
                    ExoValue::Bool(b) => delegatable = *b,
                    ExoValue::Map(map) => {
                        if let Some(ExoValue::Int(n)) = map.get("expires") {
                            expires = Some(*n as u64);
                        }
                        if let Some(ExoValue::Bool(b)) = map.get("delegatable") {
                            delegatable = *b;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Also accept delegatable as 4th argument if present
        if args.len() > 4 {
            if let Some(ExoValue::Bool(b)) = args.get(4) {
                delegatable = *b;
            }
        }

        (expires, delegatable)
    }

    /// sys.* メソッド（名前空間経由）
    async fn eval_sys_method(&mut self, name: &str, args: &[Expr<'_>]) -> ExoValue<'static> {
        let evaluated = self.evaluate_args(args).await;
        self.call_namespace("sys", name, &evaluated).await
    }

    /// driver.* メソッド（名前空間経由）
    async fn eval_driver_method(&mut self, name: &str, args: &[Expr<'_>]) -> ExoValue<'static> {
        let evaluated = self.evaluate_args(args).await;
        self.call_namespace("driver", name, &evaluated).await
    }

    /// 値に対してメソッドを適用（メソッドチェーン）
    /// args は AST (未評価) のまま受け取り、メソッドに応じて評価戦略を変える
    /// 値に対してメソッドを適用（メソッドチェーン）
    /// args は AST (未評価) のまま受け取り、メソッドに応じて評価戦略を変える
    async fn apply_method(
        &mut self,
        target: ExoValue<'static>,
        method: &str,
        args: &[Expr<'_>],
    ) -> ExoValue<'static> {
        match target {
            ExoValue::Array(list) => self.apply_array_method(list, method, args).await,
            ExoValue::Map(map) => {
                let evaluated_args = self.evaluate_args(args).await;
                self.apply_map_method(map, method, &evaluated_args)
            }
            ExoValue::Bytes(bytes) => {
                let evaluated_args = self.evaluate_args(args).await;
                self.apply_bytes_method(bytes, method, &evaluated_args)
            }
            ExoValue::String(s) => {
                let evaluated_args = self.evaluate_args(args).await;
                self.apply_string_method(s.into_owned(), method, &evaluated_args)
            }
            ExoValue::Error(e) => ExoValue::Error(e), // エラーは伝播
            _ => ExoValue::Error(format!(
                "Method '{}' not supported on type {:?}",
                method, target
            )),
        }
    }

    /// 配列に対するメソッド
    async fn apply_array_method(
        &mut self,
        list: Vec<ExoValue<'static>>,
        method: &str,
        args: &[Expr<'_>],
    ) -> ExoValue<'static> {
        match method {
            "len" | "count" => ExoValue::Int(list.len() as i64),
            "first" | "head" => list.first().cloned().unwrap_or(ExoValue::Nil),
            "last" | "tail" => list.last().cloned().unwrap_or(ExoValue::Nil),
            "reverse" => ExoValue::Array(list.into_iter().rev().collect()),
            "sum" | "avg" | "average" | "min" | "max" => {
                Self::apply_array_aggregate(list, method)
            }
            "take" | "limit" | "skip" | "offset" => {
                self.apply_array_slice(list, method, args).await
            }
            "filter" | "where" | "find" | "any" | "all" => {
                Self::apply_array_predicate(list, method, args)
            }
            "map" | "select" | "sort" | "order" | "join" | "contains" => {
                self.apply_array_transform(list, method, args).await
            }
            "flatten" => {
                let mut result = Vec::new();
                for item in list {
                    match item {
                        ExoValue::Array(inner) => result.extend(inner),
                        other => result.push(other),
                    }
                }
                ExoValue::Array(result)
            }
            _ => ExoValue::Error(format!(
                "Array does not have method '{}'\nValid methods: len, first, last, reverse, take, skip, filter, map, sort, sum, avg, min, max, join, find, any, all, contains, flatten",
                method
            )),
        }
    }

    /// 配列の集約メソッド（sum, avg, min, max）
    fn apply_array_aggregate(list: Vec<ExoValue<'static>>, method: &str) -> ExoValue<'static> {
        match method {
            "sum" => {
                let sum: i64 = list
                    .iter()
                    .filter_map(|v| match v {
                        ExoValue::Int(n) => Some(*n),
                        ExoValue::Float(f) => Some(*f as i64),
                        _ => None,
                    })
                    .sum();
                ExoValue::Int(sum)
            }
            "avg" | "average" => {
                let nums: Vec<f64> = list
                    .iter()
                    .filter_map(|v| match v {
                        ExoValue::Int(n) => Some(*n as f64),
                        ExoValue::Float(f) => Some(*f),
                        _ => None,
                    })
                    .collect();
                if nums.is_empty() {
                    ExoValue::Nil
                } else {
                    ExoValue::Float(nums.iter().sum::<f64>() / nums.len() as f64)
                }
            }
            "min" => list
                .iter()
                .filter_map(|v| match v {
                    ExoValue::Int(n) => Some(*n),
                    _ => None,
                })
                .min()
                .map(ExoValue::Int)
                .unwrap_or(ExoValue::Nil),
            "max" => list
                .iter()
                .filter_map(|v| match v {
                    ExoValue::Int(n) => Some(*n),
                    _ => None,
                })
                .max()
                .map(ExoValue::Int)
                .unwrap_or(ExoValue::Nil),
            _ => ExoValue::Nil,
        }
    }

    /// 配列のスライスメソッド（take, skip）
    async fn apply_array_slice(
        &mut self,
        list: Vec<ExoValue<'static>>,
        method: &str,
        args: &[Expr<'_>],
    ) -> ExoValue<'static> {
        let args = self.evaluate_args(args).await;
        let n = args
            .first()
            .and_then(|v| match v {
                ExoValue::Int(n) => Some(*n as usize),
                _ => None,
            });
        match method {
            "take" | "limit" => {
                ExoValue::Array(list.into_iter().take(n.unwrap_or(10)).collect())
            }
            "skip" | "offset" => {
                ExoValue::Array(list.into_iter().skip(n.unwrap_or(0)).collect())
            }
            _ => ExoValue::Nil,
        }
    }

    /// 配列の述語メソッド（filter, find, any, all）
    fn apply_array_predicate(
        list: Vec<ExoValue<'static>>,
        method: &str,
        args: &[Expr<'_>],
    ) -> ExoValue<'static> {
        let condition_expr = match args.first() {
            Some(e) => e,
            None => {
                return ExoValue::Error(format!("{} requires a condition argument", method));
            }
        };
        match method {
            "filter" | "where" => {
                let filtered: Vec<_> = list
                    .into_iter()
                    .filter(|item| eval_closure_as_bool(condition_expr, item))
                    .collect();
                ExoValue::Array(filtered)
            }
            "find" => list
                .into_iter()
                .find(|item| eval_closure_as_bool(condition_expr, item))
                .unwrap_or(ExoValue::Nil),
            "any" => ExoValue::Bool(
                list.iter()
                    .any(|item| eval_closure_as_bool(condition_expr, item)),
            ),
            "all" => ExoValue::Bool(
                list.iter()
                    .all(|item| eval_closure_as_bool(condition_expr, item)),
            ),
            _ => ExoValue::Nil,
        }
    }

    /// 配列の変換メソッド（map, sort, join, contains）
    async fn apply_array_transform(
        &mut self,
        list: Vec<ExoValue<'static>>,
        method: &str,
        args: &[Expr<'_>],
    ) -> ExoValue<'static> {
        let evaluated_args = self.evaluate_args(args).await;
        match method {
            "map" | "select" => {
                let field = evaluated_args
                    .first()
                    .and_then(|v| match v {
                        ExoValue::String(s) => Some(s.as_ref().to_string()),
                        _ => None,
                    })
                    .unwrap_or_else(|| String::from("name"));
                self.map_array(list, &field)
            }
            "sort" | "order" => {
                let field = evaluated_args.first().and_then(|v| match v {
                    ExoValue::String(s) => Some(s.as_ref().to_string()),
                    _ => None,
                });
                let desc = evaluated_args
                    .get(1)
                    .and_then(|v| match v {
                        ExoValue::String(s) => Some(s.as_ref() == "desc"),
                        _ => None,
                    })
                    .unwrap_or(false);
                self.sort_array(list, field.as_deref(), desc)
            }
            "join" => {
                let sep = evaluated_args
                    .first()
                    .and_then(|v| match v {
                        ExoValue::String(s) => Some(s.as_ref().to_string()),
                        _ => None,
                    })
                    .unwrap_or_else(|| String::from(", "));
                let joined: String = list
                    .iter()
                    .map(|v| format!("{}", v))
                    .collect::<Vec<_>>()
                    .join(&sep);
                ExoValue::String(Cow::Owned(joined))
            }
            "contains" => {
                let target = evaluated_args.first();
                let found = match target {
                    Some(v) => list.iter().any(|item| item == v),
                    None => false,
                };
                ExoValue::Bool(found)
            }
            _ => ExoValue::Nil,
        }
    }

    async fn materialize_iterator(&mut self, iter: ExoIterator) -> ExoValue<'static> {
        let source_expr = match parser::expr_parser::parse_expression(iter.source.as_str()) {
            Ok(expr) => expr,
            Err(err) => {
                return ExoValue::Error(format!("Iterator source parse error: {err}"));
            }
        };

        let source_val = Box::pin(self.evaluate_expr_inner(&source_expr, 0)).await;
        let mut items = match source_val {
            ExoValue::Array(arr) => arr,
            ExoValue::Nil => Vec::new(),
            other => {
                return ExoValue::Error(format!(
                    "Iterator source did not evaluate to an array (got {:?})",
                    other
                ))
            }
        };

        for filter in iter.filters {
            let expr = match parser::expr_parser::parse_expression(filter.as_str()) {
                Ok(expr) => expr,
                Err(err) => {
                    return ExoValue::Error(format!("Iterator filter parse error: {err}"));
                }
            };
            items = items
                .into_iter()
                .filter(|item| eval_closure_as_bool(&expr, item))
                .collect();
        }

        for transform in iter.transforms {
            let expr = match parser::expr_parser::parse_expression(transform.as_str()) {
                Ok(expr) => expr,
                Err(err) => {
                    return ExoValue::Error(format!("Iterator transform parse error: {err}"));
                }
            };
            items = items
                .iter()
                .map(|item| parser::eval::eval_closure(&expr, item).into_owned())
                .collect();
        }

        if let Some(limit) = iter.limit {
            items.truncate(limit);
        }

        ExoValue::Array(items)
    }

    /// 配列をフィルタリング (AST版)
    fn filter_array(
        &self,
        list: Vec<ExoValue<'static>>,
        condition: &Expr<'_>,
    ) -> ExoValue<'static> {
        // 文字列リテラルの場合はレガシーモード
        if let Expr::Literal(ExoValue::String(s)) = condition {
            return self.filter_with_simple_condition(list, s.as_ref());
        }

        let filtered: Vec<ExoValue<'static>> = list
            .into_iter()
            .filter(|item| eval_closure_as_bool(condition, item))
            .collect();
        ExoValue::Array(filtered)
    }

    /// Map に対するメソッド
    fn apply_map_method(
        &self,
        map: BTreeMap<String, ExoValue<'static>>,
        method: &str,
        args: &[ExoValue<'static>],
    ) -> ExoValue<'static> {
        // ShellProxy handling
        if let Some(ExoValue::String(t)) = map.get("__proxy_type") {
            if t.as_ref() == "shell_proxy" {
                return crate::shell::exoshell::namespaces::shell::ShellControlNamespace::proxy_dispatch(map, method, args);
            }
        }

        match method {
            "get" => {
                let empty = String::new();
                let key = args
                    .first()
                    .and_then(|v| match v {
                        ExoValue::String(s) => Some(s.as_ref()),
                        _ => None,
                    })
                    .unwrap_or(&empty);
                map.get(key).cloned().unwrap_or(ExoValue::Nil)
            }
            "keys" => {
                let keys: Vec<ExoValue<'static>> = map
                    .keys()
                    .map(|k| ExoValue::String(Cow::Owned(k.clone())))
                    .collect();
                ExoValue::Array(keys)
            }
            "len" | "size" => ExoValue::Int(map.len() as i64),
            _ => ExoValue::Error(format!("Map does not have method '{}'", method)),
        }
    }

    /// Bytes に対するメソッド
    fn apply_bytes_method(
        &self,
        bytes: Cow<'static, [u8]>,
        method: &str,
        _args: &[ExoValue<'static>],
    ) -> ExoValue<'static> {
        match method {
            "len" => ExoValue::Int(bytes.len() as i64),
            "utf8" | "string" | "to_string" | "text" => {
                match String::from_utf8(bytes.into_owned()) {
                    Ok(s) => ExoValue::String(Cow::Owned(s)),
                    Err(_) => ExoValue::Error("Invalid UTF-8 sequence".to_string()),
                }
            }
            "hex" => {
                let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                ExoValue::String(Cow::Owned(hex))
            }
            _ => ExoValue::Error(format!("Bytes does not have method '{}'", method)),
        }
    }

    /// String に対するメソッド
    fn apply_string_method(
        &self,
        s: String,
        method: &str,
        args: &[ExoValue<'static>],
    ) -> ExoValue<'static> {
        match method {
            "len" | "length" => ExoValue::Int(s.len() as i64),
            "trim" => ExoValue::String(Cow::Owned(s.trim().to_string())),
            "upper" => ExoValue::String(Cow::Owned(s.to_uppercase())),
            "lower" => ExoValue::String(Cow::Owned(s.to_lowercase())),
            "lines" => {
                let lines: Vec<ExoValue<'static>> = s
                    .lines()
                    .map(|l| ExoValue::String(Cow::Owned(l.to_string())))
                    .collect();
                ExoValue::Array(lines)
            }
            "split" => {
                let empty = String::from(" ");
                let sep = args
                    .first()
                    .and_then(|v| match v {
                        ExoValue::String(s) => Some(s.as_ref()),
                        _ => None,
                    })
                    .unwrap_or(&empty);
                ExoValue::Array(
                    s.split(sep)
                        .map(|p| ExoValue::String(Cow::Owned(p.to_string())))
                        .collect(),
                )
            }
            "contains" => {
                let sub = args
                    .first()
                    .and_then(|v| match v {
                        ExoValue::String(s) => Some(s.as_ref()),
                        _ => None,
                    })
                    .unwrap_or("");
                ExoValue::Bool(s.contains(sub))
            }
            "starts_with" => {
                let sub = args
                    .first()
                    .and_then(|v| match v {
                        ExoValue::String(s) => Some(s.as_ref()),
                        _ => None,
                    })
                    .unwrap_or("");
                ExoValue::Bool(s.starts_with(sub))
            }
            _ => ExoValue::Error(format!("String method '{}' not found", method)),
        }
    }

    /// 従来の文字列形式でフィルタリング
    fn filter_with_simple_condition(
        &self,
        list: Vec<ExoValue<'static>>,
        condition: &str,
    ) -> ExoValue<'static> {
        let parts: Vec<&str> = condition.split_whitespace().collect();

        if parts.len() < 3 {
            return ExoValue::Array(list);
        }

        let field = parts[0];
        let op = parts[1];
        let value = parts[2..].join(" ");

        let filtered: Vec<ExoValue<'static>> = list
            .into_iter()
            .filter(|item| match item {
                ExoValue::FileEntry(entry) => {
                    self.check_file_entry_condition(entry, field, op, &value)
                }
                ExoValue::Domain(domain) => {
                    self.check_domain_condition(domain, field, op, &value)
                }
                ExoValue::Map(map) => self.check_map_condition(map, field, op, &value),
                _ => true,
            })
            .collect();

        ExoValue::Array(filtered)
    }

    /// FileEntryの条件チェック
    fn check_file_entry_condition(
        &self,
        entry: &FileEntry,
        field: &str,
        op: &str,
        value: &str,
    ) -> bool {
        match field {
            "size" => {
                let entry_val = entry.size as i64;
                let cmp_val = value.parse::<i64>().unwrap_or(0);
                self.compare_numbers(entry_val, op, cmp_val)
            }
            "name" => self.compare_strings(&entry.name, op, value),
            "type" => {
                let type_str = format!("{:?}", entry.file_type);
                self.compare_strings(&type_str, op, value)
            }
            "owner" => self.compare_strings(&entry.owner, op, value),
            _ => true,
        }
    }

    /// DomainInfoの条件チェック
    fn check_domain_condition(
        &self,
        domain: &DomainInfo,
        field: &str,
        op: &str,
        value: &str,
    ) -> bool {
        match field {
            "id" => {
                let cmp_val = value.parse::<u64>().unwrap_or(0);
                self.compare_numbers(domain.id as i64, op, cmp_val as i64)
            }
            "name" => self.compare_strings(&domain.name, op, value),
            "state" => {
                let state_str = format!("{:?}", domain.state);
                self.compare_strings(&state_str, op, value)
            }
            "tasks" => {
                let cmp_val = value.parse::<usize>().unwrap_or(0);
                self.compare_numbers(domain.tasks as i64, op, cmp_val as i64)
            }
            "memory" | "memory_kb" => {
                let cmp_val = value.parse::<u64>().unwrap_or(0);
                self.compare_numbers(domain.memory_kb as i64, op, cmp_val as i64)
            }
            "rrefs" => {
                let cmp_val = value.parse::<u64>().unwrap_or(0);
                self.compare_numbers(domain.rrefs as i64, op, cmp_val as i64)
            }
            "last_error" => domain
                .last_error
                .as_ref()
                .map(|e| self.compare_strings(e, op, value))
                .unwrap_or(false),
            _ => true,
        }
    }

    /// Mapの条件チェック
    fn check_map_condition(
        &self,
        map: &BTreeMap<String, ExoValue<'static>>,
        field: &str,
        op: &str,
        value: &str,
    ) -> bool {
        if let Some(field_val) = map.get(field) {
            match field_val {
                ExoValue::Int(n) => {
                    let cmp_val = value.parse::<i64>().unwrap_or(0);
                    self.compare_numbers(*n, op, cmp_val)
                }
                ExoValue::String(s) => self.compare_strings(s, op, value),
                _ => true,
            }
        } else {
            true
        }
    }

    /// 数値比較
    fn compare_numbers(&self, a: i64, op: &str, b: i64) -> bool {
        match op {
            ">" => a > b,
            ">=" => a >= b,
            "<" => a < b,
            "<=" => a <= b,
            "==" | "=" => a == b,
            "!=" => a != b,
            _ => true,
        }
    }

    /// 文字列比較
    fn compare_strings(&self, a: &str, op: &str, b: &str) -> bool {
        match op {
            "==" | "=" => a == b,
            "!=" => a != b,
            "contains" => a.contains(b),
            "starts_with" | "startswith" => a.starts_with(b),
            "ends_with" | "endswith" => a.ends_with(b),
            _ => true,
        }
    }

    /// 配列のフィールドを抽出
    fn map_array(&self, list: Vec<ExoValue<'static>>, field_or_closure: &str) -> ExoValue<'static> {
        let field_or_closure = field_or_closure.trim();

        if field_or_closure.starts_with('|') {
            if let Some(field) = self.parse_map_closure(field_or_closure) {
                return self.map_array_simple(list, &field);
            }
        }

        self.map_array_simple(list, field_or_closure)
    }

    /// mapクロージャをパース
    fn parse_map_closure(&self, input: &str) -> Option<String> {
        let input = input.trim();

        if !input.starts_with('|') {
            return None;
        }

        let rest = &input[1..];
        let pipe_end = rest.find('|')?;
        let param = rest[..pipe_end].trim();
        let body = rest[pipe_end + 1..].trim();

        let prefix = format!("{}.", param);
        if body.starts_with(&prefix) {
            Some(body[prefix.len()..].trim().to_string())
        } else {
            Some(body.to_string())
        }
    }

    /// シンプルなフィールド抽出
    fn map_array_simple(&self, list: Vec<ExoValue<'static>>, field: &str) -> ExoValue<'static> {
        let mapped: Vec<ExoValue<'static>> = list
            .into_iter()
            .map(|item| match item {
                ExoValue::FileEntry(entry) => match field {
                    "name" => ExoValue::String(Cow::Owned(entry.name)),
                    "size" => ExoValue::Int(entry.size as i64),
                    "path" => ExoValue::String(Cow::Owned(entry.path)),
                    "type" => ExoValue::String(Cow::Owned(format!("{:?}", entry.file_type))),
                    "owner" => ExoValue::String(Cow::Owned(entry.owner)),
                    _ => ExoValue::Nil,
                },
                ExoValue::Domain(domain) => match field {
                    "name" => ExoValue::String(Cow::Owned(domain.name)),
                    "id" => ExoValue::Int(domain.id as i64),
                    "state" => ExoValue::String(Cow::Owned(format!("{:?}", domain.state))),
                    "tasks" => ExoValue::Int(domain.tasks as i64),
                    "memory" | "memory_kb" => ExoValue::Int(domain.memory_kb as i64),
                    "rrefs" => ExoValue::Int(domain.rrefs as i64),
                    "last_error" => domain
                        .last_error
                        .map(|e| ExoValue::String(Cow::Owned(e)))
                        .unwrap_or(ExoValue::Nil),
                    _ => ExoValue::Nil,
                },
                ExoValue::Map(map) => map.get(field).cloned().unwrap_or(ExoValue::Nil),
                _ => item,
            })
            .collect();

        ExoValue::Array(mapped)
    }

    /// 配列をソート
    fn sort_array(
        &self,
        mut list: Vec<ExoValue<'static>>,
        field_or_closure: Option<&str>,
        desc: bool,
    ) -> ExoValue<'static> {
        let field = match field_or_closure {
            Some(arg) => {
                let arg = arg.trim();
                if arg.starts_with('|') {
                    self.parse_map_closure(arg)
                        .unwrap_or_else(|| "name".to_string())
                } else {
                    arg.to_string()
                }
            }
            None => "name".to_string(),
        };

        list.sort_by(|a, b| {
            let order = self.compare_by_field(a, b, &field);
            if desc { order.reverse() } else { order }
        });

        ExoValue::Array(list)
    }

    /// フィールドで比較
    fn compare_by_field(
        &self,
        a: &ExoValue<'static>,
        b: &ExoValue<'static>,
        field: &str,
    ) -> core::cmp::Ordering {
        use core::cmp::Ordering;

        let val_a = self.get_field_value(a, field);
        let val_b = self.get_field_value(b, field);

        match (&val_a, &val_b) {
            (ExoValue::String(s1), ExoValue::String(s2)) => s1.cmp(s2),
            (ExoValue::Int(i1), ExoValue::Int(i2)) => i1.cmp(i2),
            (ExoValue::Float(f1), ExoValue::Float(f2)) => {
                f1.partial_cmp(f2).unwrap_or(Ordering::Equal)
            }
            _ => Ordering::Equal,
        }
    }

    /// フィールド値を取得
    fn get_field_value(&self, value: &ExoValue<'static>, field: &str) -> ExoValue<'static> {
        match value {
            ExoValue::FileEntry(entry) => match field {
                "name" => ExoValue::String(Cow::Owned(entry.name.clone())),
                "size" => ExoValue::Int(entry.size as i64),
                "path" => ExoValue::String(Cow::Owned(entry.path.clone())),
                "type" => ExoValue::String(Cow::Owned(format!("{:?}", entry.file_type))),
                "owner" => ExoValue::String(Cow::Owned(entry.owner.clone())),
                _ => ExoValue::Nil,
            },
            ExoValue::Domain(domain) => match field {
                "name" => ExoValue::String(Cow::Owned(domain.name.clone())),
                "id" => ExoValue::Int(domain.id as i64),
                "state" => ExoValue::String(Cow::Owned(format!("{:?}", domain.state))),
                "tasks" => ExoValue::Int(domain.tasks as i64),
                "memory" | "memory_kb" => ExoValue::Int(domain.memory_kb as i64),
                "rrefs" => ExoValue::Int(domain.rrefs as i64),
                "last_error" => domain
                    .last_error
                    .as_ref()
                    .map(|e| ExoValue::String(Cow::Owned(e.clone())))
                    .unwrap_or(ExoValue::Nil),
                _ => ExoValue::Nil,
            },
            ExoValue::Map(map) => map.get(field).cloned().unwrap_or(ExoValue::Nil),
            ExoValue::String(s) => ExoValue::String(Cow::Owned(s.clone().into_owned())),
            ExoValue::Int(i) => ExoValue::Int(*i),
            _ => ExoValue::Nil,
        }
    }

    /// 互換性エイリアス（利便性のため）- async版
    async fn eval_alias(&mut self, cmd: &str) -> ExoValue<'static> {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() {
            return ExoValue::Nil;
        }

        match parts[0] {
            "ls" => {
                let path = parts.get(1).unwrap_or(&".");
                let p = if *path == "." {
                    self.cwd.clone()
                } else {
                    path.to_string()
                };
                FsNamespace::entries(&p).await
            }
            "cd" => self.eval_cd(&parts),
            "pwd" => ExoValue::String(Cow::Owned(self.cwd.clone())),
            "cat" => {
                if let Some(path) = parts.get(1) {
                    FsNamespace::read(path).await
                } else {
                    ExoValue::Error(String::from("Usage: cat <file>"))
                }
            }
            "mkdir" => {
                if let Some(path) = parts.get(1) {
                    FsNamespace::mkdir(path).await
                } else {
                    ExoValue::Error(String::from("Usage: mkdir <dir>"))
                }
            }
            "rm" => {
                if let Some(path) = parts.get(1) {
                    FsNamespace::remove(path).await
                } else {
                    ExoValue::Error(String::from("Usage: rm <path>"))
                }
            }
            "ps" => ProcNamespace::list(),
            "ifconfig" => NetNamespace::config(),
            "arp" => NetNamespace::arp_cache(),
            "ping" => self.eval_ping(&parts).await,
            "uname" => SysNamespace::info(),
            "free" => SysNamespace::memory(),
            "net" | "cell" => Self::dispatch_namespace_command(&parts, parts[0]),
            "uptime" => SysNamespace::time(),
            _ => ExoValue::Error(
format!(
                "Unknown: '{}'\nTry 'help' or use ExoShell syntax: fs.entries(), net.config(), etc.",
                cmd
            )),
        }
    }

    /// Evaluate `cd` path argument and update working directory.
    fn eval_cd(&mut self, parts: &[&str]) -> ExoValue<'static> {
        if let Some(path) = parts.get(1) {
            self.cwd = if path.starts_with('/') {
                path.to_string()
            } else if *path == ".." {
                let mut segs: Vec<&str> =
                    self.cwd.split('/').filter(|s| !s.is_empty()).collect();
                segs.pop();
                if segs.is_empty() {
                    String::from("/")
                } else {
                    format!("/{}", segs.join("/"))
                }
            } else {
                if self.cwd == "/" {
                    format!("/{}", path)
                } else {
                    format!("{}/{}", self.cwd, path)
                }
            };
        }
        ExoValue::String(Cow::Owned(self.cwd.clone()))
    }

    /// Evaluate `ping <ip>` command.
    async fn eval_ping(&self, parts: &[&str]) -> ExoValue<'static> {
        if let Some(host) = parts.get(1) {
            let ip_parts: Vec<&str> = host.split('.').collect();
            if ip_parts.len() == 4 {
                let ip: Result<Vec<u8>, _> =
                    ip_parts.iter().map(|p| p.parse::<u8>()).collect();
                if let Ok(octets) = ip {
                    if octets.len() == 4 {
                        return NetNamespace::ping(
                            [octets[0], octets[1], octets[2], octets[3]],
                            4,
                        )
                        .await;
                    }
                }
            }
            ExoValue::Error(format!("Invalid IP: {}", host))
        } else {
            ExoValue::Error(String::from("Usage: ping <ip>"))
        }
    }

    /// Dispatch a `net` or `cell` namespace sub-command.
    fn dispatch_namespace_command(parts: &[&str], namespace: &str) -> ExoValue<'static> {
        if let Some(method) = parts.get(1) {
            let args: Vec<ExoValue> = parts.iter().skip(2)
                .map(|s| ExoValue::String(Cow::Owned((*s).to_string())))
                .collect();
            match namespace {
                "net" => super::namespaces::net::NetNamespace::dispatch(method, &args),
                "cell" => super::namespaces::cell::CellNamespace::dispatch(method, &args),
                _ => ExoValue::String(Cow::Owned(format!("Usage: {} <method> [args...]", namespace))),
            }
        } else {
            ExoValue::String(Cow::Owned(format!("Usage: {} <method> [args...]", namespace)))
        }
    }

    /// Display help
    pub fn help(&self) -> ExoValue<'static> {
        let help_text = r#"
================================================================================
                      ExoShell - Rust-style REPL Environment
================================================================================
  Based on ExoRust design: operate on typed objects, not Unix text streams

[Namespaces and Methods]

  fs.*  - Filesystem
    fs.entries("/path")   - List directory contents
    fs.read("/path")      - Read file contents
    fs.stat("/path")      - Get file information
    fs.mkdir("/path")     - Create directory
    fs.remove("/path")    - Remove file/directory
    fs.cd("/path")        - Change current directory
    fs.pwd()              - Print working directory

  net.* - Network
    net.config()          - Show network configuration
    net.stats()           - Show TX/RX statistics
    net.arp()             - Show ARP cache
    net.ping("ip", count) - Send ICMP echo

  proc.* - Domains/Tasks
    proc.list()           - List domains
    proc.info(id)         - Domain details

  cap.* - Capability (permissions)
    cap.list()            - List current capabilities
    cap.grant(...)        - Grant permission
    cap.revoke(id)        - Revoke permission

  sys.* - System
    sys.info()            - System information
    sys.memory()          - Memory usage
    sys.time()            - Time information
    sys.monitor()         - System monitoring (CPU/Memory/Network)
    sys.dashboard()       - Monitoring dashboard
    sys.thermal()          - Temperature/throttling status
    sys.watchdog()        - Watchdog status
    sys.power()           - Power state/CPU idle stats
    sys.panic_record()    - Last panic DMA record
    sys.shutdown()        - Request shutdown
    sys.reboot()          - Request reboot

  driver.* - Driver Management
    driver.list()         - List registered drivers
    driver.stats()        - Driver statistics
    driver.status(id)     - Get driver status by ID
    driver.load(path)     - Load driver from ELF file
    driver.unload(id)     - Unload driver by ID

[Method Chaining]
  fs.entries("/").filter("|e| e.size > 1024").map("|e| e.name")
  proc.list().filter("memory > 1024").sort("tasks", "desc")

[Array Methods]
  .filter(cond)    - Filter elements
  .map(field)      - Extract field from elements
  .sort(field?)    - Sort elements (default: by name)
  .first()         - Get first element
  .last()          - Get last element
  .len()           - Get array length
  .take(n)         - Take first n elements
  .skip(n)         - Skip first n elements
  .reverse()       - Reverse order

[Variables]
  let x = fs.entries("/")   - Store result in variable
  $x                        - Reference variable
  _                         - Last result

[Aliases (Unix compatibility)]
  ls, cd, pwd, cat, mkdir, rm, ps, ifconfig, ping are also available
"#;
        ExoValue::String(Cow::Owned(help_text.to_string()))
    }

    /// カレントディレクトリを取得
    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    /// プロンプト文字列を生成
    pub fn prompt(&self) -> String {
        format!("exo:{}> ", self.cwd)
    }

    /// Tab補完候補を取得
    pub fn complete(&self, input: &str) -> Vec<String> {
        let input = input.trim();

        if input.is_empty() {
            return Vec::new();
        }

        if let Some(completions) = self.complete_filepath(input) {
            return completions;
        }

        let namespaces = ["fs", "net", "proc", "cap", "sys", "driver"];

        if !input.contains('.') {
            return namespaces
                .iter()
                .filter(|ns| ns.starts_with(input))
                .map(|ns| format!("{}.", ns))
                .collect();
        }

        let parts: Vec<&str> = input.splitn(2, '.').collect();
        if parts.len() < 2 {
            return Vec::new();
        }

        let namespace = parts[0];
        let method_prefix = parts[1];

        let methods: &[&str] = match namespace {
            "fs" => &[
                "entries", "read", "stat", "mkdir", "remove", "cd", "pwd", "write",
            ],
            "net" => &["config", "stats", "arp", "ping"],
            "proc" => &["list", "info"],
            "cap" => &["list", "grant", "revoke"],
            "sys" => &[
                "info",
                "memory",
                "time",
                "monitor",
                "dashboard",
                "thermal",
                "watchdog",
                "power",
                "panic_record",
                "shutdown",
                "reboot",
            ],
            "driver" => &["list", "stats", "status", "load", "unload"],
            _ => return Vec::new(),
        };

        methods
            .iter()
            .filter(|m| m.starts_with(method_prefix))
            .map(|m| format!("{}.{}(", namespace, m))
            .collect()
    }

    /// ファイルパス補完
    fn complete_filepath(&self, input: &str) -> Option<Vec<String>> {
        let quote_pos = input.rfind(|c| c == '"' || c == '\'')?;
        let quote_char = input.chars().nth(quote_pos)?;

        let after_quote = &input[quote_pos + 1..];
        if after_quote.contains(quote_char) {
            return None;
        }

        let path_prefix = after_quote;
        let prefix_before_quote = &input[..quote_pos + 1];

        let (dir_path, name_prefix) = if path_prefix.contains('/') {
            let last_slash = path_prefix.rfind('/').unwrap();
            if last_slash == 0 {
                ("/", &path_prefix[1..])
            } else {
                (&path_prefix[..last_slash], &path_prefix[last_slash + 1..])
            }
        } else {
            (self.cwd.as_str(), path_prefix)
        };

        let entries = match crate::fs::list_directory(dir_path, "/") {
            Ok(e) => e,
            Err(_) => return Some(Vec::new()),
        };

        let completions: Vec<String> = entries
            .iter()
            .filter(|e| e.name.starts_with(name_prefix))
            .map(|e| {
                let full_path = if dir_path == "/" {
                    format!("/{}", e.name)
                } else {
                    format!("{}/{}", dir_path, e.name)
                };

                let suffix = if e.file_type == crate::fs::FileType::Directory {
                    "/"
                } else {
                    ""
                };

                format!("{}{}{}", prefix_before_quote, full_path, suffix)
            })
            .collect();

        Some(completions)
    }

    /// 履歴にエントリを追加
    pub fn add_history(&mut self, entry: String) {
        if entry.trim().is_empty() {
            return;
        }
        // 重複排除
        if self.history.last() != Some(&entry) {
            self.history.push(entry);
            if self.history.len() > self.max_history {
                self.history.remove(0);
            }
        }
    }

    /// 履歴を取得（読み取り専用）
    pub fn history(&self) -> &[String] {
        &self.history
    }

    /// 履歴の長さを取得
    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// 履歴のエントリを取得
    pub fn history_get(&self, index: usize) -> Option<&String> {
        self.history.get(index)
    }

    /// 履歴を設定（同期用）
    pub fn set_history(&mut self, history: Vec<String>) {
        self.history = history;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell::exoshell::parser::parse_expression;
    use crate::task::block_on;
    use crate::security::CapabilitySet;

    #[test_case]
    fn test_block_scoping() {
        let mut shell = ExoShell::with_capabilities(CapabilitySet::full());
        let expr = parse_expression("{ let x = 5; x }").unwrap();
        let val = block_on(shell.evaluate_expr(&expr));
        assert_eq!(val, ExoValue::Int(5));
        // x should not be visible after block
        assert!(shell.env.get("x").is_none());
    }

    #[test_case]
    fn test_if_expression_evaluation() {
        let mut shell = ExoShell::new();
        let expr = parse_expression("if true { 1 } else { 2 }").unwrap();
        let val = crate::task::block_on(shell.evaluate_expr(&expr));
        assert_eq!(val, ExoValue::Int(1));
    }

    #[test_case]
    fn test_for_expression_evaluation() {
        let mut shell = ExoShell::new();
        let expr = parse_expression("for i in [1,2,3] { i }").unwrap();
        let val = crate::task::block_on(shell.evaluate_expr(&expr));
        assert_eq!(val, ExoValue::Int(3));
        assert!(shell.env.get("i").is_none());
    }

    #[test_case]
    fn test_else_if_chain() {
        let mut shell = ExoShell::new();
        let expr = parse_expression("if false { 1 } else if true { 2 } else { 3 }").unwrap();
        let val = crate::task::block_on(shell.evaluate_expr(&expr));
        assert_eq!(val, ExoValue::Int(2));
    }

    #[test_case]
    fn test_break_in_loop() {
        let mut shell = ExoShell::new();
        let val = crate::task::block_on(shell.eval("for i in [1,2,3] { if i == 2 { break } i }"));
        assert_eq!(val, ExoValue::Int(1));
    }

    #[test_case]
    fn test_continue_in_loop() {
        let mut shell = ExoShell::new();
        let val = crate::task::block_on(shell.eval("for i in [1,2,3] { if i == 2 { continue } i }"));
        assert_eq!(val, ExoValue::Int(3));
    }

    #[test_case]
    fn test_break_outside_loop_error() {
        let mut shell = ExoShell::new();
        let val = crate::task::block_on(shell.eval("break"));
        assert!(matches!(val, ExoValue::Error(_)));
    }
}
