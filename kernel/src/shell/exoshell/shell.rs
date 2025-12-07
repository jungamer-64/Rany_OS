// ============================================================================
// src/shell/exoshell/shell.rs - ExoShell REPL (Part 1)
// ============================================================================
//!
//! ExoShell REPLインタプリタの主要実装

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::types::*;
use super::namespaces::*;
use super::parser::*;

/// ExoShell REPLインタプリタ
pub struct ExoShell {
    /// 変数バインディング
    pub bindings: BTreeMap<String, ExoValue>,
    /// カレントディレクトリ
    pub cwd: String,
    /// コマンド履歴
    history: Vec<String>,
    /// 最後の結果
    last_result: ExoValue,
}

impl ExoShell {
    pub fn new() -> Self {
        Self {
            bindings: BTreeMap::new(),
            cwd: String::from("/"),
            history: Vec::new(),
            last_result: ExoValue::Nil,
        }
    }

    /// 式を評価（メソッドチェーン対応）- async版
    pub async fn eval(&mut self, input: &str) -> ExoValue {
        let input = input.trim();
        
        if input.is_empty() || input.starts_with('#') {
            return ExoValue::Nil;
        }

        // 履歴に追加
        self.history.push(input.to_string());

        // 代入式: let x = ...
        if input.starts_with("let ") {
            let result = self.eval_let(&input[4..]).await;
            self.last_result = result.clone();
            return result;
        }

        // ヘルプ
        if input == "help" || input == "?" {
            return self.help();
        }

        // 変数参照
        if input.starts_with('$') {
            let var_name = &input[1..];
            return self.bindings.get(var_name).cloned().unwrap_or(ExoValue::Nil);
        }

        // メソッドチェーン対応の式評価
        let result = self.eval_chain(input).await;
        self.last_result = result.clone();
        result
    }

    /// メソッドチェーンを評価（async版）
    async fn eval_chain(&mut self, input: &str) -> ExoValue {
        // トークナイズ
        let mut tokenizer = Tokenizer::new(input);
        let tokens = tokenizer.tokenize();
        
        if tokens.is_empty() {
            return self.eval_alias(input).await;
        }

        // メソッドチェーンをパース
        let mut parser = ChainParser::new(tokens);
        let calls = parser.parse();
        
        if calls.is_empty() {
            return self.eval_alias(input).await;
        }

        // 最初の呼び出しで名前空間を判定
        let first = &calls[0];
        let mut current = self.eval_namespace_method(&first.name, &calls.get(1)).await;

        // 残りのメソッドチェーンを適用
        for call in calls.iter().skip(2) {
            current = self.apply_method(current, &call.name, &call.args);
            if let ExoValue::Error(_) = current {
                break;
            }
        }

        current
    }

    /// 名前空間の最初のメソッドを評価（async版）
    async fn eval_namespace_method(&mut self, namespace: &str, method: &Option<&MethodCall>) -> ExoValue {
        let method = match method {
            Some(m) => m,
            None => return ExoValue::Error(
                ParseError::UnexpectedToken {
                    expected: "メソッド呼び出し",
                    found: format!("{}の後に何もない", namespace),
                    position: 0,
                }.to_string()
            ),
        };

        match namespace {
            "fs" => self.eval_fs_method(&method.name, &method.args).await,
            "net" => self.eval_net_method(&method.name, &method.args).await,
            "proc" => self.eval_proc_method(&method.name, &method.args),
            "cap" => self.eval_cap_method(&method.name, &method.args),
            "sys" => self.eval_sys_method(&method.name, &method.args),
            "_" => self.last_result.clone(),
            name if name.starts_with('$') => {
                self.bindings.get(&name[1..]).cloned().unwrap_or(ExoValue::Nil)
            }
            _ => self.eval_alias(&format!("{}", namespace)).await,
        }
    }

    /// fs.* メソッド（構造化版）- async版
    async fn eval_fs_method(&mut self, name: &str, args: &[ExoValue]) -> ExoValue {
        match name {
            "entries" => {
                let path = args.first()
                    .and_then(|v| match v {
                        ExoValue::String(s) => Some(s.clone()),
                        _ => None,
                    })
                    .unwrap_or_else(|| self.cwd.clone());
                FsNamespace::entries(&path).await
            }
            "read" => {
                let path = args.first()
                    .and_then(|v| match v { ExoValue::String(s) => Some(s.clone()), _ => None })
                    .unwrap_or_default();
                FsNamespace::read(&path).await
            }
            "stat" => {
                let path = args.first()
                    .and_then(|v| match v { ExoValue::String(s) => Some(s.clone()), _ => None })
                    .unwrap_or_default();
                FsNamespace::stat(&path).await
            }
            "mkdir" => {
                let path = args.first()
                    .and_then(|v| match v { ExoValue::String(s) => Some(s.clone()), _ => None })
                    .unwrap_or_default();
                FsNamespace::mkdir(&path).await
            }
            "remove" | "rm" => {
                let path = args.first()
                    .and_then(|v| match v { ExoValue::String(s) => Some(s.clone()), _ => None })
                    .unwrap_or_default();
                FsNamespace::remove(&path).await
            }
            "cd" => {
                let path = args.first()
                    .and_then(|v| match v { ExoValue::String(s) => Some(s.clone()), _ => None })
                    .unwrap_or_else(|| String::from("/"));
                self.cwd = if path.starts_with('/') {
                    path
                } else {
                    format!("{}/{}", self.cwd, path)
                };
                ExoValue::String(self.cwd.clone())
            }
            "pwd" => ExoValue::String(self.cwd.clone()),
            _ => ExoValue::Error(
                ParseError::UnknownMethod {
                    namespace: String::from("fs"),
                    method: name.to_string(),
                }.to_string() + "\n有効なメソッド: entries, read, stat, mkdir, remove, cd, pwd"
            ),
        }
    }

    /// net.* メソッド（構造化版）- async版
    async fn eval_net_method(&self, name: &str, args: &[ExoValue]) -> ExoValue {
        match name {
            "config" => NetNamespace::config(),
            "stats" => NetNamespace::stats(),
            "arp" => NetNamespace::arp_cache(),
            "ping" => {
                let ip_str = match args.first() {
                    Some(ExoValue::String(s)) => s.clone(),
                    Some(other) => return ExoValue::Error(
                        ParseError::InvalidArgumentType {
                            method: String::from("ping"),
                            expected: "文字列 (IPアドレス)",
                            found: format!("{:?}", other),
                        }.to_string()
                    ),
                    None => return ExoValue::Error(
                        ParseError::MissingArgument {
                            method: String::from("ping"),
                            argument: "IPアドレス",
                        }.to_string() + "\n使用法: net.ping(\"10.0.2.2\", 4)"
                    ),
                };
                let count = args.get(1)
                    .and_then(|v| match v { ExoValue::Int(n) => Some(*n as u16), _ => None })
                    .unwrap_or(4);
                
                let parts: Vec<&str> = ip_str.split('.').collect();
                if parts.len() != 4 {
                    return ExoValue::Error(
                        ParseError::InvalidIpAddress { value: ip_str }.to_string()
                    );
                }
                let ip: Result<Vec<u8>, _> = parts.iter().map(|p| p.parse::<u8>()).collect();
                match ip {
                    Ok(o) if o.len() == 4 => NetNamespace::ping([o[0], o[1], o[2], o[3]], count).await,
                    _ => ExoValue::Error(
                        ParseError::InvalidIpAddress { value: ip_str }.to_string()
                    ),
                }
            }
            _ => ExoValue::Error(
                ParseError::UnknownMethod {
                    namespace: String::from("net"),
                    method: name.to_string(),
                }.to_string() + "\n有効なメソッド: config, stats, arp, ping"
            ),
        }
    }

    /// proc.* メソッド（構造化版）
    fn eval_proc_method(&self, name: &str, args: &[ExoValue]) -> ExoValue {
        match name {
            "list" | "ps" => ProcNamespace::list(),
            "info" => {
                let pid = args.first()
                    .and_then(|v| match v { ExoValue::Int(n) => Some(*n as u32), _ => None })
                    .unwrap_or(0);
                ProcNamespace::info(pid)
            }
            _ => ExoValue::Error(
                ParseError::UnknownMethod {
                    namespace: String::from("proc"),
                    method: name.to_string(),
                }.to_string() + "\n有効なメソッド: list, ps, info"
            ),
        }
    }

    /// cap.* メソッド（構造化版）
    fn eval_cap_method(&self, name: &str, args: &[ExoValue]) -> ExoValue {
        match name {
            "list" => CapNamespace::list(),
            "revoke" => {
                let id = args.first()
                    .and_then(|v| match v { ExoValue::Int(n) => Some(*n as u64), _ => None })
                    .unwrap_or(0);
                CapNamespace::revoke(id)
            }
            "grant" => {
                ExoValue::Error(String::from("grant() は未実装です"))
            }
            _ => ExoValue::Error(
                ParseError::UnknownMethod {
                    namespace: String::from("cap"),
                    method: name.to_string(),
                }.to_string() + "\n有効なメソッド: list, grant, revoke"
            ),
        }
    }

    /// sys.* メソッド（構造化版）
    fn eval_sys_method(&self, name: &str, _args: &[ExoValue]) -> ExoValue {
        match name {
            "info" => SysNamespace::info(),
            "memory" | "mem" => SysNamespace::memory(),
            "time" => SysNamespace::time(),
            "monitor" => SysNamespace::monitor(),
            "dashboard" => SysNamespace::monitor_dashboard(),
            "thermal" | "temp" => SysNamespace::thermal(),
            "watchdog" | "wd" => SysNamespace::watchdog(),
            "power" => SysNamespace::power(),
            "shutdown" => SysNamespace::shutdown(),
            "reboot" => SysNamespace::reboot(),
            _ => ExoValue::Error(
                ParseError::UnknownMethod {
                    namespace: String::from("sys"),
                    method: name.to_string(),
                }.to_string() + "\n有効なメソッド: info, memory, time, monitor, dashboard, thermal, watchdog, power, shutdown, reboot"
            ),
        }
    }

    /// 値に対してメソッドを適用（メソッドチェーン）
    fn apply_method(&self, target: ExoValue, method: &str, args: &[ExoValue]) -> ExoValue {
        match target {
            ExoValue::Array(list) => self.apply_array_method(list, method, args),
            ExoValue::Map(map) => self.apply_map_method(map, method, args),
            ExoValue::Bytes(bytes) => self.apply_bytes_method(bytes, method, args),
            ExoValue::String(s) => self.apply_string_method(s, method, args),
            _ => ExoValue::Error(format!("Type does not support method '{}'", method)),
        }
    }

    /// 配列に対するメソッド
    fn apply_array_method(&self, list: Vec<ExoValue>, method: &str, args: &[ExoValue]) -> ExoValue {
        match method {
            "len" | "count" => ExoValue::Int(list.len() as i64),
            "first" => list.first().cloned().unwrap_or(ExoValue::Nil),
            "last" => list.last().cloned().unwrap_or(ExoValue::Nil),
            "reverse" => ExoValue::Array(list.into_iter().rev().collect()),
            
            "take" | "head" => {
                let n = args.first()
                    .and_then(|v| match v { ExoValue::Int(n) => Some(*n as usize), _ => None })
                    .unwrap_or(10);
                ExoValue::Array(list.into_iter().take(n).collect())
            }
            
            "skip" | "tail" => {
                let n = args.first()
                    .and_then(|v| match v { ExoValue::Int(n) => Some(*n as usize), _ => None })
                    .unwrap_or(0);
                ExoValue::Array(list.into_iter().skip(n).collect())
            }
            
            "filter" | "where" => {
                let condition = args.first()
                    .and_then(|v| match v { ExoValue::String(s) => Some(s.as_str()), _ => None })
                    .unwrap_or("");
                self.filter_array(list, condition)
            }
            
            "sort" => {
                let field_arg = args.first()
                    .and_then(|v| match v { ExoValue::String(s) => Some(s.clone()), _ => None });
                let desc = args.get(1)
                    .and_then(|v| match v { ExoValue::String(s) => Some(s.as_str() == "desc"), _ => None })
                    .unwrap_or(false);
                
                self.sort_array(list, field_arg.as_deref(), desc)
            }
            
            "map" | "select" => {
                let field = args.first()
                    .and_then(|v| match v { ExoValue::String(s) => Some(s.clone()), _ => None })
                    .unwrap_or_else(|| String::from("name"));
                self.map_array(list, &field)
            }
            
            _ => ExoValue::Error(format!("Array does not have method '{}'", method)),
        }
    }

    /// 配列をフィルタリング
    fn filter_array(&self, list: Vec<ExoValue>, condition: &str) -> ExoValue {
        let condition = condition.trim();
        
        if let Some(closure) = self.parse_closure_expression(condition) {
            return self.filter_with_closure(list, &closure);
        }
        
        self.filter_with_simple_condition(list, condition)
    }
    
    /// クロージャ式をパース
    fn parse_closure_expression(&self, input: &str) -> Option<ClosureExpr> {
        let input = input.trim();
        
        if !input.starts_with('|') {
            return None;
        }
        
        let rest = &input[1..];
        let pipe_end = rest.find('|')?;
        let param = rest[..pipe_end].trim().to_string();
        let body = rest[pipe_end + 1..].trim();
        
        if let Some(and_pos) = body.find("&&") {
            let left = body[..and_pos].trim();
            let right = body[and_pos + 2..].trim();
            
            let left_expr = self.parse_closure_body(&param, left)?;
            let right_expr = self.parse_closure_body(&param, right)?;
            
            return Some(ClosureExpr {
                param,
                conditions: alloc::vec![left_expr, right_expr],
                logical_op: LogicalOp::And,
            });
        }
        
        if let Some(or_pos) = body.find("||") {
            let left = body[..or_pos].trim();
            let right = body[or_pos + 2..].trim();
            
            let left_expr = self.parse_closure_body(&param, left)?;
            let right_expr = self.parse_closure_body(&param, right)?;
            
            return Some(ClosureExpr {
                param,
                conditions: alloc::vec![left_expr, right_expr],
                logical_op: LogicalOp::Or,
            });
        }
        
        let cond = self.parse_closure_body(&param, body)?;
        Some(ClosureExpr {
            param,
            conditions: alloc::vec![cond],
            logical_op: LogicalOp::And,
        })
    }
    
    /// クロージャ本体をパース
    fn parse_closure_body(&self, param: &str, body: &str) -> Option<ClosureCondition> {
        let body = body.trim();
        
        let prefix = format!("{}.", param);
        let field_start = if body.starts_with(&prefix) {
            prefix.len()
        } else {
            0
        };
        
        let rest = &body[field_start..];
        
        let operators = [">=", "<=", "!=", "==", "=", ">", "<", "contains", "starts_with", "ends_with"];
        
        for op in &operators {
            if let Some(op_pos) = rest.find(op) {
                let field = rest[..op_pos].trim().to_string();
                let value = rest[op_pos + op.len()..].trim().trim_matches('"').trim_matches('\'').to_string();
                
                return Some(ClosureCondition {
                    field,
                    op: op.to_string(),
                    value,
                });
            }
        }
        
        None
    }
    
    /// クロージャ式でフィルタリング
    fn filter_with_closure(&self, list: Vec<ExoValue>, closure: &ClosureExpr) -> ExoValue {
        let filtered: Vec<ExoValue> = list.into_iter().filter(|item| {
            self.evaluate_closure_conditions(item, &closure.conditions, &closure.logical_op)
        }).collect();
        
        ExoValue::Array(filtered)
    }
    
    /// クロージャ条件を評価
    fn evaluate_closure_conditions(&self, item: &ExoValue, conditions: &[ClosureCondition], logical_op: &LogicalOp) -> bool {
        match logical_op {
            LogicalOp::And => conditions.iter().all(|cond| self.evaluate_single_condition(item, cond)),
            LogicalOp::Or => conditions.iter().any(|cond| self.evaluate_single_condition(item, cond)),
        }
    }
    
    /// 単一条件を評価
    fn evaluate_single_condition(&self, item: &ExoValue, cond: &ClosureCondition) -> bool {
        match item {
            ExoValue::FileEntry(entry) => {
                self.check_file_entry_condition(entry, &cond.field, &cond.op, &cond.value)
            }
            ExoValue::Process(proc) => {
                self.check_process_condition(proc, &cond.field, &cond.op, &cond.value)
            }
            ExoValue::Map(map) => {
                self.check_map_condition(map, &cond.field, &cond.op, &cond.value)
            }
            _ => true,
        }
    }
    
    /// 従来の文字列形式でフィルタリング
    fn filter_with_simple_condition(&self, list: Vec<ExoValue>, condition: &str) -> ExoValue {
        let parts: Vec<&str> = condition.split_whitespace().collect();
        
        if parts.len() < 3 {
            return ExoValue::Array(list);
        }
        
        let field = parts[0];
        let op = parts[1];
        let value = parts[2..].join(" ");
        
        let filtered: Vec<ExoValue> = list.into_iter().filter(|item| {
            match item {
                ExoValue::FileEntry(entry) => {
                    self.check_file_entry_condition(entry, field, op, &value)
                }
                ExoValue::Process(proc) => {
                    self.check_process_condition(proc, field, op, &value)
                }
                ExoValue::Map(map) => {
                    self.check_map_condition(map, field, op, &value)
                }
                _ => true,
            }
        }).collect();
        
        ExoValue::Array(filtered)
    }

    /// FileEntryの条件チェック
    fn check_file_entry_condition(&self, entry: &FileEntry, field: &str, op: &str, value: &str) -> bool {
        match field {
            "size" => {
                let entry_val = entry.size as i64;
                let cmp_val = value.parse::<i64>().unwrap_or(0);
                self.compare_numbers(entry_val, op, cmp_val)
            }
            "name" => {
                self.compare_strings(&entry.name, op, value)
            }
            "type" => {
                let type_str = format!("{:?}", entry.file_type);
                self.compare_strings(&type_str, op, value)
            }
            "owner" => {
                self.compare_strings(&entry.owner, op, value)
            }
            _ => true,
        }
    }

    /// ProcessInfoの条件チェック
    fn check_process_condition(&self, proc: &ProcessInfo, field: &str, op: &str, value: &str) -> bool {
        match field {
            "pid" => {
                let cmp_val = value.parse::<u32>().unwrap_or(0);
                self.compare_numbers(proc.pid as i64, op, cmp_val as i64)
            }
            "name" => {
                self.compare_strings(&proc.name, op, value)
            }
            "cpu" => {
                let cmp_val = value.parse::<f32>().unwrap_or(0.0);
                match op {
                    ">" => proc.cpu_usage > cmp_val,
                    ">=" => proc.cpu_usage >= cmp_val,
                    "<" => proc.cpu_usage < cmp_val,
                    "<=" => proc.cpu_usage <= cmp_val,
                    "==" | "=" => (proc.cpu_usage - cmp_val).abs() < 0.01,
                    _ => true,
                }
            }
            "memory" => {
                let cmp_val = value.parse::<u64>().unwrap_or(0);
                self.compare_numbers(proc.memory_kb as i64, op, cmp_val as i64)
            }
            _ => true,
        }
    }

    /// Mapの条件チェック
    fn check_map_condition(&self, map: &BTreeMap<String, ExoValue>, field: &str, op: &str, value: &str) -> bool {
        if let Some(field_val) = map.get(field) {
            match field_val {
                ExoValue::Int(n) => {
                    let cmp_val = value.parse::<i64>().unwrap_or(0);
                    self.compare_numbers(*n, op, cmp_val)
                }
                ExoValue::String(s) => {
                    self.compare_strings(s, op, value)
                }
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
    fn map_array(&self, list: Vec<ExoValue>, field_or_closure: &str) -> ExoValue {
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
    fn map_array_simple(&self, list: Vec<ExoValue>, field: &str) -> ExoValue {
        let mapped: Vec<ExoValue> = list.into_iter().map(|item| {
            match item {
                ExoValue::FileEntry(entry) => {
                    match field {
                        "name" => ExoValue::String(entry.name),
                        "size" => ExoValue::Int(entry.size as i64),
                        "path" => ExoValue::String(entry.path),
                        "type" => ExoValue::String(format!("{:?}", entry.file_type)),
                        "owner" => ExoValue::String(entry.owner),
                        _ => ExoValue::Nil,
                    }
                }
                ExoValue::Process(proc) => {
                    match field {
                        "name" => ExoValue::String(proc.name),
                        "pid" => ExoValue::Int(proc.pid as i64),
                        "cpu" => ExoValue::Float(proc.cpu_usage as f64),
                        "memory" => ExoValue::Int(proc.memory_kb as i64),
                        _ => ExoValue::Nil,
                    }
                }
                ExoValue::Map(map) => {
                    map.get(field).cloned().unwrap_or(ExoValue::Nil)
                }
                _ => item,
            }
        }).collect();
        
        ExoValue::Array(mapped)
    }

    /// 配列をソート
    fn sort_array(&self, mut list: Vec<ExoValue>, field_or_closure: Option<&str>, desc: bool) -> ExoValue {
        let field = match field_or_closure {
            Some(arg) => {
                let arg = arg.trim();
                if arg.starts_with('|') {
                    self.parse_map_closure(arg).unwrap_or_else(|| "name".to_string())
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
    fn compare_by_field(&self, a: &ExoValue, b: &ExoValue, field: &str) -> core::cmp::Ordering {
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
    fn get_field_value(&self, value: &ExoValue, field: &str) -> ExoValue {
        match value {
            ExoValue::FileEntry(entry) => {
                match field {
                    "name" => ExoValue::String(entry.name.clone()),
                    "size" => ExoValue::Int(entry.size as i64),
                    "path" => ExoValue::String(entry.path.clone()),
                    "type" => ExoValue::String(format!("{:?}", entry.file_type)),
                    "owner" => ExoValue::String(entry.owner.clone()),
                    _ => ExoValue::Nil,
                }
            }
            ExoValue::Process(proc) => {
                match field {
                    "name" => ExoValue::String(proc.name.clone()),
                    "pid" => ExoValue::Int(proc.pid as i64),
                    "cpu" => ExoValue::Float(proc.cpu_usage as f64),
                    "memory" => ExoValue::Int(proc.memory_kb as i64),
                    _ => ExoValue::Nil,
                }
            }
            ExoValue::Map(map) => {
                map.get(field).cloned().unwrap_or(ExoValue::Nil)
            }
            ExoValue::String(s) => ExoValue::String(s.clone()),
            ExoValue::Int(i) => ExoValue::Int(*i),
            _ => ExoValue::Nil,
        }
    }

    /// マップに対するメソッド
    fn apply_map_method(&self, map: BTreeMap<String, ExoValue>, method: &str, _args: &[ExoValue]) -> ExoValue {
        match method {
            "keys" => ExoValue::Array(map.keys().map(|k| ExoValue::String(k.clone())).collect()),
            "values" => ExoValue::Array(map.values().cloned().collect()),
            "len" => ExoValue::Int(map.len() as i64),
            _ => ExoValue::Error(format!("Map does not have method '{}'", method)),
        }
    }

    /// バイト列に対するメソッド
    fn apply_bytes_method(&self, bytes: Vec<u8>, method: &str, _args: &[ExoValue]) -> ExoValue {
        match method {
            "len" => ExoValue::Int(bytes.len() as i64),
            "to_string" | "text" => {
                match core::str::from_utf8(&bytes) {
                    Ok(s) => ExoValue::String(s.to_string()),
                    Err(_) => ExoValue::Error(String::from("Invalid UTF-8")),
                }
            }
            "hex" => {
                let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                ExoValue::String(hex)
            }
            _ => ExoValue::Error(format!("Bytes does not have method '{}'", method)),
        }
    }

    /// 文字列に対するメソッド
    fn apply_string_method(&self, s: String, method: &str, args: &[ExoValue]) -> ExoValue {
        match method {
            "len" => ExoValue::Int(s.len() as i64),
            "upper" => ExoValue::String(s.to_uppercase()),
            "lower" => ExoValue::String(s.to_lowercase()),
            "trim" => ExoValue::String(s.trim().to_string()),
            "split" => {
                let sep = args.first()
                    .and_then(|v| match v { ExoValue::String(s) => Some(s.as_str()), _ => None })
                    .unwrap_or(" ");
                ExoValue::Array(s.split(sep).map(|p| ExoValue::String(p.to_string())).collect())
            }
            "contains" => {
                let needle = args.first()
                    .and_then(|v| match v { ExoValue::String(s) => Some(s.as_str()), _ => None })
                    .unwrap_or("");
                ExoValue::Bool(s.contains(needle))
            }
            _ => ExoValue::Error(format!("String does not have method '{}'", method)),
        }
    }

    /// let 式を評価（async版）
    async fn eval_let(&mut self, expr: &str) -> ExoValue {
        if let Some(eq_pos) = expr.find('=') {
            let name = expr[..eq_pos].trim().to_string();
            let value_expr = expr[eq_pos + 1..].trim();
            let value = self.eval_chain(value_expr).await;
            self.bindings.insert(name.clone(), value.clone());
            value
        } else {
            ExoValue::Error(String::from("Invalid let expression"))
        }
    }

    /// 互換性エイリアス（利便性のため）- async版
    async fn eval_alias(&mut self, cmd: &str) -> ExoValue {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() {
            return ExoValue::Nil;
        }

        match parts[0] {
            "ls" => {
                let path = parts.get(1).unwrap_or(&".");
                let p = if *path == "." { self.cwd.clone() } else { path.to_string() };
                FsNamespace::entries(&p).await
            }
            "cd" => {
                if let Some(path) = parts.get(1) {
                    self.cwd = if path.starts_with('/') {
                        path.to_string()
                    } else if *path == ".." {
                        let mut segs: Vec<&str> = self.cwd.split('/').filter(|s| !s.is_empty()).collect();
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
                ExoValue::String(self.cwd.clone())
            }
            "pwd" => ExoValue::String(self.cwd.clone()),
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
            "ping" => {
                if let Some(host) = parts.get(1) {
                    let ip_parts: Vec<&str> = host.split('.').collect();
                    if ip_parts.len() == 4 {
                        let ip: Result<Vec<u8>, _> = ip_parts.iter().map(|p| p.parse::<u8>()).collect();
                        if let Ok(octets) = ip {
                            if octets.len() == 4 {
                                return NetNamespace::ping(
                                    [octets[0], octets[1], octets[2], octets[3]],
                                    4,
                                ).await;
                            }
                        }
                    }
                    ExoValue::Error(format!("Invalid IP: {}", host))
                } else {
                    ExoValue::Error(String::from("Usage: ping <ip>"))
                }
            }
            "uname" => SysNamespace::info(),
            "free" => SysNamespace::memory(),
            "uptime" => SysNamespace::time(),
            _ => ExoValue::Error(format!(
                "Unknown: '{}'\nTry 'help' or use ExoShell syntax: fs.entries(), net.config(), etc.",
                cmd
            )),
        }
    }

    /// Display help
    pub fn help(&self) -> ExoValue {
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

  proc.* - Process/Task
    proc.list()           - List tasks
    proc.info(pid)        - Task details

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
    sys.thermal()         - Temperature/throttling status
    sys.watchdog()        - Watchdog status
    sys.power()           - Power state/CPU idle stats
    sys.shutdown()        - Request shutdown
    sys.reboot()          - Request reboot

[Method Chaining]
  fs.entries("/").filter("|e| e.size > 1024").map("|e| e.name")
  proc.list().filter("cpu > 50").sort("memory", "desc")

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
        ExoValue::String(help_text.to_string())
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

        let namespaces = ["fs", "net", "proc", "cap", "sys"];
        
        if !input.contains('.') {
            return namespaces.iter()
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
            "fs" => &["entries", "read", "stat", "mkdir", "remove", "cd", "pwd", "write"],
            "net" => &["config", "stats", "arp", "ping"],
            "proc" => &["list", "info"],
            "cap" => &["list", "grant", "revoke"],
            "sys" => &["info", "memory", "time", "monitor", "dashboard", "thermal", "watchdog", "power", "shutdown", "reboot"],
            _ => return Vec::new(),
        };

        methods.iter()
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
}
