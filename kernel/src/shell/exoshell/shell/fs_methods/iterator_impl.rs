use super::*;

mod cd_eval;
impl ExoShell {

    pub(crate) async fn materialize_iterator(&mut self, iter: ExoIterator) -> ExoValue<'static> {
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
    pub(super) fn filter_array(
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
    pub(super) fn apply_map_method(
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
    pub(super) fn apply_bytes_method(
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
    pub(super) fn apply_string_method(
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
    pub(super) fn filter_with_simple_condition(
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
    pub(super) fn check_file_entry_condition(
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
    pub(super) fn check_domain_condition(
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
    pub(super) fn check_map_condition(
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
    pub(super) fn compare_numbers(&self, a: i64, op: &str, b: i64) -> bool {
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
    pub(super) fn compare_strings(&self, a: &str, op: &str, b: &str) -> bool {
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
    pub(super) fn map_array(&self, list: Vec<ExoValue<'static>>, field_or_closure: &str) -> ExoValue<'static> {
        let field_or_closure = field_or_closure.trim();

        if field_or_closure.starts_with('|') {
            if let Some(field) = self.parse_map_closure(field_or_closure) {
                return self.map_array_simple(list, &field);
            }
        }

        self.map_array_simple(list, field_or_closure)
    }

    /// mapクロージャをパース
    pub(super) fn parse_map_closure(&self, input: &str) -> Option<String> {
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
    pub(super) fn map_array_simple(&self, list: Vec<ExoValue<'static>>, field: &str) -> ExoValue<'static> {
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
    pub(super) fn sort_array(
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
    pub(super) fn compare_by_field(
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
    pub(super) fn get_field_value(&self, value: &ExoValue<'static>, field: &str) -> ExoValue<'static> {
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
    pub(crate) async fn eval_alias(&mut self, cmd: &str) -> ExoValue<'static> {
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
            "ifconfig" => NetNamespace::config_async().await,
            "arp" => NetNamespace::arp_cache_async().await,
            "ping" => self.eval_ping(&parts).await,
            "netstat" => NetNamespace::netstat_async().await,
            "route" => {
                if parts.len() > 1 {
                    Self::dispatch_namespace_command(&["net", &format!("route_{}", parts[1])], "net").await
                } else {
                    NetNamespace::routes_async().await
                }
            }
            "uname" => SysNamespace::info(),
            "free" => SysNamespace::memory(),
            "net" => Self::dispatch_namespace_command(&parts, parts[0]).await,
            "uptime" => SysNamespace::time(),
            _ => ExoValue::Error(
format!(
                "Unknown: '{}'\nTry 'help' or use ExoShell syntax: fs.entries(), net.config(), etc.",
                cmd
            )),
        }
    }
}
