use super::*;

mod iterator_impl;
impl ExoShell {

    /// fs.* メソッド（構造化版）- async版
    pub(super) async fn eval_fs_method(&mut self, name: &str, args: &[Expr<'_>]) -> ExoValue<'static> {
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
    pub(super) async fn eval_net_method(&mut self, name: &str, args: &[Expr<'_>]) -> ExoValue<'static> {
        let args = self.evaluate_args(args).await;

        match name {
            "config" => NetNamespace::config_async().await,
            "stats" => NetNamespace::stats_async().await,
            "arp" => NetNamespace::arp_cache_async().await,
            "dhcp_state" => NetNamespace::dhcp_state_async().await,
            "dhcp_renew" => NetNamespace::dhcp_renew_async().await,
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
                    + "\n有効なメソッド: config, stats, arp, ping, dhcp_state, dhcp_renew",
            ),
        }
    }

    /// domain.* メソッド（構造化版）
    pub(super) async fn eval_domain_method(&mut self, name: &str, args: &[Expr<'_>]) -> ExoValue<'static> {
        let args = self.evaluate_args(args).await;

        match name {
            "list" => DomainNamespace::list(),
            "info" => {
                let id = args
                    .first()
                    .and_then(|v| match v {
                        ExoValue::Int(n) => Some(*n as u64),
                        _ => None,
                    })
                    .unwrap_or(0);
                DomainNamespace::info(id)
            }
            "kill" => {
                let id = args
                    .first()
                    .and_then(|v| match v {
                        ExoValue::Int(n) => Some(*n as u64),
                        _ => None,
                    })
                    .unwrap_or(0);
                self.call_namespace("domain", "kill", &[ExoValue::Int(id as i64)]).await
            }
            _ => ExoValue::Error(
                ParseError::UnknownMethod {
                    namespace: String::from("domain"),
                    method: name.to_string(),
                }
                .to_string()
                    + "\n有効なメソッド: list, info, kill",
            ),
        }
    }

    /// cap.* メソッド（構造化版）
    pub(super) async fn eval_cap_method(&mut self, name: &str, args: &[Expr<'_>]) -> ExoValue<'static> {
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
    pub(super) fn eval_cap_grant(args: &[ExoValue<'static>]) -> ExoValue<'static> {
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
    pub(super) fn parse_op(s: &str) -> Option<CapOperation> {
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
    pub(super) fn parse_cap_ops(arg: Option<&ExoValue<'static>>) -> Vec<CapOperation> {
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
    pub(super) fn resolve_grant_target(args: &[ExoValue<'static>]) -> Result<String, ExoValue<'static>> {
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
    pub(super) fn parse_grant_options(args: &[ExoValue<'static>]) -> (Option<u64>, bool) {
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
    pub(super) async fn eval_sys_method(&mut self, name: &str, args: &[Expr<'_>]) -> ExoValue<'static> {
        let evaluated = self.evaluate_args(args).await;
        self.call_namespace("sys", name, &evaluated).await
    }

    /// driver.* メソッド（名前空間経由）
    pub(super) async fn eval_driver_method(&mut self, name: &str, args: &[Expr<'_>]) -> ExoValue<'static> {
        let evaluated = self.evaluate_args(args).await;
        self.call_namespace("driver", name, &evaluated).await
    }

    /// 値に対してメソッドを適用（メソッドチェーン）
    /// args は AST (未評価) のまま受け取り、メソッドに応じて評価戦略を変える
    /// 値に対してメソッドを適用（メソッドチェーン）
    /// args は AST (未評価) のまま受け取り、メソッドに応じて評価戦略を変える
    pub(super) async fn apply_method(
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
    pub(super) async fn apply_array_method(
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
    pub(super) fn apply_array_aggregate(list: Vec<ExoValue<'static>>, method: &str) -> ExoValue<'static> {
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
    pub(super) async fn apply_array_slice(
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
    pub(super) fn apply_array_predicate(
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
    pub(super) async fn apply_array_transform(
        &mut self,
        list: Vec<ExoValue<'static>>,
        method: &str,
        args: &[Expr<'_>],
    ) -> ExoValue<'static> {
        let evaluated_args = self.evaluate_args(args).await;
        match method {
            "map" | "select" => {
                let field = Self::extract_string_arg(&evaluated_args)
                    .unwrap_or_else(|| String::from("name"));
                self.map_array(list, &field)
            }
            "sort" | "order" => {
                let field = Self::extract_string_arg(&evaluated_args);
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
                let sep = Self::extract_string_arg(&evaluated_args)
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
}
