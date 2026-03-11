use super::*;

mod iterator_impl;
impl ExoShell {
    /// fs.* メソッド（構造化版）- async版
    pub(super) async fn eval_fs_method(
        &mut self,
        name: &str,
        args: &[Expr<'_>],
    ) -> ExoValue<'static> {
        let args = self.evaluate_args(args).await;

        match name {
            "entries" => {
                let path = Self::extract_string_arg(&args).unwrap_or_else(|| self.cwd.clone());
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
                let path = Self::extract_string_arg(&args).unwrap_or_else(|| String::from("/"));
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
    pub(super) async fn eval_net_method(
        &mut self,
        name: &str,
        args: &[Expr<'_>],
    ) -> ExoValue<'static> {
        let args = self.evaluate_args(args).await;

        match name {
            "config" => NetNamespace::config_async(&args).await,
            "stats" => NetNamespace::stats_async(&args).await,
            "arp" => NetNamespace::arp_cache_async().await,
            "dhcp_state" => NetNamespace::dhcp_state_async(&args).await,
            "dhcp_renew" => NetNamespace::dhcp_renew_async().await,
            "dhcp_discover" => NetNamespace::dhcp_discover_async().await,
            "dhcp_release" => NetNamespace::dhcp_release_async().await,
            "dhcp_last_declined" => NetNamespace::dhcp_last_declined_async().await,
            "dhcp_last_released" => NetNamespace::dhcp_last_released_async().await,
            // TCP/UDP接続管理
            "connections" | "netstat" => NetNamespace::netstat_async().await,
            "tcp" => NetNamespace::tcp_connections_async().await,
            "udp" => NetNamespace::udp_endpoints_async().await,
            // インターフェース管理
            "interfaces" | "ifaces" => NetNamespace::interfaces_async().await,
            "if_up" => NetNamespace::if_up_async(&args).await,
            "if_down" => NetNamespace::if_down_async(&args).await,
            // ルーティング
            "routes" => NetNamespace::routes_async().await,
            "route_add" => NetNamespace::route_add_async(&args).await,
            "route_del" => NetNamespace::route_del_async(&args).await,
            // ファイアウォール
            "firewall" => NetNamespace::firewall_status_async().await,
            "firewall_enable" => NetNamespace::firewall_enable_async().await,
            "firewall_disable" => NetNamespace::firewall_disable_async().await,
            "firewall_rules" => NetNamespace::firewall_rules_async().await,
            "firewall_stats" => NetNamespace::firewall_stats_async().await,
            "firewall_add" => NetNamespace::firewall_add_async(&args).await,
            "firewall_remove" => NetNamespace::firewall_remove_async(&args).await,
            "firewall_clear" => NetNamespace::firewall_clear_async().await,
            "firewall_policy" => NetNamespace::firewall_policy_async(&args).await,
            // DNS
            "dns" | "resolve" => NetNamespace::dns_resolve_async(&args).await,
            // 診断
            "snapshot" => NetNamespace::snapshot_async().await,
            "events" => NetNamespace::events_async(&args).await,
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
                    + "\n有効なメソッド: config, stats, arp, ping, connections/netstat, tcp, udp,\n  \
                       interfaces/ifaces, if_up, if_down, routes, route_add, route_del,\n  \
                       firewall, firewall_enable, firewall_disable, firewall_rules, firewall_stats,\n  \
                       firewall_add, firewall_remove, firewall_clear, firewall_policy,\n  \
                       dns/resolve, snapshot, events,\n  \
                       dhcp_state, dhcp_renew, dhcp_discover, dhcp_release, dhcp_last_declined, dhcp_last_released",
            ),
        }
    }

    /// domain.* メソッド（構造化版）
    pub(super) async fn eval_domain_method(
        &mut self,
        name: &str,
        args: &[Expr<'_>],
    ) -> ExoValue<'static> {
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
                self.call_namespace("domain", "kill", &[ExoValue::Int(id as i64)])
                    .await
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
    pub(super) async fn eval_cap_method(
        &mut self,
        name: &str,
        args: &[Expr<'_>],
    ) -> ExoValue<'static> {
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
                let domain = args.first().and_then(|v| match v {
                    ExoValue::Int(n) => Some(*n as u64),
                    ExoValue::String(s) => s.parse().ok(),
                    _ => None,
                });
                CapNamespace::tokens(domain)
            }
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
    pub(super) fn resolve_grant_target(
        args: &[ExoValue<'static>],
    ) -> Result<String, ExoValue<'static>> {
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
    pub(super) async fn eval_sys_method(
        &mut self,
        name: &str,
        args: &[Expr<'_>],
    ) -> ExoValue<'static> {
        let evaluated = self.evaluate_args(args).await;
        self.call_namespace("sys", name, &evaluated).await
    }

    /// driver.* メソッド（名前空間経由）
    pub(super) async fn eval_driver_method(
        &mut self,
        name: &str,
        args: &[Expr<'_>],
    ) -> ExoValue<'static> {
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
            ExoValue::Int(n) => {
                let evaluated_args = self.evaluate_args(args).await;
                Self::apply_int_method(n, method, &evaluated_args)
            }
            ExoValue::Float(f) => {
                let evaluated_args = self.evaluate_args(args).await;
                Self::apply_float_method(f, method, &evaluated_args)
            }
            ExoValue::FileEntry(entry) => {
                let evaluated_args = self.evaluate_args(args).await;
                Self::apply_file_entry_method(entry, method, &evaluated_args)
            }
            ExoValue::Error(e) => ExoValue::Error(e), // エラーは伝播
            _ => ExoValue::Error(format!(
                "Method '{}' not supported on type {:?}",
                method, target
            )),
        }
    }

    /// 整数(Int)に対するメソッド
    pub(super) fn apply_int_method(
        n: i64,
        method: &str,
        args: &[ExoValue<'static>],
    ) -> ExoValue<'static> {
        match method {
            "abs" => ExoValue::Int(n.abs()),
            "hex" => ExoValue::String(Cow::Owned(alloc::format!("0x{:x}", n))),
            "bin" => ExoValue::String(Cow::Owned(alloc::format!("0b{:b}", n))),
            "oct" => ExoValue::String(Cow::Owned(alloc::format!("0o{:o}", n))),
            "pow" => {
                let exp = args
                    .first()
                    .and_then(|v| match v {
                        ExoValue::Int(e) => Some(*e as u32),
                        _ => None,
                    })
                    .unwrap_or(2);
                ExoValue::Int(n.saturating_pow(exp))
            }
            "to_float" => ExoValue::Float(n as f64),
            "to_string" => ExoValue::String(Cow::Owned(alloc::format!("{}", n))),
            "clamp" => {
                let min = args
                    .first()
                    .and_then(|v| match v {
                        ExoValue::Int(n) => Some(*n),
                        _ => None,
                    })
                    .unwrap_or(i64::MIN);
                let max = args
                    .get(1)
                    .and_then(|v| match v {
                        ExoValue::Int(n) => Some(*n),
                        _ => None,
                    })
                    .unwrap_or(i64::MAX);
                ExoValue::Int(n.clamp(min, max))
            }
            "is_positive" => ExoValue::Bool(n > 0),
            "is_negative" => ExoValue::Bool(n < 0),
            "is_zero" => ExoValue::Bool(n == 0),
            "is_even" => ExoValue::Bool(n % 2 == 0),
            "is_odd" => ExoValue::Bool(n % 2 != 0),
            _ => ExoValue::Error(alloc::format!(
                "Int does not have method '{}'\nValid: abs, hex, bin, oct, pow, to_float, to_string, clamp, is_positive, is_negative, is_zero, is_even, is_odd",
                method
            )),
        }
    }

    /// 浮動小数点(Float)に対するメソッド
    pub(super) fn apply_float_method(
        f: f64,
        method: &str,
        args: &[ExoValue<'static>],
    ) -> ExoValue<'static> {
        match method {
            "abs" => ExoValue::Float(if f < 0.0 { -f } else { f }),
            "ceil" => ExoValue::Float(if f >= 0.0 {
                (f as i64 + if f > f as i64 as f64 { 1 } else { 0 }) as f64
            } else {
                (f as i64) as f64
            }),
            "floor" => ExoValue::Float(if f >= 0.0 {
                (f as i64) as f64
            } else {
                (f as i64 - if f < f as i64 as f64 { 1 } else { 0 }) as f64
            }),
            "round" => {
                let precision = args
                    .first()
                    .and_then(|v| match v {
                        ExoValue::Int(n) => Some(*n as i32),
                        _ => None,
                    })
                    .unwrap_or(0);

                // Simple rounding without pow/libm
                if precision == 0 {
                    ExoValue::Float(if f >= 0.0 {
                        (f + 0.5) as i64 as f64
                    } else {
                        (f - 0.5) as i64 as f64
                    })
                } else {
                    // For non-zero precision, we'd need pow, but we avoid libm.
                    // Return as-is or implement simple int pow if critical.
                    ExoValue::Float(f)
                }
            }
            "sqrt" => {
                // sqrt without libm is hard in no_std core.
                // Using a very simple Newton-Raphson for basic shell needs if f > 0
                if f < 0.0 {
                    ExoValue::Error(String::from("Cannot take sqrt of negative number"))
                } else if f == 0.0 {
                    ExoValue::Float(0.0)
                } else {
                    let mut x = f;
                    let mut y = 1.0;
                    for _ in 0..10 {
                        // 10 iterations is enough for shell display
                        x = (x + y) / 2.0;
                        y = f / x;
                    }
                    ExoValue::Float(x)
                }
            }
            "to_int" | "truncate" => ExoValue::Int(f as i64),
            "to_string" => ExoValue::String(Cow::Owned(alloc::format!("{}", f))),
            "is_nan" => ExoValue::Bool(f.is_nan()),
            "is_infinite" => ExoValue::Bool(f.is_infinite()),
            "is_positive" => ExoValue::Bool(f > 0.0),
            "is_negative" => ExoValue::Bool(f < 0.0),
            _ => ExoValue::Error(alloc::format!(
                "Float does not have method '{}'\nValid: abs, ceil, floor, round, sqrt, to_int, to_string, is_nan, is_infinite, is_positive, is_negative",
                method
            )),
        }
    }

    /// FileEntryに対するメソッド
    pub(super) fn apply_file_entry_method(
        entry: FileEntry,
        method: &str,
        _args: &[ExoValue<'static>],
    ) -> ExoValue<'static> {
        match method {
            "name" => ExoValue::String(Cow::Owned(entry.name)),
            "path" => ExoValue::String(Cow::Owned(entry.path)),
            "size" => ExoValue::Int(entry.size as i64),
            "type" | "file_type" => {
                ExoValue::String(Cow::Owned(alloc::format!("{:?}", entry.file_type)))
            }
            "owner" => ExoValue::String(Cow::Owned(entry.owner)),
            "inode" => ExoValue::Int(entry.inode as i64),
            "is_dir" => ExoValue::Bool(entry.file_type == FileType::Directory),
            "is_file" => ExoValue::Bool(entry.file_type == FileType::Regular),
            "is_symlink" => ExoValue::Bool(entry.file_type == FileType::Symlink),
            "to_map" => {
                let mut map = BTreeMap::new();
                map.insert(
                    String::from("name"),
                    ExoValue::String(Cow::Owned(entry.name)),
                );
                map.insert(
                    String::from("path"),
                    ExoValue::String(Cow::Owned(entry.path)),
                );
                map.insert(String::from("size"), ExoValue::Int(entry.size as i64));
                map.insert(
                    String::from("type"),
                    ExoValue::String(Cow::Owned(alloc::format!("{:?}", entry.file_type))),
                );
                map.insert(
                    String::from("owner"),
                    ExoValue::String(Cow::Owned(entry.owner)),
                );
                map.insert(String::from("inode"), ExoValue::Int(entry.inode as i64));
                ExoValue::Map(map)
            }
            _ => ExoValue::Error(alloc::format!(
                "FileEntry does not have method '{}'\nValid: name, path, size, type, owner, inode, is_dir, is_file, is_symlink, to_map",
                method
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
            "sum" | "avg" | "average" | "min" | "max" => Self::apply_array_aggregate(list, method),
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
            "unique" | "dedup" | "distinct" => {
                let mut result = Vec::new();
                for item in list {
                    if !result.contains(&item) {
                        result.push(item);
                    }
                }
                ExoValue::Array(result)
            }
            "enumerate" => {
                let enumerated: Vec<ExoValue<'static>> = list
                    .into_iter()
                    .enumerate()
                    .map(|(i, v)| {
                        let mut map = BTreeMap::new();
                        map.insert(String::from("index"), ExoValue::Int(i as i64));
                        map.insert(String::from("value"), v);
                        ExoValue::Map(map)
                    })
                    .collect();
                ExoValue::Array(enumerated)
            }
            "zip" => {
                let args = self.evaluate_args(args).await;
                let other = match args.first() {
                    Some(ExoValue::Array(arr)) => arr.clone(),
                    _ => return ExoValue::Error(String::from("zip requires an array argument")),
                };
                let zipped: Vec<ExoValue<'static>> = list
                    .into_iter()
                    .zip(other.into_iter())
                    .map(|(a, b)| ExoValue::Array(alloc::vec![a, b]))
                    .collect();
                ExoValue::Array(zipped)
            }
            "group_by" => {
                let args = self.evaluate_args(args).await;
                let field = Self::extract_string_arg(&args).unwrap_or_else(|| String::from("name"));
                let mut groups: BTreeMap<String, Vec<ExoValue<'static>>> = BTreeMap::new();
                for item in list {
                    let key = match self.get_field_value(&item, &field) {
                        ExoValue::String(s) => s.into_owned(),
                        ExoValue::Int(n) => alloc::format!("{}", n),
                        other => alloc::format!("{}", other),
                    };
                    groups.entry(key).or_insert_with(Vec::new).push(item);
                }
                let mut map = BTreeMap::new();
                for (k, v) in groups {
                    map.insert(k, ExoValue::Array(v));
                }
                ExoValue::Map(map)
            }
            "chunks" => {
                let args = self.evaluate_args(args).await;
                let chunk_size = args
                    .first()
                    .and_then(|v| match v {
                        ExoValue::Int(n) if *n > 0 => Some(*n as usize),
                        _ => None,
                    })
                    .unwrap_or(2);
                let chunks: Vec<ExoValue<'static>> = list
                    .chunks(chunk_size)
                    .map(|chunk| ExoValue::Array(chunk.to_vec()))
                    .collect();
                ExoValue::Array(chunks)
            }
            "reduce" | "fold" => {
                // reduce(initial, |acc, x| acc + x) — 遅延クロージャ不対応のため簡易版
                // reduce("sum") / reduce("product") / reduce("concat") の既定演算
                let args = self.evaluate_args(args).await;
                let op = Self::extract_string_arg(&args).unwrap_or_else(|| String::from("sum"));
                match op.as_str() {
                    "sum" => {
                        let sum: i64 = list
                            .iter()
                            .filter_map(|v| match v {
                                ExoValue::Int(n) => Some(*n),
                                _ => None,
                            })
                            .sum();
                        ExoValue::Int(sum)
                    }
                    "product" => {
                        let product: i64 = list
                            .iter()
                            .filter_map(|v| match v {
                                ExoValue::Int(n) => Some(*n),
                                _ => None,
                            })
                            .product();
                        ExoValue::Int(product)
                    }
                    "concat" => {
                        let parts: Vec<String> =
                            list.iter().map(|v| alloc::format!("{}", v)).collect();
                        ExoValue::String(Cow::Owned(parts.join("")))
                    }
                    _ => ExoValue::Error(alloc::format!("reduce supports: sum, product, concat")),
                }
            }
            "is_empty" => ExoValue::Bool(list.is_empty()),
            _ => ExoValue::Error(format!(
                "Array does not have method '{}'\nValid methods: len, first, last, reverse, take, skip, filter, map, sort, sum, avg, min, max, join, find, any, all, contains, flatten, unique, enumerate, zip, group_by, chunks, reduce, is_empty",
                method
            )),
        }
    }

    /// 配列の集約メソッド（sum, avg, min, max）
    pub(super) fn apply_array_aggregate(
        list: Vec<ExoValue<'static>>,
        method: &str,
    ) -> ExoValue<'static> {
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
        let n = args.first().and_then(|v| match v {
            ExoValue::Int(n) => Some(*n as usize),
            _ => None,
        });
        match method {
            "take" | "limit" => ExoValue::Array(list.into_iter().take(n.unwrap_or(10)).collect()),
            "skip" | "offset" => ExoValue::Array(list.into_iter().skip(n.unwrap_or(0)).collect()),
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
                let sep =
                    Self::extract_string_arg(&evaluated_args).unwrap_or_else(|| String::from(", "));
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
