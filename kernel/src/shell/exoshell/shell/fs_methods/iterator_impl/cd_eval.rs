use super::*;

impl ExoShell {

    /// Evaluate `cd` path argument and update working directory.
    pub(super) fn eval_cd(&mut self, parts: &[&str]) -> ExoValue<'static> {
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
    pub(super) async fn eval_ping(&self, parts: &[&str]) -> ExoValue<'static> {
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

    /// Dispatch a legacy `net` namespace sub-command.
    pub(super) fn dispatch_namespace_command(parts: &[&str], namespace: &str) -> ExoValue<'static> {
        if let Some(method) = parts.get(1) {
            let args: Vec<ExoValue> = parts.iter().skip(2)
                .map(|s| ExoValue::String(Cow::Owned((*s).to_string())))
                .collect();
            match namespace {
                "net" => crate::shell::exoshell::namespaces::net::NetNamespace::dispatch(method, &args),
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
    net.dhcp_state()      - Show DHCPv4/DHCPv6 state
    net.dhcp_discover()   - Send DHCPDISCOVER and return any offer
    net.dhcp_request("server","offered") - Send DHCPREQUEST to server
    net.dhcp_release()    - Send DHCPRELEASE and clear lease
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

  cell.* - DriverDomain / Live Update
    cell.list()                  - List DriverDomains (structured)
    cell.info(id_or_name)        - DriverDomain + loader/live-update details
    cell.graph()                 - Loaded cell dependency graph
    cell.inspect_artifact(path)  - Inspect Type ID dependencies in .cell/ELF
    cell.epoch_status()          - Epoch/validation status
    cell.wait_quiescent(epoch)   - Wait for quiescent state (admin)
    cell.load(path, opts?)       - Create and start DriverDomain from artifact
    cell.swap(id_or_name, path)  - Hot-swap DriverDomain with new artifact
    cell.commit(id_or_name)      - Commit validation window
    cell.rollback(id_or_name)    - Roll back validation window
    cell.unload(id_or_name)      - Unload DriverDomain

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

        let namespaces = ["fs", "net", "proc", "cap", "sys", "driver", "cell"];

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
            "net" => &["config", "stats", "arp", "ping", "dhcp_state", "dhcp_renew"],
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
            "cell" => &[
                "list",
                "info",
                "graph",
                "inspect_artifact",
                "epoch_status",
                "wait_quiescent",
                "load",
                "swap",
                "update",
                "commit",
                "rollback",
                "unload",
            ],
            _ => return Vec::new(),
        };

        methods
            .iter()
            .filter(|m| m.starts_with(method_prefix))
            .map(|m| format!("{}.{}(", namespace, m))
            .collect()
    }

    /// パスプレフィックスからディレクトリと名前プレフィックスを分離
    pub(super) fn split_path_prefix<'a>(path_prefix: &'a str, cwd: &'a str) -> (&'a str, &'a str) {
        if path_prefix.contains('/') {
            let last_slash = path_prefix.rfind('/').unwrap();
            if last_slash == 0 {
                ("/", &path_prefix[1..])
            } else {
                (&path_prefix[..last_slash], &path_prefix[last_slash + 1..])
            }
        } else {
            (cwd, path_prefix)
        }
    }

    /// ファイルパス補完
    pub(super) fn complete_filepath(&self, input: &str) -> Option<Vec<String>> {
        let quote_pos = input.rfind(|c| c == '"' || c == '\'')?;
        let quote_char = input.chars().nth(quote_pos)?;

        let after_quote = &input[quote_pos + 1..];
        if after_quote.contains(quote_char) {
            return None;
        }

        let path_prefix = after_quote;
        let prefix_before_quote = &input[..quote_pos + 1];

        let (dir_path, name_prefix) = Self::split_path_prefix(path_prefix, self.cwd.as_str());

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
