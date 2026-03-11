use super::*;

impl ExoShell {
    /// Evaluate `cd` path argument and update working directory.
    pub(super) fn eval_cd(&mut self, parts: &[&str]) -> ExoValue<'static> {
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
        ExoValue::String(Cow::Owned(self.cwd.clone()))
    }

    /// Evaluate `ping <ip>` command.
    pub(super) async fn eval_ping(&self, parts: &[&str]) -> ExoValue<'static> {
        if let Some(host) = parts.get(1) {
            let ip_parts: Vec<&str> = host.split('.').collect();
            if ip_parts.len() == 4 {
                let ip: Result<Vec<u8>, _> = ip_parts.iter().map(|p| p.parse::<u8>()).collect();
                if let Ok(octets) = ip {
                    if octets.len() == 4 {
                        return NetNamespace::ping([octets[0], octets[1], octets[2], octets[3]], 4)
                            .await;
                    }
                }
            }
            ExoValue::Error(format!("Invalid IP: {}", host))
        } else {
            ExoValue::Error(String::from("Usage: ping <ip>"))
        }
    }

    /// Dispatch a legacy `net` namespace sub-command (async version).
    ///
    /// イベントキュー経由の非同期APIを使用し、
    /// NETWORK_STACKロックの同期取得を完全に回避する。
    pub(super) async fn dispatch_namespace_command(
        parts: &[&str],
        namespace: &str,
    ) -> ExoValue<'static> {
        if let Some(method) = parts.get(1) {
            let args: Vec<ExoValue> = parts
                .iter()
                .skip(2)
                .map(|s| ExoValue::String(Cow::Owned((*s).to_string())))
                .collect();
            match namespace {
                "net" => {
                    let ns = crate::shell::exoshell::namespaces::net::NetNamespace;
                    let caps = crate::security::CapabilitySet::empty();
                    ns.call(method, &args, &caps).await
                }
                _ => ExoValue::String(Cow::Owned(format!(
                    "Usage: {} <method> [args...]",
                    namespace
                ))),
            }
        } else {
            ExoValue::String(Cow::Owned(format!(
                "Usage: {} <method> [args...]",
                namespace
            )))
        }
    }

    /// Display help
    pub fn help(&self) -> ExoValue<'static> {
        let help_text = r#"
================================================================================
                      ExoShell - Rust-style REPL Environment
================================================================================
  Based on ExoRust design: operate on typed objects, not Unix text streams

[Built-in Commands]

  help            - Show this help message
  exit            - Exit ExoShell
  clear           - Clear screen
  echo <args...>  - Print arguments separated by spaces
  history [n]     - Show command history (optional: last n entries)
  env             - Show all environment variables
  type <expr>     - Show the type of a value
  whoami          - Show current user/domain/privilege info
  date            - Show system uptime (ticks)
  set <k> <v>     - Set environment variable
  unset <key>     - Unset environment variable

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
    net.interfaces()      - List network interfaces
    net.config(if_id)     - Show network configuration
    net.stats(if_id)      - Show TX/RX statistics
    net.arp()             - Show ARP cache
    net.arp_insert(ip,mac)- Insert ARP entry manually
    net.ping("ip", count) - Send ICMP echo
    net.dhcp_state(if_id) - Show DHCPv4/DHCPv6 state
    net.dhcp_discover()   - Send DHCPDISCOVER and return any offer
    net.dhcp_renew()      - Renew DHCP lease
    net.dhcp_release()    - Send DHCPRELEASE and clear lease

  net.* - Connection Tracking
    net.connections()     - Show all TCP/UDP connections (netstat)
    net.netstat()         - Alias for connections()
    net.tcp()             - Show TCP connections only
    net.udp()             - Show UDP endpoints only

  net.* - Interface Management
    net.interfaces()      - List all network interfaces
    net.ifaces()          - Alias for interfaces()
    net.if_up(id)         - Bring interface up (CAP_NET_ADMIN)
    net.if_down(id)       - Bring interface down (CAP_NET_ADMIN)

  net.* - Routing
    net.routes()          - Show IPv4/IPv6 routing table
    net.route_add(dest, prefix_len, gateway, if_id [, metric])
                          - Add IPv4 static route (CAP_NET_ADMIN)
    net.route_del(dest, prefix_len, if_id)
                          - Delete IPv4 route (CAP_NET_ADMIN)

  net.* - Firewall
    net.firewall()        - Show firewall status
    net.firewall_enable() - Enable firewall (CAP_NET_ADMIN)
    net.firewall_disable()- Disable firewall (CAP_NET_ADMIN)
    net.firewall_rules()  - List firewall rules
    net.firewall_stats()  - Show firewall statistics
    net.firewall_add(action, dir, src, dst, proto, sport, dport, prio [, name])
                          - Add firewall rule (CAP_NET_ADMIN)
    net.firewall_remove(id) - Remove rule by ID (CAP_NET_ADMIN)
    net.firewall_clear()  - Clear all rules (CAP_NET_ADMIN)
    net.firewall_policy(dir, action) - Set default policy (CAP_NET_ADMIN)

  net.* - DNS & Diagnostics
    net.dns("hostname")   - Resolve hostname to IPv4
    net.resolve("host")   - Alias for dns()
    net.snapshot()        - Full network diagnostic snapshot
    net.events(limit?)    - Recent network events (default: 20)

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
    sys.panic_record()    - Last panic DMA record
    sys.shutdown()        - Request shutdown
    sys.reboot()          - Request reboot

  driver.* - Driver Management
    driver.list()         - List registered drivers
    driver.stats()        - Driver statistics
    driver.status(id)     - Get driver status by ID
    driver.load(path)     - Compatibility alias for cell.load(path)
    driver.unload(id)     - Compatibility alias for unloading the owning DriverDomain
    driver.update(id, path) - Compatibility alias for DriverDomain hot-swap

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

  task.* - Task / Async Executor
    task.stats()          - Executor statistics (wake queue, timers, fuel)
    task.fuel()           - Current fuel budget
    task.preemption()     - Preemption counters
    task.tick()           - Current timer tick
    task.yield()          - Cooperatively yield current task

  log.* - Log Level Control
    log.level()           - Current log level and output settings
    log.set_level("lvl")  - Set log level (CAP_SYS_ADMIN)
    log.console(bool)     - Toggle console mirror (CAP_SYS_ADMIN)
    log.serial(bool)      - Toggle serial output (CAP_SYS_ADMIN)
    log.trace("msg")      - Emit TRACE log with [ExoShell] prefix
    log.debug("msg")      - Emit DEBUG log
    log.info("msg")       - Emit INFO log
    log.warn("msg")       - Emit WARN log
    log.error("msg")      - Emit ERROR log

  shell.* - Shell Control
    shell.spawn()         - Spawn proxy shell
    shell.spawn_with_caps(caps) - Spawn with specific capabilities
    shell.with_cap(cap)   - Run with additional capability
    shell.revoke(cap)     - Revoke capability
    shell.list_caps()     - List requested capabilities
    shell.run(cmd)        - Run command string

  async_swapout.* - Async Swapout
    async_swapout.status()    - Show async swapout status
    async_swapout.set(params) - Configure async swapout

  reclaim.* - Memory Reclaim
    reclaim.status()      - Show reclaim status
    reclaim.set(params)   - Configure reclaim parameters

[Method Chaining]
  fs.entries("/").filter("|e| e.size > 1024").map("|e| e.name")
  domain.list().filter("memory > 1024").sort("tasks", "desc")

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
  .sum()           - Sum of numeric elements
  .avg()           - Average of numeric elements
  .min() / .max()  - Min/Max element
  .join(sep)       - Join into string
  .contains(v)     - Check if contains value
  .find(cond)      - Find first matching element
  .any(cond)       - Any element matches?
  .all(cond)       - All elements match?
  .flatten()       - Flatten nested arrays
  .unique()        - Remove duplicates
  .enumerate()     - [{index, value}, ...]
  .zip(other)      - Combine two arrays pairwise
  .group_by(key)   - Group into Map by field
  .chunks(n)       - Split into chunks of size n
  .reduce(op)      - Reduce (op: "sum", "product", "concat")
  .is_empty()      - Check if array is empty

[String Methods]
  .len()           - Byte length
  .char_count()    - Character count (Unicode)
  .trim()          - Trim whitespace
  .trim_start()    - Trim leading whitespace
  .trim_end()      - Trim trailing whitespace
  .upper()         - Uppercase
  .lower()         - Lowercase
  .reverse()       - Reverse string
  .is_empty()      - Check if empty
  .lines()         - Split into lines
  .split(sep)      - Split by separator
  .chars()         - Split into characters
  .bytes()         - Array of byte values
  .contains(s)     - Check substring
  .starts_with(s)  - Check prefix
  .ends_with(s)    - Check suffix
  .replace(a, b)   - Replace all occurrences of a with b
  .repeat(n)       - Repeat string n times
  .substring(s, e) - Substring by char indices
  .pad_left(n)     - Pad left to width n
  .pad_right(n)    - Pad right to width n
  .find(s)         - Index of substring (-1 if not found)
  .count(s)        - Count occurrences
  .to_int()        - Parse as integer
  .to_float()      - Parse as float

[Map Methods]
  .get(key)        - Get value by key
  .keys()          - Array of keys
  .values()        - Array of values
  .entries()       - [{key, value}, ...]
  .len()           - Number of entries
  .contains_key(k) - Check if key exists
  .merge(other)    - Merge another map
  .to_json()       - Format as JSON-like string
  .is_empty()      - Check if map is empty

[Int Methods]
  .abs()           - Absolute value
  .hex()           - Hex string (0x...)
  .bin()           - Binary string (0b...)
  .oct()           - Octal string (0o...)
  .pow(n)          - Power (saturating)
  .to_float()      - Convert to Float
  .to_string()     - Convert to String
  .clamp(min, max) - Clamp to range
  .is_positive()   - > 0?
  .is_negative()   - < 0?
  .is_zero()       - == 0?
  .is_even()       - Even number?
  .is_odd()        - Odd number?

[Float Methods]
  .abs()           - Absolute value
  .ceil()          - Ceiling
  .floor()         - Floor
  .round(n?)       - Round (optional: n decimal places)
  .sqrt()          - Square root
  .to_int()        - Truncate to Int
  .to_string()     - Convert to String
  .is_nan()        - Check NaN
  .is_infinite()   - Check Infinity

[FileEntry Methods]
  .name()          - File name
  .path()          - Full path
  .size()          - Size in bytes
  .type()          - "file", "dir", or "symlink"
  .is_dir()        - Is directory?
  .is_file()       - Is regular file?
  .is_symlink()    - Is symlink?
  .to_map()        - Convert to Map

[Variables]
  let x = fs.entries("/")   - Store result in variable
  $x                        - Reference variable
  _                         - Last result

[Control Flow]
  if <cond> { ... } else { ... }  - Conditional expression
  for x in <iter> { ... }        - For loop over arrays
  let x = <expr>                 - Variable binding

[Pipe Operator]
  expr | .method()  - Pipe result to method chain

[Aliases (Unix compatibility)]
  ls, cd, pwd, cat, mkdir, rm, ifconfig, ping, netstat, route are also available
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

        // ビルトインコマンド
        let builtins = [
            "help", "exit", "clear", "echo", "history", "env", "type", "whoami", "date", "set",
            "unset",
        ];

        // 名前空間
        let namespaces = [
            "fs",
            "net",
            "domain",
            "cap",
            "sys",
            "driver",
            "cell",
            "shell",
            "task",
            "log",
            "async_swapout",
            "reclaim",
        ];

        // Unixエイリアス
        let aliases = [
            "ls", "cd", "pwd", "cat", "mkdir", "rm", "ifconfig", "ping", "netstat", "route",
        ];

        if !input.contains('.') {
            let mut completions: Vec<String> = Vec::new();

            // 名前空間の補完
            for ns in &namespaces {
                if ns.starts_with(input) {
                    completions.push(format!("{}.", ns));
                }
            }

            // ビルトインコマンドの補完
            for cmd in &builtins {
                if cmd.starts_with(input) {
                    completions.push(cmd.to_string());
                }
            }

            // エイリアスの補完
            for alias in &aliases {
                if alias.starts_with(input) {
                    completions.push(alias.to_string());
                }
            }

            return completions;
        }

        // メソッドチェイン (.filter, .map, etc.) の補完
        if input.starts_with('.') {
            let method_prefix = &input[1..];
            let chain_methods = [
                "filter",
                "map",
                "sort",
                "first",
                "last",
                "len",
                "take",
                "skip",
                "reverse",
                "sum",
                "avg",
                "min",
                "max",
                "join",
                "contains",
                "find",
                "any",
                "all",
                "flatten",
                "unique",
                "enumerate",
                "zip",
                "group_by",
                "chunks",
                "reduce",
                "is_empty",
            ];
            return chain_methods
                .iter()
                .filter(|m| m.starts_with(method_prefix))
                .map(|m| format!(".{}(", m))
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
            "net" => &[
                "config",
                "stats",
                "arp",
                "arp_insert",
                "ping",
                "dhcp_state",
                "dhcp_renew",
                "dhcp_discover",
                "dhcp_release",
                "dhcp_last_declined",
                "dhcp_last_released",
                "open",
                "connections",
                "netstat",
                "tcp",
                "udp",
                "interfaces",
                "ifaces",
                "if_up",
                "if_down",
                "routes",
                "route_add",
                "route_del",
                "firewall",
                "firewall_enable",
                "firewall_disable",
                "firewall_rules",
                "firewall_stats",
                "firewall_add",
                "firewall_remove",
                "firewall_clear",
                "firewall_policy",
                "dns",
                "resolve",
                "snapshot",
                "events",
            ],
            "domain" => &["list", "info", "kill"],
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
            "shell" => &[
                "spawn",
                "spawn_with_caps",
                "with_cap",
                "revoke",
                "list_caps",
                "run",
            ],
            "task" => &["stats", "fuel", "preemption", "tick", "yield"],
            "log" => &[
                "level",
                "status",
                "set_level",
                "console",
                "serial",
                "trace",
                "debug",
                "info",
                "warn",
                "error",
            ],
            "async_swapout" => &["status", "get", "set"],
            "reclaim" => &["status", "get", "set"],
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
        self.history.push(entry);
        if self.history.len() > self.max_history {
            self.history.remove(0);
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
