// ============================================================================
// src/shell/mod.rs - Interactive Shell Implementation
// ============================================================================
//!
//! # シェル/コマンドラインインターフェース
//!
//! 対話型シェルの実装。基本的なコマンドとスクリプト実行機能を提供。
//!
//! ## 機能
//! - コマンドライン解析
//! - 組み込みコマンド（help, ls, cd, cat, echo, etc.）
//! - ヒストリ
//! - タブ補完（基本）
//! - 環境変数
//! - 非同期シリアル入力（IRQ4駆動）
//!
//! ## ExoShell (New!)
//! ExoRustの設計思想に基づいたRust式REPL環境も利用可能。
//! `exoshell` モジュールで型付きオブジェクトを直接操作できます。

#![allow(dead_code)]

pub mod async_shell;
pub mod exoshell;

// Re-export ExoShell types
pub use exoshell::{ExoShell, ExoValue, Capability, CapOperation};

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write;
use spin::Mutex;

// ============================================================================
// Command Types
// ============================================================================

/// コマンド実行結果
#[derive(Debug, Clone)]
pub enum CommandResult {
    /// 成功
    Success,
    /// 出力付き成功
    Output(String),
    /// エラー
    Error(String),
    /// シェル終了
    Exit(i32),
    /// カレントディレクトリ変更
    ChangeDir(String),
}

/// コマンドハンドラの型
pub type CommandHandler = fn(&mut Shell, &[&str]) -> CommandResult;

/// コマンド定義
pub struct Command {
    /// コマンド名
    pub name: &'static str,
    /// 説明
    pub description: &'static str,
    /// 使用方法
    pub usage: &'static str,
    /// ハンドラ関数
    pub handler: CommandHandler,
}

// ============================================================================
// Shell State
// ============================================================================

/// シェル状態
pub struct Shell {
    /// 環境変数
    env: BTreeMap<String, String>,
    /// コマンドヒストリ
    history: Vec<String>,
    /// ヒストリの最大サイズ
    history_max: usize,
    /// カレントディレクトリ
    cwd: String,
    /// 前のディレクトリ
    prev_dir: String,
    /// 最後の終了コード
    last_exit_code: i32,
    /// 出力バッファ
    output: String,
    /// 実行中フラグ
    running: bool,
    /// プロンプト
    prompt: String,
    /// 登録されたコマンド
    commands: Vec<Command>,
}

impl Shell {
    /// 新しいシェルを作成
    pub fn new() -> Self {
        let mut shell = Self {
            env: BTreeMap::new(),
            history: Vec::new(),
            history_max: 100,
            cwd: String::from("/"),
            prev_dir: String::from("/"),
            last_exit_code: 0,
            output: String::new(),
            running: true,
            prompt: String::from("RanyOS$ "),
            commands: Vec::new(),
        };

        // デフォルトの環境変数を設定
        shell
            .env
            .insert(String::from("PATH"), String::from("/bin:/usr/bin"));
        shell
            .env
            .insert(String::from("HOME"), String::from("/home"));
        shell.env.insert(String::from("USER"), String::from("root"));
        shell
            .env
            .insert(String::from("SHELL"), String::from("/bin/rsh"));
        shell.env.insert(String::from("PWD"), String::from("/"));

        // 組み込みコマンドを登録
        shell.register_builtin_commands();

        shell
    }

    /// 組み込みコマンドを登録
    fn register_builtin_commands(&mut self) {
        self.commands = vec![
            Command {
                name: "help",
                description: "Display help information",
                usage: "help [command]",
                handler: cmd_help,
            },
            Command {
                name: "echo",
                description: "Display a line of text",
                usage: "echo [text...]",
                handler: cmd_echo,
            },
            Command {
                name: "ls",
                description: "List directory contents",
                usage: "ls [path]",
                handler: cmd_ls,
            },
            Command {
                name: "cd",
                description: "Change directory",
                usage: "cd [path]",
                handler: cmd_cd,
            },
            Command {
                name: "pwd",
                description: "Print working directory",
                usage: "pwd",
                handler: cmd_pwd,
            },
            Command {
                name: "cat",
                description: "Concatenate and print files",
                usage: "cat <file>",
                handler: cmd_cat,
            },
            Command {
                name: "mkdir",
                description: "Create directories",
                usage: "mkdir <directory>",
                handler: cmd_mkdir,
            },
            Command {
                name: "rm",
                description: "Remove files or directories",
                usage: "rm [-r] <path>",
                handler: cmd_rm,
            },
            Command {
                name: "cp",
                description: "Copy files",
                usage: "cp <source> <dest>",
                handler: cmd_cp,
            },
            Command {
                name: "mv",
                description: "Move/rename files",
                usage: "mv <source> <dest>",
                handler: cmd_mv,
            },
            Command {
                name: "touch",
                description: "Create empty file or update timestamp",
                usage: "touch <file>",
                handler: cmd_touch,
            },
            Command {
                name: "stat",
                description: "Display file or directory status",
                usage: "stat <path>",
                handler: cmd_stat,
            },
            Command {
                name: "ln",
                description: "Create links",
                usage: "ln -s <target> <link_name>",
                handler: cmd_ln,
            },
            Command {
                name: "write",
                description: "Write content to a file",
                usage: "write <file> <content>",
                handler: cmd_write,
            },
            Command {
                name: "clear",
                description: "Clear the screen",
                usage: "clear",
                handler: cmd_clear,
            },
            Command {
                name: "env",
                description: "Display environment variables",
                usage: "env",
                handler: cmd_env,
            },
            Command {
                name: "export",
                description: "Set environment variable",
                usage: "export NAME=VALUE",
                handler: cmd_export,
            },
            Command {
                name: "unset",
                description: "Unset environment variable",
                usage: "unset NAME",
                handler: cmd_unset,
            },
            Command {
                name: "history",
                description: "Show command history",
                usage: "history",
                handler: cmd_history,
            },
            Command {
                name: "exit",
                description: "Exit the shell",
                usage: "exit [code]",
                handler: cmd_exit,
            },
            Command {
                name: "date",
                description: "Display current date and time",
                usage: "date",
                handler: cmd_date,
            },
            Command {
                name: "uptime",
                description: "Show system uptime",
                usage: "uptime",
                handler: cmd_uptime,
            },
            Command {
                name: "free",
                description: "Display memory usage",
                usage: "free",
                handler: cmd_free,
            },
            Command {
                name: "ps",
                description: "List processes",
                usage: "ps",
                handler: cmd_ps,
            },
            Command {
                name: "uname",
                description: "Print system information",
                usage: "uname [-a]",
                handler: cmd_uname,
            },
            Command {
                name: "whoami",
                description: "Print current user",
                usage: "whoami",
                handler: cmd_whoami,
            },
            Command {
                name: "hostname",
                description: "Print or set hostname",
                usage: "hostname [name]",
                handler: cmd_hostname,
            },
            Command {
                name: "reboot",
                description: "Reboot the system",
                usage: "reboot",
                handler: cmd_reboot,
            },
            Command {
                name: "shutdown",
                description: "Shutdown the system",
                usage: "shutdown",
                handler: cmd_shutdown,
            },
            Command {
                name: "hexdump",
                description: "Display file in hexadecimal",
                usage: "hexdump <file>",
                handler: cmd_hexdump,
            },
            Command {
                name: "head",
                description: "Output the first part of files",
                usage: "head [-n lines] <file>",
                handler: cmd_head,
            },
            Command {
                name: "tail",
                description: "Output the last part of files",
                usage: "tail [-n lines] <file>",
                handler: cmd_tail,
            },
            Command {
                name: "wc",
                description: "Word, line, character count",
                usage: "wc <file>",
                handler: cmd_wc,
            },
            Command {
                name: "grep",
                description: "Search for patterns in files",
                usage: "grep <pattern> <file>",
                handler: cmd_grep,
            },
            // Network commands
            Command {
                name: "ifconfig",
                description: "Configure network interfaces",
                usage: "ifconfig [interface]",
                handler: cmd_ifconfig,
            },
            Command {
                name: "ping",
                description: "Send ICMP echo requests",
                usage: "ping <host> [-c count]",
                handler: cmd_ping,
            },
            Command {
                name: "netstat",
                description: "Network statistics",
                usage: "netstat [-a]",
                handler: cmd_netstat,
            },
            Command {
                name: "dns",
                description: "DNS lookup",
                usage: "dns <hostname>",
                handler: cmd_dns,
            },
            Command {
                name: "dhcp",
                description: "DHCP client operations",
                usage: "dhcp [discover|request]",
                handler: cmd_dhcp,
            },
            Command {
                name: "arp",
                description: "Show/manipulate ARP cache",
                usage: "arp [-a]",
                handler: cmd_arp,
            },
        ];
    }

    /// コマンドを検索
    fn find_command(&self, name: &str) -> Option<&Command> {
        self.commands.iter().find(|cmd| cmd.name == name)
    }

    /// 環境変数を取得
    pub fn get_env(&self, name: &str) -> Option<&String> {
        self.env.get(name)
    }

    /// 環境変数を設定
    pub fn set_env(&mut self, name: &str, value: &str) {
        self.env.insert(name.to_string(), value.to_string());
    }

    /// 環境変数を削除
    pub fn unset_env(&mut self, name: &str) {
        self.env.remove(name);
    }

    /// カレントディレクトリを取得
    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    /// プロンプトを取得
    pub fn prompt(&self) -> &str {
        &self.prompt
    }

    /// プロンプトを設定
    pub fn set_prompt(&mut self, prompt: &str) {
        self.prompt = prompt.to_string();
    }

    /// 実行中かどうか
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// コマンドラインを解析
    fn parse_line(&self, line: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut current = String::new();
        let mut in_quote = false;
        let mut quote_char = ' ';
        let mut escape_next = false;

        for c in line.chars() {
            if escape_next {
                current.push(c);
                escape_next = false;
                continue;
            }

            match c {
                '\\' => {
                    escape_next = true;
                }
                '"' | '\'' if !in_quote => {
                    in_quote = true;
                    quote_char = c;
                }
                c if c == quote_char && in_quote => {
                    in_quote = false;
                }
                ' ' | '\t' if !in_quote => {
                    if !current.is_empty() {
                        tokens.push(self.expand_variables(&current));
                        current.clear();
                    }
                }
                _ => {
                    current.push(c);
                }
            }
        }

        if !current.is_empty() {
            tokens.push(self.expand_variables(&current));
        }

        tokens
    }

    /// 変数を展開
    fn expand_variables(&self, s: &str) -> String {
        let mut result = String::new();
        let mut chars = s.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '$' {
                let mut var_name = String::new();

                // ${VAR} 形式
                if chars.peek() == Some(&'{') {
                    chars.next(); // skip '{'
                    while let Some(&c) = chars.peek() {
                        if c == '}' {
                            chars.next();
                            break;
                        }
                        var_name.push(c);
                        chars.next();
                    }
                } else {
                    // $VAR 形式
                    while let Some(&c) = chars.peek() {
                        if c.is_alphanumeric() || c == '_' {
                            var_name.push(c);
                            chars.next();
                        } else {
                            break;
                        }
                    }
                }

                // 特殊変数
                let value = match var_name.as_str() {
                    "?" => self.last_exit_code.to_string(),
                    "PWD" => self.cwd.clone(),
                    "HOME" => self.env.get("HOME").cloned().unwrap_or_default(),
                    _ => self.env.get(&var_name).cloned().unwrap_or_default(),
                };

                result.push_str(&value);
            } else {
                result.push(c);
            }
        }

        result
    }

    /// リダイレクト演算子を解析
    /// 戻り値: (コマンド部分, Option<(ファイルパス, 追記モードか)>)
    fn parse_redirect(&self, line: &str) -> (String, Option<(String, bool)>) {
        // >> (追記) を先にチェック
        if let Some(pos) = line.find(">>") {
            let command = line[..pos].trim().to_string();
            let file = line[pos + 2..].trim().to_string();
            if !file.is_empty() {
                return (command, Some((file, true)));
            }
        }
        // > (上書き) をチェック
        if let Some(pos) = line.find('>') {
            let command = line[..pos].trim().to_string();
            let file = line[pos + 1..].trim().to_string();
            if !file.is_empty() {
                return (command, Some((file, false)));
            }
        }
        (line.to_string(), None)
    }

    /// 出力をファイルにリダイレクト
    fn redirect_output(&self, content: &str, file_path: &str, append: bool) -> Result<(), String> {
        use crate::fs;
        
        // 既存の内容を取得（追記モードの場合）
        let final_content = if append {
            match fs::read_file_content(file_path, &self.cwd) {
                Ok(existing) => {
                    let mut combined = String::from_utf8_lossy(&existing).to_string();
                    combined.push_str(content);
                    combined
                }
                Err(fs::FsError::NotFound) => content.to_string(),
                Err(e) => return Err(format!("redirect: {:?}", e)),
            }
        } else {
            content.to_string()
        };
        
        // ファイルに書き込み
        fs::write_file_content(file_path, &self.cwd, final_content.as_bytes())
            .map_err(|e| format!("redirect: {:?}", e))
    }

    /// コマンドを実行
    pub fn execute(&mut self, line: &str) -> CommandResult {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            return CommandResult::Success;
        }

        // ヒストリに追加
        if self.history.last().map(|s| s.as_str()) != Some(line) {
            self.history.push(line.to_string());
            if self.history.len() > self.history_max {
                self.history.remove(0);
            }
        }

        // リダイレクト処理の検出
        let (command_part, redirect) = self.parse_redirect(line);

        // トークンに分解
        let tokens = self.parse_line(&command_part);
        if tokens.is_empty() {
            return CommandResult::Success;
        }

        let cmd_name = &tokens[0];
        let args: Vec<&str> = tokens.iter().skip(1).map(|s| s.as_str()).collect();

        // コマンドを検索して実行
        if let Some(cmd) = self.find_command(cmd_name) {
            let handler = cmd.handler;
            let result = handler(self, &args);

            // リダイレクト処理
            let result = if let Some((file_path, append)) = redirect {
                match &result {
                    CommandResult::Output(output) => {
                        // 出力をファイルに書き込む
                        match self.redirect_output(output, &file_path, append) {
                            Ok(_) => CommandResult::Success,
                            Err(e) => CommandResult::Error(e),
                        }
                    }
                    _ => result,
                }
            } else {
                result
            };

            // 終了コードを更新
            match &result {
                CommandResult::Success | CommandResult::Output(_) => {
                    self.last_exit_code = 0;
                }
                CommandResult::Error(_) => {
                    self.last_exit_code = 1;
                }
                CommandResult::Exit(code) => {
                    self.last_exit_code = *code;
                    self.running = false;
                }
                CommandResult::ChangeDir(path) => {
                    self.prev_dir = self.cwd.clone();
                    self.cwd = path.clone();
                    self.env.insert(String::from("PWD"), path.clone());
                    self.last_exit_code = 0;
                }
            }

            result
        } else {
            CommandResult::Error(format!("{}: command not found", cmd_name))
        }
    }

    /// 出力を追加
    pub fn print(&mut self, s: &str) {
        self.output.push_str(s);
    }

    /// 出力を取得してクリア
    pub fn take_output(&mut self) -> String {
        core::mem::take(&mut self.output)
    }

    /// ヒストリを取得
    pub fn history(&self) -> &[String] {
        &self.history
    }

    /// タブ補完
    pub fn complete(&self, partial: &str) -> Vec<String> {
        let mut completions = Vec::new();

        // コマンド名の補完
        for cmd in &self.commands {
            if cmd.name.starts_with(partial) {
                completions.push(cmd.name.to_string());
            }
        }

        completions.sort();
        completions
    }
}

// ============================================================================
// Built-in Commands
// ============================================================================

fn cmd_help(shell: &mut Shell, args: &[&str]) -> CommandResult {
    if let Some(cmd_name) = args.first() {
        if let Some(cmd) = shell.find_command(cmd_name) {
            return CommandResult::Output(format!(
                "{} - {}\nUsage: {}\n",
                cmd.name, cmd.description, cmd.usage
            ));
        } else {
            return CommandResult::Error(format!("help: no help for '{}'", cmd_name));
        }
    }

    let mut output = String::from("Available commands:\n\n");
    for cmd in &shell.commands {
        output.push_str(&format!("  {:12} - {}\n", cmd.name, cmd.description));
    }
    output.push_str("\nUse 'help <command>' for more information.\n");

    CommandResult::Output(output)
}

fn cmd_echo(_shell: &mut Shell, args: &[&str]) -> CommandResult {
    let mut output = args.join(" ");
    output.push('\n');
    CommandResult::Output(output)
}

fn cmd_ls(shell: &mut Shell, args: &[&str]) -> CommandResult {
    let path = args.first().unwrap_or(&".");

    // memfsと連携
    match crate::fs::list_directory(path, &shell.cwd) {
        Ok(entries) => {
            let mut output = String::new();
            for entry in entries {
                let suffix = match entry.file_type {
                    crate::fs::FileType::Directory => "/",
                    crate::fs::FileType::Symlink => "@",
                    _ => "",
                };
                output.push_str(&format!("  {}{}\n", entry.name, suffix));
            }
            if output.is_empty() {
                output.push_str("  (empty directory)\n");
            }
            CommandResult::Output(output)
        }
        Err(crate::fs::FsError::NotFound) => {
            CommandResult::Error(format!("ls: {}: No such file or directory", path))
        }
        Err(crate::fs::FsError::NotDirectory) => {
            // ファイルの場合はファイル名を表示
            CommandResult::Output(format!("  {}\n", path))
        }
        Err(e) => CommandResult::Error(format!("ls: {:?}", e)),
    }
}

fn cmd_cd(shell: &mut Shell, args: &[&str]) -> CommandResult {
    let path = match args.first() {
        Some(&"-") => shell.prev_dir.clone(),
        Some(&"~") | None => shell
            .get_env("HOME")
            .cloned()
            .unwrap_or_else(|| String::from("/home/user")),
        Some(path) => {
            if path.starts_with('/') {
                path.to_string()
            } else if *path == ".." {
                let mut parts: Vec<&str> = shell.cwd.split('/').filter(|s| !s.is_empty()).collect();
                parts.pop();
                if parts.is_empty() {
                    String::from("/")
                } else {
                    format!("/{}", parts.join("/"))
                }
            } else if *path == "." {
                shell.cwd.clone()
            } else {
                if shell.cwd == "/" {
                    format!("/{}", path)
                } else {
                    format!("{}/{}", shell.cwd, path)
                }
            }
        }
    };

    // パスの存在確認 (memfsと連携)
    match crate::fs::resolve_path(&path, &shell.cwd) {
        Ok(inode) => {
            match inode.getattr() {
                Ok(attr) => {
                    if attr.file_type == crate::fs::FileType::Directory {
                        CommandResult::ChangeDir(path)
                    } else {
                        CommandResult::Error(format!("cd: {}: Not a directory", path))
                    }
                }
                Err(_) => CommandResult::ChangeDir(path), // 属性取得に失敗してもディレクトリ変更
            }
        }
        Err(crate::fs::FsError::NotFound) => {
            CommandResult::Error(format!("cd: {}: No such file or directory", path))
        }
        Err(e) => CommandResult::Error(format!("cd: {:?}", e)),
    }
}

fn cmd_pwd(shell: &mut Shell, _args: &[&str]) -> CommandResult {
    CommandResult::Output(format!("{}\n", shell.cwd))
}

fn cmd_cat(shell: &mut Shell, args: &[&str]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::Error(String::from("cat: missing file operand"));
    }

    // memfsと連携してファイル内容を読み取り
    match crate::fs::read_file_content(args[0], &shell.cwd) {
        Ok(content) => {
            match core::str::from_utf8(&content) {
                Ok(text) => CommandResult::Output(text.to_string()),
                Err(_) => CommandResult::Error(format!("cat: {}: Binary file", args[0])),
            }
        }
        Err(crate::fs::FsError::NotFound) => {
            CommandResult::Error(format!("cat: {}: No such file or directory", args[0]))
        }
        Err(crate::fs::FsError::IsDirectory) => {
            CommandResult::Error(format!("cat: {}: Is a directory", args[0]))
        }
        Err(e) => CommandResult::Error(format!("cat: {:?}", e)),
    }
}

fn cmd_mkdir(shell: &mut Shell, args: &[&str]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::Error(String::from("mkdir: missing operand"));
    }

    // memfsと連携してディレクトリを作成
    match crate::fs::make_directory(args[0], &shell.cwd) {
        Ok(()) => CommandResult::Success,
        Err(crate::fs::FsError::AlreadyExists) => {
            CommandResult::Error(format!("mkdir: {}: File exists", args[0]))
        }
        Err(crate::fs::FsError::NotFound) => {
            CommandResult::Error(format!("mkdir: {}: No such file or directory", args[0]))
        }
        Err(e) => CommandResult::Error(format!("mkdir: {:?}", e)),
    }
}

fn cmd_rm(shell: &mut Shell, args: &[&str]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::Error(String::from("rm: missing operand"));
    }

    // -r/-R オプションチェック (再帰削除)
    let recursive = args.iter().any(|a| *a == "-r" || *a == "-R" || *a == "-rf");
    let paths: Vec<&str> = args.iter().filter(|a| !a.starts_with('-')).copied().collect();

    if paths.is_empty() {
        return CommandResult::Error(String::from("rm: missing operand"));
    }

    for path in paths {
        // まずファイルとして削除を試行
        match crate::fs::remove_file(path, &shell.cwd) {
            Ok(()) => continue,
            Err(crate::fs::FsError::IsDirectory) => {
                if recursive {
                    // 再帰削除 (空ディレクトリのみ)
                    match crate::fs::remove_directory(path, &shell.cwd) {
                        Ok(()) => continue,
                        Err(crate::fs::FsError::NotEmpty) => {
                            return CommandResult::Error(format!("rm: {}: Directory not empty", path));
                        }
                        Err(e) => return CommandResult::Error(format!("rm: {:?}", e)),
                    }
                } else {
                    return CommandResult::Error(format!("rm: {}: Is a directory", path));
                }
            }
            Err(crate::fs::FsError::NotFound) => {
                return CommandResult::Error(format!("rm: {}: No such file or directory", path));
            }
            Err(e) => return CommandResult::Error(format!("rm: {:?}", e)),
        }
    }

    CommandResult::Success
}

fn cmd_cp(shell: &mut Shell, args: &[&str]) -> CommandResult {
    if args.len() < 2 {
        return CommandResult::Error(String::from("cp: missing operand"));
    }

    let src = args[0];
    let dst = args[1];

    match crate::fs::copy_file(src, dst, &shell.cwd) {
        Ok(()) => CommandResult::Success,
        Err(crate::fs::FsError::NotFound) => {
            CommandResult::Error(format!("cp: {}: No such file or directory", src))
        }
        Err(crate::fs::FsError::IsDirectory) => {
            CommandResult::Error(format!("cp: {}: Is a directory", src))
        }
        Err(e) => CommandResult::Error(format!("cp: {:?}", e)),
    }
}

fn cmd_mv(shell: &mut Shell, args: &[&str]) -> CommandResult {
    if args.len() < 2 {
        return CommandResult::Error(String::from("mv: missing operand"));
    }

    let src = args[0];
    let dst = args[1];

    match crate::fs::move_file(src, dst, &shell.cwd) {
        Ok(()) => CommandResult::Success,
        Err(crate::fs::FsError::NotFound) => {
            CommandResult::Error(format!("mv: {}: No such file or directory", src))
        }
        Err(crate::fs::FsError::CrossDeviceLink) => {
            CommandResult::Error(format!("mv: cannot move across directories"))
        }
        Err(e) => CommandResult::Error(format!("mv: {:?}", e)),
    }
}

fn cmd_touch(shell: &mut Shell, args: &[&str]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::Error(String::from("touch: missing operand"));
    }

    for path in args {
        match crate::fs::touch_file(path, &shell.cwd) {
            Ok(()) => {}
            Err(crate::fs::FsError::NotFound) => {
                return CommandResult::Error(format!("touch: {}: No such file or directory", path));
            }
            Err(e) => return CommandResult::Error(format!("touch: {:?}", e)),
        }
    }

    CommandResult::Success
}

fn cmd_stat(shell: &mut Shell, args: &[&str]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::Error(String::from("stat: missing operand"));
    }

    let path = args[0];
    match crate::fs::stat_file(path, &shell.cwd) {
        Ok(attr) => {
            let file_type = match attr.file_type {
                crate::fs::FileType::Regular => "regular file",
                crate::fs::FileType::Directory => "directory",
                crate::fs::FileType::Symlink => "symbolic link",
                crate::fs::FileType::BlockDevice => "block device",
                crate::fs::FileType::CharDevice => "character device",
                crate::fs::FileType::Fifo => "FIFO (named pipe)",
                crate::fs::FileType::Socket => "socket",
            };
            
            let output = format!(
                "  File: {}\n  Size: {} bytes\n  Type: {}\n  Inode: {}\n  Links: {}\n  Mode: {:o}\n  UID: {}\n  GID: {}\n",
                path,
                attr.size,
                file_type,
                attr.ino,
                attr.nlink,
                attr.mode.0,
                attr.uid,
                attr.gid,
            );
            CommandResult::Output(output)
        }
        Err(crate::fs::FsError::NotFound) => {
            CommandResult::Error(format!("stat: {}: No such file or directory", path))
        }
        Err(e) => CommandResult::Error(format!("stat: {:?}", e)),
    }
}

fn cmd_ln(shell: &mut Shell, args: &[&str]) -> CommandResult {
    // ln -s <target> <link_name>
    if args.len() < 3 || args[0] != "-s" {
        return CommandResult::Error(String::from("ln: usage: ln -s <target> <link_name>"));
    }

    let target = args[1];
    let link_name = args[2];

    match crate::fs::create_symlink(target, link_name, &shell.cwd) {
        Ok(()) => CommandResult::Success,
        Err(crate::fs::FsError::AlreadyExists) => {
            CommandResult::Error(format!("ln: {}: File exists", link_name))
        }
        Err(crate::fs::FsError::NotFound) => {
            CommandResult::Error(format!("ln: {}: No such file or directory", link_name))
        }
        Err(e) => CommandResult::Error(format!("ln: {:?}", e)),
    }
}

fn cmd_write(shell: &mut Shell, args: &[&str]) -> CommandResult {
    if args.len() < 2 {
        return CommandResult::Error(String::from("write: usage: write <file> <content>"));
    }

    let file = args[0];
    let content = args[1..].join(" ");

    match crate::fs::write_file_content(file, &shell.cwd, content.as_bytes()) {
        Ok(()) => CommandResult::Success,
        Err(crate::fs::FsError::NotFound) => {
            // ファイルが存在しない場合は作成
            if let Err(e) = crate::fs::touch_file(file, &shell.cwd) {
                return CommandResult::Error(format!("write: {:?}", e));
            }
            match crate::fs::write_file_content(file, &shell.cwd, content.as_bytes()) {
                Ok(()) => CommandResult::Success,
                Err(e) => CommandResult::Error(format!("write: {:?}", e)),
            }
        }
        Err(e) => CommandResult::Error(format!("write: {:?}", e)),
    }
}

fn cmd_clear(_shell: &mut Shell, _args: &[&str]) -> CommandResult {
    // ANSIエスケープシーケンスで画面クリア
    CommandResult::Output(String::from("\x1B[2J\x1B[H"))
}

fn cmd_env(shell: &mut Shell, _args: &[&str]) -> CommandResult {
    let mut output = String::new();
    for (key, value) in &shell.env {
        output.push_str(&format!("{}={}\n", key, value));
    }
    CommandResult::Output(output)
}

fn cmd_export(shell: &mut Shell, args: &[&str]) -> CommandResult {
    for arg in args {
        if let Some(pos) = arg.find('=') {
            let name = &arg[..pos];
            let value = &arg[pos + 1..];
            shell.set_env(name, value);
        } else {
            return CommandResult::Error(format!("export: invalid format: {}", arg));
        }
    }
    CommandResult::Success
}

fn cmd_unset(shell: &mut Shell, args: &[&str]) -> CommandResult {
    for name in args {
        shell.unset_env(name);
    }
    CommandResult::Success
}

fn cmd_history(shell: &mut Shell, _args: &[&str]) -> CommandResult {
    let mut output = String::new();
    for (i, cmd) in shell.history.iter().enumerate() {
        output.push_str(&format!("{:5}  {}\n", i + 1, cmd));
    }
    CommandResult::Output(output)
}

fn cmd_exit(_shell: &mut Shell, args: &[&str]) -> CommandResult {
    let code = args
        .first()
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(0);
    CommandResult::Exit(code)
}

fn cmd_date(_shell: &mut Shell, _args: &[&str]) -> CommandResult {
    // TODO: 実際の時刻を取得
    let ticks = crate::task::timer::current_tick();
    let seconds = ticks / 1000;
    let minutes = seconds / 60;
    let hours = minutes / 60;

    CommandResult::Output(format!(
        "System Time: {:02}:{:02}:{:02} (uptime)\n",
        hours % 24,
        minutes % 60,
        seconds % 60
    ))
}

fn cmd_uptime(_shell: &mut Shell, _args: &[&str]) -> CommandResult {
    let ticks = crate::task::timer::current_tick();
    let seconds = ticks / 1000;
    let minutes = seconds / 60;
    let hours = minutes / 60;
    let days = hours / 24;

    let output = if days > 0 {
        format!(
            "up {} days, {:02}:{:02}:{:02}\n",
            days,
            hours % 24,
            minutes % 60,
            seconds % 60
        )
    } else {
        format!("up {:02}:{:02}:{:02}\n", hours, minutes % 60, seconds % 60)
    };

    CommandResult::Output(output)
}

fn cmd_free(_shell: &mut Shell, _args: &[&str]) -> CommandResult {
    // TODO: 実際のメモリ情報を取得
    let output = format!(
        "              total        used        free\n\
         Mem:      134217728    67108864    67108864\n\
         (values in bytes)\n"
    );
    CommandResult::Output(output)
}

fn cmd_ps(_shell: &mut Shell, _args: &[&str]) -> CommandResult {
    // TODO: 実際のプロセスリスト
    let output = format!(
        "  PID  STATE    NAME\n\
         {: >5}  RUNNING  kernel\n\
         {: >5}  RUNNING  shell\n",
        0, 1
    );
    CommandResult::Output(output)
}

fn cmd_uname(_shell: &mut Shell, args: &[&str]) -> CommandResult {
    let all = args.contains(&"-a");

    if all {
        CommandResult::Output(String::from("RanyOS ExoKernel 0.1.0 x86_64\n"))
    } else {
        CommandResult::Output(String::from("RanyOS\n"))
    }
}

fn cmd_whoami(shell: &mut Shell, _args: &[&str]) -> CommandResult {
    let user = shell
        .get_env("USER")
        .cloned()
        .unwrap_or_else(|| String::from("root"));
    CommandResult::Output(format!("{}\n", user))
}

fn cmd_hostname(shell: &mut Shell, args: &[&str]) -> CommandResult {
    if let Some(name) = args.first() {
        shell.set_env("HOSTNAME", name);
        CommandResult::Success
    } else {
        let hostname = shell
            .get_env("HOSTNAME")
            .cloned()
            .unwrap_or_else(|| String::from("ranyos"));
        CommandResult::Output(format!("{}\n", hostname))
    }
}

fn cmd_reboot(_shell: &mut Shell, _args: &[&str]) -> CommandResult {
    CommandResult::Output(String::from("System reboot requested...\n"))
    // TODO: 実際のリブート処理
}

fn cmd_shutdown(_shell: &mut Shell, _args: &[&str]) -> CommandResult {
    CommandResult::Output(String::from("System shutdown requested...\n"))
    // TODO: 実際のシャットダウン処理
}

fn cmd_hexdump(_shell: &mut Shell, args: &[&str]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::Error(String::from("hexdump: missing file operand"));
    }

    // TODO: 実際のファイル読み取りと16進ダンプ
    CommandResult::Output(String::from("(hexdump output)\n"))
}

fn cmd_head(_shell: &mut Shell, args: &[&str]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::Error(String::from("head: missing file operand"));
    }

    // TODO: 実際のファイル読み取り
    CommandResult::Output(String::from("(first 10 lines)\n"))
}

fn cmd_tail(_shell: &mut Shell, args: &[&str]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::Error(String::from("tail: missing file operand"));
    }

    // TODO: 実際のファイル読み取り
    CommandResult::Output(String::from("(last 10 lines)\n"))
}

fn cmd_wc(_shell: &mut Shell, args: &[&str]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::Error(String::from("wc: missing file operand"));
    }

    // TODO: 実際のファイル読み取りとカウント
    CommandResult::Output(format!("  0   0   0 {}\n", args[0]))
}

fn cmd_grep(_shell: &mut Shell, args: &[&str]) -> CommandResult {
    if args.len() < 2 {
        return CommandResult::Error(String::from("grep: missing operand"));
    }

    // TODO: 実際のパターンマッチング
    CommandResult::Output(String::from("(matching lines)\n"))
}

// ============================================================================
// Network Commands
// ============================================================================

fn cmd_ifconfig(_shell: &mut Shell, args: &[&str]) -> CommandResult {
    use crate::net;
    
    let mut output = String::new();
    
    if args.is_empty() || args[0] == "-a" {
        // Show all interfaces
        output.push_str("Network Interfaces:\n\n");
        
        // eth0 (VirtIO-Net)
        output.push_str("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>\n");
        
        // Try to get actual network config
        if let Some(config) = net::get_network_config() {
            output.push_str(&format!(
                "        inet {}.{}.{}.{}  netmask {}.{}.{}.{}  broadcast {}.{}.{}.255\n",
                config.ip[0], config.ip[1], config.ip[2], config.ip[3],
                config.netmask[0], config.netmask[1], config.netmask[2], config.netmask[3],
                config.ip[0], config.ip[1], config.ip[2]
            ));
            output.push_str(&format!(
                "        ether {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                config.mac[0], config.mac[1], config.mac[2], 
                config.mac[3], config.mac[4], config.mac[5]
            ));
        } else {
            // Default demo values
            output.push_str("        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n");
            output.push_str("        ether 52:54:00:12:34:56\n");
        }
        
        // Statistics
        if let Some(stats) = net::get_network_stats() {
            output.push_str(&format!(
                "        RX packets {}  bytes {} ({} KB)\n",
                stats.rx_packets,
                stats.rx_bytes,
                stats.rx_bytes / 1024
            ));
            output.push_str(&format!(
                "        TX packets {}  bytes {} ({} KB)\n",
                stats.tx_packets,
                stats.tx_bytes,
                stats.tx_bytes / 1024
            ));
            output.push_str(&format!(
                "        RX errors {}  dropped {}\n",
                stats.rx_errors, stats.rx_dropped
            ));
        } else {
            output.push_str("        RX packets 0  bytes 0 (0 KB)\n");
            output.push_str("        TX packets 0  bytes 0 (0 KB)\n");
        }
        
        output.push_str("\nlo: flags=73<UP,LOOPBACK,RUNNING>\n");
        output.push_str("        inet 127.0.0.1  netmask 255.0.0.0\n");
        output.push_str("        loop  txqueuelen 1000\n");
    } else {
        // Show specific interface
        let iface = args[0];
        match iface {
            "eth0" => {
                output.push_str(&format!("{}: VirtIO Network Interface\n", iface));
                output.push_str("        Status: UP\n");
            }
            "lo" => {
                output.push_str(&format!("{}: Loopback Interface\n", iface));
                output.push_str("        inet 127.0.0.1/8\n");
            }
            _ => {
                return CommandResult::Error(format!("{}: interface not found", iface));
            }
        }
    }
    
    CommandResult::Output(output)
}

fn cmd_ping(_shell: &mut Shell, args: &[&str]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::Error(String::from("ping: usage: ping <host> [-c count]"));
    }
    
    let host = args[0];
    
    // Parse count option
    let count = if args.len() >= 3 && args[1] == "-c" {
        args[2].parse::<u32>().unwrap_or(4)
    } else {
        4
    };
    
    // Parse IP address or hostname
    let ip = if host.contains('.') {
        // IP address
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() != 4 {
            return CommandResult::Error(format!("ping: invalid IP address: {}", host));
        }
        let octets: Result<Vec<u8>, _> = parts.iter()
            .map(|p| p.parse::<u8>())
            .collect();
        match octets {
            Ok(o) if o.len() == 4 => [o[0], o[1], o[2], o[3]],
            _ => return CommandResult::Error(format!("ping: invalid IP address: {}", host)),
        }
    } else {
        // Hostname - would need DNS resolution
        match host {
            "localhost" => [127, 0, 0, 1],
            "gateway" => [10, 0, 2, 2],
            _ => {
                return CommandResult::Output(format!(
                    "PING {} - DNS resolution not available in demo\n\
                     Use IP address directly (e.g., ping 10.0.2.2)\n",
                    host
                ));
            }
        }
    };
    
    let mut output = String::new();
    output.push_str(&format!(
        "PING {}.{}.{}.{} ({}.{}.{}.{}) 56(84) bytes of data.\n",
        ip[0], ip[1], ip[2], ip[3],
        ip[0], ip[1], ip[2], ip[3]
    ));
    
    // Attempt actual ping using network stack
    let mut sent = 0u32;
    let mut received = 0u32;
    
    for seq in 1..=count {
        sent += 1;
        
        // Try to send ICMP echo request via network stack
        let result = crate::net::send_icmp_echo(ip, seq as u16);
        
        match result {
            Ok(rtt_ms) => {
                received += 1;
                output.push_str(&format!(
                    "64 bytes from {}.{}.{}.{}: icmp_seq={} ttl=64 time={:.1} ms\n",
                    ip[0], ip[1], ip[2], ip[3], seq, rtt_ms
                ));
            }
            Err(e) => {
                output.push_str(&format!(
                    "From {}.{}.{}.{} icmp_seq={}: {}\n",
                    ip[0], ip[1], ip[2], ip[3], seq, e
                ));
            }
        }
    }
    
    // Statistics
    let loss = if sent > 0 {
        ((sent - received) as f32 / sent as f32) * 100.0
    } else {
        100.0
    };
    
    output.push_str(&format!(
        "\n--- {}.{}.{}.{} ping statistics ---\n",
        ip[0], ip[1], ip[2], ip[3]
    ));
    output.push_str(&format!(
        "{} packets transmitted, {} received, {:.0}% packet loss\n",
        sent, received, loss
    ));
    
    CommandResult::Output(output)
}

fn cmd_netstat(_shell: &mut Shell, args: &[&str]) -> CommandResult {
    let show_all = args.contains(&"-a");
    
    let mut output = String::new();
    output.push_str("Active Internet connections");
    if show_all {
        output.push_str(" (including servers)");
    }
    output.push_str("\n");
    output.push_str("Proto  Local Address          Foreign Address        State\n");
    
    // Get TCP connections from network stack
    if let Some(connections) = crate::net::get_tcp_connections() {
        for conn in connections {
            if show_all || conn.state != "LISTEN" {
                output.push_str(&format!(
                    "{:<6} {:<22} {:<22} {}\n",
                    "tcp", conn.local_addr, conn.remote_addr, conn.state
                ));
            }
        }
    } else {
        // Demo output
        output.push_str("tcp    0.0.0.0:22             0.0.0.0:*              LISTEN\n");
        output.push_str("tcp    0.0.0.0:80             0.0.0.0:*              LISTEN\n");
    }
    
    // UDP sockets
    if let Some(sockets) = crate::net::get_udp_sockets() {
        for sock in sockets {
            output.push_str(&format!(
                "{:<6} {:<22} {:<22} -\n",
                "udp", sock.local_addr, sock.remote_addr
            ));
        }
    } else {
        output.push_str("udp    0.0.0.0:68             0.0.0.0:*              -\n");
    }
    
    CommandResult::Output(output)
}

fn cmd_dns(_shell: &mut Shell, args: &[&str]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::Error(String::from("dns: usage: dns <hostname>"));
    }
    
    let hostname = args[0];
    let mut output = String::new();
    
    output.push_str(&format!("Looking up: {}\n", hostname));
    
    // Try DNS resolution via network stack
    match crate::net::dns_resolve(hostname) {
        Ok(addresses) => {
            output.push_str(&format!("Name:    {}\n", hostname));
            for addr in addresses {
                output.push_str(&format!("Address: {}.{}.{}.{}\n",
                    addr[0], addr[1], addr[2], addr[3]));
            }
        }
        Err(e) => {
            // Fallback for well-known addresses
            let result = match hostname {
                "localhost" => Some([127, 0, 0, 1]),
                "gateway" | "router" => Some([10, 0, 2, 2]),
                _ => None,
            };
            
            if let Some(ip) = result {
                output.push_str(&format!("Name:    {}\n", hostname));
                output.push_str(&format!("Address: {}.{}.{}.{}\n",
                    ip[0], ip[1], ip[2], ip[3]));
            } else {
                output.push_str(&format!("DNS resolution error: {}\n", e));
                output.push_str("DNS server may not be configured.\n");
                output.push_str("Try 'dhcp discover' to obtain network configuration.\n");
            }
        }
    }
    
    CommandResult::Output(output)
}

fn cmd_dhcp(_shell: &mut Shell, args: &[&str]) -> CommandResult {
    let action = args.first().unwrap_or(&"status");
    
    let mut output = String::new();
    
    match *action {
        "discover" => {
            output.push_str("DHCP: Sending DISCOVER broadcast...\n");
            
            match crate::net::dhcp_discover() {
                Ok(offer) => {
                    output.push_str(&format!("DHCP OFFER received:\n"));
                    output.push_str(&format!("  Your IP:     {}.{}.{}.{}\n",
                        offer.your_ip[0], offer.your_ip[1], 
                        offer.your_ip[2], offer.your_ip[3]));
                    output.push_str(&format!("  Server IP:   {}.{}.{}.{}\n",
                        offer.server_ip[0], offer.server_ip[1],
                        offer.server_ip[2], offer.server_ip[3]));
                    if let Some(gw) = offer.gateway {
                        output.push_str(&format!("  Gateway:     {}.{}.{}.{}\n",
                            gw[0], gw[1], gw[2], gw[3]));
                    }
                    if let Some(dns) = offer.dns {
                        output.push_str(&format!("  DNS:         {}.{}.{}.{}\n",
                            dns[0], dns[1], dns[2], dns[3]));
                    }
                    output.push_str("\nUse 'dhcp request' to accept this offer.\n");
                }
                Err(e) => {
                    output.push_str(&format!("DHCP DISCOVER failed: {}\n", e));
                    output.push_str("No DHCP server found on the network.\n");
                }
            }
        }
        "request" => {
            output.push_str("DHCP: Sending REQUEST...\n");
            
            match crate::net::dhcp_request() {
                Ok(ack) => {
                    output.push_str("DHCP ACK received - IP address bound!\n");
                    output.push_str(&format!("  Assigned IP: {}.{}.{}.{}\n",
                        ack.your_ip[0], ack.your_ip[1],
                        ack.your_ip[2], ack.your_ip[3]));
                    output.push_str(&format!("  Lease time:  {} seconds\n", ack.lease_time));
                    output.push_str("\nNetwork configuration updated.\n");
                }
                Err(e) => {
                    output.push_str(&format!("DHCP REQUEST failed: {}\n", e));
                }
            }
        }
        "release" => {
            output.push_str("DHCP: Releasing IP address...\n");
            crate::net::dhcp_release();
            output.push_str("IP address released.\n");
        }
        "status" | _ => {
            output.push_str("DHCP Client Status:\n");
            if let Some(state) = crate::net::get_dhcp_state() {
                output.push_str(&format!("  State:      {}\n", state.state));
                if let Some(ip) = state.assigned_ip {
                    output.push_str(&format!("  IP Address: {}.{}.{}.{}\n",
                        ip[0], ip[1], ip[2], ip[3]));
                }
                if let Some(lease) = state.lease_remaining {
                    output.push_str(&format!("  Lease:      {} seconds remaining\n", lease));
                }
            } else {
                output.push_str("  State:      NOT CONFIGURED\n");
                output.push_str("  Use 'dhcp discover' to obtain IP address\n");
            }
        }
    }
    
    CommandResult::Output(output)
}

fn cmd_arp(_shell: &mut Shell, args: &[&str]) -> CommandResult {
    let show_all = args.contains(&"-a");
    let _ = show_all; // ARP always shows all entries
    
    let mut output = String::new();
    output.push_str("Address                  HWaddress           Flags\n");
    
    // Get ARP cache from network stack
    if let Some(entries) = crate::net::get_arp_cache() {
        for entry in entries {
            output.push_str(&format!(
                "{:<24} {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}  {}\n",
                format!("{}.{}.{}.{}", 
                    entry.ip[0], entry.ip[1], entry.ip[2], entry.ip[3]),
                entry.mac[0], entry.mac[1], entry.mac[2],
                entry.mac[3], entry.mac[4], entry.mac[5],
                if entry.complete { "C" } else { "I" }
            ));
        }
    } else {
        // Demo entries
        output.push_str("10.0.2.2                 52:55:0a:00:02:02   C\n");
        output.push_str("10.0.2.3                 52:55:0a:00:02:03   C\n");
    }
    
    CommandResult::Output(output)
}

// ============================================================================
// Shell Runner (for console integration)
// ============================================================================

/// シェルランナー（対話モード）
pub struct ShellRunner {
    shell: Shell,
    input_buffer: String,
    cursor_pos: usize,
}

impl ShellRunner {
    /// 新しいシェルランナーを作成
    pub fn new() -> Self {
        Self {
            shell: Shell::new(),
            input_buffer: String::new(),
            cursor_pos: 0,
        }
    }

    /// プロンプトを表示
    pub fn prompt(&self) -> &str {
        self.shell.prompt()
    }

    /// 入力バッファを取得
    pub fn input(&self) -> &str {
        &self.input_buffer
    }

    /// キー入力を処理
    pub fn handle_key(&mut self, key: char) -> Option<String> {
        match key {
            '\n' | '\r' => {
                // Enter: コマンド実行
                let line = core::mem::take(&mut self.input_buffer);
                self.cursor_pos = 0;

                let result = self.shell.execute(&line);
                let output = match result {
                    CommandResult::Success => String::new(),
                    CommandResult::Output(s) => s,
                    CommandResult::Error(s) => format!("Error: {}\n", s),
                    CommandResult::Exit(_) => String::from("Goodbye!\n"),
                    CommandResult::ChangeDir(_) => String::new(),
                };

                Some(output)
            }
            '\x08' | '\x7F' => {
                // Backspace
                if self.cursor_pos > 0 {
                    self.cursor_pos -= 1;
                    self.input_buffer.remove(self.cursor_pos);
                }
                None
            }
            '\t' => {
                // Tab: 補完
                let completions = self.shell.complete(&self.input_buffer);
                if completions.len() == 1 {
                    self.input_buffer = completions[0].clone();
                    self.cursor_pos = self.input_buffer.len();
                }
                // 複数候補がある場合は何もしない（TODO: 候補を表示）
                None
            }
            c if c.is_ascii() && !c.is_control() => {
                // 通常文字
                self.input_buffer.insert(self.cursor_pos, c);
                self.cursor_pos += 1;
                None
            }
            _ => None,
        }
    }

    /// シェルが実行中か
    pub fn is_running(&self) -> bool {
        self.shell.is_running()
    }

    /// カレントディレクトリを取得
    pub fn cwd(&self) -> &str {
        self.shell.cwd()
    }
}

// ============================================================================
// Global Shell Instance
// ============================================================================

/// グローバルシェルインスタンス
static SHELL: Mutex<Option<ShellRunner>> = Mutex::new(None);

/// シェルを初期化
pub fn init() {
    *SHELL.lock() = Some(ShellRunner::new());
    crate::log!("[SHELL] Shell initialized\n");
}

/// シェルにアクセス
pub fn with_shell<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut ShellRunner) -> R,
{
    let mut guard = SHELL.lock();
    guard.as_mut().map(f)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_echo() {
        let mut shell = Shell::new();
        let result = shell.execute("echo hello world");
        match result {
            CommandResult::Output(s) => assert_eq!(s, "hello world\n"),
            _ => panic!("Expected output"),
        }
    }

    #[test]
    fn test_shell_pwd() {
        let mut shell = Shell::new();
        let result = shell.execute("pwd");
        match result {
            CommandResult::Output(s) => assert_eq!(s, "/\n"),
            _ => panic!("Expected output"),
        }
    }

    #[test]
    fn test_shell_cd() {
        let mut shell = Shell::new();
        let result = shell.execute("cd /home");
        assert!(matches!(result, CommandResult::ChangeDir(ref p) if p == "/home"));
    }

    #[test]
    fn test_variable_expansion() {
        let mut shell = Shell::new();
        shell.set_env("TEST", "value");
        let result = shell.execute("echo $TEST");
        match result {
            CommandResult::Output(s) => assert_eq!(s, "value\n"),
            _ => panic!("Expected output"),
        }
    }
}
