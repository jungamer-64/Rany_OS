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

#![allow(dead_code)]

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

        // トークンに分解
        let tokens = self.parse_line(line);
        if tokens.is_empty() {
            return CommandResult::Success;
        }

        let cmd_name = &tokens[0];
        let args: Vec<&str> = tokens.iter().skip(1).map(|s| s.as_str()).collect();

        // コマンドを検索して実行
        if let Some(cmd) = self.find_command(cmd_name) {
            let handler = cmd.handler;
            let result = handler(self, &args);

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

fn cmd_ls(_shell: &mut Shell, args: &[&str]) -> CommandResult {
    let path = args.first().unwrap_or(&".");

    // TODO: 実際のファイルシステムと連携
    // とりあえずデモ出力
    let output = format!(
        "Contents of {}:\n  bin/\n  dev/\n  etc/\n  home/\n  tmp/\n  var/\n",
        path
    );

    CommandResult::Output(output)
}

fn cmd_cd(shell: &mut Shell, args: &[&str]) -> CommandResult {
    let path = match args.first() {
        Some(&"-") => shell.prev_dir.clone(),
        Some(&"~") | None => shell
            .get_env("HOME")
            .cloned()
            .unwrap_or_else(|| String::from("/")),
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

    // TODO: パスの存在確認
    CommandResult::ChangeDir(path)
}

fn cmd_pwd(shell: &mut Shell, _args: &[&str]) -> CommandResult {
    CommandResult::Output(format!("{}\n", shell.cwd))
}

fn cmd_cat(_shell: &mut Shell, args: &[&str]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::Error(String::from("cat: missing file operand"));
    }

    // TODO: 実際のファイル読み取り
    CommandResult::Output(format!("(content of {})\n", args[0]))
}

fn cmd_mkdir(_shell: &mut Shell, args: &[&str]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::Error(String::from("mkdir: missing operand"));
    }

    // TODO: 実際のディレクトリ作成
    CommandResult::Output(format!("Created directory: {}\n", args[0]))
}

fn cmd_rm(_shell: &mut Shell, args: &[&str]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::Error(String::from("rm: missing operand"));
    }

    // TODO: 実際のファイル削除
    CommandResult::Success
}

fn cmd_cp(_shell: &mut Shell, args: &[&str]) -> CommandResult {
    if args.len() < 2 {
        return CommandResult::Error(String::from("cp: missing operand"));
    }

    // TODO: 実際のファイルコピー
    CommandResult::Success
}

fn cmd_mv(_shell: &mut Shell, args: &[&str]) -> CommandResult {
    if args.len() < 2 {
        return CommandResult::Error(String::from("mv: missing operand"));
    }

    // TODO: 実際のファイル移動
    CommandResult::Success
}

fn cmd_touch(_shell: &mut Shell, args: &[&str]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::Error(String::from("touch: missing operand"));
    }

    // TODO: 実際のファイル作成/更新
    CommandResult::Success
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
