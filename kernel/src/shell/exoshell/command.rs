// ============================================================================
// kernel/src/shell/exoshell/command.rs - Command
// ============================================================================


use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::shell::exoshell::error::ExoResult;
use crate::shell::exoshell::types::ExoValue;
use crate::shell::exoshell::ExoShell;

/// トレイト: シェルコマンド
///
/// 汎用的なシェルコマンド（`help`, `exit` など）を実装するためのインターフェース。
pub trait ShellCommand: Send + Sync {
    /// コマンド名を取得
    fn name(&self) -> &str;

    /// コマンドを実行
    fn execute(&self, shell: &mut ExoShell, args: &[ExoValue]) -> ExoResult<ExoValue<'static>>;

    /// ヘルプテキストを取得
    fn help(&self) -> &str;
}

/// コマンドレジストリ
pub struct CommandRegistry {
    commands: BTreeMap<String, Arc<dyn ShellCommand>>,
}

impl CommandRegistry {
    pub fn new() -> Self {
        Self {
            commands: BTreeMap::new(),
        }
    }

    /// コマンドを登録
    pub fn register(&mut self, cmd: impl ShellCommand + 'static) {
        let name = cmd.name().to_string();
        self.commands.insert(name, Arc::new(cmd));
    }
    
    /// コマンドを取得
    pub fn get(&self, name: &str) -> Option<Arc<dyn ShellCommand>> {
        self.commands.get(name).cloned()
    }

    /// 登録済みコマンド一覧を取得
    pub fn list(&self) -> Vec<&str> {
        self.commands.keys().map(|k: &String| k.as_str()).collect()
    }
}

// ============================================================================
// Built-in Commands
// ============================================================================

pub struct HelpCommand;
impl ShellCommand for HelpCommand {
    fn name(&self) -> &str { "help" }
    fn execute(&self, shell: &mut ExoShell, _args: &[ExoValue]) -> ExoResult<ExoValue<'static>> {
        // ExoShell has a help() method, but it returns ExoValue directly.
        // We can reuse it.
        Ok(shell.help())
    }
    fn help(&self) -> &str { "Display available commands and namespaces" }
}

pub struct ExitCommand;
impl ShellCommand for ExitCommand {
    fn name(&self) -> &str { "exit" }
    fn execute(&self, _shell: &mut ExoShell, _args: &[ExoValue]) -> ExoResult<ExoValue<'static>> {
        Ok(ExoValue::Exit)
    }
    fn help(&self) -> &str { "Exit the shell" }
}

pub struct ClearCommand;
impl ShellCommand for ClearCommand {
    fn name(&self) -> &str { "clear" }
    fn execute(&self, _shell: &mut ExoShell, _args: &[ExoValue]) -> ExoResult<ExoValue<'static>> {
        Ok(ExoValue::String(alloc::borrow::Cow::Borrowed("\x1b[2J\x1b[H")))
    }
    fn help(&self) -> &str { "Clear the screen" }
}

/// `echo` - 引数を連結して表示
pub struct EchoCommand;
impl ShellCommand for EchoCommand {
    fn name(&self) -> &str { "echo" }
    fn execute(&self, _shell: &mut ExoShell, args: &[ExoValue]) -> ExoResult<ExoValue<'static>> {
        let parts: Vec<String> = args.iter().map(|v| alloc::format!("{}", v)).collect();
        Ok(ExoValue::String(alloc::borrow::Cow::Owned(parts.join(" "))))
    }
    fn help(&self) -> &str { "Print arguments to output" }
}

/// `history` - コマンド履歴を表示
pub struct HistoryCommand;
impl ShellCommand for HistoryCommand {
    fn name(&self) -> &str { "history" }
    fn execute(&self, shell: &mut ExoShell, args: &[ExoValue]) -> ExoResult<ExoValue<'static>> {
        let limit = args.first()
            .and_then(|v| match v {
                ExoValue::Int(n) => Some(*n as usize),
                _ => None,
            })
            .unwrap_or(shell.history_len());
        let history = shell.history();
        let start = history.len().saturating_sub(limit);
        let entries: Vec<ExoValue<'static>> = history[start..]
            .iter()
            .enumerate()
            .map(|(i, cmd)| {
                let mut map = alloc::collections::BTreeMap::new();
                map.insert(
                    String::from("index"),
                    ExoValue::Int((start + i) as i64),
                );
                map.insert(
                    String::from("command"),
                    ExoValue::String(alloc::borrow::Cow::Owned(cmd.clone())),
                );
                ExoValue::Map(map)
            })
            .collect();
        Ok(ExoValue::Array(entries))
    }
    fn help(&self) -> &str { "Show command history. Usage: history [limit]" }
}

/// `env` - 環境変数一覧を表示
pub struct EnvCommand;
impl ShellCommand for EnvCommand {
    fn name(&self) -> &str { "env" }
    fn execute(&self, shell: &mut ExoShell, _args: &[ExoValue]) -> ExoResult<ExoValue<'static>> {
        let vars = shell.env.get_all();
        let mut map = alloc::collections::BTreeMap::new();
        for (k, v) in vars {
            map.insert(k, v);
        }
        Ok(ExoValue::Map(map))
    }
    fn help(&self) -> &str { "Show all defined variables" }
}

/// `type` - 値の型を表示
pub struct TypeCommand;
impl ShellCommand for TypeCommand {
    fn name(&self) -> &str { "type" }
    fn execute(&self, _shell: &mut ExoShell, args: &[ExoValue]) -> ExoResult<ExoValue<'static>> {
        let type_name = match args.first() {
            Some(ExoValue::Nil) => "Nil",
            Some(ExoValue::Bool(_)) => "Bool",
            Some(ExoValue::Int(_)) => "Int",
            Some(ExoValue::Float(_)) => "Float",
            Some(ExoValue::String(_)) => "String",
            Some(ExoValue::Bytes(_)) => "Bytes",
            Some(ExoValue::Array(_)) => "Array",
            Some(ExoValue::Map(_)) => "Map",
            Some(ExoValue::FileEntry(_)) => "FileEntry",
            Some(ExoValue::NetConnection(_)) => "NetConnection",
            Some(ExoValue::Domain(_)) => "Domain",
            Some(ExoValue::Capability(_)) => "Capability",
            Some(ExoValue::Iterator(_)) => "Iterator",
            Some(ExoValue::BufferRef(_)) => "BufferRef",
            Some(ExoValue::StringRef(_)) => "StringRef",
            Some(ExoValue::Error(_)) => "Error",
            Some(ExoValue::Break) => "Break",
            Some(ExoValue::Continue) => "Continue",
            Some(ExoValue::Exit) => "Exit",
            None => "Nil (no argument)",
        };
        Ok(ExoValue::String(alloc::borrow::Cow::Owned(String::from(type_name))))
    }
    fn help(&self) -> &str { "Show the type of a value. Usage: type <expr>" }
}

/// `whoami` - 現在のドメイン/ユーザー情報
pub struct WhoamiCommand;
impl ShellCommand for WhoamiCommand {
    fn name(&self) -> &str { "whoami" }
    fn execute(&self, _shell: &mut ExoShell, _args: &[ExoValue]) -> ExoResult<ExoValue<'static>> {
        let domain_id = kernel_api::services::kernel()
            .shell()
            .map(|s| s.current_domain())
            .unwrap_or(0);
        let mut map = alloc::collections::BTreeMap::new();
        map.insert(String::from("user"), ExoValue::String(alloc::borrow::Cow::Borrowed("root")));
        map.insert(String::from("domain_id"), ExoValue::Int(domain_id as i64));
        map.insert(String::from("privilege"), ExoValue::String(alloc::borrow::Cow::Borrowed("full")));
        Ok(ExoValue::Map(map))
    }
    fn help(&self) -> &str { "Show current user/domain identity" }
}

/// `date` - 現在のシステム時刻
pub struct DateCommand;
impl ShellCommand for DateCommand {
    fn name(&self) -> &str { "date" }
    fn execute(&self, _shell: &mut ExoShell, _args: &[ExoValue]) -> ExoResult<ExoValue<'static>> {
        let ticks = crate::system_info::uptime_ticks();
        let seconds = ticks / 1000;
        let hours = seconds / 3600;
        let minutes = (seconds % 3600) / 60;
        let secs = seconds % 60;
        let mut map = alloc::collections::BTreeMap::new();
        map.insert(
            String::from("uptime"),
            ExoValue::String(alloc::borrow::Cow::Owned(alloc::format!(
                "{}h {}m {}s", hours, minutes, secs
            ))),
        );
        map.insert(String::from("uptime_ms"), ExoValue::Int(ticks as i64));
        map.insert(String::from("uptime_s"), ExoValue::Int(seconds as i64));
        Ok(ExoValue::Map(map))
    }
    fn help(&self) -> &str { "Show system uptime" }
}

/// `set` - 変数を設定
pub struct SetCommand;
impl ShellCommand for SetCommand {
    fn name(&self) -> &str { "set" }
    fn execute(&self, shell: &mut ExoShell, args: &[ExoValue]) -> ExoResult<ExoValue<'static>> {
        if args.len() < 2 {
            return Err(crate::shell::exoshell::error::ShellError::ArgumentError(
                String::from("Usage: set <name> <value>"),
            ));
        }
        let name = match &args[0] {
            ExoValue::String(s) => s.as_ref().to_string(),
            other => alloc::format!("{}", other),
        };
        let value = args[1].clone().into_owned();
        shell.env.define(name, value.clone());
        Ok(value)
    }
    fn help(&self) -> &str { "Set a variable. Usage: set <name> <value>" }
}

/// `unset` - 変数を削除
pub struct UnsetCommand;
impl ShellCommand for UnsetCommand {
    fn name(&self) -> &str { "unset" }
    fn execute(&self, shell: &mut ExoShell, args: &[ExoValue]) -> ExoResult<ExoValue<'static>> {
        if args.is_empty() {
            return Err(crate::shell::exoshell::error::ShellError::ArgumentError(
                String::from("Usage: unset <name>"),
            ));
        }
        let name = match &args[0] {
            ExoValue::String(s) => s.as_ref().to_string(),
            other => alloc::format!("{}", other),
        };
        // Assign Nil to effectively "unset"
        shell.env.define(name, ExoValue::Nil);
        Ok(ExoValue::Bool(true))
    }
    fn help(&self) -> &str { "Remove a variable. Usage: unset <name>" }
}

