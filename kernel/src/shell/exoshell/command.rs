
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::shell::exoshell::error::{ExoResult, ShellError};
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
        self.commands.keys().map(|k| k.as_str()).collect()
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
        // Provide a special string that the frontend can interpret as "clear screen"
        // or just rely on terminal escape codes if we can print them.
        // For now, let's return a string that says [CLEAR].
        // Or specific escape sequence.
        Ok(ExoValue::String(alloc::borrow::Cow::Borrowed("\x1b[2J\x1b[H")))
    }
    fn help(&self) -> &str { "Clear the screen" }
}

