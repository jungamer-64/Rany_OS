// ============================================================================
// src/application/browser/script/shell_bridge/runtime.rs - Shell Runtime
// ============================================================================
//!
//! ExoShell用のRustScriptランタイム

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::collections::BTreeMap;

use crate::application::browser::script::{ScriptRuntime, ScriptError, ScriptResult, ScriptValue};
use crate::application::browser::script::value::{PromiseValue, PromiseState};

use super::types::{ShellCommandFn, AsyncShellCommandFn, TaskId, AsyncTask, AsyncState};
use super::commands::*;
use super::async_commands::*;
use super::completion::{CompletionHint, CompletionCategory, BUILTIN_FUNCTIONS, KEYWORDS, generate_help};

// ============================================================================
// Shell Runtime Structure
// ============================================================================

/// ExoShell用のRustScriptランタイム
/// 
/// シェル操作に特化したランタイム環境を提供し、
/// ファイルシステム、プロセス、ネットワークなどのOS操作関数を登録する
pub struct ShellRuntime {
    /// スクリプトランタイム
    runtime: ScriptRuntime,
    /// カレントディレクトリ
    cwd: String,
    /// 環境変数
    env: BTreeMap<String, String>,
    /// シェル変数
    shell_vars: BTreeMap<String, ScriptValue>,
    /// 最後のコマンド結果
    last_result: Option<ScriptValue>,
    /// 最後の終了コード
    last_exit_code: i32,
    /// 登録されたシェルコマンド（同期）
    commands: BTreeMap<String, ShellCommandFn>,
    /// 登録された非同期シェルコマンド
    async_commands: BTreeMap<String, AsyncShellCommandFn>,
    /// 非同期タスクキュー
    pending_tasks: BTreeMap<TaskId, AsyncTask>,
    /// 次のタスクID
    next_task_id: TaskId,
    /// 現在のtick（時刻）
    current_tick: u64,
}

// ============================================================================
// Shell Runtime Implementation
// ============================================================================

impl ShellRuntime {
    /// 新しいシェルランタイムを作成
    pub fn new() -> Self {
        let runtime = ScriptRuntime::new();
        let mut shell = Self {
            runtime,
            cwd: String::from("/"),
            env: BTreeMap::new(),
            shell_vars: BTreeMap::new(),
            last_result: None,
            last_exit_code: 0,
            commands: BTreeMap::new(),
            async_commands: BTreeMap::new(),
            pending_tasks: BTreeMap::new(),
            next_task_id: 1,
            current_tick: 0,
        };
        
        // OS操作のネイティブ関数を登録
        shell.register_builtin_commands();
        shell.register_async_commands();
        shell
    }

    /// ビルトインコマンドを登録
    fn register_builtin_commands(&mut self) {
        // ファイルシステム関数
        self.commands.insert(String::from("fs_ls"), cmd_fs_ls);
        self.commands.insert(String::from("fs_read"), cmd_fs_read);
        self.commands.insert(String::from("fs_write"), cmd_fs_write);
        self.commands.insert(String::from("fs_stat"), cmd_fs_stat);
        self.commands.insert(String::from("fs_mkdir"), cmd_fs_mkdir);
        self.commands.insert(String::from("fs_rm"), cmd_fs_rm);
        
        // プロセス関数
        self.commands.insert(String::from("ps"), cmd_ps);
        
        // ネットワーク関数
        self.commands.insert(String::from("net_config"), cmd_net_config);
        self.commands.insert(String::from("net_connections"), cmd_net_connections);
        
        // システム情報関数
        self.commands.insert(String::from("uptime"), cmd_uptime);
        self.commands.insert(String::from("memory_info"), cmd_memory_info);
        
        // ユーティリティ関数
        self.commands.insert(String::from("type_of"), cmd_type_of);
        self.commands.insert(String::from("len"), cmd_len);
    }

    /// 非同期コマンドを登録
    fn register_async_commands(&mut self) {
        // 非同期ファイルシステム関数
        self.async_commands.insert(String::from("fs_ls_async"), cmd_fs_ls_async);
        self.async_commands.insert(String::from("fs_read_async"), cmd_fs_read_async);
        self.async_commands.insert(String::from("fs_write_async"), cmd_fs_write_async);
        
        // 非同期ネットワーク関数
        self.async_commands.insert(String::from("net_ping"), cmd_net_ping);
        self.async_commands.insert(String::from("net_fetch"), cmd_net_fetch);
        
        // スリープ/遅延関数
        self.async_commands.insert(String::from("sleep"), cmd_sleep);
    }

    /// コマンドを実行（同期）
    pub fn execute_command(&mut self, name: &str, args: &[ScriptValue]) -> ScriptResult<ScriptValue> {
        if let Some(cmd) = self.commands.get(name) {
            let result = cmd(args)?;
            self.last_result = Some(result.clone());
            self.last_exit_code = 0;
            Ok(result)
        } else {
            // コマンドが見つからない場合はRustScriptとして評価
            self.eval(&alloc::format!("{}()", name))
        }
    }

    /// 非同期コマンドを開始（タスクIDを返す）
    pub fn start_async_command(&mut self, name: &str, args: &[ScriptValue]) -> ScriptResult<TaskId> {
        if self.async_commands.contains_key(name) {
            let task_id = self.next_task_id;
            self.next_task_id += 1;
            
            let task = AsyncTask {
                id: task_id,
                name: name.to_string(),
                state: AsyncState::Pending,
                created_at: self.current_tick,
            };
            
            self.pending_tasks.insert(task_id, task);
            
            // 非同期コマンドを実行開始
            // 注: 実際のFutureの実行はAsyncExecutorで行う
            let _ = args;
            
            Ok(task_id)
        } else {
            Err(ScriptError::runtime(&alloc::format!("Unknown async command: {}", name)))
        }
    }

    /// 非同期タスクの状態を確認
    pub fn check_task(&self, task_id: TaskId) -> Option<&AsyncState> {
        self.pending_tasks.get(&task_id).map(|t| &t.state)
    }

    /// 非同期タスクを完了させる（結果を設定）
    pub fn complete_task(&mut self, task_id: TaskId, result: ScriptValue) {
        if let Some(task) = self.pending_tasks.get_mut(&task_id) {
            task.state = AsyncState::Ready(result);
        }
    }

    /// 非同期タスクをエラーで完了させる
    pub fn fail_task(&mut self, task_id: TaskId, error: &str) {
        if let Some(task) = self.pending_tasks.get_mut(&task_id) {
            task.state = AsyncState::Error(error.to_string());
        }
    }

    /// 完了したタスクの結果を取得（タスクを削除）
    pub fn take_task_result(&mut self, task_id: TaskId) -> Option<ScriptResult<ScriptValue>> {
        if let Some(task) = self.pending_tasks.get(&task_id) {
            match &task.state {
                AsyncState::Ready(value) => {
                    let result = Ok(value.clone());
                    self.pending_tasks.remove(&task_id);
                    Some(result)
                }
                AsyncState::Error(msg) => {
                    let result = Err(ScriptError::runtime(msg));
                    self.pending_tasks.remove(&task_id);
                    Some(result)
                }
                AsyncState::Pending => None,
            }
        } else {
            None
        }
    }

    /// 保留中の全タスクを取得
    pub fn pending_tasks(&self) -> Vec<&AsyncTask> {
        self.pending_tasks.values()
            .filter(|t| matches!(t.state, AsyncState::Pending))
            .collect()
    }

    /// タイマーを進める
    pub fn tick(&mut self, delta: u64) {
        self.current_tick += delta;
    }

    /// 現在のtickを取得
    pub fn current_tick(&self) -> u64 {
        self.current_tick
    }

    /// コードを評価
    pub fn eval(&mut self, source: &str) -> ScriptResult<ScriptValue> {
        let result = self.runtime.execute(source)?;
        self.last_result = Some(result.clone());
        self.last_exit_code = 0;
        Ok(result)
    }

    /// 複数文を実行
    pub fn execute(&mut self, source: &str) -> ScriptResult<ScriptValue> {
        self.eval(source)
    }

    /// 変数を設定
    pub fn set_var(&mut self, name: &str, value: ScriptValue) {
        self.shell_vars.insert(name.to_string(), value.clone());
        self.runtime.set_global(name, value);
    }

    /// 変数を取得
    pub fn get_var(&self, name: &str) -> Option<ScriptValue> {
        self.shell_vars.get(name).cloned()
    }

    /// 環境変数を設定
    pub fn set_env(&mut self, name: &str, value: &str) {
        self.env.insert(name.to_string(), value.to_string());
        self.runtime.set_global(name, ScriptValue::String(value.to_string()));
    }

    /// 環境変数を取得
    pub fn get_env(&self, name: &str) -> Option<&String> {
        self.env.get(name)
    }

    /// カレントディレクトリを設定
    pub fn set_cwd(&mut self, path: &str) {
        self.cwd = path.to_string();
        self.runtime.set_global("PWD", ScriptValue::String(path.to_string()));
    }

    /// カレントディレクトリを取得
    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    /// 最後の結果を取得
    pub fn last_result(&self) -> Option<&ScriptValue> {
        self.last_result.as_ref()
    }

    /// 最後の終了コードを取得
    pub fn last_exit_code(&self) -> i32 {
        self.last_exit_code
    }

    /// ランタイムへの参照を取得
    pub fn runtime(&mut self) -> &mut ScriptRuntime {
        &mut self.runtime
    }

    /// 入力に対する補完候補を取得
    pub fn complete(&self, input: &str) -> Vec<CompletionHint> {
        let mut hints = Vec::new();
        
        // 組み込み関数
        for (name, desc) in BUILTIN_FUNCTIONS.iter() {
            if name.starts_with(input) {
                hints.push(CompletionHint {
                    text: name.to_string(),
                    description: desc.to_string(),
                    category: CompletionCategory::Function,
                });
            }
        }
        
        // キーワード
        for kw in KEYWORDS.iter() {
            if kw.starts_with(input) {
                hints.push(CompletionHint {
                    text: kw.to_string(),
                    description: String::from("Keyword"),
                    category: CompletionCategory::Keyword,
                });
            }
        }
        
        // シェル変数
        for (name, _) in self.shell_vars.iter() {
            if name.starts_with(input) || alloc::format!("${}", name).starts_with(input) {
                hints.push(CompletionHint {
                    text: alloc::format!("${}", name),
                    description: String::from("Variable"),
                    category: CompletionCategory::Variable,
                });
            }
        }
        
        hints
    }

    /// ヘルプメッセージを生成
    pub fn help(&self) -> ScriptValue {
        generate_help()
    }

    /// Promiseを作成（非同期操作の開始）
    pub fn create_promise(&mut self, task_id: TaskId) -> ScriptValue {
        ScriptValue::Promise(PromiseValue::new(task_id))
    }

    /// Promiseを解決（完了）
    pub fn resolve_promise(&mut self, promise: &mut PromiseValue, value: ScriptValue) {
        promise.state = PromiseState::Fulfilled;
        promise.value = Some(alloc::boxed::Box::new(value));
    }

    /// Promiseを拒否（エラー）
    pub fn reject_promise(&mut self, promise: &mut PromiseValue, error: &str) {
        promise.state = PromiseState::Rejected;
        promise.error = Some(error.to_string());
    }

    /// 非同期コマンドを実行してPromiseを返す
    pub fn spawn_async(&mut self, name: &str, args: &[ScriptValue]) -> ScriptResult<ScriptValue> {
        if self.async_commands.contains_key(name) {
            let task_id = self.start_async_command(name, args)?;
            Ok(self.create_promise(task_id))
        } else {
            Err(ScriptError::runtime(&alloc::format!("Unknown async command: {}", name)))
        }
    }
}

impl Default for ShellRuntime {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_runtime_creation() {
        let _runtime = ShellRuntime::new();
    }

    #[test]
    fn test_eval_simple_expression() {
        let mut runtime = ShellRuntime::new();
        let result = runtime.eval("1 + 2");
        assert!(result.is_ok());
    }

    #[test]
    fn test_variable_setting() {
        let mut runtime = ShellRuntime::new();
        runtime.set_var("x", ScriptValue::Int(42));
        let result = runtime.get_var("x");
        assert!(result.is_some());
    }

    #[test]
    fn test_completion_hints() {
        let runtime = ShellRuntime::new();
        let hints = runtime.complete("fs_");
        assert!(!hints.is_empty());
    }

    #[test]
    fn test_async_task_management() {
        let mut runtime = ShellRuntime::new();
        
        // タスクを開始
        let task_id = runtime.start_async_command("fs_ls_async", &[]).unwrap();
        assert_eq!(task_id, 1);
        
        // 状態を確認
        let state = runtime.check_task(task_id);
        assert!(matches!(state, Some(AsyncState::Pending)));
        
        // タスクを完了
        runtime.complete_task(task_id, ScriptValue::Bool(true));
        
        // 結果を取得
        let result = runtime.take_task_result(task_id);
        assert!(result.is_some());
    }
}
