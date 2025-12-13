// ============================================================================
// src/shell/exoshell/namespaces/proc.rs - Process Namespace
// ============================================================================

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::{BoxFuture, ShellNamespace};
use crate::security::capability::{CAP_KILL, manager};
use crate::shell::exoshell::types::*;
use crate::task::process::{getpid, getuid};
use alloc::boxed::Box;

/// プロセス/タスク名前空間
pub struct ProcNamespace;

impl ProcNamespace {
    /// 実行中のタスク一覧
    pub fn list() -> ExoValue<'static> {
        let mut processes = Vec::new();

        // プロセスマネージャから全プロセスIDを取得して情報を取得
        let pm = crate::task::process_manager();

        // 既知のプロセスIDをチェック（0-100の範囲）
        for pid in 0..100u64 {
            let proc_id = crate::task::ProcessId::new(pid);
            if let Some(process) = pm.get(proc_id) {
                let p = process.read();
                let state = match p.state {
                    crate::task::ProcessState::Running => ProcessState::Running,
                    crate::task::ProcessState::Ready => ProcessState::Running,
                    crate::task::ProcessState::Blocked => ProcessState::Blocked,
                    crate::task::ProcessState::Stopped => ProcessState::Stopped,
                    crate::task::ProcessState::Zombie => ProcessState::Zombie,
                    _ => ProcessState::Sleeping,
                };

                processes.push(ProcessInfo {
                    pid: pid as u32,
                    name: p.name.clone(),
                    state,
                    cpu_usage: 0.0,
                    memory_kb: 0,
                    domain: String::from("user"),
                });
            }
        }

        // プロセスが空の場合はカーネルプロセスを追加
        if processes.is_empty() {
            processes.push(ProcessInfo {
                pid: 0,
                name: String::from("kernel"),
                state: ProcessState::Running,
                cpu_usage: 0.0,
                memory_kb: crate::memory::used_memory_kb(),
                domain: String::from("kernel"),
            });
        }

        ExoValue::Array(processes.into_iter().map(ExoValue::Process).collect())
    }

    /// 特定プロセスの情報
    pub fn info(pid: u32) -> ExoValue<'static> {
        let proc_id = crate::task::ProcessId::new(pid as u64);

        if let Some(process) = crate::task::process_manager().get(proc_id) {
            let p = process.read();
            let state = match p.state {
                crate::task::ProcessState::Running => ProcessState::Running,
                crate::task::ProcessState::Ready => ProcessState::Running,
                crate::task::ProcessState::Blocked => ProcessState::Blocked,
                crate::task::ProcessState::Stopped => ProcessState::Stopped,
                crate::task::ProcessState::Zombie => ProcessState::Zombie,
                _ => ProcessState::Sleeping,
            };

            ExoValue::Process(ProcessInfo {
                pid,
                name: p.name.clone(),
                state,
                cpu_usage: 0.0,
                memory_kb: 0,
                domain: String::from("user"),
            })
        } else if pid == 0 {
            // PID 0 はカーネル
            ExoValue::Process(ProcessInfo {
                pid: 0,
                name: String::from("kernel"),
                state: ProcessState::Running,
                cpu_usage: 0.0,
                memory_kb: crate::memory::used_memory_kb(),
                domain: String::from("kernel"),
            })
        } else {
            ExoValue::Error(alloc::format!("Process {} not found", pid))
        }
    }

    /// プロセスを終了（シグナル送信）
    /// Requires owner or CAP_KILL
    pub fn kill(pid: u32, _signal: i32) -> ExoValue<'static> {
        if pid == 0 {
            return ExoValue::Error(String::from("Cannot kill kernel process"));
        }

        let proc_id = crate::task::ProcessId::new(pid as u64);
        let pm = crate::task::process_manager();

        if let Some(process) = pm.get(proc_id) {
            // 権限チェック
            let current_uid = getuid();
            let target_uid = process.read().credentials.uid;
            let current_pid = getpid().as_u64();

            // 自分のプロセスか、CAP_KILLを持っている場合に許可
            if current_uid != target_uid && !manager().has_capability(current_pid, CAP_KILL) {
                return ExoValue::Error(String::from(
                    "Permission denied: Owner or CAP_KILL required",
                ));
            }

            // プロセスを終了状態に設定
            let mut p = process.write();
            p.state = crate::task::ProcessState::Stopped;
            ExoValue::Bool(true)
        } else {
            ExoValue::Error(alloc::format!("Process {} not found", pid))
        }
    }
}

impl ShellNamespace for ProcNamespace {
    fn name(&self) -> &str {
        "proc"
    }

    fn call<'a>(
        &'a self,
        method: &'a str,
        args: &'a [ExoValue<'static>],
    ) -> BoxFuture<'a, ExoValue<'static>> {
        Box::pin(async move {
            match method {
                "list" | "ps" => Self::list(),
                "info" => {
                    let pid = args
                        .first()
                        .and_then(|v| match v {
                            ExoValue::Int(n) => Some(*n as u32),
                            _ => None,
                        })
                        .unwrap_or(0);
                    Self::info(pid)
                }
                "kill" => {
                    let pid = args
                        .first()
                        .and_then(|v| match v {
                            ExoValue::Int(n) => Some(*n as u32),
                            _ => None,
                        })
                        .unwrap_or(0);
                    Self::kill(pid, 9)
                }
                _ => ExoValue::Error(format!(
                    "Unknown method 'proc.{}'\nValid methods: list, info, kill",
                    method
                )),
            }
        })
    }
}
