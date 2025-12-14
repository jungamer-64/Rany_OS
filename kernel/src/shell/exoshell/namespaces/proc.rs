// ============================================================================
// src/shell/exoshell/namespaces/proc.rs - Process Namespace
// ============================================================================

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::{BoxFuture, ShellNamespace};
use crate::security::capability::CAP_KILL;
use crate::shell::exoshell::types::*;
use alloc::boxed::Box;

/// プロセス/タスク名前空間
pub struct ProcNamespace;

impl ProcNamespace {
    /// 実行中のタスク一覧
    pub fn list() -> ExoValue<'static> {
        let processes = kernel_api::services::kernel()
            .shell()
            .map(|s| s.list_processes())
            .unwrap_or_default();

        let result: Vec<ExoValue<'static>> = processes.into_iter().map(|p| {
            let state = match p.state {
                kernel_api::shell::ProcessState::Running => ProcessState::Running,
                kernel_api::shell::ProcessState::Sleeping => ProcessState::Sleeping,
                kernel_api::shell::ProcessState::Blocked => ProcessState::Blocked,
                kernel_api::shell::ProcessState::Stopped => ProcessState::Stopped,
                kernel_api::shell::ProcessState::Zombie => ProcessState::Zombie,
            };
            ExoValue::Process(ProcessInfo {
                pid: p.pid as u32,
                name: p.name,
                state,
                cpu_usage: p.cpu_usage,
                memory_kb: p.memory_kb as u64,
                domain: p.domain,
            })
        }).collect();

        ExoValue::Array(result)
    }

    /// 特定プロセスの情報
    pub fn info(pid: u32) -> ExoValue<'static> {
        let process = kernel_api::services::kernel()
            .shell()
            .and_then(|s| s.get_process(pid as u64));

        if let Some(p) = process {
            let state = match p.state {
                kernel_api::shell::ProcessState::Running => ProcessState::Running,
                kernel_api::shell::ProcessState::Sleeping => ProcessState::Sleeping,
                kernel_api::shell::ProcessState::Blocked => ProcessState::Blocked,
                kernel_api::shell::ProcessState::Stopped => ProcessState::Stopped,
                kernel_api::shell::ProcessState::Zombie => ProcessState::Zombie,
            };
            ExoValue::Process(ProcessInfo {
                pid: p.pid as u32,
                name: p.name,
                state,
                cpu_usage: p.cpu_usage,
                memory_kb: p.memory_kb as u64,
                domain: p.domain,
            })
        } else {
            ExoValue::Error(alloc::format!("Process {} not found", pid))
        }
    }

    /// プロセスを終了（シグナル送信）
    /// Requires owner or CAP_KILL
    fn kill_with_caps(pid: u32, _signal: i32, caps: &crate::security::CapabilitySet) -> ExoValue<'static> {
        if let Some(shell) = kernel_api::services::kernel().shell() {
            let caller_uid = shell.current_uid();
            let has_cap_kill = caps.has_capability(CAP_KILL);
            
            match shell.kill_process(pid as u64, caller_uid, has_cap_kill) {
                Ok(()) => ExoValue::Bool(true),
                Err(e) => ExoValue::Error(String::from(e)),
            }
        } else {
            ExoValue::Error(String::from("Shell services unavailable"))
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
        caps: &'a crate::security::CapabilitySet,
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
                    Self::kill_with_caps(pid, 9, caps)
                }
                _ => ExoValue::Error(format!(
                    "Unknown method 'proc.{}'\nValid methods: list, info, kill",
                    method
                )),
            }
        })
    }
}
