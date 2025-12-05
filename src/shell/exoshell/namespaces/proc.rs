// ============================================================================
// src/shell/exoshell/namespaces/proc.rs - Process Namespace
// ============================================================================

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::shell::exoshell::types::*;

/// プロセス/タスク名前空間
pub struct ProcNamespace;

impl ProcNamespace {
    /// 実行中のタスク一覧
    pub fn list() -> ExoValue {
        // TODO: 実際のタスクマネージャと連携
        let processes = vec![
            ProcessInfo {
                pid: 0,
                name: String::from("kernel"),
                state: ProcessState::Running,
                cpu_usage: 0.1,
                memory_kb: 4096,
                domain: String::from("kernel"),
            },
            ProcessInfo {
                pid: 1,
                name: String::from("shell"),
                state: ProcessState::Running,
                cpu_usage: 0.5,
                memory_kb: 1024,
                domain: String::from("user"),
            },
        ];
        
        ExoValue::Array(
            processes
                .into_iter()
                .map(ExoValue::Process)
                .collect()
        )
    }

    /// 特定プロセスの情報
    pub fn info(pid: u32) -> ExoValue {
        // TODO: 実際のプロセス情報を取得
        if pid == 0 {
            ExoValue::Process(ProcessInfo {
                pid: 0,
                name: String::from("kernel"),
                state: ProcessState::Running,
                cpu_usage: 0.1,
                memory_kb: 4096,
                domain: String::from("kernel"),
            })
        } else {
            ExoValue::Error(alloc::format!("Process {} not found", pid))
        }
    }
}
