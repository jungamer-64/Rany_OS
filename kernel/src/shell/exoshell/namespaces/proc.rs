// ============================================================================
// src/shell/exoshell/namespaces/proc.rs - Process Namespace
// ============================================================================

use alloc::string::String;
use alloc::vec::Vec;

use crate::shell::exoshell::types::*;

/// プロセス/タスク名前空間
pub struct ProcNamespace;

impl ProcNamespace {
    /// 実行中のタスク一覧
    pub fn list() -> ExoValue {
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
        
        ExoValue::Array(
            processes
                .into_iter()
                .map(ExoValue::Process)
                .collect()
        )
    }

    /// 特定プロセスの情報
    pub fn info(pid: u32) -> ExoValue {
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
    pub fn kill(pid: u32, _signal: i32) -> ExoValue {
        if pid == 0 {
            return ExoValue::Error(String::from("Cannot kill kernel process"));
        }
        
        let proc_id = crate::task::ProcessId::new(pid as u64);
        
        if let Some(process) = crate::task::process_manager().get(proc_id) {
            // プロセスを終了状態に設定
            let mut p = process.write();
            p.state = crate::task::ProcessState::Stopped;
            ExoValue::Bool(true)
        } else {
            ExoValue::Error(alloc::format!("Process {} not found", pid))
        }
    }
}
