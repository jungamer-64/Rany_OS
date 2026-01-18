// ============================================================================
// src/shell/exoshell/namespaces/proc.rs - Domain Namespace
// ============================================================================

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::{BoxFuture, ShellNamespace};
use crate::security::capability::CAP_KILL;
use crate::shell::exoshell::types::*;
use alloc::boxed::Box;

/// ドメイン/タスク名前空間
pub struct ProcNamespace;

impl ProcNamespace {
    /// 実行中のタスク一覧
    pub fn list() -> ExoValue<'static> {
        let domains = kernel_api::services::kernel()
            .shell()
            .map(|s| s.list_domains())
            .unwrap_or_default();

        let result: Vec<ExoValue<'static>> = domains
            .into_iter()
            .map(|d| {
                let state = match d.state {
                    kernel_api::shell::DomainState::Initializing => DomainState::Initializing,
                    kernel_api::shell::DomainState::Running => DomainState::Running,
                    kernel_api::shell::DomainState::Suspended => DomainState::Suspended,
                    kernel_api::shell::DomainState::Stopped => DomainState::Stopped,
                    kernel_api::shell::DomainState::Terminated => DomainState::Terminated,
                };
                ExoValue::Domain(DomainInfo {
                    id: d.id,
                    name: d.name,
                    state,
                    tasks: d.tasks,
                    memory_kb: d.memory_kb as u64,
                    rrefs: d.rrefs,
                    last_error: d.last_error,
                })
            })
            .collect();

        ExoValue::Array(result)
    }

    /// 特定ドメインの情報
    pub fn info(id: u64) -> ExoValue<'static> {
        let domain = kernel_api::services::kernel()
            .shell()
            .and_then(|s| s.get_domain(id));

        if let Some(d) = domain {
            let state = match d.state {
                kernel_api::shell::DomainState::Initializing => DomainState::Initializing,
                kernel_api::shell::DomainState::Running => DomainState::Running,
                kernel_api::shell::DomainState::Suspended => DomainState::Suspended,
                kernel_api::shell::DomainState::Stopped => DomainState::Stopped,
                kernel_api::shell::DomainState::Terminated => DomainState::Terminated,
            };
            ExoValue::Domain(DomainInfo {
                id: d.id,
                name: d.name,
                state,
                tasks: d.tasks,
                memory_kb: d.memory_kb as u64,
                rrefs: d.rrefs,
                last_error: d.last_error,
            })
        } else {
            ExoValue::Error(alloc::format!("Domain {} not found", id))
        }
    }

    /// ドメインを終了
    /// Requires owner or CAP_KILL
    fn terminate_with_caps(
        id: u64,
        caps: &crate::security::CapabilitySet,
    ) -> ExoValue<'static> {
        if let Some(shell) = kernel_api::services::kernel().shell() {
            let caller = shell.current_domain();
            let has_cap_kill = caps.has_capability(CAP_KILL);

            if caller != id && !has_cap_kill {
                return ExoValue::Error(String::from(
                    "Permission denied: owner or CAP_KILL required",
                ));
            }

            match shell.terminate_domain(id) {
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
                    let id = args
                        .first()
                        .and_then(|v| match v {
                            ExoValue::Int(n) => Some(*n as u64),
                            _ => None,
                        })
                        .unwrap_or(0);
                    Self::info(id)
                }
                "kill" => {
                    let id = args
                        .first()
                        .and_then(|v| match v {
                            ExoValue::Int(n) => Some(*n as u64),
                            _ => None,
                        })
                        .unwrap_or(0);
                    Self::terminate_with_caps(id, caps)
                }
                _ => ExoValue::Error(format!(
                    "Unknown method 'proc.{}'\nValid methods: list, info, kill",
                    method
                )),
            }
        })
    }
}
