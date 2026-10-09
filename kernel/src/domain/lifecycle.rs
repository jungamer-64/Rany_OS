// ============================================================================
// src/domain/lifecycle.rs - Domain Lifecycle Management
// 設計書 8: フォールトアイソレーションと回復メカニズム
// 設計書 8.1: スタックアンワインドとリソース回収
// ============================================================================
//!
//! # 責務
//!
//! このモジュールは、ドメインのライフサイクル操作を提供する。
//! ドメインのコア管理（作成・レジストリ・状態遷移）は `crate::domain` が担当し、
//! 本モジュールはその上に構築された高レベルライフサイクル操作を提供する。
//!
//! ## `domain` との関係
//!
//! - `handle_domain_panic()` → `domain::handle_domain_panic()` に委譲
//! - `restart_domain()` — 本モジュール固有（再起動ロジック）
//! - `add_domain_dependency()` — 本モジュール固有（依存関係グラフ操作）
//!
use crate::domain::{DomainId, with_domain, with_domain_mut};
use alloc::string::String;

/// ドメイン操作のエラー
#[derive(Debug, Clone)]
pub enum DomainError {
    /// ドメインが見つからない
    NotFound,
    /// ドメインがすでに停止している
    AlreadyStopped,
    /// 依存関係のエラー
    DependencyError(String),
    /// パニックが発生した
    Panicked(String),
    Policy(crate::domain::DomainPolicyError),
    Lifecycle(crate::domain::DomainLifecycleError),
}

impl core::fmt::Display for DomainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DomainError::NotFound => write!(f, "Domain not found"),
            DomainError::AlreadyStopped => write!(f, "Domain already stopped"),
            DomainError::DependencyError(msg) => write!(f, "Dependency error: {}", msg),
            DomainError::Panicked(msg) => write!(f, "Domain panicked: {}", msg),
            DomainError::Policy(error) => write!(f, "{error}"),
            DomainError::Lifecycle(error) => error.fmt(f),
        }
    }
}

/// ドメインを終了させる
/// 設計書 8.1: リソース回収
///
/// `domain::terminate_domain()` に委譲し、エラー型を変換する。
pub fn terminate_domain(domain_id: DomainId) -> Result<(), DomainError> {
    crate::domain::terminate_domain(domain_id).map_err(DomainError::Lifecycle)
}

/// ドメインがパニックした場合の処理
/// カスタムパニックハンドラから呼ばれる
///
/// `domain::handle_domain_panic()` に委譲する。
pub fn handle_domain_panic(domain_id: DomainId, message: String) {
    crate::domain::handle_domain_panic(domain_id, message);
}

/// Reopens a completed stop and clears its failure diagnostics. The retained
/// Futures remain registered; a terminated generation cannot be restarted.
pub fn restart_domain(domain_id: DomainId) -> Result<(), DomainError> {
    super::registry::restart_stopped_domain(domain_id).map_err(DomainError::Lifecycle)
}

/// ドメイン間の依存関係を追加
pub fn add_domain_dependency(dependent: DomainId, dependency: DomainId) -> Result<(), DomainError> {
    // 両方のドメインが存在することを確認
    let dep_exists = with_domain(dependency, |_| true).unwrap_or(false);
    if !dep_exists {
        return Err(DomainError::NotFound);
    }

    // 依存関係を追加
    with_domain_mut(dependent, |domain| {
        domain.add_dependency(dependency);
    });

    with_domain_mut(dependency, |domain| {
        domain.add_dependent(dependent);
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{DomainState, create_domain};

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_domain_lifecycle() {
        // ドメイン作成
        let id = crate::domain::create_domain("test_domain".into()).expect("create_domain failed");

        // 状態確認
        let state = with_domain(id, |d| d.state);
        assert_eq!(state, Some(DomainState::Initializing));

        // 状態変更
        crate::domain::start_domain(id).expect("initializing domain starts");
        let state = with_domain(id, |d| d.state);
        assert_eq!(state, Some(DomainState::Running));

        // 終了
        let result = crate::domain::terminate_domain(id);
        assert!(result.is_ok());
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn completed_stop_preserves_memory_account_and_reclaimed_domain_cannot_restart() {
        let id = create_domain("retained_restart".into()).unwrap();
        let binding = crate::domain::quota_manager().bind_memory(id).unwrap();
        let credit = binding.reserve(123).unwrap();
        assert_eq!(
            crate::domain::stop_domain(id).unwrap(),
            crate::domain::DomainStopOutcome::Complete
        );
        restart_domain(id).unwrap();
        assert_eq!(
            crate::domain::quota_manager()
                .get_stats(id)
                .unwrap()
                .memory_used,
            123
        );
        crate::domain::terminate_domain(id).unwrap();
        assert!(matches!(
            restart_domain(id),
            Err(DomainError::Lifecycle(
                crate::domain::DomainLifecycleError::InvalidState(DomainState::Terminated)
            ))
        ));
        assert!(matches!(
            binding.reserve(1),
            Err(crate::domain::QuotaError::Retired { .. })
        ));
        drop(credit);
        drop(binding);
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn rejected_policy_update_preserves_domain_metadata() {
        let id = create_domain("policy_failure".into()).unwrap();
        crate::domain::set_domain_resource_limits(id, 100, 513, 0).unwrap();
        let binding = crate::domain::quota_manager().bind_memory(id).unwrap();
        let credit = binding.reserve(512).unwrap();
        crate::domain::terminate_domain(id).unwrap();
        assert!(matches!(
            crate::domain::set_domain_resource_limits(id, 50, 19, 0),
            Err(crate::domain::DomainPolicyError::Quota(
                crate::domain::quota::QuotaError::Retired { .. }
            ))
        ));
        assert_eq!(
            crate::domain::get_domain_snapshot(id)
                .unwrap()
                .memory_limit_bytes,
            513
        );
        assert_eq!(
            crate::domain::quota_manager()
                .get_stats(id)
                .unwrap()
                .memory_used,
            512
        );
        drop(credit);
        drop(binding);
    }
}
