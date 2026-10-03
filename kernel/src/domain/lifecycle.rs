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
use crate::domain::{DomainId, DomainState, set_domain_state, with_domain, with_domain_mut};
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
}

impl core::fmt::Display for DomainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DomainError::NotFound => write!(f, "Domain not found"),
            DomainError::AlreadyStopped => write!(f, "Domain already stopped"),
            DomainError::DependencyError(msg) => write!(f, "Dependency error: {}", msg),
            DomainError::Panicked(msg) => write!(f, "Domain panicked: {}", msg),
            DomainError::Policy(error) => write!(f, "{error}"),
        }
    }
}

/// ドメインがパニックした場合の処理
/// カスタムパニックハンドラから呼ばれる
///
/// `domain::handle_domain_panic()` に委譲する。
pub fn handle_domain_panic(domain_id: DomainId, message: String) {
    crate::domain::handle_domain_panic(domain_id, message);
}

/// ドメインを再起動
pub fn restart_domain(domain_id: DomainId) -> Result<(), DomainError> {
    // ドメインの状態を確認
    let state = with_domain(domain_id, |d| d.state);

    match state {
        Some(DomainState::Stopped) | Some(DomainState::Terminated) => {
            if state == Some(DomainState::Terminated) {
                let policy = with_domain(domain_id, |domain| {
                    crate::domain::registry::domain_quota_policy(
                        domain_id,
                        domain.priority,
                        domain.cpu_limit_percent,
                        domain.memory_limit_bytes,
                        domain.io_bandwidth_limit,
                    )
                })
                .ok_or(DomainError::NotFound)?;
                // Metadata acquisition runs outside the domain registry lock.
                // Retained credits/bindings reject re-admission of this identity.
                crate::domain::quota_manager()
                    .register(policy)
                    .map_err(|error| {
                        DomainError::Policy(crate::domain::DomainPolicyError::Quota(error))
                    })?;
            }
            set_domain_state(domain_id, DomainState::Initializing).map_err(DomainError::Policy)?;

            // ドメインの状態をリセット
            with_domain_mut(domain_id, |domain| {
                // エラー状態をクリア
                domain.panic_message = None;
                domain.terminated_dependency = None;
                // タスクリストをクリア（新しいタスクがスポーンされる）
                domain.tasks.clear();
                // 統計情報はリセットしない（累積）
            });

            // 注意: 現在のDomain設計ではエントリポイントやバイナリ情報を
            // 保持していないため、完全な再ロードはできません。
            // ドメインの再起動は、外部から新しいタスクをスポーンする
            // 必要があります。例：
            //   restart_domain(id)?;
            //   spawn_domain_task_by_id(id, init_future)?;
            //
            // 将来的にはDomain構造体にentry_pointを追加し、
            // 自動的に初期化タスクを再スポーンできるようにする。

            log::info!(
                "[LIFECYCLE] Domain {} restarted (awaiting task spawn)\n",
                domain_id.as_u64()
            );

            set_domain_state(domain_id, DomainState::Running).map_err(DomainError::Policy)?;
            Ok(())
        }
        Some(_) => Err(DomainError::AlreadyStopped),
        None => Err(DomainError::NotFound),
    }
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
    use crate::domain::create_domain;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_domain_lifecycle() {
        // ドメイン作成
        let id = create_domain("test_domain".into()).expect("create_domain failed");

        // 状態確認
        let state = with_domain(id, |d| d.state);
        assert_eq!(state, Some(DomainState::Initializing));

        // 状態変更
        set_domain_state(id, DomainState::Running).expect("domain state admission");
        let state = with_domain(id, |d| d.state);
        assert_eq!(state, Some(DomainState::Running));

        // 終了
        let result = crate::domain::terminate_domain(id);
        assert!(result.is_ok());
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn restart_waits_for_retained_quota_return_rights() {
        let id = create_domain("retained_restart".into()).unwrap();
        let binding = crate::domain::quota_manager().bind_memory(id).unwrap();
        let credit = binding.reserve(123).unwrap();
        crate::domain::terminate_domain(id).unwrap();
        assert!(matches!(
            restart_domain(id),
            Err(DomainError::Policy(
                crate::domain::DomainPolicyError::Quota(
                    crate::domain::quota::QuotaError::Retired { .. }
                )
            ))
        ));
        assert_eq!(
            crate::domain::get_domain_state(id),
            Some(DomainState::Terminated)
        );
        drop(credit);
        drop(binding);
        restart_domain(id).unwrap();
        assert_eq!(
            crate::domain::get_domain_state(id),
            Some(DomainState::Running)
        );
        assert_eq!(
            crate::domain::quota_manager()
                .get_stats(id)
                .unwrap()
                .memory_used,
            0
        );
        crate::domain::terminate_domain(id).unwrap();
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
