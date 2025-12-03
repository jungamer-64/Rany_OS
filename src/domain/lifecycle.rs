// ============================================================================
// src/domain/lifecycle.rs - Domain Lifecycle Management
// 設計書 8: フォールトアイソレーションと回復メカニズム
// 設計書 8.1: スタックアンワインドとリソース回収
// ============================================================================
use super::registry::{
    Domain, DomainState, get_domain, register_domain, set_domain_state, update_domain,
};
use crate::ipc::rref::{DomainId, reclaim_domain_resources};
use crate::task::{Task, TaskId};
use alloc::string::String;
use core::future::Future;
use core::pin::Pin;

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
}

impl core::fmt::Display for DomainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DomainError::NotFound => write!(f, "Domain not found"),
            DomainError::AlreadyStopped => write!(f, "Domain already stopped"),
            DomainError::DependencyError(msg) => write!(f, "Dependency error: {}", msg),
            DomainError::Panicked(msg) => write!(f, "Domain panicked: {}", msg),
        }
    }
}

/// ドメインコンテキスト
/// タスク内で現在のドメインIDを追跡するために使用
#[derive(Debug, Clone, Copy)]
pub struct DomainContext {
    pub domain_id: DomainId,
}

impl DomainContext {
    pub fn new(domain_id: DomainId) -> Self {
        Self { domain_id }
    }
}

/// ドメイン境界でラップされたタスク
/// 設計書 8.1: パニックはドメイン境界で停止する
pub struct DomainTask<F>
where
    F: Future<Output = ()> + Send + 'static,
{
    domain_id: DomainId,
    future: F,
}

impl<F> DomainTask<F>
where
    F: Future<Output = ()> + Send + 'static,
{
    pub fn new(domain_id: DomainId, future: F) -> Self {
        Self { domain_id, future }
    }
}

/// ドメイン内でタスクをスポーン
/// パニック発生時はドメイン境界で捕捉される
pub fn spawn_domain_task<F>(domain_name: &str, future: F) -> Result<(DomainId, Task), DomainError>
where
    F: Future<Output = ()> + Send + 'static,
{
    // 新しいドメインを作成
    let domain_id = register_domain(domain_name.into());
    set_domain_state(domain_id, DomainState::Running);

    // ドメインラッパーでFutureをラップ
    let wrapped_future = domain_wrapper(domain_id, future);

    // タスクを作成
    let task = Task::new(wrapped_future);
    let task_id = task.id.as_u64();

    // ドメインにタスクを登録
    update_domain(domain_id, |domain| {
        domain.add_task(task_id);
    });

    Ok((domain_id, task))
}

/// ドメイン境界でFutureをラップ
/// 設計書 8.2: プロキシパターン - パニックを捕捉してエラーに変換
async fn domain_wrapper<F>(domain_id: DomainId, future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    // 注意: no_std環境ではstd::panic::catch_unwindが使えないため、
    // 実際にはカスタムパニックハンドラと連携する必要がある
    // ここでは概念的な実装を示す

    // タスク開始をログ
    #[cfg(feature = "verbose_logging")]
    crate::log!("[Domain {}] Task started\n", domain_id.as_u64());

    // Futureを実行
    future.await;

    // 正常終了
    #[cfg(feature = "verbose_logging")]
    crate::log!("[Domain {}] Task completed normally\n", domain_id.as_u64());
}

/// ドメインを終了させる
/// 設計書 8.1: リソース回収
pub fn terminate_domain(domain_id: DomainId) -> Result<(), DomainError> {
    // ドメインの存在確認
    let domain_exists = get_domain(domain_id, |_| true).unwrap_or(false);
    if !domain_exists {
        return Err(DomainError::NotFound);
    }

    // 状態を終了中に変更
    set_domain_state(domain_id, DomainState::Terminated);

    // Exchange Heap上のリソースを回収
    reclaim_domain_resources(domain_id);

    // TODO: ドメインに属するタスクを停止
    // TODO: ドメインに依存する他のドメインに通知

    Ok(())
}

/// ドメインがパニックした場合の処理
/// カスタムパニックハンドラから呼ばれる
pub fn handle_domain_panic(domain_id: DomainId, message: String) {
    // 状態を停止に変更
    update_domain(domain_id, |domain| {
        domain.state = DomainState::Stopped;
        domain.panic_message = Some(message.clone());
    });

    // リソースを回収
    reclaim_domain_resources(domain_id);

    // ログ出力
    crate::log!(
        "[PANIC] Domain {} crashed: {}\n",
        domain_id.as_u64(),
        message
    );

    // 依存するドメインに通知（将来の実装）
    // notify_dependents(domain_id, DomainError::Panicked(message));
}

/// ドメインを再起動
pub fn restart_domain(domain_id: DomainId) -> Result<(), DomainError> {
    // ドメインの状態を確認
    let state = get_domain(domain_id, |d| d.state);

    match state {
        Some(DomainState::Stopped) | Some(DomainState::Terminated) => {
            // 状態を初期化中に変更
            set_domain_state(domain_id, DomainState::Initializing);

            // TODO: ドメインのコードを再ロード
            // TODO: 初期化タスクを再スポーン

            set_domain_state(domain_id, DomainState::Running);
            Ok(())
        }
        Some(_) => Err(DomainError::AlreadyStopped),
        None => Err(DomainError::NotFound),
    }
}

/// ドメイン間の依存関係を追加
pub fn add_domain_dependency(dependent: DomainId, dependency: DomainId) -> Result<(), DomainError> {
    // 両方のドメインが存在することを確認
    let dep_exists = get_domain(dependency, |_| true).unwrap_or(false);
    if !dep_exists {
        return Err(DomainError::NotFound);
    }

    // 依存関係を追加
    update_domain(dependent, |domain| {
        domain.add_dependency(dependency);
    });

    update_domain(dependency, |domain| {
        domain.add_dependent(dependent);
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_lifecycle() {
        // ドメイン作成
        let id = register_domain("test_domain".into());

        // 状態確認
        let state = get_domain(id, |d| d.state);
        assert_eq!(state, Some(DomainState::Initializing));

        // 状態変更
        set_domain_state(id, DomainState::Running);
        let state = get_domain(id, |d| d.state);
        assert_eq!(state, Some(DomainState::Running));

        // 終了
        let result = terminate_domain(id);
        assert!(result.is_ok());
    }
}
