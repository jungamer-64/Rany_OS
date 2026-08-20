// ============================================================================
// src/ipc/proxy.rs - Domain Proxy Pattern
// 設計書 8.2: RedLeafの知見：交換可能な型とプロキシ
// ============================================================================
use super::rref::DomainId;
use alloc::string::String;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// プロキシ呼び出しの結果
pub type ProxyResult<T> = Result<T, ProxyError>;

/// プロキシエラー
#[derive(Debug, Clone)]
pub enum ProxyError {
    /// ターゲットドメインがパニックした
    DomainPanicked(String),
    /// ターゲットドメインが応答しない
    DomainUnresponsive,
    /// ターゲットドメインが見つからない
    DomainNotFound,
    /// 通信エラー
    CommunicationError(String),
    /// 権限エラー
    PermissionDenied,
    /// タイムアウト
    Timeout,
    /// その他のエラー
    Other(String),
}

impl core::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProxyError::DomainPanicked(msg) => write!(f, "Domain panicked: {}", msg),
            ProxyError::DomainUnresponsive => write!(f, "Domain unresponsive"),
            ProxyError::DomainNotFound => write!(f, "Domain not found"),
            ProxyError::CommunicationError(msg) => write!(f, "Communication error: {}", msg),
            ProxyError::PermissionDenied => write!(f, "Permission denied"),
            ProxyError::Timeout => write!(f, "Operation timed out"),
            ProxyError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

/// ドメインプロキシトレイト
/// 設計書 8.2: ドメインAがドメインBの関数を呼び出す際、直接呼び出すのではなく、
/// プロキシを経由する
pub trait DomainProxy {
    /// プロキシを通じて呼び出す
    fn call<F, T>(&self, func: F) -> ProxyResult<T>
    where
        F: FnOnce() -> T;

    /// 非同期プロキシ呼び出し
    fn call_async<'a, F, Fut, T>(&'a self, func: F) -> ProxyCallFuture<'a, T>
    where
        F: FnOnce() -> Fut + 'a,
        Fut: Future<Output = T> + 'a;
}

/// 基本的なドメインプロキシ実装
pub struct BasicProxy {
    /// ターゲットドメインID
    target_domain: DomainId,
    /// 呼び出し元ドメインID
    caller_domain: DomainId,
    /// タイムアウト（ミリ秒）
    timeout_ms: u64,
}

impl BasicProxy {
    /// 新しいプロキシを作成
    pub fn new(caller: DomainId, target: DomainId) -> Self {
        Self {
            target_domain: target,
            caller_domain: caller,
            timeout_ms: 5000, // デフォルト5秒
        }
    }

    /// タイムアウトを設定
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// ターゲットドメインを取得
    pub fn target(&self) -> DomainId {
        self.target_domain
    }

    /// 呼び出し元ドメインを取得
    pub fn caller(&self) -> DomainId {
        self.caller_domain
    }

    /// ドメインが利用可能かチェック
    fn check_domain_available(&self) -> ProxyResult<()> {
        // 注意: 実際の実装ではdomainモジュールとの統合が必要
        // 現時点ではスタブとして常にOKを返す
        Ok(())
    }
}

impl DomainProxy for BasicProxy {
    fn call<F, T>(&self, func: F) -> ProxyResult<T>
    where
        F: FnOnce() -> T,
    {
        self.check_domain_available()?;
        let current = crate::task::current_execution_context().ok_or_else(|| {
            ProxyError::CommunicationError(String::from("execution context unavailable"))
        })?;
        if current.subject.domain != self.caller_domain {
            return Err(ProxyError::PermissionDenied);
        }
        let _domain_guard = crate::task::enter_domain(self.target_domain).map_err(|_| {
            ProxyError::CommunicationError(String::from("execution context unavailable"))
        })?;
        execute_with_panic_capture(func)
    }

    fn call_async<'a, F, Fut, T>(&'a self, func: F) -> ProxyCallFuture<'a, T>
    where
        F: FnOnce() -> Fut + 'a,
        Fut: Future<Output = T> + 'a,
    {
        ProxyCallFuture::new(self, func)
    }
}

// ============================================================================
// Panic Capture Mechanism - 設計書 8.2: ドメイン境界でのパニック捕捉
// 設計書 8.4: PoisonLockによるパニック時の毒入れ対応
// ============================================================================

/// パニック捕捉付きで関数を実行
///
/// no_std環境ではstd::panic::catch_unwindが使えないため、
/// unwindモジュールのcatch_panic機構と連携してパニックを捕捉する。
///
/// 設計書 8.1/8.2:
/// - パニックはドメイン境界で停止
/// - パニックハンドラがリソース回収を行う
/// - プロキシは Result::Err を返す
fn execute_with_panic_capture<F, T>(func: F) -> ProxyResult<T>
where
    F: FnOnce() -> T,
{
    match crate::unwind::catch_panic(func) {
        Ok(result) => Ok(result),
        Err(payload) => Err(ProxyError::DomainPanicked(payload.message)),
    }
}

/// 非同期プロキシ呼び出しのFuture
pub struct ProxyCallFuture<'a, T> {
    proxy: &'a BasicProxy,
    _marker: core::marker::PhantomData<T>,
}

impl<'a, T> ProxyCallFuture<'a, T> {
    fn new<F, Fut>(proxy: &'a BasicProxy, _func: F) -> Self
    where
        F: FnOnce() -> Fut + 'a,
        Fut: Future<Output = T> + 'a,
    {
        Self {
            proxy,
            _marker: core::marker::PhantomData,
        }
    }
}

impl<'a, T> Future for ProxyCallFuture<'a, T> {
    type Output = ProxyResult<T>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        // ドメインの可用性をチェック
        if let Err(e) = self.proxy.check_domain_available() {
            return Poll::Ready(Err(e));
        }

        // 実際の非同期呼び出し実装
        // 注意: 完全な実装にはより複雑なステートマシンが必要
        Poll::Ready(Err(ProxyError::Other(
            "Async proxy not fully implemented".into(),
        )))
    }
}

// ============================================================================
// Service Proxy - より高レベルなサービス呼び出し
// ============================================================================

/// サービスプロキシトレイト
/// 特定のサービスインターフェースをプロキシする
pub trait ServiceProxy<S> {
    /// サービスを呼び出し
    fn invoke(&self, request: S::Request) -> ProxyResult<S::Response>
    where
        S: Service;
}

/// サービストレイト
pub trait Service {
    type Request;
    type Response;

    fn handle(&self, request: Self::Request) -> Self::Response;
}

/// サービスプロキシの実装
pub struct ServiceProxyImpl<S: Service> {
    proxy: BasicProxy,
    _marker: core::marker::PhantomData<S>,
}

impl<S: Service> ServiceProxyImpl<S> {
    pub fn new(caller: DomainId, target: DomainId) -> Self {
        Self {
            proxy: BasicProxy::new(caller, target),
            _marker: core::marker::PhantomData,
        }
    }
}

impl<S: Service> ServiceProxy<S> for ServiceProxyImpl<S> {
    fn invoke(&self, _request: S::Request) -> ProxyResult<S::Response> {
        self.proxy.check_domain_available()?;
        // サービス呼び出しの実装
        Err(ProxyError::Other("Not implemented".into()))
    }
}

// ============================================================================
// Retry Proxy - リトライ機能付きプロキシ
// ============================================================================

/// リトライ設定
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// 最大リトライ回数
    pub max_retries: u32,
    /// リトライ間隔（ミリ秒）
    pub retry_interval_ms: u64,
    /// 指数バックオフを使用するか
    pub exponential_backoff: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_interval_ms: 100,
            exponential_backoff: true,
        }
    }
}

/// リトライ機能付きプロキシ
pub struct RetryProxy {
    inner: BasicProxy,
    config: RetryConfig,
}

impl RetryProxy {
    pub fn new(proxy: BasicProxy, config: RetryConfig) -> Self {
        Self {
            inner: proxy,
            config,
        }
    }

    /// リトライ付きで呼び出し
    pub fn call_with_retry<F, T>(&self, func: F) -> ProxyResult<T>
    where
        F: Fn() -> T + Clone,
    {
        let mut last_error = ProxyError::Other("No attempts made".into());
        let mut _interval = self.config.retry_interval_ms;

        for attempt in 0..=self.config.max_retries {
            match self.inner.call(func.clone()) {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = e;

                    // 最後の試行では待機しない
                    if attempt < self.config.max_retries {
                        // 待機（実際にはasync sleep）
                        // crate::task::sleep_ms(interval).await;

                        if self.config.exponential_backoff {
                            _interval *= 2;
                        }
                    }
                }
            }
        }

        Err(last_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_proxy_error_display() {
        let error = ProxyError::DomainPanicked("test panic".into());
        let error_str = alloc::format!("{}", error);
        assert!(error_str.contains("test panic"));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert!(config.exponential_backoff);
    }
}
