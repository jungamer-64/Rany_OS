// ============================================================================
// src/ipc/proxy.rs - Domain Proxy Pattern
// 設計書 8.2: RedLeafの知見：交換可能な型とプロキシ
// ============================================================================
use super::rref::DomainId;
use alloc::string::String;

/// プロキシ呼び出しの結果
pub type ProxyResult<T> = Result<T, ProxyError>;

/// A rejected entry has not called the closure. A captured target panic may
/// follow committed work and does not imply that the operation is retryable.
#[derive(Debug)]
pub enum ProxyError {
    Execution(crate::task::ExecutionContextUnavailable),
    PermissionDenied,
    DomainPanicked(String),
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
}

/// 基本的なドメインプロキシ実装
pub struct BasicProxy {
    /// ターゲットドメインID
    target_domain: DomainId,
    /// 呼び出し元ドメインID
    caller_domain: DomainId,
}

impl BasicProxy {
    /// 新しいプロキシを作成
    pub fn new(caller: DomainId, target: DomainId) -> Self {
        Self {
            target_domain: target,
            caller_domain: caller,
        }
    }

    /// ターゲットドメインを取得
    pub fn target(&self) -> DomainId {
        self.target_domain
    }

    /// 呼び出し元ドメインを取得
    pub fn caller(&self) -> DomainId {
        self.caller_domain
    }
}

impl DomainProxy for BasicProxy {
    fn call<F, T>(&self, func: F) -> ProxyResult<T>
    where
        F: FnOnce() -> T,
    {
        self.check_domain_available()?;
        let current = crate::cpu::CurrentCpu::acquire()
            .and_then(|cpu| cpu.execution())
            .ok_or_else(|| {
                ProxyError::CommunicationError(String::from("execution context unavailable"))
            })?;
        if current.domain != self.caller_domain {
            return Err(ProxyError::PermissionDenied);
        }
        let _domain_guard = crate::task::enter_domain(self.target_domain).map_err(|_| {
            ProxyError::CommunicationError(String::from("execution context unavailable"))
        })?;
        execute_with_panic_capture(func)
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
}
