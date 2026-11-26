// ============================================================================
// src/ipc/proxy.rs - Domain Proxy Pattern
// 設計書 8.2: RedLeafの知見：交換可能な型とプロキシ
// ============================================================================
use super::rref::DomainId;

/// プロキシ呼び出しの結果
pub type ProxyResult<T> = Result<T, ProxyError>;

/// Distinguishes rejection before target entry from a panic during the call.
#[derive(Debug)]
pub enum ProxyError {
    Execution(crate::task::ExecutionContextUnavailable),
    PermissionDenied,
    DomainPanicked,
}

impl core::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProxyError::Execution(error) => write!(f, "Execution context unavailable: {error:?}"),
            ProxyError::PermissionDenied => write!(f, "Permission denied"),
            ProxyError::DomainPanicked => f.write_str("Domain panicked"),
        }
    }
}

/// ドメインプロキシトレイト
/// 設計書 8.2: ドメインAがドメインBの関数を呼び出す際、直接呼び出すのではなく、
/// プロキシを経由する
pub trait DomainProxy {
    /// Execute once on the current task's stack. The target execution binding
    /// and code lease remain owned through the call and panic capture; scope
    /// exit restores the caller's execution context.
    ///
    /// # Errors
    /// Rejects missing CPU/execution bindings, caller mismatch, or target code,
    /// security and quota admission before invoking the closure. A captured
    /// target panic may follow visible effects; failure does not undo that work
    /// or grant permission to retry it.
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
        let cpu = crate::cpu::CurrentCpu::acquire().ok_or(ProxyError::Execution(
            crate::task::ExecutionContextUnavailable::UnboundCpu,
        ))?;
        let current = cpu.execution().ok_or(ProxyError::Execution(
            crate::task::ExecutionContextUnavailable::NoExecution,
        ))?;
        if current.domain != self.caller_domain {
            return Err(ProxyError::PermissionDenied);
        }
        let domain =
            crate::task::enter_domain(self.target_domain).map_err(ProxyError::Execution)?;
        let result = func();
        if domain.caught_cell_panic() {
            // The failed invocation still owns target code and execution
            // until disposal of the result has completed.
            drop(result);
            Err(ProxyError::DomainPanicked)
        } else {
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_proxy_error_display() {
        let error = ProxyError::DomainPanicked;
        let error_str = alloc::format!("{}", error);
        assert!(error_str.contains("Domain panicked"));
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn unbound_call_rejects_before_invoking_the_closure() {
        let invoked = core::cell::Cell::new(false);
        let proxy = BasicProxy::new(DomainId::KERNEL, DomainId::KERNEL);
        let result = proxy.call(|| invoked.set(true));
        assert!(matches!(
            result,
            Err(ProxyError::Execution(
                crate::task::ExecutionContextUnavailable::UnboundCpu
            ))
        ));
        assert!(!invoked.get());
    }
}
