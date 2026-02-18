// ============================================================================
// kernel/src/task/domain_system.rs
// ============================================================================
// テスト/ベンチマーク用 Domain System Shim
//
// 【非推奨】このモジュールは正規版 `crate::domain_system` の軽量shimです。
// テスト(not full_mm_tests)およびベンチマーク構成でのみ使用されます。
// 独自のDomainRegistryやspin::Mutexは持たず、コンパイル時の型解決のみ提供します。
//
// 正規版: kernel/src/domain_system.rs (PoisonLock使用)
// ============================================================================
#![allow(dead_code)]

use core::fmt;
use alloc::string::String;

/// Unique identifier for a protection domain
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct DomainId(pub u64);

impl DomainId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    pub const KERNEL: DomainId = DomainId::new(0);
}

impl fmt::Display for DomainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DomainId({})", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainState {
    Initializing,
    Running,
    Stopped,
    Suspended,
    Terminated,
}

/// ドメイン統計（テスト用stub）
#[derive(Debug, Clone, Default)]
pub struct DomainStats {
    pub total: usize,
    pub running: usize,
    pub stopped: usize,
    pub terminated: usize,
    pub memory_used: u64,
    pub total_rrefs: u64,
}

pub fn init() {}

pub fn create_domain(_name: String) -> Option<DomainId> {
    // テスト環境では常にダミーIDを返す
    static NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
    let id = NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    Some(DomainId(id))
}

pub fn set_domain_state(_id: DomainId, _state: DomainState) {}

pub fn get_domain_stats() -> DomainStats {
    DomainStats::default()
}

pub fn get_stats() -> DomainStats {
    get_domain_stats()
}

pub fn handle_domain_panic(_id: DomainId, _message: String) {}

pub fn start_domain(_id: DomainId) -> Result<(), &'static str> { Ok(()) }
pub fn stop_domain(_id: DomainId) -> Result<(), &'static str> { Ok(()) }
pub fn resume_domain(_id: DomainId) -> Result<(), &'static str> { Ok(()) }
pub fn terminate_domain(_id: DomainId) -> Result<(), &'static str> { Ok(()) }

pub fn set_domain_numa(_id: DomainId, _node: usize) {}
pub fn get_domain_numa(_id: DomainId) -> Option<usize> { None }

pub fn add_task_to_domain(_domain_id: DomainId, _task_id: u64) {}
