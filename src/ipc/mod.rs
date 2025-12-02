// ============================================================================
// IPC (Inter-Process Communication) Module
// 設計書 3.2/8.2: ドメイン間通信とプロキシパターン
// ============================================================================
pub mod rref;
pub mod proxy;
pub mod pipe;
pub mod shared_mem;

pub use rref::{DomainId, RRef, AccessError, reclaim_domain_resources};
pub use proxy::{
    DomainProxy, BasicProxy, ProxyError, ProxyResult,
    ServiceProxy, Service, RetryConfig, RetryProxy,
};
#[allow(unused_imports)]
pub use pipe::{
    PipeFd, PipeId, PipeFlags, PipeError, Pipe, PipeReader, PipeWriter,
    PipeManager, pipe_manager, pipe, pipe2, mkfifo,
};
#[allow(unused_imports)]
pub use shared_mem::{
    ShmId, ShmKey, ShmFlags, ShmError, SharedMemoryRegion, ShmHandle,
    SharedMemoryManager, shm_manager, shmget, shmat,
    shmctl_remove, shmctl_stat, shm_open, shm_unlink,
};
