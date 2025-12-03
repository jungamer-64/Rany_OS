// ============================================================================
// IPC (Inter-Process Communication) Module
// 設計書 3.2/8.2: ドメイン間通信とプロキシパターン
// ============================================================================
pub mod pipe;
pub mod proxy;
pub mod rref;
pub mod shared_mem;

#[allow(unused_imports)]
pub use pipe::{
    Pipe, PipeError, PipeFd, PipeFlags, PipeId, PipeManager, PipeReader, PipeWriter, mkfifo, pipe,
    pipe_manager, pipe2,
};
pub use proxy::{
    BasicProxy, DomainProxy, ProxyError, ProxyResult, RetryConfig, RetryProxy, Service,
    ServiceProxy,
};
pub use rref::{AccessError, DomainId, RRef, reclaim_domain_resources};
#[allow(unused_imports)]
pub use shared_mem::{
    SharedMemoryManager, SharedMemoryRegion, ShmError, ShmFlags, ShmHandle, ShmId, ShmKey,
    shm_manager, shm_open, shm_unlink, shmat, shmctl_remove, shmctl_stat, shmget,
};
