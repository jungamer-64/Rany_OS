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
    // ゼロコピーチャンネル
    ZeroCopyChannel, ZeroCopySender, ZeroCopyReceiver, ChannelError, zero_copy_channel,
};
pub use rref::{DomainId, RRef, reclaim_domain_resources};
#[allow(unused_imports)]
pub use shared_mem::{
    SharedMemoryManager, SharedMemoryRegion, ShmError, ShmFlags, ShmHandle, ShmId, ShmKey,
    shm_manager, shm_open, shm_unlink, shmat, shmctl_remove, shmctl_stat, shmget,
    // ゼロコピー共有メモリ
    ZeroCopyRegion, SharedRingBuffer,
};
#[allow(unused_imports)]
pub use proxy::{
    BasicProxy, DomainProxy, ProxyError, ProxyResult,
    // パニック捕捉
    begin_proxy_call, record_proxy_panic, did_proxy_panic,
};
