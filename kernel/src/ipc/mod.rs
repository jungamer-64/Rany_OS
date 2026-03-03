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
    ChannelError,
    Pipe,
    PipeError,
    PipeFd,
    PipeFlags,
    PipeId,
    PipeManager,
    PipeReader,
    PipeWriter,
    // ゼロコピーチャンネル
    ZeroCopyChannel,
    ZeroCopyReceiver,
    ZeroCopySender,
    pipe_manager,
    zero_copy_channel,
};
#[allow(unused_imports)]
pub use proxy::{
    BasicProxy,
    DomainProxy,
    ProxyError,
    ProxyResult,
    // パニック捕捉
    begin_proxy_call,
    did_proxy_panic,
    record_proxy_panic,
};
pub use rref::{DomainId, RRef, reclaim_domain_resources};
#[allow(unused_imports)]
pub use shared_mem::{
    SharedMemoryManager,
    SharedMemoryRegion,
    SharedRingBuffer,
    ShmError,
    ShmFlags,
    ShmHandle,
    ShmId,
    ShmKey,
    // ゼロコピー共有メモリ
    ZeroCopyRegion,
    shm_manager,
};
