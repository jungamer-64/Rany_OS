// ============================================================================
// kernel_api/src/kapi.rs - Kernel API Functions (SPL Architecture)
// ============================================================================
//!
//! # Kernel API (KAPI) - SPL Direct Function Call Interface
//!
//! ## Design Philosophy
//!
//! ExoRust uses SPL (Single Privilege Level) architecture.
//! **Traditional syscalls do not exist** - all API calls are direct function calls.
//!
//! ## Usage
//!
//! ```rust,ignore
//! async fn my_app(ctx: &AppContext) {
//!     // Task management (no capability required)
//!     kapi::task::yield_now().await;
//!     kapi::task::sleep_ms(100).await;
//!     
//!     // With capability
//!     if let Some(net_cap) = ctx.net() {
//!         let endpoint = kapi::net::create_endpoint(net_cap)?;
//!     }
//! }
//! ```

extern crate alloc;

use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use crate::KapiResult;
use crate::security::{
    DmaCapability, FsCapability, IoCapability, IpcCapability, NetCapability, TaskCapability,
};

// ============================================================================
// Task API
// ============================================================================

/// Task management API
pub mod task {
    use super::*;
    use alloc::boxed::Box;

    /// Yield CPU to other tasks
    #[inline(always)]
    pub async fn yield_now() {
        YieldFuture::new().await
    }

    /// Sleep for specified milliseconds
    #[inline(always)]
    pub async fn sleep_ms(ms: u64) {
        SleepFuture::new(ms).await
    }

    /// Spawn a new async task
    ///
    /// The future is boxed and pinned, then passed to the kernel's executor.
    ///
    /// # Errors
    /// - `KapiError::OutOfMemory` if the kernel cannot allocate resources for the task
    pub fn spawn<F>(_cap: &TaskCapability, future: F) -> KapiResult<crate::TaskHandle>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        // Box and pin the future for the kernel
        let boxed_future = Box::pin(future);

        // Delegate to kernel implementation
        crate::kernel().spawn_task(boxed_future)
    }

    /// Get current task ID
    #[inline(always)]
    pub fn current_task_id() -> u64 {
        crate::kernel().current_task_id()
    }

    // Re-export the kernel API TaskHandle directly from the types module
    pub use crate::TaskHandle as KapiTaskHandle;

    // Internal Future implementations
    struct YieldFuture {
        yielded: bool,
    }

    impl YieldFuture {
        fn new() -> Self {
            Self { yielded: false }
        }
    }

    impl Future for YieldFuture {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.yielded {
                Poll::Ready(())
            } else {
                self.yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    struct SleepFuture {
        target_tick: u64,
        started: bool,
    }

    impl SleepFuture {
        fn new(ms: u64) -> Self {
            Self {
                target_tick: ms,
                started: false,
            }
        }
    }

    impl Future for SleepFuture {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let kernel = crate::kernel();

            if !self.started {
                self.started = true;
                let current = kernel.current_tick();
                self.target_tick = current + self.target_tick;
            }

            let current = kernel.current_tick();
            if current >= self.target_tick {
                Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}

// ============================================================================
// Memory API
// ============================================================================

/// Memory management API
pub mod mem {
    use super::*;

    /// Allocate DMA buffer
    ///
    /// # Errors
    /// - `KapiError::OutOfMemory` if buffer allocation fails
    pub fn alloc_dma(_cap: &DmaCapability, size: usize) -> KapiResult<crate::DmaBuffer> {
        crate::kernel().alloc_dma(size)
    }

    /// Read from I/O port
    #[inline(always)]
    pub fn port_read_u8(_cap: &IoCapability, port: u16) -> u8 {
        crate::kernel().port_read_u8(port)
    }

    /// Write to I/O port
    #[inline(always)]
    pub fn port_write_u8(_cap: &IoCapability, port: u16, value: u8) {
        crate::kernel().port_write_u8(port, value)
    }
}

// ============================================================================
// Network API
// ============================================================================

/// Network API (zero-copy design)
pub mod net {
    use super::*;

    /// Create TCP endpoint
    ///
    /// # Errors
    /// - `KapiError::ResourceExhausted` if the kernel cannot allocate a socket
    pub fn create_endpoint(_cap: &NetCapability) -> KapiResult<crate::TcpEndpoint> {
        crate::kernel().net_create_endpoint()
    }

    /// Receive packet (takes ownership)
    pub async fn recv_packet(
        _cap: &NetCapability,
        endpoint: &mut crate::TcpEndpoint,
    ) -> KapiResult<crate::Packet> {
        // Delegate to kernel implementation which returns a future
        crate::kernel()
            .net_recv_packet(crate::TcpEndpoint::new(endpoint.id()))
            .await
    }

    /// Send packet (gives up ownership)
    pub async fn send_packet(
        _cap: &NetCapability,
        endpoint: &mut crate::TcpEndpoint,
        packet: crate::Packet,
    ) -> KapiResult<()> {
        crate::kernel()
            .net_send_packet(crate::TcpEndpoint::new(endpoint.id()), packet)
            .await
    }

    /// Create a raw (packet-oriented) socket
    pub fn create_raw_socket(_cap: &NetCapability) -> KapiResult<crate::RawSocketHandle> {
        crate::kernel().net_create_raw_socket()
    }

    /// Close a raw socket
    pub fn close_raw_socket(_cap: &NetCapability, endpoint: crate::RawSocketHandle) -> KapiResult<()> {
        crate::kernel().net_close_raw_socket(endpoint)
    }

    /// Receive raw packet (takes ownership)
    pub async fn recv_raw_packet(
        _cap: &NetCapability,
        endpoint: &mut crate::RawSocketHandle,
    ) -> KapiResult<crate::Packet> {
        crate::kernel()
            .net_recv_raw(crate::RawSocketHandle::new(endpoint.id()))
            .await
    }

    /// Send raw packet (gives up ownership)
    pub async fn send_raw_packet(
        _cap: &NetCapability,
        endpoint: &mut crate::RawSocketHandle,
        packet: crate::Packet,
    ) -> KapiResult<()> {
        crate::kernel()
            .net_send_raw(crate::RawSocketHandle::new(endpoint.id()), packet)
            .await
    }
}

// ========================================================================
// NVMe Direct Block API
// ========================================================================

/// Direct NVMe block API
pub mod nvme {
    use super::*;

    /// Open a direct NVMe block handle (namespace + range)
    pub fn open_direct(
        _cap: &IoCapability,
        device_id: u64,
        start_block: u64,
        block_count: u64,
    ) -> KapiResult<crate::DirectBlockHandle> {
        crate::kernel().nvme_open_direct(device_id, start_block, block_count)
    }

    /// Open a direct NVMe block handle and associate it with an optional token.
    /// The caller must hold an `IoCapability` and the provided token must be
    /// valid for `CAP_DMA`.
    pub fn open_direct_with_token(
        _cap: &IoCapability,
        device_id: u64,
        start_block: u64,
        block_count: u64,
        token: Option<u64>,
    ) -> KapiResult<crate::DirectBlockHandle> {
        crate::kernel().nvme_open_direct_with_token(device_id, start_block, block_count, token)
    }

    /// Close a kernel-registered direct NVMe handle
    pub fn close_direct(_cap: &IoCapability, handle: crate::DirectBlockHandle) -> KapiResult<()> {
        crate::kernel().nvme_close_direct(handle)
    }

    /// Read blocks into a DMA buffer (buffer returned on completion)
    pub async fn read_blocks_dma(
        _cap: &IoCapability,
        handle: crate::DirectBlockHandle,
        block_offset: u64,
        buffer: crate::DmaBuffer,
    ) -> KapiResult<crate::DmaBuffer> {
        crate::kernel()
            .nvme_read_blocks_dma(handle, block_offset, buffer)
            .await
    }

    /// Write blocks from a DMA buffer (buffer returned on completion)
    pub async fn write_blocks_dma(
        _cap: &IoCapability,
        handle: crate::DirectBlockHandle,
        block_offset: u64,
        buffer: crate::DmaBuffer,
    ) -> KapiResult<crate::DmaBuffer> {
        crate::kernel()
            .nvme_write_blocks_dma(handle, block_offset, buffer)
            .await
    }

    /// Flush pending writes for a direct handle
    pub async fn flush_direct(
        _cap: &IoCapability,
        handle: crate::DirectBlockHandle,
    ) -> KapiResult<()> {
        crate::kernel().nvme_flush_direct(handle).await
    }

    /// Discard blocks (TRIM)
    pub async fn discard_direct(
        _cap: &IoCapability,
        handle: crate::DirectBlockHandle,
        block_offset: u64,
        block_count: u64,
    ) -> KapiResult<()> {
        crate::kernel()
            .nvme_discard_direct(handle, block_offset, block_count)
            .await
    }
}

// ============================================================================
// Filesystem API
// ============================================================================

/// Filesystem API
pub mod fs {
    use super::*;

    /// Open a file
    pub fn open(
        _cap: &FsCapability,
        path: &str,
        mode: crate::OpenMode,
    ) -> KapiResult<crate::FileHandle> {
        crate::kernel().fs_open(path, mode)
    }

    /// Open a file and associate it with an optional token.
    /// The caller must hold a `FsCapability` and the provided token must be
    /// valid for `CAP_FOWNER`.
    pub fn open_with_token(
        _cap: &FsCapability,
        path: &str,
        mode: crate::OpenMode,
        token: Option<u64>,
    ) -> KapiResult<crate::FileHandle> {
        crate::kernel().fs_open_with_token(path, mode, token)
    }
}

// ============================================================================
// System API
// ============================================================================

/// System information API (no capability required)
pub mod sys {
    use crate::SystemInfo;

    /// Get uptime in nanoseconds
    #[inline(always)]
    pub fn uptime_nanos() -> u64 {
        crate::kernel().current_tick() * 1_000_000
    }

    /// Get uptime in milliseconds
    #[inline(always)]
    pub fn uptime_ms() -> u64 {
        crate::kernel().current_tick()
    }

    /// Debug print
    pub fn debug_print(msg: &str) {
        crate::kernel().log(msg);
    }

    /// Get system information
    pub fn get_system_info() -> SystemInfo {
        SystemInfo {
            total_memory: 128 * 1024 * 1024,
            free_memory: 64 * 1024 * 1024,
            uptime_ms: uptime_ms(),
            cpu_count: 1,
        }
    }
}

// ============================================================================
// IPC API
// ============================================================================

/// Inter-process communication API
pub mod ipc {
    use super::*;

    /// Create IPC channel
    ///
    /// # Errors
    /// - `KapiError::ResourceExhausted` if a channel could not be created
    pub fn create_channel(
        _cap: &IpcCapability,
    ) -> KapiResult<(crate::ChannelHandle, crate::ChannelHandle)> {
        crate::kernel().ipc_create_channel()
    }
}
