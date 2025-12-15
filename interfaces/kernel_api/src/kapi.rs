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
        _endpoint: &mut crate::TcpEndpoint,
    ) -> KapiResult<crate::Packet> {
        super::task::yield_now().await;
        Ok(crate::Packet::new(Vec::new()))
    }

    /// Send packet (gives up ownership)
    pub async fn send_packet(
        _cap: &NetCapability,
        _endpoint: &mut crate::TcpEndpoint,
        packet: crate::Packet,
    ) -> KapiResult<()> {
        super::task::yield_now().await;
        drop(packet);
        Ok(())
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
