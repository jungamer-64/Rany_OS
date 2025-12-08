// ============================================================================
// kernel/src/service_impl.rs - KernelServices Implementation
// ============================================================================
//!
//! # ExoKernel Implementation of KernelServices
//!
//! This module implements the `KernelServices` trait from `kernel_api`,
//! bridging the contract defined in the interface to the kernel's internal
//! implementations.
//!
//! ## Design (設計書準拠)
//! - SPL: Single Privilege Level - all calls are direct function calls
//! - No syscall overhead - just vtable dispatch
//! - Type-safe capability model via traits
//!
//! ## Task Integration
//! Uses `per_core_executor::Task::new_boxed()` to avoid double-boxing
//! when receiving pre-boxed futures from external callers.

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_api::error::KapiError;
use kernel_api::services::KernelServices;
use kernel_api::{OpenMode, TaskHandle, DmaBuffer, TcpEndpoint, FileHandle, ChannelHandle};
use spin::Mutex;

use crate::task::per_core_executor::{Task, Priority, executor_manager};
use crate::task::timer;
use crate::task::context;
use crate::io::dma;

// ============================================================================
// File Handle Registry
// ============================================================================

/// Entry for an open file handle
struct FileHandleEntry {
    path: String,
    mode: OpenMode,
    position: u64,
}

// Channel Registry for IPC
use crate::ipc::pipe::{PipeReader, PipeWriter};

enum ChannelEntry {
    Reader(PipeReader),
    Writer(PipeWriter),
}

struct ChannelRegistry {
    channels: Mutex<BTreeMap<u64, ChannelEntry>>,
    next_id: AtomicU64,
}

impl ChannelRegistry {
    const fn new() -> Self {
        Self {
            channels: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    fn register(&self, entry: ChannelEntry) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.channels.lock().insert(id, entry);
        id
    }

    fn unregister(&self, id: u64) -> Option<ChannelEntry> {
        self.channels.lock().remove(&id)
    }
}

/// Registry for tracking open file handles
struct FileHandleRegistry {
    handles: Mutex<BTreeMap<u64, FileHandleEntry>>,
    next_id: AtomicU64,
}

impl FileHandleRegistry {
    const fn new() -> Self {
        Self {
            handles: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    fn register(&self, entry: FileHandleEntry) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.handles.lock().insert(id, entry);
        id
    }

    fn unregister(&self, id: u64) -> Option<FileHandleEntry> {
        self.handles.lock().remove(&id)
    }
}

/// Global file handle registry
static FILE_HANDLE_REGISTRY: FileHandleRegistry = FileHandleRegistry::new();
static CHANNEL_REGISTRY: ChannelRegistry = ChannelRegistry::new();

// ============================================================================
// ExoKernel: The KernelServices Implementation
// ============================================================================

/// ExoKernel - The concrete implementation of KernelServices
///
/// This struct has no fields; all state is managed via static globals
/// within the kernel. This keeps the implementation simple and allows
/// registration as a `&'static dyn KernelServices`.
pub struct ExoKernel;

impl ExoKernel {
    /// Create the singleton instance
    pub const fn new() -> Self {
        ExoKernel
    }
}

// SAFETY: ExoKernel is stateless and accesses thread-safe globals
unsafe impl Send for ExoKernel {}
unsafe impl Sync for ExoKernel {}

impl KernelServices for ExoKernel {
    // ========================================================================
    // Task Management
    // ========================================================================

    fn spawn_task(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) -> Result<TaskHandle, KapiError> {
        // Use Task::new_boxed to avoid double-boxing (optimization)
        let task = Task::new_boxed(future, Priority::Normal, None);
        let task_id = task.metadata.id.as_u64();
        
        // Submit to ExecutorManager for load-balanced scheduling
        executor_manager().spawn(task);
        
        Ok(TaskHandle::new(task_id))
    }

    fn current_tick(&self) -> u64 {
        timer::current_tick()
    }

    fn current_task_id(&self) -> u64 {
        context::current_task_id()
    }

    // ========================================================================
    // Memory Management
    // ========================================================================

    fn alloc_dma(&self, size: usize) -> Result<DmaBuffer, KapiError> {
        // Use TypedDmaSlice for coherent DMA allocation
        match dma::TypedDmaSlice::new(size) {
            Some(buffer) => {
                let phys = buffer.phys_addr().as_u64();
                // SAFETY: Leak the buffer to keep it alive for DMA use
                // TODO: Implement proper DMA buffer registry for tracking/freeing
                let ptr = Box::into_raw(Box::new(buffer)) as *mut u8;
                Ok(DmaBuffer::new(phys, ptr, size))
            }
            None => Err(KapiError::OutOfMemory),
        }
    }

    fn free_dma(&self, buffer: DmaBuffer) {
        // TODO: Implement proper DMA buffer tracking and deallocation
        // Current implementation leaks memory (acceptable for now)
        let _ = buffer;
    }

    // ========================================================================
    // I/O Operations
    // ========================================================================

    fn port_read_u8(&self, port: u16) -> u8 {
        hal::port_io::PortU8::new(port).read()
    }

    fn port_write_u8(&self, port: u16, value: u8) {
        hal::port_io::PortU8::new(port).write(value)
    }

    // ========================================================================
    // Logging
    // ========================================================================

    fn log(&self, message: &str) {
        crate::log!("{}", message);
    }

    // ========================================================================
    // Network (Connected to network stack)
    // ========================================================================

    fn net_create_endpoint(&self) -> Result<TcpEndpoint, KapiError> {
        use crate::net::endpoint::{create_tcp_socket, SocketFd};
        
        let owned = create_tcp_socket();
        let fd = owned.fd();
        
        // Detach from OwnedSocket so it remains registered in SocketManager
        // and doesn't close on drop.
        let _ = owned.into_inner(); 
        
        Ok(TcpEndpoint::new(fd.raw() as u64))
    }
    fn net_close_endpoint(&self, endpoint: TcpEndpoint) -> Result<(), KapiError> {
        use crate::net::endpoint::{socket_manager, SocketFd};
        
        let fd = SocketFd::from_raw(endpoint.id() as u32);
        
        if let Some(mgr_lock) = socket_manager() {
            if let Some(mgr) = mgr_lock.read().as_ref() {
                if mgr.unregister(fd).is_some() {
                    return Ok(());
                }
            }
        }
        
        Err(KapiError::InvalidHandle)
    }

    // ========================================================================
    // Filesystem (Connected to memfs)
    // ========================================================================

    fn fs_open(&self, path: &str, mode: OpenMode) -> Result<FileHandle, KapiError> {
        use crate::fs::memfs;
        
        // Check if file exists
        let path_buf = alloc::string::String::from(path);
        
        match mode {
            OpenMode::Read => {
                // For read, file must exist
                if memfs::stat_file(&path_buf, "/").is_err() {
                    return Err(KapiError::NotFound);
                }
            }
            OpenMode::Write | OpenMode::ReadWrite | OpenMode::Append | OpenMode::Create => {
                // For write, create if not exists
                if memfs::stat_file(&path_buf, "/").is_err() {
                    if let Err(_) = memfs::touch_file(&path_buf, "/") {
                        return Err(KapiError::IoError);
                    }
                }
            }
        }
        
        // Register in file handle table
        let handle_id = FILE_HANDLE_REGISTRY.register(FileHandleEntry {
            path: path_buf,
            mode,
            position: 0,
        });
        Ok(FileHandle::new(handle_id, mode))
    }

    fn fs_close(&self, handle: FileHandle) -> Result<(), KapiError> {
        let handle_id = handle.id();
        FILE_HANDLE_REGISTRY.unregister(handle_id)
            .ok_or(KapiError::InvalidHandle)?;
        Ok(())
    }

    fn ipc_create_channel(&self) -> Result<(ChannelHandle, ChannelHandle), KapiError> {
		// Create a new pipe
        let pipe = crate::ipc::pipe::pipe();
        
        // Register reader and writer
        let reader_id = CHANNEL_REGISTRY.register(ChannelEntry::Reader(pipe.reader));
        let writer_id = CHANNEL_REGISTRY.register(ChannelEntry::Writer(pipe.writer));
        
        // info!(target: "ipc", "Created channel: reader={}, writer={}", reader_id, writer_id);
        
        Ok((ChannelHandle::new(writer_id), ChannelHandle::new(reader_id))) // Return (Sender, Receiver)
    }

    fn ipc_close(&self, channel: ChannelHandle) -> Result<(), KapiError> {
        let channel_id = channel.id();
        if CHANNEL_REGISTRY.unregister(channel_id).is_some() {
            Ok(())
        } else {
            Err(KapiError::InvalidHandle)
        }
    }
}


/// The global ExoKernel instance
static EXOKERNEL: ExoKernel = ExoKernel::new();

/// Register the kernel services (call from kmain early in boot)
///
/// # Safety
/// Must be called exactly once, before any KAPI functions are used.
pub unsafe fn register_kernel_services() {
    unsafe {
        kernel_api::register_kernel(&EXOKERNEL);
    }
}


/// Get a reference to the exokernel (for internal use)
pub fn exokernel() -> &'static ExoKernel {
    &EXOKERNEL
}

