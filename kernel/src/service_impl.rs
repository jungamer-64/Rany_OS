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
use kernel_api::{ChannelHandle, DmaBuffer, FileHandle, OpenMode, TaskHandle, TcpEndpoint};
use spin::Mutex;

use crate::io::dma;
use crate::task::context;
use crate::task::per_core_executor::{Priority, Task, executor_manager};
use crate::task::timer;

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

// DMA registry stores heap allocated TypedDmaSlice instances keyed by
// the virtual pointer to the buffer so we can free them later.
struct DmaRegistry {
    buffers: Mutex<BTreeMap<usize, Box<crate::io::dma::TypedDmaSlice<crate::io::dma::CpuOwned>>>>,
}

impl DmaRegistry {
    const fn new() -> Self {
        Self {
            buffers: Mutex::new(BTreeMap::new()),
        }
    }

    fn register(
        &self,
        mut buf: Box<crate::io::dma::TypedDmaSlice<crate::io::dma::CpuOwned>>,
    ) -> usize {
        // Get the virtual address of the slice
        let virt_ptr = buf.as_mut_slice().as_mut_ptr() as usize;
        self.buffers.lock().insert(virt_ptr, buf);
        virt_ptr
    }

    fn unregister(
        &self,
        virt_ptr: usize,
    ) -> Option<Box<crate::io::dma::TypedDmaSlice<crate::io::dma::CpuOwned>>> {
        self.buffers.lock().remove(&virt_ptr)
    }
}

static DMA_REGISTRY: DmaRegistry = DmaRegistry::new();

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

    fn spawn_task(
        &self,
        future: Pin<Box<dyn Future<Output = ()> + Send>>,
    ) -> Result<TaskHandle, KapiError> {
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
                // Box up the buffer and register it so it can be freed later
                let boxed = Box::new(buffer);
                let virt_ptr = DMA_REGISTRY.register(boxed);
                Ok(DmaBuffer::new(phys, virt_ptr as *mut u8, size))
            }
            None => Err(KapiError::OutOfMemory),
        }
    }

    fn free_dma(&self, buffer: DmaBuffer) {
        // Try to lookup the registered buffer by its virtual pointer
        let virt_ptr = buffer.as_ptr() as usize;
        if DMA_REGISTRY.unregister(virt_ptr).is_some() {
            // Successfully unregistered and dropped
            return;
        }

        // If we couldn't find it, quietly ignore (or log) — do not panic in kernel
        crate::log!("[KAPI] free_dma: unknown buffer: {:x}\n", virt_ptr);
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
        use crate::net::endpoint::{SocketFd, create_tcp_socket};

        let owned = create_tcp_socket();
        let fd = owned.fd();

        // Detach from OwnedSocket so it remains registered in SocketManager
        // and doesn't close on drop.
        let _ = owned.into_inner();

        Ok(TcpEndpoint::new(fd.raw() as u64))
    }
    fn net_close_endpoint(&self, endpoint: TcpEndpoint) -> Result<(), KapiError> {
        use crate::net::endpoint::{SocketFd, socket_manager};

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
        FILE_HANDLE_REGISTRY
            .unregister(handle_id)
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

    fn gui(&self) -> Option<&dyn kernel_api::gui::GuiServices> {
        // GUI services are always available if framebuffer exists
        if crate::graphics::framebuffer().is_some() {
            Some(self)
        } else {
            None
        }
    }
}

// ============================================================================
// GuiServices Implementation
// ============================================================================

use kernel_api::gui::{FramebufferInfo as KapiFramebufferInfo, GuiServices, InputStreamHandle, PixelFormat as KapiPixelFormat};
use kernel_api::security::DomainCapabilities;

impl GuiServices for ExoKernel {
    fn request_framebuffer(
        &self,
        access_token: &DomainCapabilities,
    ) -> Result<KapiFramebufferInfo, KapiError> {
        // Security check: require DMA or I/O capability for direct framebuffer access
        if !access_token.has_dma() && !access_token.has_io() {
            return Err(KapiError::PermissionDenied);
        }

        // Get framebuffer info from global
        crate::graphics::with_framebuffer(|fb| {
            let info = fb.info();
            
            // Convert graphic_types::PixelFormat to kernel_api::gui::PixelFormat
            let format = match info.format {
                crate::graphics::PixelFormat::Rgba8888 => KapiPixelFormat::Rgb32,
                crate::graphics::PixelFormat::Bgra8888 => KapiPixelFormat::Bgr32,
                crate::graphics::PixelFormat::Rgb888 => KapiPixelFormat::Rgb24,
                crate::graphics::PixelFormat::Bgr888 => KapiPixelFormat::Bgr24,
                _ => KapiPixelFormat::Unknown,
            };

            Ok(KapiFramebufferInfo {
                width: info.width as usize,
                height: info.height as usize,
                stride: info.stride as usize,
                format,
                vaddr: info.address as usize,
                size: info.size(),
            })
        })
        .unwrap_or(Err(KapiError::ResourceExhausted))
    }

    fn get_input_stream_handle(&self) -> Result<InputStreamHandle, KapiError> {
        // Return a fixed handle ID for the global HID input stream
        // In a full implementation, this would register with an input manager
        Ok(InputStreamHandle(1))
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
