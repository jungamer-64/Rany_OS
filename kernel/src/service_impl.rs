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
use kernel_api::KapiResult;
use kernel_api::services::KernelServices;
use kernel_api::{
    ChannelHandle, DirectBlockHandle, DmaBuffer, FileHandle, OpenMode, TaskHandle, TcpEndpoint,
};
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
    token: Option<u64>,
    owner: u64,
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

    /// Return a list of handle IDs owned by `owner`.
    fn list_handles_by_owner(&self, owner: u64) -> alloc::vec::Vec<u64> {
        let mut result = alloc::vec::Vec::new();
        let handles = self.handles.lock();
        for (id, entry) in handles.iter() {
            if entry.owner == owner {
                result.push(*id);
            }
        }
        result
    }

    /// Get the registered path for a given handle id.
    fn get_handle_path(&self, id: u64) -> Option<String> {
        self.handles.lock().get(&id).map(|e| e.path.clone())
    }
}

/// Global file handle registry
static FILE_HANDLE_REGISTRY: FileHandleRegistry = FileHandleRegistry::new();
static CHANNEL_REGISTRY: ChannelRegistry = ChannelRegistry::new();

// Accessors for per-process file handles (used by procfs)
pub(crate) fn file_handles_for_owner(owner: u64) -> alloc::vec::Vec<u64> {
    FILE_HANDLE_REGISTRY.list_handles_by_owner(owner)
}

pub(crate) fn file_handle_path(handle_id: u64) -> Option<String> {
    FILE_HANDLE_REGISTRY.get_handle_path(handle_id)
}

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
// NVMe Direct Handle Registry
// ============================================================================

/// Entry for a kernel-opened direct block handle
struct NvmeOpenEntry {
    device_id: u64,
    start_block: u64,
    block_count: u64,
    block_size: u32,
    owner: u64,
    token: Option<u64>,
}

struct NvmeDirectRegistry {
    opens: Mutex<BTreeMap<u64, NvmeOpenEntry>>,
    next_id: AtomicU64,
}

impl NvmeDirectRegistry {
    const fn new() -> Self {
        Self {
            opens: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    fn register(
        &self,
        device_id: u64,
        start_block: u64,
        block_count: u64,
        block_size: u32,
        owner: u64,
        token: Option<u64>,
    ) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.opens.lock().insert(
            id,
            NvmeOpenEntry {
                device_id,
                start_block,
                block_count,
                block_size,
                owner,
                token,
            },
        );
        id
    }

    /// Unregister only if caller is owner or has CAP_SYS_ADMIN
    fn unregister_if_owner_or_admin(&self, id: u64, caller: u64) -> Option<NvmeOpenEntry> {
        // Check permission first
        let mgr = crate::security::capability::manager();
        let has_admin = mgr.has_capability(caller, crate::security::capability::CAP_SYS_ADMIN);
        let mut opens = self.opens.lock();
        if let Some(entry) = opens.get(&id) {
            if entry.owner == caller || has_admin {
                return opens.remove(&id);
            }
        }
        None
    }
}

static NVME_DIRECT_REGISTRY: NvmeDirectRegistry = NvmeDirectRegistry::new();

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
        log::info!("[KAPI] free_dma: unknown buffer: {:x}\n", virt_ptr);
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
        log::info!("{}", message);
    }

    // ========================================================================
    // Network (Connected to network stack)
    // ========================================================================

    fn net_create_endpoint(&self) -> Result<TcpEndpoint, KapiError> {
        use crate::net::endpoint::create_tcp_socket;

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
            let guard = mgr_lock.read();
            if let Some(mgr) = guard.as_ref() {
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
        // Backward-compatible: open without token
        self.fs_open_with_token(path, mode, None)
    }

    fn fs_open_with_token(&self, path: &str, mode: OpenMode, token: Option<u64>) -> Result<FileHandle, KapiError> {
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

        let caller = context::current_task_id();

        // If token provided, validate and increment in-flight counter
        if let Some(t) = token {
            if !crate::security::capability::manager().validate_token(caller, t, crate::security::capability::CAP_FOWNER) {
                return Err(KapiError::PermissionDenied);
            }

            if let Err(_) = crate::security::capability::manager().increment_in_flight(t) {
                return Err(KapiError::PermissionDenied);
            }
        }

        // Register in file handle table (recording owner for /proc/<pid>/fd)
        let handle_id = FILE_HANDLE_REGISTRY.register(FileHandleEntry {
            path: path_buf,
            mode,
            position: 0,
            token,
            owner: caller,
        });

        Ok(FileHandle::new(handle_id, mode))
    }

    fn fs_close(&self, handle: FileHandle) -> Result<(), KapiError> {
        let handle_id = handle.id();
        if let Some(entry) = FILE_HANDLE_REGISTRY.unregister(handle_id) {
            if let Some(t) = entry.token {
                let _ = crate::security::capability::manager().decrement_in_flight(t);
            }
            Ok(())
        } else {
            Err(KapiError::InvalidHandle)
        }
    }

    fn nvme_open_direct(
        &self,
        device_id: u64,
        start_block: u64,
        block_count: u64,
    ) -> Result<DirectBlockHandle, KapiError> {
        // Backward-compatible: open without token
        self.nvme_open_direct_with_token(device_id, start_block, block_count, None)
    }

    fn nvme_open_direct_with_token(
        &self,
        device_id: u64,
        start_block: u64,
        block_count: u64,
        token: Option<u64>,
    ) -> Result<DirectBlockHandle, KapiError> {
        if block_count == 0 {
            return Err(KapiError::IoError);
        }

        let nsid = if device_id == 0 { 1 } else { device_id as u32 };
        let block_size =
            crate::io::nvme::with_driver(|driver| driver.namespace_block_size(nsid))
                .unwrap_or(512);

        let caller = context::current_task_id();

        // If token provided, validate and increment in-flight counter
        if let Some(t) = token {
            if !crate::security::capability::manager().validate_token(caller, t, crate::security::capability::CAP_DMA) {
                return Err(KapiError::PermissionDenied);
            }
            if let Err(_) = crate::security::capability::manager().increment_in_flight(t) {
                return Err(KapiError::PermissionDenied);
            }
        }

        // Register the open in kernel registry and return a handle with open_id
        let id = NVME_DIRECT_REGISTRY.register(device_id, start_block, block_count, block_size, caller, token);
        Ok(DirectBlockHandle::new_with_id(device_id, start_block, block_count, block_size, id))
    }

    fn nvme_close_direct(&self, handle: DirectBlockHandle) -> Result<(), KapiError> {
        let id = handle.open_id();
        if id == 0 {
            return Err(KapiError::InvalidHandle);
        }

        let caller = context::current_task_id();

        match NVME_DIRECT_REGISTRY.unregister_if_owner_or_admin(id, caller) {
            Some(entry) => {
                if let Some(t) = entry.token {
                    // Best-effort decrement
                    let _ = crate::security::capability::manager().decrement_in_flight(t);
                }
                Ok(())
            }
            None => Err(KapiError::InvalidHandle),
        }
    }

    fn nvme_read_blocks_dma(
        &self,
        handle: DirectBlockHandle,
        block_offset: u64,
        buffer: DmaBuffer,
    ) -> Pin<Box<dyn Future<Output = KapiResult<DmaBuffer>> + Send>> {
        Box::pin(async move {
            let direct = crate::fs::DirectBlockHandle::new(
                handle.device_id(),
                handle.start_block(),
                handle.block_count(),
                handle.block_size(),
            );
            direct
                .read_blocks_dma(block_offset, buffer)
                .await
                .map_err(|_| KapiError::IoError)
        })
    }

    fn nvme_write_blocks_dma(
        &self,
        handle: DirectBlockHandle,
        block_offset: u64,
        buffer: DmaBuffer,
    ) -> Pin<Box<dyn Future<Output = KapiResult<DmaBuffer>> + Send>> {
        Box::pin(async move {
            let direct = crate::fs::DirectBlockHandle::new(
                handle.device_id(),
                handle.start_block(),
                handle.block_count(),
                handle.block_size(),
            );
            direct
                .write_blocks_dma(block_offset, buffer)
                .await
                .map_err(|_| KapiError::IoError)
        })
    }

    fn nvme_flush_direct(
        &self,
        handle: DirectBlockHandle,
    ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
        Box::pin(async move {
            let direct = crate::fs::DirectBlockHandle::new(
                handle.device_id(),
                handle.start_block(),
                handle.block_count(),
                handle.block_size(),
            );
            direct.flush().await.map_err(|_| KapiError::IoError)
        })
    }

    fn nvme_discard_direct(
        &self,
        handle: DirectBlockHandle,
        block_offset: u64,
        block_count: u64,
    ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
        Box::pin(async move {
            let direct = crate::fs::DirectBlockHandle::new(
                handle.device_id(),
                handle.start_block(),
                handle.block_count(),
                handle.block_size(),
            );
            direct
                .discard(block_offset, block_count)
                .await
                .map_err(|_| KapiError::IoError)
        })
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
        #[cfg(not(any(test, feature = "bench")))]
        {
            // GUI services are available only if framebuffer exists
            if crate::graphics::framebuffer().is_some() {
                Some(self)
            } else {
                None
            }
        }

        #[cfg(any(test, feature = "bench"))]
        {
            // In test/bench builds, graphics subsystem is disabled
            None
        }
    }

    fn shell(&self) -> Option<&dyn kernel_api::shell::ShellServices> {
        // Shell services are always available
        Some(self)
    }
}

// ============================================================================
// GuiServices Implementation
// ============================================================================

use kernel_api::gui::{
    FramebufferInfo as KapiFramebufferInfo, GuiServices, InputStreamHandle,
    PixelFormat as KapiPixelFormat,
};
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
        #[cfg(not(any(test, feature = "bench")))]
        {
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
        #[cfg(any(test, feature = "bench"))]
        {
            // Graphics unavailable in test builds
            Err(KapiError::NotSupported)
        }
    }

    fn get_input_stream_handle(&self) -> Result<InputStreamHandle, KapiError> {
        // Return a fixed handle ID for the global HID input stream
        // In a full implementation, this would register with an input manager
        Ok(InputStreamHandle(1))
    }

    fn current_tick(&self) -> u64 {
        crate::task::timer::current_tick()
    }

    fn poll_input_event(&self) -> Option<kernel_api::gui::InputEvent> {
        use kernel_api::gui::{
            InputEvent, KeyEvent as KapiKeyEvent, KeyState as KapiKeyState,
        };
        use crate::io::hid::keyboard::KeyEventExt;
        use spin::Mutex;
        use crate::io::hid::keyboard::KeyboardStream;

        #[cfg(feature = "mouse")]
        use kernel_api::gui::{MouseEvent as KapiMouseEvent, MouseButtons};

        // Lazy initialization of the global keyboard stream
        // We use a static Mutex to hold the stream exclusively for GuiServices
        static KEYBOARD_STREAM: Mutex<Option<KeyboardStream>> = Mutex::new(None);


        // Poll Keyboard Stream
        let hid_event_opt = {
            let mut stream_guard = KEYBOARD_STREAM.lock();
            
            // Initialize if empty
            if stream_guard.is_none() {
                 match crate::io::hid::keyboard::take_stream() {
                    Ok(stream) => *stream_guard = Some(stream),
                    Err(_) => {
                        // Stream taken by someone else?
                        // Just log once or ignore?
                    }
                 }
            }

            if let Some(stream) = stream_guard.as_mut() {
                // Manually poll the stream using its synchronous interface
                stream.poll()
            } else {
                None
            }
        };

        if let Some(hid_event) = hid_event_opt {
            let kapi_state = match hid_event.state {
                crate::io::hid::KeyState::Pressed => KapiKeyState::Pressed,
                crate::io::hid::KeyState::Released => KapiKeyState::Released,
            };

            // Encode modifiers as bitfield
            let mod_bits = {
                let mut bits = 0u8;
                if hid_event.modifiers.shift {
                    bits |= 0x01;
                }
                if hid_event.modifiers.ctrl {
                    bits |= 0x02;
                }
                if hid_event.modifiers.alt {
                    bits |= 0x04;
                }
                if hid_event.modifiers.alt_gr {
                    bits |= 0x08;
                }
                if hid_event.modifiers.caps_lock {
                    bits |= 0x10;
                }
                bits
            };

            // `to_char()` returns an `Option<char>`. Convert to an ASCII
            // `u8` (0 if not printable) to match the `char_value` field in
            // the kernel API `KeyEvent` (which stores ASCII bytes).
            let char_value = hid_event.to_char().map(|c| c as u8).unwrap_or(0u8);

            let kapi_event = KapiKeyEvent {
                scancode: hid_event.raw_scancode,
                char_value,
                state: kapi_state,
                modifiers: mod_bits,
            };

            return Some(InputEvent::Key(kapi_event));
        }

        // Try mouse (if feature enabled)
        #[cfg(feature = "mouse")]
        {
            // Note: poll_mouse_event is also deprecated, allowing it for now or we should fix it too.
            // But per task instructions: "Replace poll_input_event with KeyboardStream or equivalent"
            // We will silence the warning or use the non-deprecated path if possible.
            // Mouse stream is not yet standardized in this codebase context shown.
            // We'll treat it as existing logic for now, but cleaner to suppress if we can't fix it yet.
            #[allow(deprecated)] 
            if let Some(mouse_event) = crate::io::hid::mouse::poll_mouse_event() {
                let buttons = MouseButtons(
                    if mouse_event.buttons.left() {
                        MouseButtons::LEFT
                    } else {
                        0
                    } | if mouse_event.buttons.right() {
                        MouseButtons::RIGHT
                    } else {
                        0
                    } | if mouse_event.buttons.middle() {
                        MouseButtons::MIDDLE
                    } else {
                        0
                    },
                );

                let kapi_mouse = KapiMouseEvent {
                    dx: mouse_event.delta_x,
                    dy: mouse_event.delta_y,
                    buttons,
                };

                return Some(InputEvent::Mouse(kapi_mouse));
            }
        }

        None
    }

    fn yield_control(&self) {
        // Synchronous yield - just hint to the scheduler that we're willing to yield
        // In an async context, the caller should use `.await` on yield_now() instead
        core::hint::spin_loop();
    }
}

// ============================================================================
// ShellServices Implementation
// ============================================================================

use kernel_api::shell::{
    DirEntry as KapiDirEntry, MemoryStats, ProcessInfo, ShellServices, SystemInfo as KapiSystemInfo,
};

impl ShellServices for ExoKernel {
    fn memory_stats(&self) -> MemoryStats {
        MemoryStats {
            total_kb: crate::memory::total_memory_kb() as usize,
            free_kb: crate::memory::free_memory_kb() as usize,
            used_kb: crate::memory::used_memory_kb() as usize,
        }
    }

    fn current_tick(&self) -> u64 {
        crate::task::timer::current_tick()
    }

    fn list_processes(&self) -> alloc::vec::Vec<ProcessInfo> {
        let pm = crate::task::process_manager();
        let mut result = alloc::vec::Vec::new();

        for pid in 0..100u64 {
            let proc_id = crate::task::ProcessId::new(pid);
            if let Some(process) = pm.get(proc_id) {
                let p = process.read();
                let state = match p.state {
                    crate::task::ProcessState::Running | crate::task::ProcessState::Ready => {
                        kernel_api::shell::ProcessState::Running
                    }
                    crate::task::ProcessState::Blocked => kernel_api::shell::ProcessState::Blocked,
                    crate::task::ProcessState::Stopped => kernel_api::shell::ProcessState::Stopped,
                    crate::task::ProcessState::Zombie => kernel_api::shell::ProcessState::Zombie,
                    _ => kernel_api::shell::ProcessState::Sleeping,
                };

                result.push(ProcessInfo {
                    pid,
                    name: p.name.clone(),
                    state,
                    memory_kb: 0,
                    cpu_usage: 0.0,
                    domain: alloc::string::String::from("user"),
                    uid: p.credentials.uid.as_u32(),
                });
            }
        }

        if result.is_empty() {
            result.push(ProcessInfo {
                pid: 0,
                name: alloc::string::String::from("kernel"),
                state: kernel_api::shell::ProcessState::Running,
                memory_kb: crate::memory::used_memory_kb() as usize,
                cpu_usage: 0.0,
                domain: alloc::string::String::from("kernel"),
                uid: 0,
            });
        }

        result
    }

    fn get_process(&self, pid: u64) -> Option<ProcessInfo> {
        let proc_id = crate::task::ProcessId::new(pid);

        if let Some(process) = crate::task::process_manager().get(proc_id) {
            let p = process.read();
            let state = match p.state {
                crate::task::ProcessState::Running | crate::task::ProcessState::Ready => {
                    kernel_api::shell::ProcessState::Running
                }
                crate::task::ProcessState::Blocked => kernel_api::shell::ProcessState::Blocked,
                crate::task::ProcessState::Stopped => kernel_api::shell::ProcessState::Stopped,
                crate::task::ProcessState::Zombie => kernel_api::shell::ProcessState::Zombie,
                _ => kernel_api::shell::ProcessState::Sleeping,
            };

            Some(ProcessInfo {
                pid,
                name: p.name.clone(),
                state,
                memory_kb: 0,
                cpu_usage: 0.0,
                domain: alloc::string::String::from("user"),
                uid: p.credentials.uid.as_u32(),
            })
        } else if pid == 0 {
            Some(ProcessInfo {
                pid: 0,
                name: alloc::string::String::from("kernel"),
                state: kernel_api::shell::ProcessState::Running,
                memory_kb: crate::memory::used_memory_kb() as usize,
                cpu_usage: 0.0,
                domain: alloc::string::String::from("kernel"),
                uid: 0,
            })
        } else {
            None
        }
    }

    fn kill_process(
        &self,
        pid: u64,
        caller_uid: u32,
        has_cap_kill: bool,
    ) -> Result<(), &'static str> {
        if pid == 0 {
            return Err("Cannot kill kernel process");
        }

        let proc_id = crate::task::ProcessId::new(pid);
        let pm = crate::task::process_manager();

        if let Some(process) = pm.get(proc_id) {
            let target_uid = process.read().credentials.uid.as_u32();

            if caller_uid != target_uid && !has_cap_kill {
                return Err("Permission denied: Owner or CAP_KILL required");
            }

            process.write().state = crate::task::ProcessState::Stopped;
            Ok(())
        } else {
            Err("Process not found")
        }
    }

    fn current_uid(&self) -> u32 {
        crate::task::process::getuid().as_u32()
    }

    fn current_pid(&self) -> u64 {
        crate::task::process::getpid().as_u64()
    }

    fn system_info(&self) -> KapiSystemInfo {
        KapiSystemInfo {
            uptime_ticks: crate::task::timer::current_tick(),
            cpu_temperature: crate::thermal::cpu_temperature().map(|t| t.celsius() as f32),
        }
    }

    fn monitor_info(&self) -> kernel_api::shell::MonitorInfo {
        let snap = crate::monitor::snapshot();
        kernel_api::shell::MonitorInfo {
            timestamp: snap.timestamp,
            cpu_usage: snap.cpu_usage,
            memory: kernel_api::shell::MemoryMonitorInfo {
                heap_used: snap.memory.heap_used,
                heap_free: snap.memory.heap_free,
                heap_total: snap.memory.heap_total,
                usage_percent: snap.memory.usage_percent,
            },
            domains: kernel_api::shell::DomainMonitorInfo {
                total: snap.domains.total,
                running: snap.domains.running,
                stopped: snap.domains.stopped,
            },
            tasks: kernel_api::shell::TaskMonitorInfo {
                context_switches: snap.tasks.context_switches,
                voluntary_yields: snap.tasks.voluntary_yields,
                forced_preemptions: snap.tasks.forced_preemptions,
            },
            network: kernel_api::shell::NetworkMonitorInfo {
                rx_packets: snap.network.rx_packets,
                tx_packets: snap.network.tx_packets,
                rx_bytes: snap.network.rx_bytes,
                tx_bytes: snap.network.tx_bytes,
            },
        }
    }

    fn thermal_info(&self) -> kernel_api::shell::ThermalInfo {
        let tm = crate::thermal::thermal_manager();
        let (polling_count, trip_events) = tm.stats();
        let throttle = tm.throttle_controller();
        let sensors = tm
            .sensors()
            .iter()
            .map(|s| kernel_api::shell::ThermalSensorInfo {
                id: s.id as usize,
                name: s.name.clone(),
                current_c: if s.current.is_valid() {
                    Some(s.current.celsius() as f32)
                } else {
                    None
                },
                is_hot: s.is_hot(),
                is_critical: s.is_critical(),
            })
            .collect();

        kernel_api::shell::ThermalInfo {
            cpu_celsius: crate::thermal::cpu_temperature().map(|t| t.celsius() as f32),
            polling_count,
            trip_events,
            throttle_policy: alloc::format!("{:?}", throttle.current_policy()),
            throttle_count: throttle.throttle_count(),
            sensors,
        }
    }

    fn watchdog_info(&self) -> kernel_api::shell::WatchdogInfo {
        let wm = crate::watchdog::watchdog_manager();
        let (heartbeats, timeouts, checks) = wm.software().stats();
        kernel_api::shell::WatchdogInfo {
            heartbeats,
            timeouts,
            checks,
            deadlocks_detected: wm.deadlock_detector().deadlocks_detected(),
        }
    }

    fn power_info(&self) -> kernel_api::shell::PowerInfo {
        let pm = crate::power::power_manager();
        let idle = crate::power::cpu_idle();
        let (c1, c2, c3) = idle.stats();
        let stats = pm.stats();

        kernel_api::shell::PowerInfo {
            state: alloc::format!("{:?}", pm.current_state()),
            power_button_presses: stats
                .power_button_presses
                .load(core::sync::atomic::Ordering::Relaxed),
            sleep_button_presses: stats
                .sleep_button_presses
                .load(core::sync::atomic::Ordering::Relaxed),
            cpu_idle: kernel_api::shell::CpuIdleInfo {
                c1_count: c1,
                c2_count: c2,
                c3_count: c3,
            },
        }
    }

    fn cpu_temperature(&self) -> Option<f32> {
        crate::thermal::cpu_temperature().map(|t| t.celsius() as f32)
    }

    fn shutdown(&self) -> ! {
        crate::power::shutdown()
    }

    fn reboot(&self) -> ! {
        crate::power::reboot()
    }

    fn list_directory(&self, path: &str) -> Result<alloc::vec::Vec<KapiDirEntry>, &'static str> {
        match crate::fs::list_directory(path, "/") {
            Ok(entries) => {
                let result = entries
                    .into_iter()
                    .map(|e| {
                        let file_type = match e.file_type {
                            crate::fs::FileType::Directory => {
                                kernel_api::shell::FileType::Directory
                            }
                            crate::fs::FileType::Symlink => kernel_api::shell::FileType::Symlink,
                            crate::fs::FileType::CharDevice => {
                                kernel_api::shell::FileType::CharDevice
                            }
                            crate::fs::FileType::BlockDevice => {
                                kernel_api::shell::FileType::BlockDevice
                            }
                            crate::fs::FileType::Socket => kernel_api::shell::FileType::Socket,
                            crate::fs::FileType::Fifo => kernel_api::shell::FileType::Fifo,
                            _ => kernel_api::shell::FileType::File,
                        };
                        KapiDirEntry {
                            name: e.name,
                            file_type,
                            size: 0,
                            ino: e.ino,
                        }
                    })
                    .collect();
                Ok(result)
            }
            Err(_) => Err("Failed to list directory"),
        }
    }

    fn read_file(&self, path: &str) -> Result<alloc::vec::Vec<u8>, &'static str> {
        crate::fs::read_file_content(path, "/").map_err(|_| "Failed to read file")
    }

    fn read_file_zero_copy(
        &self,
        path: &str,
    ) -> Result<alloc::sync::Arc<alloc::vec::Vec<u8>>, &'static str> {
        // Use async_memfs's Bytes type internally for zero-copy semantics
        use crate::fs::async_memfs::Bytes;

        // Read content
        let content = crate::fs::read_file_content(path, "/").map_err(|_| "Failed to read file")?;

        // Wrap in Bytes and extract Arc
        let bytes = Bytes::from(content);
        Ok(bytes.into_inner())
    }

    fn write_file(&self, path: &str, data: &[u8]) -> Result<(), &'static str> {
        crate::fs::write_file_content(path, "/", data).map_err(|_| "Failed to write file")
    }

    fn stat_file(&self, path: &str) -> Result<kernel_api::shell::FileAttributes, &'static str> {
        match crate::fs::stat_file(path, "/") {
            Ok(attr) => {
                let file_type = match attr.file_type {
                    crate::fs::FileType::Directory => kernel_api::shell::FileType::Directory,
                    crate::fs::FileType::Symlink => kernel_api::shell::FileType::Symlink,
                    crate::fs::FileType::CharDevice => kernel_api::shell::FileType::CharDevice,
                    crate::fs::FileType::BlockDevice => kernel_api::shell::FileType::BlockDevice,
                    crate::fs::FileType::Socket => kernel_api::shell::FileType::Socket,
                    crate::fs::FileType::Fifo => kernel_api::shell::FileType::Fifo,
                    _ => kernel_api::shell::FileType::File,
                };
                Ok(kernel_api::shell::FileAttributes {
                    size: attr.size,
                    ino: attr.ino,
                    nlink: attr.nlink as u64,
                    file_type,
                })
            }
            Err(_) => Err("Failed to stat file"),
        }
    }

    fn make_directory(&self, path: &str) -> Result<(), &'static str> {
        crate::fs::make_directory(path, "/").map_err(|_| "Failed to create directory")
    }

    fn remove_file(&self, path: &str) -> Result<(), &'static str> {
        crate::fs::remove_file(path, "/").map_err(|_| "Failed to remove file")
    }

    fn remove_directory(&self, path: &str) -> Result<(), &'static str> {
        crate::fs::remove_directory(path, "/").map_err(|_| "Failed to remove directory")
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod nvme_tests {
    use super::*;
    use crate::task::process;
    use crate::security::capability::{self, CapabilitySet};

    #[test_case]
    fn test_nvme_open_with_token_reclaim() {
        // Setup: create caller and target domains
        let caller = process::process_manager().create(process::ProcessId::INIT, "caller_nvme").unwrap();
        let target = process::process_manager().create(process::ProcessId::INIT, "target_nvme").unwrap();

        // Caller gets permission to grant CAP_DMA
        process::set_current_process(caller);
        crate::security::capability::manager().set_capabilities(caller.as_u64(), CapabilitySet::with_permitted(crate::security::capability::CAP_DMA));

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_DMA, None, false)
            .unwrap();

        // Target opens using token
        process::set_current_process(target);
        let handle = EXOKERNEL
            .nvme_open_direct_with_token(0, 0, 1, Some(token))
            .expect("open should succeed");
        assert_eq!(crate::security::capability::manager().in_flight_count(token), 1);

        // Issue revocation
        process::set_current_process(caller);
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Target closes handle
        process::set_current_process(target);
        assert!(EXOKERNEL.nvme_close_direct(handle).is_ok());

        assert_eq!(crate::security::capability::manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        process::set_current_process(caller);
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }
}

#[cfg(test)]
mod fs_tests {
    use super::*;
    use crate::task::process;
    use crate::security::capability::{self, CapabilitySet};

    #[test_case]
    fn test_fs_open_with_token_reclaim() {
        // Setup: create caller and target domains
        let caller = process::process_manager().create(process::ProcessId::INIT, "caller_fs").unwrap();
        let target = process::process_manager().create(process::ProcessId::INIT, "target_fs").unwrap();

        // Caller gets permission to grant CAP_FOWNER
        process::set_current_process(caller);
        crate::security::capability::manager().set_capabilities(caller.as_u64(), CapabilitySet::with_permitted(crate::security::capability::CAP_FOWNER));

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_FOWNER, None, false)
            .unwrap();

        // Target opens using token
        process::set_current_process(target);
        let handle = EXOKERNEL
            .fs_open_with_token("test_token_file", kernel_api::OpenMode::Write, Some(token))
            .expect("open should succeed");
        assert_eq!(crate::security::capability::manager().in_flight_count(token), 1);

        // Issue revocation
        process::set_current_process(caller);
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Close file handle
        process::set_current_process(target);
        assert!(EXOKERNEL.fs_close(handle).is_ok());

        // Now reclaim should succeed
        process::set_current_process(caller);
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }
}

/// Get a reference to the exokernel (for internal use)
pub fn exokernel() -> &'static ExoKernel {
    &EXOKERNEL
}

