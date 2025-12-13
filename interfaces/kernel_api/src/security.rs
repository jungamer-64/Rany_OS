// ============================================================================
// kernel_api/src/security.rs - Static Capability Types
// ============================================================================
//!
//! Zero-sized capability marker types for compile-time permission checking.
//! These types are shared between kernel, app_sdk, and applications.

// PhantomData is unused - keep import out to avoid warnings

// ============================================================================
// Capability Marker Types
// ============================================================================

/// Memory mapping capability
#[derive(Debug)]
pub struct MemoryCapability {
    _private: (),
}

unsafe impl Send for MemoryCapability {}
unsafe impl Sync for MemoryCapability {}

impl MemoryCapability {
    /// Create a new capability (kernel-only)
    ///
    /// # Safety
    /// Only the kernel should create capabilities.
    #[inline(always)]
    pub const unsafe fn new() -> Self {
        Self { _private: () }
    }
}

/// Network access capability
#[derive(Debug)]
pub struct NetCapability {
    _private: (),
}

unsafe impl Send for NetCapability {}
unsafe impl Sync for NetCapability {}

impl NetCapability {
    #[inline(always)]
    pub const unsafe fn new() -> Self {
        Self { _private: () }
    }
}

/// I/O port access capability
#[derive(Debug)]
pub struct IoCapability {
    _private: (),
}

unsafe impl Send for IoCapability {}
unsafe impl Sync for IoCapability {}

impl IoCapability {
    #[inline(always)]
    pub const unsafe fn new() -> Self {
        Self { _private: () }
    }
}

/// Interrupt registration capability
#[derive(Debug)]
pub struct InterruptCapability {
    _private: (),
}

unsafe impl Send for InterruptCapability {}
unsafe impl Sync for InterruptCapability {}

impl InterruptCapability {
    #[inline(always)]
    pub const unsafe fn new() -> Self {
        Self { _private: () }
    }
}

/// DMA access capability
#[derive(Debug)]
pub struct DmaCapability {
    _private: (),
}

unsafe impl Send for DmaCapability {}
unsafe impl Sync for DmaCapability {}

impl DmaCapability {
    #[inline(always)]
    pub const unsafe fn new() -> Self {
        Self { _private: () }
    }
}

/// Filesystem access capability
#[derive(Debug)]
pub struct FsCapability {
    _private: (),
}

unsafe impl Send for FsCapability {}
unsafe impl Sync for FsCapability {}

impl FsCapability {
    #[inline(always)]
    pub const unsafe fn new() -> Self {
        Self { _private: () }
    }
}

/// IPC capability
#[derive(Debug)]
pub struct IpcCapability {
    _private: (),
}

unsafe impl Send for IpcCapability {}
unsafe impl Sync for IpcCapability {}

impl IpcCapability {
    #[inline(always)]
    pub const unsafe fn new() -> Self {
        Self { _private: () }
    }
}

/// Task spawning capability
#[derive(Debug)]
pub struct TaskCapability {
    _private: (),
}

unsafe impl Send for TaskCapability {}
unsafe impl Sync for TaskCapability {}

impl TaskCapability {
    #[inline(always)]
    pub const unsafe fn new() -> Self {
        Self { _private: () }
    }
}

// ============================================================================
// DomainCapabilities Bundle
// ============================================================================

/// Bundle of capabilities assigned to a domain
///
/// Each field is Option - None means permission denied.
pub struct DomainCapabilities {
    pub memory: Option<MemoryCapability>,
    pub net: Option<NetCapability>,
    pub io: Option<IoCapability>,
    pub interrupt: Option<InterruptCapability>,
    pub dma: Option<DmaCapability>,
    pub fs: Option<FsCapability>,
    pub ipc: Option<IpcCapability>,
    pub task: Option<TaskCapability>,
}

impl DomainCapabilities {
    /// Empty capability set (sandbox)
    pub const fn empty() -> Self {
        Self {
            memory: None,
            net: None,
            io: None,
            interrupt: None,
            dma: None,
            fs: None,
            ipc: None,
            task: None,
        }
    }

    /// Check if has memory capability
    #[inline]
    pub fn has_memory(&self) -> bool {
        self.memory.is_some()
    }

    /// Check if has network capability
    #[inline]
    pub fn has_net(&self) -> bool {
        self.net.is_some()
    }

    /// Check if has I/O capability
    #[inline]
    pub fn has_io(&self) -> bool {
        self.io.is_some()
    }

    /// Check if has DMA capability
    #[inline]
    pub fn has_dma(&self) -> bool {
        self.dma.is_some()
    }

    /// Check if has filesystem capability
    #[inline]
    pub fn has_fs(&self) -> bool {
        self.fs.is_some()
    }

    /// Check if has IPC capability
    #[inline]
    pub fn has_ipc(&self) -> bool {
        self.ipc.is_some()
    }

    /// Check if has task capability
    #[inline]
    pub fn has_task(&self) -> bool {
        self.task.is_some()
    }
}

// ============================================================================
// Kernel-only capability factory
// ============================================================================

/// Kernel-only capability factory
pub mod kernel_only {
    use super::*;

    /// Grant all capabilities (for kernel itself)
    ///
    /// # Safety
    /// Only call during kernel initialization
    pub unsafe fn grant_all() -> DomainCapabilities {
        DomainCapabilities {
            memory: Some(unsafe { MemoryCapability::new() }),
            net: Some(unsafe { NetCapability::new() }),
            io: Some(unsafe { IoCapability::new() }),
            interrupt: Some(unsafe { InterruptCapability::new() }),
            dma: Some(unsafe { DmaCapability::new() }),
            fs: Some(unsafe { FsCapability::new() }),
            ipc: Some(unsafe { IpcCapability::new() }),
            task: Some(unsafe { TaskCapability::new() }),
        }
    }

    /// Grant memory capability
    #[inline(always)]
    pub unsafe fn grant_memory() -> MemoryCapability {
        unsafe { MemoryCapability::new() }
    }

    /// Grant network capability
    #[inline(always)]
    pub unsafe fn grant_net() -> NetCapability {
        unsafe { NetCapability::new() }
    }

    /// Grant I/O capability
    #[inline(always)]
    pub unsafe fn grant_io() -> IoCapability {
        unsafe { IoCapability::new() }
    }

    /// Grant interrupt capability
    #[inline(always)]
    pub unsafe fn grant_interrupt() -> InterruptCapability {
        unsafe { InterruptCapability::new() }
    }

    /// Grant DMA capability
    #[inline(always)]
    pub unsafe fn grant_dma() -> DmaCapability {
        unsafe { DmaCapability::new() }
    }

    /// Grant filesystem capability
    #[inline(always)]
    pub unsafe fn grant_fs() -> FsCapability {
        unsafe { FsCapability::new() }
    }

    /// Grant IPC capability
    #[inline(always)]
    pub unsafe fn grant_ipc() -> IpcCapability {
        unsafe { IpcCapability::new() }
    }

    /// Grant task capability
    #[inline(always)]
    pub unsafe fn grant_task() -> TaskCapability {
        unsafe { TaskCapability::new() }
    }
}
