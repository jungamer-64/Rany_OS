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

/// Network access capability
#[derive(Debug)]
pub struct NetCapability {
    _private: (),
}

unsafe impl Send for NetCapability {}
unsafe impl Sync for NetCapability {}

/// I/O port access capability
#[derive(Debug)]
pub struct IoCapability {
    _private: (),
}

unsafe impl Send for IoCapability {}
unsafe impl Sync for IoCapability {}

/// Interrupt registration capability
#[derive(Debug)]
pub struct InterruptCapability {
    _private: (),
}

unsafe impl Send for InterruptCapability {}
unsafe impl Sync for InterruptCapability {}

/// DMA access capability
#[derive(Debug)]
pub struct DmaCapability {
    _private: (),
}

unsafe impl Send for DmaCapability {}
unsafe impl Sync for DmaCapability {}

/// Filesystem access capability
#[derive(Debug)]
pub struct FsCapability {
    _private: (),
}

unsafe impl Send for FsCapability {}
unsafe impl Sync for FsCapability {}

/// IPC capability
#[derive(Debug)]
pub struct IpcCapability {
    _private: (),
}

unsafe impl Send for IpcCapability {}
unsafe impl Sync for IpcCapability {}

/// Task spawning capability
#[derive(Debug)]
pub struct TaskCapability {
    _private: (),
}

unsafe impl Send for TaskCapability {}
unsafe impl Sync for TaskCapability {}

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
