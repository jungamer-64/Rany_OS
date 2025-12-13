// ============================================================================
// libs/app_sdk/src/context.rs - Application Context
// ============================================================================
//!
//! Runtime context passed to applications at startup.

use alloc::string::String;
use kernel_api::{
    DmaCapability, DomainCapabilities, FsCapability, IoCapability, IpcCapability, MemoryCapability,
    NetCapability, TaskCapability,
};

/// Application Runtime Context
///
/// Passed to applications when they start.
/// Provides access to capabilities assigned by the kernel.
pub struct AppContext {
    /// Application ID
    pub app_id: u64,
    /// Application name
    pub name: String,
    /// Domain ID
    pub domain_id: u64,
    /// Capability bundle
    capabilities: DomainCapabilities,
}

impl AppContext {
    /// Create new context (kernel-only)
    pub fn new(
        app_id: u64,
        name: String,
        domain_id: u64,
        capabilities: DomainCapabilities,
    ) -> Self {
        Self {
            app_id,
            name,
            domain_id,
            capabilities,
        }
    }

    // --- Capability Accessors ---

    /// Get network capability
    #[inline]
    pub fn net(&self) -> Option<&NetCapability> {
        self.capabilities.net.as_ref()
    }

    /// Get filesystem capability
    #[inline]
    pub fn fs(&self) -> Option<&FsCapability> {
        self.capabilities.fs.as_ref()
    }

    /// Get I/O capability
    #[inline]
    pub fn io(&self) -> Option<&IoCapability> {
        self.capabilities.io.as_ref()
    }

    /// Get task capability
    #[inline]
    pub fn task(&self) -> Option<&TaskCapability> {
        self.capabilities.task.as_ref()
    }

    /// Get IPC capability
    #[inline]
    pub fn ipc(&self) -> Option<&IpcCapability> {
        self.capabilities.ipc.as_ref()
    }

    /// Get DMA capability
    #[inline]
    pub fn dma(&self) -> Option<&DmaCapability> {
        self.capabilities.dma.as_ref()
    }

    /// Get memory capability
    #[inline]
    pub fn memory(&self) -> Option<&MemoryCapability> {
        self.capabilities.memory.as_ref()
    }

    /// Get all capabilities
    pub fn capabilities(&self) -> &DomainCapabilities {
        &self.capabilities
    }
}
