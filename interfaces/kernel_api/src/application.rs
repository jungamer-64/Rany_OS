// ============================================================================
// kernel_api/src/application.rs - Application Trait and Context
// ============================================================================
//!
//! Application interface for ExoRust.
//!
//! This module defines the core application types shared between
//! the kernel and application crates.

extern crate alloc;

use crate::security::{
    DmaCapability, DomainCapabilities, FsCapability, IoCapability, IpcCapability, MemoryCapability,
    NetCapability, TaskCapability,
};
use alloc::boxed::Box;
use alloc::string::String;
use core::future::Future;
use core::pin::Pin;

// ============================================================================
// Application Trait
// ============================================================================

/// ExoRust application entry point
///
/// All applications must implement this trait.
pub trait Application: Send + Sync {
    /// Application main entry point
    fn on_start(&mut self, ctx: AppContext) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

    /// Cleanup on stop (optional)
    fn on_stop(&mut self) {
        // Default: do nothing
    }

    /// Application name
    fn name(&self) -> &str {
        "unnamed"
    }
}

// ============================================================================
// AppContext - Runtime Context
// ============================================================================

/// Application runtime context
///
/// Passed to applications at startup by the kernel.
/// Applications can only access KAPI through this context.
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
    /// Create new context (kernel-internal use)
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

    /// Access all capabilities
    pub fn capabilities(&self) -> &DomainCapabilities {
        &self.capabilities
    }
}
