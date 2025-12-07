// ============================================================================
// kernel_api/src/capability.rs - Static Capability Marker Types
// ============================================================================
//!
//! Zero-sized marker types for compile-time capability checking.
//!
//! These types are used to enforce access control at compile time,
//! eliminating runtime permission checks.
//!
//! ## Usage
//!
//! Functions that require specific capabilities take the corresponding
//! marker type as a parameter, proving at compile time that the caller
//! has the required permission.
//!
//! ```rust,ignore
//! fn send_packet(cap: &NetCapability, data: &[u8]) -> Result<(), Error> {
//!     // Only callable if caller has NetCapability
//! }
//! ```

use core::marker::PhantomData;

/// Base trait for all capability markers
pub trait Capability: private::Sealed {
    /// Human-readable name of this capability
    const NAME: &'static str;
}

mod private {
    pub trait Sealed {}
}

/// Network access capability
#[derive(Debug, Clone, Copy)]
pub struct NetCapability(PhantomData<()>);

impl private::Sealed for NetCapability {}
impl Capability for NetCapability {
    const NAME: &'static str = "network";
}

impl NetCapability {
    /// Create a new NetCapability (kernel-only)
    /// 
    /// # Safety
    /// Only the kernel should create capabilities.
    pub const unsafe fn new() -> Self {
        Self(PhantomData)
    }
}

/// Filesystem access capability
#[derive(Debug, Clone, Copy)]
pub struct FsCapability(PhantomData<()>);

impl private::Sealed for FsCapability {}
impl Capability for FsCapability {
    const NAME: &'static str = "filesystem";
}

impl FsCapability {
    /// # Safety
    /// Only the kernel should create capabilities.
    pub const unsafe fn new() -> Self {
        Self(PhantomData)
    }
}

/// DMA access capability
#[derive(Debug, Clone, Copy)]
pub struct DmaCapability(PhantomData<()>);

impl private::Sealed for DmaCapability {}
impl Capability for DmaCapability {
    const NAME: &'static str = "dma";
}

impl DmaCapability {
    /// # Safety
    /// Only the kernel should create capabilities.
    pub const unsafe fn new() -> Self {
        Self(PhantomData)
    }
}

/// I/O port access capability
#[derive(Debug, Clone, Copy)]
pub struct IoCapability(PhantomData<()>);

impl private::Sealed for IoCapability {}
impl Capability for IoCapability {
    const NAME: &'static str = "io";
}

impl IoCapability {
    /// # Safety
    /// Only the kernel should create capabilities.
    pub const unsafe fn new() -> Self {
        Self(PhantomData)
    }
}

/// Task management capability
#[derive(Debug, Clone, Copy)]
pub struct TaskCapability(PhantomData<()>);

impl private::Sealed for TaskCapability {}
impl Capability for TaskCapability {
    const NAME: &'static str = "task";
}

impl TaskCapability {
    /// # Safety
    /// Only the kernel should create capabilities.
    pub const unsafe fn new() -> Self {
        Self(PhantomData)
    }
}

/// IPC capability
#[derive(Debug, Clone, Copy)]
pub struct IpcCapability(PhantomData<()>);

impl private::Sealed for IpcCapability {}
impl Capability for IpcCapability {
    const NAME: &'static str = "ipc";
}

impl IpcCapability {
    /// # Safety
    /// Only the kernel should create capabilities.
    pub const unsafe fn new() -> Self {
        Self(PhantomData)
    }
}
