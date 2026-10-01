// ============================================================================
// kernel/src/io/iommu/common/dma/handle.rs
// ============================================================================

//! DMA Handle - IOMMU-mapped buffer with ownership tracking
//!
//! This module provides `DmaHandle<T>`, a type-safe wrapper for IOMMU-mapped
//! DMA buffers that integrates with `RRef<T>` for ownership tracking.
//!
//! # Key Features
//!
//! - **Leak Detection**: `Drop` logs and leaks if handle is dropped without proper unmap
//! - **Backend Unmap**: `unmap()` routes through the global IOMMU API
//! - **Ownership Safety**: Errors return the original `RRef<T>` or `DmaHandle<T>`
//! - **Resource Registry Integration**: Handles are tracked per-domain for SAS safety
//!
//! # Async-First Design
//!
//! The module supports both synchronous and asynchronous IOTLB invalidation:
//!
//! | API                | Behavior                  | Feature Flag                   |
//! |--------------------|---------------------------|--------------------------------|
//! | `unmap()`          | Sync or Lazy (cfg)        | `async_unmap_default`          |
//! | `unmap_sync()`     | Always synchronous        | Always available               |
//! | `unmap_async()`    | Async completion          | Always available               |
//!
//! When `async_unmap_default` feature is enabled, `unmap()` uses deferred
//! invalidation via Quarantine for improved throughput in high-frequency
//! DMA workloads.
//!
//! # Resource Registry
//!
//! Each `DmaHandle` is registered with its domain's `DmaResourceRegistry`
//! (if available). This enables:
//!
//! - **Leak Prevention**: Domain destruction can force-unmap leaked handles
//! - **Resource Tracking**: Monitor active DMA mappings per domain
//! - **SAS Safety**: Prevent memory reuse while DMA is active
//!
//! # Example
//!
//! ```ignore
//! let rref = RRef::new_slice_default_aligned(
//!     DomainId::KERNEL,
//!     4096,
//!     crate::mm::types::PAGE_SIZE_4K,
//! )
//! .expect("alloc rref slice");
//! let device = crate::io::iommu::types::DeviceId::new(0, 0, 1, 0);
//! let handle = crate::io::iommu::common::dma::handle::DmaHandle::map_rref_slice_for_device(
//!     rref,
//!     &device,
//!     DmaDirection::ToDevice,
//! )?;
//!
//! // Use handle.iova() for device programming
//! device.set_dma_address(handle.iova());
//!
//! // When done, unmap to get RRef back
//! let rref = handle.unmap()?;
//! ```

use core::marker::PhantomData;

// use super::IommuController;
use crate::io::iommu::types::{DeviceId, IommuError};
use crate::ipc::RRef;

// ============================================================================
// DMA Direction
// ============================================================================

/// DMA transfer direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    /// CPU writes, device reads (e.g., TX buffer)
    ToDevice,
    /// Device writes, CPU reads (e.g., RX buffer)
    FromDevice,
    /// Bidirectional access
    Bidirectional,
}

// ============================================================================
// Error Types
// ============================================================================

/// Map operation error kind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapErrorKind {
    /// No IOVA space available
    OutOfIova,
    /// Page table is full
    PageTableFull,
    /// Buffer is not properly aligned
    InvalidAlignment,
    /// Domain not found
    DomainNotFound,
    /// IOMMU error
    IommuError(IommuError),
}

/// A rejected map returns ordinary ownership. Once a data leaf may have been
/// published, the error retains a DMA handle instead; its backing cannot be
/// accessed or returned to an allocator until explicit unmap completes.
#[derive(Debug)]
pub enum MapError<T: ?Sized + 'static> {
    Unmapped {
        rref: RRef<T>,
        kind: MapErrorKind,
    },
    TranslationPending {
        handle: DmaHandle<T>,
        kind: MapErrorKind,
    },
}
impl<T: ?Sized + 'static> MapError<T> {
    pub fn unmapped(rref: RRef<T>, kind: MapErrorKind) -> Self {
        Self::Unmapped { rref, kind }
    }
    pub fn kind(&self) -> MapErrorKind {
        match self {
            Self::Unmapped { kind, .. } | Self::TranslationPending { kind, .. } => *kind,
        }
    }
}

/// Unmap operation error kind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmapErrorKind {
    /// Invalid IOVA address
    InvalidIova,
    /// Mapping requires a domain/context-specific unmap
    InvalidContext,
    /// IOTLB invalidation timed out
    IoTlbTimeout,
    /// Domain not found
    DomainNotFound,
    /// IOMMU error
    IommuError(IommuError),
    /// Called from ISR context where blocking operations are forbidden
    ///
    /// Synchronous unmap waits for hardware IOTLB invalidation completion,
    /// which is not allowed in interrupt handlers. Use `unmap()` with
    /// `async_unmap_default` feature or `unmap_async()` instead.
    CalledFromIsr,
    /// Blocking safety cannot be established without validated CPU-local state.
    CpuLocalUnavailable,
}

/// Unmap operation error (returns ownership on failure)
///
/// # Critical Safety
///
/// This error type returns the `DmaHandle<T>` so that ownership is not lost.
/// The caller can retry the unmap or take other recovery action.
#[derive(Debug)]
pub struct UnmapError<T: ?Sized + 'static> {
    /// The handle - returned so caller can retry
    pub handle: DmaHandle<T>,
    /// Error kind
    pub kind: UnmapErrorKind,
}

impl<T: ?Sized + 'static> UnmapError<T> {
    /// Create a new unmap error
    pub fn new(handle: DmaHandle<T>, kind: UnmapErrorKind) -> Self {
        Self { handle, kind }
    }
}

// ============================================================================
// DmaHandle<T>
// ============================================================================

