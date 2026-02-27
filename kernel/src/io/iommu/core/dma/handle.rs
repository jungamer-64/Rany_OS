// ============================================================================
// kernel/src/io/iommu/dma_handle.rs
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
//! let handle = crate::io::iommu::dma_handle::DmaHandle::map_rref_slice(
//!     rref,
//!     0,
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
use super::domain::{InvalidateRequest, IommuDomain, IommuInvalidator};
use super::interface::IommuHardwareContext;
use super::types::{DeviceId, IommuError};
use crate::ipc::RRef;

// ============================================================================
// DMA Direction
// ============================================================================

/// DMA transfer direction
mod slice_handle;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    /// CPU writes, device reads (e.g., TX buffer)
    ToDevice,
    /// Device writes, CPU reads (e.g., RX buffer)
    FromDevice,
    /// Bidirectional access
    Bidirectional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MappingKind {
    /// Identity mapping (IOMMU disabled at map time)
    Identity,
    /// Global DMA mapping (domain 0)
    Global,
    /// Device-specific DMA mapping
    Device(DeviceId),
    /// Domain-managed mapping (requires explicit domain context to unmap)
    Domain,
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

/// Map operation error (returns ownership on failure)
#[derive(Debug)]
pub struct MapError<T: ?Sized + 'static> {
    /// The original RRef - returned so caller can retry or clean up
    pub rref: RRef<T>,
    /// Error kind
    pub kind: MapErrorKind,
}

impl<T: ?Sized + 'static> MapError<T> {
    /// Create a new map error
    pub fn new(rref: RRef<T>, kind: MapErrorKind) -> Self {
        Self { rref, kind }
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

/// IOMMU-mapped DMA buffer with ownership tracking
///
/// `DmaHandle<T>` wraps an `RRef<T>` that has been mapped into device-accessible
/// IOVA space via the IOMMU. It ensures:
///
/// - **Memory Safety**: The underlying `RRef<T>` is held until unmap completes
/// - **Leak Detection**: Dropping without unmap logs an error and leaks
/// - **IOTLB Sync**: Unmap waits for IOTLB invalidation before releasing buffer
///
/// # Lifecycle
///
/// 1. `DmaHandle::map_rref()` - Maps RRef into IOVA space (consumes RRef)
/// 2. Use `iova()` for device programming
/// 3. `handle.unmap()` - Unmaps via global IOMMU API, returns RRef
///
/// # Resource Leak Problem (SAS Environment)
///
/// In Single Address Space (SAS) environments without process isolation, dropped
/// handles cannot be reclaimed by an OS-level cleanup. The current implementation
/// logs and intentionally leaks via `mem::forget()` to avoid DMA-after-free.
///
/// **Problem**: This leads to resource exhaustion (DoS) if handles are repeatedly
/// dropped without unmap.
///
/// ## Planned Solution: Resource Registry
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────────┐
/// │                    DmaResourceRegistry (Per-Domain)             │
/// ├─────────────────────────────────────────────────────────────────┤
/// │ active_handles: IntrusiveList<DmaHandleEntry>                   │
/// │ handle_count: AtomicU64                                          │
/// │ domain_ref: Weak<IommuDomain>                                   │
/// └─────────────────────────────────────────────────────────────────┘
///                              │
///                              ▼
/// ┌─────────────────────────────────────────────────────────────────┐
/// │                      DmaHandle<T>                               │
/// ├─────────────────────────────────────────────────────────────────┤
/// │ registry_entry: *mut DmaHandleEntry  // Link to registry        │
/// │ domain_weak: Weak<IommuDomain>       // For drop cleanup        │
/// │ rref: Option<RRef<T>>                                           │
/// │ ...                                                             │
/// └─────────────────────────────────────────────────────────────────┘
/// ```
///
/// **Key Features:**
/// - `Weak<IommuDomain>` allows `Drop` to attempt cleanup without a strong ref
/// - Registry tracks all active handles; domain destruction force-unmaps them
/// - Intrusive list avoids per-handle heap allocation
///
/// **Domain Destruction Flow:**
/// 1. Domain receives destroy request
/// 2. Iterate `active_handles`, force unmap each
/// 3. RRefs are returned to their owning allocator (no leak)
/// 4. Domain page tables and IOVAs freed
///
/// # Safety
///
/// Dropping a `DmaHandle` without calling an unmap method will log and leak
/// the underlying `RRef<T>` to avoid DMA-after-free.
#[derive(Debug)]
pub struct DmaHandle<T: ?Sized + 'static> {
    /// The underlying data (ownership held until unmap)
    rref: Option<RRef<T>>,
    /// IOVA address assigned by IOMMU
    iova: u64,
    /// Physical address of the buffer
    phys: u64,
    /// Size in bytes
    size: u64,
    /// Domain ID this handle belongs to
    domain_id: u16,
    /// Mapping scope (global/device/domain/identity)
    mapping: MappingKind,
    /// DMA direction
    direction: DmaDirection,
    /// Marker for T
    _marker: PhantomData<T>,
}

// SAFETY: DmaHandle is Send if T is Send
// The handle just holds a reference to memory; actual access
// is controlled by the device and IOMMU
unsafe impl<T: Send + ?Sized + 'static> Send for DmaHandle<T> {}

// SAFETY: DmaHandle is Sync if T is Sync
// Multiple threads can read the IOVA/phys addresses
unsafe impl<T: Sync + ?Sized + 'static> Sync for DmaHandle<T> {}

impl<T> DmaHandle<T> {
    /// Create a new DmaHandle (internal use only)
    ///
    /// Public construction should go through `DmaHandle::map_rref()` or API helpers.
    pub(crate) fn new(
        rref: RRef<T>,
        iova: u64,
        phys: u64,
        size: u64,
        domain_id: u16,
        direction: DmaDirection,
        mapping: MappingKind,
    ) -> Self {
        Self {
            rref: Some(rref),
            iova,
            phys,
            size,
            domain_id,
            mapping,
            direction,
            _marker: PhantomData,
        }
    }

    /// Get the IOVA address (for device programming)
    #[inline]
    pub fn iova(&self) -> u64 {
        self.iova
    }

    /// Get the physical address
    #[inline]
    pub fn phys_addr(&self) -> u64 {
        self.phys
    }

    /// Get the size in bytes
    #[inline]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get the domain ID
    #[inline]
    pub fn domain_id(&self) -> u16 {
        self.domain_id
    }

    /// Get the DMA direction
    #[inline]
    pub fn direction(&self) -> DmaDirection {
        self.direction
    }

    /// Mark this handle as properly unmapped (internal use)
    ///
    /// Returns the RRef if present.
    pub(crate) fn take_rref(&mut self) -> Option<RRef<T>> {
        self.rref.take()
    }

    /// Check if the handle has been unmapped
    #[inline]
    pub fn is_unmapped(&self) -> bool {
        self.rref.is_none()
    }
}

impl<T: ?Sized + 'static> Drop for DmaHandle<T> {
    fn drop(&mut self) {
        if let Some(rref) = self.rref.take() {
            // Identity mappings don't need cleanup - just drop the RRef
            if matches!(self.mapping, MappingKind::Identity) {
                drop(rref);
                return;
            }

            // === ASYNC-FIRST: Enqueue to Zombie Queue ===
            // Instead of synchronous unmap (which can block the executor or ISR),
            // we enqueue the handle metadata for async cleanup by the GC task.
            // This ensures Drop completes in O(1) without locks or I/O.
            
            let device_id = if let MappingKind::Device(dev) = self.mapping {
                Some(dev)
            } else {
                None
            };

            let mapping_kind_encoded = super::zombie_queue::encode_mapping_kind(&self.mapping);
            
            let raw_parts = rref.into_raw_parts();

            if super::zombie_queue::enqueue_zombie(
                self.iova,
                self.size,
                self.domain_id,
                device_id,
                mapping_kind_encoded,
                Some(raw_parts),
            ) {
                // Successfully enqueued - RRef ownership transferred to zombie queue.
                log::debug!(
                    "[DmaHandle] Enqueued zombie for async cleanup (IOVA=0x{:x}, size={})",
                    self.iova,
                    self.size
                );
            } else {
                // Queue full - this is a critical resource exhaustion.
                // To maintain memory safety (prevent DMA-after-free), we MUST NOT
                // drop the RRef. We intentionally leak it here.
                log::error!(
                    "[IOMMU][CRITICAL] Zombie queue full! Leaking DMA handle to preserve safety (IOVA=0x{:x}, size={})",
                    self.iova,
                    self.size
                );
                // The RRef is already "forgotten" because we called into_raw_parts()
                // and we're not reconstructing it.
            }
        }
    }
}

impl<T: ?Sized + 'static> DmaHandle<T> {
    /// Attempt to unmap the DMA buffer during drop.
    ///
    // Removed: `try_cleanup_on_drop` (was deprecated). Drop uses the `zombie_queue`-based
    // async cleanup path and no longer relies on synchronous best-effort cleanup.

    /// Try to unregister this mapping from the domain's resource registry.
    ///
    /// This is a best-effort operation that doesn't fail if the domain
    /// is not accessible. The registry entry will be cleaned up when
    /// the domain is destroyed.
    fn try_unregister_from_domain(&self) {
        use crate::io::iommu::registry::get_iommu_driver;

        let Some(driver) = get_iommu_driver() else {
            return;
        };

        // Get domain and unregister (best-effort, ignore errors)
        if let Ok(domain) = driver.get_domain(self.domain_id) {
            let _ = domain.unregister_dma_mapping(self.iova);
        }
    }
}

// ============================================================================
// Map/Unmap Implementation (to be completed with IommuDomain integration)
// ============================================================================

impl<T> DmaHandle<T> {
    /// Map an RRef for DMA access using identity mapping (IOVA = physical address).
    ///
    /// # Security Warning
    ///
    /// Identity mapping bypasses IOMMU protection completely. This function is
    /// only available in debug builds or when `unsafe_iommu_bypass` feature is enabled.
    ///
    /// For production use, prefer `map_rref_for_device()` which uses proper
    /// IOVA allocation with IOMMU protection.
    ///
    /// # Arguments
    /// * `rref` - The RRef to map (consumed)
    /// * `domain_id` - The IOMMU domain ID
    /// * `direction` - DMA transfer direction
    ///
    /// # Errors
    /// Returns `MapError<T>` containing the original RRef on failure.
    #[cfg(any(feature = "unsafe_iommu_bypass", debug_assertions))]
    pub fn map_simple(
        rref: RRef<T>,
        domain_id: u16,
        direction: DmaDirection,
    ) -> Result<Self, MapError<T>> {
        if crate::io::iommu::api::is_iommu_required() && !crate::io::iommu::api::is_iommu_enabled()
        {
            return Err(MapError::new(
                rref,
                MapErrorKind::IommuError(IommuError::NotInitialized),
            ));
        }
        if !crate::io::iommu::api::is_unsafe_identity_mapping_allowed() {
            return Err(MapError::new(
                rref,
                MapErrorKind::IommuError(IommuError::NotInitialized),
            ));
        }

        log::warn!(
            "[IOMMU][SECURITY] map_simple identity mapping - bypassing protection!"
        );

        use x86_64::VirtAddr;

        // Get physical address from RRef's virtual pointer
        let virt_ptr = &*rref as *const T as u64;
        let virt_addr = VirtAddr::new(virt_ptr);

        // Use mapping::virt_to_phys which assumes linear mapping (always succeeds)
        let phys_addr = crate::mm::virt::mapping::virt_to_phys(virt_addr);
        let phys = phys_addr.as_u64();

        let size = core::mem::size_of::<T>() as u64;
        if size == 0 {
            return Err(MapError::new(rref, MapErrorKind::InvalidAlignment));
        }

        // For now, use physical address as IOVA (1:1 mapping)
        let iova = phys;

        Ok(Self::new(
            rref,
            iova,
            phys,
            size,
            domain_id,
            direction,
            MappingKind::Identity,
        ))
    }

    /// Identity mapping is DISABLED in production builds.
    #[cfg(not(any(feature = "unsafe_iommu_bypass", debug_assertions)))]
    pub fn map_simple(
        rref: RRef<T>,
        _domain_id: u16,
        _direction: DmaDirection,
    ) -> Result<Self, MapError<T>> {
        log::error!(
            "[IOMMU][SECURITY] Identity mapping rejected - use map_rref_for_device() instead"
        );
        Err(MapError::new(
            rref,
            MapErrorKind::IommuError(IommuError::NotSupported),
        ))
    }

    /// Unmap a DMA buffer (simplified - no IOTLB invalidation)
    ///
    /// This is a simplified unmap that just releases the RRef without
    /// waiting for IOTLB invalidation. For full integration with IOMMU
    /// domain and proper IOTLB sync, use `IommuDomain::unmap_buffer()`.
    ///
    /// # Safety
    ///
    /// The caller must ensure the device is no longer accessing this buffer
    /// before calling this method. Without IOTLB invalidation, the device
    /// may still have cached translations.
    ///
    /// # Returns
    /// The original `RRef<T>` on success.
    ///
    /// # Errors
    /// Returns `UnmapError<T>` containing the handle if unmap fails.
    pub fn unmap_simple(mut self) -> Result<RRef<T>, UnmapError<T>> {
        // Take the rref to mark this handle as unmapped
        match self.take_rref() {
            Some(rref) => {
                // Handle is now "unmapped" - Drop won't panic
                Ok(rref)
            }
            None => {
                // Already unmapped - this shouldn't happen with proper usage
                Err(UnmapError::new(self, UnmapErrorKind::InvalidIova))
            }
        }
    }

    /// Unmap a DMA buffer using the global IOMMU API.
    ///
    /// For domain-managed mappings, use `unmap_with_domain` instead.
    ///
    /// # Security Note
    ///
    /// This method performs **synchronous** IOTLB invalidation by default to
    /// prevent DMA-after-free vulnerabilities where the returned `RRef<T>`
    /// could be reused before the IOMMU translation is fully invalidated.
    ///
    /// For background cleanup of leaked handles, `Drop` uses the asynchronous
    /// zombie queue.
    pub fn unmap(self) -> Result<RRef<T>, UnmapError<T>> {
        if self.rref.is_none() {
            return Err(UnmapError::new(self, UnmapErrorKind::InvalidIova));
        }

        self.unmap_sync_internal()
    }

    /// Synchronous unmap with immediate IOTLB invalidation.
    ///
    /// Use this when you need to guarantee that the mapping is fully
    /// invalidated before returning (e.g., before reusing the buffer).
    ///
    /// # ISR Safety Warning
    ///
    /// This function performs blocking IOTLB invalidation which waits for
    /// hardware completion. Calling this from an interrupt handler (ISR)
    /// will cause CPU blocking and may lead to system instability or deadlock.
    ///
    /// If called from ISR context, this function returns an error instead of
    /// blocking. Use `unmap()` with `async_unmap_default` feature or
    /// `unmap_async()` for ISR-safe unmapping.
    pub fn unmap_sync(self) -> Result<RRef<T>, UnmapError<T>> {
        // Check if we're in interrupt context - blocking waits are forbidden
        if crate::per_cpu::in_interrupt_context() {
            log::warn!(
                "[DmaHandle] unmap_sync() called from ISR context at IOVA {:#x} - \
                 blocking operations forbidden in ISR, returning error",
                self.iova
            );
            return Err(UnmapError::new(self, UnmapErrorKind::CalledFromIsr));
        }
        self.unmap_sync_internal()
    }

    /// Internal synchronous unmap implementation
    fn unmap_sync_internal(mut self) -> Result<RRef<T>, UnmapError<T>> {
        match self.mapping {
            MappingKind::Identity => Ok(self
                .take_rref()
                .expect("DmaHandle must have rref for unmap")),
            MappingKind::Domain => Err(UnmapError::new(self, UnmapErrorKind::InvalidContext)),
            MappingKind::Global => {
                if let Err(e) = crate::io::iommu::api::unmap_dma(self.iova, self.size) {
                    return Err(UnmapError::new(self, UnmapErrorKind::IommuError(e)));
                }
                // Unregister from domain registry
                self.try_unregister_from_domain();
                Ok(self
                    .take_rref()
                    .expect("DmaHandle must have rref for unmap"))
            }
            MappingKind::Device(device) => {
                if let Err(e) =
                    crate::io::iommu::api::unmap_for_device(&device, self.iova, self.size)
                {
                    return Err(UnmapError::new(self, UnmapErrorKind::IommuError(e)));
                }
                // Unregister from domain registry
                self.try_unregister_from_domain();
                Ok(self
                    .take_rref()
                    .expect("DmaHandle must have rref for unmap"))
            }
        }
    }

    /// Internal lazy unmap implementation using quarantine
    #[cfg(feature = "async_unmap_default")]
    fn unmap_lazy_internal(mut self) -> Result<RRef<T>, UnmapError<T>> {
        // SECURITY: The current implementation of lazy unmap is insecure because it
        // returns the RRef to the user IMMEDIATELY, before the IOTLB has been invalidated.
        // This allows a device to potentially access the memory while the user thinks
        // it is safe to reuse for other purposes.
        //
        // For safety, we fall back to synchronous unmap until a proper async API
        // (returning a QuarantineTicket) is implemented for all users.
        log::debug!("[DmaHandle] Lazy unmap requested, but falling back to sync for security");
        self.unmap_sync_internal()
    }

    /// Async variant of `unmap` for device-scoped mappings.
    pub async fn unmap_async(mut self) -> Result<RRef<T>, UnmapError<T>> {
        if self.rref.is_none() {
            return Err(UnmapError::new(self, UnmapErrorKind::InvalidIova));
        }

        match self.mapping {
            MappingKind::Device(device) => {
                if let Err(e) =
                    crate::io::iommu::api::unmap_for_device_async(&device, self.iova, self.size)
                        .await
                {
                    return Err(UnmapError::new(self, UnmapErrorKind::IommuError(e)));
                }
                Ok(self
                    .take_rref()
                    .expect("DmaHandle must have rref for unmap"))
            }
            MappingKind::Domain => Err(UnmapError::new(self, UnmapErrorKind::InvalidContext)),
            _ => self.unmap(),
        }
    }

    /// Consume the handle and return the RRef without unmap validation
    ///
    /// # Safety
    ///
    /// This is unsafe because it bypasses the unmap requirement.
    /// Use only when you have already unmapped the buffer through
    /// other means (e.g., IommuDomain::unmap).
    pub unsafe fn into_rref_unchecked(mut self) -> Option<RRef<T>> {
        self.take_rref()
    }

    // =========================================================================
    // Safe IOMMU-Integrated Map Functions (ExoRust Recommended)
    // =========================================================================

    /// Map an RRef for DMA access via IOMMU (Safe API)
    ///
    /// This is the **recommended** safe API for drivers. By accepting an `RRef<T>`,
    /// we guarantee that the physical memory is:
    /// - Owned by the caller (via RRef ownership semantics)
    /// - Not kernel code, page tables, or other critical structures
    /// - Properly tracked for DMA safety
    ///
    /// This function internally calls the `unsafe` low-level IOMMU APIs but
    /// encapsulates the safety invariants through RRef's design.
    ///
    /// # Arguments
    /// * `rref` - The RRef to map (ownership transferred)
    /// * `domain_id` - The IOMMU domain ID
    /// * `direction` - DMA transfer direction
    ///
    /// # Alignment
    /// When IOMMU is enabled, the buffer must be 4K-aligned in address and size.
    ///
    /// # Returns
    /// A `DmaHandle<T>` on success, or `MapError<T>` (including the original RRef) on failure.
    ///
    /// # Example
    /// ```no_run
    /// #[repr(align(4096))]
    /// struct DmaPage([u8; 4096]);
    ///
    /// let rref = crate::ipc::RRef::new(
    ///     crate::ipc::DomainId::KERNEL,
    ///     DmaPage([0u8; 4096]),
    /// );
    /// let handle = crate::io::iommu::dma_handle::DmaHandle::map_rref(
    ///     rref,
    ///     0,
    ///     crate::io::iommu::dma_handle::DmaDirection::ToDevice,
    /// )?;
    /// // Use handle.iova() for device programming
    /// let returned_rref = handle.unmap()?;
    /// ```
    pub fn map_rref(
        rref: RRef<T>,
        domain_id: u16,
        direction: DmaDirection,
    ) -> Result<Self, MapError<T>> {
        use x86_64::{PhysAddr, VirtAddr};

        // Get physical address from RRef's virtual pointer
        let virt_ptr = &*rref as *const T as u64;
        let virt_addr = VirtAddr::new(virt_ptr);
        let phys_addr_val = crate::mm::virt::mapping::virt_to_phys(virt_addr);
        let size = core::mem::size_of::<T>() as u64;
        if size == 0 {
            return Err(MapError::new(rref, MapErrorKind::InvalidAlignment));
        }

        // Check IOMMU enabled
        if !crate::io::iommu::api::is_iommu_enabled() {
            // Fallback to simple 1:1 mapping only when explicitly allowed
            return Self::map_simple(rref, domain_id, direction);
        }
        if !crate::io::iommu::api::is_global_dma_mapping_allowed() {
            return Err(MapError::new(
                rref,
                MapErrorKind::IommuError(IommuError::NotSupported),
            ));
        }

        if phys_addr_val.as_u64() & 0xFFF != 0 || size & 0xFFF != 0 {
            return Err(MapError::new(rref, MapErrorKind::InvalidAlignment));
        }

        let (read, write) = match direction {
            DmaDirection::ToDevice => (true, false),
            DmaDirection::FromDevice => (false, true),
            DmaDirection::Bidirectional => (true, true),
        };

        // SAFETY: We hold the RRef, which guarantees:
        // - We own this memory (RRef semantics)
        // - It's not kernel code or page tables (RRef allocation guarantees)
        // - It will remain valid as long as we hold the RRef
        let iova = match unsafe {
            crate::io::iommu::api::map_for_dma_with_perms(
                PhysAddr::new(phys_addr_val.as_u64()),
                size,
                read,
                write,
            )
        } {
            Ok(iova) => iova,
            Err(e) => return Err(MapError::new(rref, MapErrorKind::IommuError(e))),
        };

        Ok(Self::new(
            rref,
            iova,
            phys_addr_val.as_u64(),
            size,
            domain_id,
            direction,
            MappingKind::Global,
        ))
    }

    /// Map an RRef for DMA access to a specific device (Safe API)
    ///
    /// Same safety guarantees as `map_rref`, but uses device-specific domain.
    ///
    /// # Arguments
    /// * `rref` - The RRef to map (ownership transferred)
    /// * `device` - The device ID for domain lookup
    /// * `direction` - DMA transfer direction
    ///
    /// # Alignment
    /// When IOMMU is enabled, the buffer must be 4K-aligned in address and size.
    pub fn map_rref_for_device(
        rref: RRef<T>,
        device: &DeviceId,
        direction: DmaDirection,
    ) -> Result<Self, MapError<T>> {
        use x86_64::{PhysAddr, VirtAddr};

        let virt_ptr = &*rref as *const T as u64;
        let virt_addr = VirtAddr::new(virt_ptr);
        let phys_addr_val = crate::mm::virt::mapping::virt_to_phys(virt_addr);
        let size = core::mem::size_of::<T>() as u64;
        if size == 0 {
            return Err(MapError::new(rref, MapErrorKind::InvalidAlignment));
        }

        if !crate::io::iommu::api::is_iommu_enabled() {
            return Self::map_simple(rref, 0, direction);
        }

        if phys_addr_val.as_u64() & 0xFFF != 0 || size & 0xFFF != 0 {
            return Err(MapError::new(rref, MapErrorKind::InvalidAlignment));
        }

        let (read, write) = match direction {
            DmaDirection::ToDevice => (true, false),
            DmaDirection::FromDevice => (false, true),
            DmaDirection::Bidirectional => (true, true),
        };

        // SAFETY: Same as map_rref - RRef ownership guarantees memory is safe for DMA
        let iova = match unsafe {
            crate::io::iommu::api::map_for_device_with_perms(
                device,
                PhysAddr::new(phys_addr_val.as_u64()),
                size,
                read,
                write,
            )
        } {
            Ok(iova) => iova,
            Err(e) => return Err(MapError::new(rref, MapErrorKind::IommuError(e))),
        };

        let domain_id = crate::io::iommu::api::domain_id_for_device(device).unwrap_or(0);

        Ok(Self::new(
            rref,
            iova,
            phys_addr_val.as_u64(),
            size,
            domain_id,
            direction,
            MappingKind::Device(*device),
        ))
    }
}
