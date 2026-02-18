use super::*;


impl<T> DmaHandle<[T]> {
    /// Create a new DmaHandle for slices (internal use only)
    ///
    /// This is the slice-specific constructor since [T] is unsized.
    pub(crate) fn new_slice(
        rref: RRef<[T]>,
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
    pub(crate) fn take_rref(&mut self) -> Option<RRef<[T]>> {
        self.rref.take()
    }

    /// Check if the handle has been unmapped
    #[inline]
    pub fn is_unmapped(&self) -> bool {
        self.rref.is_none()
    }

    /// Unmap a DMA buffer using the global IOMMU API (slice variant).
    ///
    /// For domain-managed mappings, use `unmap_with_domain` instead.
    pub fn unmap(mut self) -> Result<RRef<[T]>, UnmapError<[T]>> {
        if self.rref.is_none() {
            return Err(UnmapError::new(self, UnmapErrorKind::InvalidIova));
        }

        match self.mapping {
            MappingKind::Identity => Ok(self
                .take_rref()
                .expect("DmaHandle must have rref for unmap")),
            MappingKind::Domain => Err(UnmapError::new(self, UnmapErrorKind::InvalidContext)),
            MappingKind::Global => {
                if let Err(e) = crate::io::iommu::api::unmap_dma(self.iova, self.size) {
                    return Err(UnmapError::new(self, UnmapErrorKind::IommuError(e)));
                }
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
                Ok(self
                    .take_rref()
                    .expect("DmaHandle must have rref for unmap"))
            }
        }
    }

    /// Async variant of `unmap` for device-scoped mappings (slice variant).
    pub async fn unmap_async(mut self) -> Result<RRef<[T]>, UnmapError<[T]>> {
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
    /// Determine read/write permissions from DMA direction
    pub(super) fn dma_direction_to_perms(direction: DmaDirection) -> (bool, bool) {
        match direction {
            DmaDirection::ToDevice => (true, false),
            DmaDirection::FromDevice => (false, true),
            DmaDirection::Bidirectional => (true, true),
        }
    }

    /// Identity-map an RRef slice when IOMMU is not enabled
    pub(super) fn map_rref_slice_no_iommu(
        rref: RRef<[T]>,
        size: u64,
        domain_id: u16,
        direction: DmaDirection,
    ) -> Result<Self, MapError<[T]>> {
        use x86_64::VirtAddr;
        if crate::io::iommu::api::is_iommu_required()
            || !crate::io::iommu::api::is_unsafe_identity_mapping_allowed()
        {
            return Err(MapError::new(
                rref,
                MapErrorKind::IommuError(IommuError::NotInitialized),
            ));
        }
        let virt_ptr = rref.as_ptr() as u64;
        let virt_addr = VirtAddr::new(virt_ptr);
        let phys_addr_val = crate::mm::mapping::virt_to_phys(virt_addr);
        Ok(Self::new_slice(
            rref,
            phys_addr_val.as_u64(),
            phys_addr_val.as_u64(),
            size,
            domain_id,
            direction,
            MappingKind::Identity,
        ))
    }

    /// Map an RRef slice for DMA access via IOMMU (Safe API)
    ///
    /// This maps a contiguous slice allocated on the Exchange Heap.
    ///
    /// # Alignment
    /// When IOMMU is enabled, the buffer must be 4K-aligned in address and size.
    pub fn map_rref_slice(
        rref: RRef<[T]>,
        domain_id: u16,
        direction: DmaDirection,
    ) -> Result<Self, MapError<[T]>> {
        use x86_64::{PhysAddr, VirtAddr};

        let elem_size = core::mem::size_of::<T>() as u64;
        let size = match (rref.len() as u64).checked_mul(elem_size) {
            Some(size) if size > 0 => size,
            _ => return Err(MapError::new(rref, MapErrorKind::InvalidAlignment)),
        };

        if !crate::io::iommu::api::is_iommu_enabled() {
            return Self::map_rref_slice_no_iommu(rref, size, domain_id, direction);
        }
        if !crate::io::iommu::api::is_global_dma_mapping_allowed() {
            return Err(MapError::new(
                rref,
                MapErrorKind::IommuError(IommuError::NotSupported),
            ));
        }

        let virt_ptr = rref.as_ptr() as u64;
        let virt_addr = VirtAddr::new(virt_ptr);
        let phys_addr_val = crate::mm::mapping::virt_to_phys(virt_addr);

        if phys_addr_val.as_u64() & 0xFFF != 0 || size & 0xFFF != 0 {
            return Err(MapError::new(rref, MapErrorKind::InvalidAlignment));
        }

        let (read, write) = Self::dma_direction_to_perms(direction);

        // SAFETY: RRef slice ownership guarantees memory is safe for DMA.
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

        Ok(Self::new_slice(
            rref,
            iova,
            phys_addr_val.as_u64(),
            size,
            domain_id,
            direction,
            MappingKind::Global,
        ))
    }

    pub(super) fn try_identity_map_rref_slice(
        rref: &RRef<[T]>,
        size: u64,
        direction: DmaDirection,
    ) -> Option<(u64, u64, u64, MappingKind)> {
        use x86_64::VirtAddr;
        if crate::io::iommu::api::is_iommu_required()
            || !crate::io::iommu::api::is_unsafe_identity_mapping_allowed()
        {
            return None;
        }
        let virt_ptr = rref.as_ptr() as u64;
        let virt_addr = VirtAddr::new(virt_ptr);
        let phys_addr_val = crate::mm::mapping::virt_to_phys(virt_addr);
        Some((phys_addr_val.as_u64(), phys_addr_val.as_u64(), size, MappingKind::Identity))
    }

    /// Map an RRef slice for DMA access to a specific device (Safe API)
    ///
    /// # Alignment
    /// When IOMMU is enabled, the buffer must be 4K-aligned in address and size.
    pub fn map_rref_slice_for_device(
        rref: RRef<[T]>,
        device: &DeviceId,
        direction: DmaDirection,
    ) -> Result<Self, MapError<[T]>> {
        use x86_64::{PhysAddr, VirtAddr};

        let elem_size = core::mem::size_of::<T>() as u64;
        let size = match (rref.len() as u64).checked_mul(elem_size) {
            Some(size) if size > 0 => size,
            _ => return Err(MapError::new(rref, MapErrorKind::InvalidAlignment)),
        };

        if !crate::io::iommu::api::is_iommu_enabled() {
            match Self::try_identity_map_rref_slice(&rref, size, direction) {
                Some((iova, phys, sz, kind)) => {
                    return Ok(Self::new_slice(rref, iova, phys, sz, 0, direction, kind));
                }
                None => {
                    return Err(MapError::new(
                        rref,
                        MapErrorKind::IommuError(IommuError::NotInitialized),
                    ));
                }
            }
        }

        let virt_ptr = rref.as_ptr() as u64;
        let virt_addr = VirtAddr::new(virt_ptr);
        let phys_addr_val = crate::mm::mapping::virt_to_phys(virt_addr);

        if phys_addr_val.as_u64() & 0xFFF != 0 || size & 0xFFF != 0 {
            return Err(MapError::new(rref, MapErrorKind::InvalidAlignment));
        }

        let (read, write) = match direction {
            DmaDirection::ToDevice => (true, false),
            DmaDirection::FromDevice => (false, true),
            DmaDirection::Bidirectional => (true, true),
        };

        // SAFETY: RRef slice ownership guarantees memory is safe for DMA.
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

        Ok(Self::new_slice(
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

impl<T> DmaHandle<T> {
    /// Map an RRef for DMA access (Full Implementation)
    ///
    /// Delegates to `IommuDomain::map_buffer` for IOVA allocation and page table mapping.
    ///
    /// # Arguments
    /// * `domain` - The IOMMU domain to map into
    /// * `rref` - The RRef to map (consumed)
    /// * `context` - The IOMMU context (for IOVA allocation)
    /// * `direction` - DMA transfer direction
    pub(crate) fn map(
        domain: &IommuDomain,
        rref: RRef<T>,
        context: &dyn IommuHardwareContext,
        direction: DmaDirection,
    ) -> Result<Self, MapError<T>> {
        domain.map_buffer(rref, context, direction)
    }

    /// Unmap a DMA buffer and return the RRef (Full Implementation)
    ///
    /// Delegates to `IommuDomain::unmap_buffer` for proper cleanup including
    /// IOTLB invalidation and IOVA deallocation.
    ///
    /// # Arguments
    /// * `domain` - The IOMMU domain to unmap from
    /// * `context` - The IOMMU context (for IOVA deallocation)
    /// * `invalidator` - Invalidator for IOTLB flush
    pub(crate) fn unmap_with_domain<I: IommuInvalidator>(
        self,
        domain: &IommuDomain,
        context: &dyn IommuHardwareContext,
        invalidator: &I,
    ) -> Result<RRef<T>, UnmapError<T>> {
        domain.unmap_buffer(self, context, invalidator)
    }

    /// Unmap a DMA buffer asynchronously and return the RRef
    ///
    /// Delegates to `IommuDomain::unmap_buffer_async` for non-blocking cleanup
    /// including async IOTLB invalidation.
    ///
    /// # Arguments
    /// * `domain` - The IOMMU domain to unmap from
    /// * `context` - The IOMMU context (for IOVA deallocation)
    /// * `invalidator` - Invalidator for async IOTLB flush
    pub(crate) async fn unmap_with_domain_async<I: IommuInvalidator + Sync>(
        self,
        domain: &IommuDomain,
        context: &dyn IommuHardwareContext,
        invalidator: &I,
    ) -> Result<RRef<T>, UnmapError<T>> {
        domain.unmap_buffer_async(self, context, invalidator).await
    }

    // ========================================================================
    // Phase 5: Zero-Allocation Quarantine Methods
    // ========================================================================

    /// Lazy unmap with quarantine - try to enqueue, fail if queue full
    ///
    /// This method provides zero-allocation IOTLB invalidation by:
    /// 1. Reserving a slot in the quarantine queue
    /// 2. Reserving space for the invalidation request
    /// 3. Clearing the page table entry
    /// 4. Decomposing the RRef into raw parts (stored in queue)
    /// 5. Returning a QuarantineTicket for later retrieval
    ///
    /// The IOVA is NOT freed until `IommuDomain::flush()` is called.
    ///
    /// # Returns
    /// - `Ok(QuarantineTicket<T>)` - On success. Poll the ticket for completion.
    /// - `Err(QuarantineLazyUnmapError<T>)` - On failure. The handle is returned.
    ///
    /// # Zero Allocation
    /// This method does NOT allocate any heap memory in the hot path.
    pub(crate) fn try_unmap_lazy(
        mut self,
        domain: &IommuDomain,
        context: &dyn IommuHardwareContext,
    ) -> Result<super::quarantine::QuarantineTicket<T>, QuarantineLazyUnmapError<T>>
    where
        T: 'static,
    {
        use super::quarantine::QuarantineError;
        use crate::ipc::rref::RRefRawParts;

        // Get the quarantine queue from the domain
        let queue = domain.quarantine_queue();

        // Round 9: Use RAII guards for panic safety
        // Reserve a slot in the quarantine queue
        let mut slot_guard = match queue.reserve_slot_guarded() {
            Ok(g) => g,
            Err(QuarantineError::QueueFull) => {
                return Err(QuarantineLazyUnmapError {
                    handle: self,
                    kind: QuarantineLazyUnmapErrorKind::QueueFull,
                });
            }
            Err(e) => {
                return Err(QuarantineLazyUnmapError {
                    handle: self,
                    kind: QuarantineLazyUnmapErrorKind::Quarantine(e),
                });
            }
        };

        // Extract info for ticket BEFORE commit
        let slot_idx = slot_guard.slot_idx;
        let slot_gen = slot_guard.slot_gen;
        let batch_id = slot_guard.batch_id;

        // Reserve invalidation slot using guard
        let mut inv_guard = match queue.reserve_invalidation_slot_guarded(batch_id) {
            Ok(g) => g,
            Err(e) => {
                return Err(QuarantineLazyUnmapError {
                    handle: self,
                    kind: QuarantineLazyUnmapErrorKind::Quarantine(e),
                });
            }
        };

        // Clear the page table entries
        if let Err(e) = domain.clear_mapping_only(self.iova, self.size) {
            return Err(QuarantineLazyUnmapError {
                handle: self,
                kind: QuarantineLazyUnmapErrorKind::IommuError(e),
            });
        }

        // Round 10: Mark PTEs as cleared so guard won't rollback on drop/panic.
        // This ensures we don't leave the system in an inconsistent state (PTE cleared, IOTLB stale).
        inv_guard.mark_pte_cleared();
        // Round 11: Also mark slot_guard as pte_cleared so we don't rollback the reservation.
        // Leaking the reservation (empty but in-use) is safer than freeing it for reuse.
        slot_guard.mark_pte_cleared();

        // Construct invalidation request (Ready state)
        let req = InvalidateRequest::pages(domain.id(), self.iova, self.size);

        // Commit invalidation (marks it Ready)
        if let Err(e) = inv_guard.commit(req) {
            return Err(QuarantineLazyUnmapError {
                handle: self,
                kind: QuarantineLazyUnmapErrorKind::Quarantine(e),
            });
        }

        // Move RRef ownership to raw parts
        let rref = self
            .take_rref()
            .expect("DmaHandle must have rref for unmap");
        let raw = RRefRawParts::from_rref(rref);

        // Commit quarantine entry
        // If this fails, we can't easily restore self because rref is gone.
        // But commit should not fail for a valid reserved slot.
        slot_guard
            .commit(raw, self.iova, self.size as u64, context)
            .expect("Quarantine commit failed despite reservation");

        // Step 7: Create and return ticket
        Ok(super::quarantine::QuarantineTicket::new(
            queue.clone(),
            slot_idx,
            slot_gen,
            batch_id,
        ))
    }

    /// Lazy unmap with quarantine - auto-flush if queue full
    ///
    /// Like `try_unmap_lazy()`, but if the queue is full, triggers a single
    /// `domain.flush()` attempt before returning an error.
    ///
    /// # Returns
    /// - `Ok(QuarantineTicket<T>)` - On success or after flush. Poll for completion.
    /// - `Err(QuarantineLazyUnmapError<T>)` - On failure after flush attempt.
    /// Flush-and-retry ヘルパー: キューがいっぱいの場合、flushしてリトライ
    pub(super) fn flush_and_retry_unmap<I: IommuInvalidator>(
        handle: DmaHandle<T>,
        domain: &IommuDomain,
        context: &dyn IommuHardwareContext,
        invalidator: &I,
    ) -> Result<super::quarantine::QuarantineTicket<T>, QuarantineLazyUnmapError<T>>
    where
        T: 'static,
    {
        if let Err(flush_err) = domain.flush(invalidator, context) {
            return Err(QuarantineLazyUnmapError {
                handle,
                kind: QuarantineLazyUnmapErrorKind::IommuError(flush_err),
            });
        }
        handle.try_unmap_lazy(domain, context)
    }

    pub(crate) fn unmap_lazy<I: IommuInvalidator>(
        self,
        domain: &IommuDomain,
        context: &dyn IommuHardwareContext,
        invalidator: &I,
    ) -> Result<super::quarantine::QuarantineTicket<T>, QuarantineLazyUnmapError<T>>
    where
        T: 'static,
    {
        let handle = self;
        let stats = domain.quarantine_queue().stats();
        if stats.pending_invalidations > 0 {
            const QUARANTINE_FLUSH_THRESHOLD: usize =
                super::quarantine::QUARANTINE_CAPACITY * 3 / 4;
            if stats.active_count as usize >= QUARANTINE_FLUSH_THRESHOLD {
                if let Err(err) = domain.flush(invalidator, context) {
                    return Err(QuarantineLazyUnmapError {
                        handle,
                        kind: QuarantineLazyUnmapErrorKind::IommuError(err),
                    });
                }
            }
        }

        // First try without flush
        match handle.try_unmap_lazy(domain, context) {
            Ok(ticket) => Ok(ticket),
            Err(err) => {
                if matches!(err.kind, QuarantineLazyUnmapErrorKind::QueueFull) {
                    Self::flush_and_retry_unmap(err.handle, domain, context, invalidator)
                } else {
                    Err(err)
                }
            }
        }
    }
}

// ============================================================================
// Quarantine Lazy Unmap Error Types
// ============================================================================

/// Error kind for lazy unmap operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuarantineLazyUnmapErrorKind {
    /// Quarantine queue is full
    QueueFull,
    /// Quarantine error
    Quarantine(super::quarantine::QuarantineError),
    /// IOMMU error
    IommuError(IommuError),
}

/// Error for lazy unmap operations (returns handle for retry)
pub(crate) struct QuarantineLazyUnmapError<T: 'static> {
    /// The handle that failed to unmap
    pub handle: DmaHandle<T>,
    /// Error kind
    pub kind: QuarantineLazyUnmapErrorKind,
}

impl<T: 'static> core::fmt::Debug for QuarantineLazyUnmapError<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QuarantineLazyUnmapError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}
