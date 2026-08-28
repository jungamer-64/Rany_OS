//! Authoritative DMA allocation, mapping, and transfer registry.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::dma::{
    CpuDmaLease, DmaAllocationRequest, DmaByteCount, DmaDeviceAddress, DmaDirection,
    DmaLeaseAuthority, DmaLeaseError, DmaLeaseId, DmaLeaseState, DmaQueueIdentity,
};

use crate::domain::DomainId;
use crate::io::dma::{
    self, DeviceDmaContext, RRefDmaBytes, RRefDmaBytesUnmapError, RRefSliceMapError,
};
use crate::sync::PoisonLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuarantineReason {
    OutcomeUnknown,
    UnmapFailed,
    CapabilityAbandoned(DmaLeaseState),
    OwnerShutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryState {
    CpuOwned,
    Prepared {
        queue: DmaQueueIdentity,
    },
    InFlight {
        queue: DmaQueueIdentity,
    },
    Completed {
        queue: DmaQueueIdentity,
    },
    Quarantined {
        reason: QuarantineReason,
        queue: Option<DmaQueueIdentity>,
    },
    RevokedAfterReset {
        queue: DmaQueueIdentity,
        reset_generation: u64,
    },
    Closing,
}

struct DmaEntry {
    mapping: Option<RRefDmaBytes>,
    owner: u64,
    device: PackedPciLocation,
    direction: DmaDirection,
    logical_len: DmaByteCount,
    state: EntryState,
}

impl DmaEntry {
    fn mapping(&self) -> Result<&RRefDmaBytes, DmaLeaseError> {
        self.mapping.as_ref().ok_or(DmaLeaseError::InvalidState)
    }

    fn mapping_mut(&mut self) -> Result<&mut RRefDmaBytes, DmaLeaseError> {
        self.mapping.as_mut().ok_or(DmaLeaseError::InvalidState)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DmaCleanupStats {
    pub(crate) released_handles: usize,
    pub(crate) released_bytes: usize,
    pub(crate) quarantined_handles: usize,
    pub(crate) quarantined_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DmaAllocationError {
    RegistryExhausted,
    AllocationFailed,
    MappingFailed,
}

pub(crate) struct DmaAbiView {
    pub(crate) device_address: DmaDeviceAddress,
    pub(crate) virtual_address: u64,
    pub(crate) byte_count: DmaByteCount,
}

struct RegistryState {
    entries: BTreeMap<u32, DmaEntry>,
    generations: BTreeMap<u32, u32>,
    reusable_slots: Vec<u32>,
    next_slot: u32,
}

impl RegistryState {
    const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            generations: BTreeMap::new(),
            reusable_slots: Vec::new(),
            next_slot: 1,
        }
    }

    fn reserve_identity(&mut self) -> Option<DmaLeaseId> {
        while let Some(slot) = self.reusable_slots.pop() {
            let previous = self.generations.get(&slot).copied().unwrap_or(0);
            let Some(generation) = previous.checked_add(1) else {
                continue;
            };
            self.generations.insert(slot, generation);
            return DmaLeaseId::from_parts(slot, generation);
        }

        let slot = self.next_slot;
        self.next_slot = self.next_slot.checked_add(1)?;
        self.generations.insert(slot, 1);
        DmaLeaseId::from_parts(slot, 1)
    }

    fn release_identity(&mut self, lease: DmaLeaseId) {
        self.reusable_slots.push(lease.slot());
    }

    fn entry(&self, lease: DmaLeaseId, owner: u64) -> Result<&DmaEntry, DmaLeaseError> {
        let entry = self
            .entries
            .get(&lease.slot())
            .ok_or(DmaLeaseError::StaleLease)?;
        if self.generations.get(&lease.slot()).copied() != Some(lease.generation()) {
            return Err(DmaLeaseError::StaleLease);
        }
        if entry.owner != owner {
            return Err(DmaLeaseError::ForeignOwner);
        }
        Ok(entry)
    }

    fn entry_mut(&mut self, lease: DmaLeaseId, owner: u64) -> Result<&mut DmaEntry, DmaLeaseError> {
        if self.generations.get(&lease.slot()).copied() != Some(lease.generation()) {
            return Err(DmaLeaseError::StaleLease);
        }
        let entry = self
            .entries
            .get_mut(&lease.slot())
            .ok_or(DmaLeaseError::StaleLease)?;
        if entry.owner != owner {
            return Err(DmaLeaseError::ForeignOwner);
        }
        Ok(entry)
    }
}

struct DmaRegistry {
    state: PoisonLock<RegistryState>,
}

impl DmaRegistry {
    const fn new() -> Self {
        Self {
            state: PoisonLock::new(RegistryState::new()),
        }
    }

    fn register(
        &self,
        entry: DmaEntry,
    ) -> Result<(DmaLeaseId, DmaDeviceAddress), DmaAllocationError> {
        let device_address = DmaDeviceAddress::from_abi(
            entry
                .mapping()
                .map_err(|_| DmaAllocationError::MappingFailed)?
                .iova(),
        );
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let lease = state
            .reserve_identity()
            .ok_or(DmaAllocationError::RegistryExhausted)?;
        if state.entries.insert(lease.slot(), entry).is_some() {
            return Err(DmaAllocationError::RegistryExhausted);
        }
        Ok((lease, device_address))
    }

    fn with_cpu_bytes(
        &self,
        lease: DmaLeaseId,
        owner: u64,
        visitor: &mut dyn FnMut(&[u8]),
    ) -> Result<(), DmaLeaseError> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry(lease, owner)?;
        if entry.state != EntryState::CpuOwned {
            return Err(DmaLeaseError::InvalidState);
        }
        let bytes = entry
            .mapping()?
            .cpu_bytes()
            .ok_or(DmaLeaseError::AuthorityViolation)?;
        visitor(bytes);
        Ok(())
    }

    fn with_cpu_bytes_mut(
        &self,
        lease: DmaLeaseId,
        owner: u64,
        visitor: &mut dyn FnMut(&mut [u8]),
    ) -> Result<(), DmaLeaseError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        if entry.state != EntryState::CpuOwned {
            return Err(DmaLeaseError::InvalidState);
        }
        let bytes = entry
            .mapping_mut()?
            .cpu_bytes_mut()
            .ok_or(DmaLeaseError::AuthorityViolation)?;
        visitor(bytes);
        Ok(())
    }

    fn abi_view(&self, lease: DmaLeaseId, owner: u64) -> Result<DmaAbiView, DmaLeaseError> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry(lease, owner)?;
        if entry.state != EntryState::CpuOwned {
            return Err(DmaLeaseError::InvalidState);
        }
        let mapping = entry.mapping()?;
        let bytes = mapping
            .cpu_bytes()
            .ok_or(DmaLeaseError::AuthorityViolation)?;
        Ok(DmaAbiView {
            device_address: DmaDeviceAddress::from_abi(mapping.iova()),
            virtual_address: bytes.as_ptr() as usize as u64,
            byte_count: entry.logical_len,
        })
    }

    fn prepare(
        &self,
        lease: DmaLeaseId,
        owner: u64,
        queue: DmaQueueIdentity,
    ) -> Result<(), DmaLeaseError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        if entry.state != EntryState::CpuOwned || entry.device != queue.device() {
            return Err(if entry.device != queue.device() {
                DmaLeaseError::QueueMismatch
            } else {
                DmaLeaseError::InvalidState
            });
        }

        let bytes = entry
            .mapping()?
            .cpu_bytes()
            .ok_or(DmaLeaseError::AuthorityViolation)?;
        dma::flush_cache_range(bytes.as_ptr(), bytes.len());
        entry.state = EntryState::Prepared { queue };
        Ok(())
    }

    fn prepared_queue(&self, lease: DmaLeaseId, owner: u64) -> Option<DmaQueueIdentity> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        match state.entry(lease, owner).ok()?.state {
            EntryState::Prepared { queue } => Some(queue),
            _ => None,
        }
    }

    fn abort_prepared(&self, lease: DmaLeaseId, owner: u64) -> Result<(), DmaLeaseError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        if !matches!(entry.state, EntryState::Prepared { .. }) {
            return Err(DmaLeaseError::InvalidState);
        }
        entry.state = EntryState::CpuOwned;
        Ok(())
    }

    fn accept(&self, lease: DmaLeaseId, owner: u64) -> Result<(), DmaLeaseError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        let EntryState::Prepared { queue } = entry.state else {
            return Err(DmaLeaseError::InvalidState);
        };
        entry.state = EntryState::InFlight { queue };
        Ok(())
    }

    fn complete(
        &self,
        lease: DmaLeaseId,
        owner: u64,
        queue: DmaQueueIdentity,
        completed_lease: DmaLeaseId,
    ) -> Result<(), DmaLeaseError> {
        if completed_lease != lease {
            return Err(DmaLeaseError::QueueMismatch);
        }
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        match entry.state {
            EntryState::InFlight { queue: expected } if expected == queue => {
                entry.state = EntryState::Completed { queue };
                Ok(())
            }
            EntryState::InFlight { .. } => Err(DmaLeaseError::QueueMismatch),
            _ => Err(DmaLeaseError::InvalidState),
        }
    }

    fn return_to_cpu(&self, lease: DmaLeaseId, owner: u64) -> Result<(), DmaLeaseError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        if !matches!(entry.state, EntryState::Completed { .. }) {
            return Err(DmaLeaseError::InvalidState);
        }
        if matches!(
            entry.direction,
            DmaDirection::FromDevice | DmaDirection::Bidirectional
        ) {
            let bytes = entry
                .mapping()?
                .cpu_bytes()
                .ok_or(DmaLeaseError::AuthorityViolation)?;
            dma::invalidate_cache_range(bytes.as_ptr(), bytes.len());
        }
        entry.state = EntryState::CpuOwned;
        Ok(())
    }

    fn mark_outcome_unknown(&self, lease: DmaLeaseId, owner: u64) -> Result<(), DmaLeaseError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        let EntryState::InFlight { queue } = entry.state else {
            return Err(DmaLeaseError::InvalidState);
        };
        entry.state = EntryState::Quarantined {
            reason: QuarantineReason::OutcomeUnknown,
            queue: Some(queue),
        };
        Ok(())
    }

    fn revoke_after_reset(
        &self,
        lease: DmaLeaseId,
        owner: u64,
        device: PackedPciLocation,
        reset_generation: u64,
    ) -> Result<(), DmaLeaseError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        if entry.device != device {
            return Err(DmaLeaseError::QueueMismatch);
        }
        let queue = match entry.state {
            EntryState::InFlight { queue } => queue,
            EntryState::Quarantined {
                reason: QuarantineReason::OutcomeUnknown,
                queue: Some(queue),
            } => queue,
            _ => return Err(DmaLeaseError::InvalidState),
        };
        if reset_generation <= queue.generation() {
            return Err(DmaLeaseError::QueueMismatch);
        }
        entry.state = EntryState::RevokedAfterReset {
            queue,
            reset_generation,
        };
        Ok(())
    }

    fn reconcile(
        &self,
        lease: DmaLeaseId,
        owner: u64,
        device: PackedPciLocation,
        reset_generation: u64,
    ) -> Result<(), DmaLeaseError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        if entry.device != device {
            return Err(DmaLeaseError::QueueMismatch);
        }
        match entry.state {
            EntryState::RevokedAfterReset {
                reset_generation: expected,
                ..
            } if expected == reset_generation => {}
            EntryState::Quarantined {
                reason: QuarantineReason::UnmapFailed,
                ..
            } => return Err(DmaLeaseError::NotSupported),
            _ => return Err(DmaLeaseError::InvalidState),
        }

        if matches!(
            entry.direction,
            DmaDirection::FromDevice | DmaDirection::Bidirectional
        ) {
            let bytes = entry
                .mapping()?
                .cpu_bytes()
                .ok_or(DmaLeaseError::AuthorityViolation)?;
            dma::invalidate_cache_range(bytes.as_ptr(), bytes.len());
        }
        entry.state = EntryState::CpuOwned;
        Ok(())
    }

    fn close(&self, lease: DmaLeaseId, owner: u64) -> Result<(), DmaLeaseError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let mapping = {
            let entry = state.entry_mut(lease, owner)?;
            if entry.state != EntryState::CpuOwned {
                return Err(DmaLeaseError::InvalidState);
            }
            entry.state = EntryState::Closing;
            entry.mapping.take().ok_or(DmaLeaseError::InvalidState)?
        };

        match mapping.try_unmap() {
            Ok(allocation) => {
                let removed = state
                    .entries
                    .remove(&lease.slot())
                    .expect("closing DMA entry must remain registered during synchronous unmap");
                debug_assert_eq!(removed.owner, owner);
                debug_assert_eq!(removed.state, EntryState::Closing);
                debug_assert!(removed.mapping.is_none());
                state.release_identity(lease);
                drop(state);
                drop(allocation);
                Ok(())
            }
            Err(RRefDmaBytesUnmapError { buffer, kind }) => {
                log::error!(
                    "[DMA] quarantining lease {:?} after unmap failure: {:?}",
                    lease,
                    kind
                );
                let entry = state
                    .entry_mut(lease, owner)
                    .expect("closing DMA entry must remain registered after unmap failure");
                entry.mapping = Some(buffer);
                entry.state = EntryState::Quarantined {
                    reason: QuarantineReason::UnmapFailed,
                    queue: None,
                };
                Err(DmaLeaseError::IommuFailure)
            }
        }
    }

    fn retry_close_after_reconcile(
        &self,
        lease: DmaLeaseId,
        owner: u64,
        device: PackedPciLocation,
        reset_generation: u64,
    ) -> Result<(), DmaLeaseError> {
        if reset_generation == 0 {
            return Err(DmaLeaseError::InvalidState);
        }

        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let mapping = {
            let entry = state.entry_mut(lease, owner)?;
            if entry.device != device {
                return Err(DmaLeaseError::QueueMismatch);
            }
            if !matches!(
                entry.state,
                EntryState::Quarantined {
                    reason: QuarantineReason::UnmapFailed,
                    ..
                }
            ) {
                return Err(DmaLeaseError::InvalidState);
            }
            entry.state = EntryState::Closing;
            entry.mapping.take().ok_or(DmaLeaseError::InvalidState)?
        };

        match mapping.try_unmap() {
            Ok(allocation) => {
                let removed = state
                    .entries
                    .remove(&lease.slot())
                    .expect("reconciled DMA entry must remain registered during unmap");
                debug_assert_eq!(removed.owner, owner);
                debug_assert_eq!(removed.state, EntryState::Closing);
                debug_assert!(removed.mapping.is_none());
                state.release_identity(lease);
                drop(state);
                drop(allocation);
                Ok(())
            }
            Err(RRefDmaBytesUnmapError { buffer, kind }) => {
                log::error!(
                    "[DMA] reconciled unmap still failed for lease {:?}: {:?}",
                    lease,
                    kind
                );
                let entry = state
                    .entry_mut(lease, owner)
                    .expect("reconciled DMA entry must remain registered after unmap failure");
                entry.mapping = Some(buffer);
                entry.state = EntryState::Quarantined {
                    reason: QuarantineReason::UnmapFailed,
                    queue: None,
                };
                Err(DmaLeaseError::IommuFailure)
            }
        }
    }

    fn abandon(&self, lease: DmaLeaseId, owner: u64, observed_state: DmaLeaseState) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let Ok(entry) = state.entry_mut(lease, owner) else {
            return;
        };
        if entry.state == EntryState::Closing
            || matches!(
                entry.state,
                EntryState::Quarantined {
                    reason: QuarantineReason::UnmapFailed,
                    ..
                }
            )
        {
            return;
        }
        let queue = match entry.state {
            EntryState::Prepared { queue }
            | EntryState::InFlight { queue }
            | EntryState::Completed { queue }
            | EntryState::RevokedAfterReset { queue, .. } => Some(queue),
            EntryState::Quarantined { queue, .. } => queue,
            EntryState::CpuOwned | EntryState::Closing => None,
        };
        entry.state = EntryState::Quarantined {
            reason: QuarantineReason::CapabilityAbandoned(observed_state),
            queue,
        };
    }
}

static DMA_REGISTRY: DmaRegistry = DmaRegistry::new();

struct KernelDmaLeaseAuthority {
    lease: DmaLeaseId,
    owner: u64,
    device_address: DmaDeviceAddress,
    byte_count: DmaByteCount,
    direction: DmaDirection,
}

// SAFETY: Every method delegates to the single registry generation named by
// `lease`. The registry serializes CPU visits and state transitions, retains the
// DmaHandle on unmap failure, and only removes the allocation after synchronous
// unmap succeeds.
unsafe impl DmaLeaseAuthority for KernelDmaLeaseAuthority {
    fn lease_id(&self) -> DmaLeaseId {
        self.lease
    }

    fn device_address(&self) -> DmaDeviceAddress {
        self.device_address
    }

    fn byte_count(&self) -> DmaByteCount {
        self.byte_count
    }

    fn direction(&self) -> DmaDirection {
        self.direction
    }

    fn with_cpu_bytes(&self, visitor: &mut dyn FnMut(&[u8])) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.with_cpu_bytes(self.lease, self.owner, visitor)
    }

    fn with_cpu_bytes_mut(&self, visitor: &mut dyn FnMut(&mut [u8])) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.with_cpu_bytes_mut(self.lease, self.owner, visitor)
    }

    fn prepare(&self, queue: DmaQueueIdentity) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.prepare(self.lease, self.owner, queue)
    }

    fn prepared_queue(&self) -> Option<DmaQueueIdentity> {
        DMA_REGISTRY.prepared_queue(self.lease, self.owner)
    }

    fn abort_prepared(&self) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.abort_prepared(self.lease, self.owner)
    }

    fn accept(&self) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.accept(self.lease, self.owner)
    }

    fn complete(&self, queue: DmaQueueIdentity, lease: DmaLeaseId) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.complete(self.lease, self.owner, queue, lease)
    }

    fn return_to_cpu(&self) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.return_to_cpu(self.lease, self.owner)
    }

    fn mark_outcome_unknown(&self) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.mark_outcome_unknown(self.lease, self.owner)
    }

    fn revoke_after_reset(
        &self,
        device: PackedPciLocation,
        reset_generation: u64,
    ) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.revoke_after_reset(self.lease, self.owner, device, reset_generation)
    }

    fn reconcile(
        &self,
        device: PackedPciLocation,
        reset_generation: u64,
    ) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.reconcile(self.lease, self.owner, device, reset_generation)
    }

    fn close(&self) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.close(self.lease, self.owner)
    }

    fn retry_close_after_reconcile(
        &self,
        device: PackedPciLocation,
        reset_generation: u64,
    ) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.retry_close_after_reconcile(self.lease, self.owner, device, reset_generation)
    }

    fn abandon(&self, observed_state: DmaLeaseState) {
        DMA_REGISTRY.abandon(self.lease, self.owner, observed_state);
    }
}

fn kernel_direction(direction: DmaDirection) -> dma::DmaDirection {
    match direction {
        DmaDirection::ToDevice => dma::DmaDirection::ToDevice,
        DmaDirection::FromDevice => dma::DmaDirection::FromDevice,
        DmaDirection::Bidirectional => dma::DmaDirection::Bidirectional,
    }
}

pub(crate) fn allocate(
    owner: DomainId,
    device: PackedPciLocation,
    iommu_device: crate::io::iommu::types::DeviceId,
    request: DmaAllocationRequest,
) -> Result<CpuDmaLease, DmaAllocationError> {
    let context = DeviceDmaContext::for_attached_device(iommu_device);
    let mapping = context
        .try_map_rref_kernel_bytes(
            request.byte_count().get(),
            kernel_direction(request.direction()),
        )
        .map_err(|error| match error {
            RRefSliceMapError::AllocFailed => DmaAllocationError::AllocationFailed,
            RRefSliceMapError::MapError(_) => DmaAllocationError::MappingFailed,
        })?;

    let logical_len = request.byte_count();
    let direction = request.direction();
    let entry = DmaEntry {
        mapping: Some(mapping),
        owner: owner.as_u64(),
        device,
        direction,
        logical_len,
        state: EntryState::CpuOwned,
    };
    let (lease, device_address) = DMA_REGISTRY.register(entry)?;
    Ok(CpuDmaLease::from_authority(Arc::new(
        KernelDmaLeaseAuthority {
            lease,
            owner: owner.as_u64(),
            device_address,
            byte_count: logical_len,
            direction,
        },
    )))
}

pub(crate) fn close_owned(lease: DmaLeaseId, owner: DomainId) -> Result<(), DmaLeaseError> {
    DMA_REGISTRY.close(lease, owner.as_u64())
}

pub(crate) fn abi_view(lease: DmaLeaseId, owner: DomainId) -> Result<DmaAbiView, DmaLeaseError> {
    DMA_REGISTRY.abi_view(lease, owner.as_u64())
}

pub(crate) fn cleanup_owner(owner: DomainId) -> DmaCleanupStats {
    let leases: Vec<DmaLeaseId> = {
        let state = DMA_REGISTRY
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state
            .entries
            .iter()
            .filter_map(|(slot, entry)| {
                if entry.owner != owner.as_u64() {
                    return None;
                }
                DmaLeaseId::from_parts(*slot, state.generations.get(slot).copied().unwrap_or(0))
            })
            .collect()
    };

    let mut stats = DmaCleanupStats::default();
    for lease in leases {
        let (logical_len, state_before) = {
            let state = DMA_REGISTRY
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let Ok(entry) = state.entry(lease, owner.as_u64()) else {
                continue;
            };
            (entry.logical_len.get(), entry.state)
        };

        let close_candidate = match state_before {
            EntryState::CpuOwned => true,
            EntryState::Prepared { .. } => {
                match DMA_REGISTRY.abort_prepared(lease, owner.as_u64()) {
                    Ok(()) => true,
                    Err(error) => {
                        log::error!(
                            "[DMA] owner {:?} failed to abort prepared lease {:?}: {:?}",
                            owner,
                            lease,
                            error
                        );
                        false
                    }
                }
            }
            _ => false,
        };

        if close_candidate {
            match DMA_REGISTRY.close(lease, owner.as_u64()) {
                Ok(()) => {
                    stats.released_handles += 1;
                    stats.released_bytes += logical_len;
                    continue;
                }
                Err(error) => {
                    log::error!(
                        "[DMA] owner {:?} failed to close lease {:?}: {:?}",
                        owner,
                        lease,
                        error
                    );
                }
            }
        }

        let mut state = DMA_REGISTRY
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Ok(entry) = state.entry_mut(lease, owner.as_u64()) {
            if entry.state == EntryState::Closing {
                continue;
            }
            if matches!(
                entry.state,
                EntryState::Quarantined {
                    reason: QuarantineReason::UnmapFailed,
                    ..
                }
            ) {
                stats.quarantined_handles += 1;
                stats.quarantined_bytes += logical_len;
                continue;
            }
            let queue = match entry.state {
                EntryState::Prepared { queue }
                | EntryState::InFlight { queue }
                | EntryState::Completed { queue }
                | EntryState::RevokedAfterReset { queue, .. } => Some(queue),
                EntryState::Quarantined { queue, .. } => queue,
                EntryState::CpuOwned | EntryState::Closing => None,
            };
            entry.state = EntryState::Quarantined {
                reason: QuarantineReason::OwnerShutdown,
                queue,
            };
            stats.quarantined_handles += 1;
            stats.quarantined_bytes += logical_len;
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_identity_changes_when_a_slot_is_reused() {
        let mut state = RegistryState::new();
        let first = state.reserve_identity().expect("first identity");
        state.release_identity(first);
        let second = state.reserve_identity().expect("reused identity");

        assert_eq!(first.slot(), second.slot());
        assert_ne!(first.generation(), second.generation());
        assert_ne!(first, second);
    }
}
