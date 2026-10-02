//! Authoritative DMA allocation, mapping, and transfer registry.

use alloc::sync::Arc;

use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::dma::{
    CpuDmaLease, DmaAccessWidth, DmaAllocationRequest, DmaByteCount, DmaCompletionWitness,
    DmaDeviceAddress, DmaDirection, DmaLeaseAuthority, DmaLeaseError, DmaLeaseId, DmaLeaseState,
    DmaQueueIdentity, DmaQuiesceWitness, DmaReconcileWitness, DmaResetWitness,
};

use crate::domain::{DomainId, DomainResourceAdmission, DomainResourceAdmissionError};
use crate::io::iommu::common::dma::handle::{DmaBytes, DmaBytesUnmapError, MapError, MapErrorKind};
use crate::io::iommu::runtime::zombie::DMA_RETIREMENT_CAPACITY;
use crate::sync::PoisonLock;

#[path = "dma/slots.rs"]
mod slots;
use slots::{LeaseSlots, ScanCursor};

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
    SharedPrepared {
        queue: DmaQueueIdentity,
    },
    SharedActive {
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
    owner: u64,
    device: PackedPciLocation,
    direction: DmaDirection,
    logical_len: DmaByteCount,
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
    OwnerAdmission(DomainResourceAdmissionError),
    OwnerMismatch,
    InvalidSize,
    AllocationFailed,
    MetadataAllocationFailed,
    MappingFailed,
    MappingRejected(MapErrorKind),
    TranslationPending(MapErrorKind),
}

pub(crate) enum DmaRegistryCommand {
    Prepare(DmaQueueIdentity),
    Arm,
    Abort,
    Complete(DmaCompletionWitness),
    ReturnToCpu,
    OutcomeUnknown,
    Revoke(DmaResetWitness),
    Reconcile(DmaReconcileWitness),
    Close,
    PrepareShared(DmaQueueIdentity),
    ActivateShared,
    QuiesceShared(DmaQuiesceWitness),
    RetryClose(DmaReconcileWitness),
    ReadShared {
        offset: usize,
        width: DmaAccessWidth,
    },
    WriteShared {
        offset: usize,
        width: DmaAccessWidth,
        value: u64,
    },
    PreparedQueue,
    Abandon(DmaLeaseState),
}

pub(crate) enum DmaRegistryResponse {
    None,
    Scalar(u64),
    Queue(DmaQueueIdentity),
}

// The bound derives from mapping admission: every DmaBytes owner already
// retains a retirement reservation. Metadata itself needs no allocator or OOM.
impl<const N: usize> LeaseSlots<DmaEntry, N> {
    fn entry(&self, lease: DmaLeaseId, owner: u64) -> Result<&DmaEntry, DmaLeaseError> {
        let entry = self.get(lease).ok_or(DmaLeaseError::StaleLease)?;
        if entry.owner != owner {
            return Err(DmaLeaseError::ForeignOwner);
        }
        Ok(entry)
    }
    fn entry_mut(&mut self, lease: DmaLeaseId, owner: u64) -> Result<&mut DmaEntry, DmaLeaseError> {
        let entry = self.get_mut(lease).ok_or(DmaLeaseError::StaleLease)?;
        if entry.owner != owner {
            return Err(DmaLeaseError::ForeignOwner);
        }
        Ok(entry)
    }
}

struct DmaRegistry {
    state: PoisonLock<LeaseSlots<DmaEntry, DMA_RETIREMENT_CAPACITY>>,
}

impl DmaRegistry {
    const fn new() -> Self {
        Self {
            state: PoisonLock::new(LeaseSlots::new()),
        }
    }

    fn register(
        &self,
        admission: &DomainResourceAdmission<'_>,
        entry: DmaEntry,
    ) -> Result<(DmaLeaseId, DmaDeviceAddress), (DmaAllocationError, DmaEntry)> {
        if entry.owner != admission.domain().as_u64() {
            return Err((DmaAllocationError::OwnerMismatch, entry));
        }
        let device_address = match entry.mapping() {
            Ok(mapping) => DmaDeviceAddress::from_abi(mapping.iova()),
            Err(_) => return Err((DmaAllocationError::MappingFailed, entry)),
        };
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let admitted = state.insert(entry);
        drop(state);
        // Return rejection ownership through the enclosing domain admission
        // scope. Neither registry may finalize the unaccepted mapping owner.
        admitted
            .map(|lease| (lease, device_address))
            .map_err(|entry| (DmaAllocationError::RegistryExhausted, entry))
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

        entry.mapping()?.flush_for_device()?;
        entry.state = EntryState::Prepared { queue };
        Ok(())
    }

    fn prepared_queue(
        &self,
        lease: DmaLeaseId,
        owner: u64,
    ) -> Result<DmaQueueIdentity, DmaLeaseError> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        match state.entry(lease, owner)?.state {
            EntryState::Prepared { queue } | EntryState::SharedPrepared { queue } => Ok(queue),
            _ => Err(DmaLeaseError::InvalidState),
        }
    }

    fn abort_prepared(&self, lease: DmaLeaseId, owner: u64) -> Result<(), DmaLeaseError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        if !matches!(
            entry.state,
            EntryState::Prepared { .. } | EntryState::SharedPrepared { .. }
        ) {
            return Err(DmaLeaseError::InvalidState);
        }
        entry.state = EntryState::CpuOwned;
        Ok(())
    }

    fn arm(&self, lease: DmaLeaseId, owner: u64) -> Result<(), DmaLeaseError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        let EntryState::Prepared { queue } = entry.state else {
            return Err(DmaLeaseError::InvalidState);
        };
        entry.state = EntryState::InFlight { queue };
        Ok(())
    }

    fn prepare_shared(
        &self,
        lease: DmaLeaseId,
        owner: u64,
        queue: DmaQueueIdentity,
    ) -> Result<(), DmaLeaseError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        if entry.device != queue.device() {
            return Err(DmaLeaseError::QueueMismatch);
        }
        if entry.state != EntryState::CpuOwned {
            return Err(DmaLeaseError::InvalidState);
        }
        entry.mapping()?.flush_for_device()?;
        entry.state = EntryState::SharedPrepared { queue };
        Ok(())
    }

    fn activate_shared(&self, lease: DmaLeaseId, owner: u64) -> Result<(), DmaLeaseError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        let EntryState::SharedPrepared { queue } = entry.state else {
            return Err(DmaLeaseError::InvalidState);
        };
        entry.state = EntryState::SharedActive { queue };
        Ok(())
    }

    fn read_shared_word(
        &self,
        lease: DmaLeaseId,
        owner: u64,
        offset: usize,
        width: DmaAccessWidth,
    ) -> Result<u64, DmaLeaseError> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry(lease, owner)?;
        if !matches!(entry.state, EntryState::SharedActive { .. }) {
            return Err(DmaLeaseError::InvalidState);
        }
        // SAFETY: only active shared state reaches this access. The registry
        // lock excludes CPU references, other CPU accesses, and reclamation;
        // the mapping owns the initialized coherent RAM allocation.
        unsafe { entry.mapping()?.read_shared_word(offset, width) }
    }

    fn write_shared_word(
        &self,
        lease: DmaLeaseId,
        owner: u64,
        offset: usize,
        width: DmaAccessWidth,
        value: u64,
    ) -> Result<(), DmaLeaseError> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry(lease, owner)?;
        if !matches!(entry.state, EntryState::SharedActive { .. }) {
            return Err(DmaLeaseError::InvalidState);
        }
        // SAFETY: shared state denies CPU slices; the registry lock serializes
        // scalar accesses and teardown while retaining the coherent allocation.
        unsafe { entry.mapping()?.write_shared_word(offset, width, value) }
    }

    fn quiesce_shared(
        &self,
        lease: DmaLeaseId,
        owner: u64,
        witness: DmaQuiesceWitness,
    ) -> Result<(), DmaLeaseError> {
        if witness.lease_id() != lease {
            return Err(DmaLeaseError::QueueMismatch);
        }
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        match entry.state {
            EntryState::SharedActive { queue } if queue == witness.queue() => {}
            EntryState::SharedActive { .. } => return Err(DmaLeaseError::QueueMismatch),
            _ => return Err(DmaLeaseError::InvalidState),
        }
        // The caller's non-cloneable witness establishes hardware quiescence.
        // Only after that fact may a normal CPU reference be constructed.
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        entry.state = EntryState::CpuOwned;
        Ok(())
    }

    fn complete(
        &self,
        lease: DmaLeaseId,
        owner: u64,
        witness: DmaCompletionWitness,
    ) -> Result<(), DmaLeaseError> {
        if witness.lease_id() != lease {
            return Err(DmaLeaseError::QueueMismatch);
        }
        let queue = witness.queue();
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
            entry.mapping()?.invalidate_for_cpu()?;
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
        witness: DmaResetWitness,
    ) -> Result<(), DmaLeaseError> {
        let device = witness.device();
        let reset_generation = witness.generation();
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        if entry.device != device {
            return Err(DmaLeaseError::QueueMismatch);
        }
        let queue = match entry.state {
            EntryState::InFlight { queue } | EntryState::SharedActive { queue } => queue,
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
        witness: DmaReconcileWitness,
    ) -> Result<(), DmaLeaseError> {
        let device = witness.device();
        let reset_generation = witness.generation();
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
            entry.mapping()?.invalidate_for_cpu()?;
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
        drop(state);

        match mapping.try_unmap() {
            Ok(allocation) => {
                let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                let removed = state
                    .remove(lease)
                    .expect("closing DMA entry must remain registered during synchronous unmap");
                debug_assert_eq!(removed.owner, owner);
                debug_assert_eq!(removed.state, EntryState::Closing);
                debug_assert!(removed.mapping.is_none());
                drop(state);
                drop(allocation);
                Ok(())
            }
            Err(DmaBytesUnmapError { buffer, kind }) => {
                log::error!(
                    "[DMA] quarantining lease {:?} after unmap failure: {:?}",
                    lease,
                    kind
                );
                let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
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
        witness: DmaReconcileWitness,
    ) -> Result<(), DmaLeaseError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let mapping = {
            let entry = state.entry_mut(lease, owner)?;
            if entry.device != witness.device() {
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
        drop(state);

        match mapping.try_unmap() {
            Ok(allocation) => {
                let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                let removed = state
                    .remove(lease)
                    .expect("reconciled DMA entry must remain registered during unmap");
                debug_assert_eq!(removed.owner, owner);
                debug_assert_eq!(removed.state, EntryState::Closing);
                debug_assert!(removed.mapping.is_none());
                drop(state);
                drop(allocation);
                Ok(())
            }
            Err(DmaBytesUnmapError { buffer, kind }) => {
                log::error!(
                    "[DMA] reconciled unmap still failed for lease {:?}: {:?}",
                    lease,
                    kind
                );
                let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
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
            | EntryState::SharedPrepared { queue }
            | EntryState::SharedActive { queue }
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

    fn prepared_queue(&self) -> Result<DmaQueueIdentity, DmaLeaseError> {
        DMA_REGISTRY.prepared_queue(self.lease, self.owner)
    }

    fn abort_prepared(&self) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.abort_prepared(self.lease, self.owner)
    }

    fn arm(&self) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.arm(self.lease, self.owner)
    }

    fn complete(&self, witness: DmaCompletionWitness) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.complete(self.lease, self.owner, witness)
    }

    fn return_to_cpu(&self) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.return_to_cpu(self.lease, self.owner)
    }

    fn mark_outcome_unknown(&self) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.mark_outcome_unknown(self.lease, self.owner)
    }

    fn revoke_after_reset(&self, witness: DmaResetWitness) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.revoke_after_reset(self.lease, self.owner, witness)
    }

    fn reconcile(&self, witness: DmaReconcileWitness) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.reconcile(self.lease, self.owner, witness)
    }

    fn close(&self) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.close(self.lease, self.owner)
    }

    fn prepare_shared(&self, queue: DmaQueueIdentity) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.prepare_shared(self.lease, self.owner, queue)
    }

    fn activate_shared(&self) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.activate_shared(self.lease, self.owner)
    }

    fn read_shared_word(&self, offset: usize, width: DmaAccessWidth) -> Result<u64, DmaLeaseError> {
        DMA_REGISTRY.read_shared_word(self.lease, self.owner, offset, width)
    }

    fn write_shared_word(
        &self,
        offset: usize,
        width: DmaAccessWidth,
        value: u64,
    ) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.write_shared_word(self.lease, self.owner, offset, width, value)
    }

    fn quiesce_shared(&self, witness: DmaQuiesceWitness) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.quiesce_shared(self.lease, self.owner, witness)
    }

    fn retry_close_after_reconcile(
        &self,
        witness: DmaReconcileWitness,
    ) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.retry_close_after_reconcile(self.lease, self.owner, witness)
    }

    fn abandon(&self, observed_state: DmaLeaseState) {
        DMA_REGISTRY.abandon(self.lease, self.owner, observed_state);
    }
}

fn kernel_direction(direction: DmaDirection) -> crate::io::iommu::api::DmaDirection {
    match direction {
        DmaDirection::ToDevice => crate::io::iommu::api::DmaDirection::ToDevice,
        DmaDirection::FromDevice => crate::io::iommu::api::DmaDirection::FromDevice,
        DmaDirection::Bidirectional => crate::io::iommu::api::DmaDirection::Bidirectional,
    }
}

pub(crate) fn allocate(
    owner: DomainId,
    device: PackedPciLocation,
    iommu_device: crate::io::iommu::types::DeviceId,
    request: DmaAllocationRequest,
) -> Result<CpuDmaLease, DmaAllocationError> {
    // Acquire the capability's metadata before committing any registry owner.
    // Initialization after admission is allocation-free and cannot reject a
    // successfully published lease because of bookkeeping allocation failure.
    let mut authority = Arc::<KernelDmaLeaseAuthority>::try_new_uninit()
        .map_err(|_| DmaAllocationError::MetadataAllocationFailed)?;
    let len = request.byte_count().get();
    let page = crate::mm::types::PAGE_SIZE_4K;
    let capacity = len
        .checked_add(page - 1)
        .map(|end| end & !(page - 1))
        .ok_or(DmaAllocationError::InvalidSize)?;
    let backing =
        crate::ipc::RRef::new_slice_default_aligned(crate::ipc::DomainId::KERNEL, capacity, page)
            .ok_or(DmaAllocationError::AllocationFailed)?;
    let mapping = DmaBytes::map(
        backing,
        len,
        &iommu_device,
        kernel_direction(request.direction()),
    )
    .map_err(|error| match error {
        MapError::Unmapped { rref, kind } => {
            drop(rref);
            DmaAllocationError::MappingRejected(kind)
        }
        MapError::TranslationPending { handle, kind } => {
            // The reserved retirement slot receives mapping and backing;
            // no ordinary CPU ownership is restored after publication.
            drop(handle);
            DmaAllocationError::TranslationPending(kind)
        }
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
    let registration = crate::domain::with_resource_admission(owner, entry, |admission, entry| {
        DMA_REGISTRY.register(&admission, entry)
    })
    .map_err(|(cause, entry)| {
        drop(entry);
        DmaAllocationError::OwnerAdmission(cause)
    })?;
    let (lease, device_address) = registration.map_err(|(cause, entry)| {
        drop(entry);
        cause
    })?;
    Arc::get_mut(&mut authority)
        .expect("unpublished capability metadata has one strong owner and no weak observers")
        .write(KernelDmaLeaseAuthority {
            lease,
            owner: owner.as_u64(),
            device_address,
            byte_count: logical_len,
            direction,
        });
    // SAFETY: the uniquely prepared Arc received the complete authority value
    // above. No uninitialized observer or clone was published, and all fields
    // refer to the successfully admitted generation and its retained mapping.
    let authority = unsafe { authority.assume_init() };
    Ok(CpuDmaLease::from_authority(authority))
}

pub(crate) fn with_cpu_bytes(
    lease: DmaLeaseId,
    owner: DomainId,
    visitor: &mut dyn FnMut(&[u8]),
) -> Result<(), DmaLeaseError> {
    DMA_REGISTRY.with_cpu_bytes(lease, owner.as_u64(), visitor)
}

pub(crate) fn with_cpu_bytes_mut(
    lease: DmaLeaseId,
    owner: DomainId,
    visitor: &mut dyn FnMut(&mut [u8]),
) -> Result<(), DmaLeaseError> {
    DMA_REGISTRY.with_cpu_bytes_mut(lease, owner.as_u64(), visitor)
}

pub(crate) fn command(
    lease: DmaLeaseId,
    owner: DomainId,
    command: DmaRegistryCommand,
) -> Result<DmaRegistryResponse, DmaLeaseError> {
    let owner = owner.as_u64();
    match command {
        DmaRegistryCommand::Prepare(queue) => {
            DMA_REGISTRY.prepare(lease, owner, queue)?;
            Ok(DmaRegistryResponse::None)
        }
        DmaRegistryCommand::Arm => {
            DMA_REGISTRY.arm(lease, owner)?;
            Ok(DmaRegistryResponse::None)
        }
        DmaRegistryCommand::Abort => {
            DMA_REGISTRY.abort_prepared(lease, owner)?;
            Ok(DmaRegistryResponse::None)
        }
        DmaRegistryCommand::Complete(witness) => {
            DMA_REGISTRY.complete(lease, owner, witness)?;
            Ok(DmaRegistryResponse::None)
        }
        DmaRegistryCommand::ReturnToCpu => {
            DMA_REGISTRY.return_to_cpu(lease, owner)?;
            Ok(DmaRegistryResponse::None)
        }
        DmaRegistryCommand::OutcomeUnknown => {
            DMA_REGISTRY.mark_outcome_unknown(lease, owner)?;
            Ok(DmaRegistryResponse::None)
        }
        DmaRegistryCommand::Revoke(witness) => {
            DMA_REGISTRY.revoke_after_reset(lease, owner, witness)?;
            Ok(DmaRegistryResponse::None)
        }
        DmaRegistryCommand::Reconcile(witness) => {
            DMA_REGISTRY.reconcile(lease, owner, witness)?;
            Ok(DmaRegistryResponse::None)
        }
        DmaRegistryCommand::Close => {
            DMA_REGISTRY.close(lease, owner)?;
            Ok(DmaRegistryResponse::None)
        }
        DmaRegistryCommand::PrepareShared(queue) => {
            DMA_REGISTRY.prepare_shared(lease, owner, queue)?;
            Ok(DmaRegistryResponse::None)
        }
        DmaRegistryCommand::ActivateShared => {
            DMA_REGISTRY.activate_shared(lease, owner)?;
            Ok(DmaRegistryResponse::None)
        }
        DmaRegistryCommand::QuiesceShared(witness) => {
            DMA_REGISTRY.quiesce_shared(lease, owner, witness)?;
            Ok(DmaRegistryResponse::None)
        }
        DmaRegistryCommand::RetryClose(witness) => {
            DMA_REGISTRY.retry_close_after_reconcile(lease, owner, witness)?;
            Ok(DmaRegistryResponse::None)
        }
        DmaRegistryCommand::ReadShared { offset, width } => DMA_REGISTRY
            .read_shared_word(lease, owner, offset, width)
            .map(DmaRegistryResponse::Scalar),
        DmaRegistryCommand::WriteShared {
            offset,
            width,
            value,
        } => {
            DMA_REGISTRY.write_shared_word(lease, owner, offset, width, value)?;
            Ok(DmaRegistryResponse::None)
        }
        DmaRegistryCommand::PreparedQueue => DMA_REGISTRY
            .prepared_queue(lease, owner)
            .map(DmaRegistryResponse::Queue),
        DmaRegistryCommand::Abandon(observed) => {
            DMA_REGISTRY.abandon(lease, owner, observed);
            Ok(DmaRegistryResponse::None)
        }
    }
}

pub(crate) fn cleanup_owner(owner: DomainId) -> DmaCleanupStats {
    let mut cursor = ScanCursor::new();
    let mut stats = DmaCleanupStats::default();
    // LOOP_PROOF: mode=event; reason=The cursor visits each bounded metadata slot at most once and returns when no further owner entry remains.;
    loop {
        let observed = {
            let state = DMA_REGISTRY
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let mut observed = None;
            // LOOP_PROOF: mode=condition; reason=Each next advances the finite slot cursor, including foreign-owner entries.;
            while let Some((lease, entry)) = state.next(&mut cursor) {
                if entry.owner == owner.as_u64() {
                    observed = Some((lease, entry.logical_len.get(), entry.state));
                    break;
                }
            }
            observed
        };
        let Some((lease, logical_len, state_before)) = observed else {
            break;
        };

        let close_candidate = match state_before {
            EntryState::CpuOwned => true,
            EntryState::Prepared { .. } | EntryState::SharedPrepared { .. } => {
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
                | EntryState::SharedPrepared { queue }
                | EntryState::SharedActive { queue }
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
