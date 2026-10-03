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
#[path = "dma/ownership.rs"]
mod ownership;
use ownership::{CpuBorrowEnd, CpuBorrowReturn, DmaStorage, MappedDma, TransferState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuarantineReason {
    OutcomeUnknown,
    UnmapFailed,
    CapabilityAbandoned(DmaLeaseState),
    OwnerShutdown,
}

struct DmaEntry {
    storage: DmaStorage<DmaBytes>,
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
    /// CPU visits or an already-running close still own these bytes.
    pub(crate) pending_handles: usize,
    pub(crate) pending_bytes: usize,
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
        let device_address = match entry.storage.mapped() {
            Ok(mapped) => DmaDeviceAddress::from_abi(mapped.mapping.iova()),
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
        let device = entry.device;
        let entry = entry.storage.mapped_mut()?;
        if entry.state != TransferState::CpuOwned || device != queue.device() {
            return Err(if device != queue.device() {
                DmaLeaseError::QueueMismatch
            } else {
                DmaLeaseError::InvalidState
            });
        }

        entry.mapping.flush_for_device()?;
        entry.state = TransferState::Prepared { queue };
        Ok(())
    }

    fn prepared_queue(
        &self,
        lease: DmaLeaseId,
        owner: u64,
    ) -> Result<DmaQueueIdentity, DmaLeaseError> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        match state.entry(lease, owner)?.storage.mapped()?.state {
            TransferState::Prepared { queue } | TransferState::SharedPrepared { queue } => {
                Ok(queue)
            }
            _ => Err(DmaLeaseError::InvalidState),
        }
    }

    fn abort_prepared(&self, lease: DmaLeaseId, owner: u64) -> Result<(), DmaLeaseError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        let entry = entry.storage.mapped_mut()?;
        if !matches!(
            entry.state,
            TransferState::Prepared { .. } | TransferState::SharedPrepared { .. }
        ) {
            return Err(DmaLeaseError::InvalidState);
        }
        entry.state = TransferState::CpuOwned;
        Ok(())
    }

    fn arm(&self, lease: DmaLeaseId, owner: u64) -> Result<(), DmaLeaseError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        let entry = entry.storage.mapped_mut()?;
        let TransferState::Prepared { queue } = entry.state else {
            return Err(DmaLeaseError::InvalidState);
        };
        entry.state = TransferState::InFlight { queue };
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
        let device = entry.device;
        let entry = entry.storage.mapped_mut()?;
        if device != queue.device() {
            return Err(DmaLeaseError::QueueMismatch);
        }
        if entry.state != TransferState::CpuOwned {
            return Err(DmaLeaseError::InvalidState);
        }
        entry.mapping.flush_for_device()?;
        entry.state = TransferState::SharedPrepared { queue };
        Ok(())
    }

    fn activate_shared(&self, lease: DmaLeaseId, owner: u64) -> Result<(), DmaLeaseError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        let entry = entry.storage.mapped_mut()?;
        let TransferState::SharedPrepared { queue } = entry.state else {
            return Err(DmaLeaseError::InvalidState);
        };
        entry.state = TransferState::SharedActive { queue };
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
        let entry = entry.storage.mapped()?;
        if !matches!(entry.state, TransferState::SharedActive { .. }) {
            return Err(DmaLeaseError::InvalidState);
        }
        // SAFETY: only active shared state reaches this access. The registry
        // lock excludes CPU references, other CPU accesses, and reclamation;
        // the mapping owns the initialized coherent RAM allocation.
        unsafe { entry.mapping.read_shared_word(offset, width) }
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
        let entry = entry.storage.mapped()?;
        if !matches!(entry.state, TransferState::SharedActive { .. }) {
            return Err(DmaLeaseError::InvalidState);
        }
        // SAFETY: shared state denies CPU slices; the registry lock serializes
        // scalar accesses and teardown while retaining the coherent allocation.
        unsafe { entry.mapping.write_shared_word(offset, width, value) }
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
        let entry = entry.storage.mapped_mut()?;
        match entry.state {
            TransferState::SharedActive { queue } if queue == witness.queue() => {}
            TransferState::SharedActive { .. } => return Err(DmaLeaseError::QueueMismatch),
            _ => return Err(DmaLeaseError::InvalidState),
        }
        // The caller's non-cloneable witness establishes hardware quiescence.
        // Only after that fact may a normal CPU reference be constructed.
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        entry.state = TransferState::CpuOwned;
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
        let entry = entry.storage.mapped_mut()?;
        match entry.state {
            TransferState::InFlight { queue: expected } if expected == queue => {
                entry.state = TransferState::Completed { queue };
                Ok(())
            }
            TransferState::InFlight { .. } => Err(DmaLeaseError::QueueMismatch),
            _ => Err(DmaLeaseError::InvalidState),
        }
    }

    fn return_to_cpu(&self, lease: DmaLeaseId, owner: u64) -> Result<(), DmaLeaseError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        let direction = entry.direction;
        let entry = entry.storage.mapped_mut()?;
        if !matches!(entry.state, TransferState::Completed { .. }) {
            return Err(DmaLeaseError::InvalidState);
        }
        if matches!(
            direction,
            DmaDirection::FromDevice | DmaDirection::Bidirectional
        ) {
            entry.mapping.invalidate_for_cpu()?;
        }
        entry.state = TransferState::CpuOwned;
        Ok(())
    }

    fn mark_outcome_unknown(&self, lease: DmaLeaseId, owner: u64) -> Result<(), DmaLeaseError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        let entry = entry.storage.mapped_mut()?;
        let TransferState::InFlight { queue } = entry.state else {
            return Err(DmaLeaseError::InvalidState);
        };
        entry.state = TransferState::Quarantined {
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
        let entry_device = entry.device;
        let entry = entry.storage.mapped_mut()?;
        if entry_device != device {
            return Err(DmaLeaseError::QueueMismatch);
        }
        let queue = match entry.state {
            TransferState::InFlight { queue } | TransferState::SharedActive { queue } => queue,
            TransferState::Quarantined {
                reason: QuarantineReason::OutcomeUnknown,
                queue: Some(queue),
            } => queue,
            _ => return Err(DmaLeaseError::InvalidState),
        };
        if reset_generation <= queue.generation() {
            return Err(DmaLeaseError::QueueMismatch);
        }
        entry.state = TransferState::RevokedAfterReset {
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
        let entry_device = entry.device;
        let direction = entry.direction;
        let entry = entry.storage.mapped_mut()?;
        if entry_device != device {
            return Err(DmaLeaseError::QueueMismatch);
        }
        match entry.state {
            TransferState::RevokedAfterReset {
                reset_generation: expected,
                ..
            } if expected == reset_generation => {}
            TransferState::Quarantined {
                reason: QuarantineReason::UnmapFailed,
                ..
            } => return Err(DmaLeaseError::NotSupported),
            _ => return Err(DmaLeaseError::InvalidState),
        }

        if matches!(
            direction,
            DmaDirection::FromDevice | DmaDirection::Bidirectional
        ) {
            entry.mapping.invalidate_for_cpu()?;
        }
        entry.state = TransferState::CpuOwned;
        Ok(())
    }

    fn borrow_cpu(&self, lease: DmaLeaseId, owner: u64) -> Result<CpuDmaBorrow<'_>, DmaLeaseError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        let mapping = entry.storage.borrow_cpu()?;
        drop(state);
        Ok(CpuDmaBorrow {
            registry: self,
            lease,
            owner,
            mapping: Some(mapping),
        })
    }

    fn with_cpu_bytes(
        &self,
        lease: DmaLeaseId,
        owner: u64,
        visitor: &mut dyn FnMut(&[u8]),
    ) -> Result<(), DmaLeaseError> {
        let borrow = self.borrow_cpu(lease, owner)?;
        // SAFETY: the owned borrow retains initialized RAM. Its registry slot
        // excludes all other visits, device publication and closing until the
        // callback ends; owner shutdown can only request return on borrow drop.
        let bytes =
            unsafe { borrow.mapping().cpu_bytes() }.ok_or(DmaLeaseError::AuthorityViolation)?;
        visitor(bytes);
        Ok(())
    }

    fn with_cpu_bytes_mut(
        &self,
        lease: DmaLeaseId,
        owner: u64,
        visitor: &mut dyn FnMut(&mut [u8]),
    ) -> Result<(), DmaLeaseError> {
        let mut borrow = self.borrow_cpu(lease, owner)?;
        // SAFETY: the sole mapped owner is in this borrow, with no references
        // in the registry and no permitted competing visit or device access.
        let bytes = unsafe { borrow.mapping_mut().cpu_bytes_mut() }
            .ok_or(DmaLeaseError::AuthorityViolation)?;
        visitor(bytes);
        Ok(())
    }

    fn close(&self, lease: DmaLeaseId, owner: u64) -> Result<(), DmaLeaseError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        if entry.storage.mapped()?.state != TransferState::CpuOwned {
            return Err(DmaLeaseError::InvalidState);
        }
        let mapping = entry.storage.take_for_close()?;
        drop(state);
        self.finish_close(lease, owner, mapping)
    }

    fn finish_close(
        &self,
        lease: DmaLeaseId,
        owner: u64,
        mapping: DmaBytes,
    ) -> Result<(), DmaLeaseError> {
        match mapping.try_unmap() {
            Ok(allocation) => {
                let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                let removed = state
                    .remove(lease)
                    .expect("closing slot retains its generation until the unmap owner finishes");
                debug_assert_eq!(removed.owner, owner);
                debug_assert!(matches!(removed.storage, DmaStorage::Closing));
                drop(state);
                drop(removed);
                drop(allocation);
                Ok(())
            }
            Err(DmaBytesUnmapError { buffer, kind }) => {
                log::error!(
                    "[DMA] lease {:?} retained after unmap failure: {:?}",
                    lease,
                    kind
                );
                let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                let entry = state
                    .entry_mut(lease, owner)
                    .expect("closing slot retains its owner during unmap failure");
                debug_assert!(matches!(entry.storage, DmaStorage::Closing));
                entry.storage = DmaStorage::Mapped(MappedDma {
                    mapping: buffer,
                    state: TransferState::Quarantined {
                        reason: QuarantineReason::UnmapFailed,
                        queue: None,
                    },
                });
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
        let entry = state.entry_mut(lease, owner)?;
        if entry.device != witness.device() {
            return Err(DmaLeaseError::QueueMismatch);
        }
        if !matches!(
            entry.storage.mapped()?.state,
            TransferState::Quarantined {
                reason: QuarantineReason::UnmapFailed,
                ..
            }
        ) {
            return Err(DmaLeaseError::InvalidState);
        }
        let mapping = entry.storage.take_for_close()?;
        drop(state);
        self.finish_close(lease, owner, mapping)
    }

    fn cleanup_entry(&self, lease: DmaLeaseId, owner: u64) -> OwnerDmaReturn {
        let mut slots = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let Ok(entry) = slots.entry_mut(lease, owner) else {
            return OwnerDmaReturn::Gone;
        };
        let bytes = entry.logical_len.get();
        match &mut entry.storage {
            DmaStorage::Closing => return OwnerDmaReturn::Pending { bytes },
            DmaStorage::CpuBorrowed(return_to) => {
                *return_to = CpuBorrowReturn::Close;
                return OwnerDmaReturn::Pending { bytes };
            }
            DmaStorage::Mapped(mapped) => {
                if !matches!(
                    mapped.state,
                    TransferState::CpuOwned
                        | TransferState::Prepared { .. }
                        | TransferState::SharedPrepared { .. }
                ) {
                    if !matches!(
                        mapped.state,
                        TransferState::Quarantined {
                            reason: QuarantineReason::UnmapFailed,
                            ..
                        }
                    ) {
                        mapped.state = TransferState::Quarantined {
                            reason: QuarantineReason::OwnerShutdown,
                            queue: mapped.state.queue(),
                        };
                    }
                    return OwnerDmaReturn::Quarantined { bytes };
                }
            }
        }
        // Prepared transfers have not been armed/accepted. This same guard
        // consumes the owner for close, excluding publication in between.
        let mapping = entry
            .storage
            .take_for_close()
            .expect("cleanup admitted a retained mapping");
        drop(slots);
        match self.finish_close(lease, owner, mapping) {
            Ok(()) => OwnerDmaReturn::Released { bytes },
            Err(error) => {
                log::error!(
                    "[DMA] owner {} retained lease {:?} after failed close: {:?}",
                    owner,
                    lease,
                    error
                );
                OwnerDmaReturn::Quarantined { bytes }
            }
        }
    }

    fn abandon(&self, lease: DmaLeaseId, owner: u64, observed_state: DmaLeaseState) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let Ok(entry) = state.entry_mut(lease, owner) else {
            return;
        };
        match &mut entry.storage {
            DmaStorage::Closing => {}
            DmaStorage::CpuBorrowed(return_to) => *return_to = CpuBorrowReturn::Close,
            DmaStorage::Mapped(mapped) => {
                if !matches!(
                    mapped.state,
                    TransferState::Quarantined {
                        reason: QuarantineReason::UnmapFailed,
                        ..
                    }
                ) {
                    mapped.state = TransferState::Quarantined {
                        reason: QuarantineReason::CapabilityAbandoned(observed_state),
                        queue: mapped.state.queue(),
                    };
                }
            }
        }
    }
}

enum OwnerDmaReturn {
    Released { bytes: usize },
    Quarantined { bytes: usize },
    Pending { bytes: usize },
    Gone,
}

// This guard owns the mapping for one synchronous visit. It restores CPU
// ownership on normal return and unwinding, or carries a shutdown request to
// explicit unmap after the last reference ends. Forgetting it only retains RAM.
struct CpuDmaBorrow<'registry> {
    registry: &'registry DmaRegistry,
    lease: DmaLeaseId,
    owner: u64,
    mapping: Option<DmaBytes>,
}

impl CpuDmaBorrow<'_> {
    fn mapping(&self) -> &DmaBytes {
        self.mapping
            .as_ref()
            .expect("borrow retains its owner until drop")
    }

    fn mapping_mut(&mut self) -> &mut DmaBytes {
        self.mapping
            .as_mut()
            .expect("borrow retains its owner until drop")
    }
}

impl Drop for CpuDmaBorrow<'_> {
    fn drop(&mut self) {
        let mapping = self
            .mapping
            .take()
            .expect("borrow returns its mapping exactly once");
        let mut state = self
            .registry
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let entry = state
            .entry_mut(self.lease, self.owner)
            .expect("borrowed slot retains its generation and owner until return");
        let completion = entry.storage.return_cpu(mapping);
        drop(state);
        if let CpuBorrowEnd::Close(mapping) = completion {
            if let Err(error) = self.registry.finish_close(self.lease, self.owner, mapping) {
                // The failed mapping stays registered in unmap-failed quarantine.
                log::error!(
                    "[DMA] deferred CPU-borrow return failed for {:?}: {:?}",
                    self.lease,
                    error
                );
            }
        }
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
        storage: DmaStorage::Mapped(MappedDma {
            mapping,
            state: TransferState::CpuOwned,
        }),
        owner: owner.as_u64(),
        device,
        direction,
        logical_len,
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
        let lease = {
            let state = DMA_REGISTRY
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let mut observed = None;
            // LOOP_PROOF: mode=condition; reason=Each next advances the finite slot cursor, including foreign-owner entries.;
            while let Some((lease, entry)) = state.next(&mut cursor) {
                if entry.owner == owner.as_u64() {
                    observed = Some(lease);
                    break;
                }
            }
            observed
        };
        let Some(lease) = lease else {
            break;
        };
        match DMA_REGISTRY.cleanup_entry(lease, owner.as_u64()) {
            OwnerDmaReturn::Released { bytes } => {
                stats.released_handles += 1;
                stats.released_bytes += bytes;
            }
            OwnerDmaReturn::Quarantined { bytes } => {
                stats.quarantined_handles += 1;
                stats.quarantined_bytes += bytes;
            }
            OwnerDmaReturn::Pending { bytes } => {
                stats.pending_handles += 1;
                stats.pending_bytes += bytes;
            }
            OwnerDmaReturn::Gone => {}
        }
    }
    stats
}
