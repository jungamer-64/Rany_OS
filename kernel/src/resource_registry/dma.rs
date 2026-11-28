//! Authoritative DMA allocation, mapping, and transfer registry.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

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
use ownership::{CloseMode, CpuBorrowReturn, DmaStorage, MappedDma, TransferState};

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
    /// A CPU visit or an already-running retirement still owns these bytes.
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
    RetryClose,
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
    // This is only a wake hint. The retained slot is the retirement owner.
    retirement_pending: AtomicBool,
}

impl DmaRegistry {
    const fn new() -> Self {
        Self {
            state: PoisonLock::new(LeaseSlots::new()),
            retirement_pending: AtomicBool::new(false),
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
        let mapping = entry.storage.take_for_close(CloseMode::Explicit)?;
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
                debug_assert!(matches!(removed.storage, DmaStorage::Closing(_)));
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
                let DmaStorage::Closing(mode) = entry.storage else {
                    unreachable!("only the closing owner can restore the failed mapping");
                };
                entry.storage = match mode {
                    CloseMode::Explicit => DmaStorage::Mapped(MappedDma {
                        mapping: buffer,
                        state: TransferState::Quarantined {
                            reason: QuarantineReason::UnmapFailed,
                            queue: None,
                        },
                    }),
                    CloseMode::Detached => {
                        self.retirement_pending.store(true, Ordering::Release);
                        DmaStorage::Retiring(buffer)
                    }
                };
                Err(DmaLeaseError::IommuFailure)
            }
        }
    }

    fn retry_close(&self, lease: DmaLeaseId, owner: u64) -> Result<(), DmaLeaseError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.entry_mut(lease, owner)?;
        if !matches!(
            entry.storage.mapped()?.state,
            TransferState::Quarantined {
                reason: QuarantineReason::UnmapFailed,
                queue: None,
            }
        ) {
            return Err(DmaLeaseError::InvalidState);
        }
        let mapping = entry.storage.take_for_close(CloseMode::Explicit)?;
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
            DmaStorage::Closing(mode) => {
                *mode = CloseMode::Detached;
                return OwnerDmaReturn::Pending { bytes };
            }
            DmaStorage::CpuBorrowed(return_to) => {
                *return_to = CpuBorrowReturn::Retire;
                return OwnerDmaReturn::Pending { bytes };
            }
            DmaStorage::Mapped(mapped) if !mapped.state.can_retire() => {
                if !matches!(mapped.state, TransferState::Quarantined { .. }) {
                    mapped.state = TransferState::Quarantined {
                        reason: QuarantineReason::OwnerShutdown,
                        queue: mapped.state.queue(),
                    };
                }
                return OwnerDmaReturn::Quarantined { bytes };
            }
            DmaStorage::Mapped(_) | DmaStorage::Retiring(_) => {}
        }
        let mapping = entry
            .storage
            .take_for_close(CloseMode::Detached)
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
        if entry.storage.abandon(observed_state) {
            self.retirement_pending.store(true, Ordering::Release);
        }
    }

    fn take_deferred_retirement(
        &self,
        cursor: &mut ScanCursor,
    ) -> Option<(DmaLeaseId, u64, DmaBytes)> {
        let mut slots = self.state.lock().unwrap_or_else(|error| error.into_inner());
        // LOOP_PROOF: mode=condition; reason=The cursor advances through the finite metadata slots until it finds a deferred owner or reaches the end.;
        while let Some((lease, entry)) = slots.next(cursor) {
            if matches!(entry.storage, DmaStorage::Retiring(_)) {
                let owner = entry.owner;
                let entry = slots.entry_mut(lease, owner).expect("same registry lock");
                let mapping = entry
                    .storage
                    .take_for_close(CloseMode::Detached)
                    .expect("deferred retirement retained its mapping");
                return Some((lease, owner, mapping));
            }
        }
        None
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
// deferred retirement after the last reference ends. Forgetting it retains RAM.
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
        if matches!(entry.storage.return_cpu(mapping), CpuBorrowReturn::Retire) {
            self.registry
                .retirement_pending
                .store(true, Ordering::Release);
        }
    }
}

static DMA_REGISTRY: DmaRegistry = DmaRegistry::new();

/// The maintenance task owns this cursor across bounded service turns.
pub(crate) struct DmaRetirementSweep {
    cursor: Option<ScanCursor>,
}

impl DmaRetirementSweep {
    pub(crate) const fn new() -> Self {
        Self { cursor: None }
    }

    pub(crate) fn service_turn(&mut self) {
        const BATCH: usize = 16;
        if !DMA_REGISTRY
            .retirement_pending
            .swap(false, Ordering::AcqRel)
        {
            return;
        }
        let resumed = self.cursor.is_some();
        let cursor = self.cursor.get_or_insert_with(ScanCursor::new);
        // LOOP_PROOF: mode=bounded; reason=One service turn attempts at most BATCH retirements.;
        for _ in 0..BATCH {
            let Some((lease, owner, mapping)) = DMA_REGISTRY.take_deferred_retirement(cursor)
            else {
                self.cursor = None;
                // A resumed scan may have consumed a hint for work behind
                // its cursor. Start the next turn at the beginning.
                if resumed {
                    DMA_REGISTRY
                        .retirement_pending
                        .store(true, Ordering::Release);
                }
                return;
            };
            // On failure finish_close logs the cause and republishes the
            // exact owner, including its translation-retirement progress.
            let _attempt = DMA_REGISTRY.finish_close(lease, owner, mapping);
        }
        // A later turn resumes after this batch, even if a prior owner is stuck.
        DMA_REGISTRY
            .retirement_pending
            .store(true, Ordering::Release);
    }
}

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

    fn retry_close(&self) -> Result<(), DmaLeaseError> {
        DMA_REGISTRY.retry_close(self.lease, self.owner)
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
        DmaRegistryCommand::RetryClose => {
            DMA_REGISTRY.retry_close(lease, owner)?;
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

/// Counts registry owners still retained during domain finalization, including
/// in-flight CPU visits, armed transfers and quarantined translations.
pub(crate) fn owner_lease_count(owner: DomainId) -> usize {
    let state = DMA_REGISTRY
        .state
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut cursor = ScanCursor::new();
    let mut count = 0;
    // LOOP_PROOF: mode=condition; reason=The cursor advances through each of the fixed metadata slots at most once.;
    while let Some((_, entry)) = state.next(&mut cursor) {
        count += usize::from(entry.owner == owner.as_u64());
    }
    count
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

#[cfg(test)]
mod retirement_tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
    use kernel_api::dma::{DmaQuiesceWitness, DmaResetWitness};

    static NEXT_LEASE: AtomicU32 = AtomicU32::new(1);

    struct RetirementLease {
        id: DmaLeaseId,
        failed: AtomicBool,
        released: AtomicBool,
        attempts: AtomicUsize,
        abandoned: AtomicUsize,
    }

    // SAFETY: this private authority admits only CPU-owned close and failed
    // retirement. It publishes no DMA descriptor, never arms hardware, and
    // rejects byte access and all transfer transitions. Failed retirement
    // preserves the same owner; successful retirement consumes it once.
    unsafe impl DmaLeaseAuthority for RetirementLease {
        fn lease_id(&self) -> DmaLeaseId {
            self.id
        }
        fn device_address(&self) -> DmaDeviceAddress {
            DmaDeviceAddress::from_abi(0x1000)
        }
        fn byte_count(&self) -> DmaByteCount {
            DmaByteCount::new(1).unwrap()
        }
        fn direction(&self) -> DmaDirection {
            DmaDirection::FromDevice
        }
        fn with_cpu_bytes(&self, _: &mut dyn FnMut(&[u8])) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn with_cpu_bytes_mut(&self, _: &mut dyn FnMut(&mut [u8])) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn prepare(&self, _: DmaQueueIdentity) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn prepared_queue(&self) -> Result<DmaQueueIdentity, DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn abort_prepared(&self) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn arm(&self) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn complete(&self, _: DmaCompletionWitness) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn return_to_cpu(&self) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn mark_outcome_unknown(&self) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn revoke_after_reset(&self, _: DmaResetWitness) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn reconcile(&self, _: DmaReconcileWitness) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn close(&self) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::IommuFailure)
        }
        fn prepare_shared(&self, _: DmaQueueIdentity) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn activate_shared(&self) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn read_shared_word(&self, _: usize, _: DmaAccessWidth) -> Result<u64, DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn write_shared_word(
            &self,
            _: usize,
            _: DmaAccessWidth,
            _: u64,
        ) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn quiesce_shared(&self, _: DmaQuiesceWitness) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn retry_close(&self) -> Result<(), DmaLeaseError> {
            self.attempts.fetch_add(1, Ordering::Relaxed);
            if self.failed.load(Ordering::Acquire) {
                return Err(DmaLeaseError::IommuFailure);
            }
            assert!(!self.released.swap(true, Ordering::AcqRel));
            Ok(())
        }
        fn abandon(&self, _: DmaLeaseState) {
            self.abandoned.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn retained_lease(scheduler: &crate::io::io_scheduler::IoScheduler) -> Arc<RetirementLease> {
        let owner = Arc::new(RetirementLease {
            id: DmaLeaseId::from_parts(NEXT_LEASE.fetch_add(1, Ordering::Relaxed), 1).unwrap(),
            failed: AtomicBool::new(true),
            released: AtomicBool::new(false),
            attempts: AtomicUsize::new(0),
            abandoned: AtomicUsize::new(0),
        });
        let authority: Arc<dyn DmaLeaseAuthority> = owner.clone();
        assert_eq!(
            scheduler.finalize_transfer(CpuDmaLease::from_authority(authority)),
            Err(DmaLeaseError::IommuFailure)
        );
        owner
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn failed_retirement_keeps_owner_until_a_later_service_turn() {
        let scheduler = crate::io::io_scheduler::IoScheduler::new();
        let owner = retained_lease(&scheduler);
        scheduler.reap_abandoned();
        assert_eq!(owner.attempts.load(Ordering::Relaxed), 1);
        assert!(!owner.released.load(Ordering::Acquire));
        assert_eq!(owner.abandoned.load(Ordering::Relaxed), 0);
        owner.failed.store(false, Ordering::Release);
        scheduler.reap_abandoned();
        scheduler.reap_abandoned();
        assert_eq!(owner.attempts.load(Ordering::Relaxed), 2);
        assert!(owner.released.load(Ordering::Acquire));
        assert_eq!(owner.abandoned.load(Ordering::Relaxed), 0);
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn failed_retirement_batches_allow_following_owners_to_progress() {
        let scheduler = crate::io::io_scheduler::IoScheduler::new();
        let owners: Vec<_> = (0..65).map(|_| retained_lease(&scheduler)).collect();
        owners[64].failed.store(false, Ordering::Release);
        scheduler.reap_abandoned();
        assert_eq!(
            owners
                .iter()
                .map(|owner| owner.attempts.load(Ordering::Relaxed))
                .sum::<usize>(),
            64
        );
        scheduler.reap_abandoned();
        assert!(owners[64].released.load(Ordering::Acquire));
        assert_eq!(owners[64].attempts.load(Ordering::Relaxed), 1);
        assert!(
            owners[..64]
                .iter()
                .all(|owner| owner.abandoned.load(Ordering::Relaxed) == 0)
        );
        for owner in &owners {
            owner.failed.store(false, Ordering::Release);
        }
        scheduler.reap_abandoned();
        assert!(
            owners
                .iter()
                .all(|owner| owner.released.load(Ordering::Acquire))
        );
    }
}
