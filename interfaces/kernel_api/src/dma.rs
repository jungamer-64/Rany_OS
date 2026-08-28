//! DMA allocation and transfer capabilities.
//!
//! A DMA allocation remains owned by the kernel resource registry.  Values in
//! this module are non-cloneable capabilities for operating on that registry
//! entry; they never own or reclaim raw memory themselves.

use alloc::sync::Arc;
use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use core::num::{NonZeroU64, NonZeroUsize};

use crate::abi::driver::PackedPciLocation;

/// Opaque identity of one registry allocation generation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct DmaLeaseId(NonZeroU64);

impl DmaLeaseId {
    /// Decode an identity received from the stable ABI.
    pub fn from_abi(raw: u64) -> Option<Self> {
        NonZeroU64::new(raw).map(Self)
    }

    /// Encode this identity for the stable ABI.
    pub const fn into_abi(self) -> u64 {
        self.0.get()
    }

    /// Registry slot encoded in this identity.
    pub const fn slot(self) -> u32 {
        self.0.get() as u32
    }

    /// Generation encoded in this identity.
    pub const fn generation(self) -> u32 {
        (self.0.get() >> 32) as u32
    }

    /// Construct an identity from a registry slot and generation.
    pub fn from_parts(slot: u32, generation: u32) -> Option<Self> {
        if slot == 0 || generation == 0 {
            return None;
        }
        Self::from_abi((u64::from(generation) << 32) | u64::from(slot))
    }
}

impl fmt::Debug for DmaLeaseId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DmaLeaseId")
            .field("slot", &self.slot())
            .field("generation", &self.generation())
            .finish()
    }
}

/// Address in a device or IOMMU address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct DmaDeviceAddress(u64);

impl DmaDeviceAddress {
    /// Construct an address supplied by the registry or stable ABI boundary.
    pub const fn from_abi(raw: u64) -> Self {
        Self(raw)
    }

    /// Value to program into a device descriptor.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Checked byte offset within the same mapped allocation.
    pub fn checked_add(self, offset: usize) -> Option<Self> {
        let offset = u64::try_from(offset).ok()?;
        self.0.checked_add(offset).map(Self)
    }
}

/// Non-zero number of bytes in a DMA allocation or descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct DmaByteCount(NonZeroUsize);

impl DmaByteCount {
    /// Validate a byte count received at an allocation or ABI boundary.
    pub fn new(bytes: usize) -> Option<Self> {
        NonZeroUsize::new(bytes)
            .filter(|value| value.get() <= isize::MAX as usize)
            .map(Self)
    }

    /// Number of bytes.
    pub const fn get(self) -> usize {
        self.0.get()
    }
}

/// Direction of device access permitted by the mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DmaDirection {
    /// The device may read bytes prepared by the CPU.
    ToDevice,
    /// The device may write bytes later consumed by the CPU.
    FromDevice,
    /// The device may both read and write the allocation.
    Bidirectional,
}

/// Validated request for one registry-owned DMA transfer allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaAllocationRequest {
    byte_count: DmaByteCount,
    direction: DmaDirection,
}

impl DmaAllocationRequest {
    /// Validate a logical byte count and requested device access direction.
    pub fn new(byte_count: usize, direction: DmaDirection) -> Option<Self> {
        Some(Self {
            byte_count: DmaByteCount::new(byte_count)?,
            direction,
        })
    }

    /// Logical byte count requested by the caller.
    pub const fn byte_count(self) -> DmaByteCount {
        self.byte_count
    }

    /// Device access permitted by the resulting mapping.
    pub const fn direction(self) -> DmaDirection {
        self.direction
    }
}

/// Identity and generation of one hardware submission queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaQueueIdentity {
    device: PackedPciLocation,
    index: u16,
    generation: NonZeroU64,
}

impl DmaQueueIdentity {
    /// Validate a queue identity established by a driver queue owner.
    pub fn new(device: PackedPciLocation, index: u16, generation: u64) -> Option<Self> {
        if device.is_null() {
            return None;
        }
        Some(Self {
            device,
            index,
            generation: NonZeroU64::new(generation)?,
        })
    }

    /// Device that owns the queue.
    pub const fn device(self) -> PackedPciLocation {
        self.device
    }

    /// Driver-defined queue index.
    pub const fn index(self) -> u16 {
        self.index
    }

    /// Queue generation, changed whenever the queue is reset or replaced.
    pub const fn generation(self) -> u64 {
        self.generation.get()
    }
}

/// Borrowed descriptor data for one prepared DMA submission.
#[derive(Debug)]
pub struct DmaDescriptor<'lease> {
    lease_id: DmaLeaseId,
    device_address: DmaDeviceAddress,
    byte_count: DmaByteCount,
    queue: DmaQueueIdentity,
    _lease: PhantomData<&'lease PreparedDmaLease>,
}

impl DmaDescriptor<'_> {
    /// Allocation identity recorded beside a hardware descriptor.
    pub const fn lease_id(&self) -> DmaLeaseId {
        self.lease_id
    }

    /// Device-visible start address.
    pub const fn device_address(&self) -> DmaDeviceAddress {
        self.device_address
    }

    /// Mapped logical byte count.
    pub const fn byte_count(&self) -> DmaByteCount {
        self.byte_count
    }

    /// Queue generation for which this descriptor was prepared.
    pub const fn queue(&self) -> DmaQueueIdentity {
        self.queue
    }
}

/// Registry-visible state used when a capability is abandoned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaLeaseState {
    /// CPU access is permitted.
    CpuOwned,
    /// Cache preparation completed, but the device has not been notified.
    Prepared,
    /// The descriptor has crossed the device-acceptance boundary.
    InFlight,
    /// A validated completion was observed.
    Completed,
    /// The outcome or unmap completion is not known to be safe.
    Quarantined,
    /// Unmap failed; the mapping and allocation remain registry-owned.
    UnmapFailed,
    /// Device access was revoked by a validated reset.
    RevokedAfterReset,
}

/// Machine-readable failure returned by the registry authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaLeaseError {
    /// The identity no longer names the same registry generation.
    StaleLease,
    /// The caller does not own this allocation.
    ForeignOwner,
    /// The requested transition is invalid in the registry's current state.
    InvalidState,
    /// Device or queue identity did not match the submitted transfer.
    QueueMismatch,
    /// The operation is unavailable at this execution boundary.
    NotSupported,
    /// An IOMMU operation failed and the allocation was quarantined.
    IommuFailure,
    /// The authority violated its callback or state-transition contract.
    AuthorityViolation,
}

/// Kernel-owned implementation behind a DMA lease capability.
///
/// # Safety
///
/// An implementation must bind every method to one live registry generation.
/// `with_cpu_bytes` and `with_cpu_bytes_mut` may invoke their visitor exactly
/// once only while the registry state is `CpuOwned`; the slice must describe
/// the same initialized allocation for the duration of the call. Mutable visits
/// must be exclusive. Successful transitions must be linearizable. After a
/// successful `prepare`, `prepared_queue` must return exactly the queue passed
/// to that transition until it is aborted or accepted. A failed `close` or
/// `retry_close_after_reconcile` must retain the mapping and allocation in an
/// unmap-failed quarantine, and `abandon` must never free memory that a device
/// might still access.
pub unsafe trait DmaLeaseAuthority: Send + Sync {
    /// Identity of the bound registry generation.
    fn lease_id(&self) -> DmaLeaseId;

    /// Device-visible mapped address.
    fn device_address(&self) -> DmaDeviceAddress;

    /// Logical allocation length.
    fn byte_count(&self) -> DmaByteCount;

    /// Mapping direction.
    fn direction(&self) -> DmaDirection;

    /// Visit initialized bytes while CPU ownership is active.
    fn with_cpu_bytes(&self, visitor: &mut dyn FnMut(&[u8])) -> Result<(), DmaLeaseError>;

    /// Mutably visit initialized bytes while CPU ownership is active.
    fn with_cpu_bytes_mut(&self, visitor: &mut dyn FnMut(&mut [u8])) -> Result<(), DmaLeaseError>;

    /// Prepare cache and registry state before descriptor publication.
    fn prepare(&self, queue: DmaQueueIdentity) -> Result<(), DmaLeaseError>;

    /// Queue identity retained by the registry for the prepared transfer.
    fn prepared_queue(&self) -> Option<DmaQueueIdentity>;

    /// Cancel a prepared transfer before device acceptance.
    fn abort_prepared(&self) -> Result<(), DmaLeaseError>;

    /// Record that descriptor publication crossed the device-acceptance point.
    fn accept(&self) -> Result<(), DmaLeaseError>;

    /// Validate and record a hardware completion.
    fn complete(&self, queue: DmaQueueIdentity, lease: DmaLeaseId) -> Result<(), DmaLeaseError>;

    /// Return a validated completed transfer to CPU ownership.
    fn return_to_cpu(&self) -> Result<(), DmaLeaseError>;

    /// Quarantine an accepted transfer whose outcome is unknown.
    fn mark_outcome_unknown(&self) -> Result<(), DmaLeaseError>;

    /// Record device revocation after a validated reset.
    fn revoke_after_reset(
        &self,
        device: PackedPciLocation,
        reset_generation: u64,
    ) -> Result<(), DmaLeaseError>;

    /// Reconcile a quarantined or reset-revoked allocation after IOTLB invalidation.
    fn reconcile(
        &self,
        device: PackedPciLocation,
        reset_generation: u64,
    ) -> Result<(), DmaLeaseError>;

    /// Explicitly unmap and release a CPU-owned allocation.
    fn close(&self) -> Result<(), DmaLeaseError>;

    /// Retry final unmap after device reset and IOTLB reconciliation.
    fn retry_close_after_reconcile(
        &self,
        device: PackedPciLocation,
        reset_generation: u64,
    ) -> Result<(), DmaLeaseError>;

    /// Conservatively retain a capability that was dropped without finalization.
    fn abandon(&self, observed_state: DmaLeaseState);
}

struct LeaseCore {
    authority: Arc<dyn DmaLeaseAuthority>,
}

impl LeaseCore {
    fn new(authority: Arc<dyn DmaLeaseAuthority>) -> Self {
        Self { authority }
    }
}

impl fmt::Debug for LeaseCore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeaseCore")
            .field("lease_id", &self.authority.lease_id())
            .field("device_address", &self.authority.device_address())
            .field("byte_count", &self.authority.byte_count())
            .field("direction", &self.authority.direction())
            .finish()
    }
}

fn visit_cpu_bytes<R>(
    authority: &dyn DmaLeaseAuthority,
    operation: impl FnOnce(&[u8]) -> R,
) -> Result<R, DmaLeaseError> {
    let mut operation = Some(operation);
    let mut output = None;
    authority.with_cpu_bytes(&mut |bytes| {
        let operation = operation
            .take()
            .expect("DMA authority invoked read visitor more than once");
        output = Some(operation(bytes));
    })?;
    output.ok_or(DmaLeaseError::AuthorityViolation)
}

fn visit_cpu_bytes_mut<R>(
    authority: &dyn DmaLeaseAuthority,
    operation: impl FnOnce(&mut [u8]) -> R,
) -> Result<R, DmaLeaseError> {
    let mut operation = Some(operation);
    let mut output = None;
    authority.with_cpu_bytes_mut(&mut |bytes| {
        let operation = operation
            .take()
            .expect("DMA authority invoked mutable visitor more than once");
        output = Some(operation(bytes));
    })?;
    output.ok_or(DmaLeaseError::AuthorityViolation)
}

/// Error that retains the state capability when a transition fails.
#[derive(Debug)]
pub struct DmaTransitionError<State> {
    state: State,
    cause: DmaLeaseError,
}

impl<State> DmaTransitionError<State> {
    fn new(state: State, cause: DmaLeaseError) -> Self {
        Self { state, cause }
    }

    /// Failure reason.
    pub const fn cause(&self) -> DmaLeaseError {
        self.cause
    }

    /// Recover the unchanged state capability and failure reason.
    pub fn into_parts(self) -> (DmaLeaseError, State) {
        (self.cause, self.state)
    }
}

macro_rules! lease_state {
    ($name:ident, $state:expr) => {
        #[derive(Debug)]
        pub struct $name {
            core: Option<LeaseCore>,
            _not_sync: PhantomData<Cell<()>>,
        }

        impl $name {
            fn from_core(core: LeaseCore) -> Self {
                Self {
                    core: Some(core),
                    _not_sync: PhantomData,
                }
            }

            fn authority(&self) -> &dyn DmaLeaseAuthority {
                self.core
                    .as_ref()
                    .expect("live DMA state must retain its authority")
                    .authority
                    .as_ref()
            }

            fn take_core(&mut self) -> LeaseCore {
                self.core
                    .take()
                    .expect("DMA state transition may consume authority only once")
            }

            /// Registry lease identity.
            pub fn lease_id(&self) -> DmaLeaseId {
                self.authority().lease_id()
            }

            /// Logical allocation size.
            pub fn byte_count(&self) -> DmaByteCount {
                self.authority().byte_count()
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                if let Some(core) = self.core.take() {
                    core.authority.abandon($state);
                }
            }
        }
    };
}

lease_state!(CpuDmaLease, DmaLeaseState::CpuOwned);
lease_state!(PreparedDmaLease, DmaLeaseState::Prepared);
lease_state!(InFlightDmaLease, DmaLeaseState::InFlight);
lease_state!(CompletedDmaLease, DmaLeaseState::Completed);
lease_state!(QuarantinedDmaLease, DmaLeaseState::Quarantined);
lease_state!(UnmapFailedDmaLease, DmaLeaseState::UnmapFailed);
lease_state!(RevokedAfterResetDmaLease, DmaLeaseState::RevokedAfterReset);

impl CpuDmaLease {
    /// Bind a driver-facing capability to a kernel registry authority.
    pub fn from_authority(authority: Arc<dyn DmaLeaseAuthority>) -> Self {
        Self::from_core(LeaseCore::new(authority))
    }

    /// Mapping direction.
    pub fn direction(&self) -> DmaDirection {
        self.authority().direction()
    }

    /// Read the allocation without allowing the borrow to escape the registry visit.
    pub fn read<R>(&self, operation: impl FnOnce(&[u8]) -> R) -> Result<R, DmaLeaseError> {
        visit_cpu_bytes(self.authority(), operation)
    }

    /// Mutate the allocation without allowing the borrow to escape the registry visit.
    pub fn write<R>(&mut self, operation: impl FnOnce(&mut [u8]) -> R) -> Result<R, DmaLeaseError> {
        visit_cpu_bytes_mut(self.authority(), operation)
    }

    /// Copy bytes into the start of this allocation.
    pub fn copy_from_slice(&mut self, source: &[u8]) -> Result<(), DmaLeaseError> {
        self.write(|destination| {
            let destination = destination
                .get_mut(..source.len())
                .ok_or(DmaLeaseError::InvalidState)?;
            destination.copy_from_slice(source);
            Ok(())
        })?
    }

    /// Copy bytes from the start of this allocation.
    pub fn copy_to_slice(&self, destination: &mut [u8]) -> Result<(), DmaLeaseError> {
        self.read(|source| {
            let source = source
                .get(..destination.len())
                .ok_or(DmaLeaseError::InvalidState)?;
            destination.copy_from_slice(source);
            Ok(())
        })?
    }

    /// Prepare this allocation for descriptor publication on `queue`.
    pub fn prepare(
        mut self,
        queue: DmaQueueIdentity,
    ) -> Result<PreparedDmaLease, DmaTransitionError<Self>> {
        if let Err(cause) = self.authority().prepare(queue) {
            return Err(DmaTransitionError::new(self, cause));
        }
        Ok(PreparedDmaLease::from_core(self.take_core()))
    }

    /// Explicitly unmap and release this allocation.
    ///
    /// On failure the allocation is retained in quarantine and returned to the
    /// caller; it cannot be accessed or freed until reconciliation succeeds.
    pub fn close(mut self) -> Result<(), DmaCloseError> {
        if let Err(cause) = self.authority().close() {
            return Err(DmaCloseError {
                lease: UnmapFailedDmaLease::from_core(self.take_core()),
                cause,
            });
        }
        drop(self.take_core());
        Ok(())
    }
}

impl PreparedDmaLease {
    /// Descriptor data borrowed from this prepared capability.
    pub fn descriptor(&self) -> DmaDescriptor<'_> {
        let authority = self.authority();
        DmaDescriptor {
            lease_id: authority.lease_id(),
            device_address: authority.device_address(),
            byte_count: authority.byte_count(),
            queue: self.queue_identity(),
            _lease: PhantomData,
        }
    }

    fn queue_identity(&self) -> DmaQueueIdentity {
        // The authority validates the same queue again at acceptance and
        // completion. The prepared wrapper stores no parallel queue authority;
        // implementations return it through this registry query.
        self.authority()
            .prepared_queue()
            .expect("PreparedDmaLease authority must expose its prepared queue")
    }

    /// Abort before the device-acceptance boundary and recover CPU ownership.
    pub fn abort(mut self) -> Result<CpuDmaLease, DmaTransitionError<PreparedDmaLease>> {
        if let Err(cause) = self.authority().abort_prepared() {
            return Err(DmaTransitionError::new(self, cause));
        }
        Ok(CpuDmaLease::from_core(self.take_core()))
    }

    /// Record that descriptor publication and the device doorbell have crossed
    /// the hardware acceptance boundary.
    ///
    /// # Safety
    ///
    /// The caller must have published this lease's borrowed descriptor to the
    /// matching queue with the device-required ordering and rung the doorbell.
    /// After this call the device may access the allocation until a validated
    /// completion or reset revocation is observed.
    pub unsafe fn accept(
        mut self,
    ) -> Result<InFlightDmaLease, DmaTransitionError<PreparedDmaLease>> {
        if let Err(cause) = self.authority().accept() {
            return Err(DmaTransitionError::new(self, cause));
        }
        Ok(InFlightDmaLease::from_core(self.take_core()))
    }
}

/// Non-cloneable proof produced by a driver completion parser.
#[derive(Debug)]
pub struct DmaCompletionWitness {
    queue: DmaQueueIdentity,
    lease: DmaLeaseId,
}

impl DmaCompletionWitness {
    /// Construct a witness after validating one hardware completion entry.
    ///
    /// # Safety
    ///
    /// The caller must have read a completed queue entry using the device's
    /// required volatile and ordering rules, validated its tag/index, and bound
    /// it to exactly `lease` on `queue`. Constructing a witness from software
    /// intent or an unvalidated device bit pattern can re-enable CPU access
    /// while DMA is still active.
    pub unsafe fn from_validated_queue_entry(queue: DmaQueueIdentity, lease: DmaLeaseId) -> Self {
        Self { queue, lease }
    }
}

impl InFlightDmaLease {
    /// Consume a validated completion and record the completed state.
    pub fn complete(
        mut self,
        witness: DmaCompletionWitness,
    ) -> Result<CompletedDmaLease, DmaTransitionError<InFlightDmaLease>> {
        if let Err(cause) = self.authority().complete(witness.queue, witness.lease) {
            return Err(DmaTransitionError::new(self, cause));
        }
        Ok(CompletedDmaLease::from_core(self.take_core()))
    }

    /// Quarantine an accepted transfer when hardware outcome cannot be proven.
    pub fn mark_outcome_unknown(
        mut self,
    ) -> Result<QuarantinedDmaLease, DmaTransitionError<InFlightDmaLease>> {
        if let Err(cause) = self.authority().mark_outcome_unknown() {
            return Err(DmaTransitionError::new(self, cause));
        }
        Ok(QuarantinedDmaLease::from_core(self.take_core()))
    }

    /// Revoke device access after a validated device reset.
    pub fn revoke_after_reset(
        mut self,
        witness: DmaResetWitness,
    ) -> Result<RevokedAfterResetDmaLease, DmaTransitionError<InFlightDmaLease>> {
        if let Err(cause) = self
            .authority()
            .revoke_after_reset(witness.device, witness.generation.get())
        {
            return Err(DmaTransitionError::new(self, cause));
        }
        Ok(RevokedAfterResetDmaLease::from_core(self.take_core()))
    }
}

impl CompletedDmaLease {
    /// Perform completion-side cache synchronization and restore CPU access.
    pub fn return_to_cpu(mut self) -> Result<CpuDmaLease, DmaTransitionError<CompletedDmaLease>> {
        if let Err(cause) = self.authority().return_to_cpu() {
            return Err(DmaTransitionError::new(self, cause));
        }
        Ok(CpuDmaLease::from_core(self.take_core()))
    }
}

/// Non-cloneable proof that a device reset revoked old queue generations.
#[derive(Debug)]
pub struct DmaResetWitness {
    device: PackedPciLocation,
    generation: NonZeroU64,
}

impl DmaResetWitness {
    /// Construct a witness after completing the device-specific reset protocol.
    ///
    /// # Safety
    ///
    /// The caller must have stopped bus mastering or completed an equivalent
    /// device reset that makes every descriptor from older queue generations
    /// unreachable by the device.
    pub unsafe fn after_device_reset(device: PackedPciLocation, generation: u64) -> Option<Self> {
        if device.is_null() {
            return None;
        }
        Some(Self {
            device,
            generation: NonZeroU64::new(generation)?,
        })
    }
}

/// Non-cloneable proof that reset reconciliation also completed IOTLB invalidation.
#[derive(Debug)]
pub struct DmaReconcileWitness {
    device: PackedPciLocation,
    generation: NonZeroU64,
}

impl DmaReconcileWitness {
    /// Construct a witness after reset and IOTLB reconciliation complete.
    ///
    /// # Safety
    ///
    /// `generation` must name a completed reset for `device`; every stale IOVA
    /// translation for allocations being reconciled must have been removed and
    /// its invalidation completion observed before constructing this witness.
    pub unsafe fn after_iotlb_invalidation(
        device: PackedPciLocation,
        generation: u64,
    ) -> Option<Self> {
        if device.is_null() {
            return None;
        }
        Some(Self {
            device,
            generation: NonZeroU64::new(generation)?,
        })
    }
}

impl QuarantinedDmaLease {
    /// Record reset revocation for a transfer whose completion outcome was unknown.
    pub fn revoke_after_reset(
        mut self,
        witness: DmaResetWitness,
    ) -> Result<RevokedAfterResetDmaLease, DmaTransitionError<QuarantinedDmaLease>> {
        if let Err(cause) = self
            .authority()
            .revoke_after_reset(witness.device, witness.generation.get())
        {
            return Err(DmaTransitionError::new(self, cause));
        }
        Ok(RevokedAfterResetDmaLease::from_core(self.take_core()))
    }

    /// Reconcile an uncertain allocation and restore CPU ownership.
    pub fn reconcile(
        mut self,
        witness: DmaReconcileWitness,
    ) -> Result<CpuDmaLease, DmaTransitionError<QuarantinedDmaLease>> {
        if let Err(cause) = self
            .authority()
            .reconcile(witness.device, witness.generation.get())
        {
            return Err(DmaTransitionError::new(self, cause));
        }
        Ok(CpuDmaLease::from_core(self.take_core()))
    }
}

impl RevokedAfterResetDmaLease {
    /// Finish IOTLB reconciliation and restore CPU ownership.
    pub fn reconcile(
        mut self,
        witness: DmaReconcileWitness,
    ) -> Result<CpuDmaLease, DmaTransitionError<RevokedAfterResetDmaLease>> {
        if let Err(cause) = self
            .authority()
            .reconcile(witness.device, witness.generation.get())
        {
            return Err(DmaTransitionError::new(self, cause));
        }
        Ok(CpuDmaLease::from_core(self.take_core()))
    }
}

impl UnmapFailedDmaLease {
    /// Retry the final unmap after reset and IOTLB reconciliation.
    ///
    /// A repeated failure retains the same allocation in unmap-failed
    /// quarantine. Successful completion consumes and releases it; CPU access
    /// is never restored through this path.
    pub fn retry_close(mut self, witness: DmaReconcileWitness) -> Result<(), DmaCloseError> {
        if let Err(cause) = self
            .authority()
            .retry_close_after_reconcile(witness.device, witness.generation.get())
        {
            return Err(DmaCloseError {
                lease: UnmapFailedDmaLease::from_core(self.take_core()),
                cause,
            });
        }
        drop(self.take_core());
        Ok(())
    }
}

/// Explicit close failure retaining the quarantined allocation capability.
#[derive(Debug)]
pub struct DmaCloseError {
    lease: UnmapFailedDmaLease,
    cause: DmaLeaseError,
}

impl DmaCloseError {
    /// Failure reason.
    pub const fn cause(&self) -> DmaLeaseError {
        self.cause
    }

    /// Recover the quarantined allocation and failure reason.
    pub fn into_parts(self) -> (DmaLeaseError, UnmapFailedDmaLease) {
        (self.cause, self.lease)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};
    use spin::Mutex;

    #[derive(Debug)]
    struct FakeState {
        state: DmaLeaseState,
        queue: Option<DmaQueueIdentity>,
        released: bool,
    }

    struct FakeAuthority {
        lease: DmaLeaseId,
        device: PackedPciLocation,
        bytes: Mutex<[u8; 8]>,
        state: Mutex<FakeState>,
        fail_close: AtomicBool,
    }

    impl FakeAuthority {
        fn new() -> Self {
            Self {
                lease: DmaLeaseId::from_parts(7, 3).expect("valid fake lease"),
                device: PackedPciLocation::new(0, 0, 1, 0),
                bytes: Mutex::new([0; 8]),
                state: Mutex::new(FakeState {
                    state: DmaLeaseState::CpuOwned,
                    queue: None,
                    released: false,
                }),
                fail_close: AtomicBool::new(false),
            }
        }

        fn require_state(&self, expected: DmaLeaseState) -> Result<(), DmaLeaseError> {
            if self.state.lock().state == expected {
                Ok(())
            } else {
                Err(DmaLeaseError::InvalidState)
            }
        }
    }

    // SAFETY: The fake serializes state and byte access with independent
    // mutexes, invokes visitors exactly once in CpuOwned, retains bytes on
    // failed close, and implements the same linear transitions as the registry.
    unsafe impl DmaLeaseAuthority for FakeAuthority {
        fn lease_id(&self) -> DmaLeaseId {
            self.lease
        }

        fn device_address(&self) -> DmaDeviceAddress {
            DmaDeviceAddress::from_abi(0x9000)
        }

        fn byte_count(&self) -> DmaByteCount {
            DmaByteCount::new(8).expect("non-zero fake allocation")
        }

        fn direction(&self) -> DmaDirection {
            DmaDirection::Bidirectional
        }

        fn with_cpu_bytes(&self, visitor: &mut dyn FnMut(&[u8])) -> Result<(), DmaLeaseError> {
            self.require_state(DmaLeaseState::CpuOwned)?;
            visitor(&*self.bytes.lock());
            Ok(())
        }

        fn with_cpu_bytes_mut(
            &self,
            visitor: &mut dyn FnMut(&mut [u8]),
        ) -> Result<(), DmaLeaseError> {
            self.require_state(DmaLeaseState::CpuOwned)?;
            visitor(&mut *self.bytes.lock());
            Ok(())
        }

        fn prepare(&self, queue: DmaQueueIdentity) -> Result<(), DmaLeaseError> {
            if queue.device() != self.device {
                return Err(DmaLeaseError::QueueMismatch);
            }
            let mut state = self.state.lock();
            if state.state != DmaLeaseState::CpuOwned {
                return Err(DmaLeaseError::InvalidState);
            }
            state.state = DmaLeaseState::Prepared;
            state.queue = Some(queue);
            Ok(())
        }

        fn prepared_queue(&self) -> Option<DmaQueueIdentity> {
            let state = self.state.lock();
            (state.state == DmaLeaseState::Prepared)
                .then_some(state.queue)
                .flatten()
        }

        fn abort_prepared(&self) -> Result<(), DmaLeaseError> {
            let mut state = self.state.lock();
            if state.state != DmaLeaseState::Prepared {
                return Err(DmaLeaseError::InvalidState);
            }
            state.state = DmaLeaseState::CpuOwned;
            state.queue = None;
            Ok(())
        }

        fn accept(&self) -> Result<(), DmaLeaseError> {
            let mut state = self.state.lock();
            if state.state != DmaLeaseState::Prepared {
                return Err(DmaLeaseError::InvalidState);
            }
            state.state = DmaLeaseState::InFlight;
            Ok(())
        }

        fn complete(
            &self,
            queue: DmaQueueIdentity,
            lease: DmaLeaseId,
        ) -> Result<(), DmaLeaseError> {
            let mut state = self.state.lock();
            if state.state != DmaLeaseState::InFlight {
                return Err(DmaLeaseError::InvalidState);
            }
            if state.queue != Some(queue) || lease != self.lease {
                return Err(DmaLeaseError::QueueMismatch);
            }
            state.state = DmaLeaseState::Completed;
            Ok(())
        }

        fn return_to_cpu(&self) -> Result<(), DmaLeaseError> {
            let mut state = self.state.lock();
            if state.state != DmaLeaseState::Completed {
                return Err(DmaLeaseError::InvalidState);
            }
            state.state = DmaLeaseState::CpuOwned;
            state.queue = None;
            Ok(())
        }

        fn mark_outcome_unknown(&self) -> Result<(), DmaLeaseError> {
            let mut state = self.state.lock();
            if state.state != DmaLeaseState::InFlight {
                return Err(DmaLeaseError::InvalidState);
            }
            state.state = DmaLeaseState::Quarantined;
            Ok(())
        }

        fn revoke_after_reset(
            &self,
            device: PackedPciLocation,
            reset_generation: u64,
        ) -> Result<(), DmaLeaseError> {
            let mut state = self.state.lock();
            if device != self.device
                || reset_generation <= state.queue.ok_or(DmaLeaseError::InvalidState)?.generation()
            {
                return Err(DmaLeaseError::QueueMismatch);
            }
            if !matches!(
                state.state,
                DmaLeaseState::InFlight | DmaLeaseState::Quarantined
            ) {
                return Err(DmaLeaseError::InvalidState);
            }
            state.state = DmaLeaseState::RevokedAfterReset;
            Ok(())
        }

        fn reconcile(
            &self,
            device: PackedPciLocation,
            reset_generation: u64,
        ) -> Result<(), DmaLeaseError> {
            let mut state = self.state.lock();
            if state.state != DmaLeaseState::RevokedAfterReset
                || device != self.device
                || reset_generation <= state.queue.ok_or(DmaLeaseError::InvalidState)?.generation()
            {
                return Err(DmaLeaseError::InvalidState);
            }
            state.state = DmaLeaseState::CpuOwned;
            state.queue = None;
            Ok(())
        }

        fn close(&self) -> Result<(), DmaLeaseError> {
            let mut state = self.state.lock();
            if state.state != DmaLeaseState::CpuOwned {
                return Err(DmaLeaseError::InvalidState);
            }
            if self.fail_close.load(Ordering::Acquire) {
                state.state = DmaLeaseState::UnmapFailed;
                return Err(DmaLeaseError::IommuFailure);
            }
            state.released = true;
            Ok(())
        }

        fn retry_close_after_reconcile(
            &self,
            device: PackedPciLocation,
            _reset_generation: u64,
        ) -> Result<(), DmaLeaseError> {
            let mut state = self.state.lock();
            if state.state != DmaLeaseState::UnmapFailed || device != self.device {
                return Err(DmaLeaseError::InvalidState);
            }
            if self.fail_close.load(Ordering::Acquire) {
                return Err(DmaLeaseError::IommuFailure);
            }
            state.released = true;
            Ok(())
        }

        fn abandon(&self, _observed_state: DmaLeaseState) {
            let mut state = self.state.lock();
            if !state.released && state.state != DmaLeaseState::UnmapFailed {
                state.state = DmaLeaseState::Quarantined;
            }
        }
    }

    #[test]
    fn lease_identity_rejects_missing_slot_or_generation() {
        assert!(DmaLeaseId::from_parts(0, 1).is_none());
        assert!(DmaLeaseId::from_parts(1, 0).is_none());
        let lease = DmaLeaseId::from_parts(4, 9).expect("valid lease");
        assert_eq!(lease.slot(), 4);
        assert_eq!(lease.generation(), 9);
        assert_eq!(DmaLeaseId::from_abi(lease.into_abi()), Some(lease));
    }

    #[test]
    fn validated_completion_is_bound_to_lease_and_queue_generation() {
        let authority = Arc::new(FakeAuthority::new());
        let mut cpu = CpuDmaLease::from_authority(authority.clone());
        cpu.copy_from_slice(b"dma-test").expect("CPU write");
        let queue = DmaQueueIdentity::new(authority.device, 2, 4).expect("queue identity");
        let prepared = cpu.prepare(queue).expect("prepare");
        assert_eq!(prepared.descriptor().lease_id(), authority.lease);
        assert_eq!(prepared.descriptor().device_address().get(), 0x9000);
        // SAFETY: the fake queue publication is the device-acceptance boundary
        // for this pure state-machine test.
        let in_flight = unsafe { prepared.accept() }.expect("accept");

        let wrong_lease = DmaLeaseId::from_parts(8, 3).expect("wrong lease");
        // SAFETY: the witness models a validated entry for a different lease;
        // the API must reject it without consuming the real in-flight owner.
        let wrong = unsafe { DmaCompletionWitness::from_validated_queue_entry(queue, wrong_lease) };
        let (cause, in_flight) = in_flight
            .complete(wrong)
            .expect_err("mismatched lease must be rejected")
            .into_parts();
        assert_eq!(cause, DmaLeaseError::QueueMismatch);

        // SAFETY: this witness names the exact fake completion entry.
        let completion =
            unsafe { DmaCompletionWitness::from_validated_queue_entry(queue, authority.lease) };
        let completed = in_flight.complete(completion).expect("completion");
        let cpu = completed.return_to_cpu().expect("CPU ownership");
        assert_eq!(cpu.read(|bytes| bytes == b"dma-test"), Ok(true));
        cpu.close().expect("observed close");
        assert!(authority.state.lock().released);
    }

    #[test]
    fn close_failure_returns_quarantined_owner() {
        let authority = Arc::new(FakeAuthority::new());
        authority.fail_close.store(true, Ordering::Release);
        let cpu = CpuDmaLease::from_authority(authority.clone());

        let (cause, unmap_failed) = cpu
            .close()
            .expect_err("failed unmap must retain owner")
            .into_parts();
        assert_eq!(cause, DmaLeaseError::IommuFailure);
        assert_eq!(authority.state.lock().state, DmaLeaseState::UnmapFailed);

        authority.fail_close.store(false, Ordering::Release);
        // SAFETY: the fake models completed device reset and IOTLB invalidation.
        let reconciled =
            unsafe { DmaReconcileWitness::after_iotlb_invalidation(authority.device, 1) }
                .expect("reconcile witness");
        unmap_failed
            .retry_close(reconciled)
            .expect("reconciled close");
        assert!(authority.state.lock().released);
    }

    #[test]
    fn unknown_outcome_requires_reset_and_iotlb_reconciliation() {
        let authority = Arc::new(FakeAuthority::new());
        let cpu = CpuDmaLease::from_authority(authority.clone());
        let queue = DmaQueueIdentity::new(authority.device, 1, 10).expect("queue identity");
        let prepared = cpu.prepare(queue).expect("prepare");
        // SAFETY: modeled descriptor publication and doorbell acceptance.
        let in_flight = unsafe { prepared.accept() }.expect("accept");
        let quarantined = in_flight
            .mark_outcome_unknown()
            .expect("unknown outcome quarantine");
        // SAFETY: modeled device reset revokes generation 10.
        let reset = unsafe { DmaResetWitness::after_device_reset(authority.device, 11) }
            .expect("reset witness");
        let revoked = quarantined
            .revoke_after_reset(reset)
            .expect("reset revocation");
        // SAFETY: modeled IOTLB invalidation completion for the same reset.
        let reconciled =
            unsafe { DmaReconcileWitness::after_iotlb_invalidation(authority.device, 11) }
                .expect("reconcile witness");
        let cpu = revoked.reconcile(reconciled).expect("reconcile");
        cpu.close().expect("close reconciled allocation");
    }
}
