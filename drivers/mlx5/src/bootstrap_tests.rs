//! Component tests use production lease constructors and a private, Rust-owned
//! authority model. The model rejects every hardware publication transition;
//! there is no raw memory backing constructor or simulated hardware completion.

#![deny(unsafe_code)]

use crate::bootstrap::{
    BootstrapAllocationCause, BootstrapDmaInventory, BootstrapDmaPlan, BootstrapDmaPurpose,
    Mlx5QueueProfile,
};
use alloc::{sync::Arc, vec, vec::Vec};
use kernel_api::dma::{
    CpuDmaLease, DmaAccessWidth, DmaAllocationRequest, DmaByteCount, DmaCompletionWitness,
    DmaDeviceAddress, DmaDirection, DmaLeaseAuthority, DmaLeaseError, DmaLeaseId, DmaLeaseState,
    DmaQueueIdentity, DmaQuiesceWitness, DmaReconcileWitness, DmaResetWitness,
};
use kernel_api::error::KapiError;
use spin::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Cpu,
    UnmapFailed,
    Closed,
}

struct AllocationState {
    state: State,
    bytes: Vec<u8>,
    fail_close: bool,
    close_attempts: usize,
    abandoned: Vec<DmaLeaseState>,
}

struct Allocation {
    id: DmaLeaseId,
    request: DmaAllocationRequest,
    inner: Mutex<AllocationState>,
}

#[expect(
    unsafe_code,
    reason = "the private authority model owns initialized Rust bytes and rejects all device publication"
)]
// SAFETY: each allocation has a unique fixed identity and exact initialized
// extent. All visits and close transitions use the same mutex. Shared/device
// transitions never succeed. Failed close retains backing and prohibits visits;
// abandon records the linear capability's state without reclaiming any backing.
unsafe impl DmaLeaseAuthority for Allocation {
    fn lease_id(&self) -> DmaLeaseId {
        self.id
    }
    fn device_address(&self) -> DmaDeviceAddress {
        DmaDeviceAddress::from_abi(0)
    }
    fn byte_count(&self) -> DmaByteCount {
        self.request.byte_count()
    }
    fn direction(&self) -> DmaDirection {
        self.request.direction()
    }

    fn with_cpu_bytes(&self, visitor: &mut dyn FnMut(&[u8])) -> Result<(), DmaLeaseError> {
        let inner = self.inner.lock();
        if inner.state != State::Cpu {
            return Err(DmaLeaseError::InvalidState);
        }
        visitor(&inner.bytes);
        Ok(())
    }
    fn with_cpu_bytes_mut(&self, visitor: &mut dyn FnMut(&mut [u8])) -> Result<(), DmaLeaseError> {
        let mut inner = self.inner.lock();
        if inner.state != State::Cpu {
            return Err(DmaLeaseError::InvalidState);
        }
        visitor(&mut inner.bytes);
        Ok(())
    }
    fn close(&self) -> Result<(), DmaLeaseError> {
        let mut inner = self.inner.lock();
        if inner.state != State::Cpu {
            return Err(DmaLeaseError::InvalidState);
        }
        inner.close_attempts += 1;
        if inner.fail_close {
            inner.state = State::UnmapFailed;
            return Err(DmaLeaseError::IommuFailure);
        }
        inner.state = State::Closed;
        inner.bytes = Vec::new();
        Ok(())
    }
    fn abandon(&self, observed: DmaLeaseState) {
        self.inner.lock().abandoned.push(observed);
    }

    fn prepare(&self, _queue: DmaQueueIdentity) -> Result<(), DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }
    fn prepared_queue(&self) -> Result<DmaQueueIdentity, DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }
    fn abort_prepared(&self) -> Result<(), DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }
    fn arm(&self) -> Result<(), DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }
    fn complete(&self, _witness: DmaCompletionWitness) -> Result<(), DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }
    fn return_to_cpu(&self) -> Result<(), DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }
    fn mark_outcome_unknown(&self) -> Result<(), DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }
    fn revoke_after_reset(&self, _witness: DmaResetWitness) -> Result<(), DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }
    fn reconcile(&self, _witness: DmaReconcileWitness) -> Result<(), DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }
    fn prepare_shared(&self, _queue: DmaQueueIdentity) -> Result<(), DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }
    fn activate_shared(&self) -> Result<(), DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }
    fn read_shared_word(
        &self,
        _offset: usize,
        _width: DmaAccessWidth,
    ) -> Result<u64, DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }
    fn write_shared_word(
        &self,
        _offset: usize,
        _width: DmaAccessWidth,
        _value: u64,
    ) -> Result<(), DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }
    fn quiesce_shared(&self, _witness: DmaQuiesceWitness) -> Result<(), DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }
    fn retry_close_after_reconcile(
        &self,
        _witness: DmaReconcileWitness,
    ) -> Result<(), DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }
}

#[derive(Default)]
struct Registry {
    allocations: Vec<Arc<Allocation>>,
}

impl Registry {
    fn allocate(&mut self, request: DmaAllocationRequest) -> CpuDmaLease {
        let slot = u32::try_from(self.allocations.len() + 1).unwrap();
        let allocation = Arc::new(Allocation {
            id: DmaLeaseId::from_parts(slot, 1).unwrap(),
            request,
            inner: Mutex::new(AllocationState {
                state: State::Cpu,
                bytes: vec![0; request.byte_count().get()],
                fail_close: false,
                close_attempts: 0,
                abandoned: Vec::new(),
            }),
        });
        self.allocations.push(Arc::clone(&allocation));
        CpuDmaLease::from_authority(allocation)
    }
}

#[test]
fn initial_allocation_failure_preserves_original_cause_and_empty_owner() {
    let plan = BootstrapDmaPlan::new(Mlx5QueueProfile::default()).unwrap();
    let failure =
        BootstrapDmaInventory::allocate(&plan, |_| Err(KapiError::PermissionDenied)).unwrap_err();
    assert!(
        matches!(failure.cause(), BootstrapAllocationCause::Allocation {
        requirement, cause: KapiError::PermissionDenied,
    } if requirement.purpose() == BootstrapDmaPurpose::CommandQueue)
    );
    let (_, inventory) = failure.into_parts();
    assert_eq!(inventory.remaining_count(), 0);
    inventory.close().unwrap();
}

#[test]
fn partial_allocation_failure_keeps_every_acquired_lease_until_explicit_close() {
    let plan = BootstrapDmaPlan::new(Mlx5QueueProfile::default()).unwrap();
    let mut registry = Registry::default();
    let failure = BootstrapDmaInventory::allocate(&plan, |request| {
        if registry.allocations.len() == 5 {
            return Err(KapiError::ResourceExhausted);
        }
        Ok(registry.allocate(request))
    })
    .unwrap_err();
    let (cause, inventory) = failure.into_parts();
    assert!(matches!(
        cause,
        BootstrapAllocationCause::Allocation {
            cause: KapiError::ResourceExhausted,
            ..
        }
    ));
    assert_eq!(inventory.remaining_count(), 5);
    for allocation in &registry.allocations {
        let inner = allocation.inner.lock();
        assert_eq!(inner.state, State::Cpu);
        assert_eq!(inner.close_attempts, 0);
        assert!(!inner.bytes.is_empty());
    }
    inventory.close().unwrap();
    for allocation in &registry.allocations {
        let inner = allocation.inner.lock();
        assert_eq!(inner.state, State::Closed);
        assert_eq!(inner.close_attempts, 1);
        assert!(inner.bytes.is_empty());
    }
}

#[test]
fn wrong_registry_extent_or_permissions_retains_even_the_rejected_allocation() {
    let plan = BootstrapDmaPlan::new(Mlx5QueueProfile::default()).unwrap();
    for request in [
        DmaAllocationRequest::new(1, DmaDirection::Bidirectional).unwrap(),
        DmaAllocationRequest::new(crate::defs::MLX5_PAGE_SIZE, DmaDirection::ToDevice).unwrap(),
    ] {
        let mut registry = Registry::default();
        let failure =
            BootstrapDmaInventory::allocate(&plan, |_| Ok(registry.allocate(request))).unwrap_err();
        let (cause, inventory) = failure.into_parts();
        assert!(matches!(
            cause,
            BootstrapAllocationCause::AuthorityViolation { .. }
        ));
        assert_eq!(inventory.remaining_count(), 1);
        assert_eq!(registry.allocations[0].inner.lock().close_attempts, 0);
        inventory.close().unwrap();
        assert_eq!(registry.allocations[0].inner.lock().state, State::Closed);
    }
}

#[test]
fn lease_transfer_is_unique_and_removes_inventory_reclamation_authority() {
    let plan = BootstrapDmaPlan::new(Mlx5QueueProfile::default()).unwrap();
    let mut registry = Registry::default();
    let mut inventory =
        BootstrapDmaInventory::allocate(&plan, |request| Ok(registry.allocate(request))).unwrap();
    let lease = inventory.take(BootstrapDmaPurpose::CommandInput).unwrap();
    assert!(inventory.take(BootstrapDmaPurpose::CommandInput).is_none());
    assert_eq!(inventory.remaining_count(), plan.allocation_count() - 1);
    inventory.close().unwrap();
    assert_eq!(registry.allocations[1].inner.lock().state, State::Cpu);
    lease.close().unwrap();
    assert_eq!(registry.allocations[1].inner.lock().state, State::Closed);
}

#[test]
fn failed_unmap_preserves_quarantine_unattempted_prefix_and_release_progress() {
    let plan = BootstrapDmaPlan::new(Mlx5QueueProfile::default()).unwrap();
    let mut registry = Registry::default();
    let inventory =
        BootstrapDmaInventory::allocate(&plan, |request| Ok(registry.allocate(request))).unwrap();
    let failed_index = 4;
    registry.allocations[failed_index].inner.lock().fail_close = true;
    let failure = inventory.close().unwrap_err();
    assert_eq!(failure.cause(), DmaLeaseError::IommuFailure);
    assert_eq!(
        failure.purpose(),
        plan.requirements().nth(failed_index).unwrap().purpose()
    );
    assert_eq!(failure.lease_id(), registry.allocations[failed_index].id);
    assert_eq!(
        failure.released_count(),
        plan.allocation_count() - failed_index - 1
    );
    assert_eq!(failure.retained_count(), failed_index + 1);
    let mut called = false;
    assert_eq!(
        registry.allocations[failed_index].with_cpu_bytes_mut(&mut |_| called = true),
        Err(DmaLeaseError::InvalidState)
    );
    assert!(!called);
    drop(failure);
    for (index, allocation) in registry.allocations.iter().enumerate() {
        let inner = allocation.inner.lock();
        if index < failed_index {
            assert_eq!(inner.state, State::Cpu);
            assert_eq!(inner.close_attempts, 0);
            assert_eq!(inner.abandoned, [DmaLeaseState::CpuOwned]);
            assert!(!inner.bytes.is_empty());
        } else if index == failed_index {
            assert_eq!(inner.state, State::UnmapFailed);
            assert_eq!(inner.close_attempts, 1);
            assert_eq!(inner.abandoned, [DmaLeaseState::UnmapFailed]);
            assert!(!inner.bytes.is_empty());
        } else {
            assert_eq!(inner.state, State::Closed);
            assert_eq!(inner.close_attempts, 1);
            assert!(inner.bytes.is_empty());
        }
    }
}

#[test]
fn dropping_unpublished_inventory_is_not_successful_release() {
    let plan = BootstrapDmaPlan::new(Mlx5QueueProfile::default()).unwrap();
    let mut registry = Registry::default();
    let inventory =
        BootstrapDmaInventory::allocate(&plan, |request| Ok(registry.allocate(request))).unwrap();
    drop(inventory);
    for allocation in &registry.allocations {
        let inner = allocation.inner.lock();
        assert_eq!(inner.state, State::Cpu);
        assert_eq!(inner.close_attempts, 0);
        assert!(!inner.bytes.is_empty());
        assert_eq!(inner.abandoned, [DmaLeaseState::CpuOwned]);
    }
}
