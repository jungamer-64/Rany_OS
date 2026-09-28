//! CPU-owned bootstrap allocations only. Publication transfers each capability
//! out of this inventory; active command/ring owners cannot be closed here.

use super::{BootstrapDmaPlan, BootstrapDmaPurpose, BootstrapDmaRequirement};
use alloc::collections::TryReserveError;
use alloc::vec::Vec;
use kernel_api::dma::{
    CpuDmaLease, DmaAllocationRequest, DmaByteCount, DmaDirection, DmaLeaseError, DmaLeaseId,
    DmaReconcileWitness, UnmapFailedDmaLease,
};
use kernel_api::error::KapiError;

#[derive(Debug)]
pub enum BootstrapAllocationCause {
    Metadata(TryReserveError),
    Allocation {
        requirement: BootstrapDmaRequirement,
        cause: KapiError,
    },
    AuthorityViolation {
        requirement: BootstrapDmaRequirement,
        actual_bytes: DmaByteCount,
        actual_direction: DmaDirection,
    },
}

/// Failed acquisition retains the successfully acquired prefix, including an
/// allocation rejected for a registry contract violation. Nothing was published.
#[derive(Debug)]
#[must_use = "observe the cause and explicitly retire the retained allocations"]
pub struct BootstrapAllocationFailure {
    cause: BootstrapAllocationCause,
    inventory: BootstrapDmaInventory,
}

impl BootstrapAllocationFailure {
    pub fn cause(&self) -> &BootstrapAllocationCause {
        &self.cause
    }

    pub fn into_parts(self) -> (BootstrapAllocationCause, BootstrapDmaInventory) {
        (self.cause, self.inventory)
    }
}

#[derive(Debug)]
struct BootstrapAllocation {
    purpose: BootstrapDmaPurpose,
    lease: CpuDmaLease,
}

/// Linear capabilities, not backing-memory ownership. The resource registry
/// retains the allocations and mappings. Drop abandons capabilities to that
/// registry; it is not successful release or a replacement for explicit close.
/// There are no CPU addresses, device addresses, or independent reclaimers here.
#[derive(Debug)]
#[must_use = "transfer the leases to protocol owners or explicitly close the inventory"]
pub struct BootstrapDmaInventory {
    allocations: Vec<BootstrapAllocation>,
}

impl BootstrapDmaInventory {
    /// The callback is allocation authority already attenuated to one device.
    /// Metadata is reserved before acquiring the first DMA allocation.
    ///
    /// # Errors
    /// Reports metadata exhaustion separately from the allocator's original
    /// cause. Every acquired capability remains in the returned failure owner.
    pub fn allocate(
        plan: &BootstrapDmaPlan,
        mut allocate: impl FnMut(DmaAllocationRequest) -> Result<CpuDmaLease, KapiError>,
    ) -> Result<Self, BootstrapAllocationFailure> {
        let mut inventory = Self {
            allocations: Vec::new(),
        };
        if let Err(cause) = inventory
            .allocations
            .try_reserve_exact(plan.allocation_count())
        {
            return Err(BootstrapAllocationFailure {
                cause: BootstrapAllocationCause::Metadata(cause),
                inventory,
            });
        }
        for requirement in plan.requirements() {
            let lease = match allocate(requirement.request()) {
                Ok(lease) => lease,
                Err(cause) => {
                    return Err(BootstrapAllocationFailure {
                        cause: BootstrapAllocationCause::Allocation { requirement, cause },
                        inventory,
                    });
                }
            };
            let actual_bytes = lease.byte_count();
            let actual_direction = lease.direction();
            inventory.allocations.push(BootstrapAllocation {
                purpose: requirement.purpose(),
                lease,
            });
            if actual_bytes != requirement.request().byte_count()
                || actual_direction != requirement.request().direction()
            {
                return Err(BootstrapAllocationFailure {
                    cause: BootstrapAllocationCause::AuthorityViolation {
                        requirement,
                        actual_bytes,
                        actual_direction,
                    },
                    inventory,
                });
            }
        }
        Ok(inventory)
    }

    pub fn remaining_count(&self) -> usize {
        self.allocations.len()
    }

    /// Consumes the allocation's only inventory capability. The receiving
    /// command/ring owner must prepare/activate it before device publication;
    /// the inventory cannot release that allocation after this transfer.
    pub fn take(&mut self, purpose: BootstrapDmaPurpose) -> Option<CpuDmaLease> {
        let index = self
            .allocations
            .iter()
            .position(|allocation| allocation.purpose == purpose)?;
        Some(self.allocations.swap_remove(index).lease)
    }

    /// # Errors
    /// Stops at the first failed unmap, preserving the failed quarantine lease,
    /// all unattempted allocations, and the exact successful release count.
    pub fn close(self) -> Result<(), BootstrapRetirementFailure> {
        self.close_after(0)
    }

    fn close_after(mut self, mut released: usize) -> Result<(), BootstrapRetirementFailure> {
        // LOOP_PROOF: mode=condition; reason=Each iteration removes one allocation or returns the failed owner, and pop returns None when this finite inventory is empty;
        while let Some(allocation) = self.allocations.pop() {
            if let Err(error) = allocation.lease.close() {
                let (cause, failed) = error.into_parts();
                return Err(BootstrapRetirementFailure {
                    cause,
                    purpose: allocation.purpose,
                    failed,
                    remaining: self,
                    released,
                });
            }
            released += 1;
        }
        Ok(())
    }
}

/// A failed close is not a CPU owner. Ordinary close/retry is unavailable;
/// resumption requires the registry's reset and IOTLB reconciliation witness.
#[derive(Debug)]
#[must_use = "retain quarantine until reset and IOTLB reconciliation permits release"]
pub struct BootstrapRetirementFailure {
    cause: DmaLeaseError,
    purpose: BootstrapDmaPurpose,
    failed: UnmapFailedDmaLease,
    remaining: BootstrapDmaInventory,
    released: usize,
}

impl BootstrapRetirementFailure {
    pub const fn cause(&self) -> DmaLeaseError {
        self.cause
    }

    pub const fn purpose(&self) -> BootstrapDmaPurpose {
        self.purpose
    }

    pub fn lease_id(&self) -> DmaLeaseId {
        self.failed.lease_id()
    }

    pub const fn released_count(&self) -> usize {
        self.released
    }

    pub fn retained_count(&self) -> usize {
        self.remaining.remaining_count() + 1
    }

    /// # Errors
    /// A rejected witness or repeated unmap failure retains this same owner.
    /// Later failures preserve cumulative release progress, never CPU access.
    pub fn reconcile(self, witness: DmaReconcileWitness) -> Result<(), Self> {
        let Self {
            purpose,
            failed,
            remaining,
            released,
            ..
        } = self;
        match failed.retry_close(witness) {
            Ok(()) => remaining.close_after(released + 1),
            Err(error) => {
                let (cause, failed) = error.into_parts();
                Err(Self {
                    cause,
                    purpose,
                    failed,
                    remaining,
                    released,
                })
            }
        }
    }
}
