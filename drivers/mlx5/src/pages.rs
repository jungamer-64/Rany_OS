//! Firmware page leases. The registry owns every allocation; this owner retains
//! the linear capabilities across page supply, firmware use and fallible close.
//! No CPU pointer, independent allocation table or manual Send/Sync is present.

#![deny(unsafe_code)]

use crate::error::{Mlx5Error, Mlx5Result};
use alloc::vec::Vec;
use kernel_api::dma::{
    CompletedDmaLease, CpuDmaLease, DmaCompletionWitness, DmaDeviceAddress, DmaLeaseError,
    DmaQueueIdentity, InFlightDmaLease, PreparedDmaLease, QuarantinedDmaLease, UnmapFailedDmaLease,
};
use kernel_api::error::KapiError;

mod response;
use response::PAGE_BYTES;
pub(crate) use response::{MAX_RETURNED_PAGES, ReturnedPages};

/// A failed operation's partial publication is retained with the page owner.
/// `unknown` pages must not be resupplied or returned to CPU access; they need
/// device reset and IOTLB reconciliation, not a repeated MANAGE_PAGES give.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PageSupplyFailure {
    pub(crate) cause: Mlx5Error,
    pub(crate) supplied: u32,
    pub(crate) unknown: u32,
}

enum PageLease {
    Cpu(CpuDmaLease),
    Prepared(PreparedDmaLease),
    InFlight(InFlightDmaLease),
    Returned(InFlightDmaLease),
    Quarantined(QuarantinedDmaLease),
    QuarantineFailed {
        cause: DmaLeaseError,
        lease: InFlightDmaLease,
    },
    Completed(CompletedDmaLease),
    UnmapFailed {
        cause: DmaLeaseError,
        lease: UnmapFailedDmaLease,
    },
    Closed,
}

struct FirmwarePage {
    function: u16,
    address: Option<DmaDeviceAddress>,
    // None exists only during an exclusive, synchronous transition. Every
    // success/error arm restores a capability before returning to its caller.
    lease: Option<PageLease>,
}

/// One command-queue generation's pinned firmware working memory.
/// A failed supply closes admission and keeps both the progress outcome and all
/// capabilities. Destruction abandons them to the registry, never deallocates.
pub(crate) struct FirmwarePages {
    queue: DmaQueueIdentity,
    pages: Vec<FirmwarePage>,
    supply_failure: Option<PageSupplyFailure>,
}

impl FirmwarePages {
    pub(crate) fn new(queue: DmaQueueIdentity) -> Self {
        Self {
            queue,
            pages: Vec::new(),
            supply_failure: None,
        }
    }

    /// Reserve and prepare each bounded batch before publication. Errors retain
    /// every successfully allocated page and the exact partial supply outcome.
    /// The callback must perform at most one firmware command per invocation.
    ///
    /// # Errors
    /// Returns the original cause; `supply_failure` on this same owner records
    /// accepted/uncertain progress. Failed admission cannot be reopened by retry.
    pub(crate) fn supply(
        &mut self,
        function: u16,
        count: u32,
        mut allocate: impl FnMut() -> Result<CpuDmaLease, KapiError>,
        mut publish: impl FnMut(&[u64]) -> Mlx5Result<()>,
    ) -> Mlx5Result<()> {
        if let Some(failure) = self.supply_failure {
            return Err(failure.cause);
        }
        let mut supplied = 0;
        // LOOP_PROOF: mode=bounded; reason=Each successful batch increases supplied by at least one and never beyond count, every failure returns;
        while supplied < count {
            let batch_count = (count - supplied).min(MAX_RETURNED_PAGES as u32) as usize;
            let start = self.pages.len();
            let result = self.prepare_batch(function, batch_count, &mut allocate);
            if let Err(cause) = result {
                self.supply_failure = Some(PageSupplyFailure {
                    cause,
                    supplied,
                    unknown: 0,
                });
                return Err(cause);
            }
            let mut addresses = [0; MAX_RETURNED_PAGES];
            for (index, page) in self.pages[start..].iter().enumerate() {
                addresses[index] = page.address.ok_or(Mlx5Error::Internal)?.get();
            }
            if let Err(cause) = self.arm_batch(start) {
                self.quarantine_batch(start);
                self.supply_failure = Some(PageSupplyFailure {
                    cause,
                    supplied,
                    unknown: batch_count as u32,
                });
                return Err(cause);
            }
            if let Err(cause) = publish(&addresses[..batch_count]) {
                self.quarantine_batch(start);
                self.supply_failure = Some(PageSupplyFailure {
                    cause,
                    supplied,
                    unknown: batch_count as u32,
                });
                return Err(cause);
            }
            supplied += batch_count as u32;
        }
        Ok(())
    }

    fn prepare_batch(
        &mut self,
        function: u16,
        count: usize,
        allocate: &mut impl FnMut() -> Result<CpuDmaLease, KapiError>,
    ) -> Mlx5Result<()> {
        self.pages
            .try_reserve(count)
            .map_err(|_| Mlx5Error::NoResources)?;
        for _ in 0..count {
            let lease = allocate().map_err(Mlx5Error::PageAllocation)?;
            self.pages.push(FirmwarePage {
                function,
                address: None,
                lease: Some(PageLease::Cpu(lease)),
            });
            let page = self.pages.last_mut().ok_or(Mlx5Error::Internal)?;
            let Some(PageLease::Cpu(mut lease)) = page.lease.take() else {
                return Err(Mlx5Error::Internal);
            };
            if let Err(cause) = lease.write(|bytes| bytes.fill(0)) {
                page.lease = Some(PageLease::Cpu(lease));
                return Err(Mlx5Error::DmaLease(cause));
            }
            match lease.prepare(self.queue) {
                Ok(prepared) => {
                    let descriptor = prepared.descriptor();
                    let address = match descriptor {
                        Ok(descriptor)
                            if descriptor.byte_count().get() == PAGE_BYTES
                                && descriptor.device_address().get() != 0
                                && descriptor
                                    .device_address()
                                    .get()
                                    .is_multiple_of(PAGE_BYTES as u64) =>
                        {
                            Ok(descriptor.device_address())
                        }
                        Ok(_) => Err(DmaLeaseError::InvalidRange),
                        Err(cause) => Err(cause),
                    };
                    page.lease = Some(PageLease::Prepared(prepared));
                    page.address = Some(address.map_err(Mlx5Error::DmaLease)?);
                }
                Err(error) => {
                    let (cause, lease) = error.into_parts();
                    page.lease = Some(PageLease::Cpu(lease));
                    return Err(Mlx5Error::DmaLease(cause));
                }
            }
        }
        Ok(())
    }

    fn arm_batch(&mut self, start: usize) -> Mlx5Result<()> {
        for page in &mut self.pages[start..] {
            let Some(PageLease::Prepared(lease)) = page.lease.take() else {
                return Err(Mlx5Error::Internal);
            };
            match lease.arm() {
                Ok(lease) => page.lease = Some(PageLease::InFlight(lease)),
                Err(error) => {
                    let (cause, lease) = error.into_parts();
                    page.lease = Some(PageLease::Prepared(lease));
                    return Err(Mlx5Error::DmaLease(cause));
                }
            }
        }
        Ok(())
    }

    fn quarantine_batch(&mut self, start: usize) {
        for page in &mut self.pages[start..] {
            let lease = page.lease.take();
            page.lease = match lease {
                Some(PageLease::InFlight(lease)) => Some(match lease.mark_outcome_unknown() {
                    Ok(lease) => PageLease::Quarantined(lease),
                    // A failed quarantine transition still retains InFlight;
                    // no CPU access/free/reuse is granted by either state.
                    Err(error) => {
                        let (cause, lease) = error.into_parts();
                        PageLease::QuarantineFailed { cause, lease }
                    }
                }),
                other => other,
            };
        }
    }

    /// Bind a complete, current MANAGE_PAGES return to exact registry leases.
    /// Validation of the entire PAS list precedes every completion transition.
    ///
    /// # Safety
    /// `returned` must come from a successful, ordered hardware completion on
    /// this owner's live command queue, for `function`, after all listed pages
    /// were given. Firmware must have relinquished every listed page. The
    /// response cannot be replayed or copied from software intent/stale RAM.
    ///
    /// # Errors
    /// Rejects foreign/duplicate/stale returns without releasing a prefix.
    /// Transition/close failure retains completed or unmap-failed ownership.
    #[expect(
        unsafe_code,
        reason = "firmware page return is an external hardware fact, not a numeric address proof"
    )]
    pub(crate) unsafe fn accept_return(
        &mut self,
        function: u16,
        returned: ReturnedPages,
    ) -> Mlx5Result<usize> {
        returned
            .validate_membership(|address| {
                self.pages.iter().any(|page| {
                    page.function == function
                        && page.address.is_some_and(|value| value.get() == address)
                        && matches!(page.lease, Some(PageLease::InFlight(_)))
                })
            })
            .map_err(|_| Mlx5Error::InvalidResponse)?;
        for address in returned.addresses() {
            let page = self
                .pages
                .iter_mut()
                .find(|page| {
                    page.function == function
                        && page.address.is_some_and(|value| value.get() == *address)
                        && matches!(page.lease, Some(PageLease::InFlight(_)))
                })
                .ok_or(Mlx5Error::Internal)?;
            let Some(PageLease::InFlight(lease)) = page.lease.take() else {
                return Err(Mlx5Error::Internal);
            };
            page.lease = Some(PageLease::Returned(lease));
        }
        self.close_returned()?;
        Ok(returned.addresses().len())
    }

    /// Retry cache synchronization for returned pages, then explicitly close.
    /// Never retries UnmapFailed without reset/IOTLB reconciliation.
    ///
    /// # Errors
    /// Keeps every failed finalization capability in this owner.
    pub(crate) fn close_returned(&mut self) -> Mlx5Result<()> {
        for page in &mut self.pages {
            if matches!(page.lease, Some(PageLease::Returned(_))) {
                let Some(PageLease::Returned(lease)) = page.lease.take() else {
                    return Err(Mlx5Error::Internal);
                };
                // SAFETY: Returned is established only by accept_return after
                // full-response validation. It retains the one current receipt
                // across fallible registry transitions, without replaying it.
                #[expect(
                    unsafe_code,
                    reason = "the private Returned state owns a validated hardware page-return receipt"
                )]
                let witness = unsafe {
                    DmaCompletionWitness::from_validated_queue_entry(self.queue, lease.lease_id())
                };
                match lease.complete(witness) {
                    Ok(lease) => page.lease = Some(PageLease::Completed(lease)),
                    Err(error) => {
                        let (cause, lease) = error.into_parts();
                        page.lease = Some(PageLease::Returned(lease));
                        return Err(Mlx5Error::DmaLease(cause));
                    }
                }
            }
            if matches!(page.lease, Some(PageLease::Completed(_))) {
                let Some(PageLease::Completed(lease)) = page.lease.take() else {
                    return Err(Mlx5Error::Internal);
                };
                match lease.return_to_cpu() {
                    Ok(lease) => page.lease = Some(PageLease::Cpu(lease)),
                    Err(error) => {
                        let (cause, lease) = error.into_parts();
                        page.lease = Some(PageLease::Completed(lease));
                        return Err(Mlx5Error::DmaLease(cause));
                    }
                }
            }
            if matches!(page.lease, Some(PageLease::Cpu(_))) {
                let Some(PageLease::Cpu(lease)) = page.lease.take() else {
                    return Err(Mlx5Error::Internal);
                };
                match lease.close() {
                    Ok(()) => page.lease = Some(PageLease::Closed),
                    Err(error) => {
                        let (cause, lease) = error.into_parts();
                        page.lease = Some(PageLease::UnmapFailed { cause, lease });
                        return Err(Mlx5Error::DmaLease(cause));
                    }
                }
            }
        }
        self.pages
            .retain(|page| !matches!(page.lease, Some(PageLease::Closed)));
        Ok(())
    }

    /// Close unpublished pages too; uncertain/unmap-failed pages require a
    /// separate reset/IOTLB reconciliation boundary and cannot finish here.
    ///
    /// # Errors
    /// Retains every unreconciled capability rather than reporting shutdown.
    pub(crate) fn finish(&mut self) -> Mlx5Result<()> {
        for page in &mut self.pages {
            if matches!(page.lease, Some(PageLease::Prepared(_))) {
                let Some(PageLease::Prepared(lease)) = page.lease.take() else {
                    return Err(Mlx5Error::Internal);
                };
                match lease.abort() {
                    Ok(lease) => page.lease = Some(PageLease::Cpu(lease)),
                    Err(error) => {
                        let (cause, lease) = error.into_parts();
                        page.lease = Some(PageLease::Prepared(lease));
                        return Err(Mlx5Error::DmaLease(cause));
                    }
                }
            }
        }
        self.close_returned()?;
        if !self.pages.is_empty() {
            if let Some(failure) = self.supply_failure {
                log::error!(target: "mlx5", "Incomplete firmware page supply: accepted={} unknown={} cause={:?}",
                    failure.supplied, failure.unknown, failure.cause);
            }
        }
        if let Some(page) = self.pages.first() {
            match &page.lease {
                Some(PageLease::Quarantined(lease)) => {
                    log::error!(target: "mlx5", "Firmware page {:?} requires reset reconciliation", lease.lease_id());
                    return Err(Mlx5Error::DmaLease(DmaLeaseError::InvalidState));
                }
                Some(PageLease::UnmapFailed { cause, lease }) => {
                    log::error!(target: "mlx5", "Firmware page {:?} retains failed unmap", lease.lease_id());
                    return Err(Mlx5Error::DmaLease(*cause));
                }
                Some(PageLease::QuarantineFailed { cause, lease }) => {
                    log::error!(target: "mlx5", "Firmware page {:?} retains failed quarantine", lease.lease_id());
                    return Err(Mlx5Error::DmaLease(*cause));
                }
                _ => return Err(Mlx5Error::DmaLease(DmaLeaseError::InvalidState)),
            }
        }
        Ok(())
    }

    pub(crate) fn next_reclaim(&self) -> Option<(u16, u32)> {
        let function = self
            .pages
            .iter()
            .find(|page| matches!(page.lease, Some(PageLease::InFlight(_))))?
            .function;
        let count = self
            .pages
            .iter()
            .filter(|page| {
                page.function == function && matches!(page.lease, Some(PageLease::InFlight(_)))
            })
            .take(MAX_RETURNED_PAGES)
            .count();
        Some((function, count as u32))
    }
}
