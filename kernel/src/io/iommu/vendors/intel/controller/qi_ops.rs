// ============================================================================
// kernel/src/io/iommu/vendors/intel/controller/qi_ops.rs
// ============================================================================

//! Queued Invalidation Operations
//!
//! This module contains QI-related methods for `IommuController` via `InvalidationOps` trait.

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{Ordering, fence};
use core::task::{Context, Poll};

use super::IommuController;
use super::utils::IommuUtils;
use crate::io::iommu::types::IommuError;
use crate::io::iommu::vendors::intel::qi::{
    InvalidationQueue, InvalidationQueueEntry, WaitCompletion, WaitNotification,
};
use crate::io::iommu::vendors::intel::registers::{fsts_bits, ics_bits};

const QI_FAULTS: u32 = fsts_bits::FSTS_IQE | fsts_bits::FSTS_ICE | fsts_bits::FSTS_ITE;

fn submit_invalidation_locked(
    controller: &IommuController,
    iq: &mut InvalidationQueue,
    entry: InvalidationQueueEntry,
) -> Result<(), IommuError> {
    // Security: Check for existing hardware faults before submitting new commands.
    // If the queue is in an error state (IQE/ICE/ITE), it will not process new entries.
    let fsts = controller.registers.fault_status().read();
    if (fsts & QI_FAULTS) != 0 {
        log::error!(
            "[IOMMU][QI] Cannot submit: hardware fault detected in FSTS: {:#x}",
            fsts
        );
        return Err(IommuError::HardwareError);
    }

    if iq.is_full() {
        iq.record_full_check();
        let head = controller.registers.queue_head().read();
        iq.record_head_refresh();
        iq.refresh_head(head)?;
        if iq.is_full() {
            iq.record_wait();
            let cached_head = iq.cached_head_offset();
            if let Err(e) = controller.wait_for_condition(
                || controller.registers.queue_head().read() != cached_head,
                100_000, // 100ms
                true,
            ) {
                iq.record_wait_timeout();
                return Err(e);
            }
            let head = controller.registers.queue_head().read();
            iq.record_head_refresh();
            iq.refresh_head(head)?;
            if iq.is_full() {
                iq.record_wait_timeout();
                return Err(IommuError::Timeout);
            }
        }
    }

    iq.submit(entry);
    iq.record_submit();
    fence(Ordering::Release);
    controller.registers.queue_tail().write(iq.tail_offset());
    Ok(())
}

pub trait InvalidationOps {
    /// Check if Queued Invalidation is enabled
    fn is_queued_invalidation_enabled(&self) -> bool;

    /// Submit a queued invalidation request
    fn submit_invalidation(&self, entry: InvalidationQueueEntry) -> Result<(), IommuError>;

    /// Submit a global IOTLB invalidation via queued invalidation
    fn qi_invalidate_iotlb_global(&self) -> Result<(), IommuError>;

    /// Submit a domain IOTLB invalidation via queued invalidation
    fn qi_invalidate_iotlb_domain(&self, domain_id: u16) -> Result<(), IommuError>;

    /// Submit a global context-cache invalidation via queued invalidation
    fn qi_invalidate_context_global(&self) -> Result<(), IommuError>;

    /// Submit a global IEC invalidation via queued invalidation
    fn qi_invalidate_iec_global(&self) -> Result<(), IommuError>;

    /// Submit an indexed IEC invalidation via queued invalidation
    fn qi_invalidate_iec_indexed(&self, index: u16) -> Result<(), IommuError>;

    /// Submit a Device-TLB invalidation via queued invalidation
    fn qi_invalidate_device_tlb_all(&self, source_id: u16) -> Result<(), IommuError>;

    /// Submit a wait descriptor and synchronize
    fn qi_wait_sync(&self) -> Result<(), IommuError>;

    /// Submit a wait descriptor and wait asynchronously for completion
    fn qi_wait_async<'a>(&'a self) -> InvalidationWaiter<'a>;

    /// Wake pending async invalidation waiter (called from interrupt handler)
    fn wake_invalidation_waiter(&self);
}

impl InvalidationOps for IommuController {
    #[inline]
    fn is_queued_invalidation_enabled(&self) -> bool {
        self.qi_enabled.load(Ordering::Acquire)
    }

    fn submit_invalidation(&self, entry: InvalidationQueueEntry) -> Result<(), IommuError> {
        let mut guard = match self.invalidation_queue.lock() {
            Ok(g) => g,
            Err(_) => {
                log::error!("[IOMMU] invalidation_queue lock poisoned");
                return Err(IommuError::HardwareError);
            }
        };

        let iq = guard.as_mut().ok_or(IommuError::NotPresent)?;
        submit_invalidation_locked(self, iq, entry)
    }

    #[inline]
    fn qi_invalidate_iotlb_global(&self) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::iotlb_invalidate_global();
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_iotlb_domain(&self, domain_id: u16) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::iotlb_invalidate_domain(domain_id);
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_context_global(&self) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::context_cache_invalidate_global();
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_iec_global(&self) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::iec_invalidate_global();
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_iec_indexed(&self, index: u16) -> Result<(), IommuError> {
        // Use mask 0 for exact index match (one entry)
        let entry = InvalidationQueueEntry::iec_invalidate(1, index, 0);
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_device_tlb_all(&self, source_id: u16) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::device_tlb_invalidate_all(source_id);
        self.submit_invalidation(entry)
    }

    fn qi_wait_sync(&self) -> Result<(), IommuError> {
        let wait = self.publish_qi_wait(WaitNotification::Poll)?;
        self.wait_for_condition(|| wait.completed().is_some(), 100_000, true)?;
        wait.completed().unwrap_or(Err(IommuError::Timeout))
    }

    fn qi_wait_async(&self) -> InvalidationWaiter<'_> {
        InvalidationWaiter(self.publish_qi_wait(WaitNotification::Interrupt))
    }

    fn wake_invalidation_waiter(&self) {
        if !self.is_queued_invalidation_enabled() {
            return;
        }
        let mut status = self.registers.invalidation_completion_status();
        if status.read() & ics_bits::IWC != 0 {
            status.write(ics_bits::IWC);
            // Flush status writes from completions that coalesced with IWC
            // before it was cleared, including those after the first read.
            let _committed = status.read();
        }
        self.pending_waiters.wake_all_from_isr();
    }
}

impl IommuController {
    fn publish_qi_wait(&self, notify: WaitNotification) -> Result<PendingWait<'_>, IommuError> {
        let mut guard = self
            .invalidation_queue
            .lock()
            .map_err(|_| IommuError::HardwareError)?;
        let iq = guard.as_mut().ok_or(IommuError::NotPresent)?;
        let completion = iq.submit_wait(notify, |iq, entry| {
            submit_invalidation_locked(self, iq, entry)
        })?;
        Ok(PendingWait {
            controller: self,
            completion,
        })
    }
}

struct PendingWait<'a> {
    controller: &'a IommuController,
    completion: WaitCompletion,
}

impl PendingWait<'_> {
    fn completed(&self) -> Option<Result<(), IommuError>> {
        let fsts = self.controller.registers.fault_status().read();
        if fsts & QI_FAULTS != 0 {
            log::error!("[IOMMU][QI] Wait failed: hardware fault in FSTS: {fsts:#x}");
            return Some(Err(IommuError::HardwareError));
        }
        // SAFETY: publication took place in this borrowed controller's queue.
        // The controller retains the backing and never replaces the queue.
        unsafe { self.completion.is_complete() }.then_some(Ok(()))
    }
}

pub(crate) struct InvalidationWaiter<'a>(Result<PendingWait<'a>, IommuError>);

impl Future for InvalidationWaiter<'_> {
    type Output = Result<(), IommuError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let wait = match &self.0 {
            Ok(wait) => wait,
            Err(error) => return Poll::Ready(Err(*error)),
        };
        if let Some(result) = wait.completed() {
            return Poll::Ready(result);
        }
        wait.controller.pending_waiters.register(cx.waker());
        // Close the race between the first observation and registration.
        wait.completed().map_or(Poll::Pending, Poll::Ready)
    }
}
