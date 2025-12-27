// ============================================================================
// kernel/src/io/iommu/intel/controller/qi_ops.rs
// ============================================================================

//! Queued Invalidation Operations
//!
//! This module contains QI-related methods for `IommuController` via `InvalidationOps` trait.

use core::sync::atomic::Ordering;

use super::utils::IommuUtils;
use super::{InvalidationWaiter, IommuController};
use crate::io::iommu::types::IommuError;
use crate::io::iommu::domain::{
    InvalidateFlags, InvalidateKind, InvalidateRequest, IommuInvalidator,
};
use crate::io::iommu::intel::qi::{InvalidationQueue, InvalidationQueueEntry};
use crate::io::iommu::intel::registers::regs; // for wait_for_condition

fn submit_invalidation_locked(
    controller: &IommuController,
    iq: &mut InvalidationQueue,
    entry: InvalidationQueueEntry,
) -> Result<u64, IommuError> {
    if iq.is_full() {
        iq.record_full_check();
        let head = (controller.read64(regs::IQH) >> 4) as usize;
        iq.record_head_refresh();
        iq.update_head(head);
        if iq.is_full() {
            iq.record_wait();
            let cached_head = iq.cached_head() as u64;
            if let Err(e) = controller.wait_for_condition(
                || (controller.read64(regs::IQH) >> 4) != cached_head,
                100_000, // 100ms
                true,
            ) {
                iq.record_wait_timeout();
                return Err(e);
            }
            let head = (controller.read64(regs::IQH) >> 4) as usize;
            iq.record_head_refresh();
            iq.update_head(head);
            if iq.is_full() {
                iq.record_wait_timeout();
                return Err(IommuError::Timeout);
            }
        }
    }

    iq.submit(entry);
    iq.record_submit();
    let tail = iq.tail() as u64; // Tail is in entry units
    controller.write64(regs::IQT, tail << 4);
    Ok(tail)
}

pub trait InvalidationOps {
    /// Check if Queued Invalidation is enabled
    fn is_queued_invalidation_enabled(&self) -> bool;

    /// Submit a queued invalidation request
    fn submit_invalidation(&self, entry: InvalidationQueueEntry) -> Result<(), IommuError>;

    /// Submit a global IOTLB invalidation via queued invalidation
    fn qi_invalidate_iotlb_global(&self, drain: bool) -> Result<(), IommuError>;

    /// Submit a domain IOTLB invalidation via queued invalidation
    fn qi_invalidate_iotlb_domain(&self, domain_id: u16, drain: bool) -> Result<(), IommuError>;

    /// Submit a page-selective IOTLB invalidation via queued invalidation
    fn qi_invalidate_iotlb_page(
        &self,
        domain_id: u16,
        addr: u64,
        drain: bool,
    ) -> Result<(), IommuError>;

    /// Submit a global context-cache invalidation via queued invalidation
    fn qi_invalidate_context_global(&self) -> Result<(), IommuError>;

    /// Submit a global IEC invalidation via queued invalidation
    fn qi_invalidate_iec_global(&self) -> Result<(), IommuError>;

    /// Submit a Device-TLB invalidation via queued invalidation
    fn qi_invalidate_device_tlb(&self, source_id: u16, domain_id: u16) -> Result<(), IommuError>;

    /// Submit a page-selective Device-TLB invalidation
    fn qi_invalidate_device_tlb_page(
        &self,
        source_id: u16,
        domain_id: u16,
        iova: u64,
        size: u8,
    ) -> Result<(), IommuError>;

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
        // Acquire the invalidation queue
        let mut guard = match self.invalidation_queue.lock() {
            Ok(g) => g,
            Err(_) => {
                log::error!(
                    "[IOMMU] invalidation_queue lock poisoned while submitting invalidation"
                );
                return Err(IommuError::HardwareError);
            }
        };

        let iq = guard.as_mut().ok_or(IommuError::NotPresent)?;
        let _ = submit_invalidation_locked(self, iq, entry)?;
        Ok(())
    }

    #[inline]
    fn qi_invalidate_iotlb_global(&self, drain: bool) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::iotlb_invalidate_global(drain);
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_iotlb_domain(&self, domain_id: u16, drain: bool) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::iotlb_invalidate_domain(domain_id, drain);
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_iotlb_page(
        &self,
        domain_id: u16,
        addr: u64,
        drain: bool,
    ) -> Result<(), IommuError> {
        // AM (Address Mask) = 0 for 4KB page
        let entry = InvalidationQueueEntry::iotlb_invalidate(3, domain_id, drain, addr);
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
    fn qi_invalidate_device_tlb(&self, source_id: u16, domain_id: u16) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::device_tlb_invalidate_device(source_id, domain_id);
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_device_tlb_page(
        &self,
        source_id: u16,
        domain_id: u16,
        iova: u64,
        size: u8,
    ) -> Result<(), IommuError> {
        let entry =
            InvalidationQueueEntry::device_tlb_invalidate_page(source_id, domain_id, iova, size);
        self.submit_invalidation(entry)
    }

    fn qi_wait_sync(&self) -> Result<(), IommuError> {
        let mut guard = match self.invalidation_queue.lock() {
            Ok(g) => g,
            Err(_) => {
                log::error!("[IOMMU] invalidation_queue lock poisoned during qi_wait_sync");
                return Err(IommuError::HardwareError);
            }
        };

        let expected_tail = {
            let iq = guard.as_mut().ok_or(IommuError::NotPresent)?;
            let entry = iq.wait_entry();
            submit_invalidation_locked(self, iq, entry)?
        };

        // Wait for hardware head to catch up (all descriptors processed)
        // This is a critical wait, use longer timeout
        self.wait_for_condition(
            || (self.read64(regs::IQH) >> 4) == expected_tail,
            100_000, // 100ms
            true,    // Safe to yield
        )
    }

    fn qi_wait_async<'a>(&'a self) -> InvalidationWaiter<'a> {
        // Submit wait descriptor first. Treat poisoned lock as a hardware error
        // and return a waiter which will immediately resolve to Err.
        let submit_result = match self.invalidation_queue.lock() {
            Ok(mut guard) => {
                if let Some(iq) = guard.as_mut() {
                    let entry = iq.wait_entry();
                    submit_invalidation_locked(self, iq, entry)
                } else {
                    Err(IommuError::NotPresent)
                }
            }
            Err(_) => {
                log::error!("[IOMMU] invalidation_queue lock poisoned during qi_wait_async");
                Err(IommuError::HardwareError)
            }
        };

        InvalidationWaiter {
            controller: self,
            submit_result,
        }
    }

    fn wake_invalidation_waiter(&self) {
        // ISR-safe: enqueue deferred wake for ALL waiting tasks
        self.pending_waiters.wake_all_from_isr();
    }
}

impl IommuInvalidator for IommuController {
    // Note: This impl block now calls methods from InvalidationOps
    // Since IommuController implements InvalidationOps, `self.method()` works.

    fn process_invalidations(&self, requests: &[InvalidateRequest]) -> Result<(), IommuError> {
        if requests.is_empty() {
            return Ok(());
        }

        // Determine if we should use ATS (Device-TLB) invalidation
        let any_ats = requests
            .iter()
            .any(|r| r.flags.contains(InvalidateFlags::ATS_AWARE));
        let drain = requests.iter().any(|r| {
            r.flags
                .intersects(InvalidateFlags::DRAIN_READ | InvalidateFlags::DRAIN_WRITE)
        });

        for req in requests {
            match req.kind {
                InvalidateKind::Pages {
                    start_iova,
                    bytes: _,
                } => {
                    // Page-selective IOTLB invalidation
                    if self.is_queued_invalidation_enabled() {
                        self.qi_invalidate_iotlb_page(req.domain_id, start_iova, drain)?;
                        // If ATS-aware, also invalidate Device-TLB (would need source_id)
                        if any_ats {
                            log::trace!(
                                "[IOMMU] ATS Page invalidation requested but source_id not available"
                            );
                        }
                    } else {
                        // Fall back to domain invalidation without QI
                        unsafe { self.invalidate_iotlb_direct(req.domain_id) };
                    }
                }
                InvalidateKind::Domain => {
                    // Domain-wide IOTLB invalidation
                    if self.is_queued_invalidation_enabled() {
                        self.qi_invalidate_iotlb_domain(req.domain_id, drain)?;
                    } else {
                        unsafe { self.invalidate_iotlb_direct(req.domain_id) };
                    }
                }
                InvalidateKind::Global => {
                    // Global IOTLB invalidation
                    if self.is_queued_invalidation_enabled() {
                        self.qi_invalidate_iotlb_global(drain)?;
                    } else {
                        unsafe { self.invalidate_iotlb_global() };
                    }
                }
                InvalidateKind::Context { source_id } => {
                    // Context cache invalidation for device
                    if self.is_queued_invalidation_enabled() {
                        // Note: qi_invalidate_context_device would be ideal but we have global
                        self.qi_invalidate_context_global()?;
                    }
                    log::trace!(
                        "[IOMMU] Context invalidation for source_id {:04x}",
                        source_id
                    );
                }
                InvalidateKind::Iec { global, index } => {
                    // Interrupt Entry Cache invalidation
                    if global {
                        self.qi_invalidate_iec_global()?;
                    } else {
                        log::trace!("[IOMMU] Indexed IEC invalidation for index {}", index);
                        self.qi_invalidate_iec_global()?; // Fall back to global
                    }
                }
            }
        }

        // Perform synchronous wait to ensure completion
        if self.is_queued_invalidation_enabled() {
            self.qi_wait_sync()?;
        }

        Ok(())
    }

    /// Optimized async invalidation using QI wait
    fn invalidate_async<'a>(
        &'a self,
        request: InvalidateRequest,
    ) -> core::pin::Pin<
        alloc::boxed::Box<dyn core::future::Future<Output = Result<(), IommuError>> + Send + 'a>,
    >
    where
        Self: Sync,
    {
        use alloc::boxed::Box;
        use core::pin::Pin;

        // Submit the invalidation request first (sync part)
        let drain = request
            .flags
            .intersects(InvalidateFlags::DRAIN_READ | InvalidateFlags::DRAIN_WRITE);

        let submit_result: Result<(), IommuError> = match request.kind {
            InvalidateKind::Pages {
                start_iova,
                bytes: _,
            } => {
                if self.is_queued_invalidation_enabled() {
                    self.qi_invalidate_iotlb_page(request.domain_id, start_iova, drain)
                } else {
                    unsafe { self.invalidate_iotlb_direct(request.domain_id) };
                    Ok(())
                }
            }
            InvalidateKind::Domain => {
                if self.is_queued_invalidation_enabled() {
                    self.qi_invalidate_iotlb_domain(request.domain_id, drain)
                } else {
                    unsafe { self.invalidate_iotlb_direct(request.domain_id) };
                    Ok(())
                }
            }
            InvalidateKind::Global => {
                if self.is_queued_invalidation_enabled() {
                    self.qi_invalidate_iotlb_global(drain)
                } else {
                    unsafe { self.invalidate_iotlb_global() };
                    Ok(())
                }
            }
            InvalidateKind::Context { source_id: _ } => {
                if self.is_queued_invalidation_enabled() {
                    self.qi_invalidate_context_global()
                } else {
                    Ok(()) // No non-QI context invalidation
                }
            }
            InvalidateKind::Iec {
                global: _,
                index: _,
            } => self.qi_invalidate_iec_global(),
        };

        // If submission failed, return error immediately
        if let Err(e) = submit_result {
            return Box::pin(async move { Err(e) });
        }

        // If QI is enabled, use async wait; otherwise we're done
        if self.is_queued_invalidation_enabled() {
            let waiter = self.qi_wait_async();
            Box::pin(async move { waiter.await })
        } else {
            Box::pin(async { Ok(()) })
        }
    }
}
