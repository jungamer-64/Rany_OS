// ============================================================================
// kernel/src/io/iommu/backends/intel/controller/qi_ops.rs
// ============================================================================

//! Queued Invalidation Operations
//!
//! This module contains QI-related methods for `IommuController` via `InvalidationOps` trait.

use core::sync::atomic::Ordering;

use super::utils::IommuUtils;
use super::{InvalidationWaiter, IommuController};
use crate::io::iommu::types::IommuError;
use crate::io::iommu::core::domain::{
    InvalidateFlags, InvalidateKind, InvalidateRequest, IommuInvalidator,
};
use crate::io::iommu::backends::intel::qi::{InvalidationQueue, InvalidationQueueEntry};
use crate::io::iommu::backends::intel::registers::regs;

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
    fn qi_invalidate_iotlb_global(&self) -> Result<(), IommuError>;

    /// Submit a domain IOTLB invalidation via queued invalidation
    fn qi_invalidate_iotlb_domain(&self, domain_id: u16) -> Result<(), IommuError>;

    /// Submit a page-selective IOTLB invalidation via queued invalidation
    fn qi_invalidate_iotlb_page(
        &self,
        domain_id: u16,
        addr: u64,
        am: u8,
    ) -> Result<(), IommuError>;

    /// Submit a global context-cache invalidation via queued invalidation
    fn qi_invalidate_context_global(&self) -> Result<(), IommuError>;

    /// Submit a device-selective context-cache invalidation via queued invalidation
    fn qi_invalidate_context_device(&self, source_id: u16, domain_id: u16) -> Result<(), IommuError>;

    /// Submit a global IEC invalidation via queued invalidation
    fn qi_invalidate_iec_global(&self) -> Result<(), IommuError>;

    /// Submit an indexed IEC invalidation via queued invalidation
    fn qi_invalidate_iec_indexed(&self, index: u16) -> Result<(), IommuError>;

    /// Submit a Device-TLB invalidation via queued invalidation
    fn qi_invalidate_device_tlb_all(&self, source_id: u16) -> Result<(), IommuError>;

    /// Submit a range-selective Device-TLB invalidation
    fn qi_invalidate_device_tlb_range(
        &self,
        source_id: u16,
        iova: u64,
        am: u8,
    ) -> Result<(), IommuError>;

    /// Submit a page-selective Device-TLB invalidation
    fn qi_invalidate_device_tlb_page(
        &self,
        source_id: u16,
        iova: u64,
    ) -> Result<(), IommuError>;

    /// Submit a global PASID cache invalidation
    fn qi_invalidate_pasid_cache_global(&self) -> Result<(), IommuError>;

    /// Submit a domain PASID cache invalidation
    fn qi_invalidate_pasid_cache_domain(&self, domain_id: u16) -> Result<(), IommuError>;

    /// Submit a PASID-based IOTLB invalidation
    fn qi_invalidate_pasid_iotlb(&self, domain_id: u16, pasid: u32) -> Result<(), IommuError>;

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
        let _ = submit_invalidation_locked(self, iq, entry)?;
        Ok(())
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
    fn qi_invalidate_iotlb_page(
        &self,
        domain_id: u16,
        addr: u64,
        am: u8,
    ) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::iotlb_invalidate(3, domain_id, false, addr, am);
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_context_global(&self) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::context_cache_invalidate_global();
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_context_device(&self, source_id: u16, domain_id: u16) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::context_cache_invalidate(3, domain_id, source_id);
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

    #[inline]
    fn qi_invalidate_device_tlb_range(
        &self,
        source_id: u16,
        iova: u64,
        am: u8,
    ) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::device_tlb_invalidate_range(source_id, iova, am);
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_device_tlb_page(
        &self,
        source_id: u16,
        iova: u64,
    ) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::device_tlb_invalidate_page(source_id, iova);
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_pasid_cache_global(&self) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::pasid_cache_invalidate_global();
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_pasid_cache_domain(&self, domain_id: u16) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::pasid_cache_invalidate_domain(domain_id);
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_pasid_iotlb(&self, domain_id: u16, pasid: u32) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::pasid_iotlb_invalidate(domain_id, pasid);
        self.submit_invalidation(entry)
    }

    fn qi_wait_sync(&self) -> Result<(), IommuError> {
        let (status_virt, expected_data) = {
            let mut guard = match self.invalidation_queue.lock() {
                Ok(g) => g,
                Err(_) => return Err(IommuError::HardwareError),
            };
            let iq = guard.as_mut().ok_or(IommuError::NotPresent)?;
            let (entry, seq) = iq.wait_entry();
            let virt = iq.status_virtual_address();
            let _ = submit_invalidation_locked(self, iq, entry)?;
            (virt, seq)
        };

        self.wait_for_condition(
            || {
                let status = unsafe { core::ptr::read_volatile(status_virt as *const u32) };
                // Use wrap-around safe comparison (distance in u32 space)
                status.wrapping_sub(expected_data) < (1u32 << 31)
            },
            100_000,
            true,
        )
    }

    fn qi_wait_async<'a>(&'a self) -> InvalidationWaiter<'a> {
        let result = match self.invalidation_queue.lock() {
            Ok(mut guard) => {
                if let Some(iq) = guard.as_mut() {
                    let (entry, expected_data) = iq.wait_entry();
                    let status_virt = iq.status_virtual_address();
                    let submit_result = submit_invalidation_locked(self, iq, entry);
                    Ok((submit_result, status_virt, expected_data))
                } else {
                    Err(IommuError::NotPresent)
                }
            }
            Err(_err) => Err(IommuError::HardwareError) // Changed to _err and kept original error type
        };

        match result {
            Ok((submit_result, status_virt, expected_data)) => InvalidationWaiter {
                controller: self,
                submit_result: submit_result.map(|_| ()),
                status_virt,
                expected_data,
            },
            Err(e) => InvalidationWaiter {
                controller: self,
                submit_result: Err(e),
                status_virt: 0,
                expected_data: 0,
            },
        }
    }

    fn wake_invalidation_waiter(&self) {
        self.pending_waiters.wake_all_from_isr();
    }
}

